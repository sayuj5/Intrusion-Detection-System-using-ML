from scapy.all import sniff, IP, TCP, UDP
import joblib
import pandas as pd
import logging
import os
import firebase_admin
from firebase_admin import credentials, firestore
import threading
import time

# Set up logging
logging.basicConfig(filename="firewall_logs.txt", level=logging.INFO, format='%(asctime)s - FIREWALL - %(message)s') #

# Global variables for ML model and Firestore
model = None
scaler = None # Assuming you'll need scaler
encoders = None # Assuming you'll need encoders
features_list = None # Assuming you'll need feature names
db = None
blacklist_ref = None
blacklist = set() # Local cache of blacklisted IPs

MODEL_DIR = os.path.dirname(__file__)

def initialize_firebase_for_firewall():
    global db, blacklist_ref
    try:
        if not firebase_admin._apps:
            cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
            if cred_path and os.path.exists(cred_path):
                cred = credentials.Certificate(cred_path)
                firebase_admin.initialize_app(cred, name='firewall_app') # Use a different app name
                logging.info("Firebase app initialized for firewall using service account credentials.")
            else:
                firebase_admin.initialize_app(name='firewall_app')
                logging.info("Firebase app initialized for firewall (managed identity or no specific credentials).")
        else:
             # If already initialized by app.py, just get the existing client.
             # You might need to retrieve the default app or ensure your main app initializes first.
             # For simpler use, initialize it specifically for the firewall if it's standalone.
            logging.info("Firebase app already initialized. Getting existing client for firewall.")
            # If app.py is the primary Firebase initializer, you can just get the default app
            # firebase_admin.get_app() might be sufficient depending on setup.
        
        db = firestore.client()
        blacklist_ref = db.collection('blacklist')
        logging.info("Firestore client initialized for firewall.")
    except Exception as e:
        logging.error(f"ERROR: Could not initialize Firebase or Firestore for firewall: {e}", exc_info=True)

def load_firewall_ml_artifacts():
    global model, scaler, encoders, features_list
    try:
        # Ensure these paths and filenames are consistent with what model.py saves
        model = joblib.load(os.path.join(MODEL_DIR, 'ids_model.pkl')) # (originally 'model.pkl')
        scaler = joblib.load(os.path.join(MODEL_DIR, 'scaler.pkl'))
        encoders = joblib.load(os.path.join(MODEL_DIR, 'encoders.pkl'))
        features_list = joblib.load(os.path.join(MODEL_DIR, 'features_list.pkl'))
        logging.info("Firewall ML model and preprocessors loaded successfully.")
    except Exception as e:
        logging.error(f"Failed to load firewall ML artifacts: {e}. Firewall detection may not work.", exc_info=True)

def sync_blacklist_from_firestore():
    global blacklist
    if blacklist_ref:
        try:
            docs = blacklist_ref.stream()
            new_blacklist = {doc.id for doc in docs}
            if new_blacklist != blacklist:
                blacklist = new_blacklist
                logging.info(f"Blacklist synced from Firestore. Current blacklisted IPs: {blacklist}")
        except Exception as e:
            logging.error(f"Error syncing blacklist from Firestore: {e}", exc_info=True)
    else:
        logging.warning("Firestore blacklist reference not available. Cannot sync blacklist.")

# Background thread for syncing blacklist
def blacklist_sync_thread():
    while True:
        sync_blacklist_from_firestore()
        time.sleep(60) # Sync every 60 seconds

# Feature extraction from packet - MUST BE CONSISTENT WITH MODEL TRAINING
def extract_features(packet):
    # This must match the feature list and order from model.py and data_preparation.py
    # Firewall.py's original extract_features is too simple (only src_port, dst_port, protocol, packet_length)
    # You need to expand it to match all `features_list` from your trained model.
    # Placeholder for the expanded logic, requires full NSL-KDD feature extraction from Scapy
    
    features_dict = {}
    
    # Example (you need to fill in all 40+ NSL-KDD features)
    features_dict['duration'] = 0 # Cannot get from single packet
    features_dict['protocol_type'] = 'unknown'
    if IP in packet:
        if packet[IP].proto == 6: features_dict['protocol_type'] = 'tcp'
        elif packet[IP].proto == 17: features_dict['protocol_type'] = 'udp'
        elif packet[IP].proto == 1: features_dict['protocol_type'] = 'icmp'
        
    features_dict['service'] = 'unknown'
    if TCP in packet: features_dict['service'] = str(packet[TCP].dport)
    elif UDP in packet: features_dict['service'] = str(packet[UDP].dport)

    features_dict['flag'] = 'unknown' # TCP flags can be mapped
    if TCP in packet: features_dict['flag'] = str(packet[TCP].flags)
    
    features_dict['src_bytes'] = len(packet)
    features_dict['dst_bytes'] = 0 # Difficult to get
    features_dict['count'] = 1
    features_dict['srv_count'] = 1
    # ... and so on for all ~40 features

    # Convert to DataFrame, ensure column order and encoding/scaling
    try:
        df = pd.DataFrame([features_dict])
        
        # Apply encoders (from loaded _encoders)
        categorical_cols = ['protocol_type', 'service', 'flag'] #
        for col in categorical_cols:
            if col in df.columns and col in encoders:
                le = encoders[col]
                df[col] = df[col].apply(lambda x: le.transform([x])[0] if x in le.classes_ else -1)
            else:
                df[col] = 0 # Default if column or encoder not found

        # Ensure all expected numerical features are present and scaled
        numerical_cols_to_scale = [ # List all numerical features from NSL-KDD that were scaled
            'duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count',
            'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
            'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
            'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate'
        ]
        
        # Reorder columns to match 'features_list' from training
        final_features_df = df[features_list]
        
        # Apply StandardScaler
        final_features_df[numerical_cols_to_scale] = scaler.transform(final_features_df[numerical_cols_to_scale]) #

        return final_features_df

    except Exception as e:
        logging.error(f"Error during firewall feature extraction/preprocessing: {e}", exc_info=True)
        return None


# Main firewall + IDS function
def process_packet(packet):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Check blacklist (local cache)
    if src_ip in blacklist:
        logging.warning(f"Blocked packet from blacklisted IP: {src_ip}") #
        # Here you would typically drop the packet. For demonstration, we just log.
        # This requires more advanced netfilter/firewall interaction, not just Scapy sniffing.
        return

    # Extract features and predict using the loaded model
    features = extract_features(packet)
    if features is None or model is None:
        logging.error("Failed to extract features or model not loaded. Skipping prediction for this packet.")
        return

    try:
        prediction = model.predict(features)[0] #

        if prediction == 1: # Intrusion detected
            logging.warning(f"Malicious packet detected from {src_ip} to {dst_ip}. Adding to blacklist if not present.") #
            # Add to Firestore blacklist if it's not already there
            if src_ip not in blacklist and blacklist_ref:
                try:
                    blacklist_ref.document(src_ip).set({'timestamp': firestore.SERVER_TIMESTAMP})
                    logging.info(f"Dynamically added {src_ip} to Firestore blacklist.")
                except Exception as e:
                    logging.error(f"Failed to add {src_ip} to Firestore blacklist: {e}")
        else:
            logging.info(f"Normal packet allowed from {src_ip} to {dst_ip}") #

    except Exception as e:
        logging.error(f"Error during firewall prediction for packet from {src_ip}: {e}", exc_info=True)


# Start sniffing
if __name__ == "__main__":
    initialize_firebase_for_firewall()
    load_firewall_ml_artifacts()

    # Start background thread to sync blacklist
    sync_thread = threading.Thread(target=blacklist_sync_thread, daemon=True)
    sync_thread.start()

    print(" Firewall+IDS with ML started...") #
    # For actual packet blocking, you'd need OS-level firewall rules or a network driver.
    # Scapy's sniff doesn't block by default, it just captures.
    # The 'return' in process_packet simulates blocking for logical flow.
    sniff(prn=process_packet, store=0) #