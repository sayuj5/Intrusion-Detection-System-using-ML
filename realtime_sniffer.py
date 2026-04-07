from scapy.all import sniff, IP, TCP, UDP, ICMP
import requests
import json
import uuid
import time
from datetime import datetime
import threading
import platform
import os
import traceback
import geoip2.database
import joblib # To load encoders and scaler if necessary for feature prep before sending
import pandas as pd
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - SNIFFER - %(levelname)s - %(message)s')

# --- Configuration for Flask API Endpoints ---
# IMPORTANT: Use the IP and port of your new prediction API
PREDICTION_API_URL = "http://127.0.0.1:5001/predict" # New prediction API endpoint
DASHBOARD_API_URL = "http://127.0.0.1:5055/realtime_data" # Updated Port
# FLASK_SESSION_END_URL = "http://127.0.0.1:5000/session_end" # Keep if session management is still needed

SESSION_ID = str(uuid.uuid4())
logging.info(f"Sniffer session ID for current run: {SESSION_ID}")

sniffing_active = True

# --- GeoIP Setup ---
GEOIP_DATABASE_PATH = 'GeoLite2-City.mmdb'
geoip_reader = None
try:
    if os.path.exists(GEOIP_DATABASE_PATH):
        geoip_reader = geoip2.database.Reader(GEOIP_DATABASE_PATH)
        logging.info("GeoIP database loaded.")
    else:
        logging.warning(f"GeoIP database not found at {GEOIP_DATABASE_PATH}. GeoIP lookup will be skipped.")
except Exception as e:
    logging.error(f"Error loading GeoIP database: {e}")

# --- Load preprocessors for feature extraction if needed locally (for consistency) ---
# It's crucial that the preprocessing here matches data_preparation.py and prediction_api.py
try:
    # Assuming model.py saves these to the same directory or a known path
    _scaler = joblib.load(os.path.join(os.path.dirname(__file__), 'scaler.pkl'))
    _encoders = joblib.load(os.path.join(os.path.dirname(__file__), 'encoders.pkl'))
    _features_list = joblib.load(os.path.join(os.path.dirname(__file__), 'features_list.pkl'))
    logging.info("Local preprocessors loaded for consistent feature extraction.")
except Exception as e:
    logging.error(f"Could not load local preprocessors for sniffer. Ensure model artifacts are available: {e}")
    # Consider exiting or setting a flag to skip ML feature prep if artifacts are missing

# --- Packet Feature Extraction and Formatting ---
def extract_features_from_packet(packet):
    # This function must extract features that match what your model was trained on
    # and what prediction_api.py expects.
    # Refer to data_preparation.py and model.py for the exact features.
    
    features = {
        'timestamp': datetime.now().isoformat(),
        'session_id': SESSION_ID,
        'src_ip': packet[IP].src if IP in packet else 'N/A',
        'dst_ip': packet[IP].dst if IP in packet else 'N/A',
        'protocol_type': packet[IP].proto if IP in packet else 0, # Map to string if model expects 'tcp', 'udp', 'icmp'
        'service': 'unknown', # Scapy doesn't directly give 'service' as in NSL-KDD, infer or default
        'flag': 'unknown',    # Similar for 'flag'
        'duration': 0,        # Scapy doesn't directly give duration, calculate if needed over flows
        'src_bytes': len(packet), # Approximation for src_bytes
        'dst_bytes': 0,       # Approximation, difficult from single packet
        'count': 1,           # Approximation
        'srv_count': 1,       # Approximation
        'serror_rate': 0,     # Requires flow analysis
        'srv_serror_rate': 0, # Requires flow analysis
        'rerror_rate': 0,     # Requires flow analysis
        'srv_rerror_rate': 0, # Requires flow analysis
        'same_srv_rate': 1.0, # Approximation
        'diff_srv_rate': 0.0, # Approximation
        'srv_diff_host_rate': 0.0, # Approximation
        'dst_host_count': 1,  # Approximation
        'dst_host_srv_count': 1, # Approximation
        'dst_host_same_srv_rate': 1.0, # Approximation
        'dst_host_diff_srv_rate': 0.0, # Approximation
        # ... other NSL-KDD features needed by your model
    }
    
    # Map protocol number to name for consistency if your model expects names
    if features['protocol_type'] == 6: features['protocol_type'] = 'tcp'
    elif features['protocol_type'] == 17: features['protocol_type'] = 'udp'
    elif features['protocol_type'] == 1: features['protocol_type'] = 'icmp'
    else: features['protocol_type'] = 'other'

    # Attempt to infer service and flags from TCP/UDP layers if present
    if TCP in packet:
        features['service'] = str(packet[TCP].dport) # Use port as service
        features['flag'] = packet[TCP].flags.value # Get TCP flags value
    elif UDP in packet:
        features['service'] = str(packet[UDP].dport) # Use port as service
        features['flag'] = 'U' # Placeholder for UDP
    elif ICMP in packet:
        features['service'] = 'icmp'
        features['flag'] = 'I' # Placeholder for ICMP

    # GeoIP lookup
    src_country, dst_country = 'Unknown', 'Unknown'
    if geoip_reader:
        try:
            if features['src_ip'] != 'N/A' and features['src_ip'] != '127.0.0.1': # Exclude localhost
                src_country = geoip_reader.city(features['src_ip']).country.name
        except Exception: pass
        try:
            if features['dst_ip'] != 'N/A' and features['dst_ip'] != '127.0.0.1':
                dst_country = geoip_reader.city(features['dst_ip']).country.name
        except Exception: pass
    
    features['src_country'] = src_country
    features['dst_country'] = dst_country

    return features

# --- Packet Processing Callback ---
def packet_callback(packet):
    global sniffing_active
    if not sniffing_active:
        return

    extracted_features = extract_features_from_packet(packet)
    if not extracted_features:
        return

    # Send features to the new Prediction API
    try:
        response = requests.post(PREDICTION_API_URL, json=extracted_features, timeout=1) # Reduced timeout
        if response.status_code == 200:
            prediction_result = response.json()
            extracted_features.update(prediction_result) # Add prediction results to the data
            logging.info(f"Packet from {extracted_features['src_ip']} processed: {prediction_result['result']}")

            # Now send the enhanced data to the main dashboard app
            try:
                requests.post(DASHBOARD_API_URL, json=extracted_features, timeout=0.5) # Non-blocking send
            except requests.exceptions.Timeout:
                logging.warning("Dashboard API did not respond in time.")
            except requests.exceptions.ConnectionError:
                logging.error("Could not connect to Dashboard API.")
            except Exception as e:
                logging.error(f"Error sending data to Dashboard API: {e}", exc_info=True)

        else:
            logging.error(f"Prediction API error for packet from {extracted_features['src_ip']}: {response.status_code} - {response.text}")
    except requests.exceptions.ConnectionError:
        logging.error(f"Could not connect to Prediction API at {PREDICTION_API_URL}. Is it running?")
    except requests.exceptions.Timeout:
        logging.warning(f"Prediction API timed out at {PREDICTION_API_URL}. Consider increasing timeout or optimizing API.")
    except Exception as e:
        logging.error(f"Error sending data to Prediction API: {e}", exc_info=True)

# --- Sniffing Control ---
def stop_sniffing():
    global sniffing_active
    sniffing_active = False
    logging.info("Sniffing stopped.")

# --- Main Sniffer Execution ---
if __name__ == '__main__':
    NETWORK_INTERFACE = os.getenv('NETWORK_INTERFACE', 'Ethernet') # Default for Windows, adjust for Linux/macOS
    if platform.system() == "Linux":
        NETWORK_INTERFACE = os.getenv('NETWORK_INTERFACE', 'eth0') # Common Linux interface
    elif platform.system() == "Darwin": # macOS
        NETWORK_INTERFACE = os.getenv('NETWORK_INTERFACE', 'en0') # Common macOS interface

    print(f"\nNetSentinel will attempt to sniff on interface: '{NETWORK_INTERFACE}'.") #
    print("For full internal/external detection, ensure proper network setup (e.g., SPAN port) and privileges.") #

    sniff_thread = threading.Thread(target=sniff, kwargs={
        'prn': packet_callback,
        'store': 0,
        'iface': NETWORK_INTERFACE,
        'promisc': True
    }) #
    sniff_thread.daemon = True
    sniff_thread.start() #

    try:
        while sniffing_active:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_sniffing()
    except Exception as e:
        logging.error(f"An unexpected error occurred in the main sniffer loop: {e}", exc_info=True)
        stop_sniffing()
    finally:
        if sniff_thread.is_alive():
            logging.info("Waiting for sniffing thread to terminate...")
            sniff_thread.join(timeout=2)