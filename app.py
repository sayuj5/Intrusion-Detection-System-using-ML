import gevent.monkey
gevent.monkey.patch_all()

import os
import joblib
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import numpy as np
import pandas as pd 
import traceback
import time
from datetime import datetime
from collections import defaultdict
import json

# Import train_model from model.py
from model import train_model 

app = Flask(__name__)
app.config['SECRET_KEY'] = b'\xaf\xf5\x1e\x81\x8e\x12\xab\x1f\x9c\x0c\x83\x1a\x1b\x90\x9d\x0c\x9f\x1c\x0e\x02\x9d\x9b\x0a\x07'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')

# Global variables for ML model artifacts
model = None
scaler = None
features_list = None
encoders = None
conf_matrix_img = None 

# --- Real-time Dashboard Statistics (Data aggregated from realtime_sniffer.py) ---
realtime_stats = {
    'total_packets_analyzed': 0,
    'total_intrusions_detected': 0,
    'intrusion_rate': 0.0,
    'attack_type_distribution': {},
    'recent_intrusions': [],
    'intrusion_locations': [],
    'top_attacker_ips': {},
    'intrusions_over_time': {},
    'failed_ssh_logins': {},
    'live_packet_log': [] 
}

MAX_LIVE_PACKETS = 100 

# --- Data Storage for HIDS (Per Session for Reports) ---
current_alerts_by_session = defaultdict(list)
current_live_traffic_by_session = defaultdict(list) 
active_session_id = None

# --- Reports Storage ---
REPORTS_FILE = 'reports.json'

def load_reports():
    """Loads historical reports from the REPORTS_FILE."""
    if os.path.exists(REPORTS_FILE):
        with open(REPORTS_FILE, 'r') as f:
            try:
                content = f.read()
                if content:
                    return json.loads(content)
                return []
            except json.JSONDecodeError:
                print(f"Warning: {REPORTS_FILE} is malformed or empty, initializing as empty list.")
                return [] 
    return [] 

def save_reports(reports):
    """Saves the list of reports to the REPORTS_FILE."""
    with open(REPORTS_FILE, 'w') as f:
        json.dump(reports, f, indent=4)

all_reports = load_reports()

# --- Utility Function for Data Aggregation ---
def get_attack_types_for_session(alerts_list): 
    """Aggregates and counts the occurrences of each attack type for a given list of alerts."""
    attack_counts = defaultdict(int)
    for alert in alerts_list:
        attack_type = alert.get('attack_type', 'UNKNOWN')
        attack_counts[attack_type] += 1
    return dict(attack_counts)

# --- Flask Routes ---

@app.route('/')
def index():
    """Renders the main dashboard HTML page."""
    return render_template('index.html')

@app.route('/realtime_data', methods=['POST'])
def receive_realtime_data():
    """
    Receives real-time intrusion and traffic data from the 'realtime_sniffer.py' script.
    Data is stored in memory, keyed by session_ID, and also updates global realtime_stats.
    """
    global active_session_id, realtime_stats

    data = request.get_json()
    if not data:
        return jsonify({'status': 'error', 'message': 'No JSON data received'}), 400

    session_id = data.get('session_id')
    if not session_id:
        return jsonify({'status': 'error', 'message': 'Missing session_id'}), 400
    
    active_session_id = session_id 

    prediction_result = data.get('prediction')
    attack_type = data.get('attack_type')
    packet_details = data.get('details', {})
    src_location = data.get('src_location', {})
    raw_packet_data = data.get('raw_packet_data', {})

    # --- Update global realtime_stats for live dashboard display ---
    current_time_obj = datetime.now()
    current_hour_str = current_time_obj.strftime('%Y-%m-%d %H') 

    realtime_stats['total_packets_analyzed'] += 1
    
    if prediction_result == "Attack Detected!":
        realtime_stats['total_intrusions_detected'] += 1
        if attack_type:
            realtime_stats['attack_type_distribution'][attack_type] = \
                realtime_stats['attack_type_distribution'].get(attack_type, 0) + 1
        
        if 'src_ip' in packet_details:
            src_ip = packet_details['src_ip']
            realtime_stats['top_attacker_ips'][src_ip] = \
                realtime_stats['top_attacker_ips'].get(src_ip, 0) + 1

        realtime_stats['intrusions_over_time'][current_hour_str] = \
            realtime_stats['intrusions_over_time'].get(current_hour_str, 0) + 1
        
        recent_entry = {
            'timestamp': raw_packet_data.get('timestamp', current_time_obj.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]),
            'prediction': prediction_result,
            'attack_type': attack_type if attack_type else 'Unknown',
            'details': packet_details,
            'src_location': src_location 
        }
        realtime_stats['recent_intrusions'].insert(0, recent_entry)
        if len(realtime_stats['recent_intrusions']) > 20: 
            realtime_stats['recent_intrusions'].pop()

        if src_location and src_location.get('latitude') is not None and src_location.get('longitude') is not None:
             realtime_stats['intrusion_locations'].insert(0, {
                 'latitude': src_location['latitude'],
                 'longitude': src_location['longitude'],
                 'city': src_location.get('city', 'N/A'),
                 'country': src_location.get('country', 'N/A'),
                 'ip': packet_details.get('src_ip', 'N/A'), 
                 'type': attack_type 
             })
             if len(realtime_stats['intrusion_locations']) > 50: 
                 realtime_stats['intrusion_locations'].pop()
        
        # Increment Failed SSH Logins chart if attack_type is SSH_ATTEMPT
        if attack_type == "SSH_ATTEMPT": 
             realtime_stats['failed_ssh_logins'][current_hour_str] = \
                realtime_stats['failed_ssh_logins'].get(current_hour_str, 0) + 1

    if raw_packet_data:
        realtime_stats['live_packet_log'].insert(0, raw_packet_data)
        if len(realtime_stats['live_packet_log']) > MAX_LIVE_PACKETS:
            realtime_stats['live_packet_log'].pop()

    if realtime_stats['total_packets_analyzed'] > 0:
        realtime_stats['intrusion_rate'] = \
            (realtime_stats['total_intrusions_detected'] / realtime_stats['total_packets_analyzed']) * 100
    else:
        realtime_stats['intrusion_rate'] = 0.0

    MAX_REPORT_LIVE_TRAFFIC = 50000 
    current_live_traffic_by_session[session_id].append(raw_packet_data)
    if len(current_live_traffic_by_session[session_id]) > MAX_REPORT_LIVE_TRAFFIC:
        current_live_traffic_by_session[session_id] = current_live_traffic_by_session[session_id][-MAX_REPORT_LIVE_TRAFFIC:] 

    MAX_REPORT_ALERTS = 5000 
    if prediction_result == "Attack Detected!":
        current_alerts_by_session[session_id].append({
            'timestamp': raw_packet_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]),
            'prediction': prediction_result,
            'attack_type': attack_type,
            'source_ip': packet_details.get('src_ip', 'N/A'),
            'destination_ip': packet_details.get('dst_ip', 'N/A'),
            'source_location': f"{src_location.get('city', 'N/A')}, {src_location.get('country', 'N/A')}",
            'source_location_raw': src_location, 
            'details': packet_details 
        })
        if len(current_alerts_by_session[session_id]) > MAX_REPORT_ALERTS:
            current_alerts_by_session[session_id] = current_alerts_by_session[session_id][-MAX_REPORT_ALERTS:]


    return jsonify({'status': 'success', 'message': 'Data received'}), 200

@app.route('/get_dashboard_data/<session_id_param>', methods=['GET'])
def get_dashboard_data(session_id_param):
    """
    Provides current dashboard data (alerts, live traffic, summaries) via AJAX.
    If 'session_id_param' is 'current', it returns data from the global 'realtime_stats'.
    This is for live updates.
    """
    global active_session_id, realtime_stats

    if session_id_param == 'current':
        response_data = {
            'total_packets': realtime_stats['total_packets_analyzed'],
            'total_intrusions': realtime_stats['total_intrusions_detected'],
            'intrusion_rate': realtime_stats['intrusion_rate'],
            'top_attacks': realtime_stats['attack_type_distribution'],
            'alerts': realtime_stats['recent_intrusions'], 
            'live_traffic': realtime_stats['live_packet_log'], 
            'map_data': realtime_stats['intrusion_locations'],
            'top_attacker_ips': realtime_stats['top_attacker_ips'],
            'intrusions_over_time': realtime_stats['intrusions_over_time'],
            'failed_ssh_logins': realtime_stats['failed_ssh_logins'], # Ensure this is sent
            'active_session_id': active_session_id 
        }
        return jsonify(response_data), 200
    else:
        report = next((r for r in all_reports if r['session_id'] == session_id_param), None)
        if report:
            alerts = report.get('alerts', [])
            live_traffic = report.get('raw_live_traffic', []) 

            total_packets = len(live_traffic)
            total_intrusions = len(alerts)
            top_attacks = get_attack_types_for_session(alerts)

            map_data = [] 
            for alert in alerts:
                loc = alert.get('source_location_raw', {})
                if loc and loc.get('latitude') is not None and loc.get('longitude') is not None:
                    map_data.append({
                        'lat': loc['latitude'],
                        'lon': loc['longitude'],
                        'ip': alert.get('source_ip', 'N/A'),
                        'type': alert.get('attack_type', 'N/A')
                    })

            response_data = {
                'total_packets': total_packets,
                'total_intrusions': total_intrusions,
                'top_attacks': top_attacks,
                'alerts': alerts,
                'live_traffic': live_traffic, 
                'map_data': map_data,
                'active_session_id': active_session_id 
            }
            return jsonify(response_data), 200
        else:
            return jsonify({"status": "error", "message": "Report not found"}), 404


@app.route('/session_end', methods=['POST'])
def session_end():
    """
    Receives a signal from 'realtime_sniffer.py' that a sniffing session has ended.
    It then aggregates data from that session, generates a summary report,
    and saves it to 'reports.json' for historical viewing.
    """
    global active_session_id, realtime_stats

    data = request.get_json()
    session_id = data.get('session_id')
    if not session_id:
        print("Received session_end signal but missing session_id.")
        return jsonify({'status': 'error', 'message': 'Missing session_id'}), 400

    print(f"Flask: Received session end signal for session ID: {session_id}")

    session_alerts = current_alerts_by_session.pop(session_id, []) 
    session_live_traffic = current_live_traffic_by_session.pop(session_id, [])

    start_time = session_live_traffic[0]['timestamp'] if session_live_traffic else datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    report_summary = {
        'session_id': session_id,
        'start_time': start_time,
        'end_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
        'total_packets': len(session_live_traffic),
        'total_intrusions': len(session_alerts),
        'top_attacks': get_attack_types_for_session(session_alerts), 
        'alerts': session_alerts,
        'raw_live_traffic': session_live_traffic 
    }
    
    all_reports.append(report_summary) 
    save_reports(all_reports) 
    print(f"Flask: Report for session {session_id} saved successfully to reports.json. "
          f"Total packets: {len(session_live_traffic)}, Total alerts: {len(session_alerts)}")
    print(f"WARNING: Saving raw live traffic can lead to very large 'reports.json' files over time.")

    # Clear real-time stats for the dashboard ONLY, preparing for a NEW live session.
    # The historical data for this session is now in reports.json.
    realtime_stats['total_packets_analyzed'] = 0
    realtime_stats['total_intrusions_detected'] = 0
    realtime_stats['intrusion_rate'] = 0.0
    realtime_stats['attack_type_distribution'] = {}
    realtime_stats['recent_intrusions'] = []
    realtime_stats['intrusion_locations'] = []
    realtime_stats['top_attacker_ips'] = {}
    realtime_stats['intrusions_over_time'] = {}
    realtime_stats['failed_ssh_logins'] = {}
    realtime_stats['live_packet_log'] = [] # Clear this so new sessions start fresh on dashboard

    if active_session_id == session_id:
        active_session_id = None

    return jsonify({'status': 'success', 'message': f'Session {session_id} ended and report saved.'}), 200

@app.route('/get_reports', methods=['GET'])
def get_reports():
    """Returns all saved historical reports as a JSON array."""
    print("Flask: Serving historical reports.")
    return jsonify(all_reports), 200

@app.route('/get_confusion_matrix_image', methods=['GET'])
def get_confusion_matrix_image():
    """
    Returns the base64 encoded confusion matrix image string.
    """
    global conf_matrix_img
    if conf_matrix_img:
        return jsonify({"image": conf_matrix_img}), 200
    else:
        return jsonify({"message": "Confusion matrix not available. Please ensure model.py is run first to generate model artifacts."}), 404

@app.route('/predict', methods=['POST'])
def predict():
    global model, scaler, features_list, encoders 

    if model is None or scaler is None or features_list is None or encoders is None:
        return jsonify({"error": "ML model not loaded. Please ensure 'model.py' is run first to generate model artifacts."}), 500

    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 415

    data = request.get_json()
    
    expected_input_features = features_list 

    processed_input_values = [] 
    
    categorical_features_model = ['protocol_type', 'service', 'flag'] 

    for feature_name in expected_input_features:
        if feature_name not in data:
            return jsonify({"error": f"Missing feature: {feature_name}. Please provide all required inputs."}), 400
        
        val = data[feature_name]
        
        try:
            if feature_name in categorical_features_model:
                le = encoders.get(feature_name)
                if le is None:
                    return jsonify({"error": f"Encoder for '{feature_name}' not found. Ensure model training includes this feature."}), 500
                
                if val not in le.classes_:
                    return jsonify({"error": f"Unseen categorical value '{val}' for '{feature_name}'. Valid options for '{feature_name}' are: {list(le.classes_)}"}), 400
                
                val_transformed = le.transform([val])[0]
                processed_input_values.append(val_transformed)
            else:
                processed_input_values.append(float(val))
        except ValueError:
            return jsonify({"error": f"Invalid numerical value for {feature_name}: '{val}'"}), 400
        except Exception as e:
            print(f"Error processing feature {feature_name}: {e}")
            traceback.print_exc()
            return jsonify({"error": f"An unexpected error occurred while processing feature '{feature_name}': {e}"}), 500

    try:
        input_df = pd.DataFrame([processed_input_values], columns=features_list)
        input_scaled = scaler.transform(input_df) 
        
        prediction = model.predict(input_scaled)[0] 
        probabilities = model.predict_proba(input_scaled)[0] 

        result = "Attack Detected!" if prediction == 1 else "Normal Traffic"
        
        response_data = {
            "prediction": result,
            "normal_proba": probabilities[0], 
            "attack_proba": probabilities[1]  
        }
        
        return jsonify(response_data), 200
    except Exception as e:
        print(f"Error during prediction: {e}")
        traceback.print_exc()
        return jsonify({"error": f"An error occurred during prediction: {e}. Check server logs for details."}), 500


# --- Load Model Artifacts ---
def load_artifacts():
    """
    Loads trained ML model artifacts (model, scaler, features list, encoders, and confusion matrix image).
    If any artifact is missing or corrupted, it prints an error and keeps them as None.
    It DOES NOT trigger retraining from app.py, that must be done manually via model.py.
    """
    global model, scaler, features_list, encoders, conf_matrix_img
    
    model_path = os.path.join(os.path.dirname(__file__), 'ids_model.pkl')
    scaler_path = os.path.join(os.path.dirname(__file__), 'scaler.pkl')
    features_list_path = os.path.join(os.path.dirname(__file__), 'features_list.pkl')
    encoders_path = os.path.join(os.path.dirname(__file__), 'encoders.pkl')
    conf_matrix_b64_path = os.path.join(os.path.dirname(__file__), 'conf_matrix_b64.txt')

    if (os.path.exists(model_path) and
        os.path.exists(scaler_path) and
        os.path.exists(features_list_path) and
        os.path.exists(encoders_path) and
        os.path.exists(conf_matrix_b64_path)):
        try:
            print("Loading ML model, scaler, features list, encoders, and confusion matrix...")
            model = joblib.load(model_path)
            scaler = joblib.load(scaler_path)
            features_list = joblib.load(features_list_path)
            encoders = joblib.load(encoders_path)
            
            with open(conf_matrix_b64_path, 'r') as f:
                conf_matrix_img = f.read() 
            
            print("ML model artifacts loaded successfully. Confusion Matrix image ready.")
            
        except Exception as e:
            print(f"ERROR: Could not load existing ML artifacts: {e}")
            traceback.print_exc() 
            print("Please run 'python model.py' to ensure model artifacts are generated and accessible.")
            model, scaler, features_list, encoders, conf_matrix_img = None, None, None, None, None
    else:
        print("WARNING: One or more ML model artifacts not found. "
              "Prediction and Confusion Matrix features will be unavailable.")
        print("Please run 'python model.py' first to train the model and generate these files.")
        model, scaler, features_list, encoders, conf_matrix_img = None, None, None, None, None


# --- Run the Flask app ---
if __name__ == '__main__':
    if not os.path.exists(REPORTS_FILE):
        with open(REPORTS_FILE, 'w') as f:
            json.dump([], f) 
    
    with app.app_context():
       load_artifacts() 

    socketio.run(app, debug=True, port=5000, allow_unsafe_werkzeug=True)
