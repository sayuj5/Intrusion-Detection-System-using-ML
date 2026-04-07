import gevent.monkey
gevent.monkey.patch_all()

import os
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import numpy as np
import pandas as pd
import traceback
import time
from datetime import datetime
from collections import defaultdict
import json
import logging # ADDED: Import logging module
import requests # ADDED: Import requests module

# Firebase imports
import firebase_admin
from firebase_admin import credentials, firestore, auth

# Configure logging for app.py
logging.basicConfig(level=logging.INFO, format='%(asctime)s - APP - %(levelname)s - %(message)s')

app = Flask(__name__)
app.config['SECRET_KEY'] = b'\xaf\xf5\x1e\x81\x8e\x12\xab\x1f\x9c\x0c\x83\x1a\x1b\x90\x9d\x0c\x9f\x1c\x0e\x02\x9d\x9b\x0a\x07'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')

# Global variables (ML model artifacts are no longer loaded here)
conf_matrix_img = None # Still used for dashboard display

# --- Configuration for Flask API Endpoints ---
# Make sure this matches the port your prediction_api.py is running on (e.g., 5001)
PREDICTION_API_URL = "http://127.0.0.1:5001/predict" # Prediction API URL

# --- Firestore Initialization ---
# These global variables are provided by the Canvas environment for deployment.
# For local testing, we provide a mechanism to load a service account key JSON.
appId = os.environ.get('__app_id', 'default-app-id') # MANDATORY: App ID provided by Canvas

# >>> START LOCAL FIREBASE CONFIGURATION (FOR DEVELOPMENT OUTSIDE CANVAS) <<<
# IMPORTANT: For local testing, replace 'firebase_service_account.json' with the actual
# path/filename of your downloaded Firebase service account key JSON file.
# Make sure this file is in the same directory as app.py or provide a full path.
_local_firebase_config_file = 'firebase_service_account.json' # <--- UPDATE THIS FILENAME IF YOU RENAMED IT

firebaseConfig = {} # Initialize as empty
if os.path.exists(_local_firebase_config_file):
    try:
        with open(_local_firebase_config_file, 'r') as f:
            firebaseConfig = json.load(f)
        logging.info(f"Successfully loaded local Firebase config from {_local_firebase_config_file}")
    except Exception as e:
        logging.error(f"Could not load local Firebase config file '{_local_firebase_config_file}': {e}", exc_info=True)
else:
    # This branch is primarily for Canvas deployment where __firebase_config is set
    # Or if the local file isn't found/configured.
    logging.warning(f"Local Firebase config file '{_local_firebase_config_file}' not found. "
                    "Attempting to load from __firebase_config environment variable (for Canvas deployment) or proceeding without.")
    try:
        env_config = os.environ.get('__firebase_config', '{}')
        if env_config:
            firebaseConfig = json.loads(env_config)
            logging.info("Successfully loaded Firebase config from environment variable.")
        else:
            logging.warning("__firebase_config environment variable is also empty.")
    except Exception as e:
        logging.error(f"Could not parse __firebase_config environment variable: {e}", exc_info=True)

# >>> END LOCAL FIREBASE CONFIGURATION <<<

initial_auth_token = os.environ.get('__initial_auth_token', None) # MANDATORY: Firebase auth token (for Canvas)

db = None # Firestore client instance
current_user_id = None # Authenticated user ID (will be set after Firebase init)

def initialize_firebase():
    global db, current_user_id

    # If Firebase Admin SDK is already initialized, just get the client and user ID
    if firebase_admin._apps:
        db = firestore.client()
        if not current_user_id: # Try to get user ID if not already set (e.g., after a reload)
            try:
                if initial_auth_token: # This pathway is mainly for Canvas environment
                    decoded_token = auth.verify_id_token(initial_auth_token)
                    current_user_id = decoded_token['uid']
                    logging.info(f"Firebase already initialized. Re-verified user ID from token: {current_user_id}")
                else:
                     if not current_user_id:
                        current_user_id = f"anonymous_{os.urandom(16).hex()}"
                        logging.info(f"Firebase already initialized. Assigned fallback anonymous ID: {current_user_id}")
            except Exception as e:
                logging.error(f"Could not get user ID from existing Firebase app: {e}", exc_info=True)
                if not current_user_id:
                    current_user_id = f"anonymous_{os.urandom(16).hex()}"
        logging.info("Firebase app already initialized. Firestore client ready.")
        return

    # Proceed with initial Firebase app initialization
    if not firebaseConfig:
        logging.error("Firebase config is empty. Cannot initialize Firebase Admin SDK.")
        current_user_id = f"anonymous_no_firebase_{os.urandom(16).hex()}"
        return

    try:
        cred = credentials.Certificate(firebaseConfig)
        firebase_admin.initialize_app(cred)
        logging.info("Firebase app initialized successfully using provided credentials.")
    except Exception as e:
        logging.error(f"Firebase initialization failed: {e}. Check your firebaseConfig.", exc_info=True)
        current_user_id = f"anonymous_init_failed_{os.urandom(16).hex()}"
        return

    db = firestore.client()

    if initial_auth_token:
        try:
            decoded_token = auth.verify_id_token(initial_auth_token)
            current_user_id = decoded_token['uid']
            logging.info(f"Authenticated using __initial_auth_token. User ID: {current_user_id}")
        except Exception as e:
            logging.warning(f"__initial_auth_token verification failed: {e}. Generating anonymous ID.", exc_info=True)
            current_user_id = f"anonymous_{os.urandom(16).hex()}"
    else:
        current_user_id = f"anonymous_{os.urandom(16).hex()}"
        logging.info(f"No __initial_auth_token found. Using generated anonymous ID: {current_user_id}")

    logging.info(f"Current Firestore User ID for operations: {current_user_id}")


# --- Real-time Dashboard Statistics (Data aggregated from realtime_sniffer.py) ---
realtime_stats = {
    'total_packets_analyzed': 0,
    'total_intrusions_detected': 0,
    'intrusion_rate': 0.0,
    'attack_type_distribution': defaultdict(int), # e.g., {'DoS': 5, 'Probe': 2, 'Generic_Attack': 10}
    'recent_alerts': [], # Store a few recent alerts for display
    'ml_model_health_score': 1.0, # Placeholder for model health, 1.0 is healthy
    'bruteforce_attempts': 0, # Placeholder for brute force login attempts
    'system_load': 0.0, # Placeholder for system load
    'live_ips_for_map': {} # To store IP locations for the map
}

# Reports collection in Firestore (private to user)
def get_reports_collection():
    if not db or not current_user_id or current_user_id.startswith("anonymous_no_firebase"):
        logging.info("Firestore DB or User ID not initialized for reports, or Firebase init failed. Reports will not be saved/loaded persistently.")
        return None
    return db.collection(f'artifacts/{appId}/users/{current_user_id}/ids_reports')

# Blacklist/Whitelist in Firestore (private to user)
# CORRECTED: This function now returns a CollectionReference for the IPs directly
def get_ip_collection(list_type): # Renamed function for clarity
    if not db or not current_user_id or current_user_id.startswith("anonymous_no_firebase"):
        logging.info("Firestore DB or User ID not initialized for IP lists, or Firebase init failed. IP lists will not be saved/loaded persistently.")
        return None
    # This returns a CollectionReference, allowing .stream() directly on it
    return db.collection(f'artifacts/{appId}/users/{current_user_id}/ids_ip_lists_{list_type}')


# In-memory IP lists (synced with Firestore when available)
# These are just local caches, the source of truth is Firestore
blacklist = set()
whitelist = set()

# --- Threat Intelligence (Mock API) ---
def get_threat_intelligence(ip_address):
    """
    Simulates querying an external Threat Intelligence API.
    """
    mock_malicious_ips = ['103.68.92.124', '103.168.92.107'] # Example malicious IPs
    if ip_address in mock_malicious_ips:
        return {'is_malicious': True, 'reason': 'Known malicious IP (mock data)'}
    return {'is_malicious': False, 'reason': 'No threat intelligence match (mock data)'}

# --- Real-time Data Endpoint (Receives already processed data from sniffer) ---
@app.route('/realtime_data', methods=['POST'])
def realtime_data():
    global realtime_stats
    try:
        data = request.json
        if not data:
            logging.error("No JSON data received in /realtime_data")
            return jsonify({"status": "error", "message": "No JSON data received"}), 400

        # Data now includes prediction results from realtime_sniffer (via prediction_api)
        # e.g., {'src_ip': '...', 'dst_ip': '...', 'is_intrusion': True, 'result': 'Intrusion Detected!', 'confidence': 98.5}

        realtime_stats['total_packets_analyzed'] += 1
        is_intrusion = data.get('is_intrusion', False)
        attack_label = data.get('attack_type', 'Unknown Attack') # Expect attack_type from sniffer/prediction_api

        if is_intrusion:
            realtime_stats['total_intrusions_detected'] += 1
            realtime_stats['attack_type_distribution'][attack_label] += 1
            event_type = "Intrusion"
        else:
            event_type = "Normal"

        realtime_stats['intrusion_rate'] = (realtime_stats['total_intrusions_detected'] /
                                        realtime_stats['total_packets_analyzed']) * 100 if realtime_stats['total_packets_analyzed'] > 0 else 0.0

        # Update real-time events for the 'Events' tab
        event_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': data.get('src_ip', 'N/A'),
            'dst_ip': data.get('dst_ip', 'N/A'),
            'protocol_type': data.get('protocol_type', 'N/A'),
            'result': data.get('result', 'N/A'),
            'confidence': data.get('confidence', 'N/A'),
            'event_type': event_type,
            'src_lat': data.get('src_lat'),
            'src_lon': data.get('src_lon'),
            'src_city': data.get('src_city'),
            'src_country': data.get('src_country'),
            'details': data # Pass full data for potential detailed view
        }
        realtime_stats['recent_alerts'].insert(0, event_entry)
        if len(realtime_stats['recent_alerts']) > 100: # Keep a manageable list size
            realtime_stats['recent_alerts'].pop()

        # Update live IP data for map/live traffic view
        src_ip = data.get('src_ip')
        dst_ip = data.get('dst_ip')

        if src_ip:
            realtime_stats['live_ips_for_map'][src_ip] = {
                'last_seen': time.time(),
                'is_intrusion': is_intrusion,
                'latitude': data.get('src_lat'),
                'longitude': data.get('src_lon'),
                'city': data.get('src_city'),
                'country': data.get('src_country')
            }
        if dst_ip:
             realtime_stats['live_ips_for_map'][dst_ip] = {
                'last_seen': time.time(),
                'is_intrusion': is_intrusion,
                'latitude': data.get('dst_lat'),
                'longitude': data.get('dst_lon'),
                'city': data.get('dst_city'),
                'country': data.get('dst_country')
            }


        # Emit updated dashboard statistics to connected clients
        socketio.emit('dashboard_update', {
            'total_packets': realtime_stats['total_packets_analyzed'],
            'intrusion_count': realtime_stats['total_intrusions_detected'],
            'intrusion_rate': round(realtime_stats['intrusion_rate'], 2),
            'attack_types': dict(realtime_stats['attack_type_distribution']),
            'ml_model_health_score': realtime_stats['ml_model_health_score'],
            'bruteforce_attempts': realtime_stats['bruteforce_attempts'],
            'system_load': realtime_stats['system_load'],
            'recent_alerts': realtime_stats['recent_alerts'], # Send recent alerts for events tab
            'live_ips_for_map': realtime_stats['live_ips_for_map'] # Send IPs for map
        })

        # Save critical intrusion events to Firestore (if db is initialized)
        if is_intrusion and get_reports_collection():
            try:
                report_data = {
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': data.get('src_ip', 'N/A'),
                    'dst_ip': data.get('dst_ip', 'N/A'),
                    'protocol_type': data.get('protocol_type', 'N/A'),
                    'service': data.get('service', 'N/A'), # Added service
                    'flag': data.get('flag', 'N/A'), # Added flag
                    'result': data.get('result', 'Intrusion Detected!'),
                    'attack_type': attack_label,
                    'confidence': data.get('confidence', 0),
                    'session_id': data.get('session_id', 'N/A'),
                    'src_lat': data.get('src_lat'),
                    'src_lon': data.get('src_lon'),
                    'src_city': data.get('src_city'),
                    'src_country': data.get('src_country'),
                    'dst_lat': data.get('dst_lat'), # Added dst location
                    'dst_lon': data.get('dst_lon'),
                    'dst_city': data.get('dst_city'),
                    'dst_country': data.get('dst_country'),
                    'threat_intelligence_check': get_threat_intelligence(data.get('src_ip', 'N/A')) # Re-run threat intel
                }
                get_reports_collection().add(report_data, timeout=30) # Added timeout
                logging.info(f"Intrusion report saved to Firestore for {data.get('src_ip')}")
            except Exception as e:
                logging.error(f"Failed to save intrusion report to Firestore: {e}", exc_info=True)


        return jsonify({"status": "success", "message": "Data received and processed"})

    except Exception as e:
        logging.error(f"Error processing real-time data: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect(*args):
    logging.info('Client connected!')
    stats_to_emit = realtime_stats.copy()
    stats_to_emit['userId'] = current_user_id if current_user_id else 'Not Authenticated'
    emit('dashboard_update', stats_to_emit) # Emit initial dashboard_update
    if conf_matrix_img:
        logging.debug(f"Emitting Confusion Matrix image on connect (first 50 chars): {conf_matrix_img[:50] if conf_matrix_img else 'None'}")
        emit('confusion_matrix', {'image': conf_matrix_img})
    else:
        logging.debug("Confusion Matrix image is not available for emission on connect.")

# --- SocketIO for Manual Test Panel (Redirects to prediction_api) ---
@socketio.on('request_prediction')
def handle_manual_prediction_request(packet_data):
    try:
        # Instead of local prediction, send to the dedicated prediction API
        response = requests.post(PREDICTION_API_URL, json=packet_data, timeout=5)
        if response.status_code == 200:
            prediction_result = response.json()
            emit('prediction_result', prediction_result)
            logging.info(f"Manual test prediction: {prediction_result['result']}")
        else:
            emit('prediction_result', {'error': f"Prediction API error: {response.status_code} - {response.text}"})
            logging.error(f"Prediction API error for manual test: {response.status_code} - {response.text}")

    except requests.exceptions.ConnectionError:
        emit('prediction_result', {'error': f"Could not connect to Prediction API at {PREDICTION_API_URL}. Ensure it's running."})
        logging.error(f"Manual test failed: Could not connect to Prediction API.")
    except requests.exceptions.Timeout:
        emit('prediction_result', {'error': "Prediction API timed out for manual test."})
        logging.warning("Manual test failed: Prediction API timed out.")
    except Exception as e:
        emit('prediction_result', {'error': f"An error occurred during manual prediction: {e}"})
        logging.error(f"Error in manual prediction request: {e}", exc_info=True)

# --- Historical Reports from Firestore (Remains largely the same) ---
@app.route('/get_reports', methods=['GET'])
def get_reports():
    reports_col = get_reports_collection()
    if not reports_col:
        return jsonify([])

    try:
        docs = reports_col.stream(timeout=30)
        all_reports = []
        for doc in docs:
            report_data = doc.to_dict()
            all_reports.append(report_data)

        all_reports.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        return jsonify(all_reports)
    except Exception as e:
        logging.error(f"Could not fetch historical reports from Firestore: {e}", exc_info=True)
        return jsonify({'error': 'Failed to retrieve historical reports'}), 500


# --- IP List Management (Blacklist/Whitelist via Firestore) ---
@app.route('/get_ip_lists', methods=['GET'])
def get_ip_lists():
    try:
        # Get the collection references directly
        blacklist_col = get_ip_collection('blacklist')
        whitelist_col = get_ip_collection('whitelist')

        current_blacklist = []
        current_whitelist = []

        if blacklist_col:
            # Now .stream() is called on a CollectionReference
            current_blacklist = [doc.id for doc in blacklist_col.stream(timeout=30)] # Added timeout
        if whitelist_col:
            # Now .stream() is called on a CollectionReference
            current_whitelist = [doc.id for doc in whitelist_col.stream(timeout=30)] # Added timeout

        return jsonify({'blacklist': current_blacklist, 'whitelist': current_whitelist})
    except Exception as e:
        logging.error(f"Error fetching IP lists: {e}", exc_info=True)
        return jsonify({'error': 'Failed to retrieve IP lists'}), 500

@app.route('/update_ip_list', methods=['POST'])
def update_ip_list():
    try:
        data = request.json
        ip_address = data.get('ip')
        list_type = data.get('type') # 'blacklist' or 'whitelist'
        action = data.get('action')  # 'add' or 'remove'

        if not ip_address or not list_type or not action:
            return jsonify({'error': 'Missing IP, type, or action'}), 400

        target_collection = get_ip_collection(list_type) # Get the collection reference
        if not target_collection:
            return jsonify({'error': 'Firestore not available for IP lists'}), 500

        # Now we operate directly on the collection
        if action == 'add':
            # Set a document with the IP address as its ID
            target_collection.document(ip_address).set({'timestamp': firestore.SERVER_TIMESTAMP}, timeout=30)
            logging.info(f"Added {ip_address} to {list_type} in Firestore.")
        elif action == 'remove':
            target_collection.document(ip_address).delete(timeout=30)
            logging.info(f"Removed {ip_address} from {list_type} in Firestore.")
        else:
            return jsonify({'error': 'Invalid action'}), 400

        return jsonify({'status': 'success', 'message': f'{ip_address} {action}ed from {list_type}'})
    except Exception as e:
        logging.error(f"Error updating IP list: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

# --- Confusion Matrix (Remains the same as app.py handles its serving) ---
@app.route('/confusion_matrix', methods=['GET'])
def get_confusion_matrix():
    global conf_matrix_img
    if not conf_matrix_img:
        try:
            # Assuming model.py saves it to a file that app.py can read
            # This path should be relative to where app.py is run
            model_dir = os.path.dirname(__file__)
            with open(os.path.join(model_dir, 'confusion_matrix.txt'), 'r') as f:
                conf_matrix_img = f.read()
            logging.info("Confusion matrix image loaded from file.")
        except Exception as e:
            logging.error(f"Error loading confusion matrix image: {e}", exc_info=True)
            return jsonify({'error': 'Confusion matrix not available or failed to load.'}), 500

    return jsonify({'image': conf_matrix_img})

# --- Run the Flask app ---
if __name__ == '__main__':
    with app.app_context():
        initialize_firebase()
        # No longer loading ML artifacts directly in app.py

    socketio.run(app, host='0.0.0.0', port=5055, debug=True, allow_unsafe_werkzeug=True)

