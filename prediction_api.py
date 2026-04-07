from flask import Flask, request, jsonify
import joblib
import pandas as pd
import numpy as np
import os
import logging
from flask_cors import CORS # For handling CORS if app.py is on a different origin

# Initialize Flask app
app = Flask(__name__)
CORS(app) # Enable CORS for cross-origin requests

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - PREDICTION_API - %(levelname)s - %(message)s')

# Global variables for ML model artifacts
model = None
scaler = None
features_list = None
encoders = None

# Directory where models are stored (assuming same directory or a subfolder like 'models/')
MODEL_DIR = os.path.dirname(__file__) # Or specify a fixed path like 'models/'

def load_ml_artifacts():
    global model, scaler, features_list, encoders
    try:
        # Load the artifacts saved by model.py
        model = joblib.load(os.path.join(MODEL_DIR, 'ids_model.pkl')) #
        scaler = joblib.load(os.path.join(MODEL_DIR, 'scaler.pkl')) #
        features_list = joblib.load(os.path.join(MODEL_DIR, 'features_list.pkl')) #
        encoders = joblib.load(os.path.join(MODEL_DIR, 'encoders.pkl')) #
        logging.info("ML model and preprocessors loaded successfully.")
    except Exception as e:
        logging.error(f"Failed to load ML artifacts: {e}")
        # Exit or raise error to prevent API from running without model
        exit(1)

# Function to extract and preprocess features for prediction
# This should match the feature engineering done in data_preparation.py and model.py
def preprocess_features_for_prediction(raw_features_dict):
    try:
        # Ensure the order and names of features match 'features_list'
        # The keys in raw_features_dict should correspond to feature_names
        # Example: if raw_features_dict contains {'duration': 10, 'protocol_type': 'tcp', ...}
        
        # Create a DataFrame from the input dictionary
        df = pd.DataFrame([raw_features_dict])

        # Apply Label Encoding for categorical features using loaded encoders
        # This part needs to be robust to new unseen categories or to match the NSL-KDD preprocessing
        categorical_cols = ['protocol_type', 'service', 'flag'] #
        for col in categorical_cols:
            if col in df.columns and col in encoders:
                le = encoders[col]
                # Handle unseen labels by converting them to a placeholder or using a default
                df[col] = df[col].apply(lambda x: le.transform([x])[0] if x in le.classes_ else -1) # Use -1 or a strategy for unseen
            else:
                df[col] = 0 # Default if column or encoder not found

        # Ensure all expected numerical features are present and scaled
        # Scale only numerical features that were scaled during training
        numerical_cols_to_scale = [
            'duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count',
            'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
            'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
            'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate'
        ] # These features are from data_preparation.py, make sure they match
        
        # Reorder columns to match 'features_list' from training
        final_features_df = df[features_list]
        
        # Apply StandardScaler
        final_features_df[numerical_cols_to_scale] = scaler.transform(final_features_df[numerical_cols_to_scale]) #

        return final_features_df

    except Exception as e:
        logging.error(f"Error during feature preprocessing: {e}")
        return None

# API Route to process features and detect intrusions
@app.route("/predict", methods=["POST"])
def predict():
    if model is None or scaler is None or features_list is None or encoders is None:
        return jsonify({"error": "ML model not loaded. Server is not ready."}), 503

    try:
        raw_packet_data = request.json
        if not raw_packet_data:
            return jsonify({"error": "No JSON data provided"}), 400

        features_df = preprocess_features_for_prediction(raw_packet_data)

        if features_df is not None:
            prediction = model.predict(features_df)
            prediction_proba = model.predict_proba(features_df) # Get probabilities

            # Assuming 0: Normal, 1: Attack
            result_label = "Intrusion Detected!" if prediction[0] == 1 else "Normal Traffic"
            confidence = prediction_proba[0][prediction[0]] * 100 # Confidence in the predicted class

            return jsonify({
                "result": result_label,
                "is_intrusion": bool(prediction[0]),
                "confidence": round(confidence, 2)
            })
        else:
            return jsonify({"error": "Failed to extract or preprocess packet features"}), 400

    except Exception as e:
        logging.error(f"Error during prediction: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    load_ml_artifacts() # Load artifacts on startup
    app.run(host="0.0.0.0", port=5001, debug=True) # Run on a different port than app.py