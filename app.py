from flask import Flask, request, render_template, jsonify
import numpy as np
import joblib
import os
from model import train_model, plot_confusion_matrix
import traceback # Import traceback module

app = Flask(__name__)

# Global variables to store loaded model components
model = None
scaler = None
features_list = None
encoders = None
conf_matrix_img = None
conf_matrix_data = None

def load_artifacts():
    global model, scaler, features_list, encoders, conf_matrix_img, conf_matrix_data

    required_files = ['ids_model.pkl', 'scaler.pkl', 'features_list.pkl', 'encoders.pkl']
    files_exist = all(os.path.exists(f) for f in required_files)

    if files_exist:
        try:
            model = joblib.load('ids_model.pkl')
            scaler = joblib.load('scaler.pkl')
            features_list = joblib.load('features_list.pkl')
            encoders = joblib.load('encoders.pkl')
            print("Model, scaler, features list, and encoders loaded successfully.")

            _, _, _, conf_matrix_data_temp, _ = train_model()
            conf_matrix_img = plot_confusion_matrix(conf_matrix_data_temp)

        except Exception as e:
            print(f"Error loading model artifacts: {e}. Attempting to retrain.")
            traceback.print_exc() # Print full traceback to console
            model, scaler, features_list, conf_matrix_data, encoders = train_model()
            conf_matrix_img = plot_confusion_matrix(conf_matrix_data)
            print("Model training complete and files saved.")
    else:
        print("One or more model files not found. Training model now. This will take some time...")
        model, scaler, features_list, conf_matrix_data, encoders = train_model()
        conf_matrix_img = plot_confusion_matrix(conf_matrix_data)
        print("Model training complete and files saved.")

with app.app_context():
    load_artifacts()

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', features=features_list, conf_matrix_img=conf_matrix_img)

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No input data provided'}), 400

        input_data_processed = []
        for feature in features_list:
            val = data.get(feature)
            if val is None:
                return jsonify({'error': f"Missing input for feature: {feature}"}), 400

            try:
                if feature in encoders:
                    le = encoders[feature]
                    val_transformed = le.transform([val])[0]
                    input_data_processed.append(val_transformed)
                else:
                    input_data_processed.append(float(val))

            except ValueError as e:
                print(f"ValueError processing feature {feature}: {e}") # Log to console
                traceback.print_exc() # Print full traceback to console
                return jsonify({'error': f"Invalid value for {feature}: {str(e)}. Please ensure correct numeric type."}), 400
            except KeyError:
                print(f"KeyError for feature {feature}: {val} not in encoder classes.") # Log to console
                traceback.print_exc() # Print full traceback to console
                return jsonify({'error': f"Unknown value for '{feature}': '{val}'. Please provide a valid option."}), 400
            except Exception as e:
                print(f"Unexpected error processing feature {feature}: {e}") # Log to console
                traceback.print_exc() # Print full traceback to console
                return jsonify({'error': f"An unexpected error occurred processing {feature}: {str(e)}"}), 500

        input_array = np.array(input_data_processed).reshape(1, -1)
        input_scaled = scaler.transform(input_array)
        pred = model.predict(input_scaled)[0]

        return jsonify({'prediction': int(pred)})

    except Exception as e:
        print(f"Failed to make prediction: {e}") # Log to console
        traceback.print_exc() # <--- THIS IS THE KEY CHANGE: Print full traceback
        return jsonify({'error': f"Failed to make prediction: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
