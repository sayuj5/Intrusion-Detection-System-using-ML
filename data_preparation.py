import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import io
import base64
import joblib
from sklearn.preprocessing import LabelEncoder, StandardScaler
import os

MODEL_DIR = os.path.dirname(__file__)

DATA_URL = 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt'
COLUMN_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

def load_and_preprocess_data_for_model():
    """
    Loads data from a URL, preprocesses it, and returns features, labels,
    scaler, feature list, and encoders.

    This version loads the FULL dataset. Be aware of increased training time.
    """
    # <<< IMPORTANT CHANGE HERE: Removed nrows to load the full dataset >>>
    df = pd.read_csv(DATA_URL, names=COLUMN_NAMES) 
    print(f"Loaded {len(df)} rows (full dataset for production mode).")

    df_processed = df.copy()

    features_to_drop_final = [
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
        'num_compromised', 'root_shell', 'su_attempted', 'num_root',
        'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
        'is_host_login', 'is_guest_login', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'difficulty'
    ]
    df_processed = df_processed.drop(columns=features_to_drop_final, errors='ignore')

    categorical_features = ['protocol_type', 'service', 'flag']
    encoders = {}
    for col in categorical_features:
        le = LabelEncoder()
        df_processed[col] = le.fit_transform(df_processed[col])
        encoders[col] = le

    model_features = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
        'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
        'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate'
    ]

    X = df_processed[model_features]
    y = df_processed['label'].apply(lambda x: 1 if x != 'normal' else 0)

    numerical_features = X.select_dtypes(include=np.number).columns.tolist()
    scaler = StandardScaler()
    X[numerical_features] = scaler.fit_transform(X[numerical_features])

    return X, y, scaler, model_features, encoders 


def plot_confusion_matrix(cm, labels=['Normal', 'Attack']):
    """
    Plots a confusion matrix and returns its base64 encoded PNG image string.
    """
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False,
                xticklabels=labels,
                yticklabels=labels)
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.title('Confusion Matrix')
    
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight')
    plt.close()

    img_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    return img_base64


def train_model():
    """
    Trains a RandomForestClassifier model, evaluates it, and saves all necessary
    artifacts (model, scaler, features list, encoders, and confusion matrix image).
    """
    X, y, scaler, features_list, encoders = load_and_preprocess_data_for_model()

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

    model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)

    conf_matrix = confusion_matrix(y_test, y_pred, labels=[0, 1])

    conf_matrix_b64_img = plot_confusion_matrix(conf_matrix)

    joblib.dump(model, os.path.join(MODEL_DIR, 'ids_model.pkl'))
    joblib.dump(scaler, os.path.join(MODEL_DIR, 'scaler.pkl'))
    joblib.dump(features_list, os.path.join(MODEL_DIR, 'features_list.pkl'))
    joblib.dump(encoders, os.path.join(MODEL_DIR, 'encoders.pkl'))
    
    with open(os.path.join(MODEL_DIR, 'conf_matrix_b64.txt'), 'w') as f:
        f.write(conf_matrix_b64_img)

    return model, scaler, features_list, conf_matrix_b64_img, encoders

if __name__ == '__main__':
    print("Starting model training and artifact saving...")
    model, scaler, features_list, conf_matrix_b64, encoders = train_model()
    print("Model training and artifact saving complete.")
    print(f"Model artifacts saved in: {MODEL_DIR}")
    print("\nIMPORTANT: Training on the full dataset takes significant time. This is expected.")
    print("Remember: You only need to run 'python model.py' again if you want to retrain the model or regenerate artifacts.")
    print("Now, run 'python app.py' to start the Flask application and use the trained model.")
