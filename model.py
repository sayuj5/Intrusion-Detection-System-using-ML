import numpy as np
import pandas as pd # Import pandas for data loading
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import io
import base64
import joblib # For saving/loading models
from sklearn.preprocessing import LabelEncoder, StandardScaler # Import these directly for clarity in model.py


# This ensures model.py can run independently if data_preparation.py is in flux
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


# Modified load_and_preprocess_data to ensure it returns encoders
# It's better to have this function in data_preparation.py and import it.
# I'm putting the full logic here to ensure it's self-contained for model.py's execution.
def load_and_preprocess_data_for_model():
    df = pd.read_csv(DATA_URL, names=COLUMN_NAMES)
    df_processed = df.copy()

    features_to_drop_final = [
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
        'num_compromised', 'root_shell', 'su_attempted', 'num_root',
        'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
        'is_host_login', 'is_guest_login', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'difficulty'
    ]
    # >>> THE CHANGE IS HERE: Added errors='ignore'
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

    return X, y, scaler, model_features, encoders # Ensure 5 values are returned


def train_model():
    # Use the self-contained data loading/preprocessing for model.py
    X, y, scaler, features_list, encoders = load_and_preprocess_data_for_model()

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    class_report = classification_report(y_test, y_pred, output_dict=True)
    conf_matrix = confusion_matrix(y_test, y_pred)

    # --- Save the trained model, scaler, features list, and encoders ---
    joblib.dump(model, 'ids_model.pkl')
    joblib.dump(scaler, 'scaler.pkl')
    joblib.dump(features_list, 'features_list.pkl')
    joblib.dump(encoders, 'encoders.pkl') # Save the encoders dictionary

    # Ensure 5 values are returned here as well
    return model, scaler, features_list, conf_matrix, encoders

def plot_confusion_matrix(cm):
    plt.figure(figsize=(4, 4))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False,
                xticklabels=['Normal', 'Attack'],
                yticklabels=['Normal', 'Attack'])
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.title('Confusion Matrix')
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    plt.close()
    return base64.b64encode(buf.getvalue()).decode('utf-8')

if __name__ == '__main__':
    print("Training model and saving artifacts (model, scaler, features list, encoders)...")
    model, scaler, features_list, conf_matrix, encoders = train_model()
    print("Training complete. Artifacts saved successfully.")
