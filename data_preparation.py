import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

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

def load_and_preprocess_data():
    df = pd.read_csv(DATA_URL, names=COLUMN_NAMES)

    features = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
        'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
        'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
        'dst_host_diff_srv_rate'
    ]
    df = df[features + ['label']]
    # Corrected: Map 'normal' to 0 and 'attack' to 1 directly. The original `apply` logic was slightly ambiguous for 'attack' types.
    df['label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)

    categorical_cols = ['protocol_type', 'service', 'flag']
    encoders = {} # Initialize encoders dictionary
    for col in categorical_cols:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
        encoders[col] = le # Store the fitted encoder

    X = df[features]
    y = df['label'] # y is already numerical (0 or 1)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Returned 5 values: X_scaled (processed features), y (labels), scaler, features (list of feature names), encoders (dict of LabelEncoders)
    return X_scaled, y, scaler, features, encoders
