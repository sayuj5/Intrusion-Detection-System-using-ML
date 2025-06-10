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
from data_preparation import load_and_preprocess_data
MODEL_DIR = os.path.dirname(__file__)
def plot_confusion_matrix(conf_matrix):
    plt.figure(figsize=(8, 6))
    sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Predicted Normal', 'Predicted Attack'],
                yticklabels=['Actual Normal', 'Actual Attack'])
    plt.title('Confusion Matrix')
    plt.ylabel('Actual Label')
    plt.xlabel('Predicted Label')
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight')
    plt.close()
    buf.seek(0)
    img_base64 = base64.b64encode(buf.read()).decode('utf-8')
    return img_base64
def train_model():
    X, y, scaler, features_list, encoders = load_and_preprocess_data()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))
    conf_matrix = confusion_matrix(y_test, y_pred, labels=[0, 1])
    print("\nConfusion Matrix:")
    print(conf_matrix)
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
    trained_model, trained_scaler, trained_features, trained_conf_matrix_img, trained_encoders = train_model()
    print("Model training complete and artifacts saved.")
