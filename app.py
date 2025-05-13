from flask import Flask, request, render_template
import numpy as np
from model import train_model, plot_confusion_matrix

app = Flask(__name__)

model, scaler, features_list, conf_matrix = train_model()
conf_matrix_img = plot_confusion_matrix(conf_matrix)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', features=features_list, prediction=None, conf_matrix_img=conf_matrix_img)

@app.route('/predict', methods=['POST'])
def predict():
    input_data = []
    for feature in features_list:
        val = request.form.get(feature)
        if val is None:
            return f"Missing input for feature: {feature}"
        try:
            if feature in ['protocol_type', 'service', 'flag']:
                val = int(val)
            else:
                val = float(val)
        except ValueError:
            return f"Invalid value for {feature}: {val}"
        input_data.append(val)
    input_array = np.array(input_data).reshape(1, -1)
    input_scaled = scaler.transform(input_array)
    pred = model.predict(input_scaled)[0]
    return render_template('index.html', features=features_list, prediction=pred, conf_matrix_img=conf_matrix_img)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
