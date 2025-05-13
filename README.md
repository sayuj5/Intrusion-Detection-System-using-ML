# Intrusion-Detection-System-using-ML
Intrusion Detection System (IDS) implemented using Machine Learning techniques. This repository contains the code, datasets (if applicable), and documentation for detecting network intrusions.
# Machine Learning-Based Intrusion Detection System

This repository contains the code for an Intrusion Detection System (IDS) implemented using Machine Learning techniques. The system is designed to classify network traffic as either normal or an attack. It utilizes the NSL-KDD dataset for training and evaluation and provides a Flask-based web interface (`index.html`) for making predictions.

## Files Description

* **`index.html`**: This file contains the HTML structure for the user interface of the Intrusion Detection System. It provides input fields for network traffic features and displays the prediction results and the confusion matrix.
* **`app.py`**: This file contains the Flask application that serves the web interface. It handles user input from `index.html`, calls the model for prediction, and renders the results, including the confusion matrix, back to the user.
* **`data_preparation.py`**: This script is responsible for loading the NSL-KDD dataset, preprocessing the data (including feature selection, label encoding for categorical features, and scaling), and splitting it into training and testing sets.
* **`model.py`**: This file contains the code for training the Random Forest Classifier model, generating the classification report and confusion matrix, and potentially saving the trained model.

## Workflow

1.  **Data Loading and Preprocessing**: The `data_preparation.py` script loads the NSL-KDD dataset, selects relevant features, encodes categorical features, and scales the numerical features using StandardScaler.
2.  **Model Training**: The `model.py` script trains a Random Forest Classifier on the preprocessed data. The data is split into training and testing sets to evaluate the model's performance. The trained model might be saved for later use.
3.  **Prediction**: The `app.py` uses the trained model to predict whether new network traffic data represents a normal connection or an attack. It receives input from the `index.html` form, preprocesses it, and feeds it to the model.
4.  **Web Interface**: The Flask application in `app.py` serves the `index.html` file, providing a user-friendly web interface. Users can input network traffic features through the form, and the application will display the model's prediction and the confusion matrix (likely rendered within `index.html`).

## Dependencies

* Python 3.x
* Flask
* NumPy
* Pandas
* Scikit-learn
* Matplotlib
* Seaborn

## Installation

1.  Clone the repository:

    ```bash
    git clone <repository_url>
    cd <repository_name>
    ```

2.  Install the required packages:

    ```bash
    pip install -r requirements.txt
    ```

    *(Note: Ensure you have a `requirements.txt` file listing the dependencies. You can generate it using `pip freeze > requirements.txt` after installing the packages)*

## Usage

1.  Run the Flask application:

    ```bash
    python app.py
    ```

2.  Open your web browser and go to `http://127.0.0.1:5000/` to access the IDS interface.

3.  Enter the network traffic features in the provided form on `index.html` and click "Predict" to see the model's classification and the confusion matrix.

## Dataset

The NSL-KDD dataset is used for training and evaluating the IDS. The dataset can be found at: [https://raw.githubusercontent.com/defcom17/NSL\_KDD/master/KDDTrain+.txt](https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt)

## Model

The model used is a Random Forest Classifier. The `model.py` script also includes functions to generate and potentially save the trained model and the confusion matrix, which is displayed in the web interface.

## Contributing

Contributions to this project are welcome! Please feel free to submit pull requests.

## License

[Specify the License - e.g., MIT License]
