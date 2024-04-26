from flask import Flask, request, jsonify
from flask_cors import CORS  # Import CORS from flask_cors
import numpy as np
from extract import FeatureExtraction1
import joblib

app = Flask(__name__)
CORS(app)  # Use CORS directly with your Flask app

# Load the trained model
model_path = "aimodel/forest_model_terbaru.pkl"
your_model = joblib.load(model_path)


# Handle CORS preflight requests
@app.route("/predict", methods=["OPTIONS"])
def handle_options():
    # Set CORS headers
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Max-Age": "86400",  # 24 hours
    }
    return ("", 204, headers)


@app.route("/predict", methods=["POST"])
def predict():
    try:
        # Get URL from request data
        data = request.get_json()
        user_url = data["url"]

        # Create FeatureExtraction1 object and extract features
        feature_extractor = FeatureExtraction1(user_url)
        x = np.array(feature_extractor.getFeaturesList()).reshape(1, 22)
        features_list = feature_extractor.getFeaturesList()  # Extract features

        # Predict using the loaded model
        y_pred = your_model.predict(x)

        # Prepare response
        if y_pred == 0:
            result = "safe"
        else:
            result = "suspicious"

        response = {
            "url": user_url,
            "prediction": result,
            "features_list": features_list,
        }

        return jsonify(response), 200

    except Exception as e:
        error_message = {"error": str(e)}
        return jsonify(error_message), 500


@app.route("/extract_features", methods=["POST"])
def extract_features():
    try:
        data = request.get_json()
        url = data["url"]
        feature_extractor = FeatureExtraction1(url)
        features_list = feature_extractor.getFeaturesList()
        return jsonify({"features_list": features_list}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/ping")
def ping():
    return "API is up and running"


if __name__ == "__main__":
    app.run(debug=True)
