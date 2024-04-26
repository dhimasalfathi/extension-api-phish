import numpy as np
import requests.exceptions
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import requests
import whois
from urllib.parse import urlencode
from datetime import datetime
from extract import FeatureExtraction1

import joblib

# Load the trained model
model_path = "aimodel/forest_model_terbaru.pkl"
your_model = joblib.load(model_path)

# ASCII Art Banner
print(
    """
██████╗░██╗░░██╗██╗░██████╗██╗███╗░░██╗░██████╗░
██╔══██╗██║░░██║██║██╔════╝██║████╗░██║██╔════╝░
██████╔╝███████║██║╚█████╗░██║██╔██╗██║██║░░██╗░
██╔═══╝░██╔══██║██║░╚═══██╗██║██║╚████║██║░░╚██╗
██║░░░░░██║░░██║██║██████╔╝██║██║░╚███║╚██████╔╝
╚═╝░░░░░╚═╝░░╚═╝╚═╝╚═════╝░╚═╝╚═╝░░╚══╝░╚═════╝░

██████╗░███████╗████████╗███████╗░█████╗░████████╗██╗░█████╗░███╗░░██╗
██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗╚══██╔══╝██║██╔══██╗████╗░██║
██║░░██║█████╗░░░░░██║░░░█████╗░░██║░░╚═╝░░░██║░░░██║██║░░██║██╔██╗██║
██║░░██║██╔══╝░░░░░██║░░░██╔══╝░░██║░░██╗░░░██║░░░██║██║░░██║██║╚████║
██████╔╝███████╗░░░██║░░░███████╗╚█████╔╝░░░██║░░░██║╚█████╔╝██║░╚███║
╚═════╝░╚══════╝░░░╚═╝░░░╚══════╝░╚════╝░░░░╚═╝░░░╚═╝░╚════╝░╚═╝░░╚══╝
"""
)

# Input in Google Colab
user_url = input("ENTER THE URL TO CHECK: ")
print(
    "======================================================================================================================================================================"
)
try:
    # Attempt to create FeatureExtraction1 object
    obj = FeatureExtraction1(user_url)
    x = np.array(obj.getFeaturesList()).reshape(1, 22)

    # Use the trained model to predict
    y_pred = your_model.predict(x)
    feature_extractor = FeatureExtraction1(user_url)
    features_list = feature_extractor.getFeaturesList()

    variable_names = [
        "URL LENGTH",
        "HOSTNAME LENGTH",
        "HAVING IP ON URL",
        "NUMBER OF DOTS",
        "NUMBER OF EXCLAMATION SYMBOL",
        "NUMBER OF EQUALS SYMBOL",
        "NUMBER OF SLASH SYMBOL",
        "NUMBER OF WWW IN URL",
        "DIGITS IN URL RATIO",
        "DIGITS IN HOSTNAME RATIO",
        "TLD IN URL PATH",
        "PREFIX SUFFIX IN URL",
        "SHORTEST WORD IN HOSTNAME",
        "LONGEST WORD IN URL",
        "LONGEST WORD IN URL PATH",
        "PHISH HINTS IN URL",
        "NUMBER OF HYPERLINK",
        "INTERNAL HYPERLINK RATIO",
        "EMPTY TITLE",
        "DOMAIN IN TITTLE",
        "DOMAIN AGE OF URL",
        "GOOGLE INDEX ON URL",
    ]

    print("Features List:")
    for variable, value in zip(variable_names, features_list):
        print(f"{variable}: {value}")

    print(
        "======================================================================================================================================================================"
    )

    if y_pred == 0:
        print("Results: We guess it is a safe website")
    else:
        print("Results: Caution! Suspicious website detected")

except requests.exceptions.RequestException as req_ex:
    print(f"Error fetching or parsing HTML content: {req_ex}")
except AttributeError as attr_error:
    print(
        f"AttributeError: {attr_error}. This might be due to the URL being no longer online or DNS errors."
    )
except whois.parser.PywhoisError as whois_ex:
    print(f"Error fetching whois information: {whois_ex}")
except Exception as e:
    print(f"Unexpected error: {e}")
