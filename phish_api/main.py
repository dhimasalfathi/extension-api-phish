import ipaddress
import re
from urllib.parse import urlencode, urljoin, urlparse
from bs4 import BeautifulSoup
import requests
import whois
import timeit
from requests.exceptions import HTTPError, RequestException, Timeout
from datetime import datetime  # Add this line to import datetime
from extract import FeatureExtraction1

# Example usage:
url = input("Enter the URL to check: ")
feature_extractor = FeatureExtraction1(url)
features_list = feature_extractor.getFeaturesList()
print("Features List:", features_list)
