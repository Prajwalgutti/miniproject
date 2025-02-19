# phishing_model.py
import re
import pandas as pd

# Load the dataset
file_path = 'dataset_phishing.csv'
data = pd.read_csv(file_path)

# Create a dictionary mapping URLs to their statuses
url_status_dict = dict(zip(data['url'], data['status']))

# Function to predict if a URL is phishing or legitimate
def predict_url(url):
    if url in url_status_dict:
        status = url_status_dict[url]
        if status == 'phishing':
            return 'Phishing'
        elif status == 'legitimate':
            return 'Legitimate'
        else:
            return 'Unknown Status'
    else:
        return 'Unknown URL'

# Function to extract URLs from email content
def extract_urls(email_content):
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_content)
    return urls

# Function to check if an email contains phishing URLs
def check_email_for_phishing(email_content):
    urls = extract_urls(email_content)
    phishing_urls = [url for url in urls if predict_url(url) == 'Phishing']
    
    if phishing_urls:
        return f'Phishing URLs found: {", ".join(phishing_urls)}'
    else:
        return 'No phishing URLs detected'
