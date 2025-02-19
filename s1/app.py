from flask import Flask, request, render_template_string, send_from_directory, jsonify
from flask_cors import CORS
import imaplib
import email
from email.header import decode_header
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import logging
import os
from datetime import datetime
import socket
import hashlib
from phishing_model import check_email_for_phishing

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('apscheduler').setLevel(logging.DEBUG)

scheduler = BackgroundScheduler()

# Initialize global variables to store phishing check results
latest_results = {"messages": [], "status_code": "good"}
processed_email_hashes = set()
seen_warnings = set()  # To track unique warnings

# Directory to store reports
REPORTS_DIR = 'E:\\report'
os.makedirs(REPORTS_DIR, exist_ok=True)

# Global variables for email account
email_address = None
password = None

def decode_email_header(header):
    decoded_header = decode_header(header)
    decoded_text = []
    for part, encoding in decoded_header:
        if isinstance(part, bytes):
            decoded_text.append(part.decode(encoding or 'utf-8'))
        else:
            decoded_text.append(part)
    return ''.join(decoded_text)

def detect_phishing(subject, body):
    phishing_keywords = ['urgent', 'verify', 'account suspension', 'password reset', 'warning','urgent action required',
'account verification',
'password reset',
'suspicious activity',
'update account information',
'secure your account',
'unauthorized login attempt',
'limited time offer',
'congratulations, you’ve won!',
'immediate attention needed',
'important notice',
'payment failure',
'account suspended',
'verify your identity',
'unusual activity detected',
'verify your email',
'click here to update',
'login required',
'confirm your details',
'account locked',
'new message from support',
'payment declined',
'access restricted',
'action needed',
'validate your account',
'contact support',
'urgent notice',
'verify your credentials',
'billing issue',
'claim your prize',
'security alert',
'login attemp']
    for keyword in phishing_keywords:
        if keyword in subject.lower() or keyword in body.lower():
            return True
    return False

def get_ip_address():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception as e:
        logging.error(f"Error getting IP address: {e}")
        return "Unknown"

def save_report_to_file(message):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    file_name = f"report_{timestamp}.html"
    file_path = os.path.join(REPORTS_DIR, file_name)
    
    report_content = f"""
    <html>
    <head>
        <title>Phishing Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                padding: 20px;
                background-color: #f4f4f4;
            }}
            .report {{
                background: #fff;
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 15px;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            }}
            h2 {{
                color: #333;
            }}
            pre {{
                white-space: pre-wrap;
                word-break: break-word;
            }}
        </style>
    </head>
    <body>
        <div class="report">
            <h2>Phishing Report</h2>
            <p><strong>Timestamp:</strong> {datetime.now()}</p>
            <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d')}</p>
            <p><strong>IP Address:</strong> {get_ip_address()}</p>
            <p><strong>Message:</strong></p>
            <pre>{message}</pre>
        </div>
    </body>
    </html>
    """
    
    with open(file_path, 'w') as file:
        file.write(report_content)
    
    return file_name

def hash_email_content(subject, body, date):
    email_content = f"Subject: {subject}\nBody: {body}\nDate: {date}"
    return hashlib.md5(email_content.encode()).hexdigest()

def check_phishing_emails():
    logging.info("Running phishing check...")
    imap_server = "imap.gmail.com"
    
    global latest_results, email_address, password, processed_email_hashes, seen_warnings
    detected_emails = []
    status_code = "good"

    if not email_address or not password:
        logging.error("Email address or password not provided.")
        return

    try:
        imap = imaplib.IMAP4_SSL(imap_server)
        imap.login(email_address, password)
        imap.select("INBOX")

        status, messages = imap.search(None, 'UNSEEN')
        if status == "OK":
            unread_message_nums = messages[0].split()
            if unread_message_nums:
                for num in unread_message_nums:
                    status, data = imap.fetch(num, "(RFC822)")
                    if status == "OK":
                        raw_email = data[0][1]
                        email_message = email.message_from_bytes(raw_email)
                        subject = decode_email_header(email_message["Subject"])
                        sender = decode_email_header(email_message["From"])
                        date = decode_email_header(email_message["Date"])
                        body = ""
                        for part in email_message.walk():
                            content_type = part.get_content_type()
                            content_disposition = str(part.get("Content-Disposition"))
                            if content_type == "text/plain" and "attachment" not in content_disposition:
                                payload = part.get_payload(decode=True)
                                if payload is not None:
                                    payload_text = payload.decode(errors='replace')
                                    body += payload_text
                        
                        email_hash = hash_email_content(subject, body, date)
                        
                        if email_hash in processed_email_hashes:
                            continue

                        # Use ML model function to check phishing
                        result_message = check_email_for_phishing(body)
                        if 'Phishing' in result_message:
                            ip_address = get_ip_address()
                            if result_message not in seen_warnings:
                                detected_emails.append((f"Warning: {result_message} from {sender} with subject: {subject} - IP Address: {ip_address}", "warning"))
                                seen_warnings.add(result_message)
                                status_code = "bad"
                            else:
                                detected_emails.append((f"Don't neglect: {result_message}", "warning"))
                            processed_email_hashes.add(email_hash)
                        
                        imap.store(num, '+FLAGS', '\\Seen')

        imap.logout()
    except Exception as e:
        logging.error(f"An error occurred while checking emails: {e}")
        result_message = f"An error occurred while checking emails: {e}"
        if result_message not in seen_warnings:
            detected_emails.append((result_message, "warning"))
            seen_warnings.add(result_message)
        status_code = "bad"

    if detected_emails:
        latest_results["messages"].extend(detected_emails)
    else:
        latest_results["messages"].append(("No phishing emails detected.", "good"))
    latest_results["status_code"] = status_code

    logging.info(f"Detection completed. Results: {latest_results['messages']}")


@app.route('/')
def index():
    global email_address, password
    
    if email_address and password:
        check_phishing_emails()
    
    status_color = "green" if latest_results["status_code"] == "good" else "orange"

    message_html = ""
    for message, msg_type in latest_results["messages"]:
        color = "red" if msg_type == "warning" else "green"
        download_link = f'<a href="/generate-report?message={message}">View Report</a>' if msg_type == "warning" else ""
        message_html += f'<p style="color: {color};">{message} {download_link}</p>'

    html = f"""
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>Phishing Email Checker</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
            background: linear-gradient(to right, #f8f9fa, #e9ecef);
        }}
        .container {{
            padding: 20px;
            flex: 1;
            max-width: 800px;
            margin: auto;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            margin-top: 60px; /* Added space to account for fixed top bar */
        }}
        .status-bar {{
            background-color: {status_color};
            color: #fff;
            padding: 15px;
            text-align: center;
            font-size: 18px;
            border-top: 2px solid #ddd;
            box-shadow: 0 -2px 4px rgba(0, 0, 0, 0.1);
        }}
        .fixed-bar {{
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            background-color: #007bff;
            color: #fff;
            padding: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            z-index: 1000;
        }}
        .fixed-bar button {{
            background-color: #007bff;
            color: #fff;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            margin-top: 5px;
        }}
        .fixed-bar button:hover {{
            background-color: #0056b3;
        }}
        .fixed-bar a {{
            color: white;
            text-decoration: none;
            margin-left: 20px;
        }}
        .fixed-bar a:hover {{
            text-decoration: underline;
        }}
        .modal {{
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.4);
            justify-content: center;
            align-items: center;
        }}
        .modal-content {{
            background-color: #fff;
            margin: 15% auto;
            padding: 20px;
            border: 1px solid #888;
            width: 80%;
            max-width: 400px;
            border-radius: 8px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }}
        .close {{
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
        }}
        .close:hover,
        .close:focus {{
            color: black;
            text-decoration: none;
            cursor: pointer;
        }}
        button {{
            background-color: #007bff;
            color: #fff;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            margin-top: 5px;
        }}
        button:hover {{
            background-color: #0056b3;
        }}
        a {{
            color: #007bff;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
    </style>
    </head>
    <body>
        <div class="fixed-bar">
            <button id="loginBtn">Login</button>
            <a href="/history">History</a>
        </div>

        <div class="container">
            <h1>Phishing Email Checker</h1>
            <div class="status-bar">
                Status: {latest_results["status_code"].capitalize()}
            </div>
            {message_html}
        </div>

        <!-- The Modal -->
        <div id="loginModal" class="modal">
            <div class="modal-content">
                <span class="close">&times;</span>
                <form action="/submit" method="post">
                    <label for="email">Email Address:</label>
                    <input type="email" id="email" name="email" required>
                    <br>
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                    <br>
                    <button type="submit">Submit</button>
                </form>
            </div>
        </div>

        <script>
            var modal = document.getElementById("loginModal");

            // Get the button that opens the modal
            var btn = document.getElementById("loginBtn");

            // Get the <span> element that closes the modal
            var span = document.getElementsByClassName("close")[0];

            // When the user clicks the button, open the modal 
            btn.onclick = function() {{
                modal.style.display = "block";
            }}

            // When the user clicks on <span> (x), close the modal
            span.onclick = function() {{
                modal.style.display = "none";
            }}

            // When the user clicks anywhere outside of the modal, close it
            window.onclick = function(event) {{
                if (event.target == modal) {{
                    modal.style.display = "none";
                }}
            }}
        </script>
    </body>
    </html>


    """

    return render_template_string(html)

@app.route('/submit', methods=['POST'])
def submit():
    global email_address, password
    
    email_address = request.form['email']
    password = request.form['password']
    
    check_phishing_emails()
    
    return index()

@app.route('/generate-report')
def generate_report():
    message = request.args.get('message', '')
    if not message:
        return "No message to report.", 400

    file_name = save_report_to_file(message)
    return send_from_directory(REPORTS_DIR, file_name)

@app.route('/history')
def history():
    files = [f for f in os.listdir(REPORTS_DIR) if os.path.isfile(os.path.join(REPORTS_DIR, f))]
    files.sort(reverse=True)  # Sort files by modification time
    file_links = []
    for file in files:
        file_path = os.path.join(REPORTS_DIR, file)
        file_stat = os.stat(file_path)
        file_time = datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        file_links.append(f'<li><a href="/report/{file}">{file}</a> - {file_time}</li>')
    
    html = f"""
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <title>History</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 0;
                display: flex;
                flex-direction: column;
                min-height: 100vh;
                background: linear-gradient(to right, #f8f9fa, #e9ecef);
            }}
            .container {{
                padding: 20px;
                flex: 1;
                max-width: 800px;
                margin: auto;
                background: #fff;
                border-radius: 8px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            }}
            h1 {{
                margin-top: 0;
            }}
            a {{
                color: #007bff;
                text-decoration: none;
            }}
            a:hover {{
                text-decoration: underline;
            }}
        </style>
      </head>
      <body>
        <div class="container">
            <h1>Report History</h1>
            <ul>
                {"".join(file_links)}
            </ul>
            <br>
            <a href="/">Back to Home</a>
        </div>
      </body>
    </html>
    """
    return render_template_string(html)

@app.route('/report/<filename>')
def report(filename):
    return send_from_directory(REPORTS_DIR, filename)

if __name__ == '__main__':
    scheduler.add_job(check_phishing_emails, IntervalTrigger(seconds=5))
    scheduler.start()
    app.run(debug=True)
