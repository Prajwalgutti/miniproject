import imaplib
import email
from email.header import decode_header
from datetime import datetime

# Function to decode email headers
def decode_email_header(header):
    decoded_header = decode_header(header)
    decoded_text = []
    for part, encoding in decoded_header:
        if isinstance(part, bytes):
            decoded_text.append(part.decode(encoding or 'utf-8'))
        else:
            decoded_text.append(part)
    return ''.join(decoded_text)

# Function to detect phishing emails
def detect_phishing(subject, body):
    # Example phishing detection logic (replace with your own implementation)
    phishing_keywords = ['urgent', 'verify', 'account suspension', 'password reset']
    for keyword in phishing_keywords:
        if keyword in subject.lower() or keyword in body.lower():
            return True
    return False

# Connect to the IMAP server
imap_server = "imap.gmail.com"
email_address = "prajwalkumargutti4570@gmail.com"
password = "dkrmikadkgtgbmpv"
imap = imaplib.IMAP4_SSL(imap_server)
imap.login(email_address, password)

# Select the inbox
imap.select("INBOX")

# Get the current date
current_date = datetime.now().strftime("%d-%b-%Y")

# Construct the search query
search_query = f'(UNSEEN) (SINCE "{current_date}")'

# Search for unread emails since the current date
status, messages = imap.search(None, search_query)
if status == "OK":
    for num in messages[0].split():
        # Fetch the email data
        status, data = imap.fetch(num, "(RFC822)")
        if status == "OK":
            raw_email = data[0][1]
            email_message = email.message_from_bytes(raw_email)
            subject = decode_email_header(email_message["Subject"])
            sender = decode_email_header(email_message["From"])
            body = ""
            for part in email_message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    payload = part.get_payload(decode=True)
                    if payload is not None:
                        # Decode payload with error handling
                        payload_text = payload.decode(errors='replace')
                        body += payload_text

            # Apply phishing detection logic
            if detect_phishing(subject, body):
                print(f"Warning: Phishing email detected from {sender} with subject: {subject}")
            else:
                print(f"Safe email from {sender} with subject: {subject}")

# Close the connection
imap.logout()
