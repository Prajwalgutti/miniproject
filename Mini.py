import streamlit as st
import imaplib
import email
from email.header import decode_header
from datetime import datetime
import time

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

# Streamlit interface
st.title("Email Phishing Detection")

email_address = st.text_input("Email Address")
password = st.text_input("Password", type="password")
check_interval = st.number_input("Check Interval (seconds)", min_value=10, value=60)

if st.button("Start Monitoring"):
    if email_address and password:
        try:
            # Connect to the IMAP server
            imap_server = "imap.gmail.com"
            imap = imaplib.IMAP4_SSL(imap_server)
            imap.login(email_address, password)

            while True:
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
                                st.warning(f"Phishing email detected from {sender} with subject: {subject}")
                            else:
                                st.success(f"Safe email from {sender} with subject: {subject}")
                else:
                    st.info("No new emails found.")

                # Wait for the specified interval before checking again
                time.sleep(check_interval)
        except Exception as e:
            st.error(f"An error occurred: {str(e)}")
    else:
        st.error("Please enter both email address and password.")
