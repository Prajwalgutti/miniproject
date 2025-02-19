import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os

# Email configuration for the spam-like email
sender_email = "prajwalkumargutti4570@gmail.com"
receiver_email = "guttiprajwal4570@gmail.com"
subject = "Urgent: Immediate Action Required!"
body = """
Dear Customer,

Your account has been compromised. To secure your account, please confirm your login details immediately.

Click here to reset your password: http://www.crestonwood.com/router.php

Thank you,
Fake Support Team
"""

# Create a multipart message
message = MIMEMultipart()
message["From"] = sender_email
message["To"] = receiver_email
message["Subject"] = subject

# Add body to email
message.attach(MIMEText(body, "plain"))

# Connect to the SMTP server (Gmail SMTP server used here)
smtp_server = "smtp.gmail.com"
smtp_port = 587  # Gmail SMTP port
smtp_username = "guttiprajwal4570@gmail.com"
# Fetch password from environment variable (set this in your environment)
smtp_password = "mhyyhckuwnwvqclp"  # It's recommended to use an environment variable

try:
    # Start TLS encryption
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    # Login to the email server
    server.login(smtp_username, smtp_password)
    
    # Send email
    server.sendmail(sender_email, receiver_email, message.as_string())
    
    # Close the SMTP server connection
    server.quit()
    
    print("Email sent successfully!")
except Exception as e:
    print(f"Failed to send email: {e}")
