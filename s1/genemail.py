import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os

# Email configuration
sender_email = "prajwalkumargutti4570@gmail.com"
receiver_email = "guttiprajwal4570@gmail.com"
subject = "Test Email from Python"
body = """
Dear recipient,

 "From": "legitimate@example.com",
    "Subject": "Urgent: Account Security Alert!",phishing
    "Body": "Dear Customer, please provide your password for security reasons: examplepassword123"phishing http://shadetreetechnology.com/V4/validation/a111aedc8ae390eabcfa130e041a10a4
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
smtp_password = "mhyyhckuwnwvqclp"

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
