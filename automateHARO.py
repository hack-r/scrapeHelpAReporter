import base64
import datetime
import os
import pytz
import re
import smtplib

from email.mime.text import MIMEText
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# IMAP settings for your email provider
imap_server = 'imap.gmail.com'
imap_user = 'youremail@gmail.com'

# SMTP settings for your email provider
smtp_server = 'smtp.gmail.com'
smtp_port = 587
smtp_user = 'youremail@gmail.com'

# Email message details
sender_email = 'youremail@gmail.com'
receiver_query_subject = 'Query regarding'
receiver_query_topics = ['topic1','topic2']

# Connect to the Gmail API
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send']
creds = None
if os.path.exists('token.json'):
    creds = Credentials.from_authorized_user_file('token.json', SCOPES)

if not creds or not creds.valid:
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
    else:
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)

    with open('token.json', 'w') as token:
        token.write(creds.to_json())

service = build('gmail', 'v1', credentials=creds)


# Search for emails matching the criteria within the last 4 hours
results = service.users().messages().list(userId='me', q='in:inbox after:4h (from:helpareporter.com)').execute()
messages = results.get('messages', [])

# Print some info to console
print(f"Found {len(messages)} matching emails")

# Create a holder for decoded emails
email_holder = ''

# Decode it!
msg = service.users().messages().get(userId='me', id=messages[0]['id']).execute()
payload = msg['payload']
if 'parts' in payload:
    for part in payload['parts']:
        if part['mimeType'] == 'multipart/alternative':
            for subpart in part['parts']:
                if subpart['mimeType'] == 'text/plain':
                    body = subpart['body']['data']
                    email_holder += base64.urlsafe_b64decode(body).decode('utf-8')
                    break
            break
        elif part['mimeType'] == 'text/plain':
            body = part['body']['data']
            email_holder += base64.urlsafe_b64decode(body).decode('utf-8')
            break

# Loop through the lines of the email and check for any topics
result_dict = {}
for i, line in enumerate(email_holder.split('\n')):
    for topic in receiver_query_topics:
        # Check for an exact match
        if topic.lower() in line.lower():
            print(f"Line {i+1}: {line}")
            # If Summary: is in the matched line, extract the summary
            if 'Summary: ' in line:
                summary = line.split('Summary: ')[-1]
            # If Summary: is not in the matched line, find the nearest preceding occurrence
            else:
                for j in range(i-1, -1, -1):
                    if 'Summary: ' in email_holder.split('\n')[j]:
                        summary = email_holder.split('\n')[j].split('Summary: ')[-1]
                        break
            # Find the email address following the summary and add it to the result dictionary
            for k in range(i+1, i+16):
                email_address = re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', email_holder.split('\n')[k])
                if email_address:
                    result_dict[summary] = email_address.group()
                    break
            break
        # Check for a pluralized match
        elif topic.lower() in line.lower()[:-1]:
            print(f"Line {i+1}: {line}")
            # If Summary: is in the matched line, extract the summary
            if 'Summary: ' in line:
                summary = line.split('Summary: ')[-1]
            # If Summary: is not in the matched line, find the nearest preceding occurrence
            else:
                for j in range(i-1, -1, -1):
                    if 'Summary: ' in email_holder.split('\n')[j]:
                        summary = email_holder.split('\n')[j].split('Summary: ')[-1]
                        break
            # Find the email address following the summary and add it to the result dictionary
            for k in range(i+1, i+16):
                email_address = re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', email_holder.split('\n')[k])
                if email_address:
                    result_dict[summary] = email_address.group()
                    break
            break
        # Check for a substring match
        elif ' ' + topic.lower()[:6] in line.lower():
            print(f"Line {i+1}: {line}")
            # If Summary: is in the matched line, extract the summary
            if 'Summary: ' in line:
                summary = line.split('Summary: ')[-1]
            # If Summary: is not in the matched line, find the nearest preceding occurrence
            else:
                for j in range(i-1, -1, -1):
                    if 'Summary: ' in email_holder.split('\n')[j]:
                        summary = email_holder.split('\n')[j].split('Summary: ')[-1]
                        break
            # Find the email address following the summary and add it to the result dictionary
            for k in range(i+1, i+16):
                email_address = re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', email_holder.split('\n')[k])
                if email_address:
                    result_dict[summary] = email_address.group()
                    break
            break

# Print the result dictionary
print(result_dict)
email_dict=result_dict

# Loop through the result dictionary and send an email for each entry
for key, value in email_dict.items():
    # Construct the email message
    key = key.replace('\n', '')
    subject = 'HARO Response - ' + key
    message = f"Dear Reporter,\n\nI am a subscriber to HARO. I have written a Python-language computer program that searches HARO for topics on which I'm an expert and sends initial emails to the reporters to see if they'd care to chat. Your topic - {key} - or its description contained terms indicating that it involves one of my areas of experience or expertise.\n\nIf you'd like to chat please just reply to this e-mail and my next response will not be automated. :) Just let me know how and where I'd be cited, if used as a source.\n\nMany thanks,\nJason"

    # Send the email
    try:
        message = MIMEText(message)
        message['to'] = value
        message['subject'] = subject
        create_message = {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}
        send_message = (service.users().messages().send(userId='me', body=create_message).execute())
        print(f'Sent email to {value} with topic {key}.')
    except HttpError as error:
        print(F'An error occurred: {error}')
        send_message = None

# Send summary email
summary_message = 'The following emails were sent:\n\n'

for key, value in result_dict.items():
    summary_message += f'{key}:\n{value}\n\n'
subject = f"Press Automation Report: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')}"
try:
    message = MIMEText(summary_message)
    message['to'] = 'youremail@gmail.com'
    message['subject'] = subject
    create_message = {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}
    send_message = (service.users().messages().send(userId='me', body=create_message).execute())
    print('Sent summary email.')
except HttpError as error:
    print(F'An error occurred: {error}')
    send_message = None
