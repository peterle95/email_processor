import os
import base64
import time
import logging
import asyncio
import re
import random
from dotenv import load_dotenv
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import requests
from requests.adapters import HTTPAdapter
from langdetect import detect
from email.mime.text import MIMEText
from email.utils import parseaddr
from groq import Groq

# Load environment variables
load_dotenv()

# Constants
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.modify']
CLIENT_SECRET_FILE = os.getenv('CLIENT_SECRET_FILE')
GROQ_API_KEY = os.getenv('GROQ_API_KEY')

# Setup logging
logging.basicConfig(filename='email_processor.log', level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')

# Add console logging
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger('').addHandler(console)

# Initialize Groq client
groq_client = Groq(api_key=GROQ_API_KEY)


def requests_retry_session(
    retries=3,
    backoff_factor=0.3,
    status_forcelist=(500, 502, 504),
    session=None,
):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def get_gmail_service(account_id):
    creds = None
    token_file = f'token_{account_id}.json'
    client_secret_file = os.getenv(f'CLIENT_SECRET_FILE_{account_id}')
    
    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = Flow.from_client_secrets_file(
                client_secret_file,
                scopes=SCOPES,
                redirect_uri='urn:ietf:wg:oauth:2.0:oob')

            auth_url, _ = flow.authorization_url(prompt='consent')
            
            print(f'Please go to this URL and authorize the application for account {account_id}: {auth_url}')
            code = input('Enter the authorization code: ')
            
            flow.fetch_token(code=code)
            creds = flow.credentials

        with open(token_file, 'w') as token:
            token.write(creds.to_json())

    return build('gmail', 'v1', credentials=creds)

def rate_limited(max_per_second):
    min_interval = 1.0 / max_per_second
    def decorate(func):
        last_time_called = [0.0]
        def rate_limited_function(*args, **kwargs):
            elapsed = time.perf_counter() - last_time_called[0]
            left_to_wait = min_interval - elapsed
            if left_to_wait > 0:
                time.sleep(left_to_wait)
            ret = func(*args, **kwargs)
            last_time_called[0] = time.perf_counter()
            return ret
        return rate_limited_function
    return decorate

def sanitize_email(email_data):
    # Remove sensitive information
    email_data.pop('from', None)
    email_data.pop('to', None)
    # Truncate body if it's too long
    if 'body' in email_data:
        email_data['body'] = email_data['body'][:1000] + '...' if len(email_data['body']) > 1000 else email_data['body']
    return email_data

@rate_limited(2)  # 2 calls per second

def fetch_emails(service, max_results=10):
    results = service.users().messages().list(userId='me', maxResults=max_results, labelIds=['INBOX'], q="is:unread").execute()
    messages = results.get('messages', [])
    
    emails = []
    for message in messages:
        msg = service.users().messages().get(userId='me', id=message['id']).execute()
        email_data = {}
        email_data['id'] = msg['id']
        email_data['snippet'] = msg['snippet']
        
        # Get the subject, sender, and full body
        headers = msg['payload']['headers']
        email_data['subject'] = next((header['value'] for header in headers if header['name'].lower() == 'subject'), 'No Subject')
        email_data['from'] = next((header['value'] for header in headers if header['name'].lower() == 'from'), 'Unknown Sender')
        
        # Fetch the full email body
        if 'parts' in msg['payload']:
            for part in msg['payload']['parts']:
                if part['mimeType'] == 'text/plain':
                    try:
                        email_data['body'] = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                    except UnicodeDecodeError:
                        email_data['body'] = base64.urlsafe_b64decode(part['body']['data']).decode('latin-1')
                    break
        elif 'body' in msg['payload'] and 'data' in msg['payload']['body']:
            try:
                email_data['body'] = base64.urlsafe_b64decode(msg['payload']['body']['data']).decode('utf-8')
            except UnicodeDecodeError:
                email_data['body'] = base64.urlsafe_b64decode(msg['payload']['body']['data']).decode('latin-1')
        else:
            email_data['body'] = "No readable content"
            logging.warning(f"No body found for email {email_data['id']}")
        
        emails.append(email_data)
    
    return emails

def safe_fetch_emails(service, max_results=10):
    try:
        return fetch_emails(service, max_results)
    except Exception as e:
        logging.error(f"Error fetching emails: {e}")
        return []

# Cache for email processing results
email_cache = {}

def basic_categorization(email_content, subject):
    full_text = (subject + " " + email_content).lower()
    
    categories = {
        "Urgent": ["urgent", "immediate", "asap", "emergency"],
        "Important": ["important", "priority", "attention"],
        "Finance": ["invoice", "payment", "bill", "subscription"],
        "Work": ["project", "meeting", "deadline", "report"],
        "Personal": ["family", "friend", "social", "invitation"],
        "Newsletter": ["newsletter", "update", "digest"]
    }
    
    for category, keywords in categories.items():
        if any(keyword in full_text for keyword in keywords):
            return category
    
    return "Regular"
    
async def generate_fallback_response(language, sender_name, category):
    templates = {
        "de": {
            "greeting": "Sehr geehrter {},".format(sender_name),
            "acknowledgment": "Vielen Dank für Ihre {} E-Mail.".format(category.lower()),
            "action": "Wir werden uns so schnell wie möglich mit Ihnen in Verbindung setzen.",
            "closing": "Mit freundlichen Grüßen,\nPeter Mölzer"
        },
        "en": {
            "greeting": "Dear {},".format(sender_name),
            "acknowledgment": "Thank you for your {} email.".format(category.lower()),
            "action": "We will get back to you as soon as possible.",
            "closing": "Best regards,\nPeter Mölzer"
        }
    }
    
    template = templates.get(language, templates["en"])
    return "\n\n".join([template["greeting"], template["acknowledgment"], template["action"], template["closing"]])

def detect_language(text):
    try:
        return detect(text)
    except:
        return 'en' 

async def process_single_email(email_data):
    email_content = email_data.get('body', email_data.get('snippet', ''))
    subject = email_data.get('subject', 'No Subject')
    sender = email_data.get('from', 'Unknown Sender')
    
    sender_name = sender.split('<')[0].strip()
    if not sender_name:
        sender_name = sender.split('@')[0]
    
    logging.info(f"Processing email: Subject: {subject[:30]}...")
    category = basic_categorization(email_content, subject)
    logging.info(f"Categorized email as: {category}")
    
    if category in ["Urgent", "Important"]:
        language = detect_language(email_content)
        response = await generate_response(subject, email_content, language, sender_name, category)
        return category, response
    else:
        return category, None

# Cache for email categorization and responses
category_cache = {}

def send_email(service, to, subject, body, from_account):
    message = create_message(from_account, to, subject, body)
    try:
        logging.info(f"Attempting to send email from account {from_account} to: {to}")
        logging.info(f"Message content: {message}")
        sent_message = service.users().messages().send(userId='me', body=message).execute()
        logging.info(f"Email sent successfully from account {from_account}. Message Id: {sent_message['id']}")
        return sent_message
    except Exception as e:
        logging.error(f"An error occurred while sending email from account {from_account}: {e}")
        return None

def create_message(sender, to, subject, message_text):
    message = MIMEText(message_text)
    message['to'] = parseaddr(to)[1]  # Extract just the email address
    message['from'] = sender
    message['subject'] = subject
    raw_message = base64.urlsafe_b64encode(message.as_string().encode('utf-8'))
    return {'raw': raw_message.decode('utf-8')}

async def process_emails_batch(emails, service, account_id, batch_size=2):
    for i in range(0, len(emails), batch_size):
        batch = emails[i:i+batch_size]
        tasks = [asyncio.create_task(process_single_email(email)) for email in batch]
        
        try:
            results = await asyncio.gather(*tasks)
        except Exception as e:
            logging.error(f"Error processing email batch: {e}")
            continue  # Skip to the next batch if there's an error
        
        for email, (category, response) in zip(batch, results):
            try:
                print(f"Account: {account_id}")
                print(f"Email ID: {email['id']}")
                print(f"Subject: {email.get('subject', 'No Subject')}")
                print(f"Category: {category}")
                if response:
                    print("Generated Response:")
                    print(response)
                    send_response = input("Do you want to send this response? (yes/no): ").lower()
                    if send_response == 'yes':
                        to_address = email.get('from', '')
                        subject = f"Re: {email.get('subject', 'No Subject')}"
                        result = send_email(service, to_address, subject, response, f'me')
                        if result:
                            print("Response sent successfully!")
                            await asyncio.sleep(5)  # Wait 5 seconds after sending
                        else:
                            print("Failed to send response.")
                    else:
                        print("Response not sent.")
                else:
                    print("No response generated for this category.")
                print("---")
            except Exception as e:
                logging.error(f"Error processing individual email: {e}")
        
        await asyncio.sleep(1)  # Small delay between batches
    
async def generate_response(subject, email_content, language, sender_name, category):
    prompt = f"""
    Generate a detailed and professional response to this {category} email. The response should be in {language} and address all points raised in the original email. Your response should:

    1. Start with an appropriate greeting addressing {sender_name}
    2. Acknowledge receipt of the email and its urgency
    3. Express serious concern about the reported issue
    4. Address each point raised in the original email, including:
       - Acknowledge the bug and its impact
       - Provide a preliminary timeline for addressing the issue
       - Outline immediate steps to be taken
       - Request any additional information needed
    5. Assure the sender that this is being treated as a top priority
    6. Provide contact information for immediate follow-up
    7. End with a professional closing

    Ensure the response is at least 150 words long and fully addresses the urgency and severity of the situation.

    Original Email:
    Subject: {subject}
    Content: {email_content}

    Response:
    """

    try:
        logging.info("Attempting to generate response using Groq")
        response = groq_client.chat.completions.create(
            model="mixtral-8x7b-32768",  # or another available model
            messages=[
                {"role": "system", "content": "You are a professional email assistant."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=1024,
            temperature=0.7
        )
        generated_text = response.choices[0].message.content.strip()
        logging.info(f"Response generated successfully. Length: {len(generated_text.split())} words")
        return generated_text
    except Exception as e:
        logging.error(f"Error generating response: {str(e)}")
        return await generate_fallback_response(language, sender_name, category)
    

async def main():
    logging.info("Script started")
    
    # Initialize services for both accounts
    service1 = get_gmail_service(1)
    service2 = get_gmail_service(2)
    logging.info("Gmail services initialized for both accounts")

    # Process emails from the first account
    emails1 = safe_fetch_emails(service1, max_results=10)
    logging.info(f"Fetched {len(emails1)} emails from account 1")
    await process_emails_batch(emails1, service1, 1, batch_size=3)

    # Process emails from the second account
    emails2 = safe_fetch_emails(service2, max_results=10)
    logging.info(f"Fetched {len(emails2)} emails from account 2")
    await process_emails_batch(emails2, service2, 2, batch_size=3)

    logging.info("Script completed")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    asyncio.run(main())
