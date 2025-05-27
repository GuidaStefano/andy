import os
from flask import Flask, redirect, url_for, session, request, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import config

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///andy.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.urandom(24) # Needed for session management
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Text, primary_key=True) # Google User ID
    email = db.Column(db.Text, unique=True, nullable=False)
    access_token = db.Column(db.Text, nullable=False)
    refresh_token = db.Column(db.Text, nullable=True)
    openai_api_key = db.Column(db.Text, nullable=True)
    last_processed_email_id = db.Column(db.Text, nullable=True)

class CachedEmail(db.Model):
    __tablename__ = 'cached_emails'
    id = db.Column(db.Text, primary_key=True)
    user_id = db.Column(db.Text, db.ForeignKey('users.id'))
    sender = db.Column(db.Text)
    subject = db.Column(db.Text)
    snippet = db.Column(db.Text)
    received_at = db.Column(db.DateTime) # Ensure this is a DateTime column

class CachedCalendarEvent(db.Model):
    __tablename__ = 'cached_calendar_events'
    id = db.Column(db.Text, primary_key=True)
    user_id = db.Column(db.Text, db.ForeignKey('users.id'))
    title = db.Column(db.Text)
    start_time = db.Column(db.DateTime) # Ensure this is a DateTime column
    end_time = db.Column(db.DateTime) # Ensure this is a DateTime column

class NotifiedEventLog(db.Model):
    __tablename__ = 'notified_event_log'
    event_id = db.Column(db.Text, primary_key=True)
    user_id = db.Column(db.Text, db.ForeignKey('users.id'), primary_key=True)
    notified_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    # Define a relationship to User if needed, though not strictly necessary for this use case
    # user = db.relationship('User', backref=db.backref('notified_events', lazy=True))

class RecentActivity(db.Model):
    __tablename__ = 'recent_activities'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Text, db.ForeignKey('users.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    activity_type = db.Column(db.Text, nullable=False) # e.g., "Email Sent", "Event Notification", "Email Notification"
    description = db.Column(db.Text, nullable=False) # e.g., "Replied to: 'Project Update'", "Upcoming: 'Team Meeting'"

    user = db.relationship('User', backref=db.backref('activities', lazy='dynamic'))

@app.route('/')
def index():
    if 'credentials' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login/google')
def login_google():
    flow = Flow.from_client_secrets_file(
        client_secrets_file=None,  # Using client_config instead
        client_config={
            "web": {
                "client_id": config.GOOGLE_CLIENT_ID,
                "client_secret": config.GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [request.host_url.rstrip('/') + config.REDIRECT_URI],
                "javascript_origins": [request.host_url.rstrip('/')]
            }
        },
        scopes=config.SCOPES,
        redirect_uri=request.host_url.rstrip('/') + config.REDIRECT_URI
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        prompt='consent',  # Force to get refresh_token every time
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)

@app.route(config.REDIRECT_URI)
def oauth2callback():
    state = session.pop('state', None)
    if not state or state != request.args.get('state'):
        return "State mismatch error. Please try logging in again.", 400

    flow = Flow.from_client_secrets_file(
        client_secrets_file=None, # Using client_config instead
         client_config={
            "web": {
                "client_id": config.GOOGLE_CLIENT_ID,
                "client_secret": config.GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [request.host_url.rstrip('/') + config.REDIRECT_URI],
                "javascript_origins": [request.host_url.rstrip('/')]
            }
        },
        scopes=config.SCOPES,
        redirect_uri=request.host_url.rstrip('/') + config.REDIRECT_URI,
        state=state
    )
    try:
        flow.fetch_token(authorization_response=request.url)
    except Exception as e:
        return f"Failed to fetch token: {str(e)}", 400

    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

    # Fetch user info
    try:
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        user_id = user_info['id']
        email = user_info['email']
    session['user_email'] = email # Store email in session for convenience
    except Exception as e:
        return f"Failed to fetch user info: {str(e)}", 400

    # Store user in database
    user = User.query.get(user_id)
    if user:
        user.access_token = credentials.token
        user.refresh_token = credentials.refresh_token # Update refresh token if a new one is provided
        user.email = email # Update email in case it changed (unlikely for Google ID)
    else:
        user = User(
            id=user_id,
            email=email,
            access_token=credentials.token,
            refresh_token=credentials.refresh_token
        )
        db.session.add(user)
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return f"Database error: {str(e)}", 500
    
    session['user_id'] = user_id # Store user_id in session for later use

    return redirect(url_for('dashboard'))

@app.route('/dashboard')
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import datetime # For timeMin
from cryptography.fernet import Fernet, InvalidToken

# Initialize Fernet with the key from config
if hasattr(config, 'ENCRYPTION_KEY') and config.ENCRYPTION_KEY:
    cipher_suite = Fernet(config.ENCRYPTION_KEY.encode())
else:
    print("CRITICAL: ENCRYPTION_KEY not set in config.py or is empty. API key encryption will not function.")
    cipher_suite = None 

def encrypt_data(data):
    if not cipher_suite:
        # This condition should ideally prevent the app from starting or clearly indicate a critical failure.
        raise ValueError("Encryption key not configured. Cannot encrypt data.")
    if data is None: # Explicitly handle None if it's a possible input
        return None
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    if not cipher_suite:
        raise ValueError("Encryption key not configured. Cannot decrypt data.")
    if encrypted_data is None: # Explicitly handle None
        return None
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except InvalidToken:
        # Log this event, as it might indicate data corruption or a key mismatch.
        print(f"Error: Invalid token during decryption. Data may be corrupted or key mismatch for: {encrypted_data[:20]}...")
        return None # Return None to indicate decryption failure

def get_credentials():
    if 'user_id' not in session:
        return None
    if 'user_id' not in session:
        return None
    user = User.query.get(session['user_id'])
    if not user:
        return None

    if not cipher_suite: # Cannot proceed without encryption utility
        print("Critical: Cipher suite not initialized. Cannot decrypt tokens.")
        return None

    decrypted_access_token = decrypt_data(user.access_token)
    decrypted_refresh_token = decrypt_data(user.refresh_token)

    if not decrypted_access_token:
        # This is a critical error if an access token was expected to be present and decryptable.
        # It might mean the token was never set, was cleared, or is corrupted.
        print(f"Warning: Could not decrypt access token for user {user.id}. Re-authentication might be needed.")
        # Depending on the app's flow, might need to force re-login or handle this state.
        # For now, we'll try to proceed, but API calls will likely fail if token is truly needed.
        # Consider if user.access_token was None to begin with vs. decryption failure.
        # If user.access_token was not None but decrypted_access_token is None, it's a decryption error.
        if user.access_token is not None: # Indicates a decryption failure specifically
             print(f"Critical Decryption Failure: Access token for user {user.id} could not be decrypted.")
             # session.clear() # Example: Force re-login
             # return redirect(url_for('login_google'))
             return None


    creds = Credentials(
        token=decrypted_access_token, # Use decrypted token
        refresh_token=decrypted_refresh_token, # Use decrypted token
        token_uri=config.TOKEN_URI if hasattr(config, 'TOKEN_URI') else "https://oauth2.googleapis.com/token",
        client_id=config.GOOGLE_CLIENT_ID,
        client_secret=config.GOOGLE_CLIENT_SECRET,
        scopes=config.SCOPES
    )

    if creds and creds.expired and creds.refresh_token: # Refresh token must exist to refresh
        try:
            creds.refresh(Request())
            # Re-encrypt the new tokens before saving
            user.access_token = encrypt_data(creds.token)
            if creds.refresh_token and creds.refresh_token != decrypted_refresh_token:
                 user.refresh_token = encrypt_data(creds.refresh_token)
            db.session.commit()
            
            # Update session credentials if they are stored there (consider security implications)
            # Storing plain tokens in session is generally discouraged if not strictly necessary.
            # If needed, ensure session is secure (HTTPS, HttpOnly cookies, etc.)
            session['credentials'] = {
                'token': creds.token, # Temporarily plain for current request cycle if needed by client
                'refresh_token': creds.refresh_token, # Same consideration
                'token_uri': creds.token_uri,
                'client_id': creds.client_id,
                'client_secret': creds.client_secret,
                'scopes': creds.scopes
            }
        except Exception as e:
            print(f"Error refreshing token for user {user.id}: {e}")
            # If refresh fails, existing (decrypted) tokens might still be valid for a short period,
            # or they might be totally invalid. Returning None or the old creds depends on desired behavior.
            # Forcing re-login on persistent refresh failure is a safe option.
            # For example, by clearing the session or parts of it.
            # session.pop('credentials', None) # Clear potentially stale session credentials
            return None # Indicate that token refresh failed
    return creds

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    user_email = session.get('user_email', 'User')
    return render_template('dashboard.html', user_email=user_email)


@app.route('/api/calendar/events')
def get_calendar_events():
    credentials = get_credentials()
    if not credentials:
        return {"error": "Unauthorized"}, 401

    try:
        service = build('calendar', 'v3', credentials=credentials)
        now = datetime.datetime.utcnow().isoformat() + 'Z'  # 'Z' indicates UTC time
        events_result = service.events().list(
            calendarId='primary',
            timeMin=now,
            maxResults=10,
            singleEvents=True,
            orderBy='startTime'
        ).execute()
        events = events_result.get('items', [])

        processed_events = []
        for event in events:
            start = event['start'].get('dateTime', event['start'].get('date'))
            end = event['end'].get('dateTime', event['end'].get('date'))
            processed_events.append({
                'summary': event.get('summary', 'No Title'),
                'start': start,
                'end': end,
                'link': event.get('htmlLink')
            })
        return {"events": processed_events}

    except HttpError as error:
        print(f'An API error occurred: {error}')
        if error.resp.status == 401: # Token issue
             # Attempt to refresh token might have failed or was not triggered correctly
             # Forcing re-login might be an option here if get_credentials() itself doesn't handle it robustly
            return {"error": "Google API authorization error. Please try logging in again.", "details": str(error)}, 401
        return {"error": "Failed to fetch calendar events", "details": str(error)}, 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return {"error": "An unexpected error occurred", "details": str(e)}, 500

@app.route('/api/gmail/emails')
def get_gmail_emails():
    credentials = get_credentials()
    if not credentials:
        return {"error": "Unauthorized"}, 401

    try:
        service = build('gmail', 'v1', credentials=credentials)
        
        # List messages in INBOX, get latest 10
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=10).execute()
        messages = results.get('messages', [])

        if not messages:
            return {"emails": [], "message": "No recent emails found."}

        processed_emails = []
        for message_info in messages:
            msg_id = message_info['id']
            # Fetch message details (metadata only for now for efficiency)
            # To get snippet, change format to 'full' or add 'snippet' to metadataHeaders if API supports
            msg = service.users().messages().get(userId='me', id=msg_id, format='metadata', metadataHeaders=['Subject', 'From', 'Date']).execute()
            
            payload = msg.get('payload', {})
            headers = payload.get('headers', [])
            
            email_data = {
                'id': msg_id,
                'snippet': msg.get('snippet', '') # Snippet is available directly if format='metadata' or 'full'
            }
            
            for header in headers:
                name = header.get('name').lower()
                if name == 'subject':
                    email_data['subject'] = header.get('value')
                elif name == 'from':
                    email_data['from'] = header.get('value')
                elif name == 'date':
                    email_data['date'] = header.get('value')
            
            # Ensure all core fields are present
            if not all(k in email_data for k in ['subject', 'from', 'date']):
                print(f"Skipping email due to missing core headers: {msg_id}")
                continue

            processed_emails.append(email_data)
            
        return {"emails": processed_emails}

    except HttpError as error:
        print(f'An API error occurred (Gmail): {error}')
        if error.resp.status == 401:
            return {"error": "Google API authorization error. Please try logging in again.", "details": str(error)}, 401
        return {"error": "Failed to fetch Gmail emails", "details": str(error)}, 500
    except Exception as e:
        print(f"An unexpected error occurred (Gmail): {e}")
        return {"error": "An unexpected error occurred while fetching emails", "details": str(e)}, 500

@app.route('/api/openai/apikey', methods=['POST'])
def save_openai_apikey():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    if not cipher_suite: # Check if encryption is available
        return jsonify({"error": "Server encryption not configured."}), 500
    
    data = request.get_json()
    if not data or 'api_key' not in data:
        return jsonify({"error": "API key is required"}), 400

    api_key = data['api_key']
    if not api_key or not api_key.strip(): # Check for empty or whitespace-only key
        return jsonify({"error": "API key cannot be empty"}), 400

    user = User.query.get(session['user_id'])
    if not user: # Should ideally not happen if session user_id is valid
        return jsonify({"error": "User not found"}), 404

    try:
        user.openai_api_key = encrypt_data(api_key)
        db.session.commit()
        return jsonify({"message": "OpenAI API Key saved successfully."})
    except ValueError as ve: # Catch specific error from encrypt_data if key isn't configured
        print(f"Encryption configuration error: {ve}")
        return jsonify({"error": "Failed to save API key due to server configuration error."}), 500
    except Exception as e:
        db.session.rollback()
        print(f"Error saving API key for user {session['user_id']}: {e}")
        return jsonify({"error": "Failed to save API key due to a server error."}), 500

@app.route('/api/openai/apikey/status', methods=['GET'])
def get_openai_apikey_status():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    if not cipher_suite: # Check if decryption is possible
        return jsonify({"error": "Server encryption not configured, cannot check API key status."}), 500

    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({"error": "User not found"}), 404

    api_key_is_set = False
    if user.openai_api_key:
        decrypted_key = decrypt_data(user.openai_api_key)
        if decrypted_key: # Successfully decrypted means it's set and valid (in terms of decryption)
            api_key_is_set = True
        else:
            # Key is present but not decryptable - could be corruption or old format
            print(f"Warning: OpenAI API key for user {user.id} exists but could not be decrypted.")
            # Optionally: clear the corrupted key here if that's the desired policy
            # user.openai_api_key = None
            # db.session.commit()
            
    return jsonify({"is_set": api_key_is_set})

from openai import OpenAI
import base64 # For decoding email body

def get_email_body(payload):
    """
    Recursively extracts the text/plain part of an email payload.
    Handles multipart messages.
    """
    if payload.get('mimeType') == 'text/plain' and payload.get('body') and payload.get('body').get('data'):
        return base64.urlsafe_b64decode(payload['body']['data'].encode('ASCII')).decode('utf-8')
    
    if 'parts' in payload:
        for part in payload['parts']:
            body = get_email_body(part)
            if body:
                return body
    return None


@app.route('/api/gmail/check_new_email')
def check_new_email():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({"error": "User not found"}), 404

    credentials = get_credentials()
    if not credentials:
        # get_credentials already handles logging and potential session clearing for critical token issues
        return jsonify({"error": "Failed to authenticate with Google. Please try logging in again."}), 401

    decrypted_openai_api_key = None
    if user.openai_api_key:
        decrypted_openai_api_key = decrypt_data(user.openai_api_key)
    
    if not decrypted_openai_api_key:
        return jsonify({"message": "OpenAI API key not set or invalid. Cannot process emails."}), 200 # Not an error, but a state

    try:
        gmail_service = build('gmail', 'v1', credentials=credentials)
        
        # Fetch the most recent email in the INBOX
        list_params = {'userId': 'me', 'labelIds': ['INBOX'], 'maxResults': 1}
        if user.last_processed_email_id:
            # This 'q' parameter looks for emails *newer than* a given message ID by using its internal date.
            # A more robust way might be to fetch messages and then filter by date if message IDs aren't strictly sequential by time.
            # However, for many cases, just getting the latest and comparing ID is simpler.
            # Gmail API does not directly support "newer than message ID". We fetch the latest and compare.
            pass # We'll fetch the latest and compare its ID.

        results = gmail_service.users().messages().list(**list_params).execute()
        messages = results.get('messages', [])

        if not messages:
            return jsonify({"message": "No new emails found."}), 200

        latest_email_id = messages[0]['id']

        if user.last_processed_email_id == latest_email_id:
            return jsonify({"message": "No new emails since last check."}), 200

        # New email found
        user.last_processed_email_id = latest_email_id
        db.session.commit()

        msg = gmail_service.users().messages().get(userId='me', id=latest_email_id, format='full').execute()
        
        email_subject = ""
        email_from_header = "" # Full From header
        from_email_address = "" # Parsed email address

        for header in msg['payload']['headers']:
            if header['name'].lower() == 'subject':
                email_subject = header['value']
            if header['name'].lower() == 'from':
                email_from_header = header['value']
                # Basic parsing for email address from "Sender Name <email@example.com>"
                if '<' in email_from_header and '>' in email_from_header:
                    from_email_address = email_from_header.split('<')[1].split('>')[0]
                else: # If it's just an email address
                    from_email_address = email_from_header 
        
        email_body_content = get_email_body(msg['payload'])

        if not email_body_content:
            return jsonify({"error": "Could not extract email body."}), 500

        # Call OpenAI
        try:
            client = OpenAI(api_key=decrypted_openai_api_key)
            prompt_text = f"""
Summarize the following email and generate 2-3 concise suggested replies.
Format your response as a JSON object with three keys: "summary", "suggested_reply_1", "suggested_reply_2".
If you want to suggest a third reply, use key "suggested_reply_3".

Email Body:
{email_body_content[:4000]} 
""" # Limit body length to avoid exceeding token limits

            chat_completion = client.chat.completions.create(
                messages=[
                    {
                        "role": "user",
                        "content": prompt_text,
                    }
                ],
                model="gpt-3.5-turbo", # Or your preferred model
                response_format={ "type": "json_object" }
            )
            
            ai_response_content = chat_completion.choices[0].message.content
            # Attempt to parse the JSON string from OpenAI
            import json
            try:
                ai_data = json.loads(ai_response_content)
            except json.JSONDecodeError:
                print(f"OpenAI returned non-JSON response: {ai_response_content}")
                # Fallback: try to extract summary and at least one reply if possible, or return generic error
                # This part needs careful implementation if non-JSON is common.
                # For now, we assume JSON format is usually respected by the model with `response_format`.
                return jsonify({"error": "AI response was not in the expected JSON format."}), 500


        except Exception as openai_error: # More specific OpenAI errors can be caught
            print(f"OpenAI API error: {openai_error}")
            return jsonify({"error": f"OpenAI API error: {str(openai_error)}"}), 500

        return jsonify({
            "new_email": True,
            "id": latest_email_id, # This is the message_id
            "thread_id": msg.get('threadId'),
            "from_header": email_from_header, # Full From: header
            "from_email": from_email_address, # Parsed email address for 'to' field in reply
            "subject": email_subject,
            "summary": ai_data.get("summary"),
            "suggested_replies": [
                ai_data.get("suggested_reply_1"),
                ai_data.get("suggested_reply_2"),
                ai_data.get("suggested_reply_3") # Will be None if not present, filter out later
            ].copy() # Use .copy() if you plan to modify this list later e.g. filter out Nones
        })

        # Log activity for new email notification shown
        try:
            activity_log = RecentActivity(
                user_id=user_id,
                activity_type="Email Notification Shown",
                description=f"New Email: '{email_subject}' from {from_email_address}"
            )
            db.session.add(activity_log)
            db.session.commit()
        except Exception as log_error:
            print(f"Error logging 'Email Notification Shown' activity: {log_error}")
            db.session.rollback()

        return response_data # Return the previously constructed response_data

    except HttpError as error:
        print(f'An API error occurred (Gmail check_new_email): {error}')
        # Handle 401 specifically if token refresh failed or token became invalid
        if error.resp.status == 401:
            # Potentially clear session or prompt re-login
            session.pop('credentials', None) # Example: clear stale session credentials
            return jsonify({"error": "Google API authorization error. Please log in again.", "details": str(error)}), 401
        return jsonify({"error": "Failed to check/process new email", "details": str(error)}), 500
    except Exception as e:
        db.session.rollback() # Rollback DB changes if any error occurs after DB ops
        print(f"An unexpected error occurred in check_new_email: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

from email.mime.text import MIMEText
import base64

@app.route('/api/gmail/send_reply', methods=['POST'])
def send_reply():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({"error": "User not found"}), 404

    credentials = get_credentials()
    if not credentials:
        return jsonify({"error": "Failed to authenticate with Google. Please try logging in again."}), 401

    data = request.get_json()
    required_fields = ['to', 'subject', 'body', 'thread_id', 'message_id']
    if not all(field in data for field in required_fields):
        missing_fields = [field for field in required_fields if field not in data]
        return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400

    try:
        gmail_service = build('gmail', 'v1', credentials=credentials)

        # Create the email message
        message = MIMEText(data['body'])
        message['to'] = data['to']
        # Ensure subject starts with "Re: " - if it already does, don't add another one.
        if data['subject'].lower().startswith("re:"):
            message['subject'] = data['subject']
        else:
            message['subject'] = f"Re: {data['subject']}"
        
        # Set In-Reply-To and References headers for correct threading
        message['In-Reply-To'] = data['message_id']
        # References header should include the original message_id and potentially prior references.
        # For simplicity, we'll start with just the message_id. Gmail is usually good at threading with In-Reply-To.
        # A more robust solution would be to get the original message's References header and append to it.
        message['References'] = data['message_id'] 

        # The message needs to be sent with the threadId to be part of the correct thread.
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        send_message_request_body = {
            'raw': raw_message,
            'threadId': data['thread_id']
        }

        sent_message = gmail_service.users().messages().send(userId='me', body=send_message_request_body).execute()
        
        # Log activity
        try:
            activity_log = RecentActivity(
                user_id=user_id,
                activity_type="Email Sent",
                description=f"Replied to: '{message['subject']}' (To: {message['to']})"
            )
            db.session.add(activity_log)
            db.session.commit()
        except Exception as log_error:
            print(f"Error logging 'Email Sent' activity: {log_error}")
            db.session.rollback() # Rollback logging error, but reply was successful

        return jsonify({"message": "Reply sent successfully!", "message_id": sent_message['id']})

    except HttpError as error:
        print(f'An API error occurred while sending reply: {error}')
        if error.resp.status == 401:
            return jsonify({"error": "Google API authorization error. Please try logging in again.", "details": str(error)}), 401
        return jsonify({"error": "Failed to send reply due to Google API error.", "details": str(error)}), 500
    except Exception as e:
        print(f"An unexpected error occurred while sending reply: {e}")
        return jsonify({"error": "An unexpected error occurred while sending reply.", "details": str(e)}), 500


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Ensure tables are created
    app.run(debug=True, port=5000) # Using port 5000 as default


from sqlalchemy import and_, desc # For composite primary key queries and ordering

@app.route('/api/calendar/check_upcoming_event')
def check_upcoming_event():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = session['user_id']
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    credentials = get_credentials()
    if not credentials:
        return jsonify({"error": "Failed to authenticate with Google. Please try logging in again."}), 401

    try:
        service = build('calendar', 'v3', credentials=credentials)
        
        # Define time window for "upcoming" events
        now_utc = datetime.datetime.utcnow()
        time_min_utc = now_utc.isoformat() + 'Z'
        # Look for events starting in the next 30 minutes
        time_max_utc = (now_utc + datetime.timedelta(minutes=30)).isoformat() + 'Z'

        events_result = service.events().list(
            calendarId='primary',
            timeMin=time_min_utc,
            timeMax=time_max_utc,
            maxResults=5, # Get a few, in case some were already notified
            singleEvents=True,
            orderBy='startTime'
        ).execute()
        
        events = events_result.get('items', [])

        if not events:
            return jsonify({"message": "No upcoming events in the next 30 minutes."}), 200

        upcoming_unnotified_event = None
        for event in events:
            event_id = event['id']
            
            # Check if notification for this event_id and user_id already exists
            existing_log = NotifiedEventLog.query.filter(
                and_(NotifiedEventLog.event_id == event_id, NotifiedEventLog.user_id == user_id)
            ).first()

            if not existing_log:
                # This is a new, upcoming, un-notified event
                upcoming_unnotified_event = event
                break # Process this one
        
        if upcoming_unnotified_event:
            # Log this event as notified
            new_log_entry = NotifiedEventLog(event_id=upcoming_unnotified_event['id'], user_id=user_id)
            db.session.add(new_log_entry)
            db.session.commit()

            start_info = upcoming_unnotified_event['start'].get('dateTime', upcoming_unnotified_event['start'].get('date'))
            end_info = upcoming_unnotified_event['end'].get('dateTime', upcoming_unnotified_event['end'].get('date'))
            
            attendees_list = [att['email'] for att in upcoming_unnotified_event.get('attendees', []) if 'email' in att]


            return jsonify({
                "upcoming_event_found": True,
                "id": upcoming_unnotified_event['id'],
                "title": upcoming_unnotified_event.get('summary', 'No Title'),
                "start_time": start_info,
                "end_time": end_info,
                "attendees": attendees_list,
                "html_link": upcoming_unnotified_event.get('htmlLink'),
                "hangout_link": upcoming_unnotified_event.get('hangoutLink') # Google Meet link
            }
            
            # Log activity
            try:
                activity_log = RecentActivity(
                    user_id=user_id,
                    activity_type="Event Notification Shown",
                    description=f"Upcoming Event: '{response_data['title']}' at {response_data['start_time']}"
                )
                db.session.add(activity_log)
                db.session.commit()
            except Exception as log_error:
                print(f"Error logging 'Event Notification Shown' activity: {log_error}")
                db.session.rollback()

            return jsonify(response_data)
        else:
            return jsonify({"message": "All upcoming events in the next 30 minutes have already been notified."}), 200

    except HttpError as error:
        print(f'An API error occurred (check_upcoming_event): {error}')
        if error.resp.status == 401:
            return jsonify({"error": "Google API authorization error. Please try logging in again.", "details": str(error)}), 401
        return jsonify({"error": "Failed to check for upcoming events.", "details": str(error)}), 500
    except Exception as e:
        db.session.rollback()
        print(f"An unexpected error occurred in check_upcoming_event: {e}")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

@app.route('/api/dashboard/recent_activities')
def get_recent_activities():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_id = session['user_id']
    try:
        activities = RecentActivity.query.filter_by(user_id=user_id)\
                                         .order_by(desc(RecentActivity.timestamp))\
                                         .limit(10).all() # Get last 10 activities
        
        result = [{
            "timestamp": activity.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"), # Format for better readability
            "activity_type": activity.activity_type,
            "description": activity.description
        } for activity in activities]
        
        return jsonify(activities=result)

    except Exception as e:
        print(f"Error fetching recent activities for user {user_id}: {e}")
        return jsonify({"error": "Failed to fetch recent activities."}), 500
