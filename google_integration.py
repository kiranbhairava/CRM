# google_integration.py - Google Workspace Integration with Meeting Confirmations
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from datetime import datetime, timedelta
import os
from typing import Optional, Dict, List
import json

# Google OAuth Scopes
SCOPES = [
    'https://www.googleapis.com/auth/calendar',
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.readonly',
]

class GoogleWorkspaceManager:
    """Manager for Google Workspace integrations"""
    
    @staticmethod
    def get_authorization_url(user_id: int) -> str:
        """Get Google OAuth authorization URL"""
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                    "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [os.getenv("GOOGLE_REDIRECT_URI")]
                }
            },
            scopes=SCOPES,
            redirect_uri=os.getenv("GOOGLE_REDIRECT_URI")
        )
        
        flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            state=str(user_id)
        )
        
        authorization_url, state = flow.authorization_url()
        return authorization_url
    
    @staticmethod
    def exchange_code_for_token(code: str) -> Dict:
        """Exchange authorization code for access token"""
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": os.getenv("GOOGLE_CLIENT_ID"),
                    "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [os.getenv("GOOGLE_REDIRECT_URI")]
                }
            },
            scopes=SCOPES,
            redirect_uri=os.getenv("GOOGLE_REDIRECT_URI")
        )
        
        flow.fetch_token(code=code)
        credentials = flow.credentials
        
        return {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
    
    @staticmethod
    def get_credentials(token_data: Dict) -> Credentials:
        """Get Google credentials from token data"""
        return Credentials(
            token=token_data['token'],
            refresh_token=token_data.get('refresh_token'),
            token_uri=token_data['token_uri'],
            client_id=token_data['client_id'],
            client_secret=token_data['client_secret'],
            scopes=token_data['scopes']
        )
    


class CalendarManager:
    """Google Calendar operations"""
    
    @staticmethod
    def create_event(credentials: Credentials, event_data: Dict) -> Dict:
        """Create a calendar event with optional Google Meet link"""
        try:
            service = build('calendar', 'v3', credentials=credentials)
            
            # Prepare attendees list
            attendees = []
            if event_data.get('attendee_emails'):
                attendees = [{'email': email} for email in event_data['attendee_emails']]
            
            # Create event with Google Meet
            event = {
                'summary': event_data['title'],
                'description': event_data.get('description', ''),
                'start': {
                    'dateTime': event_data['start_time'],
                    'timeZone': event_data.get('timezone', 'UTC'),
                },
                'end': {
                    'dateTime': event_data['end_time'],
                    'timeZone': event_data.get('timezone', 'UTC'),
                },
                'attendees': attendees,
                'conferenceData': {
                    'createRequest': {
                        'requestId': f"meet-{datetime.now().timestamp()}",
                        'conferenceSolutionKey': {'type': 'hangoutsMeet'}
                    }
                },
                'reminders': {
                    'useDefault': False,
                    'overrides': [
                        {'method': 'email', 'minutes': 24 * 60},  # 1 day before
                        {'method': 'email', 'minutes': 60},       # 1 hour before
                        {'method': 'popup', 'minutes': 30},       # 30 min before
                    ],
                },
                'guestsCanModify': False,
                'guestsCanInviteOthers': False,
                'guestsCanSeeOtherGuests': True,
            }
            
            created_event = service.events().insert(
                calendarId='primary',
                body=event,
                conferenceDataVersion=1,
                sendUpdates='all'  # Send email to all attendees
            ).execute()
            
            return {
                'event_id': created_event['id'],
                'event_link': created_event['htmlLink'],
                'meet_link': created_event.get('hangoutLink', ''),
                'status': 'created',
                'attendees': created_event.get('attendees', [])
            }
            
        except HttpError as error:
            raise Exception(f"Calendar API error: {error}")
    
    @staticmethod
    def get_upcoming_events(credentials: Credentials, max_results: int = 10) -> List[Dict]:
        """Get upcoming calendar events"""
        try:
            service = build('calendar', 'v3', credentials=credentials)
            
            now = datetime.utcnow().isoformat() + 'Z'
            events_result = service.events().list(
                calendarId='primary',
                timeMin=now,
                maxResults=max_results,
                singleEvents=True,
                orderBy='startTime'
            ).execute()
            
            events = events_result.get('items', [])
            
            return [{
                'id': event['id'],
                'title': event.get('summary', 'No Title'),
                'start': event['start'].get('dateTime', event['start'].get('date')),
                'end': event['end'].get('dateTime', event['end'].get('date')),
                'meet_link': event.get('hangoutLink', ''),
                'description': event.get('description', '')
            } for event in events]
            
        except HttpError as error:
            raise Exception(f"Calendar API error: {error}")


class GmailManager:
    """Gmail operations"""
    
    @staticmethod
    def send_email(credentials: Credentials, email_data: Dict) -> Dict:
        """Send an email via Gmail"""
        try:
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            import base64
            
            service = build('gmail', 'v1', credentials=credentials)
            
            message = MIMEMultipart()
            message['to'] = email_data['to']
            message['subject'] = email_data['subject']
            
            # Add CC if provided
            if email_data.get('cc'):
                message['cc'] = email_data['cc']
            
            # Create HTML or plain text body
            body = MIMEText(email_data['body'], 'html' if email_data.get('is_html') else 'plain')
            message.attach(body)
            
            # Encode message
            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
            
            # Send message
            sent_message = service.users().messages().send(
                userId='me',
                body={'raw': raw_message}
            ).execute()
            
            return {
                'message_id': sent_message['id'],
                'status': 'sent',
                'thread_id': sent_message.get('threadId')
            }
            
        except HttpError as error:
            raise Exception(f"Gmail API error: {error}")
    

    
    @staticmethod
    def get_recent_emails(credentials: Credentials, query: str = '', max_results: int = 10) -> List[Dict]:
        """Get recent emails matching query"""
        try:
            service = build('gmail', 'v1', credentials=credentials)
            
            results = service.users().messages().list(
                userId='me',
                q=query,
                maxResults=max_results
            ).execute()
            
            messages = results.get('messages', [])
            
            emails = []
            for message in messages:
                msg = service.users().messages().get(
                    userId='me',
                    id=message['id'],
                    format='metadata',
                    metadataHeaders=['From', 'To', 'Subject', 'Date']
                ).execute()
                
                headers = {h['name']: h['value'] for h in msg['payload']['headers']}
                
                emails.append({
                    'id': msg['id'],
                    'thread_id': msg['threadId'],
                    'from': headers.get('From', ''),
                    'to': headers.get('To', ''),
                    'subject': headers.get('Subject', ''),
                    'date': headers.get('Date', ''),
                    'snippet': msg.get('snippet', '')
                })
            
            return emails
            
        except HttpError as error:
            raise Exception(f"Gmail API error: {error}")
        
    
    @staticmethod
    def send_email_with_attachments(credentials: Credentials, email_data: Dict, attachments: List[Dict] = None) -> Dict:
        """Send an email with file attachments via Gmail"""
        try:
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            from email.mime.base import MIMEBase
            from email import encoders
            import base64
            
            service = build('gmail', 'v1', credentials=credentials)
            
            # Create multipart message
            message = MIMEMultipart()
            message['to'] = email_data['to']
            message['subject'] = email_data['subject']
            
            # Add CC if provided
            if email_data.get('cc'):
                message['cc'] = email_data['cc']
            
            # Add BCC if provided  
            if email_data.get('bcc'):
                message['bcc'] = email_data['bcc']
            
            # Create HTML or plain text body
            body = MIMEText(email_data['body'], 'html' if email_data.get('is_html', True) else 'plain')
            message.attach(body)
            
            # Add file attachments
            if attachments:
                for attachment in attachments:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment['file_data'])
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename="{attachment["filename"]}"'
                    )
                    message.attach(part)
            
            # Encode message
            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
            
            # Send message
            sent_message = service.users().messages().send(
                userId='me',
                body={'raw': raw_message}
            ).execute()
            
            return {
                'message_id': sent_message['id'],
                'status': 'sent',
                'thread_id': sent_message.get('threadId')
            }
            
        except HttpError as error:
            raise Exception(f"Gmail API error: {error}")