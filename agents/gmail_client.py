"""
OmniUil AI Agents — Cliente Gmail OAuth2
"""
import os, base64, json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from config import GMAIL_CREDS_FILE, GMAIL_TOKEN_FILE

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.modify",
]

def get_gmail_service():
    import json
    with open(GMAIL_CREDS_FILE) as f:
        creds_data = json.load(f)
    installed = creds_data.get("installed", creds_data.get("web", {}))
    client_id     = installed["client_id"]
    client_secret = installed["client_secret"]
    token_uri     = installed["token_uri"]

    with open(GMAIL_TOKEN_FILE) as f:
        token = json.load(f)

    creds = Credentials(
        token=token.get("access_token"),
        refresh_token=token.get("refresh_token"),
        token_uri=token_uri,
        client_id=client_id,
        client_secret=client_secret,
        scopes=SCOPES,
    )
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        token["access_token"] = creds.token
        with open(GMAIL_TOKEN_FILE, "w") as f:
            json.dump(token, f, indent=2)
    return build("gmail", "v1", credentials=creds)

def get_unread_emails(max_results=10):
    service = get_gmail_service()
    result = service.users().messages().list(
        userId="me", q="is:unread", maxResults=max_results).execute()
    messages = result.get("messages", [])
    emails = []
    for msg in messages:
        data = service.users().messages().get(
            userId="me", id=msg["id"], format="full").execute()
        headers = {h["name"]: h["value"] for h in data["payload"]["headers"]}
        body = ""
        if "parts" in data["payload"]:
            for part in data["payload"]["parts"]:
                if part["mimeType"] == "text/plain":
                    body = base64.urlsafe_b64decode(
                        part["body"].get("data","")).decode("utf-8", errors="ignore")
                    break
        elif "body" in data["payload"]:
            body = base64.urlsafe_b64decode(
                data["payload"]["body"].get("data","")).decode("utf-8", errors="ignore")
        emails.append({
            "id": msg["id"],
            "from": headers.get("From",""),
            "subject": headers.get("Subject",""),
            "date": headers.get("Date",""),
            "body": body[:2000],
        })
    return emails

def send_email(to, subject, body, reply_to_id=None):
    service = get_gmail_service()
    msg = MIMEMultipart("alternative")
    msg["To"] = to
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    payload = {"raw": raw}
    if reply_to_id:
        payload["threadId"] = reply_to_id
    service.users().messages().send(userId="me", body=payload).execute()
    return True

def mark_as_read(msg_id):
    service = get_gmail_service()
    service.users().messages().modify(
        userId="me", id=msg_id,
        body={"removeLabelIds": ["UNREAD"]}).execute()
