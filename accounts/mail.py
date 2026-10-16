import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

HOST = os.environ.get("SETTINGS_SMTP_HOST", "email-smtp.us-east-1.amazonaws.com")
PORT = int(os.environ.get("SETTINGS_SMTP_PORT", "587"))
USER = os.environ.get("SETTINGS_SMTP_USER", "")
SENDER = os.environ.get("SETTINGS_SMTP_SENDER", "kelliher.info <auth@kelliher.info>")
TIMEOUT = float(os.environ.get("SETTINGS_SMTP_TIMEOUT", "20"))


class MailFailed(Exception):
    pass


def _password():
    base = os.environ.get("CREDENTIALS_DIRECTORY")
    if not base:
        raise MailFailed("no CREDENTIALS_DIRECTORY")
    try:
        with open(os.path.join(base, "smtp_password")) as fh:
            return fh.read().strip()
    except OSError as e:
        raise MailFailed(f"smtp password unreadable: {e.strerror}") from None


def send(to, subject, body):
    msg = EmailMessage()
    msg["From"] = SENDER
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=SENDER.rsplit("@", 1)[-1].rstrip(">"))
    msg.set_content(body)
    try:
        with smtplib.SMTP(HOST, PORT, timeout=TIMEOUT) as s:
            s.starttls(context=ssl.create_default_context())
            s.login(USER, _password())
            s.send_message(msg)
    except (OSError, smtplib.SMTPException) as e:
        raise MailFailed(f"to {to}: {type(e).__name__}") from None
