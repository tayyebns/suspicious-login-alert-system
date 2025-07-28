import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict

class EmailAlerter:
    def __init__(self, config: Dict):
        self.smtp_server = config['email']['smtp_server']
        self.smtp_port = config['email']['smtp_port']
        self.sender_email = config['email']['sender_email']
        self.sender_password = config['email']['sender_password']
        self.recipient_email = config['email']['recipient_email']
        
    def send_brute_force_alert(self, ip_address: str, username: str, attempt_count: int) -> bool:
        subject = "🚨 SLAS: Brute Force Attack Detected"
        
        body = f"""
SUSPICIOUS LOGIN ALERT SYSTEM (SLAS)
=====================================

BRUTE FORCE ATTACK DETECTED

Source IP: {ip_address}
Target Username: {username}
Failed Attempts: {attempt_count}
Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

This alert was triggered because the source IP exceeded the maximum number of failed login attempts within the configured time window.

Please investigate this activity immediately.

---
SLAS - Suspicious Login Alert System
        """
        
        return self._send_email(subject, body)
        
    def send_suspicious_user_alert(self, ip_address: str, username: str) -> bool:
        subject = "⚠️ SLAS: Suspicious Username Targeted"
        
        body = f"""
SUSPICIOUS LOGIN ALERT SYSTEM (SLAS)
=====================================

SUSPICIOUS USERNAME TARGETED

Source IP: {ip_address}
Target Username: {username}
Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

This alert was triggered because someone attempted to login with a high-risk username that is commonly targeted by attackers.

Please investigate this activity immediately.

---
SLAS - Suspicious Login Alert System
        """
        
        return self._send_email(subject, body)
        
    def _send_email(self, subject: str, body: str) -> bool:
        try:
            message = MIMEMultipart()
            message["From"] = self.sender_email
            message["To"] = self.recipient_email
            message["Subject"] = subject
            
            message.attach(MIMEText(body, "plain"))
            
            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls(context=context)
                server.login(self.sender_email, self.sender_password)
                server.sendmail(self.sender_email, self.recipient_email, message.as_string())
            
            return True
        except Exception:
            return False