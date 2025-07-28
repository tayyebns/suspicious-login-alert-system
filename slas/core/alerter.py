import requests
import json
from datetime import datetime
from typing import Dict

class DiscordAlerter:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        
    def send_brute_force_alert(self, ip_address: str, username: str, attempt_count: int) -> bool:
        embed = {
            "title": "🚨 Brute Force Attack Detected",
            "color": 15158332,
            "fields": [
                {
                    "name": "Source IP",
                    "value": ip_address,
                    "inline": True
                },
                {
                    "name": "Target Username", 
                    "value": username,
                    "inline": True
                },
                {
                    "name": "Failed Attempts",
                    "value": str(attempt_count),
                    "inline": True
                },
                {
                    "name": "Timestamp",
                    "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "inline": False
                }
            ],
            "footer": {
                "text": "SLAS - Suspicious Login Alert System"
            }
        }
        
        payload = {
            "embeds": [embed]
        }
        
        try:
            response = requests.post(self.webhook_url, json=payload)
            return response.status_code == 204
        except Exception:
            return False
            
    def send_suspicious_user_alert(self, ip_address: str, username: str) -> bool:
        embed = {
            "title": "⚠️ Suspicious Username Targeted",
            "color": 16776960,
            "fields": [
                {
                    "name": "Source IP",
                    "value": ip_address,
                    "inline": True
                },
                {
                    "name": "Target Username",
                    "value": username,
                    "inline": True
                },
                {
                    "name": "Timestamp",
                    "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "inline": False
                }
            ],
            "footer": {
                "text": "SLAS - Suspicious Login Alert System"
            }
        }
        
        payload = {
            "embeds": [embed]
        }
        
        try:
            response = requests.post(self.webhook_url, json=payload)
            return response.status_code == 204
        except Exception:
            return False