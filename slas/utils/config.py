import json
import os
from typing import Dict

def load_config(config_path: str = "config/config.json") -> Dict:
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        sender_email = os.getenv('SENDER_EMAIL')
        sender_password = os.getenv('SENDER_PASSWORD')
        
        if sender_email:
            config['email']['sender_email'] = sender_email
        if sender_password:
            config['email']['sender_password'] = sender_password
            
        return config
    except FileNotFoundError:
        raise Exception(f"Configuration file not found: {config_path}")
    except json.JSONDecodeError:
        raise Exception(f"Invalid JSON in configuration file: {config_path}")

def validate_config(config: Dict) -> bool:
    required_keys = [
        ['detection', 'max_failed_attempts'],
        ['detection', 'time_window_seconds'],
        ['detection', 'suspicious_usernames'],
        ['email', 'smtp_server'],
        ['email', 'sender_email'],
        ['email', 'recipient_email'],
        ['logging', 'incident_log']
    ]
    
    for key_path in required_keys:
        current = config
        for key in key_path:
            if key not in current:
                return False
            current = current[key]
    
    return True