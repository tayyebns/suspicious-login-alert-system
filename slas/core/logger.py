import json
import os
from datetime import datetime
from typing import Dict

class IncidentLogger:
    def __init__(self, log_file_path: str):
        self.log_file_path = log_file_path
        self._ensure_log_directory()
        
    def _ensure_log_directory(self):
        directory = os.path.dirname(self.log_file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
            
    def log_brute_force_incident(self, ip_address: str, username: str, attempt_count: int):
        incident = {
            "timestamp": datetime.now().isoformat(),
            "incident_type": "brute_force",
            "ip_address": ip_address,
            "username": username,
            "attempt_count": attempt_count,
            "rule_triggered": "max_failed_attempts"
        }
        self._write_incident(incident)
        
    def log_suspicious_user_incident(self, ip_address: str, username: str):
        incident = {
            "timestamp": datetime.now().isoformat(),
            "incident_type": "suspicious_username",
            "ip_address": ip_address,
            "username": username,
            "rule_triggered": "suspicious_usernames"
        }
        self._write_incident(incident)
        
    def _write_incident(self, incident: Dict):
        try:
            with open(self.log_file_path, 'a') as f:
                f.write(json.dumps(incident) + '\n')
        except Exception:
            pass