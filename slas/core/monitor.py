import time
import os
from typing import Dict
from ..utils.parsers import parse_ssh_log_line
from .detector import ThreatDetector
from .email_alerter import EmailAlerter
from .logger import IncidentLogger

class LogMonitor:
    def __init__(self, config: Dict):
        self.config = config
        self.log_file = config['logging']['log_file']
        self.detector = ThreatDetector(config)
        self.alerter = EmailAlerter(config)
        self.incident_logger = IncidentLogger(config['logging']['incident_log'])
        self.last_position = 0
        
    def start_monitoring(self):
        print(f"Starting SLAS monitoring on {self.log_file}")
        
        if os.path.exists(self.log_file):
            with open(self.log_file, 'r') as f:
                f.seek(0, 2)
                self.last_position = f.tell()
        
        while True:
            try:
                self._check_for_new_logs()
                time.sleep(1)
            except KeyboardInterrupt:
                print("\nStopping SLAS monitoring...")
                break
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(5)
                
    def _check_for_new_logs(self):
        if not os.path.exists(self.log_file):
            return
            
        with open(self.log_file, 'r') as f:
            f.seek(self.last_position)
            new_lines = f.readlines()
            self.last_position = f.tell()
            
        for line in new_lines:
            self._process_log_line(line.strip())
            
    def _process_log_line(self, line: str):
        parsed = parse_ssh_log_line(line)
        if not parsed:
            return
            
        ip_address = parsed['ip_address']
        username = parsed['username']
        event_type = parsed['event_type']
        
        if event_type == 'failed_password':
            if self.detector.add_failed_attempt(ip_address, username, parsed['timestamp']):
                attempt_count = self.detector.get_attempt_count(ip_address)
                self.alerter.send_brute_force_alert(ip_address, username, attempt_count)
                self.incident_logger.log_brute_force_incident(ip_address, username, attempt_count)
                print(f"ALERT: Brute force detected from {ip_address} targeting {username}")
                
        if self.detector.is_suspicious_username(username):
            self.alerter.send_suspicious_user_alert(ip_address, username)
            self.incident_logger.log_suspicious_user_incident(ip_address, username)
            print(f"ALERT: Suspicious username '{username}' targeted from {ip_address}")