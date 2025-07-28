from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional

class ThreatDetector:
    def __init__(self, config: Dict):
        self.max_attempts = config['detection']['max_failed_attempts']
        self.time_window = config['detection']['time_window_seconds']
        self.suspicious_usernames = config['detection']['suspicious_usernames']
        self.ip_attempts = defaultdict(deque)
        
    def add_failed_attempt(self, ip_address: str, username: str, timestamp: str) -> bool:
        now = datetime.now()
        self.ip_attempts[ip_address].append((now, username))
        
        cutoff_time = now - timedelta(seconds=self.time_window)
        while self.ip_attempts[ip_address] and self.ip_attempts[ip_address][0][0] < cutoff_time:
            self.ip_attempts[ip_address].popleft()
            
        if len(self.ip_attempts[ip_address]) >= self.max_attempts:
            return True
            
        return False
        
    def is_suspicious_username(self, username: str) -> bool:
        return username in self.suspicious_usernames
        
    def get_attempt_count(self, ip_address: str) -> int:
        return len(self.ip_attempts[ip_address])