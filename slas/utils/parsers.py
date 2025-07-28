import re
from datetime import datetime
from typing import Dict, Optional

def parse_ssh_log_line(line: str) -> Optional[Dict[str, str]]:
    patterns = {
        'failed_password': r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*Failed password.*for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)',
        'accepted_password': r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)',
        'invalid_user': r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*Invalid user (\w+) from (\d+\.\d+\.\d+\.\d+)'
    }
    
    for event_type, pattern in patterns.items():
        match = re.search(pattern, line)
        if match:
            return {
                'timestamp': match.group(1),
                'username': match.group(2),
                'ip_address': match.group(3),
                'event_type': event_type
            }
    return None