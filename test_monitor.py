from slas.utils.config import load_config
from slas.utils.parsers import parse_ssh_log_line
from slas.core.detector import ThreatDetector

def test_monitoring_logic():
    config = load_config()
    detector = ThreatDetector(config)
    
    log_lines = [
        "Jan 27 14:30:01 server sshd[1234]: Failed password for user1 from 192.168.1.100 port 22 ssh2",
        "Jan 27 14:30:05 server sshd[1235]: Failed password for user1 from 192.168.1.100 port 22 ssh2",
        "Jan 27 14:30:10 server sshd[1236]: Failed password for user1 from 192.168.1.100 port 22 ssh2",
        "Jan 27 14:30:15 server sshd[1237]: Failed password for user1 from 192.168.1.100 port 22 ssh2",
        "Jan 27 14:30:20 server sshd[1238]: Failed password for user1 from 192.168.1.100 port 22 ssh2",
        "Jan 27 14:30:25 server sshd[1239]: Failed password for user1 from 192.168.1.100 port 22 ssh2",
        "Jan 27 14:31:00 server sshd[1240]: Failed password for root from 192.168.1.200 port 22 ssh2"
    ]
    
    print("Processing sample log entries...")
    
    for line in log_lines:
        parsed = parse_ssh_log_line(line)
        if parsed and parsed['event_type'] == 'failed_password':
            ip_address = parsed['ip_address']
            username = parsed['username']
            
            is_brute_force = detector.add_failed_attempt(ip_address, username, parsed['timestamp'])
            is_suspicious_user = detector.is_suspicious_username(username)
            
            print(f"IP: {ip_address}, User: {username}")
            print(f"  Attempts: {detector.get_attempt_count(ip_address)}")
            print(f"  Brute force triggered: {is_brute_force}")
            print(f"  Suspicious username: {is_suspicious_user}")
            print()

if __name__ == "__main__":
    test_monitoring_logic()