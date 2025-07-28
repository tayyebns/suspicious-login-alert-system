import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from slas.core.detector import ThreatDetector

def test_brute_force_detection():
    config = {
        'detection': {
            'max_failed_attempts': 3,
            'time_window_seconds': 60,
            'suspicious_usernames': ['root', 'admin']
        }
    }
    
    detector = ThreatDetector(config)
    
    print("Testing brute force detection...")
    
    result1 = detector.add_failed_attempt("192.168.1.100", "user1", "Jan 1 12:00:00")
    print(f"Attempt 1: {result1}")
    
    result2 = detector.add_failed_attempt("192.168.1.100", "user1", "Jan 1 12:00:10")
    print(f"Attempt 2: {result2}")
    
    result3 = detector.add_failed_attempt("192.168.1.100", "user1", "Jan 1 12:00:20")
    print(f"Attempt 3 (should trigger): {result3}")
    
    print(f"Total attempts: {detector.get_attempt_count('192.168.1.100')}")

def test_suspicious_username():
    config = {
        'detection': {
            'max_failed_attempts': 5,
            'time_window_seconds': 60,
            'suspicious_usernames': ['root', 'admin']
        }
    }
    
    detector = ThreatDetector(config)
    
    print("\nTesting suspicious username detection...")
    print(f"'root' is suspicious: {detector.is_suspicious_username('root')}")
    print(f"'user1' is suspicious: {detector.is_suspicious_username('user1')}")

if __name__ == "__main__":
    test_brute_force_detection()
    test_suspicious_username()