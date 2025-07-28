from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import json
import os
import sys
from datetime import datetime
import threading
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from slas.utils.config import load_config
from slas.core.detector import ThreatDetector
from slas.utils.parsers import parse_ssh_log_line

app = Flask(__name__)
app.config['SECRET_KEY'] = 'slas_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

alerts = []
stats = {
    'total_alerts': 0,
    'brute_force_alerts': 0,
    'suspicious_user_alerts': 0,
    'unique_ips': set(),
    'last_alert': None
}

detector = None
config = None

def load_incidents():
    global alerts, stats
    try:
        if os.path.exists('logs/incidents.log'):
            with open('logs/incidents.log', 'r') as f:
                for line in f:
                    if line.strip():
                        incident = json.loads(line.strip())
                        alerts.append(incident)
                        stats['total_alerts'] += 1
                        if incident['incident_type'] == 'brute_force':
                            stats['brute_force_alerts'] += 1
                        else:
                            stats['suspicious_user_alerts'] += 1
                        stats['unique_ips'].add(incident['ip_address'])
                        stats['last_alert'] = incident['timestamp']
    except Exception:
        pass

def monitor_logs():
    global detector, config
    if not os.path.exists(config['logging']['log_file']):
        return
        
    with open(config['logging']['log_file'], 'r') as f:
        f.seek(0, 2)
        last_position = f.tell()
        
    while True:
        try:
            with open(config['logging']['log_file'], 'r') as f:
                f.seek(last_position)
                new_lines = f.readlines()
                last_position = f.tell()
                
            for line in new_lines:
                process_log_line(line.strip())
                
            time.sleep(1)
        except Exception:
            time.sleep(5)

def process_log_line(line):
    global alerts, stats, detector
    parsed = parse_ssh_log_line(line)
    if not parsed:
        return
        
    ip_address = parsed['ip_address']
    username = parsed['username']
    event_type = parsed['event_type']
    
    if event_type == 'failed_password':
        if detector.add_failed_attempt(ip_address, username, parsed['timestamp']):
            attempt_count = detector.get_attempt_count(ip_address)
            create_alert('brute_force', ip_address, username, attempt_count)
            
    if detector.is_suspicious_username(username):
        create_alert('suspicious_username', ip_address, username, 1)

def create_alert(alert_type, ip_address, username, attempt_count):
    global alerts, stats
    
    alert = {
        'timestamp': datetime.now().isoformat(),
        'incident_type': alert_type,
        'ip_address': ip_address,
        'username': username,
        'attempt_count': attempt_count,
        'rule_triggered': 'max_failed_attempts' if alert_type == 'brute_force' else 'suspicious_usernames'
    }
    
    alerts.insert(0, alert)
    if len(alerts) > 100:
        alerts.pop()
        
    stats['total_alerts'] += 1
    if alert_type == 'brute_force':
        stats['brute_force_alerts'] += 1
    else:
        stats['suspicious_user_alerts'] += 1
    stats['unique_ips'].add(ip_address)
    stats['last_alert'] = alert['timestamp']
    
    socketio.emit('new_alert', alert)

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    return jsonify({
        'total_alerts': stats['total_alerts'],
        'brute_force_alerts': stats['brute_force_alerts'],
        'suspicious_user_alerts': stats['suspicious_user_alerts'],
        'unique_ips': len(stats['unique_ips']),
        'last_alert': stats['last_alert']
    })

@app.route('/api/alerts')
def get_alerts():
    return jsonify(alerts[:20])

if __name__ == '__main__':
    config = load_config()
    detector = ThreatDetector(config)
    load_incidents()
    
    monitor_thread = threading.Thread(target=monitor_logs, daemon=True)
    monitor_thread.start()
    
    socketio.run(app, debug=True, port=5000)