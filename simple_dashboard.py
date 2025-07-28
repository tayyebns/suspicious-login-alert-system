from flask import Flask, render_template_string
import json
import os

app = Flask(__name__)

@app.route('/')
def dashboard():
    stats = {
        'total_alerts': 0,
        'brute_force_alerts': 0,
        'suspicious_user_alerts': 0,
        'unique_ips': 0
    }
    
    alerts = []
    
    if os.path.exists('logs/incidents.log'):
        try:
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
        except:
            pass
    
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SLAS Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
            .header { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
            .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
            .stat-card { background: white; padding: 20px; border-radius: 10px; text-align: center; }
            .stat-number { font-size: 2em; font-weight: bold; color: #333; }
            .stat-label { color: #666; margin-top: 5px; }
            .alerts { background: white; padding: 20px; border-radius: 10px; }
            .alert-item { background: #f8f9fa; margin: 10px 0; padding: 15px; border-radius: 5px; border-left: 4px solid #dc3545; }
            .no-alerts { text-align: center; padding: 40px; color: #666; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ SLAS - Suspicious Login Alert System</h1>
            <p>Security Monitoring Dashboard</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{{ stats.total_alerts }}</div>
                <div class="stat-label">Total Alerts</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ stats.brute_force_alerts }}</div>
                <div class="stat-label">Brute Force</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ stats.suspicious_user_alerts }}</div>
                <div class="stat-label">Suspicious Users</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ stats.unique_ips }}</div>
                <div class="stat-label">Unique IPs</div>
            </div>
        </div>
        
        <div class="alerts">
            <h2>Recent Alerts</h2>
            {% if alerts %}
                {% for alert in alerts[:10] %}
                <div class="alert-item">
                    <strong>{{ 'Brute Force Attack' if alert.incident_type == 'brute_force' else 'Suspicious Username' }}</strong><br>
                    IP: {{ alert.ip_address }} | User: {{ alert.username }} | Time: {{ alert.timestamp }}
                </div>
                {% endfor %}
            {% else %}
                <div class="no-alerts">No alerts detected. System is secure.</div>
            {% endif %}
        </div>
        
        <script>
            setTimeout(function(){ location.reload(); }, 5000);
        </script>
    </body>
    </html>
    '''
    
    return render_template_string(html, stats=stats, alerts=alerts)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=3000, debug=False)