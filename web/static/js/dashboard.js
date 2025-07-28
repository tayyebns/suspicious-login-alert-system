const socket = io();

let stats = {
    total_alerts: 0,
    brute_force_alerts: 0,
    suspicious_user_alerts: 0,
    unique_ips: 0,
    last_alert: null
};

function updateStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            stats = data;
            
            document.getElementById('total-alerts').textContent = data.total_alerts;
            document.getElementById('brute-force-alerts').textContent = data.brute_force_alerts;
            document.getElementById('suspicious-user-alerts').textContent = data.suspicious_user_alerts;
            document.getElementById('unique-ips').textContent = data.unique_ips;
            
            if (data.last_alert) {
                const lastUpdate = new Date(data.last_alert).toLocaleString();
                document.getElementById('last-update').textContent = lastUpdate;
            }
        })
        .catch(error => console.error('Error fetching stats:', error));
}

function loadAlerts() {
    fetch('/api/alerts')
        .then(response => response.json())
        .then(alerts => {
            displayAlerts(alerts);
        })
        .catch(error => console.error('Error fetching alerts:', error));
}

function displayAlerts(alerts) {
    const container = document.getElementById('alerts-container');
    
    if (alerts.length === 0) {
        container.innerHTML = `
            <div class="no-alerts">
                <div class="no-alerts-icon">🛡️</div>
                <p>No alerts detected. System is secure.</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = alerts.map(alert => createAlertHTML(alert)).join('');
}

function createAlertHTML(alert) {
    const timestamp = new Date(alert.timestamp).toLocaleString();
    const alertTypeClass = alert.incident_type.replace('_', '-');
    const alertTypeText = alert.incident_type === 'brute_force' ? 'Brute Force Attack' : 'Suspicious Username';
    
    return `
        <div class="alert-item ${alertTypeClass}">
            <div class="alert-header">
                <span class="alert-type">${alertTypeText}</span>
                <span class="alert-time">${timestamp}</span>
            </div>
            <div class="alert-details">
                <div class="alert-detail">
                    <span class="alert-detail-label">Source IP</span>
                    <span class="alert-detail-value">${alert.ip_address}</span>
                </div>
                <div class="alert-detail">
                    <span class="alert-detail-label">Username</span>
                    <span class="alert-detail-value">${alert.username}</span>
                </div>
                ${alert.attempt_count ? `
                <div class="alert-detail">
                    <span class="alert-detail-label">Attempts</span>
                    <span class="alert-detail-value">${alert.attempt_count}</span>
                </div>
                ` : ''}
                <div class="alert-detail">
                    <span class="alert-detail-label">Rule</span>
                    <span class="alert-detail-value">${alert.rule_triggered}</span>
                </div>
            </div>
        </div>
    `;
}

function addNewAlert(alert) {
    const container = document.getElementById('alerts-container');
    const noAlertsDiv = container.querySelector('.no-alerts');
    
    if (noAlertsDiv) {
        container.innerHTML = '';
    }
    
    const alertHTML = createAlertHTML(alert);
    container.insertAdjacentHTML('afterbegin', alertHTML);
    
    const alertItems = container.querySelectorAll('.alert-item');
    if (alertItems.length > 20) {
        alertItems[alertItems.length - 1].remove();
    }
    
    const newAlertElement = container.firstElementChild;
    newAlertElement.style.opacity = '0';
    newAlertElement.style.transform = 'translateY(-20px)';
    
    setTimeout(() => {
        newAlertElement.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
        newAlertElement.style.opacity = '1';
        newAlertElement.style.transform = 'translateY(0)';
    }, 100);
}

socket.on('new_alert', function(alert) {
    addNewAlert(alert);
    updateStats();
    
    const alertTypeText = alert.incident_type === 'brute_force' ? 'Brute Force Attack' : 'Suspicious Username';
    console.log(`New alert: ${alertTypeText} from ${alert.ip_address}`);
});

socket.on('connect', function() {
    console.log('Connected to SLAS monitoring system');
});

socket.on('disconnect', function() {
    console.log('Disconnected from SLAS monitoring system');
});

document.addEventListener('DOMContentLoaded', function() {
    updateStats();
    loadAlerts();
    
    setInterval(updateStats, 5000);
});