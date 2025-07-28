# SLAS - Suspicious Login Alert System

A real-time cybersecurity monitoring system that detects and alerts on suspicious login activity.

## Overview

SLAS monitors authentication logs in real-time and automatically identifies potential security threats such as brute force attacks and suspicious username targeting. The system provides immediate alerts and maintains detailed incident logs for security analysis.

## Features

- **Real-time Log Monitoring**: Continuously processes authentication logs
- **Brute Force Detection**: Identifies multiple failed login attempts from single IP addresses
- **Suspicious Username Detection**: Flags attempts targeting high-risk accounts (root, admin, etc.)
- **Web Dashboard**: Clean, professional interface showing live security metrics
- **Email Alerting**: Automated notifications for detected threats
- **Incident Logging**: Structured JSON logging for forensic analysis

## Tech Stack

- **Backend**: Python, Flask, Socket.IO
- **Frontend**: HTML, CSS, JavaScript
- **Real-time Communication**: WebSocket integration
- **Data Processing**: JSON, regex parsing, threading
- **Notifications**: SMTP email integration

## Quick Start

1. Clone the repository
```bash
git clone https://github.com/yourusername/suspicious-login-alert-system.git
cd suspicious-login-alert-system