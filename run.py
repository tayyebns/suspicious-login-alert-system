import sys
import os
from slas.utils.config import load_config, validate_config
from slas.core.monitor import LogMonitor

def main():
    try:
        config = load_config()
        
        if not validate_config(config):
            print("Error: Invalid configuration file")
            sys.exit(1)
            
        if config['email']['sender_email'] == "YOUR_EMAIL@gmail.com":
            print("Error: Please set your email configuration in config/config.json")
            sys.exit(1)
            
        monitor = LogMonitor(config)
        monitor.start_monitoring()
        
    except Exception as e:
        print(f"Error starting SLAS: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()