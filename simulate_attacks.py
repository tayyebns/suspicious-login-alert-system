import time
import random
from datetime import datetime

def add_log_entry(log_line):
    with open('test_auth.log', 'a') as f:
        f.write(log_line + '\n')
    print(f"Added: {log_line}")

def simulate_brute_force_attack():
    print("🚨 Simulating brute force attack...")
    
    attacker_ip = f"192.168.1.{random.randint(100, 200)}"
    target_user = random.choice(['user1', 'admin', 'test'])
    
    for i in range(7):
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        log_line = f"{timestamp} server sshd[{1000+i}]: Failed password for {target_user} from {attacker_ip} port 22 ssh2"
        add_log_entry(log_line)
        time.sleep(2)

def simulate_suspicious_user_attack():
    print("⚠️ Simulating suspicious username attack...")
    
    attacker_ip = f"10.0.0.{random.randint(50, 100)}"
    suspicious_users = ['root', 'admin', 'administrator']
    
    for user in suspicious_users:
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        log_line = f"{timestamp} server sshd[{random.randint(2000, 3000)}]: Failed password for {user} from {attacker_ip} port 22 ssh2"
        add_log_entry(log_line)
        time.sleep(3)

def simulate_mixed_attacks():
    print("🔥 Simulating multiple attack patterns...")
    
    simulate_brute_force_attack()
    time.sleep(5)
    simulate_suspicious_user_attack()
    time.sleep(5)
    simulate_brute_force_attack()

if __name__ == "__main__":
    print("SLAS Attack Simulation Demo")
    print("===========================")
    print("Choose simulation type:")
    print("1. Brute Force Attack")
    print("2. Suspicious Username Attack") 
    print("3. Mixed Attack Patterns")
    
    choice = input("\nEnter choice (1-3): ")
    
    if choice == "1":
        simulate_brute_force_attack()
    elif choice == "2":
        simulate_suspicious_user_attack()
    elif choice == "3":
        simulate_mixed_attacks()
    else:
        print("Invalid choice!")
