
import sqlite3
import random
import datetime
import secrets
from werkzeug.security import generate_password_hash
import pyotp
from contextlib import closing

DB_NAME = "database.db"

# Copy of GEO_DB keys from app.py to match indices
GEO_KEYS = ["USA", "Germany", "China", "Russia", "Brazil", "India", "UK", "Unknown"]

def get_ip_for_country(target_country):
    """Finds an IP that hashes to the target country."""
    if target_country == "Localhost": return "127.0.0.1"
    
    target_idx = -1
    for i, k in enumerate(GEO_KEYS):
        if k == target_country:
            target_idx = i
            break
    
    if target_idx == -1: return "1.1.1.1" # Fallback
    
    # Try random IPs until we match
    while True:
        ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        hash_val = sum(ord(c) for c in ip)
        if hash_val % len(GEO_KEYS) == target_idx:
            return ip

def seed() -> None:
    print("Connecting to database...")
    with closing(sqlite3.connect(DB_NAME)) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # 1. Clear Data
        print("Clearing old data...")
        c.execute("DELETE FROM users")
        c.execute("DELETE FROM sessions")
        c.execute("DELETE FROM devices")
        c.execute("DELETE FROM risk_logs")
        c.execute("DELETE FROM iot_devices")
        c.execute("DELETE FROM sqlite_sequence") # Reset IDs

        # 2. Create Users
        print("Creating users...")
        users = [
            ('admin', 'admin@secure.local', 'AdminPass123!', 'admin', 'active'),
            ('alice_safe', 'alice@corp.com', 'Pass123!', 'user', 'active'),
            ('bob_risky', 'bob@corp.com', 'Pass123!', 'user', 'active'),
            ('charlie_hacker', 'charlie@bad.com', 'Pass123!', 'user', 'blocked'),
            ('dave_traveler', 'dave@remote.com', 'Pass123!', 'user', 'active'),
            ('eve_insider', 'eve@corp.com', 'Pass123!', 'user', 'active')
        ]
        
        user_ids = {}

        for u in users:
            pw_hash = generate_password_hash(u[2])
            secret = pyotp.random_base32()
            c.execute("INSERT INTO users (username, email, password_hash, role, otp_secret, status, trust_score) VALUES (?, ?, ?, ?, ?, ?, ?)",
                      (u[0], u[1], pw_hash, u[3], secret, u[4], 100.0))
            user_ids[u[0]] = c.lastrowid

        conn.commit()

        # 3. Generate History (Last 24 Hours)
        print("Generating risk history...")
        now = datetime.datetime.now()
        
        # Base risk trend
        for i in range(24):
            # Time: now - i hours
            t = (now - datetime.timedelta(hours=i)).strftime('%Y-%m-%d %H:%M:%S')
            
            # Create some random background noise logs
            for _ in range(random.randint(1, 5)):
                uid = random.choice(list(user_ids.values()))
                risk = random.randint(0, 30)
                c.execute("INSERT INTO risk_logs (user_id, event_type, risk_score, reason, ip_address, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                          (uid, 'heartbeat', risk, 'Routine Check', get_ip_for_country("USA"), t))

        # 4. Specific Scenarios
        
        # Scenario A: Bob Risky (Geo Anomaly)
        # Login from USA 4 hours ago
        bob_id = user_ids['bob_risky']
        ip_usa = get_ip_for_country("USA")
        t_usa = (now - datetime.timedelta(hours=4)).strftime('%Y-%m-%d %H:%M:%S')
        c.execute("INSERT INTO risk_logs (user_id, event_type, risk_score, reason, ip_address, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                  (bob_id, 'login', 10, 'Login Success', ip_usa, t_usa))
        
        # Login from Russia 1 hour ago (ANOMALY)
        ip_ru = get_ip_for_country("Russia")
        t_ru = (now - datetime.timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
        c.execute("INSERT INTO risk_logs (user_id, event_type, risk_score, reason, ip_address, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                  (bob_id, 'login', 85, 'Impossible Travel Detected', ip_ru, t_ru))
        
        # Active Session for Bob (Russia)
        c.execute("INSERT INTO sessions (user_id, token, ip_address, user_agent, is_active, last_activity, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (bob_id, secrets.token_hex(16), ip_ru, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 1, t_ru, 85))

        # Scenario B: Charlie Hacker (Brute Force)
        charlie_id = user_ids['charlie_hacker']
        ip_china = get_ip_for_country("China")
        for i in range(10):
            t_fail = (now - datetime.timedelta(minutes=30 + i)).strftime('%Y-%m-%d %H:%M:%S')
            c.execute("INSERT INTO risk_logs (user_id, event_type, risk_score, reason, ip_address, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                      (charlie_id, 'login_attempt', 60, 'Failed: Invalid Password', ip_china, t_fail))
        
        # Scenario C: Alice Safe (Normal)
        alice_id = user_ids['alice_safe']
        ip_usa2 = get_ip_for_country("USA")
        t_alice = (now - datetime.timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
        c.execute("INSERT INTO sessions (user_id, token, ip_address, user_agent, is_active, last_activity, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (alice_id, secrets.token_hex(16), ip_usa2, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", 1, t_alice, 5))
        c.execute("INSERT INTO devices (user_id, fingerprint, is_trusted, last_seen) VALUES (?, ?, ?, ?)",
                  (alice_id, "device_alice_mac", 1, t_alice))
        c.execute("INSERT INTO risk_logs (user_id, event_type, risk_score, reason, ip_address, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                  (alice_id, 'login', 5, 'MFA Verified', ip_usa2, t_alice))

        # Scenario D: Dave Traveler (Multiple locations)
        dave_id = user_ids['dave_traveler']
        locs = ["UK", "Germany", "France"] # France maps to Unknown or loop
        for i, loc in enumerate(["UK", "Germany"]):
            ip = get_ip_for_country(loc)
            t = (now - datetime.timedelta(hours=10-i*5)).strftime('%Y-%m-%d %H:%M:%S')
            c.execute("INSERT INTO risk_logs (user_id, event_type, risk_score, reason, ip_address, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                      (dave_id, 'login', 40, f'Login from {loc}', ip, t))

        # Scenario E: Admin Activity
        admin_id = user_ids['admin']
        t_now_str = now.strftime('%Y-%m-%d %H:%M:%S')
        c.execute("INSERT INTO sessions (user_id, token, ip_address, user_agent, is_active, last_activity, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (admin_id, secrets.token_hex(16), "127.0.0.1", "AdminConsole/1.0", 1, t_now_str, 0))
        c.execute("INSERT INTO risk_logs (user_id, event_type, risk_score, reason, ip_address, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                  (admin_id, 'admin_action', 0, 'System Update', "127.0.0.1", t_now_str))

        conn.commit()
    print("Seeding complete. Database populated with mock SOC data.")

if __name__ == "__main__":
    seed()
