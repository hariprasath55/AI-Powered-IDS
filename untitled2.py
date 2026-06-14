from flask import Flask, render_template_string, jsonify
import joblib
import numpy as np
import random
import datetime
import threading
import time

app = Flask(__name__)

# Load trained model
model  = joblib.load('../models/rf_model.pkl')
scaler = joblib.load('../models/scaler.pkl')

# Simulated live alerts store (replace with real Scapy data in production)
alerts_store = []
stats = {'Normal': 0, 'DoS': 0, 'Probe': 0, 'R2L': 0, 'U2R': 0}

def simulate_traffic():
    """Simulate network traffic for demo. Replace with real Scapy capture."""
    attack_types = ['Normal', 'Normal', 'Normal', 'Normal', 'DoS', 
                    'Probe', 'R2L', 'U2R', 'Normal', 'Normal']
    ips = ['192.168.1.5', '10.0.0.2', '172.16.0.1', '8.8.8.8', 
           '192.168.0.1', '10.10.0.50']
    
    while True:
        attack = random.choice(attack_types)
        src_ip = random.choice(ips)
        dst_ip = random.choice(ips)
        alert = {
            'time': datetime.datetime.now().strftime("%H:%M:%S"),
            'src': src_ip,
            'dst': dst_ip,
            'type': attack,
            'is_attack': attack != 'Normal'
        }
        alerts_store.append(alert)
        stats[attack] += 1
        if len(alerts_store) > 100:  # keep last 100
            alerts_store.pop(0)
        time.sleep(1)

# Start background traffic simulation
t = threading.Thread(target=simulate_tra