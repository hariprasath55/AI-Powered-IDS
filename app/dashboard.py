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
t = threading.Thread(target=simulate_traffic, daemon=True)
t.start()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <title>AI-IDS Dashboard</title>
  <meta http-equiv="refresh" content="3">
  <style>
    body { background:#0A0A0F; color:#E8E8F0; 
           font-family:'Courier New',monospace; margin:0; padding:20px; }
    h1   { color:#00FFB2; font-size:22px; margin-bottom:4px; }
    .subtitle { color:#444460; font-size:12px; margin-bottom:24px; }
    .cards { display:grid; grid-template-columns:repeat(5,1fr); gap:12px; margin-bottom:24px; }
    .card  { background:#0E0E1A; border:1px solid #1E1E2E; 
             border-radius:8px; padding:16px; text-align:center; }
    .card.alert { border-color:#FF6B35; }
    .card .num  { font-size:28px; font-weight:700; color:#00FFB2; }
    .card.alert .num { color:#FF6B35; }
    .card .lbl  { font-size:10px; color:#444460; margin-top:4px; letter-spacing:2px; }
    table { width:100%; border-collapse:collapse; }
    th    { text-align:left; padding:8px 12px; font-size:10px; 
            color:#444460; letter-spacing:2px; border-bottom:1px solid #1E1E2E; }
    td    { padding:8px 12px; font-size:12px; border-bottom:1px solid #0E0E1A; }
    .normal { color:#00FFB2; }
    .attack { color:#FF6B35; font-weight:700; }
    .badge  { padding:2px 8px; border-radius:3px; font-size:10px; 
              font-weight:700; letter-spacing:1px; }
    .badge.normal { background:#00FFB215; color:#00FFB2; }
    .badge.attack { background:#FF6B3520; color:#FF6B35; }
  </style>
</head>
<body>
  <h1>🛡️ AI-Powered Intrusion Detection System</h1>
  <p class="subtitle">Real-time network traffic analysis | Random Forest Model | NSL-KDD Trained</p>
  
  <div class="cards">
    <div class="card">
      <div class="num">{{ total }}</div>
      <div class="lbl">TOTAL PACKETS</div>
    </div>
    <div class="card">
      <div class="num">{{ stats.Normal }}</div>
      <div class="lbl">NORMAL</div>
    </div>
    <div class="card alert">
      <div class="num">{{ stats.DoS }}</div>
      <div class="lbl">DoS ATTACKS</div>
    </div>
    <div class="card alert">
      <div class="num">{{ stats.Probe }}</div>
      <div class="lbl">PROBE ATTACKS</div>
    </div>
    <div class="card alert">
      <div class="num">{{ stats.R2L + stats.U2R }}</div>
      <div class="lbl">R2L + U2R</div>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>TIME</th><th>SOURCE IP</th><th>DEST IP</th><th>CLASSIFICATION</th>
      </tr>
    </thead>
    <tbody>
      {% for a in alerts[-20:]|reverse %}
      <tr>
        <td style="color:#444460">{{ a.time }}</td>
        <td>{{ a.src }}</td>
        <td>{{ a.dst }}</td>
        <td>
          <span class="badge {{ 'attack' if a.is_attack else 'normal' }}">
            {{ '⚠️ ' if a.is_attack else '✓ ' }}{{ a.type }}
          </span>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</body>
</html>
"""

@app.route('/')
def dashboard():
    total = sum(stats.values())
    return render_template_string(HTML_TEMPLATE, 
                                   alerts=alerts_store, 
                                   stats=stats, 
                                   total=total)

if __name__ == '__main__':
    print(" Dashboard running at http://localhost:5000")
    app.run(debug=False, port=5000)
