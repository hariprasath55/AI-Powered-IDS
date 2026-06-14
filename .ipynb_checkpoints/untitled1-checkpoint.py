from scapy.all import sniff, IP, TCP, UDP
import joblib
import numpy as np
import datetime

# Load the trained model and scaler
model  = joblib.load('../models/rf_model.pkl')
scaler = joblib.load('../models/scaler.pkl')

# Color codes for terminal output
RED    = '\033[91m'
GREEN  = '\033[92m'
YELLOW = '\033[93m'
RESET  = '\033[0m'

# Store alerts for the dashboard
alerts = []

def extract_features(pkt):
    """Extract network features from a live packet."""
    features = [0] * 41  # 41 features matching our dataset
    
    if IP in pkt:
        features[0]  = pkt[IP].len           # duration (using packet length)
        features[1]  = 1 if TCP in pkt else 0  # protocol_type (TCP=1, UDP=0)
        features[4]  = len(pkt)               # src_bytes
        features[5]  = pkt[IP].ttl            # dst_bytes (using TTL as proxy)
        features[2]  = pkt[IP].proto          # service
        
        if TCP in pkt:
            features[3]  = pkt[TCP].flags      # flag
            features[22] = pkt[TCP].window     # count
    
    return features

def analyze_packet(pkt):
    """Classify a packet using the trained model."""
    if not (IP in pkt):
        return
    
    try:
        features = extract_features(pkt)
        features_scaled = scaler.transform([features])
        prediction = model.predict(features_scaled)[0]
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        if prediction == 'Normal':
            color = GREEN
            symbol = '✓'
        else:
            color = RED
            symbol = '⚠️  ALERT'
            alerts.append({
                'time': timestamp,
                'src': src_ip,
                'dst': dst_ip,
                'type': prediction
            })
        
        print(f"{color}[{timestamp}] {symbol} | {src_ip} → {dst_ip} | {prediction}{RESET}")
    
    except Exception as e:
        pass  # Skip malformed packets

def start_capture(interface=None, packet_count=50):
    print(f"{YELLOW}🔍 AI-IDS Live Detection Started...{RESET}")
    print(f"{YELLOW}Capturing {packet_count} packets...{RESET}\n")
    sniff(iface=interface, count=packet_count, prn=analyze_packet, store=False)
    
    print(f"\n📋 Summary: {len(alerts)} alerts detected")
    for alert in alerts:
        print(f"  {RED}⚠️  [{alert['time']}] {alert['type']} attack | {alert['src']} → {alert['dst']}{RESET}")

if __name__ == "__main__":
    # Run with: sudo python src/live_detector.py
    start_capture(packet_count=100)