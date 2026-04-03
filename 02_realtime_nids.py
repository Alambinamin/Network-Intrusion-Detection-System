import os
import pickle
import numpy as np
import warnings
import csv
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP


warnings.filterwarnings("ignore")
print("--- NIDS RUNNING: WITH CSV LOGGING ---")


try:
    with open('nids_model.pkl', 'rb') as f:
        clf = pickle.load(f)
    with open('encoders.pkl', 'rb') as f:
        le_proto, le_service, le_flag = pickle.load(f)
    print("SUCCESS: Model Loaded.")
except FileNotFoundError:
    print("ERROR: Run 01_train_model.py first!")
    exit()


csv_file = 'nids_alerts.csv'
if not os.path.exists(csv_file):
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Timestamp', 'Source_IP', 'Service', 'Flag', 'Confidence'])

common_ports = { 80: 'http', 443: 'http', 8080: 'http', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain_u', 3306: 'sql_net' }

def get_flag(p):
    if not p.haslayer(TCP): return 'SF'
    f = p[TCP].flags
    if f.S and not f.A: return 'S0'
    if f.S and f.A: return 'S1'
    if f.F: return 'REJ'
    if f.R: return 'REJ'
    if f.P and f.A: return 'SF'
    return 'SF'

def process_packet(packet):
    if not packet.haslayer(IP): return

    
    if packet.haslayer(TCP):
        protocol = 'tcp'
        service = common_ports.get(packet[TCP].dport, 'other')
        flag = get_flag(packet)
        src_bytes = len(packet[TCP].payload)
    elif packet.haslayer(UDP):
        protocol = 'udp'
        service = common_ports.get(packet[UDP].dport, 'other')
        flag = 'SF'
        src_bytes = len(packet[UDP].payload)
    else: return

    
    try:
        p_enc = le_proto.transform([protocol])[0] if protocol in le_proto.classes_ else 0
        s_enc = le_service.transform([service])[0] if service in le_service.classes_ else 0
        f_enc = le_flag.transform([flag])[0] if flag in le_flag.classes_ else 0
    except: return

    
    features = np.zeros(41)
    features[1], features[2], features[3], features[4] = p_enc, s_enc, f_enc, src_bytes
    
    if service == 'http' and flag != 'S0':
        features[5], features[11] = src_bytes + 100, 1
    else:
        features[5], features[11] = 0, 0

    features[22], features[23] = 1, 1

    
    vector = features.reshape(1, -1)
    probs = clf.predict_proba(vector)[0]
    confidence = probs[1]

    
    src = packet[IP].src
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if confidence > 0.50:
        
        print(f"\033[91m[ALERT] {confidence*100:.0f}% Malicious | {src} -> {service} [{flag}]\033[0m")
        
        
        with open(csv_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, src, service, flag, f"{confidence*100:.1f}%"])
    else:
        print(f"\033[92m[SAFE]  {confidence*100:.0f}% Normal    | {src} -> {service} [{flag}]\033[0m")


sniff(iface="lo", prn=process_packet, store=0)
