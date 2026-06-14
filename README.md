 AI-Powered Network Intrusion Detection System

> Real-time network traffic classifier using Machine Learning  
> Trained on NSL-KDD dataset | 99.2% accuracy | Live packet capture via Scapy

 🔍 What It Does
Monitors live network traffic and classifies each connection as:
- ✅ Normal — safe traffic
- ⚠️ DoS — Denial of Service attack  
- ⚠️ Probe — Port scanning / reconnaissance  
- ⚠️ R2L — Remote to Local attack  
- ⚠️ U2R — User to Root privilege escalation

 📊 Results
| Model          | Accuracy | F1-Score |
|----------------|----------|----------|
| Random Forest  | 99.21%   | 99.18%   |

 🛠️ Tech Stack
Python · Scikit-learn · Scapy · Flask · Pandas · Matplotlib

 🚀 How to Run

```bash
# Install dependencies
pip install -r requirements.txt

# Train the model
python src/train.py

# Start live detection (needs sudo/admin)
sudo python src/live_detector.py

# Launch web dashboard
python app/dashboard.py
# Open http://localhost:5000
```

 📁 Project Structure
```
AI-IDS/
├── data/          ← NSL-KDD dataset
├── src/           ← Core Python scripts
│   ├── preprocess.py
│   ├── train.py
│   └── live_detector.py
├── app/           ← Flask dashboard
│   └── dashboard.py
└── models/        ← Saved model + charts
```


 🎯 My Unique Addition
Added real-time Scapy packet capture module that feeds live network 
traffic into the trained model — most IDS projects only work on static datasets.

📚 Dataset
NSL-KDD (Canadian Institute for Cybersecurity)
- Training: 125,973 samples
- Testing: 22,544 samples
