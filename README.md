# 🛡️ NetPulse v1.0 — Real-Time Network Packet Sniffer & SOC Traffic Visualizer

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Framework-black?style=for-the-badge&logo=flask&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Packet_Sniffer-red?style=for-the-badge)
![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-UI-38BDF8?style=for-the-badge&logo=tailwind-css&logoColor=white)
![WebSocket](https://img.shields.io/badge/WebSockets-Realtime-green?style=for-the-badge)
![Security Status](https://img.shields.io/badge/SOC-Active_IDS-critical?style=for-the-badge)

**NetPulse v1.0** is an enterprise-grade, real-time Network Packet Sniffer, Intrusion Detection System (IDS), and Security Operations Center (SOC) traffic visualizer. Built for security researchers and SOC analysts, it captures live network traffic, analyzes packet headers, flags heuristic anomalies, and visualizes protocols via WebSockets in a high-performance dark-mode dashboard.

---

## 🚀 Key Features & Capabilities

- **Real-Time Packet Sniffing:** Powered by Python's `Scapy` engine to capture live TCP, UDP, and IP traffic packets dynamically.
- **WebSocket Streaming:** Zero-refresh live updates pushed instantly to the frontend using `Flask-SocketIO`.
- **Heuristics-Based IDS Engine:** Automated threat detection scanning for suspicious ports (e.g., Metasploit port `4444`, RDP `3389`, SMB `445`, SSH `22`, FTP `21`).
- **Deep Packet Inspection (DPI) Modal:** Interactive packet click inspector displaying transport details, TTL, TCP flags, geo-origin, and raw Hex/ASCII payload previews.
- **Advanced Search & Filter Engine:** Real-time filtering across source IPs, destination IPs, protocols, and geo-locations.
- **SQLite Database Persistence:** Secure backend storage (`netpulse.db`) tracking user authentication, 2FA OTP logs, and automated threat events.
- **Modern Cyber-Sec UI:** Designed using Tailwind CSS and Chart.js for an elite, dark-mode terminal aesthetic.

---

## 🛠️ Tech Stack

- **Backend:** Python, Flask, Flask-SocketIO, Scapy, Werkzeug, SQLite3
- **Frontend:** HTML5, Tailwind CSS, JavaScript (Chart.js, Socket.IO Client)
- **Deployment Ready:** Gunicorn, Eventlet, Procfile configuration for cloud hosting (Render/Heroku)

---

## ⚙️ Installation & Local Setup

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/saudnadaf09/netpulse-soc.git](https://github.com/saudnadaf09/netpulse-soc.git)
   cd netpulse-soc

```

2. **Create and Activate Virtual Environment:**
```bash
python -m venv venv

# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate

```


3. **Install Dependencies:**
```bash
pip install -r requirements.txt

```


4. **Run the Application:**
```bash
python backend/app.py

```


Open your browser and navigate to `http://127.0.0.1:5000`.

---

## 📌 Author

**Saud Nadaf**

*Cybersecurity Student & Researcher*

[GitHub Profile](https://www.google.com/search?q=https://github.com/saudnadaf09)
