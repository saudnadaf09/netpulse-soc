# 🛡️ NetPulse v1.0 — Real-Time Network Packet Sniffer & SOC Traffic Visualizer

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Framework-black?style=for-the-badge&logo=flask&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Packet_Sniffer-red?style=for-the-badge)
![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-UI-38BDF8?style=for-the-badge&logo=tailwind-css&logoColor=white)
![WebSocket](https://img.shields.io/badge/WebSockets-Realtime-green?style=for-the-badge)
![Security Status](https://img.shields.io/badge/SOC-Active_IDS-critical?style=for-the-badge)
![Render Deployment](https://img.shields.io/badge/Status-Live_On_Render-success?style=for-the-badge&logo=render&logoColor=white)

**NetPulse v1.0** is an enterprise-grade, real-time Network Packet Sniffer, Intrusion Detection System (IDS), and Security Operations Center (SOC) traffic visualizer. Built for security researchers and SOC analysts, it captures live network traffic, analyzes packet headers, flags heuristic anomalies, and visualizes protocols via WebSockets in a high-performance dark-mode dashboard.

> 🌐 **Live Production URL:** [https://netpulse-soc-8fhw.onrender.com](https://netpulse-soc-8fhw.onrender.com)

---

## 🚀 Key Features & Capabilities

- **Real-Time Packet Sniffing & Smart Simulation:** Powered by Python's `Scapy` engine for live network sniffing on local machines, with an intelligent cloud fallback engine for seamless real-time stream simulation on cloud servers (Render/Heroku).
- **WebSocket Streaming:** Zero-refresh live updates pushed instantly to the frontend using `Flask-SocketIO` with dual payload key architecture to eradicate rendering errors.
- **Heuristics-Based IDS Engine:** Automated threat detection scanning for anomalous traffic, SQL injection signatures, and suspicious port activities.
- **Deep Packet Inspection (DPI) Modal:** Interactive packet click inspector displaying transport details, TTL, TCP flags, geo-origin, and raw Hex/ASCII payload previews.
- **Advanced Search & Filter Engine:** Real-time client-side filtering across source IPs, destination IPs, protocols, and geo-locations.
- **SQLite Database Persistence:** Secure backend storage (`netpulse.db`) tracking user authentication, dynamic 2FA OTP verification, and automated threat event logs.
- **Modern Cyber-Sec UI:** Designed using Tailwind CSS and Chart.js for an elite, dark-mode terminal aesthetic tailored for SOC operators.

---

## 🛠️ Tech Stack

- **Backend:** Python, Flask, Flask-SocketIO, Scapy, Werkzeug, SQLite3, Threading
- **Frontend:** HTML5, Tailwind CSS, JavaScript (Chart.js, Socket.IO Client)
- **Deployment & Cloud:** Gunicorn, Eventlet, Procfile configuration, Render Cloud Platform

---

## ⚙️ Installation & Local Setup

1. **Clone the Repository:**

```

bash
git clone [https://github.com/saudnadaf09/netpulse-soc.git](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fsaudnadaf09%2Fnetpulse-soc.git)
cd netpulse-soc

```

2. **Create and Activate Virtual Environment:**

```

bash
python -m venv venv

# On Windows:

venv\Scripts\activate

# On macOS/Linux:

source venv/bin/activate

```

3. **Install Dependencies:**

```

bash
pip install -r requirements.txt

```

4. **Run the Application:**

```

bash
python backend/app.py

```

Open your browser and navigate to `http://127.0.0.1:5000`.

---

## 📂 Project Architecture


```

text
NetPulse/
│
├── backend/
│   ├── app.py             # Flask application, authentication, & SQLite DB routes
│   └── sniffer.py         # Packet sniffer engine & high-speed smart simulator
│
├── templates/
│   ├── index.html         # SOC dashboard, charts, & WebSocket client UI
│   ├── login.html         # Secure login interface
│   ├── signup.html        # User registration portal
│   └── verify_2fa.html    # 2FA OTP verification screen
│
├── requirements.txt       # Project Python dependencies
├── Procfile               # Cloud deployment configuration
└── README.md              # Project documentation

```

---

## 📌 Author

**Saud Nadaf**  
*Cybersecurity Student & Researcher*  
- **GitHub:** [@saudnadaf09](https://github.com/saudnadaf09)
- **Project Repository:** [netpulse-soc](https://github.com/saudnadaf09/netpulse-soc)
