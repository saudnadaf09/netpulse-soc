from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO
import threading
from backend.sniffer import sniffer_instance
import time
from werkzeug.security import generate_password_hash, check_password_hash
import random
import sqlite3
import os

app = Flask(__name__, template_folder='../templates')
app.config['SECRET_KEY'] = 'netpulse_secure_super_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

DB_NAME = "netpulse.db"

def init_db():
    """Initialize SQLite database with users and threat_logs tables."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            otp TEXT
        )
    ''')
    
    # Threat Logs table for SOC Security Auditing
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            threat_desc TEXT
        )
    ''')

    # Insert default admin user if not already present
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        hashed_pw = generate_password_hash("netpulse123")
        cursor.execute("INSERT INTO users (username, password, email, otp) VALUES (?, ?, ?, ?)",
                       ("admin", hashed_pw, "admin@netpulse.sec", "123456"))
    conn.commit()
    conn.close()

init_db()

sniffer_thread = None

def background_packet_broadcaster():
    while True:
        time.sleep(0.5)
        stats = sniffer_instance.get_stats()
        
        # Automatically persist detected threats into SQLite threat_logs table
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        for pkt in stats.get('packets', []):
            if pkt.get('threat'):
                # Check if threat already logged recently to prevent duplicates
                cursor.execute("SELECT id FROM threat_logs WHERE timestamp = ? AND src_ip = ?", (pkt['timestamp'], pkt['src']))
                if not cursor.fetchone():
                    cursor.execute("INSERT INTO threat_logs (timestamp, src_ip, dst_ip, protocol, threat_desc) VALUES (?, ?, ?, ?, ?)",
                                   (pkt['timestamp'], pkt['src'], pkt['dst'], pkt['protocol'], pkt['threat_desc']))
        conn.commit()
        conn.close()
        
        socketio.emit('live_packet_data', stats)

def start_background_sniffer():
    global sniffer_thread
    if sniffer_thread is None or not sniffer_thread.is_alive():
        sniffer_thread = threading.Thread(target=sniffer_instance.start_sniffing, daemon=True)
        sniffer_thread.start()
        
        broadcast_thread = threading.Thread(target=background_packet_broadcaster, daemon=True)
        broadcast_thread.start()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT password, email, otp FROM users WHERE username = ?", (username,))
        user_row = cursor.fetchone()
        conn.close()
        
        if user_row and check_password_hash(user_row[0], password):
            otp = str(random.randint(100000, 999999))
            
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET otp = ? WHERE username = ?", (otp, username))
            conn.commit()
            conn.close()
            
            session['temp_user'] = username
            session['display_otp'] = otp
            return redirect(url_for('verify_2fa'))
        else:
            flash('Invalid username or password!', 'error')
            
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'temp_user' not in session:
        return redirect(url_for('login'))
        
    otp_hint = session.get('display_otp', '------')
    
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        username = session['temp_user']
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT otp FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        
        if row and row[0] == entered_otp:
            session['user'] = username
            session.pop('temp_user', None)
            session.pop('display_otp', None)
            return redirect(url_for('index'))
        else:
            flash('Invalid 2FA Code!', 'error')
            
    return render_template('verify_2fa.html', otp_hint=otp_hint)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            flash('Username already exists!', 'error')
            conn.close()
        else:
            hashed_pw = generate_password_hash(password)
            cursor.execute("INSERT INTO users (username, password, email, otp) VALUES (?, ?, ?, ?)",
                           (username, hashed_pw, email, "123456"))
            conn.commit()
            conn.close()
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
            
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('temp_user', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

if __name__ == '__main__':
    start_background_sniffer()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)