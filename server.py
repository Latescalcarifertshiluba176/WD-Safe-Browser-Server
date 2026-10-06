import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import bcrypt
import datetime
import sqlite3

app = Flask(__name__)
CORS(app)

# SICHER: Holt SECRET aus Render Environment, nicht aus Code!
SECRET = os.environ.get("JWT_SECRET", "nur-fuer-lokal-test-123")
DB_FILE = "users.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, pw_hash BLOB, device_id TEXT)")
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return "WD Safe Browser Server laeuft sicher!"

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    pw = data.get('pw')
    device_id = data.get('device_id', 'unbekannt')

    if not email or not pw:
        return jsonify({"msg": "Fehlt"}), 400

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT email FROM users WHERE email=?", (email,))
    if cur.fetchone():
        conn.close()
        return jsonify({"msg": "Gibt es schon"}), 400

    pw_hash = bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
    cur.execute("INSERT INTO users VALUES (?, ?, ?)", (email, pw_hash, device_id))
    conn.commit()
    conn.close()
    return jsonify({"msg": "Sicher registriert!"})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    pw = data.get('pw')
    device_id = data.get('device_id', 'unbekannt')

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT pw_hash, device_id FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"ok": False, "msg": "User nicht gefunden"}), 401

    stored_hash, stored_device = row

    # Passwort pruefen
    if not bcrypt.checkpw(pw.encode(), stored_hash):
        return jsonify({"ok": False, "msg": "Falsches Passwort"}), 401

    # SICHERHEITSSYSTEM: Geraete-Bindung!
    # Wenn schon ein Geraet registriert ist und ein anderes versucht -> blocken
    if stored_device and stored_device != "unbekannt" and stored_device != device_id:
        return jsonify({"ok": False, "msg": "Anderes Geraet! Kein Zugriff ohne Erlaubnis"}), 403

    # Token generiert sich SELBER! Gueltig 30 Tage
    payload = {
        "email": email,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=30)
    }
    token = jwt.encode(payload, SECRET, algorithm="HS256")

    return jsonify({"ok": True, "token": token, "email": email})

@app.route('/verify', methods=['POST'])
def verify():
    token = request.json.get('token')
    try:
        data = jwt.decode(token, SECRET, algorithms=["HS256"])
        return jsonify({"ok": True, "email": data['email']})
    except:
        return jsonify({"ok": False}), 401

# Das MUSS unten bleiben!
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)