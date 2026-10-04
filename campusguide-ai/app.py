import os, hashlib, re
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from dotenv import load_dotenv
import psycopg2

load_dotenv()
BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
DB = os.getenv("NEON_DB_STRING", "")
SECRET = hashlib.sha256((DB + "campusguide").encode()).hexdigest()
ser = URLSafeTimedSerializer(SECRET)

INSTAGRAM = "https://www.instagram.com/"
def club(n, h, cat): return {"name": n, "link": INSTAGRAM + h, "category": cat}
DATA = {
    "institute": "Institute of Technical Research and Education (ITER), Siksha 'O' Anusandhan Deemed to be University, Jagamara, Khandagiri, Bhubaneswar - 751030, Odisha, India.",
    "center": [20.2486, 85.7762],
    "departments": [
        {"code": "CSE", "name": "Computer Science & Engineering", "email": "hod.cse.iter@soa.ac.in"},
        {"code": "CSIT", "name": "Computer Science & Information Technology", "email": "hod.csit.iter@soa.ac.in"},
        {"code": "EEE", "name": "Electrical & Electronics Engineering", "email": "hod.eee.iter@soa.ac.in"},
        {"code": "EE", "name": "Electrical Engineering", "email": "hod.ee.iter@soa.ac.in"},
        {"code": "ECE", "name": "Electronics & Communication Engineering", "email": "hod.ece.iter@soa.ac.in"},
        {"code": "ME", "name": "Mechanical Engineering", "email": "hod.me.iter@soa.ac.in"},
        {"code": "CE", "name": "Civil Engineering", "email": "hod.ce.iter@soa.ac.in"},
    ],
    "offices": [
        {"name": "Dean, ITER", "email": "dean.iter@soa.ac.in", "icon": "🎓"},
        {"name": "Placement Cell", "email": "placement.iter@soa.ac.in", "icon": "💼"},
        {"name": "General Information", "email": "info@soa.ac.in", "icon": "📩"},
        {"name": "Grievance", "email": "grievance@soa.ac.in", "icon": "⚠️"},
    ],
    "hostels": [
        {"name": "Boys' Hostels", "info": "On-campus residential blocks for male students.", "facilities": ["Mess / dining", "Wi-Fi", "Laundry", "Common room"]},
        {"name": "Girls' Hostels", "info": "On-campus residential blocks for female students.", "facilities": ["Mess / dining", "Wi-Fi", "Laundry", "Common room"]},
        {"name": "Rules & Wardens", "info": "Warden names, phone numbers, in/out timings and rules are not preloaded. Please confirm with your hostel office or info@soa.ac.in.", "facilities": ["Warden details: add yours", "Rules: add yours"]},
    ],
    "clubs": [
        club("Google Developers Group on Campus ITER", "gdg_iter", "Coding"),
        club("Codex", "codexiter", "Coding"),
        club("GeeksForGeeks Campus Body ITER", "gfg_iter", "Coding"),
        club("Coding Ninjas 10X on Campus SOA", "cn.10x.iter", "Coding"),
        club("SOA Flying Community", "soa_flying_community", "Automation"),
        club("ITER Robotics Club", "iterroboticsclub", "Automation"),
        club("Srishti - Brushing the Beyond", "srishti_club", "Art"),
        club("SOA Literary Club", "soaliterary_club", "Literary & Social"),
        club("SOA English Cafe", "soaenglishcafe", "Literary & Social"),
        club("Danza", "danza_soa", "Cultural"),
        club("Odanza - The Classical Beat", "soa_odanza", "Cultural"),
        club("SOA Music Club", "soa_music_club", "Cultural"),
        club("Toneelstuck - The Stage Piece", "soa_dramatics_society", "Cultural"),
        club("SOA ACM Students Chapter", "soa_acm", "Research"),
        club("IEEE SOA Students Branch", "ieeesoa", "Research"),
        club("National Service Scheme ITER", "iter_soa_nss", "Communities"),
        club("SOA National Cadet Corps", "soa_ncc", "Communities"),
        club("JAAGO - Towards a Better Future", "soa_jaago_official", "Other"),
        club("SOA Radio Student's Team", "soa.radio", "Other"),
        club("Innovation & Entrepreneurship Cell", "ecellsoau", "Other"),
    ],
}

def conn():
    return psycopg2.connect(DB)

_ready = False
def init_db():
    global _ready
    if _ready: return
    with conn() as c, c.cursor() as cur:
        cur.execute("""CREATE TABLE IF NOT EXISTS users(
            id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
            pw_hash TEXT NOT NULL, created_at TIMESTAMP DEFAULT NOW())""")
    _ready = True

def user_from_token():
    tok = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        return ser.loads(tok, max_age=60 * 60 * 24 * 14)
    except (BadSignature, SignatureExpired):
        return None

@app.route("/")
def home():
    return send_from_directory(BASE, "index.html")

@app.route("/healthz")
def health():
    return "ok"

@app.route("/api/data")
def data():
    return jsonify(DATA)

@app.route("/api/register", methods=["POST"])
def register():
    j = request.get_json(force=True, silent=True) or {}
    name, email, pw = j.get("name", "").strip(), j.get("email", "").strip().lower(), j.get("password", "")
    if not name or not re.match(r"[^@]+@[^@]+\.[^@]+", email) or len(pw) < 6:
        return jsonify(error="Enter a name, valid email and a password of 6+ characters."), 400
    try:
        init_db()
        with conn() as c, c.cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE email=%s", (email,))
            if cur.fetchone(): return jsonify(error="Email already registered."), 409
            cur.execute("INSERT INTO users(name,email,pw_hash) VALUES(%s,%s,%s)", (name, email, generate_password_hash(pw)))
    except Exception as e:
        return jsonify(error="Database error. Check NEON_DB_STRING."), 500
    return jsonify(token=ser.dumps({"name": name, "email": email}), name=name)

@app.route("/api/login", methods=["POST"])
def login():
    j = request.get_json(force=True, silent=True) or {}
    email, pw = j.get("email", "").strip().lower(), j.get("password", "")
    try:
        init_db()
        with conn() as c, c.cursor() as cur:
            cur.execute("SELECT name,pw_hash FROM users WHERE email=%s", (email,))
            row = cur.fetchone()
    except Exception:
        return jsonify(error="Database error. Check NEON_DB_STRING."), 500
    if not row or not check_password_hash(row[1], pw):
        return jsonify(error="Invalid email or password."), 401
    return jsonify(token=ser.dumps({"name": row[0], "email": email}), name=row[0])

@app.route("/api/me")
def me():
    u = user_from_token()
    return (jsonify(u), 200) if u else (jsonify(error="unauthorized"), 401)

@app.route("/api/chat", methods=["POST"])
def chat():
    if not user_from_token():
        return jsonify(error="Please sign in to chat with the AI assistant."), 401
    msg = (request.get_json(force=True, silent=True) or {}).get("message", "").strip()[:1000]
    if not msg: return jsonify(error="Empty message"), 400
    key = os.getenv("GEMINI_API_KEY")
    if not key: return jsonify(error="GEMINI_API_KEY is not set on the server."), 500
    try:
        import google.generativeai as genai
        genai.configure(api_key=key)
        sys = ("You are CampusGuide AI, a friendly assistant for students of ITER, SOA University, Bhubaneswar. "
               "Answer using ONLY this campus data when possible; if something is not in it (e.g. warden names, phone numbers, timings), "
               "say you don't have it and suggest contacting info@soa.ac.in or the relevant office. For nearby places (cafes, ATMs, pharmacies, "
               "stationery) tell the user to use the Map section. Keep answers short and use bullet points.\nDATA: " + str(DATA))
        model = genai.GenerativeModel(os.getenv("GEMINI_MODEL", "gemini-3.5-flash"), system_instruction=sys)
        return jsonify(reply=model.generate_content(msg).text)
    except Exception as e:
        return jsonify(error="AI service error: " + str(e)[:160]), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
