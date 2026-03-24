from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
import os
import json
import bcrypt
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

# Allow your frontend
CORS(app, origins=["https://pravi-5vv.pages.dev"])

# Firebase init
firebase_key = json.loads(os.environ["FIREBASE_KEY"])
cred = credentials.Certificate(firebase_key)
firebase_admin.initialize_app(cred)
db = firestore.client()

JWT_SECRET = os.environ["JWT_SECRET"]

# ══ AUTH DECORATOR ══
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"error": "No token"}), 401
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            request.user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Session expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

# ══ HOME ══
@app.route('/')
def home():
    return jsonify({"status": "Pravi backend running ✅"})

# ══ LOGIN ══
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    users = db.collection("admin_users")\
               .where("username", "==", username)\
               .where("active", "==", True)\
               .limit(1).stream()

    user_doc = next(users, None)
    if not user_doc:
        return jsonify({"error": "Invalid credentials"}), 401

    user = user_doc.to_dict()

    if not bcrypt.checkpw(password.encode(), user["passwordHash"].encode()):
        return jsonify({"error": "Invalid credentials"}), 401

    user_doc.reference.update({"lastLogin": firestore.SERVER_TIMESTAMP})

    token = jwt.encode({
        "uid": user_doc.id,
        "username": user["username"],
        "role": user["role"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=8)
    }, JWT_SECRET, algorithm="HS256")

    return jsonify({"token": token, "role": user["role"]})

# ══ VERIFY TOKEN ══
@app.route('/api/verify', methods=['POST'])
@require_auth
def verify():
    return jsonify({"valid": True, "user": request.user})

# ══ SUBMIT LEAD ══
@app.route('/api/leads', methods=['POST'])
def submit_lead():
    data = request.json
    if not data.get("firstName") or not data.get("email"):
        return jsonify({"error": "Name and email required"}), 400

    db.collection("leads").add({
        "firstName": data.get("firstName"),
        "lastName": data.get("lastName"),
        "email": data.get("email"),
        "phone": data.get("phone"),
        "company": data.get("company"),
        "projectType": data.get("projectType"),
        "budget": data.get("budget"),
        "details": data.get("details"),
        "status": "new",
        "priority": "normal",
        "createdAt": firestore.SERVER_TIMESTAMP
    })

    return jsonify({"success": True})

# ══ GET LEADS ══
@app.route('/api/leads', methods=['GET'])
@require_auth
def get_leads():
    docs = db.collection("leads").stream()
    leads = []
    for doc in docs:
        item = doc.to_dict()
        item["id"] = doc.id
        leads.append(item)
    return jsonify({"leads": leads})

# ══ UPDATE LEAD ══
@app.route('/api/leads/<lead_id>', methods=['PATCH'])
@require_auth
def update_lead(lead_id):
    db.collection("leads").document(lead_id).update(request.json)
    return jsonify({"success": True})

# ══ DELETE LEAD ══
@app.route('/api/leads/<lead_id>', methods=['DELETE'])
@require_auth
def delete_lead(lead_id):
    db.collection("leads").document(lead_id).delete()
    return jsonify({"success": True})

# ══ RUN (Render Fix) ══
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
    
from firebase_admin import firestore
import bcrypt

admin_ref = db.collection("admin_users").document("admin1")

if not admin_ref.get().exists:
    hashed = bcrypt.hashpw("Pravi@Secure#2026".encode(), bcrypt.gensalt()).decode()

    admin_ref.set({
        "username": "admin",
        "passwordHash": hashed,
        "role": "admin",
        "active": True,
        "createdAt": firestore.SERVER_TIMESTAMP
    })

    print("✅ Admin created")
