from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import datetime
from passlib.hash import bcrypt
import firebase_admin
from firebase_admin import credentials, firestore
import os
import json

app = Flask(__name__)
CORS(app)

# 🔐 JWT Secret (from Render env)
JWT_SECRET = os.environ.get("JWT_SECRET", "mysecretkey")

# 🔥 Firebase init
firebase_json = os.environ.get("FIREBASE_KEY")

cred = credentials.Certificate(json.loads(firebase_json))
firebase_admin.initialize_app(cred)

db = firestore.client()

# =========================
# HEALTH CHECK
# =========================
@app.route("/")
def home():
    return jsonify({"status": "Pravi backend running ✅"})


# =========================
# LOGIN API (FIXED)
# =========================
@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.get_json()

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Missing credentials"}), 400

        # 🔍 get user from Firestore
        users_ref = db.collection("admin_users")
        query = users_ref.where("username", "==", username).stream()

        user = None
        for doc in query:
            user = doc.to_dict()

        if not user:
            return jsonify({"error": "Invalid credentials"}), 401

        # 🔐 verify password
        if not bcrypt.verify(password, user["passwordHash"]):
            return jsonify({"error": "Invalid credentials"}), 401

        # 🎫 generate token
        token = jwt.encode({
            "username": username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=5)
        }, JWT_SECRET, algorithm="HS256")

        return jsonify({
            "token": token,
            "user": username
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =========================
# VERIFY TOKEN
# =========================
@app.route("/api/verify", methods=["POST"])
def verify():
    try:
        auth = request.headers.get("Authorization")

        if not auth:
            return jsonify({"error": "No token"}), 401

        token = auth.split(" ")[1]

        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

        return jsonify({"valid": True, "user": decoded["username"]})

    except Exception:
        return jsonify({"error": "Invalid token"}), 401


# =========================
# RUN
# =========================
if __name__ == "__main__":
    app.run(debug=True)
