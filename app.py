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
# HELPER — verify JWT
# =========================
def get_current_user():
    """Extract and verify JWT from Authorization header.
    Returns decoded payload or raises Exception."""
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise Exception("No token provided")
    token = auth.split(" ")[1]
    decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    return decoded  # has 'username', 'role' if you add it later


# =========================
# HEALTH CHECK
# =========================
@app.route("/")
def home():
    return jsonify({"status": "Pravi backend running ✅"})

@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


# =========================
# LOGIN
# =========================
@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Missing credentials"}), 400

        # 🔍 Get user from Firestore
        users_ref = db.collection("admin_users")
        query = users_ref.where("username", "==", username).stream()

        user_doc = None
        doc_id = None
        for doc in query:
            user_doc = doc.to_dict()
            doc_id = doc.id

        if not user_doc:
            return jsonify({"error": "Invalid credentials"}), 401

        # 🔐 Check account is active
        if user_doc.get("active") == False:
            return jsonify({"error": "Account is inactive. Contact admin."}), 403

        # 🔐 Verify password
        if not bcrypt.verify(password, user_doc["passwordHash"]):
            return jsonify({"error": "Invalid credentials"}), 401

        # Update lastLogin
        db.collection("admin_users").document(doc_id).update({
            "lastLogin": datetime.datetime.utcnow().isoformat()
        })

        # 🎫 Generate token (include role)
        token = jwt.encode({
            "username": username,
            "role": user_doc.get("role", "editor"),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=8)
        }, JWT_SECRET, algorithm="HS256")

        return jsonify({
            "token": token,
            "user": username,
            "role": user_doc.get("role", "editor")
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =========================
# VERIFY TOKEN
# =========================
@app.route("/api/verify", methods=["POST"])
def verify():
    try:
        decoded = get_current_user()
        return jsonify({"valid": True, "user": decoded["username"], "role": decoded.get("role", "editor")})
    except Exception:
        return jsonify({"error": "Invalid token"}), 401


# =========================
# CHANGE PASSWORD (own account)
# =========================
@app.route("/api/change-password", methods=["POST"])
def change_password():
    try:
        decoded = get_current_user()
        data = request.get_json()

        current_password = data.get("currentPassword")
        new_password     = data.get("newPassword")
        new_username     = data.get("newUsername", "").strip()

        if not current_password:
            return jsonify({"error": "Current password required"}), 400

        # Find the user
        query = db.collection("admin_users").where("username", "==", decoded["username"]).stream()
        user_doc = None
        doc_id = None
        for doc in query:
            user_doc = doc.to_dict()
            doc_id = doc.id

        if not user_doc:
            return jsonify({"error": "User not found"}), 404

        # Verify current password
        if not bcrypt.verify(current_password, user_doc["passwordHash"]):
            return jsonify({"error": "Current password is incorrect"}), 401

        # Build update
        updates = {}
        if new_password and len(new_password) >= 6:
            updates["passwordHash"] = bcrypt.hash(new_password)
        if new_username and new_username != decoded["username"]:
            # Check not taken
            clash = db.collection("admin_users").where("username", "==", new_username).stream()
            if any(True for _ in clash):
                return jsonify({"error": "Username already taken"}), 409
            updates["username"] = new_username

        if not updates:
            return jsonify({"error": "Nothing to update"}), 400

        db.collection("admin_users").document(doc_id).update(updates)
        return jsonify({"success": True})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =========================
# USER MANAGEMENT
# =========================

@app.route("/api/users", methods=["GET"])
def list_users():
    """List all admin users. Requires valid JWT."""
    try:
        get_current_user()  # auth check

        docs = db.collection("admin_users").stream()
        users = []
        for doc in docs:
            u = doc.to_dict()
            users.append({
                "id":        doc.id,
                "username":  u.get("username", ""),
                "role":      u.get("role", "editor"),
                "status":    "active" if u.get("active", True) else "inactive",
                "created":   u.get("createdAt", ""),
                "lastLogin": u.get("lastLogin", "")
            })
        return jsonify(users)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users", methods=["POST"])
def create_user():
    """Create a new admin user. Requires valid JWT."""
    try:
        get_current_user()  # auth check

        data     = request.get_json()
        username = data.get("username", "").strip()
        password = data.get("password", "")
        role     = data.get("role", "editor")
        status   = data.get("status", "active")

        if not username:
            return jsonify({"error": "Username is required"}), 400
        if not password or len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters"}), 400

        # Check username not already taken
        clash = db.collection("admin_users").where("username", "==", username).stream()
        if any(True for _ in clash):
            return jsonify({"error": "Username already exists"}), 409

        # Hash password and save
        doc_ref = db.collection("admin_users").add({
            "username":     username,
            "passwordHash": bcrypt.hash(password),
            "role":         role,
            "active":       (status == "active"),
            "createdAt":    datetime.datetime.utcnow().strftime("%d/%m/%Y"),
            "lastLogin":    None
        })

        return jsonify({"success": True, "id": doc_ref[1].id}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<user_id>", methods=["PUT"])
def update_user(user_id):
    """Update an existing admin user. Requires valid JWT."""
    try:
        get_current_user()  # auth check

        data     = request.get_json()
        username = data.get("username", "").strip()
        role     = data.get("role")
        status   = data.get("status")
        password = data.get("password", "")

        doc_ref = db.collection("admin_users").document(user_id)
        doc     = doc_ref.get()
        if not doc.exists:
            return jsonify({"error": "User not found"}), 404

        updates = {}
        if username:
            # Check not taken by someone else
            clash = db.collection("admin_users").where("username", "==", username).stream()
            for c in clash:
                if c.id != user_id:
                    return jsonify({"error": "Username already taken"}), 409
            updates["username"] = username
        if role:
            updates["role"] = role
        if status:
            updates["active"] = (status == "active")
        if password:
            if len(password) < 6:
                return jsonify({"error": "Password must be at least 6 characters"}), 400
            updates["passwordHash"] = bcrypt.hash(password)

        if not updates:
            return jsonify({"error": "Nothing to update"}), 400

        doc_ref.update(updates)
        return jsonify({"success": True})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<user_id>", methods=["DELETE"])
def delete_user(user_id):
    """Delete an admin user. Requires valid JWT."""
    try:
        decoded = get_current_user()  # auth check

        doc_ref = db.collection("admin_users").document(user_id)
        doc     = doc_ref.get()
        if not doc.exists:
            return jsonify({"error": "User not found"}), 404

        u = doc.to_dict()

        # Prevent deleting yourself
        if u.get("username") == decoded.get("username"):
            return jsonify({"error": "You cannot delete your own account"}), 403

        # Prevent deleting superadmin
        if u.get("role") == "superadmin":
            return jsonify({"error": "Cannot delete the Super Admin account"}), 403

        doc_ref.delete()
        return jsonify({"success": True})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =========================
# LEADS
# =========================
@app.route("/api/leads", methods=["POST"])
def save_lead():
    try:
        data = request.get_json()
        db.collection("pravi_data").document("leads").collection("submissions").add({
            **data,
            "timestamp": datetime.datetime.utcnow().isoformat()
        })
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =========================
# RUN
# =========================
if __name__ == "__main__":
    app.run(debug=True)
