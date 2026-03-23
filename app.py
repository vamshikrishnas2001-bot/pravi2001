from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
import os
import json

app = Flask(__name__)
CORS(app)   # ✅ Allow frontend requests

# 🔐 Firebase from ENV (Render)
firebase_key = json.loads(os.environ["FIREBASE_KEY"])
cred = credentials.Certificate(firebase_key)
firebase_admin.initialize_app(cred)
db = firestore.client()


# 🏠 Home route
@app.route('/')
def home():
    return "Backend is running ✅"


# 📩 API: Save form data
@app.route('/submit', methods=['POST'])
def submit():
    data = request.json

    # ✅ Validation
    if not data.get("name") or not data.get("phone"):
        return jsonify({"error": "Missing data"}), 400

    # ✅ Save data (no overwrite)
    db.collection("pravi_data").add({
        "name": data.get("name"),
        "phone": data.get("phone"),
        "time": firestore.SERVER_TIMESTAMP
    })

    return jsonify({"status": "success"})


# 📊 API: Get all leads (Admin only)
@app.route('/leads', methods=['GET'])
def get_leads():
    key = request.headers.get("admin-key")

    # 🔐 Basic security
    if key != "12345":
        return jsonify({"error": "Unauthorized"}), 403

    docs = db.collection("pravi_data").stream()

    data = []
    for doc in docs:
        item = doc.to_dict()
        item["id"] = doc.id
        data.append(item)

    return jsonify(data)


# ▶️ Run server
if __name__ == '__main__':
    app.run(debug=True)