from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///secure_users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Generate or use a fixed key for AES encryption
key = Fernet.generate_key()
cipher = Fernet(key)

# Database model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_encrypted = db.Column(db.LargeBinary, nullable=False)

# Initialize database
with app.app_context():
    db.create_all()

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    # Encrypt password using AES
    encrypted_pw = cipher.encrypt(password.encode())

    # Securely insert (no raw SQL)
    new_user = User(username=username, password_encrypted=encrypted_pw)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered securely!"}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()
    if user and cipher.decrypt(user.password_encrypted).decode() == password:
        return jsonify({"message": "Login successful!"}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

if __name__ == "__main__":
    app.run(debug=True)
