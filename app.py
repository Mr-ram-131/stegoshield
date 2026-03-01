from flask import Flask, render_template, redirect, url_for, request, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
import io
import os
from cryptography.fernet import Fernet



# Generate this once and keep constant
SECRET_ENCRYPTION_KEY = b'dyqpb8e6X0cTdyJyrcyNo2nSwJtg7FzD1CbOcCWe_rU='
cipher = Fernet(SECRET_ENCRYPTION_KEY)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# ================= DATABASE =================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    role = db.Column(db.String(20), default="user")  # NEW FIELD


from datetime import datetime

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    action = db.Column(db.String(50))
    filename = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ================= ROUTES =================

@app.route('/')
def index():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        if User.query.filter_by(username=username).first():
            flash("Username already exists", "danger")
            return redirect(url_for('register'))

        new_user = User(username=username, password=password,role="admin")
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Login now.", "success")
        return redirect(url_for('login'))

    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials", "danger")

    return render_template("login.html")


@app.route('/dashboard')
@login_required
def dashboard():
    history = History.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", history=history)


@app.route('/admin')
@login_required
def admin():
    if current_user.role != "admin":
        flash("Access Denied", "danger")
        return redirect(url_for('dashboard'))

    total_users = User.query.count()
    total_encodes = History.query.filter_by(action="Encode").count()
    total_decodes = History.query.filter_by(action="Decode").count()

    recent_activity = db.session.query(
        History, User.username
    ).join(User, History.user_id == User.id)\
     .order_by(History.timestamp.desc()).limit(10).all()

    # Daily usage tracking
    daily_data = db.session.query(
        db.func.date(History.timestamp),
        db.func.count(History.id)
    ).group_by(db.func.date(History.timestamp)).all()

    dates = [str(d[0]) for d in daily_data]
    counts = [d[1] for d in daily_data]

    all_users = User.query.all()

    return render_template(
        "admin.html",
        total_users=total_users,
        total_encodes=total_encodes,
        total_decodes=total_decodes,
        recent_activity=recent_activity,
        dates=dates,
        counts=counts,
         all_users=all_users
    )

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role != "admin":
        flash("Access Denied", "danger")
        return redirect(url_for('dashboard'))

    user = User.query.get(user_id)

    if user and user.role != "admin":
        History.query.filter_by(user_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()
        flash("User deleted successfully", "success")

    return redirect(url_for('admin'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# ================= STEGANOGRAPHY =================

@app.route('/encode', methods=['POST'])
@login_required
def encode():
    image_file = request.files['image']
    secret = request.form['secret']
    encrypted_secret = cipher.encrypt(secret.encode()).decode()
    secret = encrypted_secret

    image = Image.open(image_file).convert("RGB")
    pixels = image.load()
    width, height = image.size

    secret += "###"
    binary_secret = ''.join(format(ord(i), '08b') for i in secret)
    data_index = 0

    for y in range(height):
        for x in range(width):
            if data_index < len(binary_secret):
                r, g, b = pixels[x, y]
                r = (r & ~1) | int(binary_secret[data_index])
                pixels[x, y] = (r, g, b)
                data_index += 1

    img_io = io.BytesIO()
    image.save(img_io, 'PNG')
    img_io.seek(0)

    history = History(user_id=current_user.id, action="Encode", filename=image_file.filename)
    db.session.add(history)
    db.session.commit()

    return send_file(img_io, mimetype='image/png', as_attachment=True, download_name="encoded.png")


@app.route('/decode', methods=['POST'])
@login_required
def decode():
    image_file = request.files['image']
    image = Image.open(image_file).convert("RGB")
    pixels = image.load()
    width, height = image.size

    binary_data = ""

    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary_data += str(r & 1)

    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded = ""

    for byte in all_bytes:
        decoded += chr(int(byte, 2))
        if decoded.endswith("###"):
            break

    encrypted_message = decoded[:-3]

    try:
        message = cipher.decrypt(encrypted_message.encode()).decode()
    except:
        message = "Decryption Failed"

    history = History(user_id=current_user.id, action="Decode", filename=image_file.filename)
    db.session.add(history)
    db.session.commit()

    flash(f"Decoded Message: {message}", "info")
    return redirect(url_for('dashboard'))


# ================= MAIN =================

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    if not os.path.exists("database.db"):
        with app.app_context():
            db.create_all()
    app.run()

