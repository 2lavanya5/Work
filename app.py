import os
import secrets
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from sqlalchemy.exc import IntegrityError

# Initialize Flask app
app = Flask(__name__, template_folder="templates")

# Security Configurations
csrf = CSRFProtect(app)

# ✅ **Fixed Database Path**
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.sqlite")

# ✅ **Fixed Configurations**
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"  # Use absolute path
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "your_secret_key"

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
mail = Mail(app)

# ✅ Ensure Session Security
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# ✅ **Fix Database Not Found Issue**
if not os.path.exists(DB_PATH):
    print("📌 Database file not found! Creating a new one...")
    with app.app_context():
        db.create_all()
        print("✅ Database initialized successfully!")

# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database Model
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    reset_token = db.Column(db.String(255), nullable=True)

# Utility function for password reset token
def generate_reset_token():
    return secrets.token_urlsafe(32)

# Routes
@app.route("/")
def home():
    return render_template("home.html")  # Ensure this file exists

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip()
        password = form.password.data

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered. Try logging in.", "danger")
            return redirect(url_for("login"))

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)

        try:
            db.session.commit()
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for("login"))
        except IntegrityError:
            db.session.rollback()
            flash("This email is already registered!", "danger")
            return redirect(url_for("register"))

    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Login failed. Check your email and password.", "danger")
    
    return render_template("login.html", form=form)

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("home"))

# ✅ **Fix Gunicorn Crashes Due to DB Issues**
if __name__ == "__main__":
    print("📌 Starting Flask app...")

    # Ensure the database is accessible before starting the app
    with app.app_context():
        db.create_all()
    
    app.run(debug=True, host="0.0.0.0", port=5000)
