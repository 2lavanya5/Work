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
import secrets
import os

# Import forms correctly
from forms import LoginForm, RegistrationForm, ProfileForm  

# Initialize Flask app
app = Flask(__name__, template_folder="templates")  # Ensure correct folder

# Security and configuration
csrf = CSRFProtect(app)
app.config.from_object("config.Config")  # Load configurations from `config.py`

# Database setup
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
mail = Mail(app)

# Ensure session security
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# User loader for Flask-Login
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

# Utility function for password reset token
def generate_reset_token():
    return secrets.token_urlsafe(32)

# ✅ Ensure the database is created before running the app
with app.app_context():
    db.create_all()

# Routes
@app.route("/")
def home():
    return render_template("home.html")  # Ensure this file exists in `templates/`

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
            next_page = request.args.get("next")  # Preserve next URL if it exists
            flash("Login successful!", "success")
            return redirect(next_page) if next_page else redirect(url_for("dashboard"))
        else:
            flash("Login failed. Check your email and password.", "danger")
    
    return render_template("login.html", form=form)

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    return render_template("settings.html", user=current_user)

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        user = User.query.filter_by(email=email).first()
     
        if user:
            token = generate_reset_token()
            reset_url = url_for("reset_password", token=token, _external=True)
            msg = Message("Password Reset", sender="your-email@gmail.com", recipients=[email])
            msg.body = f"Click the link to reset your password: {reset_url}"
            mail.send(msg)
            flash("Password reset link sent to your email!", "info")
            return redirect(url_for("login"))

    return render_template("forgot_password.html")

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if request.method == "POST":
        password = request.form["password"]
        user = User.query.filter_by(reset_token=token).first()
        if user:
            user.password = bcrypt.generate_password_hash(password).decode("utf-8")
            db.session.commit()
            flash("Password updated! Please log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("Invalid or expired token!", "danger")
            return redirect(url_for("forgot_password"))

    return render_template("reset_password.html", token=token)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("home"))

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    form = ProfileForm()  # Create form instance
    
    if form.validate_on_submit():  # Check form submission
        current_user.username = form.username.data.strip()
        current_user.email = form.email.data.strip()

        if form.password.data:
            current_user.password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")

        db.session.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for("profile"))

    return render_template("profile.html", user=current_user, form=form)

# Start Flask App
if __name__ == "__main__":
    print("Starting Flask app...")  # Debugging startup messages
    app.run(debug=True, host="0.0.0.0", port=5000)
