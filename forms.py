from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo

class ProfileForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=20)])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("New Password", validators=[Length(min=6)])
    submit = SubmitField("Update Profile")
    
# Registration Form
class RegistrationForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=3, max=25)],
        render_kw={"placeholder": "Enter your username"},
    )
    email = StringField(
        "Email",
        validators=[DataRequired(), Email()],
        render_kw={"placeholder": "Enter your email"},
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=6)],
        render_kw={"placeholder": "Enter your password"},
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match")],
        render_kw={"placeholder": "Confirm your password"},
    )
    submit = SubmitField("Register")

# Login Form
class LoginForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[DataRequired(), Email()],
        render_kw={"placeholder": "Enter your email"},
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired()],
        render_kw={"placeholder": "Enter your password"},
    )
    submit = SubmitField("Login")

# Profile Update Form (Optional)
class UpdateProfileForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=3, max=25)],
        render_kw={"placeholder": "Update your username"},
    )
    email = StringField(
        "Email",
        validators=[DataRequired(), Email()],
        render_kw={"placeholder": "Update your email"},
    )
    submit = SubmitField("Update Profile")
