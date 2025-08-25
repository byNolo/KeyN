from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, DateField
from wtforms.validators import DataRequired, Email, EqualTo, Optional, Length, URL


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm = PasswordField("Confirm Password", validators=[
        DataRequired(), EqualTo("password")
    ])
    submit = SubmitField("Register")

# Forgot Password form
class ForgotPasswordForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Send Reset Link")

# Forgot Username form
class ForgotUsernameForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Send Username")

# Profile editing form
class ProfileForm(FlaskForm):
    first_name = StringField("First Name", validators=[Optional(), Length(max=100)])
    last_name = StringField("Last Name", validators=[Optional(), Length(max=100)])
    display_name = StringField("Display Name", validators=[Optional(), Length(max=200)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    bio = TextAreaField("Bio", validators=[Optional(), Length(max=500)])
    website = StringField("Website", validators=[Optional(), URL(), Length(max=500)])
    location = StringField("Location", validators=[Optional(), Length(max=200)])
    date_of_birth = DateField("Date of Birth", validators=[Optional()])
    submit = SubmitField("Update Profile")

# Profile completion form for new users
class ProfileCompletionForm(FlaskForm):
    first_name = StringField("First Name", validators=[Optional(), Length(max=100)])
    last_name = StringField("Last Name", validators=[Optional(), Length(max=100)])
    display_name = StringField("Display Name", validators=[Optional(), Length(max=200)], 
                              description="How you'd like to be displayed (optional)")
    bio = TextAreaField("Bio", validators=[Optional(), Length(max=500)], 
                       description="Tell us a bit about yourself (optional)")
    location = StringField("Location", validators=[Optional(), Length(max=200)], 
                          description="Your city, country, or region (optional)")
    date_of_birth = DateField("Date of Birth", validators=[Optional()], 
                             description="Your birthday (optional)")
    website = StringField("Website", validators=[Optional(), URL(), Length(max=500)], 
                         description="Your personal website or portfolio (optional)")
    submit = SubmitField("Complete Profile")
    skip = SubmitField("Skip for Now")

# Change Password form
class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current Password", validators=[DataRequired()])
    new_password = PasswordField("New Password", validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField("Confirm New Password", validators=[
        DataRequired(), EqualTo("new_password", message="Passwords must match")
    ])
    submit = SubmitField("Change Password")
