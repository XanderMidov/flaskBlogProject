from flask_wtf import FlaskForm
from wtforms import StringField, DateField, TextAreaField, SubmitField, RadioField, SelectField, PasswordField, EmailField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from models import User

class NameForm(FlaskForm):
    name_form = StringField('What is your fucking name?', validators=[DataRequired()])
    date_form = DateField('Choose date', validators=[DataRequired()])
    text_form = TextAreaField('Write text')
    select_form = SelectField('Choose your destiny', choices=[('piska', 'Piska'), ('jopa', 'Jopa'), ('siski', 'Siski')])
    radio_form = RadioField('Choose variant', validators=[DataRequired()],
                            choices=[('jopa', 'Jopa'), ('piska', 'Piska')])
    submit_form = SubmitField('Submit')

class TrashForm(FlaskForm):
    text_form = TextAreaField('Write text')
    submit_form = SubmitField('Submit')

class UserForm(FlaskForm):
    name_form = StringField('What is your fucking name?', validators=[DataRequired()])
    password_form = PasswordField('What is your password?', validators=[DataRequired()])
    submit_form = SubmitField('Submit')

class LoginForm(FlaskForm):
    email_form = EmailField('E-Mail', validators=[DataRequired(), Email(), Length(4)])
    password_form = PasswordField('Password', validators=[DataRequired()])
    remember_me_form = BooleanField('Keep me logged in')
    submit_form = SubmitField('Log in')

class RegistrationForm(FlaskForm):
    email_form = EmailField('E-Mail', validators=[DataRequired(), Email(), Length(4)])
    name_form = StringField('What is your fucking name?', validators=[DataRequired(), Length(4)])
    password_form = PasswordField('Password', validators=[DataRequired(), EqualTo('password_form_2', message='Passwords must match')])
    password_form_2 = PasswordField('Confirm password', validators=[DataRequired()])
    submit_form = SubmitField('Register')

    def validate_email_form(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_name_form(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Email already registered.')