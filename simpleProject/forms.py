from flask_wtf import FlaskForm
from wtforms import StringField, DateField, TextAreaField, SubmitField, RadioField, SelectField, PasswordField, EmailField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from models import User
from models import Role

class AdminUserForm(FlaskForm):
    def __init__(self):
        super(AdminUserForm, self).__init__()
        self.user.choices = [(user.id, user.username) for user in User.query.order_by(User.username).all()]
    user = SelectField('User', coerce=int)
    submit = SubmitField('Редактировать')

class EditProfileForm(FlaskForm):
    name_form = StringField('Настоящее имя', validators=[Length(0, 64)])
    location_form = StringField('Местонахождение', validators=[Length(0, 64)])
    about_me_form = TextAreaField('Обо мне')
    submit = SubmitField('Подтвердить')


class EditProfileAdminForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(1, 64)])
    confirmed = BooleanField('Confirmed')
    role = SelectField('Role', coerce=int)
    realname = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name) for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered')

    def validate_username(self, field):
        if field.data != self.user.username and User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use')


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
    name_form = StringField('Имя пользователя', validators=[DataRequired(), Length(4)])
    password_form = PasswordField('Пароль', validators=[DataRequired(), EqualTo('password_form_2', message='Passwords must match')])
    password_form_2 = PasswordField('Подтверди пароль', validators=[DataRequired()])
    submit_form = SubmitField('Регистрация')

    def validate_email_form(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_name_form(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Email already registered.')