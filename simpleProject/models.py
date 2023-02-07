import datetime
import hashlib

from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from config import config
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, AnonymousUserMixin
from itsdangerous import TimedSerializer


app = Flask(__name__)
app.config.from_object(config['development'])
db = SQLAlchemy()
db.init_app(app)
login_manager = LoginManager(app)
login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Permission:
    FOLLOW = 'F'
    COMMENT = 'C'
    WRITE = 'W'
    MODERATE = 'M'
    ADMIN = 'A'

class Permission_2:
    FOLLOW = 1
    COMMENT = 2
    WRITE = 4
    MODERATE = 8
    ADMIN = 16


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class Role(db.Model):
    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = ''

    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm

    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions = self.permissions.replace(perm, '')

    def reset_permissions(self):
        self.permissions = ''

    def has_permission(self, perm):
        return perm in self.permissions or Permission.ADMIN in self.permissions

    __tablename__ = 'roles'
    id = db.Column(db.INTEGER, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    label = db.Column(db.String(64))
    user = db.relationship('User', backref='role')
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.String(12))


    @staticmethod
    def insert_roles():
        roles = {'User': [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE],
                 'Moderator': [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE, Permission.MODERATE],
                 'Administrator': [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE, Permission.MODERATE, Permission.ADMIN]
                 }
        default_role = 'User'
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permissions()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default = (role.name == default_role)
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %s>' % self.name


class User(UserMixin, db.Model):
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == app.config['MAIL_USERNAME']:
                self.role = Role.query.filter_by(name='Administrator').first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()

    def gravatar(self, size=100, default='identicon', rating='g'):
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()
        result = f'{url}/{hash}?s={size}&d={default}&r={rating}'.format(url=url, hash=hash, size=size, default=default, rating=rating)
        return result



    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)

    def is_administrator(self):
        return self.can(Permission.ADMIN)

    __tablename__ = 'users'
    confirmed = db.Column(db.Boolean, default=False)
    password_hash = db.Column(db.String(128))
    id = db.Column(db.Integer, primary_key=True)
    realname = db.Column(db.String(64))
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    email = db.Column(db.String(64), unique=True, index=True)
    location = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.datetime.utcnow())
    about_me = db.Column(db.Text())
    posts = db.relationship('Post', backref='author')

    def ping(self):
        self.last_seen = datetime.datetime.utcnow()
        db.session.add(self)

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self):
        s = TimedSerializer(app.config['SECRET_KEY'])
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        s = TimedSerializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token, 180)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    def __repr__(self):
        return '<User %s>' % self.username

class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False

class Trash(db.Model):
    __tablename__ = 'trash'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text)

    def __repr__(self):
        return '<Text %s>' % self.text

class Trash_2(UserMixin, db.Model):
    __tablename__ = 'trash_2'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text)

    def __repr__(self):
        return '<Text %s>' % self.text


login_manager.anonymous_user = AnonymousUser
