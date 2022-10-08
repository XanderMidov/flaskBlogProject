from flask import render_template, redirect, request, session, url_for, flash
from flask import Blueprint, abort
from models import *
from forms import *
from flask_login import login_required, login_user, logout_user, current_user
from mails import send_mail, send_mail_test, send_mail_2
from decorators import admin_required, permission_required
from threading import Thread


main_blueprint = Blueprint('main', __name__)
auth_blueprint = Blueprint('auth', __name__)

nav_dict = {'first': 'Первая',
            'second': 'Вторая',
            'third': 'Третья',
            'fourth': 'Mail'}


@main_blueprint.route('/admin')
@login_required
@admin_required
def for_admins_only():
    content = 'For administrators!'
    return render_template('main.html', content_t=content)


@main_blueprint.route('/moderator')
@login_required
@permission_required(Permission.MODERATE)
def for_moderators_only():
    content = 'For comment moderators!'
    return render_template('main.html', content_t=content)


@main_blueprint.app_context_processor
def inject_nav_dict():
    return dict(nav_dict_t=nav_dict, Permission=Permission)


@main_blueprint.route('/')
def index():
    content = 'Fuck you Spielberg!'
    return render_template('main.html', content_t=content)


@main_blueprint.route('/auth_page')
@login_required
def auth_page():
    content = 'Secret page!'
    return render_template('main.html', content_t=content)


@main_blueprint.route('/<name>')
def page(name):
    if name == 'first':
        content = 'Oh shit'
    elif name == 'second':
        content = 'Oh my god'
    elif name == 'third':
        content = 'Fuck you Spielberg!'
    elif name == 'fourth':
        token = current_user.generate_confirmation_token()
        username = current_user.username
        url = url_for('auth.confirm', token=token, _external=True)
        thr = Thread(target=send_mail_2, args=['rednaskel@mail.ru', 'Hui', 'confirm'], kwargs=dict(username=username, url=url))
        thr.start()
        content = 'Mail sended'
    else:
        abort(404)
    return render_template('main.html', content_t=content)


@main_blueprint.route('/new_user', methods=['GET', 'POST'])
def new_user():
    form = UserForm()
    if form.validate_on_submit():
        user = User()
        user.username = form.data['name_form']
        user.password = form.data['password_form']
        db.session.add(user)
        db.session.commit()
        flash('New user added!')
        return redirect('new_user')
    return render_template('new_user.html', form_t=form)


@auth_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email_form.data,
                    username=form.name_form.data,
                    password=form.password_form.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        username = user.username
        url = url_for('auth.confirm', token=token, _external=True)
        thr = Thread(target=send_mail_2, args=['rednaskel@mail.ru', 'Hui', 'confirm'], kwargs=dict(username=username, url=url))
        thr.start()
        flash('A confirmation email has been sent to you by email')
        return redirect(url_for('auth.login'))
    return render_template('register.html', form_t=form)


@auth_blueprint.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You confirmed')
        db.session.commit()
    else:
        flash('You not confir....')
    return redirect(url_for('main.index'))


@auth_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email_form.data).first()
        if user is not None and user.verify_password(form.password_form.data):
            login_user(user, form.remember_me_form.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('main.index')
            return redirect(next)
        flash('Invalid username or password')
    return render_template('login.html', form_t=form)


@auth_blueprint.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out!')
    return redirect(url_for('main.index'))


@auth_blueprint.before_app_request
def before_request():
    if current_user.is_authenticated and not current_user.confirmed and request.blueprint == 'main':
        return redirect(url_for('auth.unconfirmed'))


@auth_blueprint.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect('main.index')
    return render_template('unconfirmed.html')


@auth_blueprint.route('/confirm')
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    username = current_user.username
    url = url_for('auth.confirm', token=token, _external=True)
    thr = Thread(target=send_mail_2, args=['rednaskel@mail.ru', 'Hui', 'confirm'],
                 kwargs=dict(username=username, url=url))
    thr.start()
    flash('A new blaa bla')
    return redirect(url_for('main.index'))


@main_blueprint.app_errorhandler(Exception)
def error(e):
    return render_template('error.html', error=e.description), e.code

