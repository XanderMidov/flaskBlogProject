from flask import render_template, redirect, request, session, url_for, flash
from flask import Blueprint, abort
from models import *
from forms import *
from flask_login import login_required, login_user, logout_user, current_user
from mails import send_mail, send_mail_test, send_mail_2
from decorators import admin_required, permission_required
from threading import Thread

from models import User

main_blueprint = Blueprint('main', __name__)
auth_blueprint = Blueprint('auth', __name__)

nav_dict = {'first': 'Первая',
            'second': 'Вторая',
            'third': 'Третья',
            'fourth': 'Четвертая'}


@main_blueprint.route('/user/<username>', methods=['GET', 'POST'])
@login_required
def user(username):
    form = AdminUserForm()
    if form.validate_on_submit():
        return redirect(url_for('.edit_profile_admin', id=form.user.data))
    user = User.query.filter_by(username=username).first()
    if user is None:
        abort(404)
    return render_template('user.html', user=user, form_t=form)


@main_blueprint.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.realname = form.name_form.data
        current_user.location = form.location_form.data
        current_user.about_me = form.about_me_form.data
        db.session.add(current_user)
        db.session.commit()
        flash('Ваш профиль обновлен')
        return redirect(url_for('.user', username=current_user.username))
    form.name_form.data = current_user.realname
    form.location_form.data = current_user.location
    form.about_me_form.data = current_user.about_me
    return render_template('edit_profile.html', form_t=form)


@main_blueprint.route('/edit_profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.realname = form.realname.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        db.session.commit()
        flash('Профиль обновлен')
        if current_user == user:
            redirect_param = user.username
        else:
            redirect_param = current_user.username
        return redirect(url_for('.user', username=redirect_param))
    form.email.data = user.email
    form.confirmed.data = user.confirmed
    form.username.data = user.username
    form.role.data = user.role_id
    form.realname.data = user.realname
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('edit_profile_admin.html', form_t=form, user_t=user)



@main_blueprint.route('/admin')
@login_required
@admin_required
def for_admins_only():
    content = 'Для администраторов!'
    return render_template('main.html', content_t=content)


@main_blueprint.route('/moderator')
@login_required
@permission_required(Permission.MODERATE)
def for_moderators_only():
    content = 'Для модераторов комментариев!'
    return render_template('main.html', content_t=content)


@main_blueprint.app_context_processor
def inject_nav_dict():
    return dict(nav_dict_t=nav_dict, Permission=Permission)


@main_blueprint.route('/')
def index():
    content = 'Главная страница, здесь пока ничего нет!'
    u = User.query.filter_by(email='Rednaskel@mail.ru').first()
    u.gravatar()
    return render_template('main.html', content_t=content)


@main_blueprint.route('/auth_page')
@login_required
def auth_page():
    content = 'Секретный контент, видный только авторизованным пользователям!'
    return render_template('secret.html', content_t=content)


@main_blueprint.route('/<name>')
def page(name):
    if name == 'first':
        content = 'Страница с какой-то ерундой'
    elif name == 'second':
        content = 'Ещё одна страница с ерундой'
    elif name == 'third':
        content = 'Страница третья, с ерундой'
    elif name == 'fourth':
        # token = current_user.generate_confirmation_token()
        # username = current_user.username
        # email = current_user.email
        # url = url_for('auth.confirm', token=token, _external=True)
        # thr = Thread(target=send_mail_2, args=[email, 'Hui', 'confirm'], kwargs=dict(username=username, url=url))
        # thr.start()
        content = 'Четвертая страница, здесь тоже ерунда'
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
        thr = Thread(target=send_mail_2, args=[user.email, 'Подтверждение почты', 'confirm'], kwargs=dict(username=username, url=url))
        thr.start()
        flash('Письмо с подтверждением отправлено на вашу почту, проверьте папку спам')
        return redirect(url_for('auth.login'))
    return render_template('register.html', form_t=form)


@auth_blueprint.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('Ваша почта подтверждена')
        db.session.commit()
    else:
        flash('Вы не подтвердили свою почту')
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
        flash('Не правильная почта или пароль')
    return render_template('login.html', form_t=form)


@auth_blueprint.route('/logout')
def logout():
    logout_user()
    flash('Вы вышли из аккаунта!')
    return redirect(url_for('main.index'))


@auth_blueprint.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed and request.blueprint == 'main':
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
    email = current_user.email
    url = url_for('auth.confirm', token=token, _external=True)
    thr = Thread(target=send_mail_2, args=[email, 'Повторная отправка подтверждения почты', 'confirm'],
                 kwargs=dict(username=username, url=url))
    thr.start()
    flash('A new blaa bla')
    return redirect(url_for('main.index'))


@main_blueprint.app_errorhandler(404)
def error_404(e):
    return render_template('error.html', error='Такой страницы не существует'), e.code

@main_blueprint.app_errorhandler(500)
def error_500(e):
    return render_template('error.html', error='С серваком какая-то хуйня'), e.code

@main_blueprint.app_errorhandler(403)
def error_403(e):
    return render_template('error.html', error='Эта страница доступна пользователям со специальными разрешениями'), e.code