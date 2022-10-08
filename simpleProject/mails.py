from flask_mail import Mail
from flask_mail import Message
from flask import render_template
from models import app
from threading import Thread

mail = Mail(app)

def async_send_mail(msg):
    with app.app_context():
        mail.send(msg)


def send_mail(recipient, subject, template, **kwargs):
    msg = Message(app.config['APP_SUBJECT_PRFIX'] + subject, sender=app.config['APP_MAIL_SENDER'], recipients=[recipient])
    msg.body = render_template(template + '.txt', **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    thr = Thread(target=async_send_mail, args=[msg])
    thr.start()

def send_mail_2(recipient, subject, template, **kwargs):
    with app.app_context():
        msg = Message(app.config['APP_SUBJECT_PRFIX'] + subject, sender=app.config['APP_MAIL_SENDER'], recipients=[recipient])
        msg.body = render_template(template + '.txt', **kwargs)
        msg.html = render_template(template + '.html', **kwargs)
        mail.send(msg)


def send_mail_test(recipient, subject, template, **kwargs):
    with app.app_context():
        msg = Message(app.config['APP_SUBJECT_PRFIX'] + subject, sender=app.config['APP_MAIL_SENDER'], recipients=[recipient])
        msg.body = render_template(template + '.txt', **kwargs)
        msg.html = render_template(template + '.html', **kwargs)
        mail.send(msg)


# thr = Thread(target=send_mail_test, args=['rednaskel@mail.ru', 'Hui', 'test_mail'], kwargs=dict(shit='Jkdsf'))
# thr.start()
# print('Jopa')
