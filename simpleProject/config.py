class MailRuMixin:
    MAIL_SERVER = 'smtp.mail.ru'
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_USERNAME = 'amiridan@mail.ru'
    MAIL_PASSWORD = 'FTPJvHVp6DEhuhrhb9iY'
    APP_MAIL_SENDER = 'XM <amiridan@mail.ru>'


class GmailMixin:
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_USERNAME = 'deimvod@gmail.com'
    MAIL_PASSWORD = 'vetloufmaqnborgp'
    APP_MAIL_SENDER = 'XM <deimvod@gmail.com>'


class Config(GmailMixin):
    SECRET_KEY = 'hard to guess string'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root@localhost:3306/python_flask_2'
    APP_SUBJECT_PRFIX = '[Администратор сайта lorem] '
    APP_ADMIN = 'APP_ADMIN'

    @staticmethod
    def init_app(app):
        pass

config = {
    'development': Config
}