class Config:
    SECRET_KEY = 'hard to guess string'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root@localhost:3306/python_flask_2'

    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_USERNAME = 'deimvod@gmail.com'
    MAIL_PASSWORD = 'vetloufmaqnborgp'

    APP_SUBJECT_PRFIX = '[XM with love] '
    APP_MAIL_SENDER = 'XM <deimvod@gmail.com>'
    APP_ADMIN = 'APP_ADMIN'

    @staticmethod
    def init_app(app):
        pass

config = {
    'development': Config
}