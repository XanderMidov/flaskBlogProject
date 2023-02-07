from views import app, db, Role, Trash, User, main_blueprint, auth_blueprint
from flask_migrate import Migrate

app.register_blueprint(main_blueprint)
app.register_blueprint(auth_blueprint, url_prefix='/auth')
migrate = Migrate(app, db)

if __name__ == '__main__':
    pass




