from flask import Flask
from flask_sqlalchemy import SQLAlchemy;
from os import path
from flask_login import LoginManager


db = SQLAlchemy()

user = 'root'
password = '805914'
host = '127.0.0.1'
port = 3306
database = 'FlaskProject'


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'nobody does is better'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://{0}:{1}@{2}:{3}/{4}'.format(user, password, host, port, database)
    db.init_app(app)



    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/auth')

    from .models import User, Note
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    with app.app_context():
        db.create_all()
    return app




