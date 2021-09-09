from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from flask_admin import Admin

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_SECRET_KEY']  = 'random key for form'

csrf = CSRFProtect(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
admin = Admin(app)
#api = Api(app, decorators=[csrf.exempt])


app.secret_key = 'some_random_key'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

from my_app.auth.views import auth

app.register_blueprint(auth)

db.create_all()
