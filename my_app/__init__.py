from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from flask_admin import Admin


#Intialize flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_SECRET_KEY']  = 'random key for form'


#Add cross site request forgery token for form protection
csrf = CSRFProtect(app)

#Intialiazes SQLAlchemy orm to take care of persisting data mdoels data to database
db = SQLAlchemy(app)
#Intialize flask migrate to track schema changes to database
migrate = Migrate(app, db)
app.secret_key = 'some_random_key'

#Intialize flask login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

#Import views to be used in admin view context
import my_app.auth.views as views

#Intialize admin view
admin = Admin(app, index_view=views.MyAdminIndexView())

#User admin view
admin.add_view(views.UserAdminView(views.User, db.session))

#Register blueprint for authentication route handlers
from my_app.auth.views import auth
app.register_blueprint(auth)

#Create all database schema and model
db.create_all()