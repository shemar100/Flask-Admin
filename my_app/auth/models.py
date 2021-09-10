from werkzeug.security import generate_password_hash,check_password_hash
from flask_wtf import FlaskForm
from wtforms import TextField, PasswordField, BooleanField, StringField, TextAreaField, widgets
from wtforms.validators import InputRequired, EqualTo
from my_app import db

#Creating user data model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String())
    pwdhash = db.Column(db.String())
    admin = db.Column(db.Boolean())
    notes = db.Column(db.UnicodeText)
    roles = db.Column(db.String(4))

    # Intialization of data model fields
    def __init__(self, username, password, admin=False, notes='', roles='R'):
        self.username = username
        self.pwdhash = generate_password_hash(password)
        self.admin = admin
        self.notes = notes
        self.roles = self.admin and roles or ''
        
    #get method which returns True/False for admin
    def is_admin(self):
        return self.admin
        
    #Method which checks if password is hash
    def check_password(self, password):
        return check_password_hash(self.pwdhash, password)

    #Flask login property which checks if user is logged in
    @property
    def is_authenticated(self):
        return True

    #Flask login property which checks if user if session is active
    @property
    def is_active(self):
        return True

    @property 
    def is_anonymous(self):
        return False

    #returns user id
    def get_id(self):
        return str(self.id)


#Scaffold Registration form Fields
class RegistrationForm(FlaskForm):
    username = TextField('Username', [InputRequired()])
    password = PasswordField('Password', [InputRequired(), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm', [InputRequired()])

#Scaffold Login form Fields
class LoginForm(FlaskForm):
    username = TextField('Username', [InputRequired()])
    password = PasswordField('Password', [InputRequired()])

#Scaffold AdminUser Creation form Fields
class AdminUserCreateForm(FlaskForm):
    username = TextField('Username', [InputRequired()])
    password = PasswordField('Password', [InputRequired()])
    admin = BooleanField('Is Admin ?')

#Scaffold AdminUser EditForm Fields
class AdminUserUpdateForm(FlaskForm):
    username = StringField('Username', [InputRequired()])
    admin = BooleanField('Is Admin ?')

#Create text are widget for admin user
class CKTextAreaWidget(widgets.TextArea):
    def __call__(self, field, **kwargs):
        kwargs.setdefault('class_', 'ckeditor')
        return super(CKTextAreaWidget, self).__call__(field, **kwargs)

#Scaffold form field as widget for textarea
class CKTextAreaField(TextAreaField):
    widget = CKTextAreaWidget()