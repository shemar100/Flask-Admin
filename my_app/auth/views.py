from flask import request, render_template, flash, redirect, url_for, g, Blueprint, abort
from flask_login import current_user, login_user, logout_user, login_required
from my_app import app, db, login_manager
from my_app.auth.models import User, RegistrationForm, LoginForm
from functools import wraps
from my_app.auth.models import AdminUserCreateForm, AdminUserUpdateForm

auth = Blueprint('auth', __name__)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

@auth.before_request
def get_current_user():
    g.user = current_user


def admin_login_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.admin:
            return abort(403)
        return(func(*args, **kwargs))
    return decorated_view


@auth.route('/')
@auth.route('/home')
def home():
    return render_template('home.html')

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('auth.home'))
    
    form = RegistrationForm()

    if form.validate_on_submit():
        username = request.form.get('username')
        password = request.form.get('password')
        existing_username = User.query.filter_by(username=username).first()
        if existing_username:
            flash('This username has been already taken. Try another one.','warning')
            return render_template('register.html', form=form)    
        user = User(username, password)
        db.session.add(user)
        db.session.commit()
        flash('You are now registered. Please login.', 'success')
        return redirect(url_for('auth.login'))
    if form.errors:
        flash(form.errors, 'danger')
    
    return render_template('register.html', form=form)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('auth.home'))
    
    form = LoginForm()

    if form.validate_on_submit():
        username = request.form.get('username')
        password = request.form.get('password')
        existing_user = User.query.filter_by(username=username).first()

        if not (existing_user and existing_user.check_password(password)):
            flash('Invalid username or password. Please try again.', 'danger')
            return render_template('login.html', form=form)
        
        login_user(existing_user, remember=True)
        flash('You have successfully logged in.', 'success')
        return redirect(url_for('auth.home'))

    if form.errors:
        flash(form.errors, 'danger')

    return render_template('login.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.home'))


@auth.route('/admin')
@login_required
@admin_login_required
def admin():
    return render_template('admin-home.html')

@auth.route('/admin/user-lists')
@login_required
@admin_login_required
def users_list_admin():
    users = User.query.all()
    return render_template('users-list-admin.html', users=users)

@auth.route('/admin/create-user', methods=['GET', 'POST'])
@login_required
@admin_login_required
def create_user():
    form = AdminUserCreateForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        admin = form.admin.data

        existing_username = User.query.filter_by(username=username).first()
        if existing_username:
            flash('This username has already been taken try another one.', 'warning')
            return render_template('register.html')
        user = User(username, password, admin)
        db.session.add(user)
        db.session.commit()
        flash('New user created.', 'info')
        return redirect(url_for('auth.users_list_admin'))
    
    if form.errors:
        flash(form.errors, 'error')
    
    return render_template('user-create-admin.html', form=form)

@auth.route('/admin/update-user/<id>', methods=['GET', 'POST'])
@login_required
@admin_login_required
def user_update_admin(id):
    user = User.query.get(id)
    form = AdminUserUpdateForm(
        username=user.username,
        admin=user.admin
    )

    if form.validate_on_submit():
        username = form.username.data,
        admin = form.admin.data

        User.query.filter_by(id=id).update({
            'username': username,
            'admin': admin
        })

        db.session.commit()
        flash('User Updated.', 'success')
        return redirect(url_for('auth.user_list_admin'))

    if form.errors:
        flash(form.errors, 'danger')

    return render_template('user-update-admin.html', form=form)


@auth.route('/admin/delete-user/<id>')
@login_required
@admin_login_required
def user_delete_admin(id):
    user = User.query.get(id)
    db.session.delete(user)
    db.session.commit()
    flash('User Deleted.', 'info')
    return redirect(url_for('auth.users_list_admin'))



