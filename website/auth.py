from flask import Blueprint, render_template, request as req, flash, redirect, url_for
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if req.method == 'POST':
        data = req.form
        email = data.get('email')
        password = data.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.index'))
            else:
                flash('Incorrect password', category='error')
                return render_template('login.html', user=current_user)
        else:
            flash('email not exists', category='error')
            return render_template('login.html', user=current_user)
    else:
        return render_template('login.html', user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/signup', methods=['GET', 'POST'])
def signUp():
    if req.method == 'POST':
        email = req.form.get('email')
        password = req.form.get('password1')
        confirm = req.form.get('password2')
        firstName = req.form.get('firstName')
        print(confirm)
        print(password)
        user = User.query.filter_by(email=email).first()
        if user:
            flash('email already exists', category='error')
        else:
            if len(email) < 4:
                flash('Email must be greater than 4 characters', category='error')
                return render_template('signup.html')
            elif len(firstName) < 2:
                flash('Email must be greater than 1 characters', category='error')
                return render_template('signup.html')
            elif password != confirm:
                flash('Passwords do not match', category='error')
                return render_template('signup.html')
            elif len(password) < 7:
                flash('password too short', category='error')
                return render_template('signup.html')
            else:
                new_user = User(email=email, first_name=firstName,
                                password=generate_password_hash(password, method='sha256'))
                db.session.add(new_user)
                db.session.commit()

                flash('Account created !', category='success')
                return redirect(url_for('views.index'))


    else:
        return render_template('signup.html')
