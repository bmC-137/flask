import sys
import requests
import os
from os import environ
from datetime import datetime, timedelta
from functools import wraps
from threading import Thread

from flask import Flask, render_template, g, request, jsonify, abort, redirect, url_for, session, flash, Markup
from flask_login import LoginManager, current_user, login_required, login_user, logout_user, UserMixin
from flask_mail import Mail, Message
from werkzeug.security import check_password_hash, generate_password_hash
from flask_migrate import Migrate
from apscheduler.schedulers.background import BackgroundScheduler
from flask_wtf import FlaskForm
from flask_flatpages import FlatPages
from flask_frozen import Freezer
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
# from wtform import StringField, SubmitField, BooleanField, PasswordField, IntegerField, TextField, FormField, SelectField, FieldList
from wtforms.validators import DataRequired, Length
from wtforms.fields import *


#There are some CSRF issues with this... not sure what causing it...
#from flask_wtf import FlaskForm, CSRFProtect


# Github App Config
client_secret=''
client_id=''
token_url='https://github.com/login/oauth/access_token'
github_url='https://github.com/login/oauth/authorize?client_id'
base_url='https://api.github.com'


# Dictionary Access


#Flask_FlatPages Config
DEBUG = True
FLATPAGES_AUTO_RELOAD = DEBUG
FLATPAGES_MARKDOWN_EXTENSIONS = ['codehilite', 'fenced_code']
FLATPAGES_EXTENSION = ['.md', '.html']


app = Flask(__name__)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
mail = Mail()
mail.init_app(app)
migrate = Migrate(app,db)
scheduler = BackgroundScheduler()

app.config.from_object('config.TestConfig')

app.secret_key = b''

# class Config():
#     DEBUG = True
#     CSRF_ENABLED = True
#     SECRET_KEY = os.environ.get('SECRET_KEY') or ""

#     SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
#     SQLALCHEMY_TRACK_MODIFICATIONS = True

#     MAIL_SERVER = ''
#     MAIL_PORT = 465
#     MAIL_USE_TLS = False
#     MAIL_USE_SSL = True
#     MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
#     MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
#     ADMIN_USERNAME = 'ADMIN_USERNAME'
#     ADMIN_PASSWORD = 'ADMIN_PASSWORD'


# class TestConfig():
#     DEBUG = True
#     TESTING = True
#     WTF_CSRF_ENABLED = False
#     SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

# class ProductionConfig():
#     Debug = False
#     TESTING = False

# class DevelopmentConfig():
#     DEVELOPMENT = True
#     DEBUG = True

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    email = db.Column(db.String(255))
    password = db.Column(db.String(255))
    book = db.relationship('Copy', backref='issue', lazy=True)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    author = db.Column(db.String(255))
    description = db.Column(db.String(255))
    copy = db.relationship('Copy', backref='copies', cascade='all,delete', lazy=True)
    total_copy = db.Column(db.Integer, )
    issued_copy = db.Column(db.Integer, )
    present_copy = db.Column(db.Integer, )

class Copy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_added = db.Column(db.DateTime(), )
    issued_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True, default=None)
    date_issued = db.Column(db.DateTime(), default=None)
    date_return = db.Column(db.DateTime(), default=None)
    book = db.Column(db.Integer, db.ForeignKey('book.id'))


class globalize:
    sess = 'user'
    direct = 0

async def notify():
    books = Copy.query.filter(Copy.issued_by is not None).all()
    for book in books:
        if book.date_return.hour == datetime.now().hour and book.date_return.date == datetime.now().date:
            send_mail('Notification', 'info@itenv.net', [book.issue.email], f"""Notification""")

#Login Manager

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

def send_mail(subject, sender, recipients, html_body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.html = html_body
    thr = Thread(target=send_async_email, args=[app, msg])
    thr.start()

# Why this functool @wraps is used here hmm ?
def requires_roles(roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not globalize.sess == roles:
                return unauthorized()
            return f(*args, **kwargs)
        return wrapped
    return wrapper

@app.route('/', methods=['GET'])
def index():
    books = Book.query.all()
    if books:
        return render_template('index.html', year = datetime.now().year, books = books)
    flash('No books are in library!')
    return render_template('index.html', year = datetime.now().year)

@app.route('/issue_direct/<id>', methods=['GET'])
def issue(id):
    if current_user.is_authenticated:
        globalize.direct = id
        return direct(url_for('new_issue'))
    globalize.direct = id
    return redirect(url_for('login'))

@app.route('/login', methods=['POST'])
def loginuser():
    # try:
    #     if request.method == 'GET';
    #         return redirect(url_for('index'))
    email = request.form['email']
    password = request.form['password']
    chekuser = User.query.filter_by(email=email).first()
    if chekuser and check_password_hash(checkuser.password, password):
        login_user(chekuser)
        if int(globalize.direct) > 0:
            return redirect(url_for('create_issue'))
        return redirect('/dashboard')
    flash('Invalid Credentials')
    return redirect(url_for('login'))


@app.route('/register', methods=['GET'])
def register():
    return render_template('register.html', year=datetime.now().year)

@app.route('/register', methods=['POST'])
def register_user():
    name = request.form['name']
    email = request.form['email']
    password = generate_password_hash(request.form['password'], method='sha256')
    checksuer = User.query.filter_by(email=email).first()
    if checkuser:
        flash('Email Already Exists!')
        return redirect(url_for('register'))
    user = User(name=name, email=email, password=password)
    db.session.add(user)
    db.session.commit()
    login_user(user)
    send_email('Your Registration was successfull!', 'info@itenv.net', [ current_user.email ], f"""Thank you for registering""")
    return redirect('/dashboard')

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    copies = Copy.query.filter_by(issued_by = current_user.id).all()
    if copies:
        return render_template('dashboard.html', year=datetime.now().year, books=copies)


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    globalize.direct = 0
    return redirect(url_for('index'))

@login_manager.unauthorized_handler
def unauthorized():
    flash('You are not authorized!')
    return redirect(url_for('login'))

if __name__ == '__main__':
    db.create_all()
    HOST = environ.get('SERVER_HOST', 'localhost')
    try:
        PORT = int(environ.get('SERVER_PORT', '8000'))
    except ValueError:
        PORT = 8000
    app.run(HOST, PORT, threaded=True, debug=True)
