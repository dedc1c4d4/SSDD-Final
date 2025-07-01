import os
import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, url_for, render_template, redirect, request, abort
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired

from data import db_session
from data.users import User
from data.news import News

from flask_login import LoginManager, logout_user, login_user, login_required, current_user

# Flask extensions for security
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'verystrong_secret_key'

# Rate Limiting Configuration
limiter = Limiter(get_remote_address, app=app, default_limits=["200/day", "50/hour"])

# Secure Headers + CSP Configuration using Flask-Talisman
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'']
}
Talisman(app, content_security_policy=csp)

# Setup login manager
login_manager = LoginManager()
login_manager.init_app(app)

# Setup Logging
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/security.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Application startup')


# Load user from database
@login_manager.user_loader
def load_user(user_id):
    session = db_session.create_session()
    return session.query(User).get(user_id)


# Registration Form
class RegisterForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    password_again = PasswordField('Repeat Password', validators=[DataRequired()])
    name = StringField('Username', validators=[DataRequired()])
    about = TextAreaField("About Me")
    submit = SubmitField('Register')


# Login Form
class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField("Remember Me")
    submit = SubmitField('Login')


# News Form
class NewsForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField("Content")
    is_private = BooleanField("Private")
    submit = SubmitField('Save')


# Home Page
@app.route("/")
def index():
    session = db_session.create_session()
    if current_user.is_authenticated:
        news = session.query(News).filter((News.user == current_user) | (News.is_private != True))
    else:
        news = session.query(News).filter(News.is_private != True)
    return render_template("index.html", news=news)


# Register Route
@app.route('/register', methods=['GET', 'POST'])
def reqister():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('register.html', title='Register',
                                   form=form, message="Passwords do not match")
        session = db_session.create_session()
        if session.query(User).filter(User.email == form.email.data).first():
            return render_template('register.html', title='Register',
                                   form=form, message="User already exists")
        user = User(
            name=form.name.data,
            email=form.email.data,
            about=form.about.data
        )
        user.set_password(form.password.data)
        session.add(user)
        session.commit()
        return redirect('/login')
    return render_template('register.html', title='Register', form=form)


# Login Route with Rate Limiting and Logging
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Only allow 5 login attempts per minute
def login():
    form = LoginForm()
    if form.validate_on_submit():
        session = db_session.create_session()
        user = session.query(User).filter(User.email == form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            app.logger.info(f"Successful login: {user.email}")
            return redirect("/")
        app.logger.warning(f"Failed login attempt for email: {form.email.data}")
        return render_template('login.html', message="Invalid login", form=form)
    return render_template('login.html', title='Login', form=form)


# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


# Add News Route
@app.route('/news', methods=['GET', 'POST'])
@login_required
def add_news():
    form = NewsForm()
    if form.validate_on_submit():
        session = db_session.create_session()
        news = News()
        news.title = form.title.data
        news.content = form.content.data
        news.is_private = form.is_private.data
        current_user.news.append(news)
        session.merge(current_user)
        session.commit()
        return redirect('/')
    return render_template('news.html', title='Add News', form=form)


# Edit News Route
@app.route('/news/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_news(id):
    form = NewsForm()
    session = db_session.create_session()
    news = session.query(News).filter(News.id == id, News.user == current_user).first()
    if request.method == "GET":
        if news:
            form.title.data = news.title
            form.content.data = news.content
            form.is_private.data = news.is_private
        else:
            abort(404)
    if form.validate_on_submit():
        if news:
            news.title = form.title.data
            news.content = form.content.data
            news.is_private = form.is_private.data
            session.commit()
            return redirect('/')
        else:
            abort(404)
    return render_template('news.html', title='Edit News', form=form)


# Delete News Route
@app.route('/news_delete/<int:id>', methods=['GET', 'POST'])
@login_required
def news_delete(id):
    session = db_session.create_session()
    news = session.query(News).filter(News.id == id, News.user == current_user).first()
    if news:
        session.delete(news)
        session.commit()
    else:
        abort(404)
    return redirect('/')


# Main function
def main():
    db_session.global_init("db/blogs.sqlite")
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)


if __name__ == '__main__':
    main()
