import flask
from flask import Flask, request, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import PasswordField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user


app = Flask(__name__)
app.config['ENV'] = 'development'
app.config['SECRET_KEY'] = "thisissecret"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = "strong"
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class LoginForm(FlaskForm):
    email = EmailField(label='email', validators=[DataRequired(), Email(message="invalid email")], render_kw={"placeholder": "Email"})
    password = PasswordField(label='password',
                             validators=[DataRequired(), Length(min=5, max=20, message="min 5 and max 20")],
                             render_kw={"placeholder": "Password"})


class RegisterForm(FlaskForm):
    email = EmailField(label='email', validators=[DataRequired(), Email(message="invalid email")], render_kw={"placeholder": "Email"})
    password = PasswordField(label='password', validators=[DataRequired()], render_kw={"placeholder": "Password"})


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
db.create_all()


@app.route("/home")
@login_required
def home():
    print(current_user.is_authenticated)
    print(current_user.is_active)
    return render_template("home.html")


@app.route("/", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('home'))
            else:
                flask.flash("incorrect password")
        else:
            flask.flash("user not found")

    return render_template("login.html", form=form)


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        if User.query.filter_by(email=email).first():
            flask.flash("user has already registered")
        else:
            # create new user
            new_user = User(
                email = email,
                password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))

    return render_template("register.html", form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
