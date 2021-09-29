# flask-authentication

### Authentication (register and login website)
- flask wtf form for secure request
- simple register and login (check email and password)
- hashing and salting password (in python werkzeug.security)
- route authentication with flask-login or flask session
- flash message
- use ssl
---------------------------------
## Hashing and Salting Password
### Import 
```
from werkzeug.security import generate_password_hash, check_password_hash
```

### Generate Hash Password
```
generate_password_hash('pa$$word', method='pbkdf2:sha256', salt_length=8)
```

### Check Hash Password
```
check_password_hash(password from database, user input password)
```
-------------------------------------
------------------
## Flask-Login Authentication
### import
#### main.py
```
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
```
----------------------------
### LoginManager Class
#### main.py
```
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))
```
-------------------------
### UserMixin
#### main.py
```
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(50), nullable=False)
    type = db.Column(db.String(50), nullable=False)
```
--------------------------
### Login User
#### main.py (login and register route)
```
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        new_user = User(
            name=request.form['name'],
            email = request.form['email'],
            password = generate_password_hash(request.form['password'], method='pbkdf2:sha256', salt_length=8)
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)

        return redirect(url_for("user"))
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user:
            if check_password_hash(user.password, request.form['password']):
                login_user(user)
                return redirect(url_for("user"))
            else:
                flash("incorrect password")
        else:
            flash("not found email")
    return render_template("login.html")
```
----------------------------------
### Login Required
#### main.py
```
@app.route('/user')
@login_required
def user():
    return render_template("user.html", name=current_user.name)
    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))
```
------------------------------
### Secure Cookie
#### app config
```
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
```
#### main.py
```
login_manager.session_protection = "strong"
```
-------------------------------
---------------------------------
------------------
## Flask Messages
### Flash Messages for unauthorized user
#### main.py
```
login_manager.login_view = "login"
login_manager.login_message = "You really need to login!"
```
#### login.html
```
{% with messages = get_flashed_messages() %}
  {% if messages %}
    <ul class=flashes>
    {% for message in messages %}
      <li>{{ message }}</li>
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
```
---------------------------------------
### Flash Messages for login failed (flash("incorrect password"))
#### main.py
```
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # hash_password = generate_password_hash(request.form['password'], method='pbkdf2:sha256', salt_length=8)
        user = User.query.filter_by(email=request.form['email']).first()
        if user:
            if check_password_hash(user.password, request.form['password']):
                login_user(user)
                return redirect(url_for("secrets"))
            else:
                flash("incorrect password")
        else:
            flash("not found email")
    return render_template("login.html")
```
#### login.html
```
{% with messages = get_flashed_messages() %}
  {% if messages %}
    <ul class=flashes>
    {% for message in messages %}
      <li>{{ message }}</li>
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
```
----------------------------------------

