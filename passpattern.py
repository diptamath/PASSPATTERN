import string, random, re
from flask import Flask, request, g, render_template, redirect, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash

from sqlalchemy.ext.hybrid import hybrid_property
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo

app = Flask(__name__)

app.config.update(dict(
    DEBUG=True,
    SECRET_KEY=''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) 
                for _ in range(20)),
    SQLALCHEMY_DATABASE_URI='sqlite:///users.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
))

app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(64), unique=True)
    password = db.Column(db.String(128))

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def valid_username(self):
        return (self.query.filter_by(username=self.username).first() is not None);

    def valid_password(self, pattern_grid):
        stored_pattern = self.query.filter_by(username=self.username).first().password
        stored_pattern = stored_pattern.split('c')
        stored_pattern = stored_pattern[1:]
        print 'stoder_pattern: ', stored_pattern
        symbols = list(self.password)
        print 'symbols: ', symbols 
        i = 0
        for c in stored_pattern:
            print '"', pattern_grid[2][int(c[0])-1][int(c[1])-1], '"'
            if (pattern_grid[2][int(c[0])-1][int(c[1])-1] != symbols[i]):
                return False
            i = i + 1
        return True



@app.route('/')
def home():
    return render_template('home.html')


class UsernamePasswordForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=4, max=128)])

class RegisterForm(UsernamePasswordForm):
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])


def generate_pattern_guide():
    pattern = [8, 8, []]

    for i in range(pattern[0]):
        pattern[2].append([])
        for j in range(pattern[1]):
            pattern[2][i].append('c'+str(i+1)+str(j+1))
    return pattern

def generate_pattern_password():
    pattern = [8, 8, []]
    population = string.letters + string.digits + '~!@#$%^&*()_+-={}[]:;/?<>,.'
    population = population.translate(None, 'Oo-_')
    # symbols = random.sample(population, pattern[0] * pattern[1])
    # k = 0

    for i in range(pattern[0]):
        pattern[2].append([])
        for j in range(pattern[1]):
            # pattern[2][i].append(symbols[k])
            # k = k + 1

            pattern[2][i].append(random.choice(population))
    return pattern


def print_pattern(pattern):
    for i in range(pattern[0]):
        for j in range(pattern[1]):
            print pattern[2][i][j]

def print_pattern_rows(pattern):
    for i in range(pattern[0]):
        print pattern[2][i]


def check_pattern(str):
    str = str.replace(' ', '').replace('C', 'c')
    if (len(str) % 3 != 0):
        return None
    m = re.match(r'(([cC]\d\d)+)', str)
    if (not m or m.end() < len(str)):
        return None
    return str


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        password = check_pattern(form.password.data)
        new_user = User(form.username.data, password)

        if new_user.valid_username():
            flash('Username already taken', 'danger')
        elif not password:
            flash('Not a good pattern. Use something like ([cC]\d\d)+', 'danger')
        else:
            db.session.add(new_user);
            db.session.commit();
            flash('Registration successful. Log in with your credentials.', 'success')
            return redirect(url_for('home'))
    return render_template('register.html', form=form, pattern=generate_pattern_guide())


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = UsernamePasswordForm()

    print form.password.data
    if form.validate_on_submit():
        user = User(form.username.data, form.password.data)

        if not user.valid_username():
            flash('Invalid user name', 'danger')
        elif not user.valid_password(session['pattern-grid']):
            flash('Incorrect password', 'danger')
        else:
            session['logged_in'] = True
            session['username'] = user.username
            flash('Successfully logged in', 'success')
            return redirect(url_for('home'))
    pattern_grid = generate_pattern_password()
    session['pattern-grid'] = pattern_grid
    print 'login-GET: '
    print_pattern_rows(pattern_grid)
    return render_template('login.html', form=form, pattern=pattern_grid)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out', 'info')
    return redirect(url_for('home'))

