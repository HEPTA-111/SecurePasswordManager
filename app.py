import os
import random
import string
import json
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError

from security import (
    hash_master_password,
    verify_master_password,
    derive_encryption_key,
    encrypt_data,
    decrypt_data,
)

app = Flask(__name__)
try:
    os.makedirs(app.instance_path)
except OSError:
    pass

app.config['SECRET_KEY'] = os.urandom(32)
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(app.instance_path, 'passwords.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    hashed_master_password = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.LargeBinary, nullable=False)
    credentials = db.relationship('Credential', backref='owner', lazy=True, cascade="all, delete-orphan")

class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website_name = db.Column(db.String(200), nullable=False)
    encrypted_data = db.Column(db.LargeBinary, nullable=False)
    nonce = db.Column(db.LargeBinary, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Master Password', validators=[DataRequired(), Length(min=12)])
    confirm_password = PasswordField('Confirm Master Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Create Secure Account')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Username already taken.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Master Password', validators=[DataRequired()])
    submit = SubmitField('Unlock Vault')

class AddPasswordForm(FlaskForm):
    website_name = StringField('Website Name', validators=[DataRequired()])
    username = StringField('Username / Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Save to Vault')

class DeleteForm(FlaskForm):
    pass

@app.route("/")
def index():
    return redirect(url_for('dashboard'))

@app.route("/dashboard")
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    form = AddPasswordForm()
    delete_form = DeleteForm()
    credentials_list = []
    key = derive_encryption_key(session['master_password'], user.salt)
    for cred in user.credentials:
        data = decrypt_data(cred.nonce, cred.encrypted_data, key)
        if data:
            info = json.loads(data.decode())
            credentials_list.append({
                'id': cred.id,
                'website': cred.website_name,
                'username': info.get('username', '[N/A]')
            })
    credentials_list.sort(key=lambda x: x['website'].lower())
    return render_template('dashboard.html', title='Dashboard',
                           credentials=credentials_list, form=form,
                           delete_form=delete_form, username=user.username)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        salt = os.urandom(16)
        new_user = User(
            username=form.username.data,
            hashed_master_password=hash_master_password(form.password.data),
            salt=salt
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Account created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and verify_master_password(user.hashed_master_password, form.password.data):
            session['user_id'] = user.id
            session['master_password'] = form.password.data
            return redirect(url_for('dashboard'))
        flash('Login failed.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/add_password", methods=['POST'])
def add_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    form = AddPasswordForm()
    if form.validate_on_submit():
        user = User.query.get(session['user_id'])
        key = derive_encryption_key(session['master_password'], user.salt)
        blob = json.dumps({
            'username': form.username.data,
            'password': form.password.data
        }).encode()
        nonce, encrypted = encrypt_data(blob, key)
        new_cred = Credential(
            website_name=form.website_name.data,
            encrypted_data=encrypted,
            nonce=nonce,
            owner=user
        )
        db.session.add(new_cred)
        db.session.commit()
        flash(f'Credentials for {form.website_name.data} saved!', 'success')
    else:
        for errors in form.errors.values():
            for e in errors:
                flash(e, 'danger')
    return redirect(url_for('dashboard'))

@app.route("/get_password/<int:cred_id>")
def get_password(cred_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Auth required'}), 401
    cred = Credential.query.get(cred_id)
    if not cred or cred.user_id != session['user_id']:
        return jsonify({'error': 'Not found'}), 404
    user = User.query.get(session['user_id'])
    key = derive_encryption_key(session['master_password'], user.salt)
    data = decrypt_data(cred.nonce, cred.encrypted_data, key)
    if data:
        return jsonify({'password': json.loads(data.decode()).get('password')})
    return jsonify({'error': 'Decryption failed'}), 500

@app.route("/delete_password/<int:cred_id>", methods=['POST'])
def delete_password(cred_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    form = DeleteForm()
    if form.validate_on_submit():
        cred = Credential.query.get(cred_id)
        if cred and cred.user_id == session['user_id']:
            db.session.delete(cred)
            db.session.commit()
            flash('Credential deleted.', 'success')
        else:
            flash('Error deleting credential.', 'danger')
    else:
        flash('Invalid request.', 'danger')
    return redirect(url_for('dashboard'))

@app.route("/generate_password")
def generate_password():
    if 'user_id' not in session:
        return jsonify({'error': 'Auth required'}), 401
    chars = string.ascii_letters + string.digits + string.punctuation
    pw = ''.join(random.SystemRandom().choice(chars) for _ in range(16))
    return jsonify({'password': pw})

@app.route("/logout")
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
