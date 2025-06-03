from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a random secret key
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'index'

# User model
class User(UserMixin):
    def __init__(self, id, username, password, name, birthday, address, profile_pic):
        self.id = id
        self.username = username
        self.password = password
        self.name = name
        self.birthday = birthday
        self.address = address
        self.profile_pic = profile_pic

# Initialize database
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT NOT NULL,
            birthday TEXT NOT NULL,
            address TEXT NOT NULL,
            profile_pic TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    if user_data:
        return User(*user_data)
    return None

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data and check_password_hash(user_data[2], password):
        user = User(*user_data)
        login_user(user)
        return redirect(url_for('profile'))
    else:
        flash('Invalid username or password')
        return redirect(url_for('index'))

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = generate_password_hash(request.form['password'])
    name = request.form['name']
    birthday = request.form['birthday']
    address = request.form['address']
    
    # Handle file upload
    if 'profile_pic' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['profile_pic']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        profile_pic = filename
    else:
        flash('Invalid file type')
        return redirect(request.url)
    
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password, name, birthday, address, profile_pic)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, password, name, birthday, address, profile_pic))
        conn.commit()
        conn.close()
        
        # Log in the new user
        user_id = cursor.lastrowid
        user = User(user_id, username, password, name, birthday, address, profile_pic)
        login_user(user)
        return redirect(url_for('profile'))
    except sqlite3.IntegrityError:
        flash('Username already exists')
        return redirect(url_for('register_page'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user, now=datetime.now())

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)