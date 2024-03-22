from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_cors import CORS
from getpass import getpass
import hashlib
import requests
import mysql.connector
from cryptography.fernet import Fernet
import random
import string
from flask_cors import cross_origin

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

key = Fernet.generate_key()
cipher_suite = Fernet(key)

connection = mysql.connector.connect(
    host="localhost",
    user="root",
    password="suratna",
    database="password_manager"
)
cursor = connection.cursor()

# Function to generate strong password
def generate_strong_password(length=12, uppercase=True, digits=True, special_chars=True):
    chars = string.ascii_lowercase
    if uppercase:
        chars += string.ascii_uppercase
    if digits:
        chars += string.digits
    if special_chars:
        chars += string.punctuation

    return ''.join(random.choice(chars) for _ in range(length))

# Route to render index page
@app.route('/')
def index():
    return render_template('index.html')

# Function to check if a password has been breached
def is_password_breached(password):
    try:
        hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = hashed_password[:5], hashed_password[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url)
        
        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for tail, count in hashes:
                if suffix == tail:
                    return int(count)
            return False
        else:
            return False  # Assuming the password hasn't been breached if API request fails
    except Exception as e:
        print(f"Error checking password breach: {e}")
        return False

# Route to check if a password has been breached
@app.route('/check_password_breached', methods=['POST'])
def check_password_breached():
    data = request.get_json()
    if not data or 'password' not in data:
        return jsonify({'error': 'Invalid JSON data or missing password'}), 400

    password = data['password']
    breached_count = is_password_breached(password)

    if breached_count:
        return jsonify({'breached': True, 'message': f'Password has been breached {breached_count} times'}), 200
    else:
        return jsonify({'breached': False, 'message': 'Password has not been breached'}), 200

# Route to create a new user account
@app.route('/create_account', methods=['POST'])
def create_account():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Invalid JSON data'}), 400

    email = data['email']
    password = data['password']
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    try:
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if user:
            return jsonify({'error': 'An account with this email already exists'}), 400
        else:
            cursor.execute("INSERT INTO users (email, password_hash) VALUES (%s, %s)", (email, hashed_password))
            connection.commit() 
            return jsonify({'message': 'Account created successfully'}), 200
    except mysql.connector.Error as err:
        return jsonify({'error': f'Error creating account: {err}'}), 500

# Route to sign in
@app.route('/sign_in', methods=['POST'])
@cross_origin(supports_credentials=True)
def sign_in():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Invalid JSON data'}), 400

    email = data['email']
    password = data['password']
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    try:
        cursor.execute("SELECT * FROM users WHERE email = %s AND password_hash = %s", (email, hashed_password))
        user = cursor.fetchone()
        if user:
            session['user_id'] = user[0]
            return jsonify({'message': 'Sign-in successful'}), 200
        else:
            return jsonify({'error': 'Incorrect email or password'}), 400
    except mysql.connector.Error as err:
        return jsonify({'error': f'Error signing in: {err}'}), 500

# Route to render dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        return render_template('dashboard.html')
    return redirect(url_for('sign_in'))

# Route to store password
@app.route('/store_password', methods=['POST'])
def store_password():
    if 'user_id' in session:
        data = request.get_json()
        if not data or 'url' not in data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Invalid JSON data'}), 400

        url = data['url']
        username = data['username']
        password = data['password']
        encrypted_password = cipher_suite.encrypt(password.encode()).decode()
        try:
            cursor.execute("INSERT INTO passwords (user_id, url, username, password_encrypted) VALUES (%s, %s, %s, %s)",
                           (session['user_id'], url, username, encrypted_password))
            connection.commit()
            return jsonify({'message': 'Password stored successfully'}), 200
        except mysql.connector.Error as err:
            return jsonify({'error': f'Error storing password: {err}'}), 500
    return jsonify({'error': 'User not logged in'}), 401

# Route to retrieve passwords
@app.route('/retrieve_passwords')
def retrieve_passwords():
    if 'user_id' in session:
        try:
            cursor.execute("SELECT url, username, password_encrypted FROM passwords WHERE user_id = %s", (session['user_id'],))
            passwords = cursor.fetchall()
            if passwords:
                decrypted_passwords = []
                for password in passwords:
                    url = password[0]
                    username = password[1]
                    encrypted_password = password[2]
                    decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()
                    decrypted_passwords.append({'url': url, 'username': username, 'password': decrypted_password})
                return jsonify({'passwords': decrypted_passwords}), 200
            else:
                return jsonify({'message': 'No passwords found for this user'}), 200
        except mysql.connector.Error as err:
            return jsonify({'error': f'Error retrieving passwords: {err}'}), 500
    return jsonify({'error': 'User not logged in'}), 401

# Route to generate password
@app.route('/generate_password', methods=['POST'])
def generate_password():
    data = request.get_json()
    if not data or 'length' not in data:
        return jsonify({'error': 'Missing length field'}), 400

    length = int(data['length'])

    # Set uppercase, digits, and special_chars to True by default
    uppercase = True
    digits = True
    special_chars = True

    password = generate_strong_password(length, uppercase, digits, special_chars)
    return jsonify({'password': password}), 200



# Route to log out
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return ("Logout successful")


