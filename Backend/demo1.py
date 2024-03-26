from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
import hashlib
import requests
import mysql.connector
from cryptography.fernet import Fernet
import random
import string
import os

# Initialize Flask app
app = Flask(__name__)
CORS(app, supports_credentials=True)

# Secret key for session management
app.secret_key = os.urandom(24)

# Generate or load the Fernet key for encryption/decryption
key_file = "fernet.key"
if os.path.exists(key_file):
    with open(key_file, "rb") as f:
        cipher_key = f.read()
else:
    cipher_key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(cipher_key)

cipher_suite = Fernet(cipher_key)

# Generate a random key for JWT token generation
jwt_secret_key = os.urandom(24)
app.config['JWT_SECRET_KEY'] = jwt_secret_key
jwt = JWTManager(app)


# MySQL connection
connection = mysql.connector.connect(
    host="localhost",
    user="root",
    password="suratna",
    database="password_manager"
)

cursor = connection.cursor()

# Create users table if not exists
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL
    )
""")

# Create passwords table if not exists
cursor.execute("""
    CREATE TABLE IF NOT EXISTS passwords (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        url VARCHAR(255) NOT NULL,
        username VARCHAR(255) NOT NULL,
        password_encrypted TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
""")


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


# Route to sign in and generate JWT token
@app.route('/login', methods=['POST'])
def login():
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
            user_id = user[0]  # Assuming the first column is user_id
            # Create JWT token with user_id
            access_token = create_access_token(identity={'user_id': user_id})
            # Store user email in session
            session['email'] = email
            return jsonify(access_token=access_token), 200
        else:
            return jsonify({'error': 'Incorrect email or password'}), 401
    except mysql.connector.Error as err:
        return jsonify({'error': f'Error signing in: {err}'}), 500

# Protected route example that requires JWT
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    # Get user identity from JWT
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


# Route to store password
@app.route('/store_password', methods=['POST'])
@jwt_required()  # Protect this route with JWT
def store_password():
    try:
        data = request.get_json()
        if not data or 'url' not in data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Invalid JSON data'}), 400

        url = data['url']
        username = data['username']
        password = data['password']
        
        # Get the user's identity from the JWT token
        current_user = get_jwt_identity()
        
        # Ensure the user identity is valid
        if isinstance(current_user, dict) and 'user_id' in current_user:
            user_id = current_user['user_id']
            
            # Encrypt the password using the cipher suite
            encrypted_password = cipher_suite.encrypt(password.encode()).decode()
            
            # Save the password to the database along with the user's id
            cursor.execute("INSERT INTO passwords (user_id, url, username, password_encrypted) VALUES (%s, %s, %s, %s)",
                           (user_id, url, username, encrypted_password))
            connection.commit()
            
            return jsonify({'message': 'Password stored successfully'}), 200

        else:
            return jsonify({'error': 'Invalid user identity in JWT token'}), 400
    except Exception as e:
        return jsonify({'error': f'Error storing password: {e}'}), 500

# Route to retrieve passwords
@app.route('/retrieve_passwords')
@jwt_required()  # Protect this route with JWT
def retrieve_passwords():
    try:
        # Get the user's identity from the JWT token
        current_user = get_jwt_identity()
        
        # Ensure the user identity is valid
        if isinstance(current_user, dict) and 'user_id' in current_user:
            user_id = current_user['user_id']
            
            cursor.execute("SELECT url, username, password_encrypted FROM passwords WHERE user_id = %s", (user_id,))
            passwords = cursor.fetchall()
            decrypted_passwords = []
            
            for password in passwords:
                url = password[0]
                username = password[1]
                encrypted_password = password[2]
                
                try:
                    # Decrypt the password using the cipher suite
                    decrypted_password = cipher_suite.decrypt(encrypted_password.encode())
                    decrypted_passwords.append({'url': url, 'username': username, 'password': decrypted_password.decode()})
                except Exception as e:
                    # Log decryption error
                    print(f"Decryption error for password with URL {url}: {e}")
                    # Append placeholder for the password
                    decrypted_passwords.append({'url': url, 'username': username, 'password': 'Decryption Error'})
            
            return jsonify({'passwords': decrypted_passwords}), 200
        
        else:
            return jsonify({'error': 'Invalid user identity in JWT token'}), 400
        
    except mysql.connector.Error as err:
        return jsonify({'error': f'Error retrieving passwords: {err}'}), 500


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

if __name__ == "__main__":
    app.run(debug=True)