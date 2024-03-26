from getpass import getpass
import hashlib
import requests
import mysql.connector
from cryptography.fernet import Fernet
import random
import string

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

# Database functions for account management and password storage/retrieval
def create_account(email, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    try:
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if user:
            return 'An account with this email already exists'
        else:
            cursor.execute("INSERT INTO users (email, password_hash) VALUES (%s, %s)", (email, hashed_password))
            connection.commit() 
            return 'Account created successfully'
    except mysql.connector.Error as err:
        return f'Error creating account: {err}'

def sign_in(email, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    try:
        cursor.execute("SELECT * FROM users WHERE email = %s AND password_hash = %s", (email, hashed_password))
        user = cursor.fetchone()
        if user:
            return True
        else:
            return False
    except mysql.connector.Error as err:
        return f'Error signing in: {err}'

def store_password(user_id, url, username, password):
    encrypted_password = cipher_suite.encrypt(password.encode()).decode()
    try:
        cursor.execute("INSERT INTO passwords (user_id, url, username, password_encrypted) VALUES (%s, %s, %s, %s)",
                       (user_id, url, username, encrypted_password))
        connection.commit()
        return 'Password stored successfully'
    except mysql.connector.Error as err:
        return f'Error storing password: {err}'

def retrieve_passwords(user_id):
    try:
        cursor.execute("SELECT url, username, password_encrypted FROM passwords WHERE user_id = %s", (user_id,))
        passwords = cursor.fetchall()
        if passwords:
            decrypted_passwords = []
            for password in passwords:
                url = password[0]
                username = password[1]
                encrypted_password = password[2]
                decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()
                decrypted_passwords.append({'url': url, 'username': username, 'password': decrypted_password})
            return decrypted_passwords
        else:
            return 'No passwords found for this user'
    except mysql.connector.Error as err:
        return f'Error retrieving passwords: {err}'

def logout():
    session.pop('user_id', None)
    return "Logout successful"
