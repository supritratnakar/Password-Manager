import hashlib
from getpass import getpass
import mysql.connector
from cryptography.fernet import Fernet

# Generate a key for encryption and decryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

try:
    connection = mysql.connector.connect(
        host="localhost",
        user="root",  # Replace with your actual MySQL username
        password="suratna",  # Replace with your actual MySQL password
        database="new_pass"
    )
    cursor = connection.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INT AUTO_INCREMENT PRIMARY KEY,
                     email VARCHAR(255) UNIQUE,
                     password_hash VARCHAR(255))''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                     (id INT AUTO_INCREMENT PRIMARY KEY,
                     user_id INT,
                     url VARCHAR(255),
                     username VARCHAR(255),
                     password_encrypted VARCHAR(255),
                     FOREIGN KEY (user_id) REFERENCES users(id))''')
except mysql.connector.Error as err:
    print("Error connecting to MySQL:", err)
    exit(1)


def create_account():
    email = input("Enter your email address: ")
    password = getpass("Enter your password: ")
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    try:
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if user:
            print("An account with this email already exists.")
        else:
            cursor.execute("INSERT INTO users (email, password_hash) VALUES (%s, %s)", (email, hashed_password))
            connection.commit()
            print("Account created successfully.")
    except mysql.connector.Error as err:
        print("Error creating account:", err)


def sign_in():
    email = input("Enter your email address: ")
    password = getpass("Enter your password: ")
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    try:
        cursor.execute("SELECT * FROM users WHERE email = %s AND password_hash = %s", (email, hashed_password))
        user = cursor.fetchone()
        if user:
            print("Sign-in successful.")
            return user[0]
        else:
            print("Incorrect email or password.")
            return None
    except mysql.connector.Error as err:
        print("Error signing in:", err)
        return None


def store_password(user_id):
    url = input("Enter the URL or app name: ")
    username = input("Enter the username: ")
    password = getpass("Enter the password: ")
    # Encrypt the password before storing
    encrypted_password = cipher_suite.encrypt(password.encode()).decode()
    try:
        cursor.execute("INSERT INTO passwords (user_id, url, username, password_encrypted) VALUES (%s, %s, %s, %s)",
                       (user_id, url, username, encrypted_password))
        connection.commit()
        print("Password stored successfully.")
    except mysql.connector.Error as err:
        print("Error storing password:", err)


def retrieve_passwords(user_id):
    try:
        cursor.execute("SELECT url, username, password_encrypted FROM passwords WHERE user_id = %s", (user_id,))
        passwords = cursor.fetchall()
        if passwords:
            print("Saved passwords:")
            for password in passwords:
                url = password[0]
                username = password[1]
                encrypted_password = password[2]
                
                # Decrypt the password before displaying
                decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()
                
                print(f"URL: {url}, Username: {username}, Password: {decrypted_password}")
        else:
            print("No passwords found for this user.")
    except mysql.connector.Error as err:
        print("Error retrieving passwords:", err)


def main():
    user_id = None
    while True:
        print("\nOptions:")
        print("1. Create an account")
        print("2. Sign in")
        print("3. Store password")
        print("4. Retrieve passwords")
        print("5. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            create_account()
        elif choice == "2":
            user_id = sign_in()
        elif choice == "3":
            if user_id:
                store_password(user_id)
            else:
                print("Please sign in first.")
        elif choice == "4":
            if user_id:
                retrieve_passwords(user_id)
            else:
                print("Please sign in first.")
        elif choice == "5":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please choose again.")

    cursor.close()
    connection.close()


if __name__ == "__main__":
    main()
