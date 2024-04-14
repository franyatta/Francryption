from flask import Flask, render_template, request, redirect, url_for, session
import base64
import re
from flask_sqlalchemy import SQLAlchemy
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    encryption = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

# Create the database tables
with app.app_context():
    db.create_all()

def caesar_cipher_encrypt(password, shift):
    char_set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    encrypted_password = ""
    for char in password:
        if char in char_set:
            index = char_set.index(char)
            encrypted_char = char_set[(index + shift) % len(char_set)]
            encrypted_password += encrypted_char
        else:
            encrypted_password += char
    return encrypted_password

def lsfr_encrypt(password):
    char_set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    # Convert the password to a list of integers
    key = [char_set.index(char) for char in password if char in char_set]

    # Initialize the LFSR with the key
    register = key.copy()

    # Define the tap positions (e.g., [0, 2, 3, 5])
    taps = [0, 2,]

    # Define the length of the LFSR
    length = len(register)

    # Initialize the encrypted password as an empty string
    encrypted_password = ""

    # Iterate over each character in the password
    for char in password:
        if char in char_set:
            # Calculate the XOR of the tapped positions
            xor_result = 0
            for tap in taps:
                xor_result ^= register[tap]

            # Convert the XOR result to a character within the custom character set
            encrypted_char = char_set[xor_result % len(char_set)]
            encrypted_password += encrypted_char

            # Shift the register to the right
            feedback = register[length - 1]
            register = [feedback] + register[:-1]
        else:
            encrypted_password += char

    return encrypted_password

import string
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

def ecb_encrypt(password):
    # Define the block size (in bytes) for AES encryption
    block_size = 16

    # Convert the password to bytes
    password_bytes = password.encode('utf-8')

    # Pad the password bytes to the block size
    padded_password = pad(password_bytes, block_size, style='pkcs7')

    # Generate a random encryption key if not already set
    if not hasattr(app, 'encryption_key'):
        app.encryption_key = get_random_bytes(32)

    # Create an AES cipher object
    cipher = AES.new(app.encryption_key, AES.MODE_ECB)

    # Encrypt the padded password
    encrypted_password = cipher.encrypt(padded_password)

    # Define the custom character set
    char_set = string.ascii_letters + string.digits

    # Convert the encrypted password to a custom encoded string
    encrypted_chars = []
    for byte in encrypted_password:
        index = byte % len(char_set)
        encrypted_chars.append(char_set[index])

    encrypted_password = ''.join(encrypted_chars)

    return encrypted_password

@app.route('/', methods=['GET', 'POST'])
def launch():
    if request.method == 'POST':
        if 'login' in request.form:
            return redirect(url_for('login'))
        elif 'register' in request.form:
            return redirect(url_for('register'))
    return render_template('launch.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error_message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user:
            encryption_method = user.encryption
            stored_password = user.password

            if encryption_method == 'Caesar-Cipher':
                encrypted_password = caesar_cipher_encrypt(password, 3)
            elif encryption_method == 'LSFR':
                encrypted_password = lsfr_encrypt(password)
            elif encryption_method == 'ECB':
                encrypted_password = ecb_encrypt(password)

            if encrypted_password == stored_password:
                session['username'] = username
                return render_template('home.html', username=username, encrypted_password=encrypted_password)
            else:
                error_message = "Invalid password"
        else:
            error_message = "Invalid username"

    return render_template('login.html', error_message=error_message)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error_message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            error_message = "Username already exists"
        elif len(password) < 4:
            error_message = "Password must be at least 4 characters long"
        elif not re.match(r'^[A-Za-z0-9]+$', password):
            error_message = "Password can only contain capital letters, lowercase letters, and numbers"
        else:
            session['username'] = username
            session['password'] = password
            return redirect(url_for('choose_encryption'))

    return render_template('register.html', error_message=error_message)

@app.route('/choose_encryption', methods=['GET', 'POST'])
def choose_encryption():
    if request.method == 'POST':
        encryption_method = request.form['encryption']
        username = session['username']
        password = session['password']

        if encryption_method == 'Caesar-Cipher':
            encrypted_password = caesar_cipher_encrypt(password, 3)
        elif encryption_method == 'LSFR':
            encrypted_password = lsfr_encrypt(password)
        elif encryption_method == 'ECB':
            encrypted_password = ecb_encrypt(password)

        new_user = User(username=username, password=encrypted_password, encryption=encryption_method)
        db.session.add(new_user)
        db.session.commit()

        session.pop('password', None)  # Remove the plain password from the session
        return redirect(url_for('home'))

    return render_template('choose_encryption.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('launch'))

@app.route('/home')
def home():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if user:
            encrypted_password = user.password
            return render_template('home.html', username=username, encrypted_password=encrypted_password)
        else:
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
