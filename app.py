from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify
from flask_mysqldb import MySQL
import base64
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from werkzeug.security import generate_password_hash, check_password_hash
import string, random

app = Flask(__name__)
app.secret_key = "securevault"

# MySQL Configuration - Fixed the typo in 'mysql_user' to 'MYSQL_USER'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'  # Corrected from 'mysql_user' to 'MYSQL_USER'
app.config['MYSQL_PASSWORD'] = 'Vickylesnar@007'
app.config['MYSQL_DB'] = 'securevault'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)

# AES Encryption Key (Should be stored securely, not hardcoded)
SECRET_KEY = b"your-very-secure-passphrase!!"
SALT = b"random_salt_value"  # Should be random & stored securely
AES_KEY = PBKDF2(SECRET_KEY, SALT, dkLen=32)  # Generate a 256-bit key

def init_db():
    """Initialize the database tables if they don't exist"""
    cur = mysql.connection.cursor()
    
    # Create users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL
        )
    """)
    
    # Create passwords table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            site_name VARCHAR(255) NOT NULL,
            site_email VARCHAR(255) NOT NULL,
            site_password TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    
    mysql.connection.commit()

def encrypt_password(password):
    cipher = AES.new(AES_KEY, AES.MODE_EAX)
    nonce = cipher.nonce  # Random IV for each encryption
    ciphertext, tag = cipher.encrypt_and_digest(password.encode())  # Encrypt and authenticate
    return base64.b64encode(nonce + ciphertext).decode()  # Store nonce + ciphertext

def decrypt_password(encrypted_password):
    try:
        data = base64.b64decode(encrypted_password.encode())
        nonce = data[:16]  # Extract nonce
        ciphertext = data[16:]  # Extract encrypted data
        cipher = AES.new(AES_KEY, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt(ciphertext).decode()  # Decrypt
    except Exception:
        return "[Decryption Error]"

def generator_pwd(length=12):
    char = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(char) for _ in range(length))

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_or_username = request.form['email']  # Email or Username input
        password = request.form['password']

        # Use MySQL connection instead of SQLite
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username=%s OR email=%s", 
                   (email_or_username, email_or_username))
        data = cur.fetchone()

        if data and check_password_hash(data["password"], password):  # Check hashed password
            session["username"] = data["username"]
            session["id"] = data["id"]
            return redirect(url_for("vault"))  # Redirect to vault on success
        else:
            flash("Invalid Username or Password. Please try again.", "danger")
            return redirect(url_for('index'))  # Stay on login page if failed

    return render_template("login.html")  # Show login page on GET request

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = generate_password_hash(password)  # Encrypt password

        try:
            # Use MySQL connection instead of SQLite
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", 
                      (username, email, hashed_password))
            mysql.connection.commit()
            return redirect(url_for('login'))  # Redirect to login on success
        except Exception as e:
            flash(f"Registration error: {str(e)}", "danger")
            return render_template('register.html')  # Stay on register page if error

    return render_template('register.html')

@app.route('/vault')
def vault():
    if "id" in session:
        # Use MySQL connection instead of SQLite
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM passwords WHERE user_id=%s", (session['id'],))
        data = cur.fetchall()

        # Decrypt passwords before displaying
        decrypted_data = []
        for row in data:
            # When using DictCursor, row is already dictionary-like, no need to convert
            row_copy = dict(row)
            row_copy["site_password"] = decrypt_password(row_copy["site_password"])
            decrypted_data.append(row_copy)

        return render_template("vault.html", data=decrypted_data)
    return redirect(url_for('login'))

@app.route('/insert', methods=['GET', 'POST'])
def insert():
    if "id" not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        try:
            sitename = request.form['Websitename']
            siteemail = request.form['email']
            sitepassword = encrypt_password(request.form['password'])  # Encrypt password

            # Use MySQL connection instead of SQLite
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO passwords (user_id, site_name, site_email, site_password) VALUES (%s, %s, %s, %s)",
                      (session['id'], sitename, siteemail, sitepassword))
            mysql.connection.commit()
            return redirect(url_for('vault'))
        except Exception as e:
            flash(f"Something went wrong with the database: {str(e)}", "danger")
    return render_template("insert.html")

@app.route("/generator_password", methods=['GET'])
def generate():
    pwd = generator_pwd(12)
    return jsonify({"password": pwd}) 

@app.route('/generator')
def generator():
    return render_template("generator-mini.html")

@app.route('/edit/<string:id>', methods=['POST', 'GET'])
def edit(id):
    if "id" not in session:
        return redirect(url_for('login'))
        
    # Use MySQL connection instead of SQLite
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM passwords WHERE id=%s AND user_id=%s", (id, session['id']))
    data = cur.fetchone()

    if not data:
        flash("Password entry not found or not authorized", "danger")
        return redirect(url_for('vault'))

    # No need to convert to dict as DictCursor already provides dictionary-like access
    data["site_password"] = decrypt_password(data["site_password"])  # Decrypt password for editing

    if request.method == 'POST':
        try:
            sitename = request.form['Websitename']
            siteemail = request.form['email']
            sitepassword = encrypt_password(request.form['password'])  # Encrypt updated password

            # Use MySQL connection instead of SQLite
            cur = mysql.connection.cursor()
            cur.execute("UPDATE passwords SET site_name=%s, site_email=%s, site_password=%s WHERE id=%s AND user_id=%s",
                      (sitename, siteemail, sitepassword, id, session['id']))
            mysql.connection.commit()
            return redirect(url_for('vault'))
        except Exception as e:
            flash(f"Error in Update Operation: {str(e)}", "danger")
            
    return render_template("edit.html", data=data)

@app.route('/delete/<string:id>')
def delete(id):
    if "id" not in session:
        return redirect(url_for('login'))
        
    try:
        # Use MySQL connection instead of SQLite
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM passwords WHERE id=%s AND user_id=%s", (id, session['id']))
        mysql.connection.commit()
    except Exception as e:
        flash(f"Error in Delete Operation: {str(e)}", "danger")
        
    return redirect(url_for('vault'))
    
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Initialize database tables when the app starts
    with app.app_context():
        init_db()
    app.run(debug=True)