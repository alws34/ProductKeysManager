import random
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
import bcrypt
import hashlib
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'

connection_string = ''

port = 8086

# Use SQLAlchemy create_engine with pyodbc
engine = create_engine(connection_string, echo=False)

# Password hashing utility
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password.decode('utf-8'), salt.decode('utf-8')

# Normalize category names: lowercase and remove special characters
def normalize_category_name(name):
    return re.sub(r'\W+', '', name.lower())

# Utility to hash the serial key with SHA-512
def hash_serial_key(serial_key, device_id=None):
    """Generate SHA-512 hash using the serial_key and device_id."""
    if device_id is None:
        device_id = str(random.randint(1, 1000))  # Random fallback value
    
    return hashlib.sha512(device_id.encode('utf-8') + serial_key.encode('utf-8')).hexdigest()

@app.route('/', methods=['GET', 'POST'])
def home():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Add a new device if it's a POST request
    if request.method == 'POST' and 'device_name' in request.form:
        device_name = request.form['device_name']
        normalized_device_name = normalize_device_name(device_name)

        try:
            with engine.connect() as conn:
                conn.execute(text("INSERT INTO Devices (name) VALUES (:name)"), {'name': normalized_device_name})
                conn.commit()
        except SQLAlchemyError as e:
            print(f"Error inserting device: {str(e)}")
            return f"An error occurred: {str(e)}", 500

    with engine.connect() as conn:
        categories = conn.execute(text("SELECT * FROM Categories")).fetchall()
        devices = conn.execute(text("SELECT * FROM Devices")).fetchall()

    return render_template('index.html', categories=categories, devices=devices)

@app.route('/add_category', methods=['POST'])
def add_category():
    if 'username' not in session:
        return redirect(url_for('login'))

    category_name = request.form['category_name']
    normalized_name = normalize_category_name(category_name)

    try:
        with engine.connect() as conn:
            existing_category = conn.execute(text("SELECT * FROM Categories WHERE name = :name"), {'name': normalized_name}).fetchone()
            if existing_category:
                return 'Category already exists!', 400

            conn.execute(text("INSERT INTO Categories (name) VALUES (:name)"), {'name': normalized_name})
            conn.commit()

    except SQLAlchemyError as e:
        print(f"Error inserting category: {str(e)}")
        return f"An error occurred: {str(e)}", 500

    return redirect(url_for('home'))

@app.route('/remove_category/<int:category_id>', methods=['POST'])
def remove_category(category_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        with engine.connect() as conn:
            conn.execute(text("DELETE FROM Keys WHERE category_id = :category_id"), {'category_id': category_id})
            conn.execute(text("DELETE FROM Categories WHERE id = :category_id"), {'category_id': category_id})
            conn.commit()
    except SQLAlchemyError as e:
        print(f"Error removing category: {str(e)}")
        return f"An error occurred: {str(e)}", 500

    return redirect(url_for('home'))

@app.route('/category/<int:category_id>', methods=['GET'])
def category_keys(category_id):
    with engine.connect() as conn:
        category = conn.execute(text("SELECT * FROM Categories WHERE id = :category_id"), {'category_id': category_id}).fetchone()
        keys = conn.execute(text("SELECT * FROM Keys WHERE category_id = :category_id"), {'category_id': category_id}).fetchall()
        all_categories = conn.execute(text("SELECT * FROM Categories")).fetchall()
        all_devices = conn.execute(text("SELECT * FROM Devices")).fetchall()

    return render_template('keys.html', category_id=category.id, category_name=category.name, keys=keys, all_categories=all_categories, all_devices=all_devices)

@app.route('/search', methods=['GET'])
def search_keys():
    query = request.args.get('query')
    with engine.connect() as conn:
        keys = conn.execute(text("SELECT * FROM Keys WHERE name LIKE :query OR serial_key LIKE :query"), {'query': f'%{query}%'}).fetchall()

    return render_template('keys.html', keys=keys)

@app.route('/get_unused_key/<int:category_id>', methods=['GET'])
def get_unused_key(category_id):
    with engine.connect() as conn:
        unused_key = conn.execute(text("SELECT * FROM Keys WHERE category_id = :category_id AND is_in_use = 0"), {'category_id': category_id}).fetchone()

    if unused_key:
        return jsonify({'serial_key': unused_key.serial_key})
    else:
        return jsonify({'error': 'No unused keys available'}), 404

@app.route('/remove_key/<int:key_id>', methods=['POST'])
def remove_key(key_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        with engine.connect() as conn:
            conn.execute(text("DELETE FROM Keys WHERE id = :key_id"), {'key_id': key_id})
            conn.commit()
    except SQLAlchemyError as e:
        print(f"Error removing key: {str(e)}")
        return f"An error occurred: {str(e)}", 500

    return redirect(request.referrer)

@app.route('/add_key', methods=['POST'])
def add_key():
    if 'username' not in session:
        return redirect(url_for('login'))

    name = request.form['name']
    serial_key = request.form['serial_key']
    description = request.form.get('description')
    is_in_use = 'is_in_use' in request.form  # Check if the checkbox is selected
    category_id = request.form.get('category_id')
    device_id = request.form.get('device_id') or None

    hash_value = hash_serial_key(serial_key, device_id)

    try:
        with engine.connect() as conn:
            conn.execute(text("""
                INSERT INTO Keys (name, serial_key, hash_serial_key, description, is_in_use, category_id, device_id) 
                VALUES (:name, :serial_key, :hash_serial_key, :description, :is_in_use, :category_id, :device_id)
            """), {
                'name': name,
                'serial_key': serial_key,
                'hash_serial_key': hash_value,
                'description': description,
                'is_in_use': is_in_use,
                'category_id': category_id,
                'device_id': device_id
            })
            conn.commit()
    except SQLAlchemyError as e:
        print(f"Error inserting key: {str(e)}")
        return f"An error occurred: {str(e)}", 500

    return redirect(f'/category/{category_id}')

@app.route('/update_key/<int:key_id>', methods=['POST'])
def update_key(key_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    data = request.get_json()

    # Fetch the fields from the JSON request, using defaults if fields are missing
    name = data.get('name')
    serial_key = data.get('serial_key')
    description = data.get('description', None)
    device_id = data.get('device_id') or None  # Handle None device
    is_in_use = data.get('is_in_use', False)  # Default to False if not provided

    # Ensure required fields are present
    if not serial_key:
        return jsonify({'error': 'Missing required fields'}), 400

    # Generate the new hash for the updated serial_key
    hash_value = hash_serial_key(serial_key, device_id)
    
    # Handle the case where 'None' means device_id = 0
    if device_id == "0" or device_id == 0:
        device_id = None  # Set to None in the database
    else: 
        is_in_use = True

    try:
        with engine.connect() as conn:
            # Update all relevant fields including device_id and is_in_use status
            conn.execute(text("""
                UPDATE Keys 
                SET name = :name, 
                    serial_key = :serial_key, 
                    hash_serial_key = :hash_serial_key, 
                    description = :description, 
                    device_id = :device_id, 
                    is_in_use = :is_in_use
                WHERE id = :key_id
            """), {
                'name': name,
                'serial_key': serial_key,
                'hash_serial_key': hash_value,
                'description': description,
                'device_id': device_id,
                'is_in_use': is_in_use,
                'key_id': key_id
            })
            conn.commit()  # Commit the transaction

    except SQLAlchemyError as e:
        print(f"Error updating key: {str(e)}")
        return jsonify({'error': 'Failed to update key'}), 500

    return jsonify({'message': 'Key updated successfully'})

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        with engine.connect() as conn:
            result = conn.execute(text("SELECT * FROM Users WHERE email = :email"), {'email': email}).fetchone()
            if result:
                return 'Email already registered', 400

        hashed_password, salt = hash_password(password)

        with engine.connect() as conn:
            conn.execute(text("""
                INSERT INTO Users (email, username, password_hash, salt)
                VALUES (:email, :username, :password_hash, :salt)
            """), {
                'email': email,
                'username': username,
                'password_hash': hashed_password,
                'salt': salt
            })

        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/move_key/<int:key_id>', methods=['POST'])
def move_key(key_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    new_category_id = request.form['new_category']

    try:
        with engine.connect() as conn:
            conn.execute(text("UPDATE Keys SET category_id = :new_category_id WHERE id = :key_id"), {'new_category_id': new_category_id, 'key_id': key_id})
            conn.commit()
    except SQLAlchemyError as e:
        print(f"Error moving key: {str(e)}")
        return f"An error occurred: {str(e)}", 500

    return redirect(request.referrer)

@app.route('/add_device', methods=['POST'])
def add_device():
    if 'username' not in session:
        return redirect(url_for('login'))

    device_name = request.form['device_name']
    normalized_name = normalize_category_name(device_name)

    try:
        with engine.connect() as conn:
            existing_device = conn.execute(text("SELECT * FROM Devices WHERE name = :name"), {'name': normalized_name}).fetchone()
            if existing_device:
                return 'Device already exists!', 400
            conn.execute(text("INSERT INTO Devices (name) VALUES (:name)"), {'name': normalized_name})
            conn.commit()
    except SQLAlchemyError as e:
        print(f"Error inserting device: {str(e)}")
        return f"An error occurred: {str(e)}", 500

    return redirect(url_for('home'))

@app.route('/remove_device/<int:device_id>', methods=['POST'])
def remove_device(device_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        with engine.connect() as conn:
            conn.execute(text("DELETE FROM Devices WHERE id = :device_id"), {'device_id': device_id})
            conn.commit()
        return '', 204
    except SQLAlchemyError as e:
        print(f"Error removing device: {str(e)}")
        return f"An error occurred: {str(e)}", 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        with engine.connect() as conn:
            result = conn.execute(text("SELECT * FROM Users WHERE email = :email"), {'email': email}).fetchone()
            if result and bcrypt.checkpw(password.encode(), result.password_hash.encode()):
                session['username'] = result.username
                return redirect(url_for('home'))

        return 'Invalid credentials', 401

    return render_template('login.html')

@app.route('/devices', methods=['GET', 'POST'])
def manage_devices():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        device_name = request.form['device_name']
        normalized_name = normalize_device_name(device_name)

        try:
            with engine.connect() as conn:
                existing_device = conn.execute(text("SELECT * FROM Devices WHERE name = :name"), {'name': normalized_name}).fetchone()
                if existing_device:
                    return 'Device already exists!', 400

                conn.execute(text("INSERT INTO Devices (name) VALUES (:name)"), {'name': normalized_name})
                conn.commit()

        except SQLAlchemyError as e:
            print(f"Error inserting device: {str(e)}")
            return f"An error occurred: {str(e)}", 500

    with engine.connect() as conn:
        devices = conn.execute(text("SELECT * FROM Devices")).fetchall()

    return render_template('devices.html', devices=devices)

def normalize_device_name(name):
    return re.sub(r'\W+', '', name.lower())

@app.route('/device/<int:device_id>', methods=['GET'])
def device_keys(device_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    with engine.connect() as conn:
        device = conn.execute(text("SELECT * FROM Devices WHERE id = :device_id"), {'device_id': device_id}).fetchone()
        if device is None:
            return "Device not found", 404

        keys = conn.execute(text("SELECT * FROM Keys WHERE device_id = :device_id"), {'device_id': device_id}).fetchall()

    return render_template('device_keys.html', device=device, keys=keys)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=port)
