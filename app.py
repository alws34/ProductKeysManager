from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

import bcrypt
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'

connection_string = ''

port = 8086

# Use SQLAlchemy create_engine with pyodbc
engine = create_engine(connection_string,
    echo=False
)
# Password hashing utility


def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password.decode('utf-8'), salt.decode('utf-8')

# Normalize category names: lowercase and remove special characters


def normalize_category_name(name):
    return re.sub(r'\W+', '', name.lower())


@app.route('/', methods=['GET', 'POST'])
def home():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Add a new device if it's a POST request
    if request.method == 'POST' and 'device_name' in request.form:
        device_name = request.form['device_name']
        normalized_device_name = normalize_device_name(
            device_name)  # Normalization function like before

        try:
            with engine.connect() as conn:
                # Insert the new device into the Devices table
                conn.execute(text("INSERT INTO Devices (name) VALUES (:name)"), {
                             'name': normalized_device_name})
                conn.commit()  # Commit the transaction
        except SQLAlchemyError as e:
            print(f"Error inserting device: {str(e)}")
            return f"An error occurred: {str(e)}", 500

    # Fetch all categories and devices for display
    with engine.connect() as conn:
        categories = conn.execute(text("SELECT * FROM Categories")).fetchall()
        devices = conn.execute(text("SELECT * FROM Devices")).fetchall()

    return render_template('index.html', categories=categories, devices=devices)

# Add Category Route


@app.route('/add_category', methods=['POST'])
def add_category():
    if 'username' not in session:
        return redirect(url_for('login'))

    category_name = request.form['category_name']
    normalized_name = normalize_category_name(category_name)

    try:
        with engine.connect() as conn:
            # Insert category if it doesn't already exist
            existing_category = conn.execute(text(
                "SELECT * FROM Categories WHERE name = :name"), {'name': normalized_name}).fetchone()
            if existing_category:
                return 'Category already exists!', 400

            # Insert new category
            conn.execute(text("INSERT INTO Categories (name) VALUES (:name)"), {
                         'name': normalized_name})
            conn.commit()  # Explicitly commit the transaction

    except SQLAlchemyError as e:
        print(f"Error inserting category: {str(e)}")
        return f"An error occurred: {str(e)}", 500

    return redirect(url_for('home'))

# Remove Category Route


@app.route('/remove_category/<int:category_id>', methods=['POST'])
def remove_category(category_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        with engine.connect() as conn:
            # Optionally delete all keys under this category if necessary (or handle foreign key constraints)
            conn.execute(text("DELETE FROM Keys WHERE category_id = :category_id"), {
                         'category_id': category_id})

            # Delete the category
            conn.execute(text("DELETE FROM Categories WHERE id = :category_id"), {
                         'category_id': category_id})
            conn.commit()  # Ensure the changes are committed
    except SQLAlchemyError as e:
        print(f"Error removing category: {str(e)}")
        return f"An error occurred: {str(e)}", 500

    return redirect(url_for('home'))


@app.route('/category/<int:category_id>', methods=['GET'])
def category_keys(category_id):
    with engine.connect() as conn:
        # Fetch the selected category
        category = conn.execute(text(
            "SELECT * FROM Categories WHERE id = :category_id"), {'category_id': category_id}).fetchone()

        # Fetch keys for this category
        keys = conn.execute(text("SELECT * FROM Keys WHERE category_id = :category_id"), {
                            'category_id': category_id}).fetchall()

        # Fetch all categories (for the dropdown to move keys)
        all_categories = conn.execute(
            text("SELECT * FROM Categories")).fetchall()

        # Fetch all devices (for the dropdown to bind keys to devices)
        all_devices = conn.execute(text("SELECT * FROM Devices")).fetchall()

        # Fetch the device with the smallest ID (assumed to be the "None" option)
        none_device = conn.execute(
            text("SELECT TOP 1 id FROM Devices ORDER BY id ASC")).fetchone()

    return render_template('keys.html',
                           category_id=category.id,
                           category_name=category.name,
                           keys=keys,
                           all_categories=all_categories,
                           all_devices=all_devices,
                           none_device=none_device)

# Search for a key in free text


@app.route('/search', methods=['GET'])
def search_keys():
    query = request.args.get('query')
    with engine.connect() as conn:
        keys = conn.execute(text(
            "SELECT * FROM Keys WHERE name LIKE :query"), {'query': f'%{query}%'}).fetchall()

    return render_template('keys.html', keys=keys)

# Get a key which is not in use


@app.route('/get_unused_key/<int:category_id>', methods=['GET'])
def get_unused_key(category_id):
    with engine.connect() as conn:
        unused_key = conn.execute(text(
            "SELECT * FROM Keys WHERE category_id = :category_id AND is_in_use = 0"), {'category_id': category_id}).fetchone()

    if unused_key:
        return jsonify({'serial_key': unused_key.serial_key})
    else:
        return jsonify({'error': 'No unused keys available'}), 404

# Remove a key


@app.route('/remove_key/<int:key_id>', methods=['POST'])
def remove_key(key_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        with engine.connect() as conn:
            # Delete the key from the database
            conn.execute(text("DELETE FROM Keys WHERE id = :key_id"), {
                         'key_id': key_id})
            conn.commit()  # Ensure the deletion is committed
    except SQLAlchemyError as e:
        print(f"Error removing key: {str(e)}")
        return f"An error occurred: {str(e)}", 500

    return redirect(request.referrer)  # Redirect back to the category page


@app.route('/add_key', methods=['POST'])
def add_key():
    if 'username' not in session:
        return redirect(url_for('login'))

    name = request.form['name']
    serial_key = request.form['serial_key']
    # Get the description (optional)
    description = request.form.get('description')
    is_in_use = 'is_in_use' in request.form  # Check if the checkbox is selected
    category_id = request.form.get('category_id')  # Get the category
    device_id = request.form.get('device_id')  # Get the device (optional)

    # If device_id is not provided or empty, set it to None
    if not device_id:
        device_id = None

    try:
        with engine.connect() as conn:
            # Insert the new key into the database, including the device_id and other fields
            conn.execute(text("""
                INSERT INTO Keys (name, serial_key, description, is_in_use, category_id, device_id) 
                VALUES (:name, :serial_key, :description, :is_in_use, :category_id, :device_id)
            """), {
                'name': name,
                'serial_key': serial_key,
                'description': description,
                'is_in_use': is_in_use,
                'category_id': category_id,
                'device_id': device_id
            })
            conn.commit()  # Commit the transaction
    except SQLAlchemyError as e:
        print(f"Error inserting key: {str(e)}")
        return f"An error occurred: {str(e)}", 500

    return redirect(f'/category/{category_id}')


@app.route('/update_key_description/<int:key_id>', methods=['POST'])
def update_key_description(key_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    description = request.form.get('description')

    try:
        with engine.connect() as conn:
            # Update the description for the specific key
            conn.execute(text("""
                UPDATE Keys 
                SET description = :description
                WHERE id = :key_id
            """), {'description': description, 'key_id': key_id})
            conn.commit()
    except SQLAlchemyError as e:
        print(f"Error updating description: {str(e)}")
        return f"An error occurred: {str(e)}", 500

    return redirect(request.referrer)


# Signup and Login routes (remain unchanged)
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT * FROM Users WHERE email = :email"), {'email': email}).fetchone()
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

# Move a key to another category


@app.route('/move_key/<int:key_id>', methods=['POST'])
def move_key(key_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    new_category_id = request.form['new_category']

    try:
        with engine.connect() as conn:
            # Update the category_id for the key
            conn.execute(text("UPDATE Keys SET category_id = :new_category_id WHERE id = :key_id"), {
                'new_category_id': new_category_id,
                'key_id': key_id
            })
            conn.commit()  # Ensure the update is committed
    except SQLAlchemyError as e:
        print(f"Error moving key: {str(e)}")
        return f"An error occurred: {str(e)}", 500

    return redirect(request.referrer)  # Redirect back to the category page

# Add Device Route


@app.route('/add_device', methods=['POST'])
def add_device():
    if 'username' not in session:
        return redirect(url_for('login'))

    device_name = request.form['device_name']
    normalized_name = normalize_category_name(
        device_name)  # Same normalization as category names

    try:
        with engine.connect() as conn:
            # Insert device if it doesn't already exist
            existing_device = conn.execute(text(
                "SELECT * FROM Devices WHERE name = :name"), {'name': normalized_name}).fetchone()
            if existing_device:
                return 'Device already exists!', 400
            conn.execute(text("INSERT INTO Devices (name) VALUES (:name)"), {
                         'name': normalized_name})
            conn.commit()  # Ensure the insert is committed
    except SQLAlchemyError as e:
        print(f"Error inserting device: {str(e)}")
        return f"An error occurred: {str(e)}", 500

    return redirect(url_for('home'))

# Remove Device Route


@app.route('/remove_device/<int:device_id>', methods=['POST'])
def remove_device(device_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        with engine.connect() as conn:
            # Delete the device
            conn.execute(text("DELETE FROM Devices WHERE id = :device_id"), {
                         'device_id': device_id})
            conn.commit()  # Ensure the changes are committed
        return '', 204  # Return 204 No Content on success
    except SQLAlchemyError as e:
        print(f"Error removing device: {str(e)}")
        return f"An error occurred: {str(e)}", 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT * FROM Users WHERE email = :email"), {'email': email}).fetchone()
            if result and bcrypt.checkpw(password.encode(), result.password_hash.encode()):
                session['username'] = result.username
                return redirect(url_for('home'))

        return 'Invalid credentials', 401

    return render_template('login.html')

# Display and Add Devices


@app.route('/devices', methods=['GET', 'POST'])
def manage_devices():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        device_name = request.form['device_name']
        normalized_name = normalize_device_name(device_name)

        try:
            with engine.connect() as conn:
                # Check if device already exists
                existing_device = conn.execute(text(
                    "SELECT * FROM Devices WHERE name = :name"), {'name': normalized_name}).fetchone()
                if existing_device:
                    return 'Device already exists!', 400

                # Insert new device
                conn.execute(text("INSERT INTO Devices (name) VALUES (:name)"), {
                             'name': normalized_name})
                conn.commit()  # Commit the transaction

        except SQLAlchemyError as e:
            print(f"Error inserting device: {str(e)}")
            return f"An error occurred: {str(e)}", 500

    # Fetch all devices to display
    with engine.connect() as conn:
        devices = conn.execute(text("SELECT * FROM Devices")).fetchall()

    return render_template('devices.html', devices=devices)


# Normalize device names: lowercase and remove spaces
def normalize_device_name(name):
    return re.sub(r'\W+', '', name.lower())


# Update a key's device binding and set 'is_in_use' status accordingly
@app.route('/update_key_device/<int:key_id>', methods=['POST'])
def update_key_device(key_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    device_id = request.form['device_id']  # Get the device_id from the form

    try:
        with engine.connect() as conn:
            if not device_id:  # If "None" (empty value) is selected
                # Set device_id to NULL and mark the key as not in use
                conn.execute(text("UPDATE Keys SET device_id = NULL, is_in_use = 0 WHERE id = :key_id"), {
                             'key_id': key_id})
            else:
                # Update the device_id and mark the key as in use
                conn.execute(text("UPDATE Keys SET device_id = :device_id, is_in_use = 1 WHERE id = :key_id"), {
                    'device_id': device_id,
                    'key_id': key_id
                })
            conn.commit()  # Commit the transaction
    except SQLAlchemyError as e:
        print(f"Error updating key device: {str(e)}")
        return f"An error occurred: {str(e)}", 500

    return redirect(request.referrer)  # Redirect back to the category page


@app.route('/device/<int:device_id>', methods=['GET'])
def device_keys(device_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    with engine.connect() as conn:
        # Fetch the selected device
        device = conn.execute(text(
            "SELECT * FROM Devices WHERE id = :device_id"), {'device_id': device_id}).fetchone()

        if device is None:
            return "Device not found", 404

        # Fetch all keys associated with the device
        keys = conn.execute(text(
            "SELECT * FROM Keys WHERE device_id = :device_id"), {'device_id': device_id}).fetchall()

    return render_template('device_keys.html', device=device, keys=keys)


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=port)
