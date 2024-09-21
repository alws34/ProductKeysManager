# Product Key Manager
This is a Flask web application for managing product keys and devices. The application allows users to:

- Add, update, and delete product keys.
- Bind keys to specific devices.
- Add categories and devices.
- Filter and display keys by category or device.
- Store detailed information, including descriptions, for each key.

## Features
- User authentication (login and signup).
- Manage categories, devices, and product keys.
- Update key information (name, serial key, device binding, description, and usage status).
- Dark mode UI for a modern look.

## Requirements
To run this application, you will need the following:

- Python 3.x
- Flask
- SQLAlchemy
- pyodbc (for connecting to SQL Server)
- Microsoft SQL Server
- ODBC Driver for SQL Server (ODBC Driver 18 for SQL Server)
- Installation
- Clone this repository:

git clone https://github.com/your-repo/product-key-manager.git
cd product-key-manager
Set up a virtual environment and install the required packages:

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
Create a .env file for configuring the Flask secret key and database connection string.

FLASK_APP=app.py
SECRET_KEY=your_secret_key
Set up the database and tables in SQL Server by following the instructions in the Database Setup section below.

## Database Setup
Ensure you have SQL Server set up and running. You'll also need the ODBC Driver 18 for SQL Server installed on your system for connecting to SQL Server using pyodbc.

1. Create the Database
Open SQL Server Management Studio (SSMS) and run the following command to create the database:

CREATE DATABASE ProductKeyManager;
GO
2. Create the Required Tables
Run the following SQL commands to create the necessary tables:

### Users Table
This table stores user credentials for authentication.

CREATE TABLE Users (
    id INT IDENTITY PRIMARY KEY,
    email NVARCHAR(255) UNIQUE NOT NULL,
    username NVARCHAR(255) NOT NULL,
    password_hash NVARCHAR(255) NOT NULL,
    salt NVARCHAR(255) NOT NULL
);

### Categories Table
This table stores the product key categories (e.g., Windows 10, Office 365).

CREATE TABLE Categories (
    id INT IDENTITY PRIMARY KEY,
    name NVARCHAR(255) UNIQUE NOT NULL
);

### Devices Table
This table stores the devices that keys can be bound to.

CREATE TABLE Devices (
    id INT IDENTITY PRIMARY KEY,
    name NVARCHAR(255) UNIQUE NOT NULL
);
### Keys Table
This table stores product keys, including their name, serial key, description, category, and device binding.


CREATE TABLE Keys (
    id INT IDENTITY PRIMARY KEY,
    name NVARCHAR(255) NOT NULL,
    serial_key NVARCHAR(255) UNIQUE NOT NULL,
    description NVARCHAR(MAX),  -- Allows long descriptions
    is_in_use BIT NOT NULL DEFAULT 0,
    category_id INT NOT NULL,
    device_id INT NULL,
    FOREIGN KEY (category_id) REFERENCES Categories(id),
    FOREIGN KEY (device_id) REFERENCES Devices(id)
);

3. Configure the Connection String
In the app.py file, update the SQLAlchemy connection string to connect to your local SQL Server:

`from sqlalchemy import create_engine`

`engine = create_engine('mssql+pyodbc://@YOUR-SERVER-NAME/ProductKeyManager?driver=ODBC+Driver+18+for+SQL+Server&Trusted_Connection=yes&TrustServerCertificate=yes')`

Make sure to replace YOUR-SERVER-NAME with the actual server name of your SQL Server instance (e.g., localhost, YOUR-PC-NAME\SQLEXPRESS).

## Running the App
After setting up the database, run the Flask app:

`flask run`
Open your browser and navigate to http://127.0.0.1:5000/ to access the application. or whtever port you defined. 

## Usage
Sign Up and Login: First, create an account by signing up. Once registered, you can log in and start managing your product keys.
Categories: Add and manage product key categories.
Devices: Add and manage devices to which keys can be bound.
Keys: Add, update, and delete product keys. Bind keys to specific devices and manage descriptions and status (in use or available).

## File Structure
.
├── app.py                # Main application file
├── templates/            # HTML templates (index.html, keys.html, devices.html)
├── static/               # Static assets (CSS, JS, images)
├── requirements.txt      # Python dependencies
├── README.md             # This file
└── .env                  # Environment variables (secret key)

## Future Enhancements
Add support for more product key types.
Implement pagination for large lists of keys.
Add search and filtering capabilities.

License
This project is licensed under the MIT License.

