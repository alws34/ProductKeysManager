-- Categories Table
CREATE TABLE Categories (
    id INT IDENTITY PRIMARY KEY,
    name NVARCHAR(100) NOT NULL UNIQUE
);

-- Keys Table
CREATE TABLE Keys (
    id INT IDENTITY PRIMARY KEY,
    name NVARCHAR(255) NOT NULL,
    category_id INT NOT NULL FOREIGN KEY REFERENCES Categories(id),
    serial_key NVARCHAR(MAX) NOT NULL,  -- Allow longer serial keys
    hash_serial_key CHAR(128) NOT NULL, -- SHA-512 produces a 128-character hexadecimal hash
    is_in_use BIT NOT NULL,
    device_id INT NULL,  -- Added support for optional device association
    description NVARCHAR(MAX) NULL,  -- Optional description for each key
    UNIQUE (serial_key),  -- Keep unique constraint on serial_key
    UNIQUE (hash_serial_key)  -- Ensure the hash of the serial_key is also unique
);


-- Users Table for Authentication
CREATE TABLE Users (
    email NVARCHAR(255) PRIMARY KEY,
    username NVARCHAR(100) NOT NULL,
    password_hash NVARCHAR(255) NOT NULL,
    salt NVARCHAR(255) NOT NULL
);
