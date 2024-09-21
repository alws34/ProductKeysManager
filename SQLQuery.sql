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
    serial_key NVARCHAR(255) NOT NULL UNIQUE,
    is_in_use BIT NOT NULL
);

-- Users Table for Authentication
CREATE TABLE Users (
    email NVARCHAR(255) PRIMARY KEY,
    username NVARCHAR(100) NOT NULL,
    password_hash NVARCHAR(255) NOT NULL,
    salt NVARCHAR(255) NOT NULL
);
