CREATE DATABASE IF NOT EXISTS datasentry;
USE datasentry;

CREATE TABLE IF NOT EXISTS admin_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS database_connections (
    id INT AUTO_INCREMENT PRIMARY KEY,
    connection_name VARCHAR(150) NOT NULL,
    host VARCHAR(150) NOT NULL,
    database_name VARCHAR(150) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    database_name VARCHAR(150) NOT NULL,
    total_tables INT NOT NULL,
    total_columns INT NOT NULL,
    sensitive_columns INT NOT NULL,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    table_name VARCHAR(200) NOT NULL,
    column_name VARCHAR(200) NOT NULL,
    detected_type VARCHAR(150) NOT NULL,
    risk_level VARCHAR(50) NOT NULL,
    recommendation TEXT NOT NULL,
    classification_reason TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan_history(id)
);

CREATE TABLE IF NOT EXISTS schema_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    table_name VARCHAR(200) NOT NULL,
    column_name VARCHAR(200) NOT NULL,
    data_type VARCHAR(100) NOT NULL,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
