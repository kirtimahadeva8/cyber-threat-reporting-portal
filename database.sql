CREATE DATABASE cyber_threat_db;

USE cyber_threat_db;

CREATE TABLE users(
    id INT AUTO_INCREMENT PRIMARY KEY,
    fullname VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('user','admin') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

USE cyber_threat_db;


CREATE TABLE threat_reports(

id INT AUTO_INCREMENT PRIMARY KEY,

title VARCHAR(255) NOT NULL,

category VARCHAR(100),

description TEXT,

severity ENUM(
'Low',
'Medium',
'High',
'Critical'
),

status ENUM(
'Open',
'Investigating',
'Resolved'
)
DEFAULT 'Open',

evidence_file VARCHAR(255),

reported_by INT,

created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,


FOREIGN KEY(reported_by)
REFERENCES users(id)

);

USE cyber_threat_db;

SELECT * FROM users;

UPDATE users
SET role='admin'
WHERE id=2;