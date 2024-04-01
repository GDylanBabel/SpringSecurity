CREATE TABLE user_login (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL,
    role VARCHAR(255)
);

-- Insert User data
INSERT INTO User_login (username, password, enabled, role)
VALUES ('admin', '$2a$10$15Cc4Mm8mGSUurBfNLhJZ.qnJXaDlYo.0CXBO.9Xo4mtE9BGLxGyC', true, 'ADMIN');

INSERT INTO User_login (username, password, enabled, role)
VALUES ('user', '$2a$10$15Cc4Mm8mGSUurBfNLhJZ.qnJXaDlYo.0CXBO.9Xo4mtE9BGLxGyC', true, 'USER');
