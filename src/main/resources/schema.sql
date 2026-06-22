CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255)
);

INSERT INTO users (username, password, email) VALUES ('alice', '5f4dcc3b5aa765d61d8327deb882cf99', 'alice@example.com');
INSERT INTO users (username, password, email) VALUES ('bob', 'e10adc3949ba59abbe56e057f20f883e', 'bob@example.com');
