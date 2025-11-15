-- db/mysql_sample_dump.sql
USE securechat;

INSERT INTO users (email, username, salt, pwd_hash) VALUES
('test@example.com', 'testuser', X'00112233445566778899aabbccddeeff', 'd2d2f0a9...replace_with_real_hash...');
