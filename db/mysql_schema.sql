-- db/mysql_schema.sql
CREATE DATABASE IF NOT EXISTS securechat;
USE securechat;

CREATE TABLE IF NOT EXISTS users (
  email VARCHAR(255) NOT NULL,
  username VARCHAR(100) NOT NULL UNIQUE,
  salt VARBINARY(16) NOT NULL,
  pwd_hash CHAR(64) NOT NULL,
  PRIMARY KEY (email)
);
