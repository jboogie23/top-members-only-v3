-- Migration number: 0001 	 2024-08-07T12:20:38.414Z
CREATE TABLE users
(
    id TEXT NOT NULL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    hashed_password TEXT
);

CREATE TABLE sessions
(
    id TEXT NOT NULL PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    user_id TEXT NOT NULL
);