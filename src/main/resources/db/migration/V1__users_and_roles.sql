CREATE TABLE users (
    id BINARY(16) NOT NULL PRIMARY KEY,
    email VARCHAR(254) NOT NULL,
    password_hash VARCHAR(100) NOT NULL,
    enabled BOOLEAN NOT NULL,
    version BIGINT NOT NULL,
    CONSTRAINT uk_users_email UNIQUE (email)
);
CREATE TABLE user_roles (
    user_id BINARY(16) NOT NULL,
    role VARCHAR(20) NOT NULL,
    PRIMARY KEY (user_id, role),
    CONSTRAINT fk_roles_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT chk_user_role CHECK (role IN ('ADMIN', 'CLIENTE', 'REPARTIDOR'))
);
