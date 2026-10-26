ALTER TABLE users ADD COLUMN username VARCHAR(100) NULL;
ALTER TABLE users ADD COLUMN name VARCHAR(200) NULL;
ALTER TABLE users ADD COLUMN customer_id BINARY(16) NULL;
ALTER TABLE users ADD COLUMN courier_id BINARY(16) NULL;

ALTER TABLE users ADD CONSTRAINT uk_users_username UNIQUE (username);
ALTER TABLE users ADD CONSTRAINT uk_users_customer_id UNIQUE (customer_id);
ALTER TABLE users ADD CONSTRAINT uk_users_courier_id UNIQUE (courier_id);
