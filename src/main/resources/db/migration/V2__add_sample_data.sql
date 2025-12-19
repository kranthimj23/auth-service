-- Sample Data for Auth Service
-- Version: 1.0.0
-- Description: Insert sample users for testing

-- Insert sample admin user (password: Admin@123)
INSERT INTO users_auth (id, email, username, password_hash, enabled, account_non_expired, account_non_locked, credentials_non_expired)
VALUES (
    'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
    'admin@mobilebanking.com',
    'admin',
    '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.G5HqGqYqYqYqYq',
    true, true, true, true
);

-- Insert sample regular user (password: User@123)
INSERT INTO users_auth (id, email, username, password_hash, enabled, account_non_expired, account_non_locked, credentials_non_expired)
VALUES (
    'b1eebc99-9c0b-4ef8-bb6d-6bb9bd380a22',
    'john.doe@example.com',
    'johndoe',
    '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.G5HqGqYqYqYqYq',
    true, true, true, true
);

-- Insert sample test user (password: Test@123)
INSERT INTO users_auth (id, email, username, password_hash, enabled, account_non_expired, account_non_locked, credentials_non_expired)
VALUES (
    'c2eebc99-9c0b-4ef8-bb6d-6bb9bd380a33',
    'jane.smith@example.com',
    'janesmith',
    '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.G5HqGqYqYqYqYq',
    true, true, true, true
);

-- Assign roles to users
INSERT INTO user_roles (user_id, role) VALUES
    ('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', 'ROLE_ADMIN'),
    ('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', 'ROLE_USER'),
    ('b1eebc99-9c0b-4ef8-bb6d-6bb9bd380a22', 'ROLE_USER'),
    ('c2eebc99-9c0b-4ef8-bb6d-6bb9bd380a33', 'ROLE_USER');
