-- V2__insert_master_data.sql

-- Insert predefined roles into the roles table
INSERT INTO roles (name, created_at, updated_at) VALUES ('ADMIN', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
INSERT INTO roles (name, created_at, updated_at) VALUES ('USER', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Insert predefined permissions into the permissions table for AuthController
INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('LOGIN', 'POST', '/api/auth/login', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('CHANGE_PASSWORD', 'POST', '/api/auth/change-password', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('VALIDATE_TOKEN', 'GET', '/api/auth/validate-token', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('REFRESH_TOKEN', 'POST', '/api/auth/refresh-token', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Insert predefined permissions into the permissions table for MicroserviceController
INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('REGISTER_MICROSERVICE', 'POST', '/api/auth/microservices/register', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('VIEW_MICROSERVICE', 'GET', '/api/auth/microservices/{microserviceId}', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('VIEW_ALL_MICROSERVICES', 'GET', '/api/auth/microservices', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('UPDATE_MICROSERVICE', 'PUT', '/api/auth/microservices/{microserviceId}', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('DELETE_MICROSERVICE', 'DELETE', '/api/auth/microservices/{microserviceId}', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Insert predefined permissions into the permissions table for Role CRUD
INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('CREATE_ROLE', 'POST', '/api/auth/roles', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('VIEW_ROLE', 'GET', '/api/auth/roles/{roleId}', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('VIEW_ALL_ROLES', 'GET', '/api/auth/roles', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);  -- New permission for viewing all roles

INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('UPDATE_ROLE', 'PUT', '/api/auth/roles/{roleId}', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('DELETE_ROLE', 'DELETE', '/api/auth/roles/{roleId}', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Insert predefined permissions into the permissions table for Permission CRUD
INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('CREATE_PERMISSION', 'POST', '/api/auth/permissions', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('VIEW_PERMISSION', 'GET', '/api/auth/permissions/{permissionId}', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('UPDATE_PERMISSION', 'PUT', '/api/auth/permissions/{permissionId}', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('DELETE_PERMISSION', 'DELETE', '/api/auth/permissions/{permissionId}', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Insert predefined permissions into the permissions table for User CRUD
INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('CREATE_USER', 'POST', '/api/auth/users', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('VIEW_USER', 'GET', '/api/auth/users/{userId}', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('UPDATE_USER', 'PUT', '/api/auth/users/{userId}', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO permissions (name, method, endpoint, microservice, created_at, updated_at)
VALUES ('DELETE_USER', 'DELETE', '/api/auth/users/{userId}', 'auth-server', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);


-- Link roles to permissions
-- Assigning all permissions to the 'ADMIN' role
INSERT INTO role_permissions (role_id, permission_id)
SELECT (SELECT id FROM roles WHERE name = 'ADMIN'), id FROM permissions;

-- Assigning specific permissions to the 'USER' role
INSERT INTO role_permissions (role_id, permission_id)
VALUES ((SELECT id FROM roles WHERE name = 'USER'), (SELECT id FROM permissions WHERE name = 'LOGIN'));

INSERT INTO role_permissions (role_id, permission_id)
VALUES ((SELECT id FROM roles WHERE name = 'USER'), (SELECT id FROM permissions WHERE name = 'CHANGE_PASSWORD'));

INSERT INTO role_permissions (role_id, permission_id)
VALUES ((SELECT id FROM roles WHERE name = 'USER'), (SELECT id FROM permissions WHERE name = 'VALIDATE_TOKEN'));

INSERT INTO role_permissions (role_id, permission_id)
VALUES ((SELECT id FROM roles WHERE name = 'USER'), (SELECT id FROM permissions WHERE name = 'REFRESH_TOKEN'));


-- Insert an admin user into the users table
INSERT INTO users (username, password, enabled, created_at, updated_at)
VALUES ('nazim', '{bcrypt}$2a$10$u.Tl5/47FHtO8lzb30I5OusWaoyh3Hztq3eAgm0UDAUucKoxM1buW', true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Link the 'nazim' user to the 'ADMIN' role
INSERT INTO user_roles (user_id, role_id)
VALUES ((SELECT id FROM users WHERE username = 'nazim'), (SELECT id FROM roles WHERE name = 'ADMIN'));


