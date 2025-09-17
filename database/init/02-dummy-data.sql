-- Add more dummy data for SQL injection testing
\c vulnerable_webapp;

-- Insert additional users with predictable data
INSERT INTO users (email, password_hash, first_name, last_name, email_verified, created_at, updated_at) VALUES
('admin@example.com', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Admin', 'User', true, NOW(), NOW()),
('john@example.com', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'John', 'Doe', true, NOW(), NOW()),
('jane@example.com', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Jane', 'Smith', true, NOW(), NOW()),
('test@example.com', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Test', 'User', true, NOW(), NOW()),
('vulnerable@example.com', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Vulnerable', 'Account', true, NOW(), NOW())
ON CONFLICT (email) DO NOTHING;

-- Insert some tasks for these users
INSERT INTO tasks (user_id, title, description, priority, status, created_at, updated_at) VALUES
(1, 'Setup database', 'Configure the vulnerable database for testing', 'HIGH', 'COMPLETED', NOW(), NOW()),
(2, 'Test SQL injection', 'Verify SQL injection vulnerabilities work', 'URGENT', 'IN_PROGRESS', NOW(), NOW()),
(3, 'Security review', 'Review all security vulnerabilities', 'MEDIUM', 'TODO', NOW(), NOW()),
(4, 'Documentation', 'Write security documentation', 'LOW', 'TODO', NOW(), NOW()),
(5, 'Penetration testing', 'Conduct penetration tests', 'HIGH', 'IN_PROGRESS', NOW(), NOW())
ON CONFLICT DO NOTHING;

-- Insert some comments
INSERT INTO comments (task_id, user_id, content, created_at, updated_at) VALUES
(1, 2, 'Database setup looks good!', NOW(), NOW()),
(2, 1, 'SQL injection tests are working', NOW(), NOW()),
(3, 3, 'Found several vulnerabilities', NOW(), NOW()),
(4, 4, 'Documentation is in progress', NOW(), NOW()),
(5, 5, 'Penetration tests reveal critical issues', NOW(), NOW())
ON CONFLICT DO NOTHING;