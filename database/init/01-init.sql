-- Initialize the vulnerable_webapp database
-- This script runs when the PostgreSQL container starts

-- Create the database if it doesn't exist
SELECT 'CREATE DATABASE vulnerable_webapp'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'vulnerable_webapp')\gexec

-- Connect to the database
\c vulnerable_webapp;

-- Create extensions that might be useful for the application
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Set timezone
SET timezone = 'UTC';

-- Create a function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Grant necessary permissions to the webapp user
GRANT ALL PRIVILEGES ON DATABASE vulnerable_webapp TO webapp_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO webapp_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO webapp_user;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO webapp_user;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO webapp_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO webapp_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO webapp_user;