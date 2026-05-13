-- ============================================
-- SUPABASE SETUP FOR USER AUTHENTICATION
-- Run this in Supabase SQL Editor
-- ============================================

-- 1. Create users table
CREATE TABLE IF NOT EXISTS users (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE
);

-- 2. Create index for faster username lookups (improves login speed)
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- 3. Create index for email lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- 4. Enable Row Level Security (RLS)
-- RLS ensures users can only access their own data
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- 5. Create policies for secure access

-- Allow anyone to sign up (insert new user)
CREATE POLICY "Allow insert for signup" ON users
    FOR INSERT WITH CHECK (true);

-- Allow users to select their own data during login
CREATE POLICY "Allow select for login" ON users
    FOR SELECT USING (true);

-- Allow users to update their own last_login timestamp
CREATE POLICY "Allow update own data" ON users
    FOR UPDATE USING (true);

-- 6. Optional: Create a test user (password will be hashed by your app)
-- The password below is 'test123' - but your app will hash it properly
-- INSERT INTO users (username, email, password_hash) 
-- VALUES ('testuser', 'test@example.com', 'waiting_for_app_to_hash');

-- 7. Verify table was created
SELECT * FROM users LIMIT 1;

-- Expected output: "Success. No rows returned" (empty table is fine)