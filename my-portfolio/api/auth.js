import { createClient } from '@supabase/supabase-js';
import bcrypt from 'bcryptjs';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

async function hashPassword(password) {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { action, username, email, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const lowerUsername = username.toLowerCase().trim();

  if (action === 'signup') {
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
    if (!usernameRegex.test(lowerUsername)) {
      return res.status(400).json({ error: 'Username must be 3-20 characters (letters, numbers, underscore)' });
    }

    try {
      const { data: existingUser } = await supabase
        .from('users')
        .select('username')
        .eq('username', lowerUsername)
        .single();

      if (existingUser) {
        return res.status(409).json({ error: 'Username already taken' });
      }

      const hashedPassword = await hashPassword(password);

      const { error } = await supabase
        .from('users')
        .insert([{
          username: lowerUsername,
          email: email || null,
          password_hash: hashedPassword,
          created_at: new Date().toISOString()
        }]);

      if (error) {
        console.error('Supabase insert error:', error);
        return res.status(500).json({ error: 'Failed to create account: ' + error.message });
      }

      return res.status(200).json({
        success: true,
        message: 'Account created successfully!'
      });

    } catch (error) {
      console.error('Signup error:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  if (action === 'login') {
    try {
      const { data: user, error } = await supabase
        .from('users')
        .select('username, password_hash')
        .eq('username', lowerUsername)
        .single();

      if (error || !user) {
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      const isValid = await verifyPassword(password, user.password_hash);

      if (!isValid) {
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      await supabase
        .from('users')
        .update({ last_login: new Date().toISOString() })
        .eq('username', lowerUsername);

      return res.status(200).json({
        success: true,
        username: user.username,
        message: 'Login successful'
      });

    } catch (error) {
      console.error('Login error:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  return res.status(400).json({ error: 'Invalid action. Use "login" or "signup"' });
}