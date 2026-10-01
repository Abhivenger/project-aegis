-- ============================================================================
-- PROJECT AEGIS: PRIMARY DATABASE SCHEMA & ROW LEVEL SECURITY
-- Target Database: Supabase / PostgreSQL 15+
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ----------------------------------------------------------------------------
-- 1. Profiles Table (Synchronized with Clerk Authentication)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.profiles (
  id TEXT PRIMARY KEY, -- Clerk user ID format: 'user_2...'
  email TEXT NOT NULL,
  first_name TEXT,
  last_name TEXT,
  plan TEXT NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'pro', 'enterprise')),
  daily_scan_count INT NOT NULL DEFAULT 0,
  last_scan_reset_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ----------------------------------------------------------------------------
-- 2. Scans Table (Audit Log for URL & Code Inspections)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  scan_type TEXT NOT NULL CHECK (scan_type IN ('url', 'code', 'cli_precommit')),
  target TEXT NOT NULL, -- Target URL or Target File Path
  risk_score INT NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  verdict TEXT NOT NULL CHECK (verdict IN ('SAFE', 'SUSPICIOUS', 'DANGEROUS')),
  summary TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ----------------------------------------------------------------------------
-- 3. Developer API Keys (For aegis.py CLI & Git Hooks)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id TEXT NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  key_name TEXT NOT NULL,
  key_prefix TEXT NOT NULL, -- e.g., 'aegis_live_9a4f'
  hashed_key TEXT NOT NULL UNIQUE, -- SHA-256 of the plaintext secret
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ----------------------------------------------------------------------------
-- 4. Performance Indexes
-- ----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);
CREATE INDEX IF NOT EXISTS idx_scans_user_created ON public.scans(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON public.scans(verdict);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON public.api_keys(hashed_key);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON public.api_keys(user_id);

-- ----------------------------------------------------------------------------
-- 5. Row Level Security (RLS) Configuration
-- ----------------------------------------------------------------------------
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;

-- Note: In Next.js App Router, all database operations in our API routes run
-- through the server-side Supabase client using SUPABASE_SERVICE_ROLE_KEY, which
-- bypasses RLS. These policies safeguard any direct client connections.

CREATE POLICY "Allow service role full access to profiles"
  ON public.profiles
  FOR ALL
  USING (auth.role() = 'service_role')
  WITH CHECK (auth.role() = 'service_role');

CREATE POLICY "Allow service role full access to scans"
  ON public.scans
  FOR ALL
  USING (auth.role() = 'service_role')
  WITH CHECK (auth.role() = 'service_role');

CREATE POLICY "Allow service role full access to api_keys"
  ON public.api_keys
  FOR ALL
  USING (auth.role() = 'service_role')
  WITH CHECK (auth.role() = 'service_role');
