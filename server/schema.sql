-- SQL Schema for NeuraauditAI Supabase Database
-- Run these commands in the Supabase SQL Editor to initialize your database tables.

-- 1. Scans Table (Stores individual audit results)
CREATE TABLE IF NOT EXISTS public.scans (
    id BIGSERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    result JSONB NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- Index for fast lookups by URL and sorting by timestamp
CREATE INDEX IF NOT EXISTS scans_url_timestamp_idx ON public.scans (url, timestamp DESC);

-- 2. Batches Table (Stores batch scan logs and progress)
CREATE TABLE IF NOT EXISTS public.batches (
    batch_id TEXT PRIMARY KEY,
    batch_data JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- Index for sorting batches by creation time
CREATE INDEX IF NOT EXISTS batches_created_at_idx ON public.batches (created_at DESC);

-- 3. AI Cache Table (Stores cached technical AI summaries)
CREATE TABLE IF NOT EXISTS public.ai_cache (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT TIMEZONE('utc'::text, NOW()) NOT NULL
);

-- Enable RLS and permissions if using public client, or simply run with service_role key.
-- Note: If you are connecting from your backend server using your service_role key, 
-- you can bypass RLS as the server acts as an admin.
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ai_cache ENABLE ROW LEVEL SECURITY;

-- Create policy for service role/admin access (or default full access if bypass is active)
CREATE POLICY "Allow full access to admin role" ON public.scans TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "Allow full access to admin role" ON public.batches TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "Allow full access to admin role" ON public.ai_cache TO service_role USING (true) WITH CHECK (true);
