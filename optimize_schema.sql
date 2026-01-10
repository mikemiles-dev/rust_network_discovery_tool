-- Database Schema Optimizations
-- Run this with: sqlite3 test.db < optimize_schema.sql

-- 1. Add index on endpoints.name (case-insensitive)
-- This significantly speeds up endpoint name lookups
CREATE INDEX IF NOT EXISTS idx_endpoints_name_lower ON endpoints (LOWER(name));

-- 2. Add composite indexes for time-range communications queries
-- These help queries that filter by last_seen_at and endpoint_id together
CREATE INDEX IF NOT EXISTS idx_communications_last_seen_src ON communications (last_seen_at, src_endpoint_id);
CREATE INDEX IF NOT EXISTS idx_communications_last_seen_dst ON communications (last_seen_at, dst_endpoint_id);

-- 3. Remove unused index on endpoint_attributes.created_at (optional)
-- Uncomment if you never query by created_at on this table
-- DROP INDEX IF EXISTS idx_endpoint_attributes_created_at;

-- 4. Add index on endpoints.name for direct lookups (optional, but recommended)
CREATE INDEX IF NOT EXISTS idx_endpoints_name ON endpoints (name);

-- Verify indexes were created
SELECT 'Indexes created successfully';
.indexes
