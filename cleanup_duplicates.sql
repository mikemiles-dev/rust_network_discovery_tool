-- Cleanup Script: Merge Duplicate Endpoints
-- This script merges endpoints that share the same MAC address but are separate entries
-- Run with: sqlite3 test.db < cleanup_duplicates.sql

BEGIN TRANSACTION;

-- Step 1: Find duplicate endpoints (same MAC, different endpoint_id)
-- For each MAC that appears in multiple endpoints, keep the one with a non-empty name
CREATE TEMPORARY TABLE duplicate_endpoints AS
SELECT
    ea1.endpoint_id as keep_id,
    ea2.endpoint_id as merge_id,
    ea1.mac,
    e1.name as keep_name,
    e2.name as merge_name
FROM endpoint_attributes ea1
JOIN endpoint_attributes ea2 ON ea1.mac = ea2.mac AND ea1.endpoint_id < ea2.endpoint_id
JOIN endpoints e1 ON ea1.endpoint_id = e1.id
JOIN endpoints e2 ON ea2.endpoint_id = e2.id
WHERE ea1.mac IS NOT NULL
  AND ea1.mac != ''
  -- Keep the endpoint with a name, or the lower ID if both/neither have names
  AND (
    (e1.name IS NOT NULL AND e1.name != '' AND (e2.name IS NULL OR e2.name = ''))
    OR (e1.name = e2.name)
    OR ((e1.name IS NULL OR e1.name = '') AND (e2.name IS NULL OR e2.name = ''))
  )
GROUP BY ea1.mac, ea2.endpoint_id;

-- Step 2: Report what will be merged
SELECT 'Found ' || COUNT(*) || ' duplicate endpoints to merge' as status FROM duplicate_endpoints;
SELECT 'Merging endpoint ' || merge_id || ' (' || COALESCE(merge_name, 'no name') || ') into endpoint ' || keep_id || ' (' || COALESCE(keep_name, 'no name') || ') [MAC: ' || mac || ']' as merge_plan
FROM duplicate_endpoints;

-- Step 3: Update communications to point to the kept endpoint
UPDATE communications
SET src_endpoint_id = (
    SELECT keep_id FROM duplicate_endpoints WHERE merge_id = communications.src_endpoint_id
)
WHERE src_endpoint_id IN (SELECT merge_id FROM duplicate_endpoints);

UPDATE communications
SET dst_endpoint_id = (
    SELECT keep_id FROM duplicate_endpoints WHERE merge_id = communications.dst_endpoint_id
)
WHERE dst_endpoint_id IN (SELECT merge_id FROM duplicate_endpoints);

-- Step 4: Merge endpoint_attributes (copy unique attributes to kept endpoint)
-- First, copy any unique IP/hostname combinations from duplicate to kept endpoint
INSERT OR IGNORE INTO endpoint_attributes (created_at, endpoint_id, mac, ip, hostname)
SELECT
    ea.created_at,
    d.keep_id,
    ea.mac,
    ea.ip,
    ea.hostname
FROM endpoint_attributes ea
JOIN duplicate_endpoints d ON ea.endpoint_id = d.merge_id
WHERE NOT EXISTS (
    SELECT 1 FROM endpoint_attributes ea2
    WHERE ea2.endpoint_id = d.keep_id
      AND ea2.ip = ea.ip
      AND ea2.hostname = ea.hostname
);

-- Step 5: Delete the duplicate endpoint_attributes
DELETE FROM endpoint_attributes
WHERE endpoint_id IN (SELECT merge_id FROM duplicate_endpoints);

-- Step 6: Delete the duplicate endpoints
DELETE FROM endpoints
WHERE id IN (SELECT merge_id FROM duplicate_endpoints);

-- Step 7: Report results
SELECT 'Cleanup complete. Merged ' || COUNT(*) || ' duplicate endpoints.' as result FROM duplicate_endpoints;

COMMIT;

-- Verify no more duplicates exist
SELECT 'Remaining duplicate MACs (should be 0): ' || COUNT(*) as verification
FROM (
    SELECT mac, COUNT(DISTINCT endpoint_id) as endpoint_count
    FROM endpoint_attributes
    WHERE mac IS NOT NULL AND mac != ''
    GROUP BY mac
    HAVING COUNT(DISTINCT endpoint_id) > 1
);
