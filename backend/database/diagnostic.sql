-- Run this query in Railway's PostgreSQL console to check the notes table schema
-- This will show the data types of all columns in the notes table

SELECT
    column_name,
    data_type,
    udt_name,
    is_nullable,
    column_default
FROM information_schema.columns
WHERE table_name = 'notes'
ORDER BY ordinal_position;

-- Also check if there are any weird constraints or triggers
SELECT
    conname as constraint_name,
    contype as constraint_type,
    pg_get_constraintdef(oid) as definition
FROM pg_constraint
WHERE conrelid = 'notes'::regclass;
