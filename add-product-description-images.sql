-- Extends the products table to support long descriptions and multiple images.
-- Run this once in the Supabase SQL editor.
--
-- The existing "category" TEXT column continues to act as the categoryId
-- that links a product to a homepage panel. We keep it to avoid breaking
-- the existing collection page routing (/collection.html?cat=<category>).

ALTER TABLE products ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE products ADD COLUMN IF NOT EXISTS image_urls JSONB DEFAULT '[]'::jsonb;

-- Backfill image_urls with the legacy single image_url when present,
-- so existing rows render correctly in the new multi-image UI.
UPDATE products
SET image_urls = jsonb_build_array(image_url)
WHERE image_url IS NOT NULL
  AND (image_urls IS NULL OR image_urls = '[]'::jsonb);
