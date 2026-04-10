-- =============================================
-- BAMBEO SECURITY FIX: RLS POLICIES
-- Run this in Supabase SQL Editor
-- =============================================

-- STEP 1: Drop all the insecure "Allow all operations" policies
DROP POLICY IF EXISTS "Allow all operations" ON products;
DROP POLICY IF EXISTS "Allow all operations" ON gallery;
DROP POLICY IF EXISTS "Allow all operations" ON testimonials;
DROP POLICY IF EXISTS "Allow all operations" ON site_settings;
DROP POLICY IF EXISTS "Allow all operations" ON faqs;

-- STEP 2: Drop existing read policies (we'll recreate them)
DROP POLICY IF EXISTS "Public read access" ON products;
DROP POLICY IF EXISTS "Public read access" ON gallery;
DROP POLICY IF EXISTS "Public read access" ON testimonials;
DROP POLICY IF EXISTS "Public read access" ON site_settings;
DROP POLICY IF EXISTS "Public read access" ON faqs;

-- STEP 3: Create proper read-only policies for public (anon) access
-- Public can only SELECT active items
CREATE POLICY "anon_read_active_products" ON products
  FOR SELECT USING (is_active = true);

CREATE POLICY "anon_read_active_gallery" ON gallery
  FOR SELECT USING (is_active = true);

CREATE POLICY "anon_read_active_testimonials" ON testimonials
  FOR SELECT USING (is_active = true);

CREATE POLICY "anon_read_active_faqs" ON faqs
  FOR SELECT USING (is_active = true);

-- Settings: only allow reading non-sensitive keys
CREATE POLICY "anon_read_public_settings" ON site_settings
  FOR SELECT USING (key NOT IN ('admin_password'));

-- STEP 4: Create quote_requests policies
-- Anyone can INSERT a quote (that's the contact form)
-- But nobody can read/update/delete quotes via anon key
DROP POLICY IF EXISTS "Public read access" ON quote_requests;
DROP POLICY IF EXISTS "Allow all operations" ON quote_requests;

CREATE POLICY "anon_insert_quotes" ON quote_requests
  FOR INSERT WITH CHECK (true);

-- No SELECT/UPDATE/DELETE for anon on quote_requests

-- STEP 5: Create a service_role-only write policy
-- Admin operations should use the service_role key (server-side only)
-- For now, we'll use authenticated role for admin writes
CREATE POLICY "authenticated_full_access_products" ON products
  FOR ALL TO authenticated USING (true) WITH CHECK (true);

CREATE POLICY "authenticated_full_access_gallery" ON gallery
  FOR ALL TO authenticated USING (true) WITH CHECK (true);

CREATE POLICY "authenticated_full_access_testimonials" ON testimonials
  FOR ALL TO authenticated USING (true) WITH CHECK (true);

CREATE POLICY "authenticated_full_access_settings" ON site_settings
  FOR ALL TO authenticated USING (true) WITH CHECK (true);

CREATE POLICY "authenticated_full_access_faqs" ON faqs
  FOR ALL TO authenticated USING (true) WITH CHECK (true);

CREATE POLICY "authenticated_full_access_quotes" ON quote_requests
  FOR ALL TO authenticated USING (true) WITH CHECK (true);

-- =============================================
-- RESULT:
-- Anon key (public): Can only READ active items + INSERT quotes
-- Authenticated: Full CRUD access (for admin, via Supabase Auth)
-- Admin password is hidden from public reads
-- =============================================
