// ============================================================================
// PROJECT AEGIS: HARDENED SERVICE-ROLE SUPABASE CLIENT
// ============================================================================

import { createClient, SupabaseClient } from '@supabase/supabase-js';

let serviceClientInstance: SupabaseClient | null = null;

/**
 * Returns a singleton Supabase client authenticated with the service role key,
 * or null when Supabase environment variables are not configured.
 *
 * Null-safe by design: callers must handle the null case and degrade
 * gracefully (e.g. skip audit logging, fail-open quota) instead of crashing.
 * This client bypasses RLS and must be strictly confined to server-side code.
 */
export function getServiceSupabase(): SupabaseClient | null {
  if (serviceClientInstance) {
    return serviceClientInstance;
  }

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !serviceRoleKey) {
    // Supabase not configured: skip the DB gracefully instead of throwing.
    return null;
  }

  serviceClientInstance = createClient(supabaseUrl, serviceRoleKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });

  return serviceClientInstance;
}
