import { redirect } from 'next/navigation';

/**
 * Dashboard root. There is no dedicated landing page, so `/dashboard` forwards
 * straight to the primary SafeLink engine. This keeps
 * http://localhost:3000/dashboard working without any auth handshake.
 */
export default function DashboardIndexPage() {
  redirect('/dashboard/url-inspector');
}
