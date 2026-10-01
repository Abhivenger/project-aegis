import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server';

/**
 * Route matcher for pages that require an authenticated session.
 * API routes are excluded here on purpose: they resolve auth themselves via
 * resolveAuthContext (Clerk session OR Bearer API key) so the aegis.py CLI
 * can call them with Bearer tokens instead of redirects.
 */
const isProtectedRoute = createRouteMatcher(['/dashboard(.*)']);

export default clerkMiddleware(async (auth, req) => {
  if (isProtectedRoute(req)) {
    await auth.protect();
  }
});

export const config = {
  matcher: [
    // Skip Next.js internals and static assets
    '/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)',
    // Always run for API routes
    '/(api|trpc)(.*)',
  ],
};
