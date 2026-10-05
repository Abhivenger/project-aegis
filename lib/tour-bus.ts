// ============================================================================
// PROJECT AEGIS: GUIDED DEMO TOUR LAUNCH BUS
// Decouples tour triggers (bottom HUD pill, command palette) from the global
// <DemoTour /> engine mounted in the dashboard layout. Any client component can
// call startDemoTour() without prop-drilling through the layout tree.
// ============================================================================

export const TOUR_START_EVENT = 'aegis:tour-start';

/** Opens the cinematic guided walkthrough from the first milestone. */
export function startDemoTour(): void {
  if (typeof window === 'undefined') {
    return;
  }
  window.dispatchEvent(new Event(TOUR_START_EVENT));
}
