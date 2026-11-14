// ============================================================================
// PROJECT AEGIS: GUIDED DEMO TOUR LAUNCH BUS
// Decouples tour triggers (header pill, bottom HUD, command palette, landing
// page) from the <DemoTour /> engine mounted in the dashboard layout.
// ============================================================================

export const TOUR_START_EVENT = 'aegis:tour-start';
export const TOUR_SAMPLE_SCAN_EVENT = 'aegis:tour-sample-scan';

export type SampleRepo = 'Abhivenger/project-aegis' | 'trufflesecurity/test_keys';

/** Opens the guided walkthrough from the first milestone. */
export function startDemoTour(): void {
  if (typeof window === 'undefined') {
    return;
  }
  window.dispatchEvent(new Event(TOUR_START_EVENT));
}

/** Asks the mounted GitHub scanner to run a real scan for a sample repo. */
export function requestSampleScan(repo: SampleRepo): void {
  if (typeof window === 'undefined') {
    return;
  }
  window.dispatchEvent(new CustomEvent<SampleRepo>(TOUR_SAMPLE_SCAN_EVENT, { detail: repo }));
}
