// ============================================================================
// PROJECT AEGIS: CROSS-ROUTE PRESET HANDOFF BUS
// Lets the global command palette trigger a "instant preset" on a dashboard
// page that is not mounted yet. A sessionStorage handoff survives client-side
// navigation deterministically, while a CustomEvent covers the same-route case.
// ============================================================================

export type PresetId =
  | 'stripe'
  | 'aws'
  | 'clean'
  | 'github'
  | 'phishing'
  | 'metadata'
  | 'localhost';

export const PENDING_PRESET_KEY = 'aegis:pending-preset';
export const PRESET_EVENT = 'aegis:preset';

export interface PresetEventDetail {
  preset: PresetId;
}

const PRESET_IDS: readonly PresetId[] = [
  'stripe',
  'aws',
  'clean',
  'github',
  'phishing',
  'metadata',
  'localhost',
];

export function isPresetId(value: unknown): value is PresetId {
  return typeof value === 'string' && (PRESET_IDS as readonly string[]).includes(value);
}

/** Records a preset to be applied by the next dashboard page that mounts. */
export function requestPreset(preset: PresetId): void {
  try {
    window.sessionStorage.setItem(PENDING_PRESET_KEY, preset);
  } catch {
    // sessionStorage may be unavailable (private mode); the event fallback runs.
  }
}

/** Reads and clears any pending preset. Safe to call during a mount effect. */
export function consumePendingPreset(): PresetId | null {
  try {
    const raw = window.sessionStorage.getItem(PENDING_PRESET_KEY);
    if (!raw) {
      return null;
    }
    window.sessionStorage.removeItem(PENDING_PRESET_KEY);
    return isPresetId(raw) ? raw : null;
  } catch {
    return null;
  }
}

/** Dispatches a preset for a page that is already mounted. */
export function dispatchPreset(preset: PresetId): void {
  if (typeof window === 'undefined') {
    return;
  }
  window.dispatchEvent(new CustomEvent<PresetEventDetail>(PRESET_EVENT, { detail: { preset } }));
}
