"use client";

// ============================================================================
// PROJECT AEGIS: INTERACTIVE PRODUCT SHOWCASE
// A Linear/Apple-style guided walkthrough built on Framer Motion + Tailwind.
//
//  * SVG-mask spotlight via `motion.rect`: the cut-out MORPHS and GLIDES between
//    same-route steps with spring physics, and springs into place after a
//    cross-route navigation. Crisp `rgba(5,7,12,0.78)` backdrop — no blur, so
//    the spotlighted element stays 100% sharp.
//  * Route-safe flow: fade the spotlight, route, poll/retry until the DOM target
//    mounts, smooth-scroll, wait for scroll settling, then measure.
//  * Compact glass popover that auto-docks top/bottom/left/right with a 14px gap.
// ============================================================================

import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";
import { usePathname, useRouter } from "next/navigation";
import { AnimatePresence, motion } from "motion/react";
import { ArrowLeft, ArrowRight, X } from "lucide-react";
import { requestPreset, dispatchPreset, type PresetId } from "@/lib/preset-bus";
import { TOUR_START_EVENT } from "@/lib/tour-bus";

// ============================================================================
// 8-milestone product showcase script
// ============================================================================

interface TourAction {
  /** CSS selector of a control to programmatically click on entry. */
  click: string;
}

export interface TourStep {
  /** Stable id, also mirrored by the target's data-tour attribute. */
  id: string;
  /** Accent category badge shown in the popover header. */
  badge: string;
  title: string;
  description: string;
  /** Route to navigate to. Omitted for global (route-agnostic) steps. */
  route?: string;
  /** CSS selector for the spotlighted element. */
  target: string;
  /** Selector used if the primary target does not mount in time. */
  fallback?: string;
  /** Preset fired so the page renders the data this step showcases. */
  preset?: PresetId;
  /** Optional programmatic interaction (e.g. switching the heatmap view). */
  action?: TourAction;
}

export const TOUR_STEPS: readonly TourStep[] = [
  {
    id: "code-editor",
    badge: "GITSHIELD",
    title: "GitShield Code Auditor",
    description:
      "Scans staged code in real time against 27+ cryptographic token signatures with zero cloud latency.",
    route: "/dashboard/code-auditor",
    target: '[data-tour="code-editor"]',
    preset: "stripe",
  },
  {
    id: "entropy-toggle",
    badge: "ENTROPY",
    title: "Shannon Entropy Analysis",
    description:
      "Calculates mathematical randomness per token (H = -Σ p log₂ p) to distinguish true high-risk secrets from normal code syntax.",
    route: "/dashboard/code-auditor",
    target: '[data-tour="entropy-toggle"]',
    fallback: '[data-tour="code-editor"]',
    action: { click: '[data-tour-action="entropy-heatmap"]' },
  },
  {
    id: "remediation-diff",
    badge: "REMEDIATION",
    title: "Automated .env Remediation",
    description:
      "Instantly extracts exposed secrets into localized environment variables and generates sanitized diff replacements.",
    route: "/dashboard/code-auditor",
    target: '[data-tour="remediation-diff"]',
    fallback: '[data-tour="code-editor"]',
    action: { click: '[data-tour-action="diff-view"]' },
  },
  {
    id: "export-audit",
    badge: "TELEMETRY",
    title: "Cryptographic Threat Telemetry",
    description:
      "Generates exportable Markdown reports and JSON telemetry tagged with SHA-256 fingerprints and risk scoring.",
    route: "/dashboard/code-auditor",
    target: '[data-tour="export-audit"]',
    fallback: '[data-tour="code-editor"]',
  },
  {
    id: "url-input",
    badge: "SAFELINK",
    title: "SafeLink SSRF Interceptor",
    description:
      "Inspects inbound webhooks and URLs, blocking internal loopbacks and private RFC-1918 subnets.",
    route: "/dashboard/url-inspector",
    target: '[data-tour="url-input"]',
    preset: "metadata",
  },
  {
    id: "red-team-lab",
    badge: "RED TEAM",
    title: "Live Exploit Simulator",
    description:
      "Simulates cloud metadata exfiltration (AWS IMDSv2) and DNS rebinding with real-time socket abort tracing.",
    route: "/dashboard/url-inspector",
    target: '[data-tour="red-team-lab"]',
  },
  {
    id: "api-keys-table",
    badge: "DEV PORTAL",
    title: "Developer Key Gateway",
    description:
      "Issues authenticated aegis_live_... tokens backed by resilient local persistence.",
    route: "/dashboard/api-keys",
    target: '[data-tour="api-keys-table"]',
  },
  {
    id: "hud-status",
    badge: "HUD",
    title: "Armed HUD & Command Palette",
    description:
      "Real-time telemetry monitoring with Cmd+K navigation and pre-commit GitShield CLI enforcement.",
    target: '[data-tour="hud-status"]',
  },
];

// ============================================================================
// Geometry + animation constants
// ============================================================================

interface Spotlight {
  x: number;
  y: number;
  w: number;
  h: number;
}

interface ViewportSize {
  w: number;
  h: number;
}

/** The requested spring for the spotlight morph. */
const SPRING = { type: "spring" as const, stiffness: 220, damping: 28 };
/** Breathing room between the element edge and the cut-out. */
const SPOTLIGHT_PADDING = 8;
const CUTOUT_RADIUS = 12;
/** Gap between the spotlight edge and the popover. */
const CARD_MARGIN = 14;
const CARD_MAX_WIDTH = 384;

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

interface CancelSignal {
  cancelled: boolean;
}

/**
 * Polls for a target element to mount (cross-route safe). The primary selector
 * is tried first; the fallback only engages after a short grace period so a
 * late-mounting primary target is never shadowed by a generic fallback.
 */
async function waitForTarget(
  primary: string,
  fallback: string | undefined,
  signal: CancelSignal,
  timeoutMs = 7000,
  intervalMs = 90,
  fallbackDelayMs = 1200
): Promise<Element | null> {
  const startedAt = performance.now();
  while (performance.now() - startedAt < timeoutMs) {
    if (signal.cancelled) {
      return null;
    }
    const primaryEl = document.querySelector(primary);
    if (primaryEl) {
      return primaryEl;
    }
    if (fallback && performance.now() - startedAt > fallbackDelayMs) {
      const fallbackEl = document.querySelector(fallback);
      if (fallbackEl) {
        return fallbackEl;
      }
    }
    await delay(intervalMs);
  }
  return document.querySelector(primary) ?? (fallback ? document.querySelector(fallback) : null);
}

/** Resolves once the window scroll position has held steady for two frames. */
function waitForScrollSettle(signal: CancelSignal): Promise<void> {
  return new Promise((resolve) => {
    let lastX = window.scrollX;
    let lastY = window.scrollY;
    let stableFrames = 0;
    const loop = () => {
      if (signal.cancelled) {
        resolve();
        return;
      }
      const { scrollX, scrollY } = window;
      if (scrollX === lastX && scrollY === lastY) {
        stableFrames += 1;
      } else {
        stableFrames = 0;
      }
      lastX = scrollX;
      lastY = scrollY;
      if (stableFrames >= 2) {
        resolve();
        return;
      }
      window.requestAnimationFrame(loop);
    };
    window.requestAnimationFrame(loop);
  });
}

function formatStep(value: number): string {
  return String(value).padStart(2, "0");
}

// ============================================================================
// Main engine
// ============================================================================

export function DemoTour() {
  const router = useRouter();
  const pathname = usePathname();

  const [active, setActive] = useState(false);
  const [index, setIndex] = useState(0);
  const [mounted, setMounted] = useState(false);
  const [spot, setSpot] = useState<Spotlight | null>(null);
  const [viewport, setViewport] = useState<ViewportSize>({ w: 1280, h: 800 });
  const [cardSize, setCardSize] = useState({ w: CARD_MAX_WIDTH, h: 190 });

  const cardRef = useRef<HTMLDivElement>(null);
  const elementRef = useRef<Element | null>(null);
  const viewportRef = useRef(viewport);
  const phaseRef = useRef<"idle" | "locating" | "settling" | "active">("idle");
  const preparedRef = useRef<Set<number>>(new Set());
  const scrolledRef = useRef<Set<number>>(new Set());

  const step = TOUR_STEPS[index];
  const totalSteps = TOUR_STEPS.length;

  useEffect(() => {
    setMounted(true);
  }, []);

  // ---------------------------------------------------------------------------
  // Viewport tracking (resize / orientation / tab visibility)
  // ---------------------------------------------------------------------------
  useEffect(() => {
    const measure = () => setViewport({ w: window.innerWidth, h: window.innerHeight });
    measure();
    window.addEventListener("resize", measure);
    window.addEventListener("orientationchange", measure);
    document.addEventListener("visibilitychange", measure);
    return () => {
      window.removeEventListener("resize", measure);
      window.removeEventListener("orientationchange", measure);
      document.removeEventListener("visibilitychange", measure);
    };
  }, []);

  useEffect(() => {
    viewportRef.current = viewport;
  }, [viewport]);

  // ---------------------------------------------------------------------------
  // Launch listener (bottom HUD pill / command palette)
  // ---------------------------------------------------------------------------
  useEffect(() => {
    const onStart = () => {
      preparedRef.current = new Set();
      scrolledRef.current = new Set();
      elementRef.current = null;
      phaseRef.current = "idle";
      setIndex(0);
      setSpot(null);
      setActive(true);
    };
    window.addEventListener(TOUR_START_EVENT, onStart);
    return () => window.removeEventListener(TOUR_START_EVENT, onStart);
  }, []);

  const close = useCallback(() => {
    setActive(false);
    setSpot(null);
    elementRef.current = null;
    phaseRef.current = "idle";
  }, []);

  const goTo = useCallback((target: number) => {
    setIndex(clamp(target, 0, TOUR_STEPS.length - 1));
  }, []);

  const goNext = useCallback(() => {
    if (index >= TOUR_STEPS.length - 1) {
      close();
      return;
    }
    setIndex(index + 1);
  }, [index, close]);

  const goBack = useCallback(() => {
    setIndex((current) => Math.max(0, current - 1));
  }, []);

  // ---------------------------------------------------------------------------
  // Measure a resolved element into a padded spotlight cut-out.
  // ---------------------------------------------------------------------------
  const measureElement = useCallback((el: Element) => {
    const bounds = el.getBoundingClientRect();
    const { w: vw, h: vh } = viewportRef.current;
    const x = clamp(bounds.left - SPOTLIGHT_PADDING, 0, Math.max(0, vw));
    const y = clamp(bounds.top - SPOTLIGHT_PADDING, 0, Math.max(0, vh));
    const w = clamp(bounds.width + SPOTLIGHT_PADDING * 2, 0, Math.max(0, vw - x));
    const h = clamp(bounds.height + SPOTLIGHT_PADDING * 2, 0, Math.max(0, vh - y));
    setSpot((prev) => {
      if (
        prev &&
        Math.abs(prev.x - x) < 0.5 &&
        Math.abs(prev.y - y) < 0.5 &&
        Math.abs(prev.w - w) < 0.5 &&
        Math.abs(prev.h - h) < 0.5
      ) {
        return prev;
      }
      return { x, y, w, h };
    });
  }, []);

  // ---------------------------------------------------------------------------
  // Step flow — route, retry-poll for mount, smooth-scroll, settle, then morph.
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (!active) {
      return;
    }
    const signal: CancelSignal = { cancelled: false };
    const current = TOUR_STEPS[index];
    const prepared = preparedRef.current;

    const run = async () => {
      const onRoute = !current.route || pathname === current.route;

      if (!onRoute) {
        // Cross-route: fade the spotlight out, then navigate.
        if (current.preset && !prepared.has(index)) {
          prepared.add(index);
          requestPreset(current.preset);
        }
        phaseRef.current = "idle";
        elementRef.current = null;
        setSpot(null);
        router.push(current.route as string);
      } else if (current.preset && !prepared.has(index)) {
        prepared.add(index);
        dispatchPreset(current.preset);
      }

      phaseRef.current = "locating";
      const el = await waitForTarget(current.target, current.fallback, signal);
      if (signal.cancelled) {
        return;
      }
      if (!el) {
        elementRef.current = null;
        setSpot(null);
        phaseRef.current = "idle";
        return;
      }

      elementRef.current = el;

      // Smooth auto-scroll once per milestone, then wait for the scroll to settle
      // before measuring so the spotlight never lands mid-scroll.
      if (!scrolledRef.current.has(index)) {
        scrolledRef.current.add(index);
        el.scrollIntoView({ behavior: "smooth", block: "center" });
        phaseRef.current = "settling";
        await waitForScrollSettle(signal);
      }
      if (signal.cancelled) {
        return;
      }

      // Optional programmatic interaction (e.g. switch to the heatmap view).
      if (current.action) {
        const actionEl = document.querySelector(current.action.click);
        if (actionEl instanceof HTMLElement) {
          actionEl.click();
        }
      }

      measureElement(el);
      phaseRef.current = "active";
    };

    void run();

    return () => {
      signal.cancelled = true;
    };
    // `pathname` is read at entry and intentionally excluded so a route change
    // mid-flow does not restart the effect (the polling loop absorbs it).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, index, router, measureElement]);

  // ---------------------------------------------------------------------------
  // Continuous tracker: while a spotlight is active, follow the element every
  // frame so user scrolling / layout shifts never desync the cut-out.
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (!active) {
      return;
    }
    let frame = 0;
    const loop = () => {
      const el = elementRef.current;
      if (el && document.contains(el) && phaseRef.current === "active") {
        measureElement(el);
      }
      frame = window.requestAnimationFrame(loop);
    };
    frame = window.requestAnimationFrame(loop);
    return () => window.cancelAnimationFrame(frame);
  }, [active, measureElement]);

  // ---------------------------------------------------------------------------
  // Measure the popover for space-aware docking.
  // ---------------------------------------------------------------------------
  useEffect(() => {
    const node = cardRef.current;
    if (!active || !node || typeof ResizeObserver === "undefined") {
      return;
    }
    const observer = new ResizeObserver(() => {
      const current = cardRef.current;
      if (current) {
        setCardSize({ w: current.offsetWidth, h: current.offsetHeight });
      }
    });
    observer.observe(node);
    return () => observer.disconnect();
  }, [active, index]);

  // ---------------------------------------------------------------------------
  // Keyboard controls
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (!active) {
      return;
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "ArrowRight" || event.key === "Enter") {
        if (event.key === "Enter") {
          const target = event.target as HTMLElement | null;
          if (target && target.closest("button, a, input, textarea, select")) {
            return;
          }
        }
        event.preventDefault();
        goNext();
        return;
      }
      if (event.key === "ArrowLeft") {
        event.preventDefault();
        goBack();
        return;
      }
      if (event.key === "Escape") {
        event.preventDefault();
        close();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [active, goNext, goBack, close]);

  // ---------------------------------------------------------------------------
  // Space-aware popover docking (top / bottom / left / right) with 14px margin.
  // ---------------------------------------------------------------------------
  const card = useMemo(() => {
    const { w: vw, h: vh } = viewport;
    const cardW = clamp(Math.min(CARD_MAX_WIDTH, vw - CARD_MARGIN * 2), 240, CARD_MAX_WIDTH);
    const cardH = cardSize.h;
    const maxLeft = Math.max(CARD_MARGIN, vw - cardW - CARD_MARGIN);
    const maxTop = Math.max(CARD_MARGIN, vh - cardH - CARD_MARGIN);

    if (!spot) {
      return {
        cardW,
        left: clamp((vw - cardW) / 2, CARD_MARGIN, maxLeft),
        top: clamp(vh * 0.3, CARD_MARGIN, maxTop),
      };
    }

    const spaceBelow = vh - (spot.y + spot.h);
    const spaceAbove = spot.y;
    const spaceRight = vw - (spot.x + spot.w);
    const spaceLeft = spot.x;

    let side: "top" | "bottom" | "left" | "right";
    if (spaceBelow >= cardH + CARD_MARGIN) {
      side = "bottom";
    } else if (spaceAbove >= cardH + CARD_MARGIN) {
      side = "top";
    } else if (spaceRight >= cardW + CARD_MARGIN) {
      side = "right";
    } else if (spaceLeft >= cardW + CARD_MARGIN) {
      side = "left";
    } else {
      const best = Math.max(spaceBelow, spaceAbove, spaceRight, spaceLeft);
      side =
        best === spaceBelow
          ? "bottom"
          : best === spaceAbove
            ? "top"
            : best === spaceRight
              ? "right"
              : "left";
    }

    let left = spot.x + spot.w / 2 - cardW / 2;
    let top = spot.y + spot.h + CARD_MARGIN;
    if (side === "top") {
      top = spot.y - cardH - CARD_MARGIN;
    } else if (side === "right") {
      left = spot.x + spot.w + CARD_MARGIN;
      top = spot.y + spot.h / 2 - cardH / 2;
    } else if (side === "left") {
      left = spot.x - cardW - CARD_MARGIN;
      top = spot.y + spot.h / 2 - cardH / 2;
    }

    return {
      cardW,
      left: clamp(left, CARD_MARGIN, maxLeft),
      top: clamp(top, CARD_MARGIN, maxTop),
    };
  }, [spot, viewport, cardSize.h]);

  if (!mounted) {
    return null;
  }

  const stepNumber = formatStep(index + 1);
  const totalPadded = formatStep(totalSteps);
  const isLast = index === totalSteps - 1;
  const centerX = viewport.w / 2;
  const centerY = viewport.h / 2;

  const overlay = (
    <AnimatePresence>
      {active && (
        <motion.div
          key="aegis-showcase"
          className="fixed inset-0 z-[95]"
          style={{ pointerEvents: "none" }}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.2, ease: "easeOut" }}
        >
          {/* Crisp dim backdrop with an animating SVG-mask cut-out (no blur) */}
          <svg aria-hidden className="absolute inset-0 h-full w-full">
            <defs>
              <mask id="aegis-showcase-mask">
                <rect x="0" y="0" width="100%" height="100%" fill="white" />
                <motion.rect
                  initial={false}
                  rx={CUTOUT_RADIUS}
                  fill="black"
                  animate={
                    spot
                      ? { attrX: spot.x, attrY: spot.y, width: spot.w, height: spot.h }
                      : { attrX: centerX, attrY: centerY, width: 0, height: 0 }
                  }
                  transition={SPRING}
                />
              </mask>
            </defs>
            <rect
              x="0"
              y="0"
              width="100%"
              height="100%"
              fill="rgba(5, 7, 12, 0.78)"
              mask="url(#aegis-showcase-mask)"
            />
          </svg>

          {/* Neon accent frame, perfectly synced with the mask cut-out */}
          <AnimatePresence>
            {spot && (
              <motion.div
                key="frame"
                className="pointer-events-none fixed z-[96] rounded-xl border border-cyan-400/40 ring-2 ring-cyan-500/10"
                initial={{
                  opacity: 0,
                  left: spot.x,
                  top: spot.y,
                  width: spot.w,
                  height: spot.h,
                }}
                animate={{
                  opacity: 1,
                  left: spot.x,
                  top: spot.y,
                  width: spot.w,
                  height: spot.h,
                }}
                exit={{ opacity: 0 }}
                transition={{ ...SPRING, opacity: { duration: 0.2, ease: "easeOut" } }}
              />
            )}
          </AnimatePresence>

          {/* Glass popover */}
          <motion.div
            ref={cardRef}
            role="dialog"
            aria-modal="true"
            aria-label="Interactive product showcase"
            className="fixed z-[100]"
            style={{ pointerEvents: "auto", width: card.cardW }}
            initial={false}
            animate={{ left: card.left, top: card.top }}
            transition={SPRING}
          >
            <div className="rounded-2xl border border-white/10 bg-zinc-950/95 p-4 shadow-2xl shadow-black/60 backdrop-blur-xl">
              {/* Header: step indicator + accent badge + close */}
              <div className="flex items-center justify-between gap-2">
                <div className="flex min-w-0 items-center gap-2">
                  <span className="rounded-md border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold tracking-wide text-cyan-300">
                    [ STEP {stepNumber} / {totalPadded} ]
                  </span>
                  <span className="truncate rounded-md border border-emerald-500/20 bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-widest text-emerald-300">
                    {step.badge}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={close}
                  aria-label="Close showcase"
                  className="rounded-md p-1 text-zinc-500 transition hover:bg-white/5 hover:text-zinc-200"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>

              {/* Content */}
              <AnimatePresence mode="wait" initial={false}>
                <motion.div
                  key={step.id}
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -6 }}
                  transition={{ duration: 0.18, ease: "easeOut" }}
                  className="mt-3"
                >
                  <h2 className="text-sm font-semibold text-white">{step.title}</h2>
                  <p className="mt-1.5 text-xs leading-relaxed text-zinc-400">
                    {step.description}
                  </p>
                </motion.div>
              </AnimatePresence>

              {/* Segmented progress + controls */}
              <div className="mt-4 space-y-3 border-t border-white/5 pt-3">
                <div className="flex items-center gap-1" role="tablist" aria-label="Showcase progress">
                  {TOUR_STEPS.map((item, i) => (
                    <button
                      key={item.id}
                      type="button"
                      role="tab"
                      aria-selected={i === index}
                      aria-label={`Go to step ${i + 1}`}
                      onClick={() => goTo(i)}
                      className={`h-1 flex-1 rounded-full transition-colors duration-300 ${
                        i < index
                          ? "bg-cyan-500/50"
                          : i === index
                            ? "bg-cyan-400"
                            : "bg-zinc-800 hover:bg-zinc-700"
                      }`}
                    />
                  ))}
                </div>

                <div className="flex items-center justify-between">
                  <button
                    type="button"
                    onClick={goBack}
                    disabled={index === 0}
                    className="flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium text-zinc-400 transition hover:bg-white/5 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    <ArrowLeft className="h-3.5 w-3.5" />
                    Back
                  </button>

                  <div className="flex items-center gap-2">
                    <span className="hidden font-mono text-[10px] text-zinc-600 sm:inline">
                      [→]
                    </span>
                    <span className="hidden font-mono text-[10px] text-zinc-600 sm:inline">
                      [Esc]
                    </span>
                    <button
                      type="button"
                      onClick={goNext}
                      className="flex items-center gap-1.5 rounded-md bg-gradient-to-r from-cyan-500 to-emerald-500 px-3 py-1 text-xs font-semibold text-zinc-950 shadow-[0_0_18px_rgba(34,211,238,0.45)] transition hover:from-cyan-400 hover:to-emerald-400"
                    >
                      {isLast ? "Finish" : "Next"}
                      <ArrowRight className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );

  return createPortal(overlay, document.body);
}
