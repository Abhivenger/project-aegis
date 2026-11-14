"use client";

// ============================================================================
// PROJECT AEGIS: MULTI-TAB INTERACTIVE GUIDED WALKTHROUGH
// Five spotlighted milestones, each on its real dashboard tab:
//   1. /dashboard              Live GitHub repository auditor + real scan
//   2. /dashboard/code-auditor Code & entropy sandbox + vulnerable snippet
//   3. /dashboard/url-inspector SafeLink phishing scan + risk gauge
//   4. /dashboard/vault        Zero-knowledge secrets vault + rotation status
//   5. /dashboard/api-keys     GitShield CLI pre-commit defense + terminal
//
// Step changes navigate the App Router automatically. The controller itself is
// mounted in the persistent dashboard layout and mirrored to sessionStorage, so
// routes change underneath it without ever closing or resetting the tour.
// Spotlight: SVG-mask cut-out that springs between targets. Keyboard: Esc closes,
// ArrowRight / ArrowLeft step. `?tour=1` auto-launches from the landing page.
// ============================================================================

import React, { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { usePathname, useRouter } from "next/navigation";
import { AnimatePresence, motion } from "motion/react";
import { toast } from "sonner";
import {
  ArrowLeft,
  ArrowRight,
  Copy,
  FileCode2,
  Loader2,
  Play,
  ShieldAlert,
  Terminal,
  X,
} from "lucide-react";
import {
  TOUR_START_EVENT,
  requestSampleScan,
  type SampleRepo,
} from "@/lib/tour-bus";
import { dispatchPreset } from "@/lib/preset-bus";

interface TourStep {
  id: string;
  /** Short label for the clickable step pill. */
  pill: string;
  badge: string;
  title: string;
  body: string;
  /** Dashboard route this step lives on. */
  route: string;
  /** data-tour target for the spotlight. */
  target: string;
  /** Secondary target if the primary has not mounted yet. */
  fallback?: string;
  /** Where the spotlight moves once the step action renders real results. */
  resultTarget?: string;
  action?: "repo-scan" | "load-snippet" | "test-url" | "copy-cli";
  actionLabel?: string;
  resultTimeoutMs?: number;
}

const REPO_SAMPLES = [
  "Abhivenger/project-aegis",
  "trufflesecurity/test_keys",
] as const;

const TOUR_STEPS: readonly TourStep[] = [
  {
    id: "repo-auditor",
    pill: "Repo",
    badge: "TAB 1 · LIVE GITHUB",
    title: "Live GitHub Repository Auditor",
    body: "Aegis pulls a real public repository through the GitHub REST API — the files below are the repository's actual contents. Run the live scan and the findings land right in this dashboard.",
    route: "/dashboard",
    target: '[data-tour="repo-search"]',
    resultTarget: '[data-tour="repo-telemetry"]',
    action: "repo-scan",
    actionLabel: "Run Live Repo Scan",
    resultTimeoutMs: 45_000,
  },
  {
    id: "code-sandbox",
    pill: "Sandbox",
    badge: "TAB 2 · ENTROPY",
    title: "Code & Entropy Sandbox",
    body: "Every token is scored by calibrated Shannon entropy (H ≥ 4.55) plus 27+ credential signatures. Load the vulnerable snippet to see the side-by-side Git diff and the clean .env template.",
    route: "/dashboard/code-auditor",
    target: '[data-tour="code-editor"]',
    resultTarget: '[data-tour="remediation-diff"]',
    action: "load-snippet",
    actionLabel: "Load Vulnerable Snippet",
    resultTimeoutMs: 15_000,
  },
  {
    id: "safelink",
    pill: "SafeLink",
    badge: "TAB 3 · PHISHING",
    title: "SafeLink Threat & Phishing Scanner",
    body: "SSRF-safe resolution, per-hop redirect tracing and phishing heuristics. Test the malicious homograph URL to render the live Risk Gauge and a shareable threat report.",
    route: "/dashboard/url-inspector",
    target: '[data-tour="url-input"]',
    resultTarget: '[data-tour="url-report"]',
    action: "test-url",
    actionLabel: "Test Malicious URL",
    resultTimeoutMs: 20_000,
  },
  {
    id: "vault",
    pill: "Vault",
    badge: "TAB 4 · ZERO-KNOWLEDGE",
    title: "Zero-Knowledge Secrets Vault",
    body: "Credentials stay masked and are shared only as ref:// environment references — never plaintext in a bundle or log. Each entry tracks entropy and rotation status so stale keys surface early.",
    route: "/dashboard/vault",
    target: '[data-tour="vault-secrets"]',
    fallback: '[data-tour="vault-stats"]',
  },
  {
    id: "cli-defense",
    pill: "CLI",
    badge: "TAB 5 · GITSHIELD CLI",
    title: "Local Pre-Commit Defense",
    body: "cli/aegis.py installs a zero-dependency Git hook. An accidental AKIA… or sk_live_… commit is blocked on the developer's machine — before it ever reaches GitHub.",
    route: "/dashboard/api-keys",
    target: '[data-tour="cli-banner"]',
    fallback: '[data-tour="api-keys-table"]',
    action: "copy-cli",
    actionLabel: "Copy CLI Install Command",
  },
];

const CLI_INSTALL_COMMAND = "python3 cli/aegis.py --install";
const TOUR_STORAGE_KEY = "aegis:tour-state";

const CLI_TRANSCRIPT: readonly { text: string; tone: "prompt" | "muted" | "danger" | "label" | "ok" }[] = [
  { text: '$ git commit -m "wire checkout flow"', tone: "prompt" },
  { text: "[aegis] scanning staged diff · 3 files", tone: "muted" },
  { text: "COMMIT BLOCKED: Unencrypted developer secrets detected!", tone: "danger" },
  { text: "  payment-handler.ts · Stripe API Key · sk_l****w9xY7z", tone: "label" },
  { text: "  cloud-config.ts · AWS Access Key ID · AKIA****MPLE", tone: "label" },
  { text: "  entropy 5.112 bits/char · exit 1", tone: "muted" },
  { text: "$ python3 cli/aegis.py --fix  # extracts to .env, restages", tone: "ok" },
];

interface Spotlight {
  x: number;
  y: number;
  w: number;
  h: number;
}

interface StoredTourState {
  open: boolean;
  step: number;
}

const SPRING = { type: "spring" as const, stiffness: 220, damping: 28 };
const SPOTLIGHT_PADDING = 8;
const CUTOUT_RADIUS = 16;
const CARD_MARGIN = 14;
const CARD_MAX_WIDTH = 392;

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function readStoredTour(): StoredTourState | null {
  try {
    const raw = window.sessionStorage.getItem(TOUR_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<StoredTourState>;
    if (typeof parsed.open !== "boolean" || typeof parsed.step !== "number") return null;
    return {
      open: parsed.open,
      step: clamp(Math.trunc(parsed.step), 0, TOUR_STEPS.length - 1),
    };
  } catch {
    return null;
  }
}

function writeStoredTour(state: StoredTourState): void {
  try {
    window.sessionStorage.setItem(TOUR_STORAGE_KEY, JSON.stringify(state));
  } catch {
    // Persistence is best-effort; the in-memory controller remains authoritative.
  }
}

interface CancelSignal {
  cancelled: boolean;
}

async function waitForTarget(
  primary: string,
  fallback: string | undefined,
  signal: CancelSignal,
  timeoutMs = 8_000,
  intervalMs = 100,
  fallbackDelayMs = 2_000,
  allowFallbackDuringWait = true
): Promise<Element | null> {
  const startedAt = performance.now();
  while (performance.now() - startedAt < timeoutMs) {
    if (signal.cancelled) return null;
    const primaryEl = document.querySelector(primary);
    if (primaryEl) return primaryEl;
    if (allowFallbackDuringWait && fallback && performance.now() - startedAt > fallbackDelayMs) {
      const fallbackEl = document.querySelector(fallback);
      if (fallbackEl) return fallbackEl;
    }
    await delay(intervalMs);
  }
  return document.querySelector(primary) ?? (fallback ? document.querySelector(fallback) : null);
}

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

export function DemoTour() {
  const router = useRouter();
  const pathname = usePathname();

  const [active, setActive] = useState(false);
  const [index, setIndex] = useState(0);
  const [mounted, setMounted] = useState(false);
  const [spot, setSpot] = useState<Spotlight | null>(null);
  const [viewport, setViewport] = useState({ w: 1280, h: 800 });
  const [cardSize, setCardSize] = useState({ w: CARD_MAX_WIDTH, h: 220 });
  const [sampleRepo, setSampleRepo] = useState<SampleRepo>("trufflesecurity/test_keys");
  const [readyStep, setReadyStep] = useState(-1);
  const [fired, setFired] = useState<{ step: number; nonce: number } | null>(null);
  const [resultVisible, setResultVisible] = useState(false);

  const cardRef = useRef<HTMLDivElement>(null);
  const elementRef = useRef<Element | null>(null);
  const viewportRef = useRef(viewport);
  const phaseRef = useRef<"idle" | "locating" | "settling" | "active">("idle");
  const scrolledRef = useRef<Set<number>>(new Set());
  const autoStartedRef = useRef(false);
  const previousStepRef = useRef<number | null>(null);
  const nonceRef = useRef(0);

  const step = TOUR_STEPS[index];
  const totalSteps = TOUR_STEPS.length;
  const waitingForResult = fired !== null && fired.step === index && !resultVisible;

  useEffect(() => {
    setMounted(true);
    const stored = readStoredTour();
    if (stored?.open) {
      setIndex(stored.step);
      setActive(true);
    }
  }, []);

  // Mirror controller state so a hard reload or deep link restores the tour.
  useEffect(() => {
    if (!mounted) return;
    writeStoredTour({ open: active, step: index });
  }, [active, index, mounted]);

  useEffect(() => {
    const measure = () => setViewport({ w: window.innerWidth, h: window.innerHeight });
    measure();
    window.addEventListener("resize", measure);
    window.addEventListener("orientationchange", measure);
    return () => {
      window.removeEventListener("resize", measure);
      window.removeEventListener("orientationchange", measure);
    };
  }, []);

  useEffect(() => {
    viewportRef.current = viewport;
  }, [viewport]);

  const openTour = useCallback(() => {
    scrolledRef.current = new Set();
    elementRef.current = null;
    phaseRef.current = "idle";
    previousStepRef.current = null;
    setFired(null);
    setResultVisible(false);
    setReadyStep(-1);
    setIndex(0);
    setSpot(null);
    setActive(true);
  }, []);

  const close = useCallback(() => {
    setActive(false);
    setSpot(null);
    setFired(null);
    setResultVisible(false);
    setReadyStep(-1);
    elementRef.current = null;
    phaseRef.current = "idle";
    scrolledRef.current = new Set();
  }, []);

  /** Moves to a step and resets the action/result machinery for that step. */
  const goTo = useCallback((target: number) => {
    setFired(null);
    setResultVisible(false);
    setReadyStep(-1);
    setIndex(clamp(target, 0, TOUR_STEPS.length - 1));
  }, []);

  const goNext = useCallback(() => {
    if (index >= TOUR_STEPS.length - 1) {
      close();
      return;
    }
    goTo(index + 1);
  }, [index, close, goTo]);

  const goBack = useCallback(() => {
    if (index === 0) return;
    goTo(index - 1);
  }, [index, goTo]);

  // Launch listeners: header/HUD/palette event, plus `?tour=1` from the landing page.
  useEffect(() => {
    const onStart = () => openTour();
    window.addEventListener(TOUR_START_EVENT, onStart);
    return () => window.removeEventListener(TOUR_START_EVENT, onStart);
  }, [openTour]);

  useEffect(() => {
    if (autoStartedRef.current || !mounted) return;
    autoStartedRef.current = true;
    const params = new URLSearchParams(window.location.search);
    if (params.get("tour") === "1") {
      window.history.replaceState({}, "", "/dashboard");
      openTour();
    }
  }, [mounted, openTour]);

  // Step-driven navigation: every step change lands on its real dashboard tab.
  // Manual navigation mid-step is left alone — the tour only steers on Next/Back.
  useEffect(() => {
    if (!active) {
      previousStepRef.current = null;
      return;
    }
    if (previousStepRef.current === index) return;
    previousStepRef.current = index;
    const stepRoute = TOUR_STEPS[index].route;
    if (pathname !== stepRoute) {
      router.push(stepRoute);
    }
  }, [active, index, pathname, router]);

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

  // Resolve the current step's spotlight target once its route is mounted.
  useEffect(() => {
    if (!active) return;
    const current = TOUR_STEPS[index];
    if (pathname !== current.route) {
      // The navigation effect owns the route transition; drop the stale cut-out
      // so it never lingers over the previous tab.
      elementRef.current = null;
      setSpot(null);
      return;
    }

    const signal: CancelSignal = { cancelled: false };
    const run = async () => {
      phaseRef.current = "locating";
      const el = await waitForTarget(current.target, current.fallback, signal, 12_000);
      if (signal.cancelled) return;
      if (!el) {
        elementRef.current = null;
        setSpot(null);
        phaseRef.current = "idle";
        return;
      }

      elementRef.current = el;

      if (!scrolledRef.current.has(index)) {
        scrolledRef.current.add(index);
        el.scrollIntoView({ behavior: "smooth", block: "center" });
        phaseRef.current = "settling";
        await waitForScrollSettle(signal);
      }
      if (signal.cancelled) return;

      measureElement(el);
      phaseRef.current = "active";
      setReadyStep(index);
    };

    void run();
    return () => {
      signal.cancelled = true;
    };
  }, [active, index, pathname, measureElement]);

  // After a step action runs, follow the real results into the spotlight.
  useEffect(() => {
    if (!active || !fired || fired.step !== index) return;
    const current = TOUR_STEPS[index];
    if (!current.resultTarget) return;

    const signal: CancelSignal = { cancelled: false };
    const nonce = fired.nonce;
    const timeout = current.resultTimeoutMs ?? 15_000;

    const run = async () => {
      const el = await waitForTarget(current.resultTarget!, undefined, signal, timeout, 150, 0, false);
      if (signal.cancelled) return;
      if (!el) {
        // Let the user retry (quota exhausted, network failure, …).
        setFired((prev) => (prev && prev.nonce === nonce ? null : prev));
        return;
      }

      elementRef.current = el;
      setResultVisible(true);
      el.scrollIntoView({ behavior: "smooth", block: "center" });
      await waitForScrollSettle(signal);
      if (signal.cancelled) return;
      measureElement(el);
      phaseRef.current = "active";
    };

    void run();
    return () => {
      signal.cancelled = true;
    };
  }, [active, index, fired, measureElement]);

  // Follow the spotlighted element every frame so scrolling never desyncs it.
  useEffect(() => {
    if (!active) return;
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

  useEffect(() => {
    const node = cardRef.current;
    if (!active || !node || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(() => {
      const current = cardRef.current;
      if (current) setCardSize({ w: current.offsetWidth, h: current.offsetHeight });
    });
    observer.observe(node);
    return () => observer.disconnect();
  }, [active, index]);

  useEffect(() => {
    if (!active) return;
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (
        target &&
        (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable)
      ) {
        return;
      }
      if (event.key === "ArrowRight") {
        event.preventDefault();
        goNext();
      } else if (event.key === "ArrowLeft") {
        event.preventDefault();
        goBack();
      } else if (event.key === "Escape") {
        event.preventDefault();
        close();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [active, goNext, goBack, close]);

  const copyCliCommand = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(CLI_INSTALL_COMMAND);
      toast.success("CLI install command copied", {
        description: "Run it at your repository root to arm the pre-commit guard.",
      });
    } catch {
      toast.error("Clipboard unavailable", { description: CLI_INSTALL_COMMAND });
    }
  }, []);

  const runStepAction = useCallback(() => {
    const current = TOUR_STEPS[index];
    if (!current.action) return;

    if (current.action === "repo-scan") {
      requestSampleScan(sampleRepo);
    } else if (current.action === "load-snippet") {
      dispatchPreset("aws");
    } else if (current.action === "test-url") {
      dispatchPreset("homograph");
    } else {
      void copyCliCommand();
      return;
    }

    setResultVisible(false);
    setFired({ step: index, nonce: (nonceRef.current += 1) });
  }, [index, sampleRepo, copyCliCommand]);

  const card = (() => {
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
    if (spaceBelow >= cardH + CARD_MARGIN) side = "bottom";
    else if (spaceAbove >= cardH + CARD_MARGIN) side = "top";
    else if (spaceRight >= cardW + CARD_MARGIN) side = "right";
    else if (spaceLeft >= cardW + CARD_MARGIN) side = "left";
    else {
      const best = Math.max(spaceBelow, spaceAbove, spaceRight, spaceLeft);
      side =
        best === spaceBelow ? "bottom" : best === spaceAbove ? "top" : best === spaceRight ? "right" : "left";
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
  })();

  if (!mounted) return null;

  const isLast = index === totalSteps - 1;
  const centerX = viewport.w / 2;
  const centerY = viewport.h / 2;
  const actionReady = readyStep === index && !waitingForResult;

  const runLabel =
    step.id === "repo-auditor" && resultVisible ? "Re-run Live Repo Scan" : step.actionLabel;

  const overlay = (
    <AnimatePresence>
      {active && (
        <motion.div
          key="aegis-tour"
          className="fixed inset-0 z-[95]"
          style={{ pointerEvents: "none" }}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.2, ease: "easeOut" }}
        >
          <svg aria-hidden className="absolute inset-0 h-full w-full">
            <defs>
              <mask id="aegis-tour-mask">
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
              fill="rgba(4, 6, 12, 0.70)"
              mask="url(#aegis-tour-mask)"
            />
          </svg>

          <AnimatePresence>
            {spot && (
              <motion.div
                key="frame"
                aria-hidden
                className="pointer-events-none fixed z-[96] rounded-2xl border border-white/30 shadow-[0_0_0_1px_rgba(255,255,255,0.06),0_0_48px_rgba(34,211,238,0.16)]"
                initial={{ opacity: 0, left: spot.x, top: spot.y, width: spot.w, height: spot.h }}
                animate={{ opacity: 1, left: spot.x, top: spot.y, width: spot.w, height: spot.h }}
                exit={{ opacity: 0 }}
                transition={{ ...SPRING, opacity: { duration: 0.2, ease: "easeOut" } }}
              />
            )}
          </AnimatePresence>

          <motion.div
            ref={cardRef}
            role="dialog"
            aria-modal="true"
            aria-label="Interactive product tour"
            className="fixed z-[100]"
            style={{ pointerEvents: "auto", width: card.cardW }}
            initial={false}
            animate={{ left: card.left, top: card.top }}
            transition={SPRING}
          >
            <div className="rounded-[20px] border border-white/[0.08] bg-zinc-950/90 shadow-[0_24px_80px_rgba(0,0,0,0.6)] backdrop-blur-xl transition-all duration-200 ease-out">
              <div className="h-px rounded-t-[20px] bg-gradient-to-r from-transparent via-white/25 to-transparent" />
              <div className="p-4">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="rounded-md border border-white/10 bg-white/[0.04] px-2 py-0.5 font-mono text-[10px] font-semibold tabular-nums tracking-wide text-zinc-300">
                      {index + 1} / {totalSteps}
                    </span>
                    <span className="truncate rounded-md border border-emerald-500/20 bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-widest text-emerald-300/90">
                      {step.badge}
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={close}
                    aria-label="Close tour"
                    className="rounded-md p-1 text-zinc-500 transition-all duration-200 ease-out hover:bg-white/[0.06] hover:text-zinc-200"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>

                {/* Tab map: judges can jump straight to any capability. */}
                <div className="mt-2.5 flex items-center gap-1 overflow-x-auto pb-0.5 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
                  {TOUR_STEPS.map((item, i) => (
                    <button
                      key={item.id}
                      type="button"
                      aria-label={`Go to ${item.title}`}
                      aria-current={i === index}
                      onClick={() => goTo(i)}
                      className={`shrink-0 rounded-full border px-2.5 py-1 font-mono text-[10px] transition-all duration-200 ease-out ${
                        i === index
                          ? "border-emerald-400/50 bg-emerald-400/10 text-emerald-200"
                          : i < index
                            ? "border-white/[0.06] bg-white/[0.02] text-zinc-400 hover:border-white/20 hover:text-zinc-200"
                            : "border-white/[0.06] bg-transparent text-zinc-500 hover:border-white/20 hover:text-zinc-300"
                      }`}
                    >
                      {item.pill}
                    </button>
                  ))}
                </div>

                <AnimatePresence mode="wait" initial={false}>
                  <motion.div
                    key={step.id}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -6 }}
                    transition={{ duration: 0.18, ease: "easeOut" }}
                    className="mt-3"
                  >
                    <h2 className="text-sm font-semibold tracking-tight text-white">{step.title}</h2>
                    <p className="mt-1.5 text-xs leading-relaxed text-zinc-400">{step.body}</p>

                    {waitingForResult && (
                      <div role="status" className="mt-2 flex items-center gap-1.5 font-mono text-[10px] text-cyan-300">
                        <Loader2 className="h-3 w-3 animate-spin motion-reduce:animate-none" />
                        {step.id === "repo-auditor"
                          ? "Scanning the live repository via the GitHub API…"
                          : step.id === "code-sandbox"
                            ? "Scoring tokens with entropy + signature rules…"
                            : "Tracing the redirect chain…"}
                      </div>
                    )}

                    {step.action === "repo-scan" && (
                      <div className="mt-3 space-y-2 rounded-xl border border-white/[0.06] bg-white/[0.02] p-2.5">
                        <div className="flex flex-wrap gap-1.5">
                          {REPO_SAMPLES.map((repo) => (
                            <button
                              key={repo}
                              type="button"
                              onClick={() => setSampleRepo(repo)}
                              aria-pressed={sampleRepo === repo}
                              className={`rounded-full border px-2.5 py-1 font-mono text-[10px] transition-all duration-200 ease-out ${
                                sampleRepo === repo
                                  ? "border-cyan-400/50 bg-cyan-400/10 text-cyan-200"
                                  : "border-white/[0.08] bg-white/[0.02] text-zinc-400 hover:border-white/20 hover:text-zinc-200"
                              }`}
                            >
                              {repo}
                            </button>
                          ))}
                        </div>
                        <button
                          type="button"
                          onClick={runStepAction}
                          disabled={!actionReady}
                          className="flex w-full items-center justify-center gap-1.5 rounded-lg bg-gradient-to-r from-emerald-400 to-cyan-400 px-3 py-1.5 text-[11px] font-semibold text-zinc-950 shadow-[0_0_20px_rgba(52,211,153,0.25)] transition-all duration-200 ease-out hover:from-emerald-300 hover:to-cyan-300 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          <Play className="h-3 w-3 fill-current" />
                          {runLabel}
                        </button>
                      </div>
                    )}

                    {step.action === "load-snippet" && (
                      <div className="mt-3 rounded-xl border border-white/[0.06] bg-white/[0.02] p-2.5">
                        <div className="flex flex-wrap items-center gap-1.5 font-mono text-[9px] text-zinc-500">
                          <span className="rounded border border-white/[0.08] px-1.5 py-0.5">H ≥ 4.55</span>
                          <span className="rounded border border-white/[0.08] px-1.5 py-0.5">27+ signatures</span>
                          <span className="rounded border border-white/[0.08] px-1.5 py-0.5">AWS + Stripe</span>
                        </div>
                        <button
                          type="button"
                          onClick={runStepAction}
                          disabled={!actionReady}
                          className="mt-2 flex w-full items-center justify-center gap-1.5 rounded-lg bg-gradient-to-r from-emerald-400 to-cyan-400 px-3 py-1.5 text-[11px] font-semibold text-zinc-950 shadow-[0_0_20px_rgba(52,211,153,0.25)] transition-all duration-200 ease-out hover:from-emerald-300 hover:to-cyan-300 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          <FileCode2 className="h-3 w-3" />
                          {runLabel}
                        </button>
                      </div>
                    )}

                    {step.action === "test-url" && (
                      <div className="mt-3 rounded-xl border border-white/[0.06] bg-white/[0.02] p-2.5">
                        <code className="block truncate rounded border border-white/[0.06] bg-black/30 px-2 py-1 font-mono text-[10px] text-cyan-200/80">
                          secure.login.verify.otp.auth.xn--pypal-4ve.com.xyz
                        </code>
                        <button
                          type="button"
                          onClick={runStepAction}
                          disabled={!actionReady}
                          className="mt-2 flex w-full items-center justify-center gap-1.5 rounded-lg bg-gradient-to-r from-rose-400 to-amber-300 px-3 py-1.5 text-[11px] font-semibold text-zinc-950 shadow-[0_0_20px_rgba(251,113,133,0.22)] transition-all duration-200 ease-out hover:from-rose-300 hover:to-amber-200 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          <ShieldAlert className="h-3 w-3" />
                          {runLabel}
                        </button>
                      </div>
                    )}

                    {step.action === "copy-cli" && (
                      <div className="mt-3 rounded-xl border border-white/[0.06] bg-[#05070d] p-2.5">
                        <div className="mb-1.5 flex items-center justify-between gap-2">
                          <span className="flex items-center gap-1.5 font-mono text-[9px] uppercase tracking-widest text-zinc-500">
                            <Terminal className="h-3 w-3" /> terminal · pre-commit
                          </span>
                          <span className="rounded border border-rose-500/30 bg-rose-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-rose-300">
                            BLOCKED
                          </span>
                        </div>
                        <div className="max-h-40 space-y-0.5 overflow-y-auto font-mono text-[10px] leading-relaxed">
                          {CLI_TRANSCRIPT.map((line) => (
                            <div
                              key={line.text}
                              className={
                                line.tone === "prompt"
                                  ? "text-zinc-200"
                                  : line.tone === "danger"
                                    ? "text-rose-300"
                                    : line.tone === "label"
                                      ? "text-cyan-200/90"
                                      : line.tone === "ok"
                                        ? "text-emerald-300"
                                        : "text-zinc-500"
                              }
                            >
                              {line.text}
                            </div>
                          ))}
                        </div>
                        <button
                          type="button"
                          onClick={runStepAction}
                          className="mt-2.5 flex w-full items-center justify-center gap-1.5 rounded-lg border border-emerald-400/40 bg-emerald-400/10 px-3 py-1.5 text-[11px] font-semibold text-emerald-200 transition-all duration-200 ease-out hover:bg-emerald-400/20"
                        >
                          <Copy className="h-3 w-3" />
                          {step.actionLabel}
                        </button>
                      </div>
                    )}
                  </motion.div>
                </AnimatePresence>

                <div className="mt-4 space-y-3 border-t border-white/[0.06] pt-3">
                  <div className="flex items-center justify-between gap-2">
                    <button
                      type="button"
                      onClick={close}
                      className="rounded-md px-2 py-1 text-[11px] font-medium text-zinc-500 transition-all duration-200 ease-out hover:bg-white/[0.04] hover:text-zinc-300"
                    >
                      Skip tour
                    </button>

                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={goBack}
                        disabled={index === 0}
                        className="flex items-center gap-1 rounded-lg border border-white/[0.08] bg-white/[0.02] px-2.5 py-1.5 text-[11px] font-medium text-zinc-300 transition-all duration-200 ease-out hover:bg-white/[0.06] hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        <ArrowLeft className="h-3 w-3" />
                        Back
                      </button>
                      <button
                        type="button"
                        onClick={goNext}
                        className="flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-emerald-400 to-cyan-400 px-3 py-1.5 text-[11px] font-semibold text-zinc-950 shadow-[0_0_18px_rgba(52,211,153,0.22)] transition-all duration-200 ease-out hover:from-emerald-300 hover:to-cyan-300"
                      >
                        {isLast ? "Finish" : "Next"}
                        <ArrowRight className="h-3 w-3" />
                      </button>
                    </div>
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
