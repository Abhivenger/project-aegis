"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { AnimatePresence, motion } from "motion/react";
import {
  Search,
  Globe,
  Code2,
  Key,
  Flame,
  ShieldAlert,
  Braces,
  Trash2,
  CornerDownLeft,
  Command,
  type LucideIcon,
} from "lucide-react";
import {
  requestPreset,
  dispatchPreset,
  type PresetId,
} from "@/lib/preset-bus";

interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

type CommandGroup = "Navigation" | "Instant Presets";

interface PaletteCommand {
  id: string;
  label: string;
  hint: string;
  group: CommandGroup;
  icon: LucideIcon;
  keywords: string[];
  run: () => void;
}

export function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const close = useCallback(() => onOpenChange(false), [onOpenChange]);

  // Triggers a route-aware preset: persists it for the next page mount AND
  // emits it for an already-mounted page, then navigates.
  const runPreset = useCallback(
    (preset: PresetId, href: string) => {
      requestPreset(preset);
      dispatchPreset(preset);
      router.push(href);
      close();
    },
    [router, close]
  );

  const commands = useMemo<PaletteCommand[]>(
    () => [
      {
        id: "nav-url",
        label: "SafeLink URL Inspector",
        hint: "SSRF-safe URL inspection",
        group: "Navigation",
        icon: Globe,
        keywords: ["url", "link", "ssrf", "safelink", "phishing"],
        run: () => {
          router.push("/dashboard/url-inspector");
          close();
        },
      },
      {
        id: "nav-code",
        label: "GitShield Code Auditor",
        hint: "Secret scanning & entropy heatmap",
        group: "Navigation",
        icon: Code2,
        keywords: ["code", "audit", "secret", "entropy", "gitshield"],
        run: () => {
          router.push("/dashboard/code-auditor");
          close();
        },
      },
      {
        id: "nav-keys",
        label: "Developer API Keys",
        hint: "CLI + pre-commit hook credentials",
        group: "Navigation",
        icon: Key,
        keywords: ["key", "api", "token", "cli", "hook"],
        run: () => {
          router.push("/dashboard/api-keys");
          close();
        },
      },
      {
        id: "preset-stripe",
        label: "Audit Stripe Live-Key Leak",
        hint: "Code Auditor · instant preset",
        group: "Instant Presets",
        icon: Flame,
        keywords: ["stripe", "payment", "leak", "code", "preset"],
        run: () => runPreset("stripe", "/dashboard/code-auditor"),
      },
      {
        id: "preset-aws",
        label: "Audit AWS + Gemini Credentials",
        hint: "Code Auditor · instant preset",
        group: "Instant Presets",
        icon: Flame,
        keywords: ["aws", "gcp", "gemini", "cloud", "code", "preset"],
        run: () => runPreset("aws", "/dashboard/code-auditor"),
      },
      {
        id: "preset-clean",
        label: "Audit Clean Module",
        hint: "Code Auditor · instant preset",
        group: "Instant Presets",
        icon: Braces,
        keywords: ["clean", "safe", "code", "preset"],
        run: () => runPreset("clean", "/dashboard/code-auditor"),
      },
      {
        id: "preset-metadata",
        label: "Inspect Cloud Metadata SSRF",
        hint: "URL Inspector · instant preset",
        group: "Instant Presets",
        icon: ShieldAlert,
        keywords: ["metadata", "169.254", "imds", "ssrf", "url", "preset"],
        run: () => runPreset("metadata", "/dashboard/url-inspector"),
      },
      {
        id: "preset-phishing",
        label: "Inspect Phishing Pattern",
        hint: "URL Inspector · instant preset",
        group: "Instant Presets",
        icon: ShieldAlert,
        keywords: ["phishing", "login", "otp", "url", "preset"],
        run: () => runPreset("phishing", "/dashboard/url-inspector"),
      },
      {
        id: "preset-localhost",
        label: "Inspect Localhost SSRF",
        hint: "URL Inspector · instant preset",
        group: "Instant Presets",
        icon: Globe,
        keywords: ["localhost", "127.0.0.1", "loopback", "url", "preset"],
        run: () => runPreset("localhost", "/dashboard/url-inspector"),
      },
    ],
    [router, close, runPreset]
  );

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) {
      return commands;
    }
    return commands.filter((command) => {
      const haystack = `${command.label} ${command.hint} ${command.keywords.join(" ")}`.toLowerCase();
      return haystack.includes(needle);
    });
  }, [commands, query]);

  // Reset transient state whenever the palette opens.
  useEffect(() => {
    if (open) {
      setQuery("");
      setSelectedIndex(0);
      const id = window.setTimeout(() => inputRef.current?.focus(), 40);
      return () => window.clearTimeout(id);
    }
    return undefined;
  }, [open]);

  useEffect(() => {
    setSelectedIndex((current) => {
      if (filtered.length === 0) {
        return 0;
      }
      return Math.min(current, filtered.length - 1);
    });
  }, [filtered]);

  // Global Cmd/Ctrl+K handler.
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        onOpenChange(!open);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onOpenChange]);

  // In-modal keyboard navigation.
  const handleKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Escape") {
      event.preventDefault();
      close();
      return;
    }
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setSelectedIndex((current) =>
        filtered.length === 0 ? 0 : (current + 1) % filtered.length
      );
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      setSelectedIndex((current) =>
        filtered.length === 0 ? 0 : (current - 1 + filtered.length) % filtered.length
      );
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      const command = filtered[selectedIndex];
      if (command) {
        command.run();
      }
    }
  };

  let lastGroup: CommandGroup | null = null;

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-[80] flex items-start justify-center p-4 pt-[12vh]"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.18 }}
          role="dialog"
          aria-modal="true"
          aria-label="Command palette"
        >
          <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={close} />

          <motion.div
            className="relative w-full max-w-xl overflow-hidden rounded-2xl border border-slate-700 bg-[#090f20] shadow-2xl"
            initial={{ opacity: 0, y: -16, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -12, scale: 0.98 }}
            transition={{ type: "spring", stiffness: 340, damping: 30 }}
          >
            {/* Search field */}
            <div className="flex items-center gap-2 border-b border-slate-800 px-4">
              <Search className="w-4 h-4 text-cyan-400 flex-shrink-0" />
              <input
                ref={inputRef}
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Search commands, pages, and instant presets..."
                className="flex-1 bg-transparent py-3.5 text-sm text-white placeholder-slate-500 focus:outline-none"
                aria-label="Command search"
              />
              <span className="hidden sm:flex items-center gap-1 text-[10px] font-mono text-slate-500 border border-slate-700 rounded px-1.5 py-0.5">
                ESC
              </span>
            </div>

            {/* Results */}
            <div className="max-h-[52vh] overflow-y-auto py-2">
              {filtered.length === 0 ? (
                <div className="flex flex-col items-center justify-center gap-1 py-10 text-slate-500">
                  <Trash2 className="w-5 h-5" />
                  <span className="text-xs">No commands match “{query}”</span>
                </div>
              ) : (
                filtered.map((command, index) => {
                  const showGroupHeader = command.group !== lastGroup;
                  lastGroup = command.group;
                  const Icon = command.icon;
                  const active = index === selectedIndex;
                  return (
                    <React.Fragment key={command.id}>
                      {showGroupHeader && (
                        <div className="px-4 pt-3 pb-1 text-[9px] uppercase tracking-widest font-bold text-slate-500">
                          {command.group}
                        </div>
                      )}
                      <button
                        type="button"
                        onMouseEnter={() => setSelectedIndex(index)}
                        onClick={command.run}
                        className={`w-full flex items-center gap-3 px-4 py-2.5 text-left transition ${
                          active ? "bg-cyan-500/10" : "hover:bg-slate-800/60"
                        }`}
                      >
                        <span
                          className={`w-7 h-7 rounded-lg border flex items-center justify-center flex-shrink-0 ${
                            active
                              ? "border-cyan-500/40 bg-cyan-500/15 text-cyan-300"
                              : "border-slate-800 bg-slate-900 text-slate-400"
                          }`}
                        >
                          <Icon className="w-3.5 h-3.5" />
                        </span>
                        <span className="min-w-0 flex-1">
                          <span className="block text-xs font-semibold text-white truncate">
                            {command.label}
                          </span>
                          <span className="block text-[10px] text-slate-400 truncate">
                            {command.hint}
                          </span>
                        </span>
                        {active && (
                          <CornerDownLeft className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />
                        )}
                      </button>
                    </React.Fragment>
                  );
                })
              )}
            </div>

            {/* Footer */}
            <div className="flex items-center justify-between border-t border-slate-800 px-4 py-2.5 text-[10px] font-mono text-slate-500 bg-[#060b14]">
              <span className="flex items-center gap-1.5">
                <Command className="w-3 h-3" />K
                <span className="text-slate-600">to toggle</span>
              </span>
              <span className="flex items-center gap-3">
                <span>↑↓ navigate</span>
                <span>↵ select</span>
              </span>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
