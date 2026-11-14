"use client";

import { motion, useReducedMotion } from "motion/react";
import { SECURITY_PRESETS, type SecurityPreset } from "@/lib/demo-presets";

export function SecurityPresets({ onSelect, selected, disabled = false }: {
  onSelect: (preset: SecurityPreset) => void;
  selected?: string | null;
  disabled?: boolean;
}) {
  const reducedMotion = useReducedMotion();
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-2" aria-label="One-click security examples">
        {SECURITY_PRESETS.map((preset) => (
          <motion.button
            key={preset.id}
            type="button"
            tabIndex={0}
            aria-pressed={selected === preset.id}
            disabled={disabled}
            onClick={() => onSelect(preset)}
            whileTap={reducedMotion ? undefined : { scale: 0.97 }}
            transition={{ type: "spring", stiffness: 400, damping: 30 }}
            className={`min-h-10 rounded-full border px-3 py-2 text-[11px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300 disabled:cursor-wait disabled:opacity-50 ${selected === preset.id ? "border-cyan-200/35 bg-cyan-300/[0.12] text-cyan-100" : "border-white/[0.12] bg-white/[0.04] text-slate-300 hover:border-white/25 hover:bg-white/[0.08]"}`}
          >
            {preset.label}
          </motion.button>
        ))}
      </div>
      <p className="text-[10px] text-slate-500">One click to scan. Fabricated examples, never real credentials.</p>
    </div>
  );
}
