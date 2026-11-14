"use client";

import React, { FormEvent, useMemo, useState } from "react";
import { motion } from "motion/react";
import { toast } from "sonner";
import {
  Activity,
  Check,
  Clipboard,
  Copy,
  Clock3,
  Eye,
  EyeOff,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  Plus,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  X,
} from "lucide-react";
import { calculateShannonEntropy } from "@/lib/scanners/entropy";

interface VaultSecret {
  id: string;
  name: string;
  project: string;
  value: string;
  reference: string;
  entropy: number;
  updated: string;
  rotatedDaysAgo: number;
  rotationPolicyDays: number;
}

const INITIAL_SECRETS: VaultSecret[] = [
  {
    id: "stripe",
    name: "STRIPE_SECRET_KEY",
    project: "checkout-api",
    value: "sk_live_51M0x9KLa8xX209qZ1abcdef9876543210zyxwvu", // aegis-ignore: fabricated vault demo key
    reference: "AEGIS_STRIPE_SECRET_KEY",
    entropy: 4.9,
    updated: "12 min ago",
    rotatedDaysAgo: 12,
    rotationPolicyDays: 90,
  },
  {
    id: "database",
    name: "DATABASE_URL",
    project: "aegis-console",
    value: "postgres://vault_user:Q4s9zK2pL8vR@db.internal:5432/aegis",
    reference: "AEGIS_DATABASE_URL",
    entropy: 4.2,
    updated: "Yesterday",
    rotatedDaysAgo: 26,
    rotationPolicyDays: 30,
  },
  {
    id: "github",
    name: "GITHUB_APP_PRIVATE_KEY",
    project: "platform-infra",
    value: "ghs_7f9b2c4d8a1e6f3b9c5d2a7e4f8b1c6d", // aegis-ignore: fabricated vault demo token
    reference: "AEGIS_GITHUB_APP_PRIVATE_KEY",
    entropy: 4.6,
    updated: "3 days ago",
    rotatedDaysAgo: 3,
    rotationPolicyDays: 90,
  },
];

const spring = { type: "spring" as const, stiffness: 350, damping: 25 };
const springFast = { type: "spring" as const, stiffness: 400, damping: 30 };

function maskedValue(value: string): string {
  return `${value.slice(0, 5)}${"•".repeat(Math.min(24, Math.max(12, value.length - 9)))}${value.slice(-4)}`;
}

function entropyTone(entropy: number): string {
  return entropy >= 4.5 ? "text-rose-300 bg-rose-300/[0.08] border-rose-300/20" : "text-amber-200 bg-amber-300/[0.08] border-amber-300/20";
}

function rotationState(secret: VaultSecret): { label: string; tone: string } {
  const remaining = secret.rotationPolicyDays - secret.rotatedDaysAgo;
  if (remaining <= 0) {
    return { label: "Rotate now", tone: "text-rose-300 bg-rose-300/[0.08] border-rose-300/20" };
  }
  if (remaining <= 7) {
    return { label: `Due in ${remaining}d`, tone: "text-amber-200 bg-amber-300/[0.08] border-amber-300/20" };
  }
  return { label: `Rotates in ${remaining}d`, tone: "text-emerald-300 bg-emerald-300/[0.08] border-emerald-300/20" };
}

function SecretCard({ secret, onCopy }: { secret: VaultSecret; onCopy: (secret: VaultSecret) => void }) {
  const [revealed, setRevealed] = useState(false);
  const rotation = rotationState(secret);

  return (
    <motion.article initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={spring} className="group rounded-[20px] border border-white/[0.09] bg-[#0f1420]/80 p-4 transition-colors hover:border-cyan-300/20">
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-cyan-300/15 bg-cyan-300/[0.07] text-cyan-200"><KeyRound className="h-4 w-4" /></div>
          <div className="min-w-0"><h3 className="truncate font-mono text-xs font-semibold text-white">{secret.name}</h3><p className="mt-1 flex items-center gap-1.5 text-[10px] text-slate-500"><span className="h-1.5 w-1.5 rounded-full bg-emerald-300" /> {secret.project}</p></div>
        </div>
        <span className={`shrink-0 rounded-full border px-2 py-1 font-mono text-[9px] ${entropyTone(secret.entropy)}`}>H {secret.entropy.toFixed(2)}</span>
      </div>
      <div className="mt-5 rounded-xl border border-white/[0.07] bg-[#07090e]/80 p-3">
        <div className="flex min-h-8 items-center justify-between gap-3"><code className={`min-w-0 break-all font-mono text-[11px] ${revealed ? "text-cyan-100" : "text-slate-500"}`}>{revealed ? secret.value : maskedValue(secret.value)}</code><motion.button type="button" whileTap={{ scale: 0.98 }} transition={springFast} onClick={() => setRevealed((value) => !value)} className="shrink-0 rounded-lg border border-white/[0.10] p-1.5 text-slate-400 transition hover:border-cyan-300/25 hover:text-cyan-200" aria-label={revealed ? `Hide ${secret.name}` : `Reveal ${secret.name}`}>{revealed ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}</motion.button></div>
      </div>
      <div className="mt-4 flex items-center justify-between gap-3"><div className="min-w-0"><div className="truncate font-mono text-[10px] text-slate-500">ref://{secret.reference}</div><div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-[10px] text-slate-600"><span className="flex items-center gap-1"><Clock3 className="h-3 w-3" /> synced {secret.updated}</span><span className={`rounded-full border px-1.5 py-0.5 font-mono text-[9px] ${rotation.tone}`}>{rotation.label}</span></div></div><motion.button type="button" whileHover={{ scale: 1.01 }} whileTap={{ scale: 0.98 }} transition={springFast} onClick={() => onCopy(secret)} className="flex shrink-0 items-center gap-1.5 rounded-lg border border-white/[0.10] bg-white/[0.03] px-2.5 py-1.5 text-[10px] font-medium text-slate-300 transition hover:border-cyan-300/25 hover:text-cyan-100"><Clipboard className="h-3 w-3" /> Copy ref</motion.button></div>
    </motion.article>
  );
}

export default function VaultWorkspace() {
  const [secrets, setSecrets] = useState(INITIAL_SECRETS);
  const [isAdding, setIsAdding] = useState(false);
  const [name, setName] = useState("");
  const [value, setValue] = useState("");

  const averageEntropy = useMemo(() => secrets.reduce((sum, secret) => sum + secret.entropy, 0) / Math.max(secrets.length, 1), [secrets]);
  const rotationHealthy = useMemo(
    () => secrets.filter((secret) => secret.rotationPolicyDays - secret.rotatedDaysAgo > 7).length,
    [secrets]
  );

  const copyReference = async (secret: VaultSecret) => {
    try {
      await navigator.clipboard.writeText(`ref://${secret.reference}`);
      toast.success("Safe reference copied", { description: `${secret.name} stays encrypted in the Vault.` });
    } catch {
      toast.error("Clipboard unavailable", { description: "Copy the reference from the card instead." });
    }
  };

  const addSecret = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmedName = name.trim().toUpperCase().replace(/[^A-Z0-9_]+/g, "_");
    const trimmedValue = value.trim();
    if (!trimmedName || !trimmedValue) return;

    const secret: VaultSecret = {
      id: `${trimmedName}-${Date.now()}`,
      name: trimmedName,
      project: "new workspace secret",
      value: trimmedValue,
      reference: `AEGIS_${trimmedName}`,
      entropy: calculateShannonEntropy(trimmedValue),
      updated: "just now",
      rotatedDaysAgo: 0,
      rotationPolicyDays: 90,
    };
    setSecrets((current) => [secret, ...current]);
    setName("");
    setValue("");
    setIsAdding(false);
    toast.success("Secret encrypted and synced to cloud", { description: `${trimmedName} is ready for safe references.` });
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
        <div><div className="mb-2 flex items-center gap-2"><LockKeyhole className="h-5 w-5 text-cyan-200" /><span className="font-mono text-[10px] uppercase tracking-[0.18em] text-cyan-200/80">Encrypted workspace</span></div><h1 className="text-2xl font-semibold tracking-[-0.04em] text-white sm:text-3xl">Web Vault</h1><p className="mt-2 max-w-xl text-xs leading-6 text-slate-400 sm:text-sm">One calm place for the credentials your team needs. Values stay masked by default and references are safe to share across codebases.</p></div>
        <motion.button type="button" whileHover={{ scale: 1.01 }} whileTap={{ scale: 0.98 }} transition={springFast} onClick={() => setIsAdding(true)} className="flex items-center justify-center gap-2 rounded-xl border border-cyan-200/25 bg-cyan-300/[0.12] px-4 py-2.5 text-xs font-semibold text-cyan-100 transition hover:bg-cyan-300/[0.18]"><Plus className="h-4 w-4" /> Add secret</motion.button>
      </div>

      <div data-tour="vault-stats" className="grid gap-3 sm:grid-cols-3"><Stat icon={<KeyRound className="h-4 w-4" />} label="Vault entries" value={secrets.length.toString().padStart(2, "0")} detail="encrypted at rest" /><Stat icon={<Activity className="h-4 w-4" />} label="Average entropy" value={averageEntropy.toFixed(2)} detail="bits per character" /><Stat icon={<RefreshCw className="h-4 w-4" />} label="Rotation health" value={`${rotationHealthy}/${secrets.length}`} detail="inside policy window" tone="emerald" /></div>

      <div className="grid gap-4 xl:grid-cols-[1fr_280px]">
        <section data-tour="vault-secrets" className="space-y-3"><div className="flex items-center justify-between"><div><h2 className="text-sm font-semibold text-white">Your secrets</h2><p className="mt-1 text-[11px] text-slate-500">Masked until you explicitly reveal them.</p></div><span className="flex items-center gap-1.5 font-mono text-[10px] text-emerald-300"><span className="h-1.5 w-1.5 rounded-full bg-emerald-300" /> vault online</span></div><div className="grid gap-3 md:grid-cols-2">{secrets.map((secret) => <SecretCard key={secret.id} secret={secret} onCopy={copyReference} />)}</div></section>
        <aside className="h-fit rounded-[20px] border border-white/[0.09] bg-[#0f1420]/60 p-5"><div className="flex h-9 w-9 items-center justify-center rounded-xl border border-emerald-300/15 bg-emerald-300/[0.07] text-emerald-200"><ShieldCheck className="h-4 w-4" /></div><h2 className="mt-5 text-sm font-semibold text-white">Safe by default</h2><p className="mt-2 text-xs leading-5 text-slate-400">Aegis never places plaintext values in URLs, logs, or generated client bundles.</p><ul className="mt-5 space-y-3 text-[11px] text-slate-400"><li className="flex gap-2"><Fingerprint className="h-3.5 w-3.5 shrink-0 text-cyan-200" />Every value gets an entropy readout.</li><li className="flex gap-2"><Copy className="h-3.5 w-3.5 shrink-0 text-cyan-200" />Shareable references never reveal a secret.</li><li className="flex gap-2"><Sparkles className="h-3.5 w-3.5 shrink-0 text-cyan-200" />Rotate or patch from the same workspace.</li></ul></aside>
      </div>

      {isAdding && <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#07090e]/80 p-4 backdrop-blur-sm"><motion.form initial={{ opacity: 0, y: 10, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} transition={springFast} onSubmit={addSecret} className="w-full max-w-md rounded-[24px] border border-white/[0.12] bg-[#101722] p-5 shadow-[0_30px_90px_rgba(0,0,0,0.42)]"><div className="flex items-start justify-between"><div><div className="flex items-center gap-2 text-sm font-semibold text-white"><KeyRound className="h-4 w-4 text-cyan-200" /> Add encrypted secret</div><p className="mt-1 text-[11px] text-slate-500">The value is only used to create the encrypted workspace entry.</p></div><button type="button" onClick={() => setIsAdding(false)} className="rounded-lg p-1.5 text-slate-500 hover:text-white" aria-label="Close add secret dialog"><X className="h-4 w-4" /></button></div><label className="mt-6 block text-[10px] uppercase tracking-[0.14em] text-slate-500">Secret name<input value={name} onChange={(event) => setName(event.target.value)} placeholder="e.g. RESEND_API_KEY" className="mt-2 w-full rounded-xl border border-white/[0.10] bg-[#07090e] px-3 py-2.5 font-mono text-xs text-white outline-none transition focus:border-cyan-300/30" autoFocus /></label><label className="mt-4 block text-[10px] uppercase tracking-[0.14em] text-slate-500">Secret value<input value={value} onChange={(event) => setValue(event.target.value)} placeholder="Paste the value once" type="password" className="mt-2 w-full rounded-xl border border-white/[0.10] bg-[#07090e] px-3 py-2.5 font-mono text-xs text-white outline-none transition focus:border-cyan-300/30" /></label><button type="submit" disabled={!name.trim() || !value.trim()} className="mt-6 flex w-full items-center justify-center gap-2 rounded-xl border border-cyan-200/25 bg-cyan-300/[0.12] py-2.5 text-xs font-semibold text-cyan-100 transition hover:bg-cyan-300/[0.18] disabled:cursor-not-allowed disabled:opacity-50"><LockKeyhole className="h-3.5 w-3.5" /> Encrypt and save</button></motion.form></div>}
    </div>
  );
}

function Stat({ icon, label, value, detail, tone = "cyan" }: { icon: React.ReactNode; label: string; value: string; detail: string; tone?: "cyan" | "emerald" }) {
  return <div className="rounded-[18px] border border-white/[0.09] bg-[#0f1420]/60 p-4"><div className="flex items-center justify-between"><span className="text-[10px] uppercase tracking-[0.14em] text-slate-500">{label}</span><span className={tone === "emerald" ? "text-emerald-300" : "text-cyan-200"}>{icon}</span></div><div className={`mt-5 font-mono text-2xl tracking-[-0.06em] ${tone === "emerald" ? "text-emerald-200" : "text-white"}`}>{value}</div><div className="mt-1 text-[10px] text-slate-600">{detail}</div></div>;
}
