"use client";

import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { X, Nfc, Lock, CircleCheck, Crown, AlertTriangle } from 'lucide-react';

type CheckoutStage = 'form' | 'processing' | 'success' | 'declined';

interface MockCheckoutModalProps {
  isOpen: boolean;
  onClose: () => void;
  /** Fired exactly once when a simulated payment succeeds. */
  onSuccess: () => void;
}

const PRESETS = [
  { label: '4242 Approved', number: '4242 4242 4242 4242' },
  { label: '0002 Decline', number: '4000 0000 0000 0002' },
] as const;

function formatCardNumber(value: string): string {
  const digits = value.replace(/\D/g, '').slice(0, 16);
  return digits.replace(/(\d{4})(?=\d)/g, '$1 ');
}

function formatExpiry(value: string): string {
  const digits = value.replace(/\D/g, '').slice(0, 4);
  if (digits.length <= 2) return digits;
  return `${digits.slice(0, 2)}/${digits.slice(2)}`;
}

export function MockCheckoutModal({ isOpen, onClose, onSuccess }: MockCheckoutModalProps) {
  const [stage, setStage] = useState<CheckoutStage>('form');
  const [flipped, setFlipped] = useState(false);
  const [cvcFocused, setCvcFocused] = useState(false);

  const [cardholder, setCardholder] = useState('AEGIS OPERATOR');
  const [cardNumber, setCardNumber] = useState('4242 4242 4242 4242');
  const [expiry, setExpiry] = useState('12/29');
  const [cvc, setCvc] = useState('');

  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Reset to a clean form whenever the modal opens.
  useEffect(() => {
    if (isOpen) {
      setStage('form');
      setFlipped(false);
      setCvcFocused(false);
      setCardholder('AEGIS OPERATOR');
      setCardNumber('4242 4242 4242 4242');
      setExpiry('12/29');
      setCvc('');
    }
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [isOpen]);

  const isDeclinePreset = cardNumber.replace(/\s/g, '').endsWith('0002');
  // Card flips when CVC is focused OR the user clicks the card.
  const showBack = cvcFocused || flipped;

  const handlePay = () => {
    if (stage !== 'form') return;
    setStage('processing');
    // Simulated gateway latency (mock, offline).
    timerRef.current = setTimeout(() => {
      if (isDeclinePreset) {
        setStage('declined');
      } else {
        setStage('success');
        onSuccess();
      }
    }, 1900);
  };

  const closeAndReset = () => {
    if (timerRef.current) clearTimeout(timerRef.current);
    onClose();
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          className="fixed inset-0 z-[60] flex items-center justify-center p-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.2 }}
        >
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-black/80 backdrop-blur-sm"
            onClick={stage === 'processing' ? undefined : closeAndReset}
          />

          {/* Modal */}
          <motion.div
            className="relative w-full max-w-md rounded-2xl border border-slate-700 bg-[#090f20] p-6 shadow-2xl"
            initial={{ opacity: 0, y: 24, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 16, scale: 0.97 }}
            transition={{ type: 'spring', stiffness: 320, damping: 28 }}
          >
            {/* Header */}
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Crown className="w-4 h-4 text-amber-400" />
                Upgrade to Enterprise — $49/mo
              </h3>
              <button
                onClick={closeAndReset}
                disabled={stage === 'processing'}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition disabled:opacity-40"
                aria-label="Close checkout"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex flex-col items-center">
              {/* ============================================================
                  3D VIRTUAL CARD (perspective flip on click / CVC focus)
              ============================================================ */}
              <div
                className="w-full max-w-[340px] mb-5"
                style={{ perspective: '1200px' }}
                onClick={() => stage === 'form' && setFlipped((f) => !f)}
              >
                <motion.div
                  className="relative w-full cursor-pointer"
                  style={{ transformStyle: 'preserve-3d', aspectRatio: '1.586 / 1' }}
                  animate={{ rotateY: showBack ? 180 : 0 }}
                  transition={{ type: 'spring', stiffness: 260, damping: 26 }}
                >
                  {/* ---- FRONT ---- */}
                  <div
                    className="absolute inset-0 rounded-2xl overflow-hidden border border-cyan-500/30"
                    style={{
                      backfaceVisibility: 'hidden',
                      WebkitBackfaceVisibility: 'hidden',
                      background:
                        'linear-gradient(135deg, #0b1224 0%, #101a33 45%, #0b1224 100%)',
                      boxShadow: '0 10px 40px rgba(34, 211, 238, 0.15)',
                    }}
                  >
                    {/* neon edge */}
                    <div className="absolute inset-0 rounded-2xl pointer-events-none opacity-60"
                      style={{
                        background:
                          'radial-gradient(240px circle at 85% 15%, rgba(34,211,238,0.18), transparent 65%)',
                      }}
                    />
                    <div className="relative h-full p-4 flex flex-col justify-between">
                      <div className="flex items-start justify-between">
                        {/* EMV chip */}
                        <div
                          className="w-9 h-7 rounded-[5px]"
                          style={{
                            background:
                              'linear-gradient(135deg, #fde68a 0%, #d4a017 45%, #fde68a 100%)',
                          }}
                        >
                          <div className="w-full h-full opacity-60"
                            style={{
                              background:
                                'repeating-linear-gradient(0deg, transparent, transparent 5px, rgba(0,0,0,0.45) 5px, rgba(0,0,0,0.45) 6px)',
                            }}
                          />
                        </div>
                        <Nfc className="w-5 h-5 text-cyan-300/80" />
                      </div>

                      {/* Card number */}
                      <div className="font-mono text-lg tracking-[0.18em] text-slate-100">
                        {cardNumber || '•••• •••• •••• ••••'}
                      </div>

                      <div className="flex items-end justify-between">
                        <div className="flex gap-6">
                          <div>
                            <div className="text-[8px] uppercase tracking-widest text-slate-500">
                              Card Holder
                            </div>
                            <div className="text-xs font-semibold text-slate-200 uppercase tracking-wide">
                              {cardholder || '—'}
                            </div>
                          </div>
                          <div>
                            <div className="text-[8px] uppercase tracking-widest text-slate-500">
                              Expires
                            </div>
                            <div className="text-xs font-semibold text-slate-200">{expiry || '—'}</div>
                          </div>
                        </div>
                        {/* Visa wordmark */}
                        <span className="italic font-extrabold text-base text-white tracking-wide">
                          VISA
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* ---- BACK ---- */}
                  <div
                    className="absolute inset-0 rounded-2xl overflow-hidden border border-cyan-500/30"
                    style={{
                      backfaceVisibility: 'hidden',
                      WebkitBackfaceVisibility: 'hidden',
                      transform: 'rotateY(180deg)',
                      background:
                        'linear-gradient(135deg, #0b1224 0%, #101a33 45%, #0b1224 100%)',
                      boxShadow: '0 10px 40px rgba(34, 211, 238, 0.15)',
                    }}
                  >
                    {/* Magnetic strip */}
                    <div className="mt-4 h-10 bg-black/85 border-y border-slate-900" />

                    <div className="p-4 flex flex-col gap-3">
                      {/* Signature panel + dynamic CVV readout */}
                      <div className="flex items-stretch gap-2">
                        <div className="flex-1 h-9 rounded bg-slate-200 flex items-center px-3">
                          <span className="font-serif text-slate-600 text-sm italic select-none">
                            {cardholder || 'signature'}
                          </span>
                        </div>
                        <div className="w-16 h-9 rounded bg-white border border-slate-300 flex items-center justify-center">
                          <span className="font-mono text-sm font-bold text-slate-900 tracking-widest">
                            {cvcFocused ? cvc.padEnd(3, '•').slice(0, 4) : '•••'}
                          </span>
                        </div>
                      </div>

                      <div className="text-[9px] text-slate-500 leading-snug">
                        The card verification value is the 3-digit code on the back. Mock data only —
                        no real transaction occurs.
                      </div>

                      <div className="flex items-center justify-end gap-1.5 text-slate-500">
                        <Lock className="w-3 h-3" />
                        <span className="text-[9px] uppercase tracking-widest">Mock Secure</span>
                      </div>
                    </div>
                  </div>
                </motion.div>
              </div>

              {/* ============================================================
                  STAGE CONTENT: form / processing / success / declined
              ============================================================ */}
              <div className="w-full min-h-[276px]">
                <AnimatePresence mode="wait">
                  {stage === 'form' && (
                    <motion.div
                      key="form"
                      initial={{ opacity: 0, x: 40 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, x: -60 }}
                      transition={{ duration: 0.28, ease: 'easeOut' }}
                      className="space-y-3"
                    >
                      {/* Presets */}
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] uppercase font-bold text-slate-400">
                          Test Preset:
                        </span>
                        {PRESETS.map((preset) => (
                          <button
                            key={preset.label}
                            onClick={() => setCardNumber(preset.number)}
                            className={`text-[11px] font-mono px-2 py-0.5 rounded border transition ${
                              cardNumber === preset.number
                                ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                                : 'bg-slate-900 text-slate-400 border-slate-800 hover:bg-slate-800'
                            }`}
                          >
                            {preset.label}
                          </button>
                        ))}
                      </div>

                      {/* Name */}
                      <div>
                        <label className="text-[10px] uppercase tracking-wider text-slate-400 block mb-1">
                          Cardholder Name
                        </label>
                        <input
                          type="text"
                          value={cardholder}
                          onChange={(e) => setCardholder(e.target.value.toUpperCase())}
                          className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-xl text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                        />
                      </div>

                      {/* Number */}
                      <div>
                        <label className="text-[10px] uppercase tracking-wider text-slate-400 block mb-1">
                          Card Number
                        </label>
                        <input
                          type="text"
                          inputMode="numeric"
                          value={cardNumber}
                          onChange={(e) => setCardNumber(formatCardNumber(e.target.value))}
                          className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-xl text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                        />
                      </div>

                      {/* Expiry + CVC */}
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="text-[10px] uppercase tracking-wider text-slate-400 block mb-1">
                            Expiry
                          </label>
                          <input
                            type="text"
                            inputMode="numeric"
                            placeholder="MM/YY"
                            value={expiry}
                            onChange={(e) => setExpiry(formatExpiry(e.target.value))}
                            className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-xl text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                          />
                        </div>
                        <div>
                          <label className="text-[10px] uppercase tracking-wider text-slate-400 block mb-1">
                            CVC
                          </label>
                          <input
                            type="text"
                            inputMode="numeric"
                            placeholder="•••"
                            value={cvc}
                            onChange={(e) => setCvc(e.target.value.replace(/\D/g, '').slice(0, 4))}
                            onFocus={() => setCvcFocused(true)}
                            onBlur={() => setCvcFocused(false)}
                            className="w-full bg-slate-950 border border-slate-700 px-3 py-2 rounded-xl text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
                          />
                        </div>
                      </div>

                      {/* Pay */}
                      <button
                        onClick={handlePay}
                        className="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 text-slate-950 font-extrabold text-sm transition shadow-lg shadow-cyan-500/20 flex items-center justify-center gap-2"
                      >
                        <Lock className="w-4 h-4" />
                        Pay $49/mo
                      </button>

                      <p className="text-[10px] text-slate-500 text-center">
                        Mock checkout — no funds move. Pick the 0002 preset to simulate a decline.
                      </p>
                    </motion.div>
                  )}

                  {stage === 'processing' && (
                    <motion.div
                      key="processing"
                      initial={{ opacity: 0, y: 12 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -12 }}
                      transition={{ duration: 0.25 }}
                      className="flex flex-col items-center justify-center gap-4 pt-6"
                    >
                      <motion.div
                        className="w-10 h-10 rounded-full border-2 border-cyan-400/30 border-t-cyan-400"
                        animate={{ rotate: 360 }}
                        transition={{ repeat: Infinity, duration: 0.9, ease: 'linear' }}
                      />
                      <div className="text-sm font-semibold text-cyan-300 font-mono tracking-wide">
                        Processing Secure Transaction...
                      </div>
                      <div className="text-[11px] text-slate-500 flex items-center gap-1.5">
                        <Lock className="w-3 h-3" /> Encrypting card details via mock gateway
                      </div>
                    </motion.div>
                  )}

                  {stage === 'success' && (
                    <motion.div
                      key="success"
                      initial={{ opacity: 0, scale: 0.9 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ type: 'spring', stiffness: 300, damping: 22 }}
                      className="flex flex-col items-center justify-center gap-3 pt-4 text-center"
                    >
                      <motion.svg
                        viewBox="0 0 52 52"
                        className="w-14 h-14"
                        initial={{ scale: 0 }}
                        animate={{ scale: 1 }}
                        transition={{ type: 'spring', stiffness: 340, damping: 18 }}
                      >
                        <motion.circle
                          cx="26"
                          cy="26"
                          r="24"
                          fill="none"
                          stroke="#34d399"
                          strokeWidth="2.5"
                          initial={{ pathLength: 0 }}
                          animate={{ pathLength: 1 }}
                          transition={{ duration: 0.45, ease: 'easeOut' }}
                        />
                        <motion.path
                          d="M15 27 L23 34 L37 19"
                          fill="none"
                          stroke="#34d399"
                          strokeWidth="3.5"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          initial={{ pathLength: 0 }}
                          animate={{ pathLength: 1 }}
                          transition={{ duration: 0.3, delay: 0.4, ease: 'easeOut' }}
                        />
                      </motion.svg>
                      <div className="text-lg font-extrabold text-emerald-400">
                        Payment Successful!
                      </div>
                      <div className="text-xs text-slate-400">
                        Enterprise Tier unlocked — quota is now{' '}
                        <span className="font-mono text-cyan-300">Unlimited (&infin; / &infin;)</span>
                      </div>
                      <button
                        onClick={closeAndReset}
                        className="mt-2 px-6 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold transition"
                      >
                        Done
                      </button>
                    </motion.div>
                  )}

                  {stage === 'declined' && (
                    <motion.div
                      key="declined"
                      initial={{ opacity: 0, scale: 0.9 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ type: 'spring', stiffness: 300, damping: 22 }}
                      className="flex flex-col items-center justify-center gap-3 pt-4 text-center"
                    >
                      <div className="w-14 h-14 rounded-full bg-rose-950/50 border border-rose-500/40 flex items-center justify-center">
                        <AlertTriangle className="w-7 h-7 text-rose-400" />
                      </div>
                      <div className="text-lg font-extrabold text-rose-400">Payment Declined</div>
                      <div className="text-xs text-slate-400">
                        The mock issuer rejected this card (0002 — insufficient funds).
                      </div>
                      <button
                        onClick={() => setStage('form')}
                        className="mt-2 px-6 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold transition"
                      >
                        Try Another Card
                      </button>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
