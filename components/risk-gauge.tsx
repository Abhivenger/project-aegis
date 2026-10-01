"use client";

import React, { useEffect, useState } from 'react';

interface RiskGaugeProps {
  score: number; // 0 to 100
  verdict?: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS';
  size?: number;
  label?: string;
}

export function RiskGauge({
  score,
  verdict,
  size = 180,
  label = "Threat Score",
}: RiskGaugeProps) {
  const [animatedScore, setAnimatedScore] = useState(0);

  // Smooth count-up animation on score changes
  useEffect(() => {
    const timer = setTimeout(() => {
      setAnimatedScore(Math.min(100, Math.max(0, score)));
    }, 50);
    return () => clearTimeout(timer);
  }, [score]);

  // Derived verdict if not provided explicitly
  const resolvedVerdict =
    verdict ||
    (animatedScore >= 70 ? 'DANGEROUS' : animatedScore >= 30 ? 'SUSPICIOUS' : 'SAFE');

  // Gauge color mapping
  const getColor = () => {
    if (resolvedVerdict === 'DANGEROUS' || animatedScore >= 70) {
      return {
        stroke: '#f43f5e', // rose-500
        text: 'text-rose-400',
        bgGlow: 'rgba(244, 63, 94, 0.15)',
        badgeBg: 'bg-rose-950/60 border-rose-500/40 text-rose-300',
      };
    }
    if (resolvedVerdict === 'SUSPICIOUS' || animatedScore >= 30) {
      return {
        stroke: '#f59e0b', // amber-500
        text: 'text-amber-400',
        bgGlow: 'rgba(245, 158, 11, 0.15)',
        badgeBg: 'bg-amber-950/60 border-amber-500/40 text-amber-300',
      };
    }
    return {
      stroke: '#10b981', // emerald-500
      text: 'text-emerald-400',
      bgGlow: 'rgba(16, 185, 129, 0.15)',
      badgeBg: 'bg-emerald-950/60 border-emerald-500/40 text-emerald-300',
    };
  };

  const colors = getColor();

  // SVG Geometry
  const strokeWidth = 12;
  const radius = (size - strokeWidth * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (animatedScore / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center select-none">
      <div className="relative" style={{ width: size, height: size }}>
        {/* Glow backdrop */}
        <div
          className="absolute inset-0 rounded-full blur-xl pointer-events-none transition-all duration-700"
          style={{ backgroundColor: colors.bgGlow }}
        />

        <svg
          width={size}
          height={size}
          className="transform -rotate-90 origin-center"
        >
          {/* Background Track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            fill="transparent"
            strokeLinecap="round"
          />
          {/* Animated Progress Arc */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={colors.stroke}
            strokeWidth={strokeWidth}
            fill="transparent"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center Readout */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`font-mono text-4xl font-extrabold tracking-tight ${colors.text}`}>
            {animatedScore}
          </span>
          <span className="text-[10px] uppercase font-semibold text-slate-400 tracking-wider">
            {label}
          </span>
        </div>
      </div>

      {/* Verdict Pill */}
      <div
        className={`mt-3 px-3 py-1 rounded-full text-xs font-bold font-mono uppercase tracking-wider border shadow-sm ${colors.badgeBg}`}
      >
        {resolvedVerdict}
      </div>
    </div>
  );
}
