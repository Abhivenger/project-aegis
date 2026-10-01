"use client";

import React, { useRef, useState } from 'react';
import { motion, useMotionValue, useSpring, useMotionTemplate } from 'motion/react';

interface SpotlightCardProps {
  children: React.ReactNode;
  className?: string;
  /** Glow tint as any CSS color, e.g. '#22d3ee' or '#34d399' */
  glowColor?: string;
}

/**
 * SpotlightCard - Kokonut UI-style dark cyber card.
 * A radial neon glow trails the cursor (spring-smoothed) and lights up a 1px
 * border ring, with a soft matching wash inside the card.
 */
export function SpotlightCard({
  children,
  className = '',
  glowColor = '#22d3ee', // cyan-400 default
}: SpotlightCardProps) {
  const cardRef = useRef<HTMLDivElement>(null);
  const [isHovered, setIsHovered] = useState(false);

  // Raw pointer coordinates relative to the card, in pixels.
  const mouseX = useMotionValue(-9999);
  const mouseY = useMotionValue(-9999);

  // Smooth lag so the spotlight trails the cursor like a physical light.
  const springX = useSpring(mouseX, { stiffness: 260, damping: 26, mass: 0.6 });
  const springY = useSpring(mouseY, { stiffness: 260, damping: 26, mass: 0.6 });

  // Reactive CSS radial gradient centered on the pointer.
  const spotlightBackground = useMotionTemplate`radial-gradient(240px circle at ${springX}px ${springY}px, ${glowColor}, transparent 70%)`;

  const handleMouseMove = (event: React.MouseEvent<HTMLDivElement>) => {
    const rect = cardRef.current?.getBoundingClientRect();
    if (!rect) return;
    mouseX.set(event.clientX - rect.left);
    mouseY.set(event.clientY - rect.top);
  };

  const handleMouseLeave = () => {
    setIsHovered(false);
    // Park the light off-card so it fades instead of sticking to the last spot.
    mouseX.set(-9999);
    mouseY.set(-9999);
  };

  return (
    <div
      ref={cardRef}
      onMouseMove={handleMouseMove}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={handleMouseLeave}
      className={`relative overflow-hidden rounded-2xl bg-slate-800/60 p-px shadow-2xl ${className}`}
    >
      {/* BORDER GLOW LAYER: 1px ring of the card shows the moving gradient */}
      <motion.div
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{ background: spotlightBackground }}
        initial={{ opacity: 0 }}
        animate={{ opacity: isHovered ? 1 : 0 }}
        transition={{ duration: 0.3, ease: 'easeOut' }}
      />

      {/* DARK INTERIOR sits 1px inside, so only the ring of glow remains visible */}
      <div className="relative h-full rounded-[15px] bg-[#0a101f]">
        {/* FILL GLOW: soft interior wash under the pointer */}
        <motion.div
          aria-hidden
          className="pointer-events-none absolute inset-0"
          style={{ background: spotlightBackground, filter: 'blur(48px)' }}
          initial={{ opacity: 0 }}
          animate={{ opacity: isHovered ? 0.25 : 0 }}
          transition={{ duration: 0.4, ease: 'easeOut' }}
        />
        <div className="relative z-10 h-full">{children}</div>
      </div>
    </div>
  );
}
