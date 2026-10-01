import type { Metadata } from 'next';
import React from 'react';
import { ClerkProvider } from '@clerk/nextjs';
import './globals.css';

export const metadata: Metadata = {
  title: 'Project Aegis — Cyber Defense Platform',
  description:
    'SafeLink SSRF-safe URL inspection and GitShield secret scanning with automated remediation.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <ClerkProvider
      publishableKey={
        process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY ||
        'pk_test_Y2xlcmsuZXhhbXBsZS5jb20k'
      }
    >
      <html lang="en">
        <body className="bg-[#030712] text-slate-100 antialiased">{children}</body>
      </html>
    </ClerkProvider>
  );
}
