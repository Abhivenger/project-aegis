import type { Metadata } from 'next';
import React from 'react';
import { ClerkProvider } from '@clerk/nextjs';
import { AppAuthProvider } from '@/lib/auth/app-auth';
import { getClerkPublishableKey } from '@/lib/auth/clerk-config';
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
  // Clerk is only mounted when a real, non-placeholder publishable key exists.
  // With the default/example key this is null, so the dashboard renders
  // immediately in local mode with a fallback operator identity and no Clerk
  // client handshake or redirect to clerk.example.com.
  const publishableKey = getClerkPublishableKey();

  const app = (
    <AppAuthProvider clerkEnabled={publishableKey !== null}>
      <html lang="en">
        <body className="bg-[#030712] text-slate-100 antialiased">{children}</body>
      </html>
    </AppAuthProvider>
  );

  if (!publishableKey) {
    return app;
  }

  return <ClerkProvider publishableKey={publishableKey}>{app}</ClerkProvider>;
}
