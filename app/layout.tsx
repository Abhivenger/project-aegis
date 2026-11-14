import type { Metadata } from 'next';
import React from 'react';
import { ClerkProvider } from '@clerk/nextjs';
import { AppAuthProvider } from '@/lib/auth/app-auth';
import { getClerkPublishableKey } from '@/lib/auth/clerk-config';
import { Toaster } from 'sonner';
import './globals.css';

export const metadata: Metadata = {
  title: 'Aegis Cloud — Ship faster. Leak nothing.',
  description:
    'Zero-trust secret defense for modern engineering teams: entropy-aware scanning, GitHub PR protection, and an encrypted Web Vault.',
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
        <body className="bg-[#07090E] text-slate-100 antialiased">
          {children}
          <Toaster
            position="bottom-right"
            theme="dark"
            richColors
            closeButton
            toastOptions={{
              className: 'border-white/[0.10] text-slate-100',
              style: {
                background: '#101722',
                borderColor: 'rgba(255,255,255,0.10)',
              },
            }}
          />
        </body>
      </html>
    </AppAuthProvider>
  );

  if (!publishableKey) {
    return app;
  }

  return <ClerkProvider publishableKey={publishableKey}>{app}</ClerkProvider>;
}
