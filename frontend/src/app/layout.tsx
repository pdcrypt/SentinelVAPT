import type { Metadata } from "next";
import { connection } from "next/server";
import type { ReactNode } from "react";

import "./globals.css";

export const metadata: Metadata = {
  title: { default: "SentinelVAPT", template: "%s · SentinelVAPT" },
  description: "Authorized web application security assessment and reporting",
  robots: { index: false, follow: false },
};

// The console itself, behind sign-in, is app/(console)/layout.tsx; sign-in
// and the password change are app/(auth).
export default async function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  // Every page renders per request: the CSP nonce is per request (ADR 0013)
  // and all data is live API state for the signed-in user.
  await connection();
  return (
    <html lang="en">
      <body>
        <a className="skip" href="#content">
          Skip to content
        </a>
        {children}
      </body>
    </html>
  );
}
