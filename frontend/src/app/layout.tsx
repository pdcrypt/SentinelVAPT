import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SentinelVAPT",
  description: "Authorized web application security assessment and reporting",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
