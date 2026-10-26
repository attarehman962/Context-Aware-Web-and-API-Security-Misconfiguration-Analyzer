import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

import { MockProvider } from "@/components/mock-provider";
import { QueryProvider } from "@/components/query-provider";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "CAWASMA",
  description: "Context-Aware Web & API Security Misconfiguration Analyzer",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    // next-themes sets the theme class on <html> before hydration.
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
      suppressHydrationWarning
    >
      <body className="flex min-h-full flex-col">
        <MockProvider>
          <QueryProvider>{children}</QueryProvider>
        </MockProvider>
      </body>
    </html>
  );
}
