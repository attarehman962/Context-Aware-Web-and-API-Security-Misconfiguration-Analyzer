import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

import { MockModeBanner } from "@/components/api-mode";
import { MockProvider } from "@/components/mock-provider";
import { PageContainer } from "@/components/page-container";
import { QueryProvider } from "@/components/query-provider";
import { SiteFooter } from "@/components/site-footer";
import { SiteHeader } from "@/components/site-header";
import { ThemeProvider } from "@/components/theme-provider";

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
        <ThemeProvider>
          <a
            href="#main"
            className="sr-only z-50 rounded-md bg-background px-3 py-2 focus:not-sr-only focus:absolute focus:top-2 focus:left-2"
          >
            Skip to content
          </a>
          <MockModeBanner />
          <SiteHeader />
          <PageContainer>
            <MockProvider>
              <QueryProvider>{children}</QueryProvider>
            </MockProvider>
          </PageContainer>
          <SiteFooter />
        </ThemeProvider>
      </body>
    </html>
  );
}
