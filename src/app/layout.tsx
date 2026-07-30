import type { Metadata } from "next";
import "./globals.css";
import LenisProvider from "@/components/providers/LenisProvider";
import Navbar from "@/components/layout/Navbar";
import Preloader from "@/components/preloader/Preloader";
import ShaderBackground from "@/components/webgl/ShaderBackground";

export const metadata: Metadata = {
  title: "GuardAI | Next-Gen Cybersecurity & Threat Intelligence",
  description: "Advanced cybersecurity platform with real-time threat monitoring, deep URL scanning, and global threat visualization.",
  keywords: ["cybersecurity", "threat intelligence", "phishing detection", "security scanning"],
};

import NextAuthSessionProvider from "@/components/providers/SessionProvider";

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body
        className="min-h-screen bg-[#050505] text-white antialiased"
      >
        <NextAuthSessionProvider>
          <LenisProvider>
            <Preloader />
            <ShaderBackground />
            <Navbar />
            <main className="relative z-10">{children}</main>
          </LenisProvider>
        </NextAuthSessionProvider>
      </body>
    </html>
  );
}
