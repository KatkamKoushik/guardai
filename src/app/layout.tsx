import type { Metadata } from "next";
import { Space_Grotesk, Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import LenisProvider from "@/components/providers/LenisProvider";
import Navbar from "@/components/layout/Navbar";
import Preloader from "@/components/preloader/Preloader";
import ShaderBackground from "@/components/webgl/ShaderBackground";

const spaceGrotesk = Space_Grotesk({
  variable: "--font-heading",
  subsets: ["latin"],
  weight: ["300", "400", "500", "600", "700"],
});

const inter = Inter({
  variable: "--font-body",
  subsets: ["latin"],
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});

export const metadata: Metadata = {
  title: "GuardAI | Next-Gen Cybersecurity & Threat Intelligence",
  description: "Advanced cybersecurity platform with real-time threat monitoring, deep URL scanning, and global threat visualization.",
  keywords: ["cybersecurity", "threat intelligence", "phishing detection", "security scanning"],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${spaceGrotesk.variable} ${inter.variable} ${jetbrainsMono.variable} min-h-screen bg-[#050505] text-white antialiased`}
      >
        <LenisProvider>
          <Preloader />
          <ShaderBackground />
          <Navbar />
          <main className="relative z-10">{children}</main>
        </LenisProvider>
      </body>
    </html>
  );
}
