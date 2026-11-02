import type { Metadata } from "next";
import "./globals.css";
import LenisProvider from "@/components/providers/LenisProvider";
import Navbar from "@/components/layout/Navbar";
import Preloader from "@/components/preloader/Preloader";
import ShaderBackground from "@/components/webgl/ShaderBackground";
import NextAuthSessionProvider from "@/components/providers/SessionProvider";

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXTAUTH_URL || "https://guardai.security"),
  title: {
    default: "GuardAI | Next-Gen Threat Intelligence & Cybersecurity Platform",
    template: "%s | GuardAI",
  },
  description:
    "Production-grade cybersecurity intelligence platform with real-time telemetry, cryptographic TLS verification, SSRF defense, and multi-engine threat aggregation.",
  keywords: [
    "cybersecurity",
    "threat intelligence",
    "phishing detection",
    "SSRF defense",
    "TLS probe",
    "URL scanner",
    "security telemetry",
  ],
  authors: [{ name: "Katkam Koushik", url: "https://github.com/KatkamKoushik" }],
  creator: "Katkam Koushik",
  publisher: "GuardAI Security",
  robots: {
    index: true,
    follow: true,
  },
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://guardai.security",
    siteName: "GuardAI Threat Intelligence",
    title: "GuardAI | Next-Gen Cybersecurity & Threat Intelligence",
    description:
      "Real-time threat monitoring, cryptographic TLS validation, SSRF-safe deep URL scanning, and global threat visualization.",
    images: [
      {
        url: "/og-preview.png",
        width: 1200,
        height: 630,
        alt: "GuardAI Threat Intelligence Dashboard",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "GuardAI | Next-Gen Threat Intelligence",
    description:
      "Real-time threat monitoring, cryptographic TLS validation, and SSRF-safe deep URL scanning.",
    creator: "@guardai_sec",
    images: ["/og-preview.png"],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#050505] text-white antialiased">
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
