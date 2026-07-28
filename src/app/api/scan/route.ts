import { NextResponse } from "next/server";

export async function POST(request: Request) {
  try {
    const { url } = await request.json();

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 });
    }

    // Validate URL format
    try {
      new URL(url);
    } catch {
      return NextResponse.json({ error: "Invalid URL format" }, { status: 400 });
    }

    // Simulate scan delay
    await new Promise((resolve) => setTimeout(resolve, 100));

    // Mock scan results (in production, integrate with VirusTotal + FastAPI ML model)
    const threatLevel = Math.random() > 0.7 ? "malicious" : Math.random() > 0.4 ? "suspicious" : "safe";
    const score = Math.floor(Math.random() * 100);

    const result = {
      url,
      threatLevel,
      score,
      scannedAt: new Date().toISOString(),
      details: {
        virusTotal: {
          status: Math.random() > 0.5 ? "clean" : "flagged",
          detections: Math.floor(Math.random() * 10),
          total: 60 + Math.floor(Math.random() * 10),
        },
        phishing: {
          probability: Math.floor(Math.random() * 100),
          indicators: [
            "Suspicious form input",
            "Known phishing kit detected",
            "Recent domain registration",
          ],
        },
        ssl: {
          valid: Math.random() > 0.3,
          issuer: "Let's Encrypt",
          expiry: "2026-12-31",
        },
        reputation: {
          score: Math.floor(Math.random() * 100),
          category: "Technology",
        },
      },
    };

    return NextResponse.json(result);
  } catch (error) {
    console.error("Scan error:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
