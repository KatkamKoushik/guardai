import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const encoder = new TextEncoder();

  // Create a readable stream
  const customReadable = new ReadableStream({
    async start(controller) {
      let isConnected = true;

      // Listen for client disconnect
      request.signal.addEventListener("abort", () => {
        isConnected = false;
        console.log("Client disconnected from SSE");
      });

      // Poll database and send events
      const pollInterval = setInterval(async () => {
        if (!isConnected) {
          clearInterval(pollInterval);
          return;
        }

        try {
          // 1. Fetch latest threats
          const latestThreats = await prisma.threatTelemetry.findMany({
            take: 50,
            orderBy: { timestamp: "desc" },
          });

          // 2. Fetch total threat count
          const threatCount = await prisma.threatTelemetry.count();

          // 3. Fetch total scan count
          const scanCount = await prisma.scansAudit.count();

          // Construct the payload
          const payload = {
            latestThreats,
            threatCount,
            scanCount,
            timestamp: new Date().toISOString(),
          };

          // Send SSE formatted message
          const message = `data: ${JSON.stringify(payload)}\n\n`;
          controller.enqueue(encoder.encode(message));
        } catch (error) {
          console.error("Error polling database for SSE:", error);
          // Don't close the stream on a single DB failure, just skip this tick
        }
      }, 2000); // Broadcast every 2 seconds

      // Cleanup when the stream is cancelled by the server
      return () => {
        clearInterval(pollInterval);
        isConnected = false;
      };
    },
  });

  return new NextResponse(customReadable, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "Content-Encoding": "none", // Prevent buffering in some proxies
    },
  });
}
