import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const encoder = new TextEncoder();
  let pollInterval: ReturnType<typeof setInterval> | null = null;

  const customReadable = new ReadableStream({
    async start(controller) {
      let isConnected = true;

      request.signal.addEventListener("abort", () => {
        isConnected = false;
        if (pollInterval) clearInterval(pollInterval);
        controller.close();
        console.log("Client disconnected from SSE");
      });

      // Keep track of what we've already sent to this client
      let lastPolledTime = new Date();

      pollInterval = setInterval(async () => {
        if (!isConnected) {
          if (pollInterval) clearInterval(pollInterval);
          return;
        }

        try {
          // 1. Fetch newly added threats from the real database pipeline
          const newThreats = await prisma.threatTelemetry.findMany({
            where: { timestamp: { gt: lastPolledTime } },
            orderBy: { timestamp: "asc" },
            take: 10,
          });

          // 2. Fetch total counts
          const threatCount = await prisma.threatTelemetry.count();
          const scanCount = await prisma.auditLog.count();

          if (newThreats.length > 0) {
            // Send each new threat as its own payload
            for (const threat of newThreats) {
              const payload = {
                newThreat: threat,
                threatCount,
                scanCount,
                timestamp: new Date().toISOString(),
              };
              const message = `data: ${JSON.stringify(payload)}\n\n`;
              controller.enqueue(encoder.encode(message));
              
              if (threat.timestamp > lastPolledTime) {
                lastPolledTime = threat.timestamp;
              }
            }
          } else {
            // Even if no new threats, push a heartbeat with the counts so latency checker works
            const payload = {
              threatCount,
              scanCount,
              timestamp: new Date().toISOString(),
            };
            const message = `data: ${JSON.stringify(payload)}\n\n`;
            controller.enqueue(encoder.encode(message));
          }

        } catch (error) {
          console.error("Error polling database for SSE:", error);
        }
      }, 1500); 
    },
    cancel() {
      if (pollInterval) clearInterval(pollInterval);
    },
  });

  return new NextResponse(customReadable, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "Content-Encoding": "none", 
    },
  });
}
