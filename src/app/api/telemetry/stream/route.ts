import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const encoder = new TextEncoder();
  let pollTimeout: ReturnType<typeof setTimeout> | null = null;

  const customReadable = new ReadableStream({
    async start(controller) {
      let isConnected = true;
      let consecutiveErrors = 0;

      const cleanup = () => {
        isConnected = false;
        if (pollTimeout) {
          clearTimeout(pollTimeout);
          pollTimeout = null;
        }
        try {
          controller.close();
        } catch {
          // Stream already closed or cancelled
        }
      };

      request.signal.addEventListener("abort", cleanup);

      // Keep track of what we've already sent to this client
      let lastPolledTime = new Date();

      const pollCycle = async () => {
        if (!isConnected || request.signal.aborted) {
          cleanup();
          return;
        }

        try {
          // 1. Fetch newly added threats from the database pipeline
          const newScans = await prisma.scan.findMany({
            where: { createdAt: { gt: lastPolledTime } },
            orderBy: { createdAt: "desc" },
            take: 10,
          });

          // 2. Fetch total metrics
          const threatCount = await prisma.scan.count({
            where: { threatLevel: { in: ["high", "critical"] } },
          });
          const scanCount = await prisma.scan.count();

          consecutiveErrors = 0; // Reset error streak on success

          if (newScans.length > 0) {
            for (const scan of newScans) {
              if (!isConnected) break;

              let domain = scan.url;
              try {
                domain = new URL(scan.url).hostname;
              } catch {
                // Keep raw URL if unparseable
              }

              const details = scan.details as any;

              const payload = {
                newThreat: {
                  id: scan.id,
                  domain,
                  threatType: scan.threatLevel,
                  ipAddress: details?.geoIp?.query || null,
                  latitude: details?.geoIp?.lat || null,
                  longitude: details?.geoIp?.lon || null,
                  countryCode: details?.geoIp?.country || null,
                  timestamp: scan.createdAt.toISOString(),
                },
                threatCount,
                scanCount,
                timestamp: new Date().toISOString(),
              };

              try {
                controller.enqueue(encoder.encode(`data: ${JSON.stringify(payload)}\n\n`));
              } catch {
                cleanup();
                return;
              }

              if (scan.createdAt > lastPolledTime) {
                lastPolledTime = scan.createdAt;
              }
            }
          } else {
            // Push periodic heartbeat telemetry
            const payload = {
              threatCount,
              scanCount,
              timestamp: new Date().toISOString(),
            };

            try {
              controller.enqueue(encoder.encode(`data: ${JSON.stringify(payload)}\n\n`));
            } catch {
              cleanup();
              return;
            }
          }
        } catch (error) {
          consecutiveErrors++;
          console.error(`[telemetry/stream] SSE polling error (attempt ${consecutiveErrors}):`, error);
        }

        if (isConnected && !request.signal.aborted) {
          // Back off exponentially on failure (3s up to 30s max), 3.5s normal interval
          const nextDelayMs =
            consecutiveErrors > 0
              ? Math.min(3000 * Math.pow(2, consecutiveErrors - 1), 30000)
              : 3500;
          pollTimeout = setTimeout(pollCycle, nextDelayMs);
        }
      };

      // Kick off the initial cycle
      pollCycle();
    },
    cancel() {
      if (pollTimeout) {
        clearTimeout(pollTimeout);
        pollTimeout = null;
      }
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
