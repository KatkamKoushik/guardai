import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const totalScans = await prisma.scan.count();
    
    return NextResponse.json(
      { totalScans },
      {
        headers: {
          "Cache-Control": "public, s-maxage=60, stale-while-revalidate=120",
        },
      }
    );
  } catch (error) {
    console.error("Error fetching stats:", error);
    return NextResponse.json({ totalScans: 0 }, { status: 500 });
  }
}
