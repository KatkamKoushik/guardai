import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { auth } from "@/lib/auth";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const session = await auth();

    // Require authentication
    if (!session?.user?.email) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const userEmail = session.user.email;

    // Strict user scoping — only return this user's logs
    const rows = await prisma.auditLog.findMany({
      take: 200,
      orderBy: { createdAt: "desc" },
      where: {
        userId: userEmail,
      },
    });

    const entries = rows.map((row) => ({
      id: row.id,
      timestamp: row.createdAt.toISOString(),
      action: row.action,
      target: row.target,
      status: row.status,
      severity: row.severity,
      source: row.action,       // Replaces "user" column — shows action source type
      details: row.details,
    }));

    return NextResponse.json({ entries });
  } catch (error) {
    console.error("Audit route error:", error);
    return NextResponse.json({ error: "Failed to fetch audit entries" }, { status: 500 });
  }
}
