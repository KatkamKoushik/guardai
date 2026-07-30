import { prisma } from "./db";

type AuditAction = "DEEP_SCAN" | "USER_LOGIN" | "USER_LOGOUT" | "SETTINGS_UPDATE" | string;
type AuditStatus = "success" | "failed" | "pending" | string;
type AuditSeverity = "low" | "medium" | "high" | "critical" | string;

export async function logAuditAction(
  action: AuditAction,
  target: string,
  status: AuditStatus,
  severity: AuditSeverity,
  details: string,
  userId?: string | null
) {
  try {
    const log = await prisma.auditLog.create({
      data: {
        action,
        target,
        status,
        severity,
        details,
        userId: userId || "System", // Default to System if no userId is provided
      },
    });
    return log;
  } catch (error) {
    console.error("Failed to log audit action:", error);
    return null;
  }
}
