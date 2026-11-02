import { PrismaClient } from "@prisma/client";
import { Pool, PoolConfig } from "pg";
import { PrismaPg } from "@prisma/adapter-pg";

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
  pgPool: Pool | undefined;
  shutdownRegistered?: boolean;
};

const databaseUrl = process.env.DATABASE_URL;

function createPgPool(): Pool {
  const connectionString = databaseUrl || "postgresql://postgres:postgres@localhost:5432/guardai";
  const poolConfig: PoolConfig = {
    connectionString,
    max: parseInt(process.env.DB_POOL_MAX || "10", 10),
    idleTimeoutMillis: parseInt(process.env.DB_IDLE_TIMEOUT_MS || "30000", 10),
    connectionTimeoutMillis: parseInt(process.env.DB_CONNECT_TIMEOUT_MS || "5000", 10),
  };

  const pool = new Pool(poolConfig);

  // Prevent uncaught errors on idle connections from crashing the node runtime
  pool.on("error", (err) => {
    console.error("[guardai/db] Unexpected idle PostgreSQL client error:", err);
  });

  return pool;
}

function createPrismaClient(): { client: PrismaClient; pool: Pool } {
  const pool = globalForPrisma.pgPool ?? createPgPool();
  const adapter = new PrismaPg(pool);
  const client = new PrismaClient({ adapter });

  return { client, pool };
}

const { client: prismaInstance, pool: poolInstance } =
  globalForPrisma.prisma && globalForPrisma.pgPool
    ? { client: globalForPrisma.prisma, pool: globalForPrisma.pgPool }
    : createPrismaClient();

export const prisma = prismaInstance;
export const pgPool = poolInstance;

// Persist singleton in non-production environments across hot-module reloads
if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = prismaInstance;
  globalForPrisma.pgPool = poolInstance;
}

// Graceful process shutdown handling
if (typeof process !== "undefined" && !globalForPrisma.shutdownRegistered) {
  globalForPrisma.shutdownRegistered = true;

  const handleShutdown = async (signal: string) => {
    try {
      if (globalForPrisma.prisma) {
        await globalForPrisma.prisma.$disconnect();
      }
      if (globalForPrisma.pgPool) {
        await globalForPrisma.pgPool.end();
      }
    } catch (err) {
      console.error(`[guardai/db] Error during ${signal} shutdown:`, err);
    }
  };

  process.once("SIGINT", () => handleShutdown("SIGINT"));
  process.once("SIGTERM", () => handleShutdown("SIGTERM"));
  process.once("beforeExit", () => handleShutdown("beforeExit"));
}

/**
 * Health check utility to probe database connectivity with round-trip latency measurement.
 */
export async function checkDatabaseHealth(): Promise<{
  status: "up" | "down";
  latencyMs?: number;
  error?: string;
}> {
  const start = Date.now();
  try {
    // Execute a fast low-overhead query
    await prisma.$queryRawUnsafe("SELECT 1");
    return {
      status: "up",
      latencyMs: Date.now() - start,
    };
  } catch (err: unknown) {
    return {
      status: "down",
      latencyMs: Date.now() - start,
      error: err instanceof Error ? err.message : "Unknown database connection failure",
    };
  }
}
