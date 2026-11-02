# syntax=docker/dockerfile:1

# ── Stage 1: Base Alpine Environment ──────────────────────────────────────────
FROM node:22-alpine AS base
WORKDIR /app
RUN apk add --no-cache libc6-compat openssl curl

# ── Stage 2: Install Production Dependencies ──────────────────────────────────
FROM base AS deps
WORKDIR /app

COPY package.json package-lock.json ./
COPY prisma ./prisma/

# Clean deterministic install
RUN npm ci

# ── Stage 3: Build Application ───────────────────────────────────────────────
FROM base AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Generate Prisma Client for PostgreSQL adapter
RUN npx prisma generate

# Build Next.js with production optimization
ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production
RUN npm run build

# ── Stage 4: Production Runner ────────────────────────────────────────────────
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Security: Enforce non-root principle of least privilege
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Copy static assets and built distribution
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next ./.next
COPY --from=builder --chown=nextjs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nextjs:nodejs /app/package.json ./package.json
COPY --from=builder --chown=nextjs:nodejs /app/prisma ./prisma

USER nextjs

EXPOSE 3000

# Container liveness check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:3000/api/health || exit 1

CMD ["npm", "start"]

