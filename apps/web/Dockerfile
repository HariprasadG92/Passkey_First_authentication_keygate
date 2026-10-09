# syntax=docker/dockerfile:1.7
# Multi-stage build for the Next.js UI. The runtime image holds only Next's standalone
# server output (traced, production-only dependencies) and runs as an unprivileged user.

ARG NODE_VERSION=22

# ---------- base ----------
FROM node:${NODE_VERSION}-alpine AS base
ENV PNPM_HOME=/pnpm \
    NEXT_TELEMETRY_DISABLED=1
ENV PATH="${PNPM_HOME}:${PATH}"
RUN corepack enable
WORKDIR /app

# ---------- deps: install from the lockfile only ----------
FROM base AS deps
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile

# ---------- dev: `next dev`, source bind-mounted by compose ----------
FROM base AS dev
ENV NODE_ENV=development
# Pre-create mount points so compose's anonymous volumes inherit node's ownership.
RUN mkdir -p /app/.next /app/node_modules && chown -R node:node /app
USER node
COPY --chown=node:node package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
EXPOSE 3000
CMD ["sh", "-c", "pnpm install --frozen-lockfile && exec pnpm dev --hostname 0.0.0.0 --port 3000"]

# ---------- builder ----------
FROM base AS builder
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NODE_ENV=production
RUN pnpm build

# ---------- runtime ----------
FROM node:${NODE_VERSION}-alpine AS runtime
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000
WORKDIR /app
RUN addgroup -S -g 10001 keygate && adduser -S -u 10001 -G keygate -H -s /sbin/nologin keygate
COPY --from=builder --chown=keygate:keygate /app/.next/standalone ./
COPY --from=builder --chown=keygate:keygate /app/.next/static ./.next/static
COPY --from=builder --chown=keygate:keygate /app/public ./public
USER keygate
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["node", "-e", "fetch('http://127.0.0.1:3000/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["node", "server.js"]
