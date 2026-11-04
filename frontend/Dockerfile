# CAWASMA frontend: production image for the Next.js app (standalone output).
#
#   docker build -t cawasma-frontend \
#     --build-arg NEXT_PUBLIC_API_URL=http://localhost:8000 .
#   docker run -p 3000:3000 -e API_INTERNAL_URL=http://api:8000 cawasma-frontend

ARG NODE_VERSION=22

# ---------------------------------------------------------------- deps
FROM node:${NODE_VERSION}-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund

# ---------------------------------------------------------------- build
FROM node:${NODE_VERSION}-alpine AS builder
WORKDIR /app
# Browser-facing API URL; NEXT_PUBLIC_* is inlined into the client bundle here.
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL} \
    NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

# ---------------------------------------------------------------- runtime
FROM node:${NODE_VERSION}-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0

# Unprivileged user; the app files stay root-owned (read-only to the app)
# except the cache dir Next.js writes to at runtime.
RUN addgroup -S -g 1001 nodejs \
 && adduser -S -u 1001 -G nodejs nextjs \
 && mkdir -p .next/cache \
 && chown nextjs:nodejs .next/cache

COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=5 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:3000/').then(r => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]

CMD ["node", "server.js"]
