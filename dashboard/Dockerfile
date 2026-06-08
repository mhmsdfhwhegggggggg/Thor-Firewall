# Thor Firewall — Dashboard Dockerfile
# Multi-stage: Node.js builder → nginx static server

FROM node:22-alpine AS builder

WORKDIR /app
COPY dashboard/package*.json ./
RUN npm ci --frozen-lockfile

COPY dashboard/ .
ARG VITE_API_URL=""
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

# ── Stage 2: nginx ────────────────────────────────────────────────────────────
FROM nginx:1.27-alpine AS runtime

# Security headers in nginx
COPY dashboard/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html

RUN addgroup -S thor && adduser -S thor -G thor
USER thor

EXPOSE 3000
HEALTHCHECK --interval=30s CMD wget -qO- http://localhost:3000/ | grep -q "Thor"
