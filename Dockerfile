# A Node LTS line by tag. Rebuilds pick up that line's patch releases, and
# Dependabot (.github/dependabot.yml) proposes the next major version, skipping
# the odd-numbered ones, which are never LTS. There is no digest pin:
# SonarCloud's S8431 refuses tag and digest together, and a pin by digest only
# would leave Dependabot unable to tell which image to track.
FROM node:26-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY server.js ./
COPY src ./src
# Audit log location inside the container. Mount a volume here to keep it.
ENV AUDIT_LOG=/data/audit.jsonl
RUN mkdir -p /data && chown node:node /data
USER node
EXPOSE 3000
# Uses Node's own fetch, so the image needs no curl or wget.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.MCP_PORT || 3000) + '/health', { signal: AbortSignal.timeout(4000) }).then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"
CMD ["node", "server.js"]
