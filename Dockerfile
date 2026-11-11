# Pinned by digest so a rebuild can't silently pick up a different image. The
# tag is kept, although Docker ignores it when a digest is given, because
# Dependabot needs it to know which image to track and opens a PR for each new
# digest (.github/dependabot.yml). SonarCloud's S8431 flags this form; it is
# accepted on purpose.
FROM node:22-alpine@sha256:0e1754758c2df4cfa3e68d59e2e1b7374bb7fd9ea6328eaaacf15cc934af8202
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
