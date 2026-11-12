# Pinned by digest so a rebuild can't silently pick up a different image. The
# tag is kept, although Docker ignores it when a digest is given, because
# Dependabot needs it to know which image to track and opens a PR for each new
# digest (.github/dependabot.yml). SonarCloud's S8431 flags this form; it is
# accepted on purpose.
#
# Even-numbered Node releases only: odd ones (23, 25) are never LTS and reach
# end of life within months. Dependabot skips major versions (see
# dependabot.yml), so moving to the next LTS is a deliberate change here.
FROM node:24-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5
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
