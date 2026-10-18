FROM node:22-alpine
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
CMD ["node", "server.js"]
