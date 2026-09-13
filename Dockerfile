FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY server/package.json server/package.json
COPY client/package.json client/package.json
RUN npm ci --no-audit --fund=false
COPY . .
RUN npm run build

FROM node:24-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=4005 \
    VAULTMESH_DB_PATH=/app/data/vaultmesh.db
COPY package.json package-lock.json ./
COPY server/package.json server/package.json
COPY client/package.json client/package.json
RUN npm ci --omit=dev --workspace=server --no-audit --fund=false && npm cache clean --force
COPY --from=build /app/server/dist ./server/dist
COPY --from=build /app/client/dist ./client/dist
RUN mkdir -p /app/data && chown node:node /app/data
USER node
EXPOSE 4005
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 4005) + '/health').then((r) => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"
CMD ["node", "--disable-warning=ExperimentalWarning", "server/dist/server/src/index.js"]
