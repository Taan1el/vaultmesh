FROM node:24-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY server/package.json server/package.json
COPY client/package.json client/package.json
RUN npm ci

FROM deps AS build
COPY . .
RUN npm run build

FROM node:24-bookworm-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=4005
COPY package.json package-lock.json ./
COPY server/package.json server/package.json
RUN npm ci --omit=dev
COPY --from=build /app/server/dist ./server/dist
COPY --from=build /app/client/dist ./client/dist
EXPOSE 4005
CMD ["npm", "run", "start", "--workspace=server"]
