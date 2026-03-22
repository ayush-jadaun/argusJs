# Stage 1: Dependencies
FROM node:20-alpine AS deps
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig.base.json ./
COPY packages/ packages/
RUN pnpm install --frozen-lockfile

# Stage 2: Build
FROM deps AS build
RUN pnpm build

# Stage 3: Production
FROM node:20-alpine AS production
RUN apk add --no-cache dumb-init wget
RUN addgroup -g 1001 -S argus && adduser -S argus -u 1001
WORKDIR /app
COPY --from=build --chown=argus:argus /app .
USER argus
EXPOSE 3100
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "packages/server/dist/server.js"]
