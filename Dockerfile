# ---- build stage: compilers live here only ----
FROM node:20-slim AS build

# better-sqlite3 needs build tools at install time
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

# ---- runtime stage: no compilers, runs as non-root ----
FROM node:20-slim

# iputils-ping stays: the cmdi module has ping-based labs.
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY . .
# Writable dirs owned by the app user. Note: when ./data is mounted as a
# volume, the host directory's ownership decides writability; on Docker
# Desktop (Windows/macOS) this just works, on Linux ensure your user can
# write ./data or chown it to uid 1000.
RUN mkdir -p uploads data && chown -R node:node /app
USER node

EXPOSE 3000
CMD ["node", "app.js"]
