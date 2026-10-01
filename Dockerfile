FROM node:20-slim

# better-sqlite3 needs build tools; ping needs iputils
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ iputils-ping \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

COPY . .
RUN mkdir -p uploads data && chmod 777 uploads data

EXPOSE 3000
CMD ["node", "app.js"]
