# Use official Node.js 24 LTS image
FROM node:24-slim

# Install nmap
#RUN apt-get update && \
#    apt-get install -y --no-install-recommends nmap && \
#    apt-get clean && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Expose honeypot ports
EXPOSE 445 3306 3322 3323 3325 8080

RUN useradd -s /bin/bash -m runner

ENV NODE_ENV=production
ENV DEBUG=*

# HEALTHCHECK
RUN chown -R runner:runner /app
USER runner

# Start the application
CMD ["node", "server.js"]
