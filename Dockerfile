# Use official Node.js 24 LTS image
FROM node:24-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Expose honeypot ports
EXPOSE 445 3306 3322 3323 3325 8080

ENV DEBUG=*

# Start the application
CMD ["node", "server.js"]
