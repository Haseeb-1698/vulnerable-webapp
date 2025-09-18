# Multi-stage build for production optimization
FROM node:18-alpine AS base

# Install security updates and create non-root user
RUN apk update && apk upgrade && \
    addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY prisma ./prisma/

# Development stage
FROM base AS development
RUN npm ci
RUN npx prisma generate
COPY . .
EXPOSE 3001
USER nodejs
CMD ["npm", "run", "dev"]

# Build stage
FROM base AS builder
RUN npm ci
RUN npx prisma generate
COPY . .
RUN npm run build
RUN npm prune --production

# Production stage
FROM node:18-alpine AS production

# Install security updates and create non-root user
RUN apk update && apk upgrade && \
    addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

WORKDIR /app

# Copy built application and dependencies
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/package*.json ./
COPY --from=builder --chown=nodejs:nodejs /app/prisma ./prisma

# Create uploads directory with proper permissions
RUN mkdir -p uploads && chown nodejs:nodejs uploads

# Security hardening
RUN rm -rf /tmp/* /var/cache/apk/* && \
    chmod -R 755 /app && \
    chmod 700 /app/uploads

# Switch to non-root user
USER nodejs

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3001/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"

# Expose port
EXPOSE 3001

# Start the application
CMD ["node", "dist/server.js"]