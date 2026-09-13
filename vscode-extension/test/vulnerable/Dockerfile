# Ch3ck3r SAST Vulnerable Test — Dockerfile
# Deliberate security flaws for container detection

# 🔴 CWE-1104 Using latest tag
FROM node:latest

# 🔴 CWE-798 Secrets in Docker layer
ENV API_KEY=sk-live-abcdef123456
ENV DB_PASSWORD=password123
ENV JWT_SECRET=my_secret

# 🔴 CWE-250 Running as root — no USER directive
WORKDIR /app
COPY package*.json ./
RUN npm install

# 🔴 CWE-829 Using ADD instead of COPY (auto-extract risk)
ADD app.js /app/
ADD config.json /app/

# 🔴 CWE-1104 apt without cleanup
RUN apt-get update && apt-get install -y curl wget

# 🔴 CWE-1104 Exposed port without docs
EXPOSE 3000

CMD ["node", "app.js"]
