# A deployable reference ADP agent. Runs the node:http service in examples/reference-agent/
# directly via tsx against the in-repo TypeScript sources (no build step), so the image is
# a faithful, minimal demonstration of "adopt ADP": serve your disclosure + handshake and
# verify a counterparty before you pay.
#
# Build (from the repo root):
#   docker build -f examples/reference-agent/Dockerfile -t adp-reference-agent .
# Run:
#   docker run --rm -p 8800:8800 adp-reference-agent
#   curl http://localhost:8800/health
#
# Override the port with -e PORT=9000 -p 9000:9000.

FROM node:22-slim

WORKDIR /app

# Install dependencies first for layer caching. tsx (a devDependency) runs the .ts
# sources directly, so we need the full install, not --omit=dev.
COPY package.json package-lock.json* ./
RUN npm ci

# Copy the protocol sources + the reference agent.
COPY src ./src
COPY examples/reference-agent ./examples/reference-agent

ENV PORT=8800
EXPOSE 8800

CMD ["node", "--import", "tsx", "examples/reference-agent/server.ts"]
