# ==============================================================================
# MailTrace AI — Production Google Cloud Run Multi-Stage Dockerfile
# ==============================================================================
# NOTE: The 1.4 GB model checkpoint is NOT baked into this container image.
# The ModelArtifactManager downloads and verifies the model at runtime from GCS.
# ==============================================================================

# ── Stage 1: Build Frontend Assets ──────────────────────────────────────────
FROM node:22-slim AS builder
WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY index.html tsconfig.json vite.config.ts ./
COPY public/ public/
COPY src/ src/
COPY scripts/ scripts/
COPY server/ server/
COPY server.ts ./

RUN npm run build

# ── Stage 2: Production Runtime ──────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Install Node.js 22 & system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gnupg \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install PyTorch CPU & Python ML dependencies
COPY ml/requirements.txt ml/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir torch torchvision --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir google-cloud-storage && \
    pip install --no-cache-dir -r ml/requirements.txt

# Install production Node dependencies
COPY package*.json ./
RUN npm ci --omit=dev

# Copy application artifacts (NO .pt files in build context)
COPY --from=builder /app/dist dist
COPY server/ server/
COPY ml/ ml/
COPY public/ public/
COPY scripts/ scripts/
COPY dataset/ dataset/
COPY reports/ reports/
COPY ref/ ref/
COPY server.ts ./
COPY tsconfig.json ./

# Environment defaults for Cloud Run
ENV NODE_ENV=production \
    PORT=3000 \
    ML_PORT=5001 \
    MAILTRACE_MODEL_DIR=/tmp/mailtrace-model \
    PYTHONUNBUFFERED=1

EXPOSE 3000 5001

# Entrypoint launches Node backend with integrated ML inference engine
CMD ["npm", "run", "dev"]
