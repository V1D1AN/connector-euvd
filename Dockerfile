FROM python:3.11-alpine

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev

# Create app directory
WORKDIR /opt/opencti-connector-euvd

# Copy requirements first for better caching
COPY src/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ .

# Create non-root user
RUN addgroup -g 1000 connector && \
    adduser -u 1000 -G connector -s /bin/sh -D connector && \
    chown -R connector:connector /opt/opencti-connector-euvd

USER connector

# Run the connector
ENTRYPOINT ["python", "main.py"]
