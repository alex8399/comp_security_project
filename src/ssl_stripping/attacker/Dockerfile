FROM python:3.9-slim

# Install system dependencies for NetfilterQueue
RUN apt-get update && apt-get install -y \
    iptables \
    libnetfilter-queue-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install scapy NetfilterQueue

# Set working directory
WORKDIR /app

# Copy the script
COPY ssl_stripping.py .

# Keep container alive
CMD ["tail", "-f", "/dev/null"]