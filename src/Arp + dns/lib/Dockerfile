FROM python:3.11-slim

# Install system tools required for Scapy and network manipulation
RUN apt-get update && apt-get install -y \
    iptables \
    net-tools \
    iproute2 \
    dnsutils \
    iputils-ping \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN pip install -r requirements.txt

# Keep the container running so we can log in and run commands manually
CMD ["tail", "-f", "/dev/null"]