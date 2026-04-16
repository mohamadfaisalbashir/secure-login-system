FROM ubuntu:24.04

# Matikan interaksi manual agar instalasi tidak tersendat minta input
ENV DEBIAN_FRONTEND=noninteractive

# (Opsional) Ganti mirror ke server Indonesia agar download cepat
# Ubuntu 24.04 menggunakan format .sources
RUN sed -i 's/archive.ubuntu.com/kebo.pens.ac.id/g' /etc/apt/sources.list.d/ubuntu.sources

# Jalankan instalasi
RUN apt-get update && apt-get install -y \
    snort \
    iptables \
    iproute2 \
    curl \
    wget \
    tar \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY local.rules /etc/snort/rules/local.rules
COPY setup.sh /usr/local/bin/setup.sh

RUN chmod +x /usr/local/bin/setup.sh

CMD ["/usr/local/bin/setup.sh"]