FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i 's/archive.ubuntu.com/kebo.pens.ac.id/g' /etc/apt/sources.list.d/ubuntu.sources
RUN apt-get update && apt-get install -y \
    snort \
    iptables \
    iproute2 \
    curl \
    wget \
    tar \
    tzdata \
    libnetfilter-queue1 \
    && rm -rf /var/lib/apt/lists/*
COPY local.rules /etc/snort/rules/local.rules
COPY setup.sh /usr/local/bin/setup.sh
RUN chmod +x /usr/local/bin/setup.sh
CMD ["/usr/local/bin/setup.sh"]