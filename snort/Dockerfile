FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y snort socat iproute2 iptables curl openssl dos2unix ca-certificates libnetfilter-queue1 libnetfilter-queue-dev && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /etc/snort/rules /var/log/snort /etc/snort/ssl && chmod 755 /var/log/snort
COPY snort.conf /etc/snort/snort.conf
COPY local.rules /etc/snort/rules/local.rules
COPY acl.conf /etc/snort/acl.conf
COPY setup.sh /usr/local/bin/setup.sh
RUN find /etc/snort /usr/local/bin/setup.sh -type f -exec sed -i '1s/^\xEF\xBB\xBF//' {} \; -exec dos2unix {} \; 2>/dev/null || true && chmod +x /usr/local/bin/setup.sh
CMD ["/usr/local/bin/setup.sh"]