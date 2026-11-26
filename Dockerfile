FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-client && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir -r requirements.txt && \
    groupadd --gid 10001 gateway && \
    useradd --uid 10001 --gid 10001 --home-dir /var/lib/unifi-gateway --no-create-home --shell /usr/sbin/nologin gateway && \
    install -d -m 0700 -o 10001 -g 10001 /var/lib/unifi-gateway
COPY . .
ENV UNIFI_GW_CONFIG=/var/lib/unifi-gateway/gateway.conf \
    UNIFI_GW_SITE_CONFIG=/run/enrollment/site.conf \
    UNIFI_GW_LOG_LEVEL=INFO \
    PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
ENTRYPOINT ["python", "unifi_gateway.py"]
CMD ["run"]
