FROM alpine:3.23
RUN apk add --no-cache openvpn python3 iptables iproute2
COPY app/ /app/
RUN chmod +x /app/status.py && ln -s /app/status.py /usr/local/bin/status
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD ["status"]
ENTRYPOINT ["python3", "/app/entrypoint.py"]
