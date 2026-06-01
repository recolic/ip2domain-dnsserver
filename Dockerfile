FROM python:3-alpine
WORKDIR /app
RUN pip install --no-cache-dir dnslib
COPY ip2domain.py .
EXPOSE 53/tcp 53/udp
CMD ["python3", "ip2domain.py"]
