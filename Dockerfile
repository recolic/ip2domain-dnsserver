# sudo docker build -t recolic/ip2domain .
# sudo docker run --log-opt max-size=10M -d -p 53:53/tcp -p 53:53/udp --name rip2d recolic/ip2domain
FROM python:3-alpine
WORKDIR /app
RUN pip install --no-cache-dir dnslib
COPY ip2domain.py .
EXPOSE 53/tcp 53/udp
CMD ["python3", "ip2domain.py"]
