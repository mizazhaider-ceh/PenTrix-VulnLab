FROM python:3.11-slim

WORKDIR /service

# Install dependencies
RUN pip install --no-cache-dir flask redis

COPY server.py .

EXPOSE 8080

CMD ["python", "server.py"]
