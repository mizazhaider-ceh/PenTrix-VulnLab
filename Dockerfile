FROM python:3.11-slim

WORKDIR /app

# Install system tools needed for RCE demos
RUN apt-get update && apt-get install -y \
    iputils-ping \
    curl \
    netcat-openbsd \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

# Create necessary directories
RUN mkdir -p /app/data /app/static/uploads /app/flags

# Seed database and flags on build
RUN python seed.py

EXPOSE 5000

CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000", "--debug"]
