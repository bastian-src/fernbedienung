FROM python:3.9-bookworm

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

COPY ./server.crt server.crt
COPY ./server.key server.key
COPY ./requirements.txt requirements.txt
COPY ./server.py server.py

RUN pip install --no-cache-dir -r requirements.txt
