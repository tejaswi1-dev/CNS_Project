#!/bin/bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -subj "/C=US/ST=State/L=City/O=SecurePM/OU=Dev/CN=localhost"
echo "Server TLS certificate generated"
