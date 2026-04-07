#!/bin/bash
# SSL Certificate Generation Script
# Run this script to generate self-signed SSL certificates for development

# Create ssl directory if it doesn't exist
mkdir -p ssl

# Generate private key
openssl genrsa -out ssl/key.pem 2048

