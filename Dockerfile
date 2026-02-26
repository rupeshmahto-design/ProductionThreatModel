# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install minimal system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build tools for some Python wheels
    build-essential \
    pkg-config \
    libffi-dev \
    # PostgreSQL client libs
    libpq-dev \
    # Tesseract OCR for image text extraction
    tesseract-ocr \
    tesseract-ocr-eng \
    # Image processing libraries
    libjpeg-dev \
    libpng-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (better caching)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

# Copy the rest of the app
COPY . /app

# Streamlit config
ENV STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0

EXPOSE 8501

# Use shell form to allow environment variable expansion
CMD streamlit run app.py --server.port=${PORT:-8501} --server.address=0.0.0.0 --server.headless=true
