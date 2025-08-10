# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application
COPY . .

# Install the package
RUN pip install -e .

# Create non-root user
RUN useradd -m -u 1000 vulnmind && chown -R vulnmind:vulnmind /app
USER vulnmind

# Create reports directory
RUN mkdir -p /app/reports

# Set environment variables
ENV PYTHONPATH=/app
ENV VULNMIND_REPORT_DIR=/app/reports

# Expose volume for reports
VOLUME ["/app/reports"]

# Default entrypoint
ENTRYPOINT ["python", "-m", "vulnmind.cli.main"]

# Default command (show help)
CMD ["--help"]

# Labels
LABEL maintainer="VulnMind Team <team@vulnmind.ai>"
LABEL version="1.0.0"
LABEL description="AI-Powered Self-Aware DAST Scanner"
