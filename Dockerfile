FROM python:3.11

# Install tcpdump
RUN apt-get update && apt-get install -y tcpdump

# Set the working directory
WORKDIR /app

# Copy the Python requirements file
COPY worker_requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r worker_requirements.txt

# Copy the rest of the application code
COPY worker.py .

# Set the entrypoint command
CMD ["python", "worker.py"]