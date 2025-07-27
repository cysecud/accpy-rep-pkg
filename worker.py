import subprocess

PIP_TIMEOUT = 600

# Launch tcpdump with no write buffer
tcpdump_process = subprocess.Popen(["tcpdump", "-U", "-i", "any", "-w", "/app/dependencies.pcap"])

# Run "pip install -r pkg_requirements.txt --find-links /app/cache"
subprocess.run(["pip", "install", "--no-build-isolation", "-r", "/app/out/pkg_requirements.txt", "--find-links", "/app/cache", "--no-index"], timeout=PIP_TIMEOUT)

# Gracefully restart tcpdump with a new capture file
tcpdump_process.terminate()
tcpdump_process.wait()
tcpdump_process = subprocess.Popen(["tcpdump", "-U", "-i", "any", "-w", "/app/package.pcap"])

# Run "pip install -r pkg_only.txt --find-links /app/cache"
subprocess.run(["pip", "install", "--no-build-isolation", "-r", "/app/out/pkg_only.txt", "--find-links", "/app/cache", "--no-index"], timeout=PIP_TIMEOUT)

# Stop tcpdump
tcpdump_process.terminate()
tcpdump_process.wait()

# Copy the capture files to the volume in /app/cache
subprocess.run(["cp", "/app/dependencies.pcap", "/app/out/dependencies.pcap"])
subprocess.run(["cp", "/app/package.pcap", "/app/out/package.pcap"])