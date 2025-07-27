import logging

# Log to both stdout and a file
LOGFILE = "./log/guarddog_analysis.log"
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s", handlers=[
    logging.FileHandler(LOGFILE),
    logging.StreamHandler()
])
logger = logging.getLogger()
logging.root.setLevel(logging.DEBUG)

import os
import docker
import argparse
import datetime

DEFAULT_CACHE_DIR = "./cache/gcache/"
DEFAULT_OUTPUT_DIR = "./out/guarddog/"

def scan_package(package):
    # Launch a new Docker container and install the package and its dependencies
    # Use the existing Dockerfile and mount a volume
    client = docker.from_env()
    install_started_at = datetime.datetime.now().isoformat()

    # Run the container, but show the logs
    cmd = f"pypi scan {package} --output-format=json"
    container = client.containers.run("ghcr.io/datadog/guarddog", cmd, detach=True)

    logger.info(f"Container {container.id} started.")

    # Wait for the container to finish
    exit_code = container.wait()
    install_ended_at = datetime.datetime.now().isoformat()

    # Print the logs
    logs = container.logs()
    logger.info(logs.decode())

    logger.info(f"Container {container.id} finished with exit code {exit_code}.")

    # Copy from the temporary directory to the final output directory
    outdir = os.path.join(output_dir, package)
    os.makedirs(outdir, exist_ok=True)

    # Write logs and build_logs to a file
    with open(os.path.join(outdir, "logs.txt"), "w") as f:
        f.write(install_started_at)
        f.write("\n")
        f.write(logs.decode())
        f.write("\n")
        f.write(install_ended_at)
        f.write("\n")
    
    container.remove()
    logger.info("Done.")

def is_already_done(pkg):
    if not os.path.exists(os.path.join(output_dir, pkg)):
        return False
    if not os.path.exists(os.path.join(output_dir, pkg, "logs.txt")):
        return False
    return True

def main():
    global cache_dir, output_dir

    # Parse the package name from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument("package", help="The package to install, or the number of random packages to install from index")
    # Parse tmp dir, output dir and index url, if not provided use default values
    parser.add_argument("--cache-dir", help="The directory to store the cache", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--output-dir", help="The directory to store the output", default=DEFAULT_OUTPUT_DIR)

    args = parser.parse_args()
    pkg = args.package
    cache_dir = args.cache_dir
    output_dir = args.output_dir
    
    if is_already_done(pkg):
        logger.info(f"Skipping {pkg} as it is already done.")
    else:
        scan_package(pkg)

if __name__ == "__main__":
    main()
