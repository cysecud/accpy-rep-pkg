import logging

# Log to both stdout and a file
LOGFILE = "./log/bandit_analysis.log"
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s", handlers=[
    logging.FileHandler(LOGFILE),
    logging.StreamHandler()
])
logger = logging.getLogger()
logging.root.setLevel(logging.DEBUG)

import pip
import os
import argparse
import tempfile
import shutil
import subprocess

DEFAULT_CACHE_DIR = "./cache/bcache/"
DEFAULT_OUTPUT_DIR = "./out/bandit/"
# INDEX_URL = "https://acc-py-repo.cern.ch/repository/vr-py-releases/simple/"
INDEX_URL = "https://pypi.org/simple/"

def scan_package(package):
    logger.info(f"Scanning package {package}")
    report_fname = package + '_report.json'
    if os.path.exists(os.path.join(output_dir, report_fname)):
        logger.info(f"Report for package {package} already exists, skipping")
        return

    pkg_cache_dir = tempfile.mkdtemp(dir=cache_dir)
    pip.main(['download', package, '--no-clean', '--no-deps', '-d', pkg_cache_dir, '-i', INDEX_URL])

    for file in os.listdir(pkg_cache_dir):
        if file.endswith('.whl'):
            shutil.unpack_archive(os.path.join(pkg_cache_dir, file), pkg_cache_dir, "zip")

    breport_path = os.path.join(pkg_cache_dir, 'bandit_report.json')
    subprocess.run(['bandit', '-r', pkg_cache_dir, '-f', 'json', '-o', breport_path])

    shutil.move(breport_path, os.path.join(output_dir, report_fname))

    shutil.rmtree(pkg_cache_dir)

    logger.info(f"Finished scanning package {package}")

def main():
    global cache_dir, output_dir

    # Parse the package name from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument("package", help="The package to install, or the number of random packages to install from index")
    # Parse tmp dir, output dir and index url, if not provided use default values
    parser.add_argument("--cache-dir", help="The directory to store the cache", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--output-dir", help="The directory to store the output", default=DEFAULT_OUTPUT_DIR)

    args = parser.parse_args()
    package = args.package
    cache_dir = args.cache_dir
    output_dir = args.output_dir

    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    scan_package(package)

if __name__ == "__main__":
    main()
