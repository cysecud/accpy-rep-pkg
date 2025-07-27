import logging

# Log to both stdout and a file
LOGFILE = "./log/dynamic_analysis.log"
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s", handlers=[
    logging.FileHandler(LOGFILE),
    logging.StreamHandler()
])
logger = logging.getLogger()
logging.root.setLevel(logging.DEBUG)

from collections import OrderedDict
import queue
import time
import pipgrip
import pipgrip.cli
from pipgrip.package_source import PackageSource
from pipgrip.libs.mixology.version_solver import VersionSolver
from pipgrip.libs.mixology.package import Package
import pip
import os
import docker
import argparse
import tempfile
import shutil
import pipgrip.pipper
import requests
import random
import traceback
import datetime
import threading

# Monkey patch pipgrip to add --no-clean option
orig_get_install_args = pipgrip.pipper._get_install_args
def _patched_get_install_args(*args, **kwargs):
    r = orig_get_install_args(*args, **kwargs)
    r.insert(4, "--no-clean")
    return r
pipgrip.pipper._get_install_args = _patched_get_install_args

orig_get_wheel_args = pipgrip.pipper._get_wheel_args
def _patched_get_wheel_args(*args, **kwargs):
    r = orig_get_wheel_args(*args, **kwargs)
    r.insert(4, "--no-clean")
    return r
pipgrip.pipper._get_wheel_args = _patched_get_wheel_args

DEFAULT_CACHE_DIR = "./cache/dcache/"
DEFAULT_OUTPUT_DIR = "./out/dynamic/"
DEFAULT_INDEX_URL = "https://pypi.org/simple/"

def fetch_index():
    response = requests.get(index_url)
    response.raise_for_status()
    for l in response.text.split("\n"):
        if l.startswith('<a href="/simple/'):
            pkgname = l.split("/")[2]
            yield pkgname

def random_sample_index(n=None):
    findex = list(fetch_index())
    if n is None or n > len(findex):
        return findex
    l = random.sample(findex, n)
    random.shuffle(l)
    return l

def install_package(package):
    # Get the dependencies of a package
    source = PackageSource(
        cache_dir=None,
        no_cache_dir=True,
        index_url=index_url,
        extra_index_url=None,
        pre=None,
    )

    source.root_dep(package)

    solver = VersionSolver(source, threads=2)
    try:
        solution = solver.solve()
        exc = None
    except RuntimeError as e:
        # RuntimeError coming from pipgrip.pipper
        if "Failed to download/build wheel" not in str(e):
            # only continue handling expected RuntimeErrors
            raise
        solution = solver.solution
        exc = e

    # build tree of the (partial) solution using package metadata from source
    decision_packages = OrderedDict()
    for _package, version in solution.decisions.items():
        if _package == Package.root():
            continue
        decision_packages[_package] = version

    tree_root, packages_tree_dict, packages_flat = pipgrip.cli.build_tree(
        source, decision_packages
    )
    deptree = pipgrip.cli.render_lock(packages_flat)

    # Create subfolder with package name in cache directory
    pkg_cache_dir = os.path.join(cache_dir, package)
    pkg_cache_dir = os.path.abspath(pkg_cache_dir)
    os.makedirs(pkg_cache_dir, exist_ok=True)

    # Download the dependencies in reverse order
    for dep in reversed(deptree):
        logger.info(f"Downloading {dep} into {pkg_cache_dir}...")
        pip.main(["download", "--no-input", "--no-clean", "--dest", pkg_cache_dir, dep])
        logger.info(f"Downloaded {dep}.")

    logger.info("All dependencies downloaded.")

    # Create a temporary folder to use as a volume
    tempdir = tempfile.TemporaryDirectory()
    volumes = {
        pkg_cache_dir: {'bind': '/app/cache', 'mode': 'ro'},
        tempdir.name: {'bind': '/app/out', 'mode': 'rw'}
    }

    # Prepare files for the Docker container
    deptree_without_root = deptree[1:]
    with open(os.path.join(tempdir.name, "pkg_requirements.txt"), "w") as f:
        f.write("\n".join(deptree_without_root))

    with open(os.path.join(tempdir.name, "pkg_only.txt"), "w") as f:
        f.write(package)

    # Store the build start time
    build_started_at = datetime.datetime.now().isoformat()

    # Launch a new Docker container and install the package and its dependencies
    # Use the existing Dockerfile and mount a volume
    client = docker.from_env()
    image, build_logs = client.images.build(path=".", tag="pipgrip")
    build_logs = [ line["stream"].strip() if "stream" in line else str(line) for line in build_logs ]
    for line in build_logs:
        logger.info(line)

    # Store the build end time
    build_ended_at = datetime.datetime.now().isoformat()
    install_started_at = datetime.datetime.now().isoformat()

    # Run the container, but show the logs
    container = client.containers.run(image, volumes=volumes, detach=True)

    logger.info(f"Container {container.id} started.")

    # Wait for the container to finish
    exit_code = container.wait()
    install_ended_at = datetime.datetime.now().isoformat()

    # Print the logs
    logs = container.logs()
    logger.info(logs.decode())

    logger.info(f"Container {container.id} finished with exit code {exit_code}.")
    container.remove()

    # Copy from the temporary directory to the final output directory
    outdir = os.path.join(output_dir, package)
    os.makedirs(outdir, exist_ok=True)
    shutil.copy(os.path.join(tempdir.name, "dependencies.pcap"), os.path.join(outdir, "dependencies.pcap"))
    shutil.copy(os.path.join(tempdir.name, "package.pcap"), os.path.join(outdir, "package.pcap"))

    # Clean up the temporary directory
    tempdir.cleanup()

    # Clean up the cache directory
    shutil.rmtree(pkg_cache_dir)

    # Write logs and build_logs to a file
    with open(os.path.join(outdir, "logs.txt"), "w") as f:
        f.write(build_started_at)
        f.write("\n")
        f.write(logs.decode())
        f.write("\n")
        f.write(build_ended_at)
        f.write("\n")
    with open(os.path.join(outdir, "build_logs.txt"), "w") as f:
        f.write(install_started_at)
        f.write("\n")
        f.write("\n".join(build_logs))
        f.write("\n")
        f.write(install_ended_at)
        f.write("\n")
    
    logger.info("Done.")

def is_already_done(pkg):
    return os.path.exists(os.path.join(output_dir, pkg))

def async_worker():
    global tqueue, output_dir
    while tqueue.qsize() > 0:
        try:
            pkg = tqueue.get()
            if is_already_done(pkg):
                logger.info(f"Skipping {pkg} as it is already done.")
            else:
                install_package(pkg)
        except Exception as e:
            logger.error(f"Failed to install {pkg}:")
            traceback.print_exc()
        finally:
            tqueue.task_done()

def async_run_all(pkglist):
    global tqueue
    tqueue = queue.Queue()
    for pkg in pkglist:
        tqueue.put(pkg)

    ts = []
    for _ in range(10):
        t = threading.Thread(target=async_worker, daemon=True)
        t.start()
        ts.append(t)
        time.sleep(60)
    [ e.join() for e in ts ]
    tqueue.join()

def main():
    global cache_dir, output_dir, index_url

    # Parse the package name from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument("package", help="The package to install, or the number of random packages to install from index")
    # Parse tmp dir, output dir and index url, if not provided use default values
    parser.add_argument("--cache-dir", help="The directory to store the cache", default=DEFAULT_CACHE_DIR)
    parser.add_argument("--output-dir", help="The directory to store the output", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--index-url", help="The index URL to fetch packages from", default=DEFAULT_INDEX_URL)
    parser.add_argument("--rasync", help="Run in async mode", action="store_true")
    parser.add_argument("--show-index", help="Print list of packages in index and exit", action="store_true")

    args = parser.parse_args()
    package = args.package
    cache_dir = args.cache_dir
    output_dir = args.output_dir
    index_url = args.index_url
    show_index = args.show_index

    if show_index:
        for pkg in fetch_index():
            print(pkg)
        return
    
    if not package.isdigit():
        if is_already_done(package):
            logger.info(f"Skipping {package} as it is already done.")
        else:
            install_package(package)
        return

    packagenum = int(package)
    logger.info("Fetching package index...")
    sample = random_sample_index(packagenum)
    logger.info(f"Installing {packagenum} random packages...")
    if args.rasync:
        async_run_all(sample)
    else:
        run_all(sample)

def run_all(pkglist):
    for pkg in pkglist:
        try:
            if is_already_done(pkg):
                logger.info(f"Skipping {pkg} as it is already done.")
            else:
                install_package(pkg)
        except Exception as e:
            logger.error(f"Failed to install {pkg}:")
            logger.error(traceback.format_exc())


if __name__ == "__main__":
    main()
