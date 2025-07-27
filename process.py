import json
import os
import os.path
import shutil
import pyshark
import random
import multiprocessing
import tqdm
import json

GUARDDOG_RESULTS = './out/guarddog/'
BANDIT_RESULTS = './out/bandit/'
DYNAMIC_RESULTS = './out/dynamic/'
OUTDIR = './results/'
NUM_THREADS = 32

def process_guarddog(sample=0.1):
    package_findings = {}
    fds = os.listdir(GUARDDOG_RESULTS)
    
    if isinstance(sample, float) or isinstance(sample, int):
        ssize = int(sample * len(fds))
        assert sample > 0
        assert ssize > 0
        random.shuffle(fds)
        fds = fds[:ssize]
    elif isinstance(sample, list):
        pnames = [ x.split("_logs.txt")[0] for x in fds ]
        missing = set(sample).difference(set(pnames))
        fds = set(pnames).intersection(set(sample))
        assert len(missing) < 1000
        if len(missing) > 0:
            print(f"Missing data for {len(missing)} packages, processing {len(fds)}/{len(sample)} packages")
            print(missing)

    i = 0
    for fd in fds:
        i += 1
        if not os.path.isdir(os.path.join(GUARDDOG_RESULTS, fd)):
            continue
        with open(os.path.join(GUARDDOG_RESULTS, fd, 'logs.txt'), 'r') as f:
            data = f.read()
            if "[Errno 28] No space left on device" in data:
                print(f"Skipping {fd} due to space error")
                continue
            data = "\n".join([ x for x in data.split("\n") if x.startswith("{") ])
            if len(data) == 0:
                print(f"Skipping {fd} due to empty data")
                continue
            data = json.loads(data)
        issues = data["issues"]

        c_issues = 0
        if "results" not in data:
            # print(f"Skipping {fd} due to missing results: {data['errors']}")
            continue
        for item in data["results"].values():
            if item is None:
                continue
            if not isinstance(item, dict) and not isinstance(item, list):
                c_issues += 1
                continue
            c_issues += len(item)

        assert c_issues == issues
        pname = fd
        package_findings[pname] = {
            "issues": issues,
            "results": data["results"]
        }
        if i % 10000 == 0:
            print(f"Processed {i}/{len(fds)} PyPI packages")
    print("PyPI GuardDog data processed successfully")
    print(f"Found {sum([x['issues'] for x in package_findings.values()])} issues in PyPI packages")
    print(f"Found {len(package_findings)} PyPI packages")
    return package_findings

def process_pypi_stats():
    with open('./data/pypi_stats.csv', 'r') as f:
        data = f.read().split("\n")
    pypi_stats = {}
    data = data[1:]
    for line in data:
        if len(line) == 0:
            continue
        parts = line.split(",")
        pypi_stats[parts[1]] = int(parts[0])
    print("PyPI stats processed successfully")
    return pypi_stats

def pypi_get_top(n=100):
    pypi_stats = process_pypi_stats()
    pypi_stats = sorted(pypi_stats.items(), key=lambda x: x[1], reverse=True)
    return [x[0] for x in pypi_stats[:n]]

def process_bandit(sample=0.1, input_dir=BANDIT_RESULTS):
    package_findings = {}
    fds = os.listdir(input_dir)
    i = 0

    if isinstance(sample, float) or isinstance(sample, int):
        ssize = int(sample * len(fds))
        assert sample > 0
        assert ssize > 0
        random.shuffle(fds)
        fds = fds[:ssize]
    elif isinstance(sample, list):
        pnames = [ x.split("_report.json")[0] for x in fds ]
        missing = set(sample).difference(set(pnames))
        fds = set(pnames).intersection(set(sample))
        fds = [ x + "_report.json" for x in fds ]
        if len(missing) > 0:
            print(f"Missing data for {len(missing)} packages, processing {len(fds)}/{len(sample)} packages")
            print(missing)
    
    for fname in fds:
        i += 1
        with open(os.path.join(input_dir, fname), 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                print(f"Skipping {fname} due to JSON error")
                continue
        pname = fname.split("_report.json")[0]
        summary = data["metrics"]["_totals"]
        results = data["results"]
        issues_check = len(results)
        issues = sum([ v for k, v in summary.items() if k.startswith("SEVERITY") ])
        assert issues_check == issues
        package_findings[pname] = {
            "issues": issues,
            "summary": summary,
            "results": results
        }
        if i % 10000 == 0:
            print(f"Processed {i}/{len(fds)} PyPI packages")
    print("PyPI Bandit data processed successfully")
    print(f"Found {sum([x['issues'] for x in package_findings.values()])} issues in PyPI packages")
    print(f"Found {len(package_findings)} PyPI packages")
    return package_findings

def process_dynamic(sample=0.1, input_dir=DYNAMIC_RESULTS):
    package_findings = {}
    fds = os.listdir(input_dir)

    if isinstance(sample, float) or isinstance(sample, int):
        ssize = int(sample * len(fds))
        assert sample > 0
        assert ssize > 0
        random.shuffle(fds)
        fds = fds[:ssize]
    elif isinstance(sample, list):
        missing = set(sample).difference(set(fds))
        fds = set(fds).intersection(set(sample))
        if len(missing) > 0:
            print(f"Missing data for {len(missing)} packages, processing {len(fds)}/{len(sample)} packages")
            print(missing)
    else:
        assert False

    processing_queue = []
    for e in fds:
        if not os.path.isdir(os.path.join(input_dir, e)):
            continue

        pname = e
        
        fpath_package = os.path.join(input_dir, pname, 'package.pcap')
        fpath_dependencies = os.path.join(input_dir, pname, 'dependencies.pcap')
        processing_queue.append((pname, fpath_package, fpath_dependencies))

    with multiprocessing.Pool(NUM_THREADS) as pool:
        res = tqdm.tqdm(pool.imap_unordered(dynamic_worker, processing_queue), total=len(processing_queue))
        for pname, res in zip(fds, res):
            if res is None:
                continue
            package_findings[pname] = res

    print("PyPI Dynamic data processed successfully")
    print(f"Found {len(package_findings)} PyPI packages")
    return package_findings

def dynamic_worker(t):
    pname, fpath_package, fpath_dependencies = t
    PCAP_FILTER = "tcp or udp or icmp"
    PCAP_FILTER_DNS = "dns"

    num_packets = 0
    num_dep_packets = 0
    packets_size = 0
    dep_packets_size = 0

    attempt = 0
    while True:
        try:
            with pyshark.FileCapture(fpath_package, display_filter=PCAP_FILTER) as cap:
                for x in cap:
                    num_packets += 1
                    packets_size += int(x.length)

            with pyshark.FileCapture(fpath_dependencies, display_filter=PCAP_FILTER) as cap:
                for x in cap:
                    num_dep_packets += 1
                    dep_packets_size += int(x.length)

            with pyshark.FileCapture(fpath_package, display_filter=PCAP_FILTER_DNS) as cap:
                packets_dns = [x for x in cap]

            with pyshark.FileCapture(fpath_dependencies, display_filter=PCAP_FILTER_DNS) as cap:
                dep_packets_dns = [x for x in cap]

            break
        except pyshark.capture.capture.TSharkCrashException:
            attempt += 1
            if attempt == 1:
                print(f"Retrying {pname} due to TShark crash")
            else:
                print(f"Skipping {pname} due to TShark crash")
                return None
        except FileNotFoundError:
            print(f"Skipping {pname} due to missing pcap")
            return

    res = {
        "packets": num_packets,
        "dep_packets": num_dep_packets,
        "packets_size": packets_size,
        "dep_packets_size": dep_packets_size,
        "packets_domains": [x.dns.qry_name for x in packets_dns if hasattr(x, 'dns') and hasattr(x.dns, 'qry_name')],
        "dep_packets_domains": [x.dns.qry_name for x in dep_packets_dns if hasattr(x, 'dns') and hasattr(x.dns, 'qry_name')],
    }

    return res

if __name__ == "__main__":
    if not os.path.exists(OUTDIR):
        os.makedirs(OUTDIR)
    
    toplist = pypi_get_top(1000)
    with open(os.path.join(OUTDIR, "top1k.json"), 'w') as f:
        json.dump(toplist, f)
    top10k = pypi_get_top(10000)
    with open(os.path.join(OUTDIR, "top10k.json"), 'w') as f:
        json.dump(top10k, f)

    pypi_bandit_all = process_bandit(sample=1)
    with open(os.path.join(OUTDIR, "bandit_all.json"), 'w') as f:
        json.dump(pypi_bandit_all, f)
    
    dynamic_all = process_dynamic(sample=1)
    with open(os.path.join(OUTDIR, "dynamic_all.json"), 'w') as f:
        json.dump(dynamic_all, f)

    gd_pypi = process_guarddog(sample=1)
    with open(os.path.join(OUTDIR, "gd_all.json"), 'w') as f:
        json.dump(gd_pypi, f)

    gd_pypi = process_guarddog(sample=toplist)
    with open(os.path.join(OUTDIR, "gd_top1k.json"), 'w') as f:
        json.dump(gd_pypi, f)

    gd_pypi = process_guarddog(sample=top10k)
    with open(os.path.join(OUTDIR, "gd_top10k.json"), 'w') as f:
        json.dump(gd_pypi, f)
    
    gd_pypi = process_guarddog(sample=0.1)
    with open(os.path.join(OUTDIR, "gd_10pct_sample.json"), 'w') as f:
        json.dump(gd_pypi, f)
    
    bandit_10pct_sample = process_bandit(sample=0.1)
    with open(os.path.join(OUTDIR, "bandit_10pct_sample.json"), 'w') as f:
        json.dump(bandit_10pct_sample, f)
    
    bandit_top1k = process_bandit(sample=toplist)
    with open(os.path.join(OUTDIR, "bandit_top1k.json"), 'w') as f:
        json.dump(bandit_top1k, f)
    
    bandit_top10k = process_bandit(sample=top10k)
    with open(os.path.join(OUTDIR, "bandit_top10k.json"), 'w') as f:
        json.dump(bandit_top10k, f)
    
    dynamic_top1k = process_dynamic(sample=toplist)
    with open(os.path.join(OUTDIR, "dynamic_top1k.json"), 'w') as f:
        json.dump(dynamic_top1k, f)
    
    dynamic_top10k = process_dynamic(sample=top10k)
    with open(os.path.join(OUTDIR, "dynamic_top10k.json"), 'w') as f:
        json.dump(dynamic_top10k, f)
    
    dynamic_10pct_sample = process_dynamic(sample=0.1)
    with open(os.path.join(OUTDIR, "dynamic_10pct_sample.json"), 'w') as f:
        json.dump(dynamic_10pct_sample, f)

