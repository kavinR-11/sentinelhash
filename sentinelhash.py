import os
import hashlib
import json
import argparse
from datetime import datetime

def hash_file(path):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def generate_baseline(directory):
    hashes = {}
    for root, _, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            hashes[full_path] = hash_file(full_path)
    return hashes

def save_baseline(hashes):
    data = {
        "created_at": datetime.utcnow().isoformat(),
        "files": hashes
    }
    with open("baseline.json", "w") as f:
        json.dump(data, f, indent=4)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelHash - File Integrity Checker")
    parser.add_argument("path", help="Directory path to scan")
    args = parser.parse_args()

    print("[*] Scanning directory...")
    hashes = generate_baseline(args.path)
    save_baseline(hashes)
    print("[+] Baseline created: baseline.json")
