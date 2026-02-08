import os
import hashlib
import json
import argparse
IGNORE_EXTENSIONS = {
    ".log",
    ".tmp",
    ".cache",
    ".part"
}

from datetime import datetime


def hash_file(path):
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (OSError, PermissionError):
        return None


def generate_baseline(directory):
    hashes = {}

    for root, _, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            file_hash = hash_file(full_path)

            if file_hash:
                hashes[full_path] = file_hash
            else:
                print(f"[!] Skipped unreadable file: {full_path}")

    return hashes


def save_baseline(hashes):
    data = {
        "created_at": datetime.utcnow().isoformat(),
        "files": hashes
    }

    with open("baseline.json", "w") as f:
        json.dump(data, f, indent=4)


def load_baseline():
    if not os.path.exists("baseline.json"):
        print("[!] baseline.json not found. Create a baseline first.")
        exit(1)

    with open("baseline.json", "r") as f:
        data = json.load(f)

    return data["files"]


def compare_files(old, current):
    old_set = set(old.keys())
    current_set = set(current.keys())

    modified = []
    new_files = []
    deleted = []

    for path in old_set & current_set:
        if old[path] != current[path]:
            modified.append(path)

    for path in current_set - old_set:
        new_files.append(path)

    for path in old_set - current_set:
        deleted.append(path)

    return modified, new_files, deleted


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SentinelHash - File Integrity Checker"
    )

    parser.add_argument(
        "path",
        help="Directory path to scan"
    )

    parser.add_argument(
        "--check",
        action="store_true",
        help="Check current state against baseline"
    )

    args = parser.parse_args()

    if args.check:
        print("[*] Loading baseline...")
        old_files = load_baseline()

        print("[*] Rescanning directory...")
        current_files = generate_baseline(args.path)

        modified, new_files, deleted = compare_files(old_files, current_files)

        print("\n=== Scan Results ===")

        for f in modified:
            print(f"[MODIFIED] {f}")

        for file in files:
    _, ext = os.path.splitext(file)
    if ext.lower() in IGNORE_EXTENSIONS:
        continue

    full_path = os.path.join(root, file)
    file_hash = hash_file(full_path)

    if file_hash:
        hashes[full_path] = file_hash
    else:
        print(f"[!] Skipped unreadable file: {full_path}")

        for f in deleted:
            print(f"[DELETED]  {f}")

        if not (modified or new_files or deleted):
            print("[+] No changes detected. System integrity intact.")

    else:
        print("[*] Scanning directory...")
        hashes = generate_baseline(args.path)
        save_baseline(hashes)
        print("[+] Baseline created: baseline.json")


