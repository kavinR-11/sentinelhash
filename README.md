SentinelHash 🔐

File Integrity Monitoring & Malware Hash Detection Tool

SentinelHash is a Python-based security tool that helps detect unauthorized file changes on a system.
It works by creating a cryptographic baseline of files using SHA-256 hashing, then comparing future scans against that baseline to identify:

Modified files

Newly added files

Deleted files

Files matching known malware hashes

The tool also generates incident-response-ready JSON reports, making it suitable for blue-team learning, SOC fundamentals, and security project portfolios.

🚀 How SentinelHash Works (High-Level)

You create a baseline of a directory when the system is in a trusted state

SentinelHash hashes every file and stores the results securely

On future scans, SentinelHash:

re-hashes the files

compares them against the baseline

reports any changes

File hashes are optionally checked against a known malware hash list

A structured forensic report is generated automatically

No antivirus engines. No signatures pulled from the internet.
Just integrity, comparison, and evidence.

📦 Project Structure
sentinelhash/
├── sentinelhash.py          # Main tool
├── malware_hashes.txt       # Offline known-bad hash list
├── baseline.json            # Generated baseline (optional, not committed)
├── sentinelhash_report_*.json  # Generated IR reports
├── README.md
└── .gitignore

🛠️ Requirements

Python 3.9+

No external dependencies (standard library only)

🧭 Step-by-Step Usage Guide
Step 1: Clone the Repository
git clone https://github.com/yourusername/sentinelhash.git
cd sentinelhash

Step 2: (Optional) Add Malware Hashes

Edit malware_hashes.txt and add SHA-256 hashes you want to flag as malicious.

Example:

e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa


Each hash must be on a new line.

Step 3: Create a Baseline (First Run)

Run SentinelHash on a directory you trust.

python sentinelhash.py C:\Users\YourName\Downloads


What this does:

Recursively scans the directory

Hashes each file using SHA-256

Saves the result as baseline.json

⚠️ Important:
Create the baseline only when the directory is in a known-safe state.

Step 4: Make File Changes (Test Detection)

Try one or more of the following:

Modify an existing file

Create a new file

Delete a file

Step 5: Run Integrity Check
python sentinelhash.py --check C:\Users\YourName\Downloads


SentinelHash will now:

Compare current files against the baseline

Detect MODIFIED, NEW, and DELETED files

Flag files matching known malware hashes

Generate a timestamped incident response report

Example output:

[NEW]      C:\Users\...\evil.exe ⚠️ KNOWN MALWARE
[MODIFIED] C:\Users\...\notes.txt
[DELETED]  C:\Users\...\old.log

Step 6: Review the Incident Report

After every --check, a report is created:

sentinelhash_report_YYYY-MM-DD_HH-MM-SS.json


The report includes:

Scan timestamp

Target directory

Modified files

New files

Deleted files

Malware detections

This file can be used for:

Incident response documentation

SOC-style analysis

Security reporting practice
