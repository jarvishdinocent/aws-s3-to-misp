# AWS S3 Threat Feed to MISP Integration

This script automates the ingestion of daily threat feed data stored in AWS S3 buckets and uploads it into a MISP instance as a new event. It fetches `.csv` files from S3, parses the indicators (such as malware hashes, IPs, or domains), and pushes them as attributes into a newly created MISP event.

## Features

- ✅ Fetches data from multiple S3 buckets.
- ✅ Dynamically creates a new event in MISP for each execution.
- ✅ Adds attributes parsed from CSV files into the MISP event.
- ✅ Automatically runs once per day via `cron`.
- ✅ Logs warnings and gracefully handles duplicates.

## Prerequisites

- Access to AWS S3 (with valid access/secret keys and proper permissions to read the buckets).
- A running MISP instance with an API key that has full permission.
- Python 3.12+ installed (or compatible version).
- Internet access (to fetch packages and reach AWS/MISP).

## Installation

1. **Clone or copy this repository**:

```bash
git clone https://github.com/yourusername/aws-s3-misp-ingestor.git
cd aws-s3-misp-ingestor

2. **Install required dependencies**:
pip install -r requirements.txt

3. **Make the script executable**:

chmod +x s3_to_misp.py

4. **Run the script manually**:

python3 s3_to_misp.py

5.**Cron Setup (Optional)**:

crontab -e

6. **Add the following line to run the script daily at 6 AM**:

0 6 * * * /path/to/venv/bin/python /path/to/s3_to_misp.py
