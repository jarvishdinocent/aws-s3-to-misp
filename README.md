# AWS S3 to MISP IOC Ingestion Script

This Python script automates the process of retrieving daily threat feed files from AWS S3 and ingesting them into a MISP (Malware Information Sharing Platform) instance as new events with attached attributes (IOCs). The script is designed for scheduled or on-demand use and avoids duplication of data in MISP.

---

## Features

- ✅ Securely connects to AWS S3 using credentials
- ✅ Downloads threat intelligence feeds based on the current date
- ✅ Automatically creates a new MISP event daily
- ✅ Adds file content as attributes (indicators of compromise)
- ✅ Skips duplicate attributes already existing in MISP
- ✅ Easy to schedule via `cron`

---

## Requirements

- Python 3.8 or higher
- AWS credentials with permission to access specific S3 buckets
- MISP instance and API key with full permissions

### Install Python Dependencies

Use the following command to install required libraries:

```bash
pip install -r requirements.txt
