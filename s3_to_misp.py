#!/usr/bin/env python3

import boto3
import csv
import gzip
import io
import os
import urllib3
import warnings
from datetime import datetime, timezone
from pymisp import PyMISP, MISPEvent, MISPAttribute

# ───── Configuration ─────
aws_region = 'ap-south-1'
s3_buckets = [
    'k457-4e2j-9189-97h1cb-malcsv', # Replace it with your original bucket name
    '8rfc-4856-938c-0c39a7-csvioc'  # Replace it with your original bucket name
]
log_prefix = f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}/"  # Daily folder format

misp_url = 'your_MISP_URL'
misp_key = 'your_misp_api_key'
misp_verifycert = False  # Set to True if using valid SSL cert

# ───── Suppress SSL Warnings (optional) ─────
if not misp_verifycert:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    warnings.filterwarnings("ignore", category=UserWarning)

# ───── MISP Initialization ─────
misp = PyMISP(misp_url, misp_key, misp_verifycert)
event = MISPEvent()
event.info = f"Daily S3 Threat Feed - {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
event.distribution = 0
event.threat_level_id = 2
event.analysis = 0
event = misp.add_event(event)

# ───── AWS Client ─────
s3 = boto3.client('s3', region_name=aws_region)

def fetch_and_parse_csv(bucket, key):
    try:
        print(f"📥 Downloading {key} from {bucket}")
        obj = s3.get_object(Bucket=bucket, Key=key)

        if key.endswith('.gz'):
            with gzip.GzipFile(fileobj=obj['Body']) as gz:
                content = gz.read().decode('utf-8')
        else:
            content = obj['Body'].read().decode('utf-8')

        csv_reader = csv.reader(io.StringIO(content))
        headers = next(csv_reader)

        for row in csv_reader:
            for col in row:
                attribute = MISPAttribute()
                attribute.value = col.strip()
                attribute.type = 'text'
                try:
                    misp.add_attribute(event, attribute)
                except Exception as e:
                    if "already exists" in str(e):
                        print(f" Duplicate attribute skipped: {col}")
                    else:
                        print(f" Error adding attribute: {e}")

    except Exception as e:
        print(f" Failed to process object {key} from {bucket}: {e}")

# ───── Fetch and Process Files from S3 ─────
for bucket in s3_buckets:
    print(f" Scanning bucket: {bucket}")
    try:
        response = s3.list_objects_v2(Bucket=bucket, Prefix=log_prefix)
        if 'Contents' in response:
            for obj in response['Contents']:
                key = obj['Key']
                if key.endswith('.csv') or key.endswith('.csv.gz'):
                    fetch_and_parse_csv(bucket, key)
        else:
            print(f" No files found in {bucket}/{log_prefix}")
    except s3.exceptions.NoSuchBucket:
        print(f" Bucket not found: {bucket}")
    except Exception as e:
        print(f" Failed to list objects in bucket {bucket}: {e}")
