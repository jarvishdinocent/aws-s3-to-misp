#!/usr/bin/env python3

import boto3
import csv
import gzip
import io
import urllib3
import warnings
from datetime import datetime, timezone
from pymisp import PyMISP, MISPEvent, MISPAttribute

# Configuration
aws_access_key_id = 'YOUR_AWS_ACCESS_KEY'
aws_secret_access_key = 'YOUR_AWS_SECRET_KEY'
aws_region = 'ap-south-1'

s3_buckets = [
    'k457-4e2j-9189-97h1cb-malcsv',
    '8rfc-4856-938c-0c39a7-csvioc'
]

log_prefix = f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}/"

misp_url = 'YOUR_MISP_URL'
misp_key = 'YOUR_MISP_API_KEY'
misp_verifycert = False

# Optional tags to help context
event_tags = ["source:aws-s3-script", "daily-threat-feed", "format:csv"]

if not misp_verifycert:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    warnings.filterwarnings("ignore", category=UserWarning)

# MISP Setup
misp = PyMISP(misp_url, misp_key, misp_verifycert)
event = MISPEvent()
event.info = f"Daily S3 Threat Feed - {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
event.distribution = 1  # Community only
event.threat_level_id = 2  # Medium
event.analysis = 0  # Initial analysis
event = misp.add_event(event)

# Add tags to event
for tag in event_tags:
    try:
        misp.tag(event["Event"]["uuid"], tag)
    except Exception as e:
        print(f"⚠️ Failed to tag event with '{tag}': {e}")

# AWS Client
s3 = boto3.client(
    's3',
    region_name=aws_region,
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key
)

def fetch_and_parse_csv(bucket, key):
    seen = set()
    try:
        print(f"📥 Downloading {key} from {bucket}")
        obj = s3.get_object(Bucket=bucket, Key=key)

        if key.endswith('.gz'):
            with gzip.GzipFile(fileobj=obj['Body']) as gz:
                content = gz.read().decode('utf-8')
        else:
            content = obj['Body'].read().decode('utf-8')

        csv_reader = csv.reader(io.StringIO(content))
        headers = next(csv_reader, None)

        for row in csv_reader:
            for col in row:
                val = col.strip()
                if not val or val in seen:
                    continue
                seen.add(val)

                attribute = MISPAttribute()
                attribute.value = val
                attribute.type = 'text'

                try:
                    misp.add_attribute(event, attribute)
                except Exception as e:
                    err_msg = str(e)
                    if "already exists" in err_msg or "Value cannot be empty" in err_msg:
                        print(f"⚠️ Skipped duplicate or empty: {val}")
                    else:
                        print(f"❌ Error adding {val}: {err_msg}")

    except Exception as e:
        print(f"❌ Failed to process object {key} from {bucket}: {e}")

# Fetch and Process Files from S3
for bucket in s3_buckets:
    print(f"🔍 Scanning bucket: {bucket}")
    try:
        response = s3.list_objects_v2(Bucket=bucket, Prefix=log_prefix)
        if 'Contents' in response:
            for obj in response['Contents']:
                key = obj['Key']
                if key.endswith('.csv') or key.endswith('.csv.gz'):
                    fetch_and_parse_csv(bucket, key)
        else:
            print(f"⚠️ No files found in {bucket}/{log_prefix}")
    except s3.exceptions.NoSuchBucket:
        print(f"❌ Bucket not found: {bucket}")
    except Exception as e:
        print(f"❌ Failed to list objects in bucket {bucket}: {e}")

# Publish the event at the end
try:
    misp.publish(event)
    print("✅ Event published successfully.")
except Exception as e:
    print(f"❌ Failed to publish event: {e}")
