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

event_tags = ["source:aws-s3-script", "daily-threat-feed", "format:csv"]

if not misp_verifycert:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    warnings.filterwarnings("ignore", category=UserWarning)

# Initialize MISP
misp = PyMISP(misp_url, misp_key, misp_verifycert)
event = MISPEvent()
event.info = f"Daily S3 Threat Feed - {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
event.distribution = 1
event.threat_level_id = 2
event.analysis = 0
event = misp.add_event(event)

# Add tags
for tag in event_tags:
    try:
        misp.tag(event["Event"]["uuid"], tag)
    except Exception as e:
        print(f"⚠️ Failed to tag event with '{tag}': {e}")

# Fetch existing attributes to deduplicate
existing_values = {attr['value'] for attr in event['Attribute']} if 'Attribute' in event else set()

# AWS client
s3 = boto3.client(
    's3',
    region_name=aws_region,
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key
)

def fetch_and_parse_csv(bucket, key, seen):
    try:
        print(f"📥 Downloading {key} from {bucket}")
        obj = s3.get_object(Bucket=bucket, Key=key)

        if key.endswith('.gz'):
            with gzip.GzipFile(fileobj=obj['Body']) as gz:
                content = gz.read().decode('utf-8')
        else:
            content = obj['Body'].read().decode('utf-8')

        csv_reader = csv.reader(io.StringIO(content))
        headers = next(csv_reader, None)  # Skip header

        for row in csv_reader:
            for col in row:
                val = col.strip()
                if not val or val in seen or val in existing_values:
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
                    elif "403" in err_msg:
                        print(f"⚠️ MISP 403 - Attribute exists or forbidden: {val}")
                    else:
                        print(f"❌ Error adding {val}: {err_msg}")

    except Exception as e:
        print(f"❌ Failed to process object {key} from {bucket}: {e}")

# Fetch and process files
seen_values = set()

for bucket in s3_buckets:
    print(f"🔍 Scanning bucket: {bucket}")
    try:
        response = s3.list_objects_v2(Bucket=bucket, Prefix=log_prefix)
        if 'Contents' in response:
            for obj in response['Contents']:
                key = obj['Key']
                if key.endswith('.csv') or key.endswith('.csv.gz'):
                    fetch_and_parse_csv(bucket, key, seen_values)
        else:
            print(f"⚠️ No files found in {bucket}/{log_prefix}")
    except s3.exceptions.NoSuchBucket:
        print(f"❌ Bucket not found: {bucket}")
    except Exception as e:
        print(f"❌ Failed to list objects in bucket {bucket}: {e}")

# Publish event
try:
    misp.publish(event)
    print("✅ MISP event published successfully.")
except Exception as e:
    print(f"❌ Failed to publish event: {e}")
