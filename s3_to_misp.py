#!/usr/bin/env python3

import boto3
import csv
import gzip
import io
import urllib3
import warnings
from datetime import datetime, timezone
from pymisp import PyMISP, MISPEvent, MISPAttribute

# ========== AWS CONFIGURATION ==========
aws_access_key_id = 'YOUR_AWS_ACCESS_KEY'           # ← replace this
aws_secret_access_key = 'YOUR_AWS_SECRET_KEY'       # ← replace this
aws_region = 'ap-south-1'

s3_buckets = [
    'k457-4e2j-9189-97h1cb-malcsv',  # ← Dummy Bucket Name 
    '8rfc-4856-938c-0c39a7-csvioc'   # ← Dummy Bucket Name
]
log_prefix = f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}/"

# ========== MISP CONFIGURATION ==========
misp_url = 'http://localhost:8080'   # ← replace if using external MISP
misp_key = 'YOUR_MISP_API_KEY'       # ← replace this
misp_verifycert = False              # Set to True if using a valid cert

# ========== SSL WARNINGS ==========
if not misp_verifycert:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    warnings.filterwarnings("ignore", category=UserWarning)

# ========== INIT MISP ==========
misp = PyMISP(misp_url, misp_key, misp_verifycert)
event = MISPEvent()
event.info = f"Daily S3 Threat Feed - {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
event.distribution = 1     # ✅ Community visibility
event.threat_level_id = 2  # Medium
event.analysis = 0         # Initial
event = misp.add_event(event)

# ========== INIT AWS S3 CLIENT ==========
s3 = boto3.client(
    's3',
    region_name=aws_region,
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key
)

# ========== HELPER ==========
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
        headers = next(csv_reader, None)

        seen = set()

        for row in csv_reader:
            for col in row:
                val = col.strip()
                if not val or val in seen:
                    continue  # skip duplicates and blanks
                seen.add(val)

                attribute = MISPAttribute()
                attribute.value = val
                attribute.type = 'text'

                try:
                    misp.add_attribute(event, attribute)
                except Exception as e:
                    error = str(e)
                    if "already exists" in error or "Value cannot be empty" in error:
                        continue
                    print(f"⚠️ Error adding {val}: {error.splitlines()[0]}")

    except Exception as e:
        print(f"❌ Failed to process {key} from {bucket}: {e}")

# ========== MAIN ==========
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
            print(f"ℹ️ No files found in {bucket}/{log_prefix}")
    except s3.exceptions.NoSuchBucket:
        print(f"🚫 Bucket not found: {bucket}")
    except Exception as e:
        print(f"❌ Could not list {bucket}: {e}")
