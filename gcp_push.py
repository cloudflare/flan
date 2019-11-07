from google.cloud import storage
import sys
import os

filename = sys.argv[1]

client = storage.Client()
bucket = client.bucket(os.getenv('bucket'))
blob = bucket.blob(filename)
blob.upload_from_filename(filename)
