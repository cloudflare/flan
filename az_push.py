import sys
import os
from azure.storage.blob import BlobServiceClient

filename = sys.argv[1]

account_url = os.getenv('AZURE_ACCOUNT_URL')
account_key = os.getenv('AZURE_ACCOUNT_KEY')
container_name = os.getenv('bucket')

try:
    blob_service_client = BlobServiceClient(
        account_url=account_url, credential=account_key
    )
    blob_client = blob_service_client.get_blob_client(
        container=container_name, blob=filename
    )

    with open(filename, "rb") as data:
        blob_client.upload_blob(data)
except Exception as e:
    print('Error uploading to azure')
    print(e)
