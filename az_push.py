import sys
import os
from azure.storage.blob import BlockBlobService, PublicAccess, ContentSettings

filename = sys.argv[1]

account_name = os.getenv('AZURE_ACCOUNT_NAME')
account_key = os.getenv('AZURE_ACCOUNT_KEY')
container_name = os.getenv('bucket')

try:
    blob_service = BlockBlobService(account_name, account_key)
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=filename)

    with open(filename, "rb") as data:
        blob_client.upload_blob(data)
except Exception, e:
    print('Error uploading to azure')
    print(e)
