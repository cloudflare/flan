import sys
import os
from google.cloud import storage


def main():
    filename = sys.argv[1]

    client = storage.Client()
    bucket = client.bucket(os.getenv('bucket'))
    blob = bucket.blob(filename)
    blob.upload_from_filename(filename)


if __name__ == "__main__":
    main()
