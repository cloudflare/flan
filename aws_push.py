import sys
import os
import boto3


def main():
    filename = sys.argv[1]

    s3_client = boto3.client('s3')
    try:
        s3_client.upload_file("/" + filename, os.getenv('bucket'), filename)
    except Exception as err:
        print('Error uploading to s3')
        print(err)


if __name__ == "__main__":
    main()
