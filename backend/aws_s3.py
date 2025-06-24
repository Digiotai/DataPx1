import time
import boto3
import pickle
import json
import io
import pandas as pd
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError


class s3_crud:
    def __init__(self, access_key, secret_key, region):
        try:
            self.region = region
            self.s3_client = boto3.client('s3',
                                          aws_access_key_id=access_key,
                                          aws_secret_access_key=secret_key,
                                          region_name=region)
            self.s3_resource = boto3.resource('s3',
                                              aws_access_key_id=access_key,
                                              aws_secret_access_key=secret_key,
                                              region_name=region)
        except NoCredentialsError:
            print("AWS credentials not available.")
        except PartialCredentialsError:
            print("Incomplete AWS credentials configuration.")

    def check_s3_file(self, bucket_name, object_key):
        try:
            self.s3_client.head_object(Bucket=bucket_name, Key=object_key)
            return True
        except Exception as e:
                return False

    def upload_file_obj_to_s3(self, file_obj, bucket_name, object_name, file_format=None):
        if not self.check_s3_bucket(bucket_name):
            return 'Upload failed'

        if file_format:
            buffer = io.BytesIO()
            if file_format == 'csv':
                file_obj.to_csv(buffer, index=False)
            elif file_format == 'json':
                buffer.write(json.dumps(file_obj).encode('utf-8'))
            buffer.seek(0)
            file_obj = buffer


        try:
            self.s3_client.upload_fileobj(file_obj, bucket_name, object_name)
            print(f"File uploaded to {bucket_name}/{object_name}")
            return True
        except Exception as e:
            print(f"Upload failed: {e}")
            return False

    def upload_pickle(self, obj, bucket_name, object_name):
        if not self.check_s3_bucket(bucket_name):
            return 'Upload failed'

        try:
            pkl_bytes = pickle.dumps(obj)
            self.s3_client.put_object(Body=pkl_bytes, Bucket=bucket_name, Key=object_name)
            print(f"Pickle object uploaded as {object_name} to bucket {bucket_name}")
            return True
        except Exception as e:
            print(f"Failed to upload pickle object: {e}")
            return False

    def upload_json(self, data, bucket_name, object_name):
        if not self.check_s3_bucket(bucket_name):
            return 'Upload failed'

        try:
            json_str = json.dumps(data)
            self.s3_client.put_object(Body=json_str, Bucket=bucket_name, Key=object_name)
            print(f"JSON object uploaded as {object_name} to bucket {bucket_name}")
            return True
        except Exception as e:
            print(f"Failed to upload JSON object: {e}")
            return False

    def download_file(self, bucket_name, object_key, file_format):
        buffer = io.BytesIO()
        self.s3_client.download_fileobj(bucket_name, object_key, buffer)
        buffer.seek(0)

        if file_format == 'csv':
            return pd.read_csv(buffer)

        elif file_format == 'json':
            data = buffer.read().decode('utf-8')
            return json.loads(data)

        elif file_format == 'pkl':
            return pickle.load(buffer)

    def delete_s3_folder(self, bucket_name, folder_prefix):
        try:
            bucket = self.s3_resource.Bucket(bucket_name)

            # Delete all objects under the prefix
            response = bucket.objects.filter(Prefix=folder_prefix).delete()

            # Handle empty folder (no objects found case)
            if not response or (isinstance(response, list) and not response[0].get('Deleted')):
                print(f"No files found under folder '{folder_prefix}'.")

            # Delete potential folder marker object
            try:
                self.s3_client.delete_object(Bucket=bucket_name, Key=folder_prefix.rstrip('/') + '/')
            except self.s3_client.exceptions.NoSuchKey:
                print("No folder marker object found.")
            except Exception as e:
                print("Folder marker delete failed:", e)

            print(f"Folder '{folder_prefix}' deleted successfully.")

        except self.s3_client.exceptions.NoSuchBucket:
            print(f"Bucket '{bucket_name}' does not exist.")
        except Exception as e:
            print(f"Error deleting folder '{folder_prefix}': {e}")

    def create_s3_bucket(self, bucket_name):
        try:
            self.s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': self.region}
            )
            print(f"Bucket {bucket_name} created successfully.")
            return True
        except Exception as e:
            print(e)
            return False

    def check_s3_bucket(self, bucket_name):
        try:
            buckets = self.s3_client.list_buckets()
            bucket_names = [b['Name'] for b in buckets['Buckets']]
            if bucket_name in bucket_names:
                return True
            else:
                return self.create_s3_bucket(bucket_name)
        except Exception as e:
            print(e)
            return False


# Example usage
if __name__ == "__main__":
    file_name = "../data.csv"  # Replace with your file path
    bucket_name = f"aipriori-backend"
    key = f'bucketstr{int(time.time())}/data.csv'

    s3_obj = s3_crud('AKIA5V6I64OZ5XXUDZXY', 'Hsr29bCbB6RRsC5wkdFL48B9llIlk+c6//GFMmvJ', 'ap-southeast-1')

    # Upload local file
    # s3_obj.upload_to_s3(file_name, bucket_name, key)

    s3_obj.delete_s3_folder(bucket_name,"bucketstr1749637965")

    # Upload pickle directly
    # my_pickle_data = {"name": "Alimi", "model": [1, 2, 3]}
    # s3_obj.upload_pickle(my_pickle_data, bucket_name, "my_model.pkl")
    #
    # # Upload JSON directly
    # my_json_data = {"project": "S3 Upload", "status": "Success"}
    # s3_obj.upload_json(my_json_data, bucket_name, "my_data.json")

    # Download pickle
    # downloaded_pickle = s3_obj.download_pickle(bucket_name, "my_model.pkl")
    # print("Downloaded Pickle:", downloaded_pickle)
    #
    # # Download JSON
    # downloaded_json = s3_obj.download_json(bucket_name, "my_data.json")
    # print("Downloaded JSON:", downloaded_json)
    #
    # # Download file
    # s3_obj.download_file(bucket_name, "my_data.json", "downloaded_my_data.json")
