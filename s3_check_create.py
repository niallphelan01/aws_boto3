
#!/usr/bin/env python3
import sys
import boto3

def check_bucket(bucket):
    s3 = boto3.resource("s3")
    for bucket in s3.buckets.all():
      print (bucket.name)
    try:
        if bucket_exists(bucket.name):
           print("Bucket Exists!")
        else:
           print ("no existing bucket: " + bucket.name)
    except:
       print("error")


def bucket_exists(bucket):
  s3 = boto3.resource('s3')
  return s3.Bucket(bucket) in s3.buckets.all()
