from s3 import S3, S3Args

s3_bucket = S3("pulumi-s3", S3Args(
    bucket="test-pulumi-s3",
    tags={
        "example": "true"
    },
    sse_algorithm="AES256",
))
