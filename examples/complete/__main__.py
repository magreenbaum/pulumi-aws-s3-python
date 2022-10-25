from s3 import S3, S3Args

s3_bucket = S3("pulumi-s3", S3Args(
    bucket="test-pulumi-s3",
    tags={
        "example": "true"
    },
    sse_algorithm="AES256",
    lifecycle_status_enabled=True,
    lifecycle_rules=[
        {
            "id": "lifecycle",
            "status": "Enabled",
            "noncurrent_version_expiration": {
                "noncurrent_days": 2
            }
        },
        {
            "id": "lifecycle2",
            "status": "Disabled",
            "abort_incomplete_multipart_upload": {
                "days_after_initiation": 7
            },
            "expiration": {
                "days": 30
            }
        }
    ],
    object_lock_enabled=True,
    object_lock_configuration=[
        {
            "mode": "GOVERNANCE",
            "years": 1
        }
    ],
    # This needs further testing
    website=[
        {
            "error_document": "error.html",
            "index_document": "index.html"
        }
    ]
))
