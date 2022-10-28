from s3 import S3, S3Args
import pulumi_aws as aws
from pulumi import Output

current = aws.get_caller_identity()
s3_canonical_user = aws.s3.get_canonical_user_id()

# Extra resources for example
key = aws.kms.Key("s3_encryption_key",
                  deletion_window_in_days=7,
                  description="S3 encryption key for complete example",
                  enable_key_rotation=True,
                  tags={
                      "Owner": "Melissa"
                  })

s3_logging_bucket = S3("s3-logging-bucket", S3Args(
    bucket_prefix="s3-logging-",
    acl="private",
    tags={
        "Owner": "Melissa"
    },
    sse_algorithm="AES256",
    lifecycle_status_enabled=True,
    lifecycle_rules=[
        {
            "id": "lifecycle",
            "status": "Enabled",
            "expiration": {
                "days": 30
            },
            "abort_incomplete_multipart_upload": {
                "days_after_initiation": 7
            }
        }
    ],
    bucket_elb_logging=True,
    bucket_policy_configuration=[
        {
            # Not sure if Pulumi has a function to get ELB service account, nothing obvious stood out
            "elb_account_id": "797873946194",
        }
    ],
    force_destroy=True
))

s3_bucket = S3("pulumi-s3", S3Args(
    bucket_prefix="test-pulumi-s3-",
    acl="private",
    tags={
        "Owner": "Melissa"
    },
    sse_algorithm="aws:kms",
    kms_key_id=key.arn,
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
    force_destroy=True,
    versioning_configuration=[
        {
            "status": "Enabled"
        }
    ],
    object_lock_enabled=True,
    object_lock_configuration=[
        {
            "mode": "GOVERNANCE",
            "years": 1
        }
    ],
    logging_configuration=[
        {
            "target_bucket": s3_logging_bucket.bucket_name,
            "target_prefix": "test-pulumi-s3/",
        }
    ],
    # This needs further testing
    website=[
        {
            "error_document": "error.html",
            "index_document": "index.html"
        }
    ],
    intelligent_tiering_configuration=[
        {
            "name": "test",
            "status": "Enabled",
            "tierings": [
                {
                    "access_tier": "ARCHIVE_ACCESS",
                    "days": 180
                },
                {
                    "access_tier": "DEEP_ARCHIVE_ACCESS",
                    "days": 360
                }
            ]
        }
    ],
    metric_configuration=[
        {
            "name": "test"
        }
    ],
    analytics_configuration=[
        {
            "data_export_bucket_arn": "arn:aws:s3:::pulumi-state-maf"
        }
    ],
    # The encryption portion is not working as desired for this section
    # inventory_configuration=[
    #     {
    #         "schedule_frequency": "Daily",
    #         "destination_format": "CSV"
    #     },
    #     {
    #         "schedule_frequency": "Weekly",
    #         "destination_format": "CSV"
    #     }
    # ]
))
