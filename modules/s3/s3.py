import pulumi
from typing import Mapping, Sequence
from pulumi_aws import s3

class S3Args:
    def __init__(self,
                 tags: Mapping[str, str],
                 bucket: str,
                 acl: str = "private",
                 sse_algorithm: str = None,
                 block_public_acls: bool = True,
                 block_public_policy: bool = True,
                 ignore_public_acls: bool = True,
                 restrict_public_buckets: bool = True,
                 expected_bucket_owner: str = None,
                 kms_key_id: str = None,
                 mfa: str = None,
                 versioning_status: str = "Enabled",
                 target_bucket: str = None,
                 target_prefix: str = None):

        # Bucket
        self.tags = tags
        self.bucket = bucket

        # ACL
        self.acl = acl

        # Encryption
        self.kms_key_id = kms_key_id
        self.sse_algorithm = sse_algorithm
        self.expected_bucket_owner = expected_bucket_owner

        # Block Public Access
        self.block_public_acls = block_public_acls
        self.block_public_policy = block_public_policy
        self.ignore_public_acls = ignore_public_acls
        self.restrict_public_buckets = restrict_public_buckets

        # Versioning
        self.mfa = mfa
        self.versioning_status = versioning_status

        # Logging
        self.target_bucket = target_bucket
        self.target_prefix = target_prefix

class S3(pulumi.ComponentResource):
    """
    Notes go here
    """
    def __init__(self,
                 resource_name: str,
                 args: S3Args,
                 opts: pulumi.ResourceOptions = None):

        super().__init__('S3', resource_name, None, opts)

        self.resource_name = resource_name
        self.bucket_name = args.bucket
        self.tags = args.tags

        # s3 bucket
        self.s3_bucket = s3.BucketV2(
            f"{resource_name}-bucket",
            bucket=args.bucket,
            tags=args.tags,
            opts=pulumi.ResourceOptions(
                parent=self,
        ))

        # Bucket ACL
        self.acl = s3.BucketAclV2(
            f"{resource_name}-acl",
            bucket=self.s3_bucket.id,
            acl=args.acl,
        )

        # Default Encryption
        self.default_encryption = s3.BucketServerSideEncryptionConfigurationV2(
            f"{resource_name}-encryption",
            bucket=self.s3_bucket.id,
            expected_bucket_owner=args.expected_bucket_owner,
            rules=[s3.BucketServerSideEncryptionConfigurationV2RuleArgs(
                apply_server_side_encryption_by_default=s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs(
                    kms_master_key_id=args.kms_key_id,
                    sse_algorithm=args.sse_algorithm,
                ))
            ],
            opts=pulumi.ResourceOptions(
                parent=self,
            )
        )

        # Public Access Block
        self.public_access_block = s3.BucketPublicAccessBlock(
            f"{resource_name}-public-access-block",
            bucket=self.s3_bucket.id,
            block_public_acls=args.block_public_acls,
            block_public_policy=args.block_public_policy,
            ignore_public_acls=args.ignore_public_acls,
            restrict_public_buckets=args.restrict_public_buckets,
            opts=pulumi.ResourceOptions(
                parent=self,
            )
        )

        # Bucket Versioning
        self.versioning = s3.BucketVersioningV2(
            f"{resource_name}-versioning",
            bucket=self.s3_bucket.id,
            expected_bucket_owner=args.expected_bucket_owner,
            mfa=args.mfa,
            versioning_configuration=s3.BucketVersioningV2VersioningConfigurationArgs(
                status=args.versioning_status
            ),
            opts=pulumi.ResourceOptions(
                parent=self,
            )
        )

        # Bucket logging
        if args.target_bucket:
            s3.BucketLoggingV2(
            f"{resource_name}-logging",
                bucket=self.s3_bucket.id,
                expected_bucket_owner=args.expected_bucket_owner,
                target_bucket=args.target_bucket,
                target_prefix=args.target_prefix,
                opts=pulumi.ResourceOptions(
                    parent=self,
            )
        )

        super().register_outputs({})