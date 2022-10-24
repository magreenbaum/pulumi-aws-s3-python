import pulumi
from typing import Mapping, Sequence
from pulumi_aws import s3


class S3Args:
    def __init__(self,
                 tags: Mapping[str, str],
                 bucket: str = None,
                 bucket_prefix: str = None,
                 force_destroy: bool = False,
                 object_lock_enabled: bool = False,
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
                 versioning_mfa_delete: str = "Disabled",
                 target_bucket: str = None,
                 target_prefix: str = None,
                 lifecycle_status_enabled: bool = False,
                 lifecycle_rules: Sequence[s3.BucketLifecycleConfigurationV2RuleArgs] = None,
                 cors_rules: Sequence[s3.BucketCorsConfigurationV2CorsRuleArgs] = None):

        # Bucket
        self.bucket = bucket
        self.bucket_prefix = bucket_prefix
        self.force_destroy = force_destroy
        self.object_lock_enabled = object_lock_enabled
        self.tags = tags

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
        self.versioning_mfa_delete = versioning_mfa_delete

        # Logging
        self.target_bucket = target_bucket
        self.target_prefix = target_prefix

        # Lifecycle
        self.lifecycle_status_enabled = lifecycle_status_enabled
        self.lifecycle_rules = lifecycle_rules

        # CORS
        self.cors_rules = cors_rules

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
            bucket_prefix=args.bucket_prefix,
            force_destroy=args.force_destroy,
            object_lock_enabled=args.object_lock_enabled,
            tags=args.tags,
            opts=pulumi.ResourceOptions(
                parent=self,
            ))

        # Bucket ACL
        self.acl = s3.BucketAclV2(
            f"{resource_name}-acl",
            bucket=self.s3_bucket.id,
            acl=args.acl,
            expected_bucket_owner=args.expected_bucket_owner
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
                status=args.versioning_status,
                mfa_delete=args.versioning_mfa_delete,
            ),
            opts=pulumi.ResourceOptions(
                parent=self,
            )
        )

        # Bucket logging
        if args.target_bucket:
            self.logging = s3.BucketLoggingV2(
                f"{resource_name}-logging",
                bucket=self.s3_bucket.id,
                expected_bucket_owner=args.expected_bucket_owner,
                target_bucket=args.target_bucket,
                target_prefix=args.target_prefix,
                opts=pulumi.ResourceOptions(
                    parent=self,
                )
            )

        # Bucket Lifecycle Configuration
        if args.lifecycle_status_enabled:
            self.lifecycle = s3.BucketLifecycleConfigurationV2(
                f"{resource_name}-lifecycle-configuration",
                bucket=self.s3_bucket.id,
                rules=args.lifecycle_rules
            )

        # Bucket CORS Configuration
        if args.cors_rules != None:
            self.cors = s3.BucketCorsConfigurationV2(
                f"{resource_name}-cors-configuration",
                bucket=self.s3_bucket.id,
                expected_bucket_owner=args.expected_bucket_owner,
                cors_rules=args.cors_rules
            )


        super().register_outputs({})
