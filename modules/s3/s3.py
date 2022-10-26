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
                 versioning_status: str = None,
                 versioning_mfa_delete: str = "Disabled",
                 target_bucket: str = None,
                 target_prefix: str = None,
                 lifecycle_status_enabled: bool = False,
                 lifecycle_rules: Sequence[s3.BucketLifecycleConfigurationV2RuleArgs] = None,
                 cors_rules: Sequence[s3.BucketCorsConfigurationV2CorsRuleArgs] = None,
                 object_lock_configuration: list = None,
                 accelerate_configuration_enabled: str = "Disabled",
                 request_payment_configuration_payer: str = None,
                 website: list = None,
                 bucket_policy: str = None,
                 intelligent_tiering_configuration: list = None,
                 object_ownership: str = None,
                 replication_configuration: list = None,
                 metric_configuration: list = None,
                 analytics_configuration: list = None,
                 inventory_configuration: list = None):

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

        # Object Lock
        self.object_lock_configuration = object_lock_configuration

        # Accelerate
        self.accelerate_configuration_enabled = accelerate_configuration_enabled

        # Request Payment
        self.request_payment_configuration_payer = request_payment_configuration_payer

        # Website
        self.website = website

        # Policy
        self.bucket_policy = bucket_policy

        # Intelligent Tiering
        self.intelligent_tiering_configuration = intelligent_tiering_configuration

        # Ownership Controls
        self.object_ownership = object_ownership

        # Replication
        self.replication_configuration = replication_configuration

        # Metrics
        self.metric_configuration = metric_configuration

        # Analytics
        self.analytics_configuration = analytics_configuration

        # Inventory
        self.inventory_configuration = inventory_configuration

class S3(pulumi.ComponentResource):

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
            expected_bucket_owner=args.expected_bucket_owner,
            opts=pulumi.ResourceOptions(
                parent=self,
            )
        )

        # Default Encryption
        if args.sse_algorithm is not None:
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
        if args.versioning_status is not None:
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
                rules=args.lifecycle_rules,
                opts=pulumi.ResourceOptions(
                    parent=self
                )
            )

        # Bucket CORS Configuration
        if args.cors_rules is not None:
            self.cors = s3.BucketCorsConfigurationV2(
                f"{resource_name}-cors-configuration",
                bucket=self.s3_bucket.id,
                expected_bucket_owner=args.expected_bucket_owner,
                cors_rules=args.cors_rules,
                opts=pulumi.ResourceOptions(
                    parent=self
                )
            )

        # Object Lock Configuration
        if args.object_lock_enabled is True:
            self.object_lock_configuration = s3.BucketObjectLockConfigurationV2(
                f"{resource_name}-object-lock-configuration",
                bucket=self.s3_bucket.id,
                expected_bucket_owner=args.expected_bucket_owner,
                object_lock_enabled="Enabled",
                rule=s3.BucketObjectLockConfigurationV2RuleArgs(
                    default_retention=s3.BucketObjectLockConfigurationV2RuleDefaultRetentionArgs(
                        days=args.object_lock_configuration[0].get('days', None),
                        mode=args.object_lock_configuration[0].get('mode', None),
                        years=args.object_lock_configuration[0].get('years', None)
                    ),
                ),
                token=args.object_lock_configuration[0].get('token', None),
                opts=pulumi.ResourceOptions(
                    parent=self
                )
            )

        # Accelerate Configuration
        if args.accelerate_configuration_enabled == 'Enabled':
            self.accelerate_configuration = s3.BucketAccelerateConfigurationV2(
                f"{resource_name}-accelerate-configuration",
                bucket=self.s3_bucket.id,
                expected_bucket_owner=args.expected_bucket_owner,
                status=args.accelerate_configuration_enabled,
                opts=pulumi.ResourceOptions(
                    parent=self
                )
            )

        # Request Payment configuration
        if args.request_payment_configuration_payer is not None:
            self.request_payment_configuration = s3.BucketRequestPaymentConfigurationV2(
                f"{resource_name}-request-payment-configuration",
                bucket=self.s3_bucket.id,
                expected_bucket_owner=args.expected_bucket_owner,
                payer=args.request_payment_configuration_payer,
                opts=pulumi.ResourceOptions(
                    parent=self
                )
            )

        # Website Configuration
        # Not really sure if this is a good way to do this
        if args.website[0].get('error_document') != '':
            self.website_configuration = s3.BucketWebsiteConfigurationV2(
                f"{resource_name}-website-configuration",
                bucket=self.s3_bucket.id,
                expected_bucket_owner=args.expected_bucket_owner,
                error_document=s3.BucketWebsiteConfigurationV2ErrorDocumentArgs(
                    key=args.website[0].get('error_document', None)
                ),
                index_document=s3.BucketWebsiteConfigurationV2IndexDocumentArgs(
                    suffix=args.website[0].get('index_document', None)
                ),
                routing_rules=args.website[0].get('routing_rules', None),
                routing_rule_details=args.website[0].get('routing_rule_details', None),
                opts=pulumi.ResourceOptions(
                    parent=self
                )
            )
        else:
            self.website_configuration = s3.BucketWebsiteConfigurationV2(
                f"{resource_name}-website-configuration",
                bucket=self.s3_bucket.id,
                expected_bucket_owner=args.expected_bucket_owner,
                redirect_all_requests_to=s3.BucketWebsiteConfigurationV2RedirectAllRequestsTo(
                    host_name=args.website[0].get('host_name', None),
                    protocol=args.website[0].get('protocol', None)
                ),
                opts=pulumi.ResourceOptions(
                    parent=self
                )
            )

        # Policy
        if args.bucket_policy is not None:
            self.policy = s3.BucketPolicy(
                f"{resource_name}-policy",
                bucket=self.s3_bucket.id,
                policy=args.bucket_policy,
                opts=pulumi.ResourceOptions(
                    parent=self
                )
            )

        # Intelligent Tiering
        if args.intelligent_tiering_configuration is not None:
            self.intelligent_tiering = s3.BucketIntelligentTieringConfiguration(
                f"{resource_name}-intelligent-tiering",
                bucket=self.s3_bucket.id,
                filter=s3.BucketIntelligentTieringConfigurationFilterArgs(
                    prefix=args.intelligent_tiering_configuration[0].get('filter_prefix', ''),
                    tags=args.intelligent_tiering_configuration[0].get('filter_tags', {})
                ),
                name=args.intelligent_tiering_configuration[0].get('name', ''),
                status=args.intelligent_tiering_configuration[0].get('status', None),
                tierings=args.intelligent_tiering_configuration[0].get('tierings', None),
                opts=pulumi.ResourceOptions(
                    parent=self
                )
            )

        # Ownership Controls
        if args.object_ownership is not None:
            self.ownership_controls = s3.BucketOwnershipControls(
                f"{resource_name}-ownership-controls",
                bucket=self.s3_bucket.id,
                rule=s3.BucketOwnershipControlsRuleArgs(
                    object_ownership=args.object_ownership
                ),
                opts=pulumi.ResourceOptions(
                    parent=self
                )
            )

        # Replication Configuration
        if args.replication_configuration is not None:
            self.replication_configuration = s3.BucketReplicationConfig(
                f"{resource_name}-replication-configuration",
                bucket=self.s3_bucket.id,
                role=args.replication_configuration[0].get('role', ''),
                rules=args.replication_configuration[0].get('rules', []),
                token=args.replication_configuration[0].get('token', None),
                opts=pulumi.ResourceOptions(
                    parent=self
                )
            )

        # Metric Configuration
        if args.metric_configuration is not None:
            self.metrics = s3.BucketMetric(
                f"{resource_name}-metrics",
                bucket=self.s3_bucket.id,
                filter=s3.BucketMetricFilterArgs(
                    prefix=args.metric_configuration[0].get('filter_prefix', None),
                    tags=args.metric_configuration[0].get('tags', {})
                ),
                name=args.metric_configuration[0].get('name', None),
                opts=pulumi.ResourceOptions(
                    parent=self
                )
            )

        # Analytics Configuration
        if args.analytics_configuration is not None:
            self.analytics = s3.AnalyticsConfiguration(
                f"{resource_name}-analytics-configuration",
                bucket=self.s3_bucket.id,
                filter=s3.AnalyticsConfigurationFilterArgs(
                    prefix=args.analytics_configuration[0].get('filter_prefix', None),
                    tags=args.analytics_configuration[0].get('tags', {})
                ),
                name=args.analytics_configuration[0].get('name', None),
                storage_class_analysis=s3.AnalyticsConfigurationStorageClassAnalysisArgs(
                    data_export=s3.AnalyticsConfigurationStorageClassAnalysisDataExportArgs(
                        output_schema_version=args.analytics_configuration[0].get('data_export_output_schema_version', None),
                        destination=s3.AnalyticsConfigurationStorageClassAnalysisDataExportDestinationArgs(
                            s3_bucket_destination=s3.AnalyticsConfigurationStorageClassAnalysisDataExportDestinationS3BucketDestinationArgs(
                                bucket_arn=args.analytics_configuration[0].get('data_export_bucket_arn', None),
                                bucket_account_id=args.analytics_configuration[0].get('data_export_bucket_account_id', None),
                                format=args.analytics_configuration[0].get('data_export_bucket_destination_format', None),
                                prefix=args.analytics_configuration[0].get('data_export_bucket_destination_prefix', None),
                            )
                        )
                    )
                ),
                opts=pulumi.ResourceOptions(
                    parent=self
                )
            )

        if args.inventory_configuration is not None:
            self.inventory = s3.Inventory(
                f"{resource_name}-inventory-configuration",
                bucket=args.inventory_configuration[0].get('source', self.s3_bucket.id),
                destination=s3.InventoryDestinationArgs(
                    bucket=s3.InventoryDestinationBucketArgs(
                        bucket_arn=args.inventory_configuration[0].get('destination', self.s3_bucket.arn),
                        format=args.inventory_configuration[0].get('destination_format', None),
                        account_id=args.inventory_configuration[0].get('destination_account_id', None),
                        encryption=s3.InventoryDestinationBucketEncryptionArgs(
                            sse_kms=s3.InventoryDestinationBucketEncryptionSseKmsArgs(
                                key_id=args.inventory_configuration[0].get('destination_kms_key_id', None)
                            ),
                            sse_s3=s3.InventoryDestinationBucketEncryptionSseS3Args(

                            )
                        )
                    )
                ),
                included_object_versions=args.inventory_configuration[0].get('included_object_versions', 'All'),
                schedule=s3.InventoryScheduleArgs(
                    frequency=args.inventory_configuration[0].get('schedule_frequency', None),
                ),
                enabled=True,
                filter=s3.InventoryFilterArgs(
                    prefix=args.inventory_configuration[0].get('filter_prefix', None),
                ),
                name=args.inventory_configuration[0].get('name', None),
                optional_fields=args.inventory_configuration[0].get('optional_fields', None),
                opts=pulumi.ResourceOptions(
                    parent=self
                )
            )

        super().register_outputs({})
