###################################################################################
#                                                                                 #
# Copyright 2015-2021 Forensic Analytics Limited. All rights reserved.            #
#                                                                                 #
# If you wish to use this software or any part of it for any purpose, you require #
#                                                                                 #
# an express licence given in writing by Forensic Analytics Limited.              #
#                                                                                 #
# Visit forensicanalytics.co.uk                                                   #
#                                                                                 #
###################################################################################
data "aws_caller_identity" "current" {
}

resource "aws_cloudtrail" "cloudtrail" {
  name                       = "fa-cloudtrail"
  s3_bucket_name             = aws_s3_bucket.fa-cloudtrail.id
  s3_key_prefix              = "log"
  enable_log_file_validation = true
  is_multi_region_trail      = true
  cloud_watch_logs_group_arn = aws_cloudwatch_log_group.fa-eval.arn
  cloud_watch_logs_role_arn =  aws_iam_role.fa-eval.arn
}

resource "aws_cloudwatch_log_group" "fa-eval" {
  name              = "fa-eval_cloudtrail_logs"
  retention_in_days = 180
}




resource "aws_iam_role" "fa-eval" {
  name                = "fa-eval_cloudtrail_role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

}

resource "aws_iam_role_policy" "fa-eval" {
  name   = "fa-eval_cloudtrail_policy"
  role   = aws_iam_role.fa-eval.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:PutSubscriptionFilter",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF

}


resource "aws_s3_bucket" "fa-cloudtrail" {
  bucket        = "fa-cloudtrail"
  force_destroy = true
  acl           = "private"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::fa-cloudtrail"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::fa-cloudtrail/log/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        },
          {
            "Sid": "RequireEncryptedTransport",
            "Effect": "Deny",
            "Action": [
                "s3:*"
            ],
            "Resource": [
                "arn:aws:s3:::fa-cloudtrail/*"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            },
            "Principal": "*"
        }
    ]
}
POLICY

 
  versioning {
    enabled = true
    #mfa_delete = true
  }
   logging {
    target_bucket = var.log_bucket
    target_prefix = "fa-cloudtrail/"
  }
}

resource "aws_s3_bucket_public_access_block" "fa-cloudtrail" {
  bucket                  = aws_s3_bucket.fa-cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudwatch_log_metric_filter" "fa-eval-cloudtrail-unauth-api" {
  name           = "fa-eval-cloudtrail-unauth-api"
  pattern        = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
  log_group_name = "fa-eval_cloudtrail_logs"

  metric_transformation {
    name      = "Unauthorized API calls"
    namespace = "Log Metric Filters"
    value     = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "fa-eval-cloudtrail-unauth-api" {
  alarm_name          = "fa-eval-cloudtrail-unauth-api"
  alarm_description   = "fa-eval-cloudtrail-unauth-api"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Unauthorized API calls"
  namespace           = "Log Metric Filters"
  period              = 60
  threshold           = 1
  statistic           = "Sum"
  alarm_actions       = []
}

resource "aws_cloudwatch_log_metric_filter" "fa-eval-cloudtrail-no-MFA" {
  name           = "fa-eval-cloudtrail-no-MFA"
  pattern        = "{ $.eventName = \"ConsoleLogin\" && $.additionalEventData.MFAUsed = \"No\" }"
  log_group_name = "fa-eval_cloudtrail_logs"

  metric_transformation {
    name      = "Sign-in without MFA"
    namespace = "Log Metric Filters"
    value     = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "fa-eval-cloudtrail-no-MFA" {
  alarm_name          = "fa-eval-cloudtrail-no-MFA"
  alarm_description   = "fa-eval-cloudtrail-no-MFA"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Sign-in without MFA"
  namespace           = "Log Metric Filters"
  period              = 60
  threshold           = 1
  statistic           = "Sum"
  alarm_actions       = []
}

resource "aws_cloudwatch_log_metric_filter" "fa-eval-cloudtrail-root-account" {
  name           = "fa-eval-cloudtrail-root-account"
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
  log_group_name = "fa-eval_cloudtrail_logs"

  metric_transformation {
    name      = "Usage of root account"
    namespace = "Log Metric Filters"
    value     = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "fa-eval-cloudtrail-root-account" {
  alarm_name          = "fa-eval-cloudtrail-root-account"
  alarm_description   = "fa-eval-cloudtrail-root-account"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Usage of root account"
  namespace           = "Log Metric Filters"
  period              = 60
  threshold           = 1
  statistic           = "Sum"
  alarm_actions       = []
}

resource "aws_cloudwatch_log_metric_filter" "fa-eval-cloudtrail-iam-poicy-change" {
  name           = "fa-eval-cloudtrail-iam-poicy-change"
  pattern        = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"
  log_group_name = "fa-eval_cloudtrail_logs"

  metric_transformation {
    name      = "IAM Policy Changes"
    namespace = "Log Metric Filters"
    value     = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "fa-eval-cloudtrail-iam-poicy-change" {
  alarm_name          = "fa-eval-cloudtrail-iam-poicy-change"
  alarm_description   = "fa-eval-cloudtrail-iam-poicy-change"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "IAM Policy Changes"
  namespace           = "Log Metric Filters"
  period              = 60
  threshold           = 1
  statistic           = "Sum"
  alarm_actions       = []
}

resource "aws_cloudwatch_log_metric_filter" "fa-eval-cloudtrail-cloudtrail-config-change" {
  name           = "fa-eval-cloudtrail-cloudtrail-config-change"
  pattern        = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
  log_group_name = "fa-eval_cloudtrail_logs"

  metric_transformation {
    name      = "CloudTrail Configuration Changes"
    namespace = "Log Metric Filters"
    value     = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "fa-eval-cloudtrail-cloudtrail-config-change" {
  alarm_name          = "fa-eval-cloudtrail-cloudtrail-config-change"
  alarm_description   = "fa-eval-cloudtrail-cloudtrail-config-change"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "CloudTrail Configuration Changes"
  namespace           = "Log Metric Filters"
  period              = 60
  threshold           = 1
  statistic           = "Sum"
  alarm_actions       = []
}

resource "aws_cloudwatch_log_metric_filter" "fa-eval-cloudtrail-console-auth-failure" {
  name           = "fa-eval-cloudtrail-console-auth-failure"
  pattern        = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
  log_group_name = "fa-eval_cloudtrail_logs"

  metric_transformation {
    name      = "AWS Management Console Authentication Failures"
    namespace = "Log Metric Filters"
    value     = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "fa-eval-cloudtrail-console-auth-failure" {
  alarm_name          = "fa-eval-cloudtrail-console-auth-failure"
  alarm_description   = "fa-eval-cloudtrail-console-auth-failure"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "AWS Management Console Authentication Failures"
  namespace           = "Log Metric Filters"
  period              = 60
  threshold           = 1
  statistic           = "Sum"
  alarm_actions       = []
}

resource "aws_cloudwatch_log_metric_filter" "fa-eval-cloudtrail-CMK-delete" {
  name           = "fa-eval-cloudtrail-CMK-delete"
  pattern        = "{ $.eventSource = kms* && $.errorMessage = \"* is pending deletion.\"}"
  log_group_name = "fa-eval_cloudtrail_logs"

  metric_transformation {
    name      = "Disabling or Scheduled Deletion of Customer Created CMKs"
    namespace = "Log Metric Filters"
    value     = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "fa-eval-cloudtrail-CMK-delete" {
  alarm_name          = "fa-eval-cloudtrail-CMK-delete"
  alarm_description   = "fa-eval-cloudtrail-CMK-delete"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Disabling or Scheduled Deletion of Customer Created CMKs"
  namespace           = "Log Metric Filters"
  period              = 60
  threshold           = 1
  statistic           = "Sum"
  alarm_actions       = []
}

resource "aws_cloudwatch_log_metric_filter" "fa-eval-cloudtrail-S3-policy-change" {
  name           = "fa-eval-cloudtrail-S3-policy-change"
  pattern        = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
  log_group_name = "fa-eval_cloudtrail_logs"

  metric_transformation {
    name      = "S3 Bucket Policy Changes"
    namespace = "Log Metric Filters"
    value     = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "fa-eval-cloudtrail-S3-policy-change" {
  alarm_name          = "fa-eval-cloudtrail-S3-policy-change"
  alarm_description   = "fa-eval-cloudtrail-S3-policy-change"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "S3 Bucket Policy Changes"
  namespace           = "Log Metric Filters"
  period              = 60
  threshold           = 1
  statistic           = "Sum"
  alarm_actions       = []
}


