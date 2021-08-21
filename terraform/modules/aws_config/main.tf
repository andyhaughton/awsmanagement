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

# -----------------------------------------------------------
# set up a role for the Configuration Recorder to use
# -----------------------------------------------------------
resource "aws_iam_role" "fa-aws-config" {
  name = "fa-eval_aws_config"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "fa-aws-config" {
  role       = aws_iam_role.fa-aws-config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRole"
}

# -----------------------------------------------------------
# set up a bucket for the Configuration Recorder to write to
# -----------------------------------------------------------
resource "aws_s3_bucket" "fa-aws-config" {
  bucket  =  "fa-aws-config"
  acl           = "private"
  force_destroy = true

  versioning {
    enabled = true
  }


  
  logging {
    target_bucket = var.log_bucket
    target_prefix = "fa-aws-config/"
  }

}

resource "aws_s3_bucket_policy" "fa-aws-config_bucket_policy" {
  bucket = aws_s3_bucket.fa-aws-config.id
  depends_on = [aws_s3_bucket_public_access_block.fa-aws-config]

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Allow bucket ACL check",
      "Effect": "Allow",
      "Principal": {
        "Service": [
         "config.amazonaws.com"
        ]
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "${aws_s3_bucket.fa-aws-config.arn}",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "true"
        }
      }
    },
    {
      "Sid": "Allow bucket write",
      "Effect": "Allow",
      "Principal": {
        "Service": [
         "config.amazonaws.com"
        ]
      },
      "Action": "s3:PutObject",
      "Resource": "${aws_s3_bucket.fa-aws-config.arn}/AWSLogs/${var.aws_account_id}/Config/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        },
        "Bool": {
          "aws:SecureTransport": "true"
        }
      }
    },
    {
      "Sid": "Require SSL",
      "Effect": "Deny",
      "Principal": {
        "AWS": "*"
      },
      "Action": "s3:*",
      "Resource": "${aws_s3_bucket.fa-aws-config.arn}/*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_public_access_block" "fa-aws-config" {
  bucket                  = aws_s3_bucket.fa-aws-config.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# -----------------------------------------------------------
# set up the  Config Recorder
# -----------------------------------------------------------

resource "aws_config_configuration_recorder" "fa-aws-config" {
  name     = "fa-aws-config"
  role_arn = aws_iam_role.fa-aws-config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "fa-aws-config" {
  name           = "fa-aws-config"
  s3_bucket_name = aws_s3_bucket.fa-aws-config.bucket
  sns_topic_arn  = var.sns_topic_arn

  snapshot_delivery_properties {
    delivery_frequency = "Three_Hours"
  }

  depends_on = [aws_config_configuration_recorder.fa-aws-config]
}

resource "aws_config_configuration_recorder_status" "fa-aws-config" {
  name       = aws_config_configuration_recorder.fa-aws-config.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.fa-aws-config]
}

# -----------------------------------------------------------
# set up the Config Recorder rules
# see https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-fa-aws-config.html
# -----------------------------------------------------------
resource "aws_config_config_rule" "fa-eval_instances_in_vpc" {
  name = "fa-eval_instances_in_vpc"

  source {
    owner             = "AWS"
    source_identifier = "INSTANCES_IN_VPC"
  }

  depends_on = [aws_config_configuration_recorder.fa-aws-config]
}

resource "aws_config_config_rule" "fa-eval_ec2_volume_inuse_check" {
  name = "fa-eval_ec2_volume_inuse_check"

  source {
    owner             = "AWS"
    source_identifier = "EC2_VOLUME_INUSE_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.fa-aws-config]
}

resource "aws_config_config_rule" "fa-eval_eip_attached" {
  name = "fa-eval_eip_attached"

  source {
    owner             = "AWS"
    source_identifier = "EIP_ATTACHED"
  }

  depends_on = [aws_config_configuration_recorder.fa-aws-config]
}

resource "aws_config_config_rule" "fa-eval_encrypted_volumes" {
  name = "fa-eval_encrypted_volumes"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder.fa-aws-config]
}

resource "aws_config_config_rule" "fa-eval_incoming_ssh_disabled" {
  name = "fa-eval_incoming_ssh_disabled"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder.fa-aws-config]
}

// see https://docs.aws.amazon.com/config/latest/developerguide/cloudtrail-enabled.html
resource "aws_config_config_rule" "fa-eval-cloud_trail_enabled" {
  name = "fa-eval-cloud_trail_enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  input_parameters = <<EOF
{
  "s3BucketName": "example-logs20180305121401385000000001"
}
EOF

  depends_on = [aws_config_configuration_recorder.fa-aws-config]
}

resource "aws_config_config_rule" "fa-eval_cloudwatch_alarm_action_check" {
  name = "fa-eval_cloudwatch_alarm_action_check"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDWATCH_ALARM_ACTION_CHECK"
  }

  input_parameters = <<EOF
{
  "alarmActionRequired" : "true",
  "insufficientDataActionRequired" : "false",
  "okActionRequired" : "false"
}
EOF

  depends_on = [aws_config_configuration_recorder.fa-aws-config]
}

resource "aws_config_config_rule" "fa-eval_iam_group_has_users_check" {
  name = "fa-eval_iam_group_has_users_check"

  source {
    owner             = "AWS"
    source_identifier = "IAM_GROUP_HAS_USERS_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.fa-aws-config]
}

//see https://docs.aws.amazon.com/config/latest/developerguide/iam-password-policy.html
resource "aws_config_config_rule" "fa-eval_iam_password_policy" {
  name = "fa-eval_iam_password_policy"

  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }

  input_parameters = <<EOF
{
  "RequireUppercaseCharacters" : "true",
  "RequireLowercaseCharacters" : "true",
  "RequireSymbols" : "true",
  "RequireNumbers" : "true",
  "MinimumPasswordLength" : "16",
  "PasswordReusePrevention" : "12",
  "MaxPasswordAge" : "30"
}
EOF

  depends_on = [aws_config_configuration_recorder.fa-aws-config]
}

resource "aws_config_config_rule" "fa-eval_iam_user_group_membership_check" {
  name = "fa-eval_iam_user_group_membership_check"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_GROUP_MEMBERSHIP_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.fa-aws-config]
}

resource "aws_config_config_rule" "fa-eval_iam_user_no_policies_check" {
  name = "fa-eval_iam_user_no_policies_check"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_NO_POLICIES_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.fa-aws-config]
}

resource "aws_config_config_rule" "fa-eval_root_account_mfa_enabled" {
  name = "fa-eval_root_account_mfa_enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.fa-aws-config]
}

resource "aws_config_config_rule" "fa-eval_s3_bucket_public_read_prohibited" {
  name = "fa-eval_s3_bucket_public_read_prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.fa-aws-config]
}

resource "aws_config_config_rule" "fa-eval_s3_bucket_public_write_prohibited" {
  name = "fa-eval_s3_bucket_public_write_prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.fa-aws-config]
}

resource "aws_config_config_rule" "fa-eval_s3_bucket_ssl_requests_only" {
  name = "fa-eval_s3_bucket_ssl_requests_only"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }

  depends_on = [aws_config_configuration_recorder.fa-aws-config]
}

resource "aws_config_config_rule" "fa-eval_s3_bucket_server_side_encryption_enabled" {
  name = "fa-eval_s3_bucket_server_side_encryption_enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.fa-aws-config]
}

resource "aws_config_config_rule" "fa-eval_s3_bucket_versioning_enabled" {
  name = "fa-eval_s3_bucket_versioning_enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_VERSIONING_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.fa-aws-config]
}

resource "aws_config_config_rule" "fa-eval_ebs_optimized_instance" {
  name = "fa-eval_ebs_optimized_instance"

  source {
    owner             = "AWS"
    source_identifier = "EBS_OPTIMIZED_INSTANCE"
  }

  depends_on = [aws_config_configuration_recorder.fa-aws-config]
}
