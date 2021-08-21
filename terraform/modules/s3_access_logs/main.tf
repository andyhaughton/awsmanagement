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
resource "aws_s3_bucket" "fa-s3-access-logs" {
  bucket        = "fa-s3-access-logs"
  acl           = "log-delivery-write"
  force_destroy = true
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
    "Id": "RequireEncryption",
    "Statement": [
        {
            "Sid": "RequireEncryptedTransport",
            "Effect": "Deny",
            "Action": [
                "s3:*"
            ],
            "Resource": [
                 "arn:aws:s3:::fa-s3-access-logs/*"
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
  }
}

resource "aws_s3_bucket_public_access_block" "aws-management-s3-access-log-bucket" {
  bucket                  = aws_s3_bucket.fa-s3-access-logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}




