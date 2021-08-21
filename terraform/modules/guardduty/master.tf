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
locals {
  ipset_name          = "IPSet"
  ipset_key           = "ipset.txt"
  threatintelset_name = "ThreatIntelSet"
  threatintelset_key  = "threatintelset.txt"
}

resource "aws_s3_bucket" "fa-guardduty" {
  count  = var.is_guardduty_master && (var.has_ipset || var.has_threatintelset) ? 1 : 0
  bucket = "fa-guardduty""
  acl    = "private"
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
                "arn:aws:s3:::${aws_s3_bucket.fa-guardduty}/*"
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
  
}

resource "aws_s3_bucket_object" "ipset" {
  count = var.is_guardduty_master && var.has_ipset ? 1 : 0
  acl   = "public-read"
  content = templatefile("${path.module}/templates/ipset.txt.tpl",
  { ipset_iplist = var.ipset_iplist })
  bucket = aws_s3_bucket.guardduty[0].id
  key    = local.ipset_key
}

resource "aws_guardduty_ipset" "ipset" {
  count       = var.is_guardduty_master && var.has_ipset ? 1 : 0
  activate    = var.ipset_activate
  detector_id = aws_guardduty_detector.detector.id
  format      = var.ipset_format
  location    = "https://s3.amazonaws.com/${aws_s3_bucket.bucket[0].id}/${local.ipset_key}"
  name        = local.ipset_name
}

resource "aws_s3_bucket_object" "threatintelset" {
  count = var.is_guardduty_master && var.has_threatintelset ? 1 : 0
  acl   = "public-read"
  content = templatefile("${path.module}/templates/threatintelset.txt.tpl",
  { threatintelset_iplist = var.threatintelset_iplist })
  bucket = aws_s3_bucket.guardduty[0].id
  key    = local.threatintelset_key
}

resource "aws_guardduty_threatintelset" "threatintelset" {
  count       = var.is_guardduty_master && var.has_threatintelset ? 1 : 0
  activate    = var.threatintelset_activate
  detector_id = aws_guardduty_detector.detector.id
  format      = var.threatintelset_format
  location    = "https://s3.amazonaws.com/${aws_s3_bucket.bucket[0].id}/${local.threatintelset_key}"
  name        = local.threatintelset_name
}

resource "aws_guardduty_member" "members" {
  count              = var.is_guardduty_master ? length(var.member_list) : 0
  account_id         = var.member_list[count.index]["account_id"]
  detector_id        = aws_guardduty_detector.detector.id
  email              = var.member_list[count.index]["member_email"]
  invite             = var.member_list[count.index]["invite"]
  invitation_message = "Please accept GuardDuty invitation"
}
