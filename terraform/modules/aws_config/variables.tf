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
variable "aws_account_id" {}


variable "log_bucket" {}

variable "bucket_prefix" {
  default = "aws-config"
}

variable "bucket_key_prefix" {
  default = "aws-config"
}

variable "sns_topic_arn" {
  default = "arn:aws:sns:eu-west-2:889199313043:security-alerts-topic"
}

