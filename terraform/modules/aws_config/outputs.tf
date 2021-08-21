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
output "bucket_arn" {
  value = "${aws_s3_bucket.fa-aws-config.arn}"
}

output "recorder_id" {
  value = "${aws_config_configuration_recorder.fa-aws-config.id}"
}
