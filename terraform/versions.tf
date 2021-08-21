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
terraform {
  required_version = ">= 0.12.18"
  required_providers {
    aws      = "~> 2.50"
    external = "~> 1.2"
    local    = "~> 1.4"
    random   = "~> 2.2"
  }
}
