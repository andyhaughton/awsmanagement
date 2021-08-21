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
# See ./bootstrap
terraform {
  backend "s3" {
    bucket         = "fa-tfstate"
    key            = "fa.tfstate"
    dynamodb_table = "fa-tfstate-lock"
    region         = "eu-west-2" # Terraform should support variables here
  }
}

module "cloudtrail" {
  source        = "./modules/cloudtrail"
  log_bucket  = module.s3_access_logs.bucketid

 
}


#module "guardduty" {
  #source = "./modules/guardduty"
  

#}

module "aws_config" {
  source = "./modules/aws_config" 
  aws_account_id="524130412650"
  log_bucket        = module.s3_access_logs.bucketid


}

module "s3_access_logs" {
  source      = "./modules/s3_access_logs"
  
}
