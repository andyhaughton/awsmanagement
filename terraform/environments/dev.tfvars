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
###############################################################################
## Environment Common
###############################################################################

env_tla = "eval" // MUST be changed for tst & prd

region = "eu-west-2"

project = "fa"

###############################################################################
## Networking
###############################################################################

vpc_cidr = "172.17.0.0/16"
# TODO: vpc_subnet is only used for security group ingress/egress rules. Could
# probably use vpc_cidr or one of the specific CIDRs below instead.
vpc_subnet = "172.17.0.0/16"


private_subnet_cidrs = [
  "172.17.16.0/20",
  "172.17.32.0/20"
]

public_subnet_cidrs = [
  "172.17.64.0/20",
  "172.17.96.0/20"
]

availability_zones = [
  "eu-west-2a",
  "eu-west-2b",
]

###############################################################################
## load balancer
###############################################################################

load_balancer_type_alb = "application"

load_balancer_type_nlb = "network"

enable_deletion_protection = "false"

enable_cross_zone_load_balancing = "true"

dns_ips = [
  "8.8.8.8",
  "8.8.4.4",
]



/*
###############################################################################
# CIS hardened RHEL AMI from AWS marketplace
# Used for all RHEL EC2 instances. Updating this will update all of them.
###############################################################################
A command like the following should give you the latest AMI ID:

AWS_PROFILE=fa-dev aws ec2 describe-images \
--filters "Name=product-code,Values=1mcmco51rfhc7dpqbq8a1nt75" \
--query "reverse(sort_by(Images, &CreationDate))[:1]"

*/



###############################################################################
## EC2 AD
###############################################################################

ec2_ad_instance_type = "t3.medium"
ec2_ad_ami           = "ami-0141f15c0dc928c2a" 

############################################################################
## EC2 CB
############################################################################

ec2_cb_instance_type = "t3.medium"
ec2_cb_ami           = "ami-0481a03637cf28531" 

############################################################################
## EC2 GW
############################################################################

ec2_gw_instance_type = "t3.medium"
ec2_gw_ami           = "ami-0481a03637cf28531" 

############################################################################
## EC2 WEB
############################################################################

ec2_web_instance_type = "t3.medium"
ec2_web_ami           = "ami-0850b3556e127e65c" 

############################################################################
## EC2 FILE1
############################################################################

ec2_file1_instance_type = "t3.medium"
ec2_file1_ami           = "ami-0481a03637cf28531" 

############################################################################
## EC2 SH1
############################################################################

ec2_sh1_instance_type = "t3.large"
ec2_sh1_ami           = "ami-0481a03637cf28531"


############################################################################
## EC2 PWM
############################################################################

ec2_pwm_instance_type = "t3.large"
ec2_pwm_ami           = "ami-0481a03637cf28531" 

rds_sec_cidrs = "172.17.0.0/16"


