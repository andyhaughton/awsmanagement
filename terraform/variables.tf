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
variable "rds_sec_cidrs" {

}

variable "dns_ips" {
  type = list(string)
}




variable "availability_zones" {
  type        = list(string)
  description = "List of avalibility zones you want. Example: eu-west-1a and eu-west-1b"
}

variable "ec2_ad_ami" {
  type = string
}

variable "ec2_cb_ami" {
  type = string
}

variable "ec2_gw_ami" {
  type = string
}

variable "ec2_file1_ami" {
  type = string
}

variable "ec2_web_ami" {
  type = string
}

variable "ec2_sh1_ami" {
  type = string
}


variable "ec2_pwm_ami" {
  type = string
}

#variable "domain_iam_role_name" {
#}

variable "ec2_ad_instance_type" {
  type = string
}

variable "ec2_cb_instance_type" {
  type = string
}

variable "ec2_gw_instance_type" {
  type = string
}

variable "ec2_file1_instance_type" {
  type = string
}

variable "ec2_sh1_instance_type" {
  type = string
}

variable "ec2_pwm_instance_type" {
  type = string
}


variable "ec2_web_instance_type" {
  type = string
}

variable "enable_cross_zone_load_balancing" {
}


variable "env_tla" {
  description = "TLA for the environment - one of dev, tst, prd"
}


variable "load_balancer_type_alb" {
}

variable "load_balancer_type_nlb" {
}

variable "enable_deletion_protection" {
}


variable "project" {
}




variable "private_subnet_cidrs" {
  type        = list(string)
  description = "List of private cidrs, for every avalibility zone you want you need one. Example: 10.0.0.0/24 and 10.0.1.0/24"
}

variable "public_subnet_cidrs" {
  type        = list(string)
  description = "List of public cidrs, for every avalibility zone you want you need one. Example: 10.0.0.0/24 and 10.0.1.0/24"
}


variable "region" {
  description = "AWS Region Name"
}

variable "vpc_cidr" {
  description = "VPC cidr block. Example: 10.0.0.0/16"
}

variable "vpc_subnet" {
}


