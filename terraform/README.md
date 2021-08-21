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
# Terraform configuration

The code in this area **provisions** the infrastructure. Other code e.g.
PowerShell & Ansible is then used to **configure** it.

## Design

The code is structured as a series of Terraform modules. `main.tf` in this
directory calls the relevant modules to build the environment. In some cases,
modules called from `main.tf` will call other, lower-level modules for common
tasks.

Build-time variables are in `environments/*.tfvars`. These files set all the
variables necessary to build a `dev`, `tst` or `prd` environment e.g.
`dev.tfvars` is used to build a dev environment.

## Usage

### Bootstrapping/initial setup

First, you should go to `bootstrap` and bootstrap the state & secrets KMS key
(only needs to be done once):

    cd bootstrap
    export AWS_PROFILE=fa-eval
    terraform init && terraform apply

Then initialise the main environment:

    cd ..
    terraform init

### Ongoing use

In this Terraform setup, `dev`, `tst` and `prd` environments don't share state.
It's impossible to deploy dev config directly to production. This is enforced by
[Terraform workspaces](https://www.terraform.io/docs/state/workspaces.html)
and specific Gitlab branches for each of `dev`, `tst` and `prd`.

**`main.tf` checks that the `.tfvars` file, workspace, and Git branch all match
and will fail if they don't.**

So to run the Terraform code you need to:

1. Create a new workspace matching the environment e.g. `terraform workspace new dev`
2. Change to the workspace: `terraform workspace select dev`
3. Ensure matching Git branch: `git branch dev`
4. Run your command: `AWS_PROFILE=fa-eval terraform apply -var-file=environments/dev.tfvars`
   (note `.tfvars` file name)
