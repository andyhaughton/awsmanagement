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
resource "aws_guardduty_invite_accepter" "member_accepter" {
  count             = var.is_guardduty_member ? 1 : 0
  detector_id       = aws_guardduty_detector.detector.id
  master_account_id = var.master_account_id
}
