############################################
# Bonus-E: WAF Logging (CloudWatch, S3, Firehose)
############################################

# CloudWatch Logs destination
resource "aws_cloudwatch_log_group" "chewbarm_waf_log_group01" {
  count             = var.waf_log_destination == "cloudwatch" ? 1 : 0
  name              = "aws-waf-logs-${var.project}-webacl01"
  retention_in_days = var.waf_log_retention_days
}



resource "aws_s3_bucket" "chewbarm_waf_logs_bucket01" {
  count  = var.waf_log_destination == "s3" ? 1 : 0
  bucket = "aws-waf-logs-${var.project}-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

# Firehose destination
resource "aws_kinesis_firehose_delivery_stream" "chewbarm_waf_firehose01" {
  count       = var.waf_log_destination == "firehose" ? 1 : 0
  name        = "aws-waf-logs-${var.project}-firehose01"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose_role[0].arn
    bucket_arn = aws_s3_bucket.firehose_dest_bucket[0].arn
    prefix     = "waf-logs/"
  }
}

resource "aws_s3_bucket" "firehose_dest_bucket" {
  count  = var.waf_log_destination == "firehose" ? 1 : 0
  bucket = "aws-waf-firehose-dest-${var.project}-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_iam_role" "firehose_role" {
  count = var.waf_log_destination == "firehose" ? 1 : 0
  name = "aws-waf-firehose-role-${var.project}"
  assume_role_policy = data.aws_iam_policy_document.firehose_assume_role.json
}

data "aws_iam_policy_document" "firehose_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }
  }
}

# WAF Logging configuration
resource "aws_wafv2_web_acl_logging_configuration" "chewbarm_waf_logging" {
  log_destination_configs = [
    var.waf_log_destination == "cloudwatch" ? aws_cloudwatch_log_group.chewbarm_waf_log_group01[0].arn :
    var.waf_log_destination == "s3" ? aws_s3_bucket.chewbarm_waf_logs_bucket01[0].arn :
    aws_kinesis_firehose_delivery_stream.chewbarm_waf_firehose01[0].arn
  ]
  resource_arn = aws_wafv2_web_acl.chrisbarm_waf01.arn
  depends_on = [aws_wafv2_web_acl.chrisbarm_waf01]
}
