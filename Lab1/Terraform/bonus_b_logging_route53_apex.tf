############################################
# Bonus-D: Route53 Apex + ALB Access Logs
############################################

# S3 bucket for ALB access logs
resource "aws_s3_bucket" "chewbacca_alb_logs_bucket01" {
  count = var.enable_alb_access_logs ? 1 : 0
  bucket = "chewbacca-alb-logs-${random_id.suffix.hex}"
  force_destroy = true
}

resource "random_id" "suffix" {
  byte_length = 4
}

# S3 bucket policy for ALB logging
resource "aws_s3_bucket_policy" "chewbacca_alb_logs_policy01" {
  count = var.enable_alb_access_logs ? 1 : 0
  bucket = aws_s3_bucket.chewbacca_alb_logs_bucket01[0].id
  policy = data.aws_iam_policy_document.chewbacca_alb_logs_policy01.json
}

data "aws_iam_policy_document" "chewbacca_alb_logs_policy01" {
  statement {
    sid    = "AWSLogDeliveryWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }
    actions = [
      "s3:PutObject"
    ]
    resources = [
      "${aws_s3_bucket.chewbacca_alb_logs_bucket01[0].arn}/*"
    ]
  }
}

# Route53 apex ALIAS record to ALB
resource "aws_route53_record" "chewbacca_apex_alias" {
  zone_id = local.route53_zone_id
  name    = var.domain_name
  type    = "A"
  alias {
    name                   = aws_lb.chrisbarm_alb01.dns_name
    zone_id                = aws_lb.chrisbarm_alb01.zone_id
    evaluate_target_health = true
  }
}
