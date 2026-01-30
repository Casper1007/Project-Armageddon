# Explicit output for CloudWatch WAF log group (Bonus-E)
output "chrisbarm_waf_cloudwatch_log_group" {
  value = aws_cloudwatch_log_group.chewbarm_waf_log_group01[0].name
  description = "CloudWatch log group for WAF logs (if CloudWatch is used)"
}
# Explanation: Coordinates for the WAF log destination—Chewbacca wants to know where the footprints landed.
output "chewbacca_waf_log_destination" {
  value = var.waf_log_destination
}

output "chewbacca_waf_cw_log_group_name" {
  value = var.waf_log_destination == "cloudwatch" ? aws_cloudwatch_log_group.chewbarm_waf_log_group01[0].name : null
}

output "chewbacca_waf_logs_s3_bucket" {
  value = var.waf_log_destination == "s3" ? aws_s3_bucket.chewbarm_waf_logs_bucket01[0].bucket : null
}

output "chewbacca_waf_firehose_name" {
  value = var.waf_log_destination == "firehose" ? aws_kinesis_firehose_delivery_stream.chewbarm_waf_firehose01[0].name : null
}
# Explanation: The apex URL is the front gate—humans type this when they forget subdomains.
output "chewbacca_apex_url_https" {
  value = "https://${var.domain_name}"
}

# Explanation: Log bucket name is where the footprints live—useful when hunting 5xx or WAF blocks.
output "chewbacca_alb_logs_bucket_name" {
  value = var.enable_alb_access_logs ? aws_s3_bucket.chewbacca_alb_logs_bucket01[0].bucket : null
}
# Explanation: Outputs are your mission report—what got built and where to find it.
output "chrisbarm_vpc_id" {
  value = aws_vpc.chrisbarm_vpc01.id
}

output "chrisbarm_public_subnet_ids" {
  value = aws_subnet.chrisbarm_public_subnets[*].id
}

output "chrisbarm_private_subnet_ids" {
  value = aws_subnet.chrisbarm_private_subnets[*].id
}

#output "chrisbarm_ec2_public_instance_id" {
 #   value = aws_instance.chrisbarm_ec2_public01.id
#}

#output "chrisbarm_ec2_private_instance_id" {
 # value = aws_instance.chrisbarm_ec2_private01.id
#}

output "chrisbarm_rds_endpoint" {
  value = aws_db_instance.chrisbarm_rds01.address
}

output "chrisbarm_sns_topic_arn" {
  value = aws_sns_topic.chrisbarm_sns_topic01.arn
}

output "chrisbarm_log_group_name" {
  value = "/aws/ec2/${var.project_name}-rds-app"  # Log group managed outside of Terraform
}

# Explanation: Outputs are the nav computer readout—Chewbacca needs coordinates that humans can paste into browsers.
output "chrisbarm_route53_zone_id" {
  value = local.route53_zone_id
}

output "chrisbarm_app_url_https" {
  value = "https://${var.app_subdomain}.${var.domain_name}"
}
