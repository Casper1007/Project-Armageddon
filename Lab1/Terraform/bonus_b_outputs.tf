output "alb_dns_name" {
  description = "ALB DNS name (use for CNAME/ALIAS if managing DNS outside Route53)."
  value       = aws_lb.chrisbarm_alb01.dns_name
}

output "alb_arn" {
  description = "ALB ARN."
  value       = aws_lb.chrisbarm_alb01.arn
}

output "alb_target_group_arn" {
  description = "ALB target group ARN."
  value       = aws_lb_target_group.chrisbarm_alb_tg01.arn
}

output "acm_certificate_arn" {
  description = "ACM certificate ARN for the app domain."
  value       = var.acm_certificate_arn != "" ? var.acm_certificate_arn : aws_acm_certificate.chrisbarm_acm_cert01.arn
}

output "acm_dns_validation_records" {
  description = "DNS validation records to add in external DNS (name/type/value)."
  value = [
    for dvo in aws_acm_certificate.chrisbarm_acm_cert01.domain_validation_options : {
      name  = dvo.resource_record_name
      type  = dvo.resource_record_type
      value = dvo.resource_record_value
    }
  ]
}

output "waf_web_acl_arn" {
  description = "WAFv2 web ACL ARN."
  value       = aws_wafv2_web_acl.chrisbarm_waf01.arn
}

output "alb_dashboard_name" {
  description = "CloudWatch dashboard name."
  value       = aws_cloudwatch_dashboard.chrisbarm_alb_dashboard01.dashboard_name
}

output "app_url" {
  description = "App URL (requires DNS to point to the ALB)."
  value       = "https://${var.app_subdomain}.${var.domain_name}"
}
