############################################
# Bonus-B Route53 Add-on (Chewbacca Edition)
############################################

# Rrrrrrr... Hosted Zone (optional, if Terraform manages Route53)
resource "aws_route53_zone" "chrisbarm_zone01" {
  count = var.manage_route53_in_terraform ? 1 : 0
  name  = var.domain_name

  tags = {
    Name = "${local.name_prefix}-hosted-zone"
  }
}

# Wrrrgh... DNS validation records for ACM (only when DNS validation is used)
resource "aws_route53_record" "chrisbarm_acm_validation" {
  for_each = var.manage_route53_in_terraform && var.acm_validation_method == "DNS" ? {
    for dvo in aws_acm_certificate.chrisbarm_acm_cert01.domain_validation_options :
    dvo.domain_name => {
      name  = dvo.resource_record_name
      type  = dvo.resource_record_type
      value = dvo.resource_record_value
    }
  } : {}

  zone_id = local.route53_zone_id
  name    = each.value.name
  type    = each.value.type
  records = [each.value.value]
  ttl     = 60
}

# Raaaaargh... Validate ACM certificate via DNS
resource "aws_acm_certificate_validation" "chrisbarm_acm_cert_validation" {
  count           = var.manage_route53_in_terraform && var.acm_validation_method == "DNS" ? 1 : 0
  certificate_arn = var.acm_certificate_arn != "" ? var.acm_certificate_arn : aws_acm_certificate.chrisbarm_acm_cert01.arn
  validation_record_fqdns = [
    for record in aws_route53_record.chrisbarm_acm_validation : record.fqdn
  ]
}

# Rrrrrowl... app.chewbacca-growl.com ALIAS -> ALB
resource "aws_route53_record" "chrisbarm_app_alias" {
  count   = var.manage_route53_in_terraform ? 1 : 0
  zone_id = local.route53_zone_id
  name    = local.app_fqdn
  type    = "A"

  alias {
    name                   = aws_lb.chrisbarm_alb01.dns_name
    zone_id                = aws_lb.chrisbarm_alb01.zone_id
    evaluate_target_health = true
  }
}
