############################################
# Lab 1C Bonus-B: ALB + TLS + WAF + Monitoring
############################################

locals {
  app_fqdn = "${var.app_subdomain}.${var.domain_name}"
  route53_zone_id = var.manage_route53_in_terraform ? aws_route53_zone.chrisbarm_zone01[0].zone_id : var.route53_hosted_zone_id
}

############################################
# ALB Security Group
############################################

resource "aws_security_group" "chrisbarm_alb_sg01" {
  name        = "${local.name_prefix}-alb-sg01"
  description = "ALB security group"
  vpc_id      = aws_vpc.chrisbarm_vpc01.id

  tags = {
    Name = "${local.name_prefix}-alb-sg01"
  }
}

resource "aws_vpc_security_group_ingress_rule" "chrisbarm_alb_sg_ingress_http" {
  ip_protocol       = local.tcp_protocol
  security_group_id = aws_security_group.chrisbarm_alb_sg01.id
  from_port         = local.ports_http
  to_port           = local.ports_http
  cidr_ipv4         = local.all_ip_address
}

resource "aws_vpc_security_group_ingress_rule" "chrisbarm_alb_sg_ingress_https" {
  ip_protocol       = local.tcp_protocol
  security_group_id = aws_security_group.chrisbarm_alb_sg01.id
  from_port         = local.ports_https
  to_port           = local.ports_https
  cidr_ipv4         = local.all_ip_address
}

resource "aws_vpc_security_group_egress_rule" "chrisbarm_alb_sg_egress_app" {
  ip_protocol                  = local.tcp_protocol
  security_group_id            = aws_security_group.chrisbarm_alb_sg01.id
  from_port                    = var.app_port
  to_port                      = var.app_port
  referenced_security_group_id = aws_security_group.chrisbarm_ec2_sg01.id
}

############################################
# ALB + Target Group + Listeners
############################################

resource "aws_lb" "chrisbarm_alb01" {
  name               = "${local.name_prefix}-alb01"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.chrisbarm_alb_sg01.id]
  subnets            = aws_subnet.chrisbarm_public_subnets[*].id

  tags = {
    Name = "${local.name_prefix}-alb01"
  }
  # Explanation: Chewbacca keeps flight logs—ALB access logs go to S3 for audits and incident response.
  access_logs {
    bucket  = aws_s3_bucket.chewbacca_alb_logs_bucket01[0].bucket
    prefix  = var.alb_access_logs_prefix
    enabled = var.enable_alb_access_logs
  }
}

resource "aws_lb_target_group" "chrisbarm_alb_tg01" {
  name     = "${local.name_prefix}-tg01"
  port     = var.app_port
  protocol = "HTTP"
  vpc_id   = aws_vpc.chrisbarm_vpc01.id

  health_check {
    path                = var.health_check_path
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
    timeout             = 5
    matcher             = "200-399"
  }

  tags = {
    Name = "${local.name_prefix}-tg01"
  }
}

resource "aws_lb_target_group_attachment" "chrisbarm_alb_tg_attach01" {
  target_group_arn = aws_lb_target_group.chrisbarm_alb_tg01.arn
  target_id        = aws_instance.chrisbarm_ec2_01.id
  port             = var.app_port
}

resource "aws_lb_listener" "chrisbarm_alb_http" {
  load_balancer_arn = aws_lb.chrisbarm_alb01.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

############################################
# ACM Certificate (TLS)
############################################

resource "aws_acm_certificate" "chrisbarm_acm_cert01" {
  domain_name       = local.app_fqdn
  validation_method = var.acm_validation_method

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_listener" "chrisbarm_alb_https" {
  load_balancer_arn = aws_lb.chrisbarm_alb01.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = var.acm_certificate_arn != "" ? var.acm_certificate_arn : aws_acm_certificate.chrisbarm_acm_cert01.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.chrisbarm_alb_tg01.arn
  }

  depends_on = [aws_acm_certificate_validation.chrisbarm_acm_cert_validation]
}

############################################
# WAF (Web ACL + Association)
############################################

resource "aws_wafv2_web_acl" "chrisbarm_waf01" {
  name  = "${local.name_prefix}-waf01"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-waf-common"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name_prefix}-waf"
    sampled_requests_enabled   = true
  }

  tags = {
    Name = "${local.name_prefix}-waf01"
  }
}

resource "aws_wafv2_web_acl_association" "chrisbarm_waf_assoc01" {
  resource_arn = aws_lb.chrisbarm_alb01.arn
  web_acl_arn  = aws_wafv2_web_acl.chrisbarm_waf01.arn
}

############################################
# CloudWatch Dashboard + Alarm
############################################

resource "aws_cloudwatch_dashboard" "chrisbarm_alb_dashboard01" {
  dashboard_name = "${local.name_prefix}-alb-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        x    = 0
        y    = 0
        width  = 12
        height = 6
        properties = {
          title  = "ALB 5XX"
          region = var.aws_region
          metrics = [
            ["AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", "LoadBalancer", aws_lb.chrisbarm_alb01.arn_suffix]
          ]
          stat   = "Sum"
          period = 300
        }
      },
      {
        type = "metric"
        x    = 12
        y    = 0
        width  = 12
        height = 6
        properties = {
          title  = "Target 5XX"
          region = var.aws_region
          metrics = [
            ["AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "LoadBalancer", aws_lb.chrisbarm_alb01.arn_suffix, "TargetGroup", aws_lb_target_group.chrisbarm_alb_tg01.arn_suffix]
          ]
          stat   = "Sum"
          period = 300
        }
      }
    ]
  })
}

resource "aws_cloudwatch_metric_alarm" "chrisbarm_alb_5xx_alarm01" {
  alarm_name          = "${local.name_prefix}-alb-5xx"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  threshold           = var.alb_5xx_threshold
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"

  dimensions = {
    LoadBalancer = aws_lb.chrisbarm_alb01.arn_suffix
  }

  alarm_actions = [aws_sns_topic.chrisbarm_sns_topic01.arn]

  tags = {
    Name = "${local.name_prefix}-alarm-alb-5xx"
  }
}
