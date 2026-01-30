# Bonus-F: CloudWatch Logs Insights Query Pack

This section provides a ready-to-use set of CloudWatch Logs Insights queries for Lab 1C-Bonus-B incident response and troubleshooting.

**Important notes:**
- CloudWatch Logs Insights only works on logs in CloudWatch Logs.
- This pack covers:
  - WAF logs (when waf_log_destination="cloudwatch")
  - App logs (/aws/ec2/<project>-rds-app)
- ALB access logs are in S3, not CloudWatch Logs (unless you ship them to CW via another pipeline).
  - For ALB, correlate via CloudWatch metrics (5xx alarm/metrics) or Athena for S3 log analysis.

## Variables to fill in for the runbook
- WAF log group: `aws-waf-logs-<project>-webacl01`
- App log group: `/aws/ec2/<project>-rds-app`

**Set the time range to Last 15 minutes (or match incident window).**

### A) WAF Queries (CloudWatch Logs Insights)

**A1) What’s happening right now? (Top actions: ALLOW/BLOCK)**
```sql
fields @timestamp, action
| stats count() as hits by action
| sort hits desc
```

**A2) Top client IPs (who is hitting us the most?)**
```sql
fields @timestamp, httpRequest.clientIp as clientIp
| stats count() as hits by clientIp
| sort hits desc
| limit 25
```

**A3) Top requested URIs (what are they trying to reach?)**
```sql
fields @timestamp, httpRequest.uri as uri
| stats count() as hits by uri
| sort hits desc
| limit 25
```

**A4) Blocked requests only (who/what is being blocked?)**
```sql
fields @timestamp, action, httpRequest.clientIp as clientIp, httpRequest.uri as uri
| filter action = "BLOCK"
| stats count() as blocks by clientIp, uri
| sort blocks desc
| limit 25
```

**A5) Which WAF rule is doing the blocking?**
```sql
fields @timestamp, action, terminatingRuleId, terminatingRuleType
| filter action = "BLOCK"
| stats count() as blocks by terminatingRuleId, terminatingRuleType
| sort blocks desc
| limit 25
```

**A6) Rate of blocks over time (did it spike?)**
```sql
fields @timestamp, httpRequest.clientIp as clientIp, httpRequest.uri as uri
| filter uri like /wp-login|xmlrpc|\.env|admin|phpmyadmin|\.git|\/login/i
| stats count() as hits by clientIp, uri
| sort hits desc
| limit 50
```

**A7) Suspicious scanners (common patterns: admin paths, wp-login, etc.)**
```sql
fields @timestamp, httpRequest.clientIp as clientIp, httpRequest.uri as uri
| filter uri like /wp-login|xmlrpc|\.env|admin|phpmyadmin|\.git|\/login/i
| stats count() as hits by clientIp, uri
| sort hits desc
| limit 50
```

**A8) Country/geo (if present in your WAF logs)**
```sql
fields @timestamp, httpRequest.country as country
| stats count() as hits by country
| sort hits desc
| limit 25
```

### B) App Queries (EC2 app log group)

Assumes your app logs include strings like ERROR, DBConnectionErrors, timeout, etc.

**B1) Count errors over time (should line up with alarm window)**
```sql
fields @timestamp, @message
| filter @message like /ERROR|Exception|Traceback|DB|timeout|refused/i
| stats count() as errors by bin(1m)
| sort bin(1m) asc
```

**B2) Show the most recent DB failures (triage view)**
```sql
fields @timestamp, @message
| filter @message like /DB|mysql|timeout|refused|Access denied|could not connect/i
| sort @timestamp desc
| limit 50
```

**B3) “Is it creds or network?” classifier hints**
```sql
fields @timestamp, @message
| filter @message like /Access denied|authentication failed|timeout|refused|no route|could not connect/i
| stats count() as hits by
  case(
    @message like /Access denied|authentication failed/i, "Creds/Auth",
    @message like /timeout|no route/i, "Network/Route",
    @message like /refused/i, "Port/SG/ServiceRefused",
    "Other"
  )
| sort hits desc
```

**B4) Extract structured fields (Requires log JSON)**
```sql
fields @timestamp, level, event, reason
| filter level="ERROR"
| stats count() as n by event, reason
| sort n desc
```

### C) Correlation “Enterprise-style” mini-workflow (Runbook Section)

**Step 1 — Confirm signal timing**
- CloudWatch alarm time window: last 5–15 minutes
- Run App B1 to see error spike time bins

**Step 2 — Decide: Attack vs Backend Failure**
- Run WAF A1 + A6:
  - If BLOCK spikes align with incident time → likely external pressure/scanning
  - If WAF is quiet but app errors spike → likely backend (RDS/SG/creds)

**Step 3 — If backend failure suspected**
- Run App B2 and classify:
  - Access denied → secrets drift / wrong password
  - timeout → SG/routing/RDS down
- Then retrieve known-good values:
  - Parameter Store /lab/db/*
  - Secrets Manager /<prefix>/rds/mysql

**Step 4 — Verify recovery**
- App errors return to baseline (B1)
- WAF blocks stabilize (A6)
- Alarm returns to OK
- curl https://app.chrisbdevsecops.com/list works

---
**Section Summary:**
Provides a ready-to-use set of CloudWatch Logs Insights queries for WAF and app logs, plus a runbook for incident triage and correlation. Enables rapid investigation of attacks, backend failures, and recovery in Lab 1C-Bonus-B.
# Bonus-E: WAF Logging (CloudWatch, S3, Firehose)
---
**Section Summary:**
Describes how to enable AWS WAF logging to CloudWatch, S3, or Firehose using Terraform. Includes variables, resource skeletons, outputs, CLI verification steps, and incident response context.

## Terraform Output (CloudWatch)

chrisbarm_waf_cloudwatch_log_group = aws-waf-logs-<project>-webacl01

This is the CloudWatch log group where WAF logs are delivered if you set var.waf_log_destination = "cloudwatch".
# Bonus-E: WAF Logging (CloudWatch, S3, Firehose)

## Student Verification (CLI)

A) Confirm WAF logging is enabled (authoritative)
```sh
aws wafv2 get-logging-configuration \
  --resource-arn <WEB_ACL_ARN>
```
Expected: LogDestinationConfigs contains exactly one destination.

B) Generate traffic (hits + blocks)
```sh
curl -I https://chrisbdevsecops.com/
curl -I https://app.chrisbdevsecops.com/
```

C1) If CloudWatch Logs destination
```sh
aws logs describe-log-streams \
  --log-group-name aws-waf-logs-<project>-webacl01 \
  --order-by LastEventTime --descending

aws logs filter-log-events \
  --log-group-name aws-waf-logs-<project>-webacl01 \
  --max-items 20
```

C2) If S3 destination
```sh
aws s3 ls s3://aws-waf-logs-<project>-<account_id>/ --recursive | head
```

C3) If Firehose destination
```sh
aws firehose describe-delivery-stream \
  --delivery-stream-name aws-waf-logs-<project>-firehose01 \
  --query "DeliveryStreamDescription.DeliveryStreamStatus"

aws s3 ls s3://<firehose_dest_bucket>/waf-logs/ --recursive | head
```

---
## Why this makes incident response “real”

Now you can answer questions like:
  - “Are 5xx caused by attackers or backend failure?”
  - “Do we see WAF blocks spike before ALB 5xx?”
  - “What paths / IPs are hammering the app?”
  - “Is it one client, one ASN, one country, or broad?”
  - “Did WAF mitigate, or are we failing downstream?”

This is precisely why WAF logging destinations include CloudWatch Logs (fast search) and S3/Firehose (archive/SIEM pipeline)
# Bonus-D: Apex ALIAS & ALB Access Logs (chrisbarm)
---
**Section Summary:**
Covers adding a Route53 apex ALIAS record pointing to the ALB and enabling ALB access logging to S3. Includes Terraform resources, variables, outputs, and CLI verification for DNS and log delivery.

## Student Verification (CLI)

1. **Verify apex record exists**
   ```sh
   aws route53 list-resource-record-sets \
     --hosted-zone-id <ZONE_ID> \
     --query "ResourceRecordSets[?Name=='chrisbdevsecops.com.']"
   ```

2. **Verify ALB logging is enabled**
   ```sh
   aws elbv2 describe-load-balancers \
     --names chrisbarm-alb01 \
     --query "LoadBalancers[0].LoadBalancerArn"
   
   aws elbv2 describe-load-balancer-attributes \
     --load-balancer-arn <ALB_ARN>
   ```
   **Expected attributes include:**
   - access_logs.s3.enabled = true
   - access_logs.s3.bucket = your bucket
   - access_logs.s3.prefix = your prefix

3. **Generate some traffic**
   ```sh
  curl -I https://chrisbdevsecops.com
  curl -I https://app.chrisbdevsecops.com
   ```

4. **Verify logs arrived in S3 (may take a few minutes)**
   ```sh
   aws s3 ls s3://<BUCKET_NAME>/<PREFIX>/AWSLogs/<ACCOUNT_ID>/elasticloadbalancing/ --recursive | head
   ```

---
## Why this matters (career-critical point)

Access logs tell you:
  - client IPs
  - paths
  - response codes
  - target behavior
  - latency

Combined with WAF logs/metrics and ALB 5xx alarms, you can do real triage:
  “Is it attackers, misroutes, or downstream failure?”

---
# Bonus-B Route53 Add-on (chrisbarm)
---
**Section Summary:**
Explains how to manage Route53 hosted zones and DNS records for the app domain in Terraform, including ACM DNS validation. Provides code snippets and verification steps.

### 1. Add to variables.tf

```hcl
variable "manage_route53_in_terraform" {
  description = "If true, create/manage Route53 hosted zone + records in Terraform."
  type        = bool
  default     = true
}

variable "route53_hosted_zone_id" {
  description = "If manage_route53_in_terraform=false, provide existing Hosted Zone ID for domain."
  type        = string
  default     = ""
}
```

---

### 2. Add file: bonus_b_route53.tf

```hcl
############################################
# Route53 Add-on (chrisbarm style)
---
**Section Summary:**
Detailed Terraform skeleton for Route53 zone, ACM certificate, DNS validation, and ALIAS record. Shows how to wire up DNS and TLS for the app using infrastructure as code.
############################################

resource "aws_route53_zone" "chrisbarm_zone01" {
  count = var.manage_route53_in_terraform ? 1 : 0
  name  = var.domain_name
}

locals {
  chrisbarm_zone_id = var.manage_route53_in_terraform ? aws_route53_zone.chrisbarm_zone01[0].zone_id : var.route53_hosted_zone_id
  chrisbarm_app_fqdn = "${var.app_subdomain}.${var.domain_name}"
}

resource "aws_acm_certificate" "chrisbarm_acm_cert01" {
  domain_name       = local.chrisbarm_app_fqdn
  validation_method = "DNS"
}

resource "aws_route53_record" "chrisbarm_acm_validation" {
  for_each = {
    for dvo in aws_acm_certificate.chrisbarm_acm_cert01.domain_validation_options : dvo.domain_name => {
      name  = dvo.resource_record_name
      type  = dvo.resource_record_type
      value = dvo.resource_record_value
    }
  }
  zone_id = local.chrisbarm_zone_id
  name    = each.value.name
  type    = each.value.type
  records = [each.value.value]
  ttl     = 60
}

resource "aws_acm_certificate_validation" "chrisbarm_acm_validation01_dns_bonus" {
  certificate_arn         = aws_acm_certificate.chrisbarm_acm_cert01.arn
  validation_record_fqdns = [for record in aws_route53_record.chrisbarm_acm_validation : record.fqdn]
}

resource "aws_route53_record" "chrisbarm_app_alias01" {
  zone_id = local.chrisbarm_zone_id
  name    = local.chrisbarm_app_fqdn
  type    = "A"
  alias {
    name                   = aws_lb.chrisbarm_alb01.dns_name
    zone_id                = aws_lb.chrisbarm_alb01.zone_id
    evaluate_target_health = true
  }
}
```

---

### 3. Update your HTTPS listener in bonus_b.tf

```hcl
resource "aws_lb_listener" "chrisbarm_alb_https" {
  load_balancer_arn = aws_lb.chrisbarm_alb01.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.chrisbarm_acm_cert01.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.chrisbarm_alb_tg01.arn
  }

  depends_on = [
    aws_acm_certificate_validation.chrisbarm_acm_validation01_dns_bonus
  ]
}
```

---

### 4. Add to outputs.tf

```hcl
output "chrisbarm_route53_zone_id" {
  value = local.chrisbarm_zone_id
}

output "chrisbarm_app_url_https" {
  value = "https://${var.app_subdomain}.${var.domain_name}"
}
```

---

### 5. Verification (CLI)

1. **Confirm hosted zone exists**
   ```sh
   aws route53 list-hosted-zones-by-name --dns-name chrisbdevsecops.com --query "HostedZones[].Id"
   ```

2. **Confirm app record exists**
   ```sh
   aws route53 list-resource-record-sets --hosted-zone-id <ZONE_ID> --query "ResourceRecordSets[?Name=='app.chrisbdevsecops.com.']"
   ```

3. **Confirm certificate issued**
   ```sh
   aws acm describe-certificate --certificate-arn <CERT_ARN> --query "Certificate.Status"
   ```
   **Expected:** ISSUED

4. **Confirm HTTPS works**
   ```sh
   curl -I https://app.chrisbdevsecops.com
   ```
   **Expected:** HTTP/1.1 200 (or 301 then 200 depending on your app)

---

**Note:**
- All resource names use the chrisbarm prefix.
- This is the real-world pattern for DNS, TLS, and ALB in AWS.

---
# Bonus-B: Enterprise Pattern (chrisbarm)
---
**Section Summary:**
Describes the full enterprise AWS pattern: public ALB, private EC2, TLS, WAF, CloudWatch dashboard, and SNS alarms. Lists what must be implemented and provides CLI verification commands for each component.

This stack implements a real enterprise AWS pattern:

- **Public ALB (internet-facing)**
- **Private EC2 targets (no public IP)**
- **TLS with ACM for app.chrisbdevsecops.com**
- **WAF attached to ALB**
- **CloudWatch Dashboard**
- **SNS alarm on ALB 5xx spikes**

This is how modern companies ship: IaC + private compute + managed ingress + TLS + WAF + monitoring + paging.

---

### What you must implement

- **TLS (ACM) validation for app.chrisbdevsecops.com**
  - DNS validation (best): create Route53 hosted zone + validation records in Terraform, or
  - Email validation (acceptable): do it manually, then Terraform continues

- **ALB Security Group rules**
  - Inbound 80/443 from 0.0.0.0/0
  - Outbound to targets on app port

- **EC2 runs app on the target port**
  - Ensure user-data/app listens on port 80 (or update TG/SG accordingly)

---

### Verification commands (CLI) for Bonus-B

1. **ALB exists and is active**
   ```sh
   aws elbv2 describe-load-balancers \
     --names chrisbarm-alb01 \
     --query "LoadBalancers[0].State.Code"
   ```

2. **HTTPS listener exists on 443**
   ```sh
   aws elbv2 describe-listeners \
     --load-balancer-arn <ALB_ARN> \
     --query "Listeners[].Port"
   ```

3. **Target is healthy**
   ```sh
   aws elbv2 describe-target-health \
     --target-group-arn <TG_ARN>
   ```

4. **WAF attached**
   ```sh
   aws wafv2 get-web-acl-for-resource \
     --resource-arn <ALB_ARN>
   ```

5. **Alarm created (ALB 5xx)**
   ```sh
   aws cloudwatch describe-alarms \
     --alarm-name-prefix chrisbarm-alb-5xx
   ```

6. **Dashboard exists**
   ```sh
   aws cloudwatch list-dashboards \
     --dashboard-name-prefix chrisbarm
   ```

---

**Note:**
- All resource names use the chrisbarm prefix, not chewbacca.
- If you need a Route53 skeleton or further customization, just ask!
---
# Bonus-A: Private Compute, Endpoints, IAM
---
**Section Summary:**
Documents the design goals for private compute: EC2 in private subnets, SSM Session Manager, VPC endpoints for AWS APIs, S3 gateway, and least-privilege IAM. Explains why these are best practices.

## Design Goals

- **EC2 is private (no public IP):**  All EC2 instances are launched in private subnets with no public IPs assigned.
- **No SSH required (use SSM Session Manager):**  SSM Session Manager is enabled via VPC endpoints, so you can access instances without SSH or public IPs.
- **Private subnets don’t need NAT to talk to AWS control-plane services:**  VPC Interface Endpoints are created for SSM, EC2Messages, SSMMessages, CloudWatch Logs, Secrets Manager, and optionally KMS.
- **Use S3 Gateway Endpoint:**  S3 Gateway endpoint is provisioned for private access to S3 (for package repos, etc.).
- **Tighten IAM:**  IAM policies restrict GetSecretValue to only your secret, and GetParameter(s) to only your SSM path.

# Student Verification (CLI) for Bonus-A
---
**Section Summary:**
Step-by-step CLI commands for students to prove their EC2 is private, VPC endpoints exist, SSM works, IAM is correct, and CloudWatch logs are delivered privately.

1. **Prove EC2 is private (no public IP):**
  ```sh
  aws ec2 describe-instances --instance-ids <INSTANCE_ID> --query "Reservations[].Instances[].PublicIpAddress"
  ```
  **Expected:** `null`

2. **Prove VPC endpoints exist:**
  ```sh
  aws ec2 describe-vpc-endpoints --filters "Name=vpc-id,Values=<VPC_ID>" --query "VpcEndpoints[].ServiceName"
  ```
  **Expected:** List includes: ssm, ec2messages, ssmmessages, logs, secretsmanager, s3

3. **Prove Session Manager path works (no SSH):**
  ```sh
  aws ssm describe-instance-information --query "InstanceInformationList[].InstanceId"
  ```
  **Expected:** Your private EC2 instance ID appears

4. **Prove the instance can read both config stores (from SSM session):**
  ```sh
  aws ssm get-parameter --name /lab/db/endpoint
  aws secretsmanager get-secret-value --secret-id <your-secret-name>
  ```

5. **Prove CloudWatch logs delivery path is available via endpoint:**
  ```sh
  aws logs describe-log-streams --log-group-name /aws/ec2/<prefix>-rds-app
  ```

# Real-World Mapping
---
**Section Summary:**
Maps the lab’s architecture and practices to real-world cloud engineering and security requirements, emphasizing why each pattern is used in industry.

- **Private compute + SSM** is standard in regulated orgs and mature cloud shops.
- **VPC endpoints** reduce exposure and dependency on NAT for AWS APIs.
- **Least privilege** is not optional in security interviews.
- **Terraform workflow** (PR → plan → review → apply → monitor) mirrors how real teams ship changes.

---
# Terraform Outputs
---
**Section Summary:**
Lists all key Terraform outputs: ARNs, DNS names, log group names, subnet IDs, endpoints, and more. These are the coordinates for all major AWS resources created in the lab.

acm_certificate_arn = "arn:aws:acm:us-east-1:198547498722:certificate/3de0afe2-3d6d-48b6-9d5a-36d672c8a363"
acm_dns_validation_records = []
alb_arn = "arn:aws:elasticloadbalancing:us-east-1:198547498722:loadbalancer/app/chrisbarm-alb01/f44080c04815d278"
alb_dashboard_name = "chrisbarm-alb-dashboard"
alb_dns_name = "chrisbarm-alb01-314051232.us-east-1.elb.amazonaws.com"
alb_target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:198547498722:targetgroup/chrisbarm-tg01/6d98bd3be23bcc29"
app_url = "https://app.chrisbdevsecops.com"
chrisbarm_app_url_https = "https://app.chrisbdevsecops.com"
chrisbarm_log_group_name = "/aws/ec2/chrisbarm-rds-app"
chrisbarm_private_subnet_ids = [
  "subnet-0d031673ccea05cd3",
  "subnet-0f2feaef150f4e03b",
]
chrisbarm_public_subnet_ids = [
  "subnet-0655ae0b6e9841dcb",
  "subnet-00d181630fc5e348a",
]
chrisbarm_rds_endpoint = "chrisbarm-rds01.c4x68420cyvy.us-east-1.rds.amazonaws.com"
chrisbarm_route53_zone_id = "Z08048393STUNV0M1KHTL"
chrisbarm_sns_topic_arn = "arn:aws:sns:us-east-1:198547498722:chrisbarm-db-incidents"
chrisbarm_vpc_id = "vpc-02166ff22af50efb9"
db_connection_alarm_name = "lab-db-connection-failure"
db_incidents_topic_arn = "arn:aws:sns:us-east-1:198547498722:lab-db-incidents"
db_incidents_topic_name = "lab-db-incidents"
log_group_name = "/aws/ec2/chrisbarm-rds-app"
waf_web_acl_arn = "arn:aws:wafv2:us-east-1:198547498722:regional/webacl/chrisbarm-waf01/7327a679-f0c1-49a7-b8a1-d794659ca1f9"
