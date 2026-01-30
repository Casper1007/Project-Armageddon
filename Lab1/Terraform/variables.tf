variable "project" {
  description = "Project name or prefix for resource naming."
  type        = string
  default     = "chrisbarm"
}
variable "waf_log_destination" {
  description = "Choose ONE destination per WebACL: cloudwatch | s3 | firehose"
  type        = string
  default     = "cloudwatch"
}

variable "waf_log_retention_days" {
  description = "Retention for WAF CloudWatch log group."
  type        = number
  default     = 14
}

variable "enable_waf_sampled_requests_only" {
  description = "If true, students can optionally filter/redact fields later. (Placeholder toggle.)"
  type        = bool
  default     = false
}
variable "enable_alb_access_logs" {
  description = "Enable ALB access logging to S3."
  type        = bool
  default     = true
}

variable "alb_access_logs_prefix" {
  description = "S3 prefix for ALB access logs."
  type        = string
  default     = "alb-access-logs"
}
variable "acm_certificate_arn" {
  description = "ACM certificate ARN to use for the ALB. Leave blank to use the managed ACM certificate."
  type        = string
  default     = "arn:aws:acm:us-east-1:198547498722:certificate/3de0afe2-3d6d-48b6-9d5a-36d672c8a363"
}
variable "aws_region" {
  description = "AWS Region for the Chrisbarm lab environment."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix for naming (used in tags and resource names)."
  type        = string
  default     = "chrisbarm"
}

variable "vpc_cidr" {
  description = "VPC CIDR (use 10.x.x.x/xx as instructed)."
  type        = string
  default     = "10.0.0.0/16" # TODO: student supplies
}

variable "public_subnet_cidrs" {
  description = "Public subnet CIDRs (use 10.x.x.x/xx)."
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"] # TODO: student supplies
}

variable "private_subnet_cidrs" {
  description = "Private subnet CIDRs (use 10.x.x.x/xx)."
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24"] # TODO: student supplies
}

variable "azs" {
  description = "Availability Zones list (match count with subnets)."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"] # TODO: student supplies
}

variable "ec2_ami_id" {
  description = "AMI ID for the EC2 app host."
  type        = string
  default     = "ami-REPLACE_ME" # TODO
}

variable "ec2_instance_type" {
  description = "EC2 instance size for the app."
  type        = string
  default     = "t3.micro"
}


variable "key_name" {
  description = "Optional EC2 key pair name. Leave null/empty to avoid SSH keys (SSM recommended)."
  type        = string
  default     = null
}

variable "enable_nat_gateway" {
  description = "Whether to create a NAT gateway for private subnet outbound internet access."
  type        = bool
  default     = false
}

variable "enable_kms_endpoint" {
  description = "Whether to create an Interface VPC Endpoint for KMS."
  type        = bool
  default     = false
}

variable "ssm_parameter_path" {
  description = "Root path for SSM parameters used by the app."
  type        = string
  default     = "/lab/db"
}
variable "db_engine" {
  description = "RDS engine."
  type        = string
  default     = "mysql"
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t3.micro"
}


variable "storage_type" {
  description = "RDS storage type (gp3 recommended)."
  type        = string
  default     = "gp3"
}
variable "db_name" {
  description = "Initial database name."
  type        = string
  default     = "labdb" # Students can change
}

variable "db_username" {
  description = "DB master username (students should use Secrets Manager in 1B/1C)."
  type        = string
  default     = "admin" # TODO: student supplies
}

variable "db_password" {
  description = "DB master password (DO NOT hardcode in real life; for lab only)."
  type        = string
  sensitive   = true
  default     = "REPLACE_ME" # TODO: student supplies
}

variable "sns_email_endpoint" {
  description = "Email for SNS subscription (PagerDuty simulation)."
  type        = string
  default     = "student@example.com" # TODO: student supplies
}

############################################
# Lab 1C Bonus-B variables
############################################

variable "domain_name" {
  description = "Root domain for the app (example: www.chrisbdevsecops.com)."
  type        = string
  default     = "chrisbdevsecops.com"
}

variable "app_subdomain" {
  description = "Subdomain for the app (example: app)."
  type        = string
  default     = "www"
}

variable "app_port" {
  description = "Port the app listens on behind the ALB."
  type        = number
  default     = 80
}

variable "health_check_path" {
  description = "ALB target group health check path."
  type        = string
  default     = "/"
}

variable "acm_validation_method" {
  description = "ACM validation method. Use DNS if you can manage Route53 in Terraform."
  type        = string
  default     = "DNS"
}

variable "route53_zone_id" {
  description = "Route53 Hosted Zone ID for the domain. Leave empty if DNS is external."
  type        = string
  default     = ""
}

variable "create_route53_zone" {
  description = "Create a Route53 public hosted zone for domain_name."
  type        = bool
  default     = false
}

variable "manage_route53_in_terraform" {
  description = "If true, create/manage Route53 hosted zone + records in Terraform."
  type        = bool
  default     = false
}

variable "route53_hosted_zone_id" {
  description = "If manage_route53_in_terraform=false, provide existing Hosted Zone ID for domain."
  type        = string
  default     = ""
}

variable "alb_5xx_threshold" {
  description = "ALB 5XX alarm threshold."
  type        = number
  default     = 5
}
