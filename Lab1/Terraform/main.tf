############################################
# Locals (naming convention: satellite-*)
############################################
locals {
  name_prefix = var.project_name
  ports_http  = 80
  ports_ssh   = 22
  ports_https = 443
  # ports_dns = 53
  db_port        = 3306
  tcp_protocol   = "tcp"
  udp_protocol   = "udp"
  all_ip_address = "0.0.0.0/0"
  # For AWS SG rules, "all protocols" is represented by ip_protocol = "-1".
  # When ip_protocol = "-1", AWS expects from_port/to_port to be 0.
  all_ports    = 0
  all_protocol = "-1"
}

data "aws_caller_identity" "current" {}

data "aws_prefix_list" "s3" {
  name = "com.amazonaws.${var.aws_region}.s3"
}

############################################
# VPC + Internet Gateway
############################################

# Explanation: satellite needs a hyperlaneâ€”this VPC is the Millennium Falconâ€™s flight corridor.
resource "aws_vpc" "chrisbarm_vpc01" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${local.name_prefix}-vpc01"
  }
}

# Explanation: Even Wookiees need to reach the wider galaxyâ€”IGW is your door to the public internet.
resource "aws_internet_gateway" "chrisbarm_igw01" {
  vpc_id = aws_vpc.chrisbarm_vpc01.id

  tags = {
    Name = "${local.name_prefix}-igw01"
  }
}

############################################
# Subnets (Public + Private)
############################################

# Explanation: Public subnets are like docking baysâ€”ships can land directly from space (internet).
resource "aws_subnet" "chrisbarm_public_subnets" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.chrisbarm_vpc01.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${local.name_prefix}-public-subnet0${count.index + 1}"
  }
}

# Explanation: Private subnets are the hidden Rebel baseâ€”no direct access from the internet.
resource "aws_subnet" "chrisbarm_private_subnets" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.chrisbarm_vpc01.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.azs[count.index]
  
  

  tags = {
    Name = "${local.name_prefix}-private-subnet0${count.index + 1}"
  }
}

############################################
# NAT Gateway + EIP
############################################

# Explanation: satellite wants the private base to call homeâ€”EIP gives the NAT a stable â€œholonet address.â€
resource "aws_eip" "_nat_eip01" {
  count  = var.enable_nat_gateway ? 1 : 0
  domain = "vpc"

  tags = {
    Name = "${local.name_prefix}-nat-eip01"
  }
}

# Explanation: NAT is satelliteâ€™s smuggler tunnelâ€”private subnets can reach out without being seen.
resource "aws_nat_gateway" "chrisbarm_nat01" {
  count         = var.enable_nat_gateway ? 1 : 0
  allocation_id = aws_eip._nat_eip01[0].id
  subnet_id     = aws_subnet.chrisbarm_public_subnets[0].id # NAT in a public subnet

  tags = {
    Name = "${local.name_prefix}-nat01"
  }

  depends_on = [aws_internet_gateway.chrisbarm_igw01]
}

############################################
# Routing (Public + Private Route Tables)
############################################

# Explanation: Public route table = â€œopen lanesâ€ to the galaxy via IGW.
resource "aws_route_table" "_public_rt01" {
  vpc_id = aws_vpc.chrisbarm_vpc01.id

  tags = {
    Name = "${local.name_prefix}-public-rt01"
  }
}

# Explanation: This route is the Kessel Runâ€”0.0.0.0/0 goes out the IGW.
resource "aws_route" "chrisbarm_public_default_route" {
  route_table_id         = aws_route_table._public_rt01.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.chrisbarm_igw01.id
}

# Explanation: Attach public subnets to the â€œpublic lanes.â€
resource "aws_route_table_association" "chrisbarm_public_rta" {
  count          = length(aws_subnet.chrisbarm_public_subnets)
  subnet_id      = aws_subnet.chrisbarm_public_subnets[count.index].id
  route_table_id = aws_route_table._public_rt01.id
}

# Explanation: Private route table = â€œstay hidden, but still ship supplies.â€
resource "aws_route_table" "_private_rt01" {
  vpc_id = aws_vpc.chrisbarm_vpc01.id

  tags = {
    Name = "${local.name_prefix}-private-rt01"
  }
}

# Explanation: Private subnets route outbound internet via NAT (satellite-approved stealth).
resource "aws_route" "chrisbarm_private_default_route" {
  count                  = var.enable_nat_gateway ? 1 : 0
  route_table_id         = aws_route_table._private_rt01.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.chrisbarm_nat01[0].id
}

# Explanation: Attach private subnets to the â€œstealth lanes.â€
resource "aws_route_table_association" "chrisbarm_private_rta" {
  count          = length(aws_subnet.chrisbarm_private_subnets)
  subnet_id      = aws_subnet.chrisbarm_private_subnets[count.index].id
  route_table_id = aws_route_table._private_rt01.id
}

############################################
# Security Groups (EC2 + RDS)
############################################

# Explanation: EC2 SG is satelliteâ€™s bodyguardâ€”only let in what you mean to.
resource "aws_security_group" "chrisbarm_ec2_sg01" {
  name        = "${local.name_prefix}-ec2-sg01"
  description = "EC2 app security group"
  vpc_id      = aws_vpc.chrisbarm_vpc01.id

  tags = {
    Name = "${local.name_prefix}-ec2-sg01"
  }
}
resource "aws_security_group" "chrisbarm_ec2_sg02" {
  name        = "${local.name_prefix}-ec2-sg02"
  description = "EC2 app security group"
  vpc_id      = aws_vpc.chrisbarm_vpc01.id

  tags = {
    Name = "${local.name_prefix}-ec2-sg02"
  }
}

# Explanation: VPC endpoint SG allows private instances to reach AWS APIs via Interface Endpoints.
resource "aws_security_group" "chrisbarm_vpce_sg01" {
  name        = "${local.name_prefix}-vpce-sg01"
  description = "Interface VPC endpoints security group"
  vpc_id      = aws_vpc.chrisbarm_vpc01.id

  tags = {
    Name = "${local.name_prefix}-vpce-sg01"
  }
}

resource "aws_vpc_security_group_ingress_rule" "chrisbarm_vpce_sg_ingress_https" {
  ip_protocol                  = local.tcp_protocol
  security_group_id            = aws_security_group.chrisbarm_vpce_sg01.id
  from_port                    = local.ports_https
  to_port                      = local.ports_https
  referenced_security_group_id = aws_security_group.chrisbarm_ec2_sg01.id
}

resource "aws_vpc_security_group_egress_rule" "chrisbarm_vpce_sg_egress_all" {
  ip_protocol       = local.all_protocol
  security_group_id = aws_security_group.chrisbarm_vpce_sg01.id
  from_port         = -1
  to_port           = -1
  cidr_ipv4         = local.all_ip_address
}

# Adds inbound rules (HTTP 80, SSH 22 from their IP)

resource "aws_vpc_security_group_ingress_rule" "chrisbarm_ec2_sg_ingress_http" {
  ip_protocol       = local.tcp_protocol
  security_group_id = aws_security_group.chrisbarm_ec2_sg01.id
  from_port         = local.ports_http
  to_port           = local.ports_http
  cidr_ipv4         = var.vpc_cidr
}

# resource "aws_vpc_security_group_ingress_rule" "satellite_bastion_host_sg_ingress_ssh" {
#   ip_protocol       = local.tcp_protocol
#   security_group_id = aws_security_group.satellite_ec2_sg02.id
#   from_port         = local.ports_ssh
#   to_port           = local.ports_ssh
#   cidr_ipv4         = var.my_ip_cidr
# }
# resource "aws_vpc_security_group_ingress_rule" "satellite_ec2_sg_ingress_private_ssh" {
#   ip_protocol                  = local.tcp_protocol
#   security_group_id            = aws_security_group.satellite_ec2_sg02.id
#   from_port                    = local.ports_ssh
#   to_port                      = local.ports_ssh
#   referenced_security_group_id = aws_security_group.satellite_ec2_sg02.id #allow traffic ONLY from specified SG
# }


# Ensures outbound allows DB port to RDS SG (or allow all outbound)
# Chris- We should not need http, but keeping it
# resource "aws_vpc_security_group_egress_rule" "satellite_ec2_sg_egress_http" {
#   ip_protocol       = local.tcp_protocol
#   security_group_id = aws_security_group.satellite_ec2_sg01.id
#   from_port         = local.ports_http
#   to_port           = local.ports_http
#   cidr_ipv4         = local.all_ip_address
# }

# Chris- My working click ops environment
# Tightened egress: DB + AWS endpoints + S3 + DNS
resource "aws_vpc_security_group_egress_rule" "chrisbarm_ec2_sg_egress_db" {
  ip_protocol                  = local.tcp_protocol
  security_group_id            = aws_security_group.chrisbarm_ec2_sg01.id
  from_port                    = local.db_port
  to_port                      = local.db_port
  referenced_security_group_id = aws_security_group.chrisbarm_rds_sg01.id
}

resource "aws_vpc_security_group_egress_rule" "chrisbarm_ec2_sg_egress_https_vpce" {
  ip_protocol                  = local.tcp_protocol
  security_group_id            = aws_security_group.chrisbarm_ec2_sg01.id
  from_port                    = local.ports_https
  to_port                      = local.ports_https
  referenced_security_group_id = aws_security_group.chrisbarm_vpce_sg01.id
}

resource "aws_vpc_security_group_egress_rule" "chrisbarm_ec2_sg_egress_https_s3" {
  ip_protocol       = local.tcp_protocol
  security_group_id = aws_security_group.chrisbarm_ec2_sg01.id
  from_port         = local.ports_https
  to_port           = local.ports_https
  prefix_list_id    = data.aws_prefix_list.s3.id
}

resource "aws_vpc_security_group_egress_rule" "chrisbarm_ec2_sg_egress_dns_udp" {
  ip_protocol       = local.udp_protocol
  security_group_id = aws_security_group.chrisbarm_ec2_sg01.id
  from_port         = 53
  to_port           = 53
  cidr_ipv4         = var.vpc_cidr
}

resource "aws_vpc_security_group_egress_rule" "chrisbarm_ec2_sg_egress_dns_tcp" {
  ip_protocol       = local.tcp_protocol
  security_group_id = aws_security_group.chrisbarm_ec2_sg01.id
  from_port         = 53
  to_port           = 53
  cidr_ipv4         = var.vpc_cidr
}

# Explanation: RDS SG is the Rebel vaultâ€”only the app server gets a keycard.
resource "aws_security_group" "chrisbarm_rds_sg01" {
  name        = "${local.name_prefix}-rds-sg01"
  description = "RDS security group"
  vpc_id      = aws_vpc.chrisbarm_vpc01.id

  tags = {
    Name = "${local.name_prefix}-rds-sg01"
  }
}

# TODO: student adds inbound MySQL 3306 from aws_security_group.chrisbarm_ec2_sg01.id

resource "aws_vpc_security_group_ingress_rule" "chrisbarm_rds_sg_ingress_mysql" {
  ip_protocol                  = local.tcp_protocol
  security_group_id            = aws_security_group.chrisbarm_rds_sg01.id
  from_port                    = local.db_port
  to_port                      = local.db_port
  referenced_security_group_id = aws_security_group.chrisbarm_ec2_sg01.id #allow traffic ONLY from specified SG
}


############################################
# RDS Subnet Group
############################################

# Explanation: RDS hides in private subnets like the Rebel base on Hothâ€”cold, quiet, and not public.
resource "aws_db_subnet_group" "chrisbarm_rds_subnet_group01" {
  name       = "${local.name_prefix}-rds-subnet-group01"
  subnet_ids = aws_subnet.chrisbarm_private_subnets[*].id

  tags = {
    Name = "${local.name_prefix}-rds-subnet-group01"
  }
}

############################################
# RDS Instance (MySQL)
############################################

# Explanation: This is the holocron of stateâ€”your relational data lives here, not on the EC2.
resource "aws_db_instance" "chrisbarm_rds01" {
  identifier               = "${local.name_prefix}-rds01"
  engine                   = var.db_engine
  instance_class           = var.db_instance_class
  storage_type             = var.storage_type
  allocated_storage        = 20
  backup_retention_period  = 0  # Free tier: set to 0 to disable automated backups
  db_name                  = var.db_name
  username                 = var.db_username
  password                 = var.db_password
  multi_az                 = false  # Free tier limitation: set to false
  delete_automated_backups = false

  db_subnet_group_name   = aws_db_subnet_group.chrisbarm_rds_subnet_group01.name
  vpc_security_group_ids = [aws_security_group.chrisbarm_rds_sg01.id]

  publicly_accessible = false
  skip_final_snapshot = true

  # TODO: student sets multi_az / backups / monitoring as stretch goals

  tags = {
    Name = "${local.name_prefix}-rds01"
  }

  depends_on = [aws_db_subnet_group.chrisbarm_rds_subnet_group01, aws_security_group.chrisbarm_rds_sg01]
}

############################################
# IAM Role + Instance Profile for EC2
############################################

# Explanation: satellite refuses to carry static keysâ€”this role lets EC2 assume permissions safely.
resource "aws_iam_role" "chrisbarm_ec2_role01" {
  name = "${local.name_prefix}-ec2-role01"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  lifecycle {
    ignore_changes = all
  }
}
resource "aws_iam_role" "chrisbarm_ec2_role02" {
  name = "${local.name_prefix}-ec2-role02"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Explanation: These policies are your Wookiee toolbeltâ€”tighten them (least privilege) as a stretch goal.
resource "aws_iam_role_policy_attachment" "chrisbarm_ec2_ssm_attach" {
  role       = aws_iam_role.chrisbarm_ec2_role01.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
# resource "aws_iam_role_policy_attachment" "chrisbarm_ec2_ssm_attach02" {
#   role       = aws_iam_role.chrisbarm_ec2_role02.name
#   policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
# }

# Explanation: EC2 must read secrets/params during recoveryâ€”give it access (students should scope it down).
resource "aws_iam_role_policy_attachment" "chrisbarm_ec2_secrets_attach" {
  role       = aws_iam_role.chrisbarm_ec2_role01.name
  policy_arn = aws_iam_policy.chrisbarm_secrets_policy.arn
}

# Explanation: CloudWatch logs are the â€œshipâ€™s black boxâ€â€”you need them when things explode.
resource "aws_iam_role_policy_attachment" "chrisbarm_ec2_cw_attach" {
  role       = aws_iam_role.chrisbarm_ec2_role01.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Explanation: Instance profile is the harness that straps the role onto the EC2 like bandolier ammo.
resource "aws_iam_instance_profile" "chrisbarm_instance_profile01" {
  name = "${local.name_prefix}-instance-profile01"
  role = aws_iam_role.chrisbarm_ec2_role01.name

  lifecycle {
    ignore_changes = all
  }
}
resource "aws_iam_instance_profile" "chrisbarm_instance_profile02" {
  name = "${local.name_prefix}-instance-profile02"
  role = aws_iam_role.chrisbarm_ec2_role02.name
}
resource "aws_iam_policy" "chrisbarm_secrets_policy" {
  name        = "secrets_policy"
  description = "EC2 to RDS using Secrets Manager"

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "ReadSpecificSecret",
        "Effect" : "Allow",
        "Action" : [
          "secretsmanager:GetSecretValue"
        ],
        "Resource" : "${aws_secretsmanager_secret.chrisbarm_db_secret01.arn}*"
      }
    ]
  })

  lifecycle {
    ignore_changes = all
  }
}

resource "aws_iam_policy" "chrisbarm_ssm_param_policy" {
  name        = "ssm_param_read_policy"
  description = "EC2 read-only access to app SSM parameters"

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "ReadAppParams",
        "Effect" : "Allow",
        "Action" : [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ],
        "Resource" : "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter${var.ssm_parameter_path}/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "chrisbarm_ec2_ssm_param_attach" {
  role       = aws_iam_role.chrisbarm_ec2_role01.name
  policy_arn = aws_iam_policy.chrisbarm_ssm_param_policy.arn
}

############################################
# EC2 Instance (App Host)
############################################

# Explanation: This is your â€œHan Solo boxâ€â€”it talks to RDS and complains loudly when the DB is down.
resource "aws_instance" "chrisbarm_bastion_host_ec2_02" {
  ami                         = "ami-0030e4319cbf4dbf2"  # Ubuntu 22.04 LTS in us-east-1
  instance_type               = var.ec2_instance_type
  subnet_id                   = aws_subnet.chrisbarm_private_subnets[0].id
  vpc_security_group_ids      = [aws_security_group.chrisbarm_ec2_sg01.id]
  iam_instance_profile        = aws_iam_instance_profile.chrisbarm_instance_profile01.name
  # user_data_replace_on_change = true
  associate_public_ip_address = false
  
  # TODO: student supplies user_data to install app + CW agent + configure log shipping
  // user_data  = file("${path.module}/1a_user_data.sh")
  # depends_on = [aws_db_instance.satellite_rds01]

  tags = {
    Name = "${local.name_prefix}-bastion-host"
  }
}
resource "aws_instance" "chrisbarm_ec2_01" {
  ami                         = "ami-0030e4319cbf4dbf2"  # Ubuntu 22.04 LTS in us-east-1
  instance_type               = var.ec2_instance_type
  subnet_id                   = aws_subnet.chrisbarm_private_subnets[0].id
  vpc_security_group_ids      = [aws_security_group.chrisbarm_ec2_sg01.id]
  iam_instance_profile        = aws_iam_instance_profile.chrisbarm_instance_profile01.name
  user_data_replace_on_change = true
  associate_public_ip_address = false
  
  # TODO: student supplies user_data to install app + CW agent + configure log shipping
  user_data  = file("${path.module}/1a_user_data.sh")
  depends_on = [aws_db_instance.chrisbarm_rds01]

  tags = {
    Name = "${local.name_prefix}-ec2_01"
  }
}
resource "aws_instance" "chrisbarm_ec2_03" {
  ami                         = "ami-0030e4319cbf4dbf2"  # Ubuntu 22.04 LTS in us-east-1
  instance_type               = var.ec2_instance_type
  subnet_id                   = aws_subnet.chrisbarm_private_subnets[1].id
  vpc_security_group_ids      = [aws_security_group.chrisbarm_ec2_sg01.id]
  iam_instance_profile        = aws_iam_instance_profile.chrisbarm_instance_profile01.name
  #user_data_replace_on_change = true
  associate_public_ip_address = false
  # key_name = var.key_name
  # TODO: student supplies user_data to install app + CW agent + configure log shipping
  #user_data  = file("${path.module}/1a_user_data.sh")
  # depends_on = [aws_db_instance.satellite_rds01]

  tags = {
    Name = "${local.name_prefix}-ec2_03"
  }
}


############################################
# Parameter Store (SSM Parameters)
############################################

# Explanation: Parameter Store is chrisbarmâ€™s mapâ€”endpoints and config live here for fast recovery.
resource "aws_ssm_parameter" "chrisbarm_db_endpoint_param" {
  name      = "/lab/db/endpoint"
  type      = "String"
  value     = aws_db_instance.chrisbarm_rds01.address
  overwrite = true  # Allow overwrite if parameter already exists

  tags = {
    Name = "${local.name_prefix}-param-db-endpoint"
  }
}

# Explanation: Ports are boring, but even Wookiees need to know which door number to kick in.
resource "aws_ssm_parameter" "chrisbarm_db_port_param" {
  name      = "/lab/db/port"
  type      = "String"
  value     = tostring(aws_db_instance.chrisbarm_rds01.port)
  overwrite = true  # Allow overwrite if parameter already exists

  tags = {
    Name = "${local.name_prefix}-param-db-port"
  }
}

# Explanation: DB name is the label on the crateâ€”without it, youâ€™re rummaging in the dark.
resource "aws_ssm_parameter" "chrisbarm_db_name_param" {
  name      = "/lab/db/name"
  type      = "String"
  value     = var.db_name
  overwrite = true  # Allow overwrite if parameter already exists

  tags = {
    Name = "${local.name_prefix}-param-db-name"
  }
}

############################################
# Secrets Manager (DB Credentials)
############################################

# Explanation: Secrets Manager is chrisbarmâ€™s locked holsterâ€”credentials go here, not in code.
#Recovery_window_in_days forces deletion of secrets and allows re-deployment of secret without constantly changing name

resource "aws_secretsmanager_secret" "chrisbarm_db_secret01" {
  name                    = "lab1a/rds/mysql"
  recovery_window_in_days = 0
}

# Explanation: Secret payloadâ€”students should align this structure with their app (and support rotation later).
resource "aws_secretsmanager_secret_version" "chrisbarm_db_secret_version01" {
  secret_id = aws_secretsmanager_secret.chrisbarm_db_secret01.id

  secret_string = jsonencode({
    username = var.db_username
    password = var.db_password
    host     = aws_db_instance.chrisbarm_rds01.address
    port     = aws_db_instance.chrisbarm_rds01.port
    dbname   = var.db_name
  })
}

############################################
# CloudWatch Logs (Log Group)
############################################

# Explanation: When the Falcon is on fire, logs tell you *which* wire sparkedâ€”ship them centrally.
# NOTE: CloudWatch log group already exists in AWS, managed outside of Terraform for now
# resource "aws_cloudwatch_log_group" "chrisbarm_log_group01" {
#   name              = "/aws/ec2/${local.name_prefix}-rds-app"
#   retention_in_days = 7
#
#   tags = {
#     Name = "${local.name_prefix}-log-group01"
#   }
#
#   lifecycle {
#     ignore_changes = all
#   }
#
#   depends_on = [aws_vpc.chrisbarm_vpc01]
# }

############################################
# Custom Metric + Alarm (Skeleton)
############################################

# Explanation: Metrics are satelliteâ€™s growlsâ€”when they spike, something is wrong.
# NOTE: Students must emit the metric from app/agent; this just declares the alarm.
resource "aws_cloudwatch_metric_alarm" "chrisbarm_db_alarm01" {
  alarm_name          = "${local.name_prefix}-db-connection-failure"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "DBConnectionErrors"
  namespace           = "Lab/RDSApp"
  period              = 300
  statistic           = "Sum"
  threshold           = 3

  alarm_actions = [aws_sns_topic.chrisbarm_sns_topic01.arn]

  tags = {
    Name = "${local.name_prefix}-alarm-db-fail"
  }
}

############################################
# SNS (PagerDuty simulation)
############################################

# Explanation: SNS is the distress beaconâ€”when the DB dies, the galaxy (your inbox) must hear about it.
resource "aws_sns_topic" "chrisbarm_sns_topic01" {
  name = "${local.name_prefix}-db-incidents"
}

# Explanation: Email subscription = â€œpoor manâ€™s PagerDutyâ€â€”still enough to wake you up at 3AM.
resource "aws_sns_topic_subscription" "chrisbarm_sns_sub01" {
  topic_arn = aws_sns_topic.chrisbarm_sns_topic01.arn
  protocol  = "email"
  endpoint  = var.sns_email_endpoint
}

############################################
# (Optional but realistic) VPC Endpoints (Skeleton)
############################################

resource "aws_vpc_endpoint" "chrisbarm_vpce_ssm" {
  vpc_id              = aws_vpc.chrisbarm_vpc01.id
  service_name        = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.chrisbarm_private_subnets[*].id
  private_dns_enabled = true
  security_group_ids  = [aws_security_group.chrisbarm_vpce_sg01.id]

  tags = {
    Name = "${local.name_prefix}-vpce-ssm"
  }
}

resource "aws_vpc_endpoint" "chrisbarm_vpce_ec2messages" {
  vpc_id              = aws_vpc.chrisbarm_vpc01.id
  service_name        = "com.amazonaws.${var.aws_region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.chrisbarm_private_subnets[*].id
  private_dns_enabled = true
  security_group_ids  = [aws_security_group.chrisbarm_vpce_sg01.id]

  tags = {
    Name = "${local.name_prefix}-vpce-ec2messages"
  }
}

resource "aws_vpc_endpoint" "chrisbarm_vpce_ssmmessages" {
  vpc_id              = aws_vpc.chrisbarm_vpc01.id
  service_name        = "com.amazonaws.${var.aws_region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.chrisbarm_private_subnets[*].id
  private_dns_enabled = true
  security_group_ids  = [aws_security_group.chrisbarm_vpce_sg01.id]

  tags = {
    Name = "${local.name_prefix}-vpce-ssmmessages"
  }
}

resource "aws_vpc_endpoint" "chrisbarm_vpce_logs" {
  vpc_id              = aws_vpc.chrisbarm_vpc01.id
  service_name        = "com.amazonaws.${var.aws_region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.chrisbarm_private_subnets[*].id
  private_dns_enabled = true
  security_group_ids  = [aws_security_group.chrisbarm_vpce_sg01.id]

  tags = {
    Name = "${local.name_prefix}-vpce-logs"
  }
}

resource "aws_vpc_endpoint" "chrisbarm_vpce_secretsmanager" {
  vpc_id              = aws_vpc.chrisbarm_vpc01.id
  service_name        = "com.amazonaws.${var.aws_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.chrisbarm_private_subnets[*].id
  private_dns_enabled = true
  security_group_ids  = [aws_security_group.chrisbarm_vpce_sg01.id]

  tags = {
    Name = "${local.name_prefix}-vpce-secretsmanager"
  }
}

resource "aws_vpc_endpoint" "chrisbarm_vpce_kms" {
  count               = var.enable_kms_endpoint ? 1 : 0
  vpc_id              = aws_vpc.chrisbarm_vpc01.id
  service_name        = "com.amazonaws.${var.aws_region}.kms"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.chrisbarm_private_subnets[*].id
  private_dns_enabled = true
  security_group_ids  = [aws_security_group.chrisbarm_vpce_sg01.id]

  tags = {
    Name = "${local.name_prefix}-vpce-kms"
  }
}

resource "aws_vpc_endpoint" "chrisbarm_vpce_s3" {
  vpc_id            = aws_vpc.chrisbarm_vpc01.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table._private_rt01.id]

  tags = {
    Name = "${local.name_prefix}-vpce-s3"
  }
}

