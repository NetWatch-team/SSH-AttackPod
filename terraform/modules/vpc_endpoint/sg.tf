resource "aws_security_group" "ssm" {

  name_prefix = "vpc-endpoint-ssm"
  description = "SG to SSM"
  vpc_id      = var.vpc_id

  tags = merge({ Name = "vpc-endpoint-ssm-${var.vpc_id}" }, var.tags)
}

resource "aws_security_group_rule" "ssm_incoming" {

  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = [var.vpc_cidr_block]
  security_group_id = aws_security_group.ssm.id
  description       = "Allow 443 inbound traffic from trusted Security Groups"
}

resource "aws_security_group_rule" "ssm_outbound" {

  type              = "egress"
  from_port         = 0
  to_port           = 65535
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.ssm.id
  description       = "Allow all outbound traffic"
}
