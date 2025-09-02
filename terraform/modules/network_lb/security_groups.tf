resource "aws_security_group" "nlb" {
  count = var.module_enabled ? 1 : 0

  vpc_id      = var.vpc_id
  name_prefix = "${var.lb_name}-"
  description = "Security group for ${var.lb_name}"

  tags = {
    Name = "${var.lb_name}"
  }
}

resource "aws_security_group_rule" "allow" {
  count = var.module_enabled ? length(var.ports) : 0

  type        = "ingress"
  from_port   = element(var.ports, count.index)
  to_port     = element(var.ports, count.index)
  protocol    = "tcp"
  cidr_blocks = var.ranges_ipv4
  #ipv6_cidr_blocks         = var.ranges_ipv6
  security_group_id = aws_security_group.nlb[0].id
  description       = "Allow sources"
}


resource "aws_security_group_rule" "sg_https_lb_egress" {
  count = var.module_enabled ? 1 : 0

  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.nlb[0].id
  description       = "Allow all outbound traffic"
}
