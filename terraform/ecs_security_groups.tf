resource "aws_security_group" "sg_container" {
  count = var.mandatory_requirements && var.service_enabled ? 1 : 0

  vpc_id      = module.vpc.vpc_id
  name_prefix = "${var.project_name}-ecs-fargate-"
  description = "Security group for NetWatch container"

  tags = {
    Name = "${var.project_name}-fargate"
  }
}

resource "aws_security_group_rule" "sg_container_lb" {
  count = var.mandatory_requirements && var.service_enabled ? 1 : 0

  depends_on = [module.network_load_balancer]

  type                     = "ingress"
  from_port                = var.netwatch_port
  to_port                  = var.netwatch_port
  protocol                 = "tcp"
  source_security_group_id = module.network_load_balancer.sg_lb_id
  security_group_id        = aws_security_group.sg_container[0].id
  description              = "Allow ${element(var.whitelist_ports, count.index)} to Container from Load Balancer"
}

output "network_load_balancer_sg_lb_id" {
  value = module.network_load_balancer.sg_lb_id
}

resource "aws_security_group_rule" "sg_container_egress" {
  count = var.mandatory_requirements && var.service_enabled ? 1 : 0

  type              = "egress"
  from_port         = 0
  to_port           = 65535
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.sg_container[0].id
  description       = "Allow all outbound traffic"
}
