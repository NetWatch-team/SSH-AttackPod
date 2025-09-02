resource "aws_lb" "this" {
  count = var.module_enabled ? 1 : 0

  name                             = var.lb_name
  internal                         = false
  load_balancer_type               = "network"
  subnets                          = var.loadbalancer_subnets
  enable_deletion_protection       = var.enable_deletion_protection
  enable_cross_zone_load_balancing = var.enable_cross_zone_load_balancing
  security_groups = [
    aws_security_group.nlb[0].id
  ]

  idle_timeout = 60

  dynamic "access_logs" {
    for_each = var.lb_access_logs_enable && var.lb_access_logs_s3_bucket_name != "" ? [1] : []
    content {
      enabled = var.lb_access_logs_enable
      bucket  = var.lb_access_logs_s3_bucket_name
      prefix  = var.lb_name
    }
  }

  tags = {
    Name = var.lb_name
  }
}

resource "aws_lb_listener" "ssh_22" {
  count = var.module_enabled ? 1 : 0

  load_balancer_arn = aws_lb.this[0].arn
  port              = "22"
  protocol          = "TCP"

  default_action {
    target_group_arn = aws_lb_target_group.ssh_22[0].arn
    type             = "forward"
  }
}
