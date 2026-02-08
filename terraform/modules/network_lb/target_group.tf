resource "aws_lb_target_group" "ssh_22" {
  count = var.module_enabled ? 1 : 0

  name_prefix          = "22-"
  port                 = 22
  protocol             = "TCP"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  deregistration_delay = 90
  preserve_client_ip   = true

  target_health_state {
    enable_unhealthy_connection_termination = false
  }
}
