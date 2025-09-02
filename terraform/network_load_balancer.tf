
module "network_load_balancer" {
  source = "./modules/network_lb"

  module_enabled = var.mandatory_requirements && var.service_enabled

  lb_name                          = var.project_name
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = true
  ports                            = var.whitelist_ports
  vpc_id                           = try(module.vpc.vpc_id, "")
  loadbalancer_subnets             = try(module.vpc.public_subnets, "")
  ranges_ipv4                      = var.whitelist_source_ipv4
}
