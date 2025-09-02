output "vpc_id" {
  value = try(module.vpc.vpc_id, "")
}

output "vpc_arn" {
  value = try(module.vpc.vpc_arn, "")
}

output "vpc_private_subnets" {
  value = try(module.vpc.private_subnets, "")
}

output "private_subnets_cidr_blocks" {
  value = try(module.vpc.private_subnets_cidr_blocks, "")
}

output "load_balancer_dns_name" {
  value = try(module.network_load_balancer.load_balancer_dns_name, "")
}
