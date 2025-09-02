# module "vpc" {
#   source = "./modules/vpc"

#   count = var.mandatory_requirements ? 1 : 0

#   vpc_name = var.project_name

#   # General
#   environment = var.env
#   project     = var.project_name

#   tags = {
#     "Project" = "NetWatch PoC"
#   }

#   # Flow Logs
#   enable_flow_logs              = false
#   create_athena_analytics_setup = false

#   # VPC
#   vpc_cidr_block = var.vpc_cidr_block

#   # public subnets
#   public_subnets = var.vpc_public_subnets

#   # workload subnets
#   workload_subnets = var.vpc_workload_subnets

#   # create NAT GW in each AZ
#   enable_nat_gateway = true

#   enable_dns_support   = true
#   enable_dns_hostnames = true

# }

module "vpc_endpoints" {
  source = "./modules/vpc_endpoint"

  count = var.mandatory_requirements ? 1 : 0

  vpc_id         = module.vpc.vpc_id
  vpc_cidr_block = module.vpc.vpc_cidr_block
  subnet_ids     = module.vpc.private_subnets
  endpoints = [
    "sts",
    "ecs",
    "elasticloadbalancing",
    "secretsmanager"
  ]

  tags = var.tags
}

module "vpc" {
  source = "./modules/vpc"

  create_vpc = var.mandatory_requirements

  name = var.project_name
  cidr = var.vpc_cidr_block

  azs             = var.vpc_azs
  private_subnets = var.vpc_private_subnets
  public_subnets  = var.vpc_public_subnets

  enable_nat_gateway   = true
  enable_vpn_gateway   = false
  enable_dns_hostnames = true
  enable_dns_support   = true
  enable_flow_log      = false

  tags = var.tags

}
