region       = "eu-central-1"
env          = "poc"
project_name = "netwatch_ssh"

mandatory_requirements = true
service_enabled        = false


################
# VPC Network
################
vpc_cidr_block      = "10.0.0.0/16"
vpc_azs             = ["eu-central-1a", "eu-central-1b"]
vpc_private_subnets = ["10.0.1.0/24", "10.0.2.0/24"]
vpc_public_subnets  = ["10.0.101.0/24", "10.0.102.0/24"]


################
# Load Balancer
################
whitelist_source_ipv4 = ["0.0.0.0/0"]
whitelist_source_ipv6 = []
whitelist_ports       = [22]


########################################
# ECS - Elastic Agent Container service
########################################
ecs_container_insights        = "enabled"
ecs_fargate_definition_cpu    = "512"
ecs_fargate_definition_memory = "1024"
ecs_fargate_desired_count     = 1


########################################
# NetWatch
########################################
netwatch_collector_url = "https://api.netwatch.team"
netwatch_test_mode     = "true"
netwatch_port          = 2222

tags = {
  "Project" = "NetWatch PoC"
}
