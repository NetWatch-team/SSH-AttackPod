variable "mandatory_requirements" {
  description = "Create mandatory requirements"
  type        = bool
  default     = true
}

variable "service_enabled" {
  description = "Whether to create service resources"
  type        = bool
  default     = true
}

variable "env" {
  type = string
}

variable "region" {
  type = string
}

# variable "account_id" {
#   type = string
# }

variable "project_name" {
  type        = string
  description = "Project name"
}

variable "vpc_cidr_block" {
  description = "The CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "vpc_azs" {
  type = list(string)
}

variable "vpc_private_subnets" {
  type = list(string)
}

variable "vpc_public_subnets" {
  type = list(string)
}

# variable "vpc_public_subnets" {
#   description = "List of subnets that will be configured to host components with direct internet access (e.g. Cloud Connector)"
#   type = list(object({
#     name              = string
#     cidr_block        = string
#     availability_zone = string
#   }))
#   default = []
# }

# variable "vpc_workload_subnets" {
#   description = "List of subnets that will be configured to host components with direct internet access (e.g. Cloud Connector)"
#   type = list(object({
#     name              = string
#     cidr_block        = string
#     availability_zone = string
#   }))
# }

variable "lb_subnet_az" {
  type    = string
  default = "eu-central-1a"
}

variable "ecs_fargate_desired_count" {
  type    = number
  default = 1
}

variable "ecs_container_insights" {
  type    = string
  default = "disabled"
}

variable "ecs_fargate_definition_cpu" {
  type    = string
  default = "1024"
}

variable "ecs_fargate_definition_memory" {
  type    = string
  default = "2048"
}

variable "netwatch_collector_url" {
  type = string
}

variable "netwatch_test_mode" {
  type = string
}

variable "whitelist_ports" {
  type = list(number)
}

variable "whitelist_source_ipv4" {
  type    = list(string)
  default = []
}

variable "whitelist_source_ipv6" {
  type    = list(string)
  default = []
}

variable "netwatch_port" {
  type    = number
  default = 22
}

variable "tags" {
  description = "(Required) Tags applied to all resources"
  type        = map(string)
}

