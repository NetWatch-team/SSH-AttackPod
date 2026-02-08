# variable "aws_region" {
#   description = "AWS region application for the endpoint"
# }

variable "endpoints" {
  description = "A list of endpoint identifiers to enable"
  type        = list(string)
  default     = []
}

variable "vpc_id" {
  description = "Name of the VPC to deploy to"
  default     = null
}

variable "vpc_cidr_block" {
  description = "The CIDR block for the VPC"
  type        = string
}

variable "subnet_ids" {
  description = "The ID of one or more subnets in which to create a network interface for the endpoint."
  type        = list(string)
}

variable "tags" {
  description = "(Required) Mandatory tags."
  type        = map(string)
}
