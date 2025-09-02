// common
variable "module_enabled" {
  description = "Whether to create cluster"
  type        = bool
  default     = true
}

variable "loadbalancer_subnets" {
  description = "Provide subnets for Loadbalancer "
  type        = list(string)
}

variable "enable_deletion_protection" {
  type        = bool
  description = "If true, deletion of the load balancer will be disabled via the AWS API. This will prevent Terraform from deleting the load balancer."
  default     = false
}

variable "vpc_id" {
  description = "Please provide VPC"
  type        = string
}


// listner

variable "protocol" {
  description = "protocol value for listner other than https"
  type        = string
  default     = "HTTP"
}

// target group

variable "container_port" {
  description = "Please provide port for container"
  type        = string
  default     = 80
}

variable "lb_name" {
  description = "Please pass the alb name"
  type        = string
}

variable "enable_cross_zone_load_balancing" {
  type        = bool
  default     = false
  description = "If true, cross-zone load balancing of the load balancer will be enabled. For network and gateway type load balancers, this feature is disabled by default (false). For application load balancer this feature is always enabled (true) and cannot be disabled."
}

variable "matcher" {
  type    = string
  default = "200,302"
}

variable "health_check_path" {
  type    = string
  default = "/"
}

variable "timeout_interval" {
  type    = string
  default = "30"
}

variable "healthy_threshold" {
  type    = string
  default = "3"
}

variable "timeout" {
  type    = string
  default = "5"
}

variable "unhealthy_threshold" {
  type    = string
  default = "3"
}

// alb sg source ip ranges


variable "ports" {
  type = list(number)
}

variable "ranges_ipv4" {
  type    = list(string)
  default = []
}

variable "ranges_ipv6" {
  type    = list(string)
  default = []
}

variable "vpc_nat_gateway_public_ip_ranges" {
  type    = list(string)
  default = []
}

//access logs
variable "lb_access_logs_enable" {
  type    = bool
  default = false
}

variable "lb_access_logs_s3_bucket_name" {
  type    = string
  default = ""
}
