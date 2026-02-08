variable "module_enabled" {
  description = "Whether to create module resources"
  type        = bool
  default     = true
}

variable "ecs_cluster_name" {
  type        = string
  description = "ECS Cluster name"
}

variable "ecs_container_insights" {
  type    = string
  default = "disabled"
}

variable "capacity_providers" {
  description = "List of short names of one or more capacity providers to associate with the cluster. Valid values also include FARGATE and FARGATE_SPOT"
  type        = list(map(string))
  default     = []
}

variable "tags" {
  type    = map(string)
  default = {}
}
