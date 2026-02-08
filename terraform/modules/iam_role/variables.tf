variable "module_enabled" {
  description = "Whether to create role and all policies"
  type        = bool
  default     = true
}

variable "role_name" {
  type        = string
  description = "IAM Role name"
}

variable "create_role_name_with_prefix" {
  type        = bool
  description = "create role using name prefix"
  default     = true
}

variable "role_path" {
  type        = string
  description = "Path to the role."
  default     = "/"
}

variable "role_description" {
  type        = string
  description = "IAM Role description"
  default     = ""
}

variable "tags" {
  description = "IAM Role tags to apply to all taggable resources"
  type        = map(string)
  default     = {}
}

variable "attach_policy_arns" {
  description = "List of policies permissions"
  type        = list(string)
  default     = []
}

variable "assume_role_policy" {
  type        = string
  description = "Policy that grants an entity permission to assume the role."
}

variable "account" {
  type        = string
  description = "AWS account"
  default     = ""
}
