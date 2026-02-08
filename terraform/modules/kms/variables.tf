variable "module_enabled" {
  description = "Whether to create the module"
  type        = bool
  default     = true
}

variable "create_alias" {
  description = "Whether to create KMS Alias"
  type        = bool
  default     = false
}

variable "name" {
  type = string
}

variable "description" {
  type    = string
  default = ""
}

variable "deletion_window_in_days" {
  type    = number
  default = 7
}

variable "enable_key_rotation" {
  type    = bool
  default = true
}

variable "policy" {
  type    = string
  default = ""
}

variable "enable_default_policy" {
  description = "Specifies whether to enable the default key policy. Defaults to `true`"
  type        = bool
  default     = true
}

variable "allow_cloudwatch_log_encryption" {
  type    = bool
  default = false
}

variable "tags" {
  type    = map(string)
  default = {}
}
