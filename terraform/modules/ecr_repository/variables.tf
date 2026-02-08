variable "module_enabled" {
  description = "Whether to create module resources"
  type        = bool
  default     = true
}

variable "repository_name" {
    type = string
    description = "Repository name to store docker images"
}

variable "kms_ecr_repository" {
  type    = string
  default = ""
}

variable "tags" {
  type    = map(string)
  default = {}
}
