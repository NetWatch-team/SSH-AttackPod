output "arn" {
    value = try(aws_ecr_repository.this[0].arn, "")
}

output "registry_id" {
    value = try(aws_ecr_repository.this[0].registry_id, "")
}

output "repository_url" {
    value = try(aws_ecr_repository.this[0].repository_url, "")
}
