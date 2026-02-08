output "arn" {
  description = "The ARN of the Role"
  value       = try(aws_iam_role.this[0].arn, aws_iam_role.this_name_prefix[0].arn, "")
}

output "id" {
  description = "The Name of the Role"
  value       = try(aws_iam_role.this[0].id, aws_iam_role.this_name_prefix[0].id, "")
}

output "name" {
  description = "The Name of the Role"
  value       = try(aws_iam_role.this[0].name, aws_iam_role.this_name_prefix[0].name, "")
}
