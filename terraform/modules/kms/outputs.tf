output "key_arn" {
  value = try(aws_kms_key.key[0].arn, "")
}

output "key_id" {
  value = try(aws_kms_key.key[0].id, "")
}

output "key_policy" {
  value = try(aws_kms_key.key[0].policy, "")
}

output "alias_arn" {
  value = try(aws_kms_alias.key[0].arn, "")
}

output "alias_id" {
  value = try(aws_kms_alias.key[0].id, "")
}
