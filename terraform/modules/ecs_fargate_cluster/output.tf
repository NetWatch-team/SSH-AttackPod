output "arn" {
    value = try(aws_ecs_cluster.this[0].arn, "")
}

output "id" {
    value = try(aws_ecs_cluster.this[0].id, "")
}
