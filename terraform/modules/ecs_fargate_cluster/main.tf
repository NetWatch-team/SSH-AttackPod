resource "aws_ecs_cluster" "this" {
  count = var.module_enabled ? 1 : 0

  name = var.ecs_cluster_name

  setting {
    name  = "containerInsights"
    value = var.ecs_container_insights
  }

  configuration {
    execute_command_configuration {
      logging = "DEFAULT"
    }
  }

  tags = var.tags
}

resource "aws_ecs_cluster_capacity_providers" "this" {

  count = var.module_enabled ? 1 : 0

  cluster_name = aws_ecs_cluster.this[0].name

  capacity_providers = [
    "FARGATE",
    "FARGATE_SPOT"
  ]

  dynamic "default_capacity_provider_strategy" {
    for_each = var.capacity_providers
    content {
      base              = lookup(default_capacity_provider_strategy.value, "base", null)
      weight            = lookup(default_capacity_provider_strategy.value, "weight", null)
      capacity_provider = lookup(default_capacity_provider_strategy.value, "capacity_provider", null)
    }
  }
}
