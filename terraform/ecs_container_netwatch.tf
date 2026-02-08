resource "aws_ecs_task_definition" "task_definition" {
  count = var.mandatory_requirements && var.service_enabled ? 1 : 0

  family                   = var.project_name
  network_mode             = "awsvpc"
  cpu                      = var.ecs_fargate_definition_cpu
  memory                   = var.ecs_fargate_definition_memory
  requires_compatibilities = ["FARGATE"]
  task_role_arn            = module.task_role.arn
  execution_role_arn       = module.task_execution_role.arn

  container_definitions = templatefile(
    "${path.module}/templates/container-definition.json.tpl",
    {
      IMAGE                            = "${module.ecr_repository.repository_url}:latest",
      CPU                              = "${var.ecs_fargate_definition_cpu}",
      MEMORY                           = "${var.ecs_fargate_definition_memory}",
      AWS_REGION                       = "${local.region}",
      ECS_TASK_DEFINITION_NAME         = "${var.project_name}",
      CLOUDWATCH_LOGROUP_NAME          = "${aws_cloudwatch_log_group.loggroup[0].name}",
      NETWATCH_COLLECTOR_AUTHORIZATION = "${aws_secretsmanager_secret.netwatch[0].arn}:ssh_key::",
      NETWATCH_COLLECTOR_URL           = "${var.netwatch_collector_url}",
      NETWATCH_TEST_MODE               = "${var.netwatch_test_mode}"
      NETWATCH_PORT                    = "${var.netwatch_port}"
    }
  )

  tags = {
    Name = var.project_name
  }
}

resource "aws_ecs_service" "service" {
  count = var.mandatory_requirements && var.service_enabled ? 1 : 0

  name                    = var.project_name
  cluster                 = module.ecs_fargate_cluster.id
  task_definition         = aws_ecs_task_definition.task_definition[0].arn
  desired_count           = var.ecs_fargate_desired_count
  enable_execute_command  = true
  scheduling_strategy     = "REPLICA"
  platform_version        = "LATEST"
  enable_ecs_managed_tags = "true"
  propagate_tags          = "SERVICE"

  network_configuration {
    security_groups  = [aws_security_group.sg_container[0].id]
    subnets          = [module.vpc.private_subnets]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = module.network_load_balancer.nlb_target_group_ssh_22_arn
    container_name   = var.project_name
    container_port   = var.netwatch_port
  }

  capacity_provider_strategy {
    base              = 0
    capacity_provider = "FARGATE"
    weight            = 1
  }

  tags = {
    Name = var.project_name
  }
}
