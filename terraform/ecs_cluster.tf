module "ecs_fargate_cluster" {
  source = "./modules/ecs_fargate_cluster"

  module_enabled = var.mandatory_requirements

  ecs_cluster_name       = var.project_name
  ecs_container_insights = var.ecs_container_insights

  tags = {
    "AWS.SSM.AppManager.ECS.Cluster.ARN" = "arn:aws:ecs:${local.region}:${local.account_id}:cluster/${var.project_name}"
    Project                              = "${var.project_name}"
  }
}

module "ecr_repository" {
  source = "./modules/ecr_repository"

  module_enabled = var.mandatory_requirements

  repository_name    = var.project_name
  kms_ecr_repository = module.kms_key.key_arn

  tags = {
    Name = "${var.project_name}"
  }
}
