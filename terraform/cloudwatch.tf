resource "aws_cloudwatch_log_group" "loggroup" {
  count = var.mandatory_requirements ? 1 : 0

  name              = "/aws/ecs/${var.project_name}/${var.env}-${var.project_name}"
  retention_in_days = "30"
  kms_key_id        = module.kms_key.key_arn

  tags = {
    Name = var.project_name
  }
}
