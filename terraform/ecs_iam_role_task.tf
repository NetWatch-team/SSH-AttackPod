data "aws_iam_policy_document" "ssmmessages" {
  count = var.mandatory_requirements ? 1 : 0

  statement {
    effect = "Allow"
    actions = [
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel"
    ]

    resources = [
      "*"
    ]
  }
}

resource "aws_iam_policy" "ssmmessages" {
  count = var.mandatory_requirements ? 1 : 0

  name_prefix = "ECSCommandExecution-"
  policy      = data.aws_iam_policy_document.ssmmessages[0].json

}

########
# Role
########

data "aws_iam_policy_document" "task_role" {
  count = var.mandatory_requirements ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = [
        "ecs.amazonaws.com",
        "ecs-tasks.amazonaws.com"
      ]
    }

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS"]
    }
  }
}

module "task_role" {
  source = "./modules/iam_role"

  module_enabled = var.mandatory_requirements

  role_name                    = "${var.project_name}-TaskRole"
  account                      = local.account_id
  create_role_name_with_prefix = true

  assume_role_policy = try(data.aws_iam_policy_document.task_role[0].json, "")

  attach_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceRole",
    try(aws_iam_policy.cloudwatch[0].arn, ""),
    try(aws_iam_policy.ssmmessages[0].arn, "")
  ]

  tags = {
    app-role    = "role"
    app-purpose = "allow access to resources"
  }
}
