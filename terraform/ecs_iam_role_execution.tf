data "aws_iam_policy_document" "ssh_client_key" {
  count = var.mandatory_requirements ? 1 : 0

  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetResourcePolicy",
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:ListSecretVersionIds"
    ]

    resources = [
      "${aws_secretsmanager_secret.netwatch[0].arn}"
    ]
  }
}

resource "aws_iam_policy" "ssh_client_key" {
  count = var.mandatory_requirements ? 1 : 0

  name_prefix = "NetWatchSecretsManagerReadExecution-"
  policy      = data.aws_iam_policy_document.ssh_client_key[0].json

  tags = {
    Name     = "NetWatch Secret Manager Read"
    app-role = "policy"
  }
}

data "aws_iam_policy_document" "kms_key" {
  count = var.mandatory_requirements ? 1 : 0

  statement {
    sid    = "NetWatchDecryptKMS"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:GenerateDataKey"
    ]

    resources = [
      module.kms_key.key_arn
    ]
  }
}

resource "aws_iam_policy" "kms_key" {
  count = var.mandatory_requirements ? 1 : 0

  name_prefix = "NetWatchLbKMS"
  policy      = data.aws_iam_policy_document.kms_key[0].json
}

data "aws_iam_policy_document" "cloudwatch" {
  count = var.mandatory_requirements ? 1 : 0

  statement {
    sid    = "AllowCloudWatchAccess"
    effect = "Allow"
    actions = [
      "logs:ListLogDeliveries",
      "logs:ListTagsForResource",
      "logs:ListTagsLogGroup",
      "logs:DescribeAccountPolicies",
      "logs:DescribeLogGroups",
      "logs:DescribeQueries",
      "logs:DescribeSubscriptionFilters",
      "logs:DescribeDestinations",
      "logs:DescribeLogStreams",
      "logs:DescribeQueryDefinitions",
      "logs:DescribeExportTasks",
      "logs:DescribeMetricFilters",
      "logs:DescribeResourcePolicies",
      "logs:CreateLogGroup",
      "logs:CreateLogDelivery",
      "logs:CreateExportTask",
      "logs:CreateLogStream",
      "logs:GetLogEvents",
      "logs:GetQueryResults",
      "logs:GetLogDelivery",
      "logs:GetLogRecord",
      "logs:GetDataProtectionPolicy",
      "logs:GetLogGroupFields"
    ]

    resources = [
      "${aws_cloudwatch_log_group.loggroup[0].arn}:*"
    ]
  }
}

resource "aws_iam_policy" "cloudwatch" {
  count = var.mandatory_requirements ? 1 : 0

  name   = "${var.project_name}-Cloudwatch"
  policy = data.aws_iam_policy_document.cloudwatch[0].json

  tags = {
    Name        = "${var.project_name}-Cloudwatch"
    description = "Allow ECS to manage cloudwatch log group"
  }
}

data "aws_iam_policy_document" "task_execution_role" {
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

module "task_execution_role" {
  source = "./modules/iam_role"

  module_enabled = var.mandatory_requirements

  role_name                    = "${var.project_name}-TaskExecutionRole"
  account                      = local.account_id
  create_role_name_with_prefix = true

  assume_role_policy = try(data.aws_iam_policy_document.task_execution_role[0].json, "")

  attach_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
    "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceRole",
    try(aws_iam_policy.cloudwatch[0].arn, ""),
    try(aws_iam_policy.ssh_client_key[0].arn, ""),
    try(aws_iam_policy.kms_key[0].arn, "")
  ]

  tags = {
    app-id      = "NetWatch"
    app-role    = "role"
    app-purpose = "allow access to CloudWatch streaming logs"
  }
}
