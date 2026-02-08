
data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_kms_key" "key" {

  count = var.module_enabled ? 1 : 0

  description             = var.description # "This key is used to encrypt data as rest"
  deletion_window_in_days = var.deletion_window_in_days
  enable_key_rotation     = var.enable_key_rotation

  policy = coalesce(var.policy, data.aws_iam_policy_document.this[0].json)

  tags = merge(
    var.tags,
    {
      "Name" = "${var.name}"
    }
  )
}

resource "aws_kms_alias" "key" {

  count = var.module_enabled && var.create_alias ? 1 : 0

  target_key_id = aws_kms_key.key[0].id
  name          = "alias/${var.name}"
}


data "aws_iam_policy_document" "this" {

  count = var.module_enabled ? 1 : 0

  # Default policy - account wide access to all key operations
  dynamic "statement" {
    for_each = var.enable_default_policy ? [1] : []

    content {
      sid       = "Enable IAM User Permissions"
      actions   = ["kms:*"]
      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.allow_cloudwatch_log_encryption ? [1] : []

    content {
      sid = "Allow cloudwatch logs to use key for log encryption"
      actions = [
        "kms:Encrypt*",
        "kms:Decrypt*",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:Describe*"
      ]
      resources = ["*"]

      principals {
        type        = "Service"
        identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
      }

      condition {
        test     = "ArnLike"
        variable = "kms:EncryptionContext:aws:logs:arn"
        values   = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"]
      }
    }
  }
}
