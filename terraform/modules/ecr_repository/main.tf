data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_ecr_repository" "this" {
  count = var.module_enabled ? 1 : 0

  name = var.repository_name

  dynamic "encryption_configuration" {

    for_each = var.kms_ecr_repository != "" ? [1] : []
    content {
      encryption_type = "KMS"
      kms_key         = var.kms_ecr_repository
    }
  }

  tags = var.tags
}

resource "aws_ecr_lifecycle_policy" "this" {
  count = var.module_enabled ? 1 : 0
  
  # If a newer image with the same tag is pushed, the old image looses its tag.
  # Remove all untagged images as they are not used anymore.
  repository = aws_ecr_repository.this[0].name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Remove untagged images as they are not used anymore."
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 5
        }
        action = {
          type = "expire"
        }
      },
    ]
  })
}
