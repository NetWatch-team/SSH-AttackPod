locals {
  module_enabled = var.module_enabled

  # Create role name from the two possible role creation
  this_role_name = concat(aws_iam_role.this.*.name, aws_iam_role.this_name_prefix.*.id, [""])[0]
}

############################
# IAM role with name
############################

resource "aws_iam_role" "this" {

  count = var.module_enabled && !var.create_role_name_with_prefix ? 1 : 0

  name               = var.role_name
  path               = var.role_path
  description        = var.role_description
  assume_role_policy = var.assume_role_policy
  tags               = var.tags
}

############################
# IAM role with name prefix
############################

resource "aws_iam_role" "this_name_prefix" {

  count = var.module_enabled && var.create_role_name_with_prefix ? 1 : 0

  name_prefix        = "${var.role_name}-"
  path               = var.role_path
  description        = var.role_description
  assume_role_policy = var.assume_role_policy
  tags               = var.tags
}

######################################
# Attach all IAM policies to the role
######################################

# If the role must be created without prefix
resource "aws_iam_role_policy_attachment" "this" {
  count = var.module_enabled && !var.create_role_name_with_prefix ? length(var.attach_policy_arns) : 0

  role       = local.this_role_name
  policy_arn = element(var.attach_policy_arns, count.index)
}

# If the role must be created with prefix
resource "aws_iam_role_policy_attachment" "this_name_prefix" {
  count = var.module_enabled && var.create_role_name_with_prefix ? length(var.attach_policy_arns) : 0

  role       = local.this_role_name
  policy_arn = element(var.attach_policy_arns, count.index)
}
