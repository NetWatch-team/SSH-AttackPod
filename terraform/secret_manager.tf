resource "aws_secretsmanager_secret" "netwatch" {
  count = var.mandatory_requirements ? 1 : 0

  name_prefix = "${var.project_name}-ssh-client-key"
  description = "Credentials for NetWatch to access remote service"
  kms_key_id  = module.kms_key.alias_arn

  tags = {
    description = "Credentials for NetWatch to access remote service"
  }
}


# Create empty entry to store the API Key
# ATTENTION: do not store in any way the API Key here because it will be exposed in Terraform state file in clear text
resource "aws_secretsmanager_secret_version" "netwatch" {
  count = var.mandatory_requirements ? 1 : 0

  secret_id     = aws_secretsmanager_secret.netwatch[0].id
  secret_string = <<EOF
   {
    "ssh_key": ""
   }
EOF
}
