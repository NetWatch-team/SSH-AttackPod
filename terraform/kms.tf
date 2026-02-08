module "kms_key" {
  source = "./modules/kms"

  module_enabled = var.mandatory_requirements

  name                            = var.project_name
  deletion_window_in_days         = 14
  enable_key_rotation             = true
  allow_cloudwatch_log_encryption = true
  create_alias                    = true

  tags = {
    Name        = "${var.project_name}"
    app-id      = "kms"
    app-role    = "encryption"
    app-purpose = "Simmetric encryption and descryption key"
    Project     = "${var.project_name}"
  }

}
