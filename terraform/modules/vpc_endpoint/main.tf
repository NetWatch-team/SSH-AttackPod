resource "aws_vpc_endpoint" "endpoint" {
  for_each = toset(var.endpoints)

  service_name        = local.endpoints[each.value]
  vpc_id              = var.vpc_id
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = var.subnet_ids
  security_group_ids  = [aws_security_group.ssm.id]

  policy = <<EOT
  {
        "Id": "Policy",
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "*",
            "Resource": "*",
            "Condition": {
              "StringEquals": {
                  "aws:PrincipalAccount": "${data.aws_caller_identity.current.account_id}",
                  "aws:RequestedRegion": "${data.aws_region.current.name}"
              }
            }
          }
        ]
      }
  EOT

  tags = merge({ Name = "${each.value}-endpoint" }, var.tags)

}
