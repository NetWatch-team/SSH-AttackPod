output "load_balancer_arn" {
  value = try(aws_lb.this[0].arn, "")
}

output "load_balancer_dns_name" {
  value = try(aws_lb.this[0].dns_name, "")
}

output "nlb_target_group_ssh_22_arn" {
  value = try(aws_lb_target_group.ssh_22[0].arn, "")
}

output "sg_lb_id" {
  value = try(aws_security_group.nlb[0].id, "")
}

# output "dns_record_name" {
#   value = try(aws_route53_record.a_record[0].name, "")
# }

# output "dns_record_fqdn" {
#   value = try(aws_route53_record.a_record[0].fqdn, "")
# }
