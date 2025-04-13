variable "rules" {
  type = list(object({
    rule_name       = string
    source_ip       = string
    destination_ip  = string
    port            = number
    protocol        = string
    action          = string
    description     = string
  }))
}

resource "null_resource" "rule_simulation" {
  for_each = { for rule in var.rules : rule.rule_name => rule }

  triggers = {
    name           = each.value.rule_name
    source_ip      = each.value.source_ip
    destination_ip = each.value.destination_ip
    port           = each.value.port
    protocol       = each.value.protocol
    action         = each.value.action
    description    = each.value.description
  }

  provisioner "local-exec" {
    command = "echo Applying rule ${each.value.rule_name}: ${each.value.description}"
  }
}
