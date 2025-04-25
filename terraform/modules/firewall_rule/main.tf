terraform {
  required_providers {
    panos = {
      source = "PaloAltoNetworks/panos"
    }
  }
}

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

resource "panos_security_policy" "firewall_rule" {
  vsys = "vsys1"

  dynamic "rule" {
  for_each = var.rules
  content {
    name                  = rule.value.rule_name
    source_zones          = ["trust"]
    destination_zones     = ["untrust"]
    source_addresses      = [rule.value.source_ip]
    destination_addresses = [rule.value.destination_ip]
    applications          = [rule.value.protocol]
    services              = ["application-default"]
    action                = rule.value.action
    description           = rule.value.description
    source_users          = ["any"]
    categories            = ["any"]
  }
}
}


