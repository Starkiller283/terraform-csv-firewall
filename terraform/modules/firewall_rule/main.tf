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

  rule {
    name                  = "allow-ssh"
    source_zones          = ["trust"]
    destination_zones     = ["untrust"]
    source_addresses      = ["10.0.0.1"]
    destination_addresses = ["10.0.1.1"]
    applications          = ["ssh"]
    services              = ["application-default"]
    action                = "allow"
    description           = "Allow SSH from trust to untrust"
    source_users          = ["any"]
    categories            = ["any"]
  }
}


