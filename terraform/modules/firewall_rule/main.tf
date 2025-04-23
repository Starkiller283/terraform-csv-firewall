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

resource "panos_security_rule" "firewall_rule" {
  rule_name           = "allow_ssh"
  source_zone         = "trust"
  destination_zone    = "untrust"
  source_address      = ["10.0.0.1"]
  destination_address = ["10.0.1.1"]
  application         = ["ssh"]
  service             = []
  action              = "allow"
  description         = "Allow SSH from trust to untrust"
}
