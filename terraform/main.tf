locals {
  csv_data = csvdecode(file("${path.module}/../rules.csv"))
  
  firewall_rules = [
    for rule in local.csv_data : {
      rule_name      = rule.rule_name
      source_ip      = rule.source_ip
      destination_ip = rule.destination_ip
      port           = tonumber(rule.port)
      protocol       = rule.protocol
      action         = rule.action
      description    = rule.description
    }
  ]
}

module "firewall_rules" {
  source = "./modules/firewall_rule"
  rules  = local.firewall_rules
}
