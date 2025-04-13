locals {
  firewall_rules = csvdecode(file("${path.module}/../rules.csv"))
}

module "firewall_rules" {
  source = "./modules/firewall_rule"
  rules  = local.firewall_rules
}
