terraform {
  required_providers {
    panos = {
      source  = "PaloAltoNetworks/panos"
      version = "~> 1.10"
    }
  }
}

provider "panos" {
  hostname = "192.168.0.156"          
  api_key  = var.panos_api_key    
  timeout  = 60
}
