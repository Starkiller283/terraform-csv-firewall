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
  api_key  = var.LUFRPT1vRFdGN1BLU2EwYmpUSnRraXNxWDkwT0FNOFU9ZytqWjRUUSt4bnhsbVY2VEtGbTIvTGRiR0pGMHozUTdCbGVzaWlPVjBxbmtwTEU2Y0NuU2ZTZlVDU1RybmNrWg     
  timeout  = 60
}
