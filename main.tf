terraform {
  required_providers {
    splunk = {
      source  = "splunk/splunk"
      version = "1.5.7"
    }
  }
}

provider "splunk" {
  # Configuration options
  url                  = "localhost:8089" # Your Splunk Management Port (not the web UI port)
  username             = var.SPLUNK_USERNAME
  password             = var.SPLUNK_PASSWORD
  insecure_skip_verify = true
}

variable "SPLUNK_USERNAME" {
  type        = string
  description = "SPLUNK Login Username"
}
variable "SPLUNK_PASSWORD" {
  type        = string
  description = "SPLUNK Login Password"
  sensitive   = true
}

variable "TINES_WEBHOOK" {
  type        = string
  description = "Tines Webhook URL"
}
