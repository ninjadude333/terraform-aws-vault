terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "4.39.0"
    }
    grafana = {
      source  = "grafana/grafana"
      version = "1.30.0"
    }
  }
}

provider "grafana" {
  url  = "http://${aws_instance.grafana.public_ip}:3000"
  auth = "admin:Su93rS3cu5e"
}
