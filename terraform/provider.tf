provider "aws" {
  region = var.region
}

terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}
