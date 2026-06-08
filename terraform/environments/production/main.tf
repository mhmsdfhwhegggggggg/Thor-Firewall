# Thor Firewall — Production Environment
# بيئة الإنتاج على AWS EKS

terraform {
  required_version = ">= 1.6.0"
  backend "s3" {
    bucket         = "thor-firewall-terraform-state"
    key            = "production/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "thor-firewall-terraform-locks"
  }
  required_providers {
    aws  = { source = "hashicorp/aws", version = "~> 5.0" }
    helm = { source = "hashicorp/helm", version = "~> 2.12" }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "thor-firewall"
      Environment = "production"
      ManagedBy   = "terraform"
    }
  }
}

variable "aws_region"      { default = "us-east-1" }
variable "cluster_name"    { default = "thor-firewall-prod" }
variable "environment"     { default = "production" }
variable "vpc_cidr"        { default = "10.100.0.0/16" }

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
  name   = "${var.cluster_name}-vpc"
  cidr   = var.vpc_cidr
  azs    = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnets = ["10.100.1.0/24", "10.100.2.0/24", "10.100.3.0/24"]
  public_subnets  = ["10.100.11.0/24", "10.100.12.0/24", "10.100.13.0/24"]
  enable_nat_gateway = true
  single_nat_gateway = false  # Production: one per AZ
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb"               = "1"
    "kubernetes.io/cluster/${var.cluster_name}"     = "shared"
  }
}

module "eks" {
  source          = "../../modules/aws/eks"
  cluster_name    = var.cluster_name
  cluster_version = "1.29"
  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.private_subnets
  environment     = var.environment
  instance_types  = ["m6i.2xlarge"]
  min_nodes       = 3
  max_nodes       = 50
  desired_nodes   = 5
  gpu_nodes       = 2
  gpu_instance_types = ["g4dn.2xlarge"]
}

output "cluster_name"     { value = module.eks.cluster_name }
output "cluster_endpoint" { value = module.eks.cluster_endpoint }
