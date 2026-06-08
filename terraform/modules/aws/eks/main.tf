# Thor Firewall — AWS EKS Terraform Module
# إنشاء Kubernetes cluster على AWS

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.27"
    }
  }
}

variable "cluster_name"       { type = string default = "thor-firewall" }
variable "cluster_version"    { type = string default = "1.29" }
variable "vpc_id"             { type = string }
variable "subnet_ids"         { type = list(string) }
variable "environment"        { type = string default = "production" }
variable "instance_types"     { type = list(string) default = ["m6i.xlarge"] }
variable "gpu_instance_types" { type = list(string) default = ["g4dn.xlarge"] }
variable "min_nodes"          { type = number default = 3 }
variable "max_nodes"          { type = number default = 20 }
variable "desired_nodes"      { type = number default = 3 }
variable "gpu_nodes"          { type = number default = 1 }
variable "tags"               { type = map(string) default = {} }

# ── EKS Cluster ─────────────────────────────────────────────────────────────
resource "aws_eks_cluster" "thor" {
  name     = var.cluster_name
  version  = var.cluster_version
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false  # Production: private only
    security_group_ids      = [aws_security_group.eks_cluster.id]
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = [
    "api", "audit", "authenticator", "controllerManager", "scheduler"
  ]

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
  ]

  tags = merge(var.tags, {
    Name        = var.cluster_name
    Environment = var.environment
    ManagedBy   = "terraform"
    Project     = "thor-firewall"
  })
}

# ── System Node Group (Control Plane workloads) ────────────────────────────
resource "aws_eks_node_group" "system" {
  cluster_name    = aws_eks_cluster.thor.name
  node_group_name = "${var.cluster_name}-system"
  node_role_arn   = aws_iam_role.eks_nodes.arn
  subnet_ids      = var.subnet_ids
  instance_types  = ["m6i.large"]

  scaling_config {
    min_size     = 2
    max_size     = 5
    desired_size = 2
  }

  labels = {
    "thor.io/role" = "system"
  }

  taint {
    key    = "CriticalAddonsOnly"
    value  = "true"
    effect = "NO_SCHEDULE"
  }

  update_config {
    max_unavailable = 1
  }

  tags = var.tags
}

# ── Application Node Group (Thor workloads) ────────────────────────────────
resource "aws_eks_node_group" "application" {
  cluster_name    = aws_eks_cluster.thor.name
  node_group_name = "${var.cluster_name}-application"
  node_role_arn   = aws_iam_role.eks_nodes.arn
  subnet_ids      = var.subnet_ids
  instance_types  = var.instance_types

  scaling_config {
    min_size     = var.min_nodes
    max_size     = var.max_nodes
    desired_size = var.desired_nodes
  }

  labels = {
    "thor.io/role" = "application"
  }

  update_config {
    max_unavailable = 1
  }

  # eBPF requires specific kernel — use bottlerocket AMI
  ami_type = "BOTTLEROCKET_x86_64"

  tags = var.tags
}

# ── GPU Node Group (ML Inference) ─────────────────────────────────────────
resource "aws_eks_node_group" "gpu" {
  count = var.gpu_nodes > 0 ? 1 : 0

  cluster_name    = aws_eks_cluster.thor.name
  node_group_name = "${var.cluster_name}-gpu"
  node_role_arn   = aws_iam_role.eks_nodes.arn
  subnet_ids      = [var.subnet_ids[0]]
  instance_types  = var.gpu_instance_types
  ami_type        = "AL2_x86_64_GPU"

  scaling_config {
    min_size     = 0
    max_size     = 8
    desired_size = var.gpu_nodes
  }

  labels = {
    "thor.io/role"           = "ml-inference"
    "nvidia.com/gpu.present" = "true"
  }

  taint {
    key    = "nvidia.com/gpu"
    value  = "true"
    effect = "NO_SCHEDULE"
  }

  tags = var.tags
}

# ── KMS Key for Secrets Encryption ────────────────────────────────────────
resource "aws_kms_key" "eks" {
  description             = "Thor Firewall EKS Secrets Encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = var.tags
}

# ── Security Group ─────────────────────────────────────────────────────────
resource "aws_security_group" "eks_cluster" {
  name_prefix = "${var.cluster_name}-cluster-"
  vpc_id      = var.vpc_id
  description = "Thor EKS Cluster Security Group"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${var.cluster_name}-cluster-sg" })
}

# ── IAM Roles ─────────────────────────────────────────────────────────────
resource "aws_iam_role" "eks_cluster" {
  name = "${var.cluster_name}-eks-cluster"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster.name
}

resource "aws_iam_role" "eks_nodes" {
  name = "${var.cluster_name}-eks-nodes"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "eks_worker_node" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_nodes.name
}

resource "aws_iam_role_policy_attachment" "eks_cni" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_nodes.name
}

resource "aws_iam_role_policy_attachment" "eks_ecr" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_nodes.name
}

# ── Outputs ────────────────────────────────────────────────────────────────
output "cluster_name"     { value = aws_eks_cluster.thor.name }
output "cluster_endpoint" { value = aws_eks_cluster.thor.endpoint }
output "cluster_ca"       { value = aws_eks_cluster.thor.certificate_authority[0].data }
output "cluster_arn"      { value = aws_eks_cluster.thor.arn }
