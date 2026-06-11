terraform {
  required_providers {
    aws        = { source = "hashicorp/aws";        version = "~> 5.0" }
    kubernetes = { source = "hashicorp/kubernetes"; version = "~> 2.25" }
  }
}

resource "aws_eks_cluster" "thor" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster.arn
  version  = var.kubernetes_version

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = var.enable_public_endpoint
    public_access_cidrs     = var.public_access_cidrs
    security_group_ids      = [aws_security_group.eks_cluster.id]
  }

  encryption_config {
    provider   { key_arn = aws_kms_key.eks_secrets.arn }
    resources  = ["secrets"]
  }

  enabled_cluster_log_types = ["api","audit","authenticator","controllerManager","scheduler"]

  tags = merge(var.tags, { Name = var.cluster_name, Environment = var.environment })
  depends_on = [aws_iam_role_policy_attachment.eks_cluster_policy, aws_cloudwatch_log_group.eks_logs]
}

resource "aws_eks_node_group" "general" {
  cluster_name    = aws_eks_cluster.thor.name
  node_group_name = "${var.cluster_name}-general"
  node_role_arn   = aws_iam_role.eks_nodes.arn
  subnet_ids      = var.private_subnet_ids
  instance_types  = var.general_instance_types
  ami_type        = "AL2_x86_64"

  scaling_config {
    desired_size = var.general_desired_size
    min_size     = var.general_min_size
    max_size     = var.general_max_size
  }

  update_config { max_unavailable_percentage = 25 }
  labels  = { role = "general", environment = var.environment }
  tags    = var.tags
  depends_on = [aws_iam_role_policy_attachment.eks_worker_node_policy]
}

resource "aws_eks_node_group" "gpu" {
  count           = var.enable_gpu_nodes ? 1 : 0
  cluster_name    = aws_eks_cluster.thor.name
  node_group_name = "${var.cluster_name}-gpu"
  node_role_arn   = aws_iam_role.eks_nodes.arn
  subnet_ids      = var.private_subnet_ids
  instance_types  = var.gpu_instance_types
  ami_type        = "AL2_x86_64_GPU"

  scaling_config {
    desired_size = var.gpu_desired_size
    min_size     = 0
    max_size     = var.gpu_max_size
  }

  taint { key = "nvidia.com/gpu"; value = "true"; effect = "NO_SCHEDULE" }
  labels  = { role = "gpu-inference", gpu = "true", environment = var.environment }
  tags    = var.tags
  depends_on = [aws_iam_role_policy_attachment.eks_worker_node_policy]
}

resource "aws_iam_role" "eks_cluster" {
  name = "${var.cluster_name}-cluster-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow"; Principal = { Service = "eks.amazonaws.com" }; Action = "sts:AssumeRole" }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster.name
}

resource "aws_iam_role" "eks_nodes" {
  name = "${var.cluster_name}-node-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow"; Principal = { Service = "ec2.amazonaws.com" }; Action = "sts:AssumeRole" }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
  ])
  policy_arn = each.value
  role       = aws_iam_role.eks_nodes.name
}

resource "aws_kms_key" "eks_secrets" {
  description             = "Thor EKS secrets encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags = merge(var.tags, { Name = "${var.cluster_name}-secrets-key" })
}

resource "aws_security_group" "eks_cluster" {
  name        = "${var.cluster_name}-cluster-sg"
  description = "EKS cluster control plane"
  vpc_id      = var.vpc_id
  ingress { from_port = 443; to_port = 443; protocol = "tcp"; security_groups = [aws_security_group.eks_nodes.id]; description = "Workers to API" }
  egress  { from_port = 0;   to_port = 0;   protocol = "-1";  cidr_blocks = ["0.0.0.0/0"] }
  tags = merge(var.tags, { Name = "${var.cluster_name}-cluster-sg" })
}

resource "aws_security_group" "eks_nodes" {
  name        = "${var.cluster_name}-nodes-sg"
  description = "EKS worker nodes"
  vpc_id      = var.vpc_id
  ingress { from_port = 0; to_port = 65535; protocol = "-1"; self = true; description = "Node to node" }
  ingress { from_port = 1025; to_port = 65535; protocol = "tcp"; security_groups = [aws_security_group.eks_cluster.id]; description = "Cluster to nodes" }
  egress  { from_port = 0; to_port = 0; protocol = "-1"; cidr_blocks = ["0.0.0.0/0"] }
  tags = merge(var.tags, { Name = "${var.cluster_name}-nodes-sg" })
}

resource "aws_cloudwatch_log_group" "eks_logs" {
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = 90
  tags              = var.tags
}

data "aws_caller_identity" "current" {}
locals {
  oidc_issuer = trimprefix(aws_eks_cluster.thor.identity[0].oidc[0].issuer, "https://")
}
