output "cluster_id"                { value = aws_eks_cluster.thor.id }
output "cluster_endpoint"          { value = aws_eks_cluster.thor.endpoint }
output "cluster_ca_data"           { value = aws_eks_cluster.thor.certificate_authority[0].data }
output "cluster_security_group_id" { value = aws_security_group.eks_cluster.id }
output "node_role_arn"             { value = aws_iam_role.eks_nodes.arn }
output "kms_key_arn"               { value = aws_kms_key.eks_secrets.arn }
output "oidc_issuer"               { value = local.oidc_issuer }
