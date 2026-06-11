variable "cluster_name"             { type = string }
variable "kubernetes_version"       { type = string;       default = "1.29" }
variable "environment"              { type = string;       default = "production" }
variable "vpc_id"                   { type = string }
variable "private_subnet_ids"       { type = list(string) }
variable "enable_public_endpoint"   { type = bool;         default = false }
variable "public_access_cidrs"      { type = list(string); default = [] }
variable "general_instance_types"   { type = list(string); default = ["m6i.xlarge"] }
variable "general_desired_size"     { type = number;       default = 3 }
variable "general_min_size"         { type = number;       default = 2 }
variable "general_max_size"         { type = number;       default = 20 }
variable "enable_gpu_nodes"         { type = bool;         default = true }
variable "gpu_instance_types"       { type = list(string); default = ["g4dn.xlarge"] }
variable "gpu_desired_size"         { type = number;       default = 1 }
variable "gpu_max_size"             { type = number;       default = 4 }
variable "edr_desired_size"         { type = number;       default = 3 }
variable "edr_min_size"             { type = number;       default = 1 }
variable "edr_max_size"             { type = number;       default = 50 }
variable "tags"                     { type = map(string);  default = {} }
