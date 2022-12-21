# You can overwrite the default values for the variables below, typically
# variable values are set when calling the module. See on of the `examples/`.

variable "vault_name" {
  description = "The name of the vault cluster in 3 to 5 characters. Changes in runtime would re-deploy a new cluster, data from the old cluster would be lost."
  type        = string
  default     = "dudeV"
  validation {
    condition     = length(var.vault_name) >= 3 && length(var.vault_name) <= 5 && var.vault_name != "default"
    error_message = "Please use a minimum of 3 and a maximum of 5 characters. \"default\" can't be used because it is reserved."
  }
}

variable "vault_version" {
  description = "The version of Vault to install."
  type        = string
  default     = "1.12.2"
  validation {
    condition     = can(regex("^1\\.", var.vault_version))
    error_message = "Please use a SemVer version, where the major version is \"1\". Use \"1.2.7\" or newer."
  }
}

variable "vault_aws_key_name" {
  description = "The name of an existing ssh key. Either specify \"vault_aws_key_name\" or \"vault_keyfile_path\"."
  type        = string
  default     = "dudug"
}

variable "vault_keyfile_path" {
  description = "The name of the file that has the public ssh key stored. Either specify \"vault_aws_key_name\" or \"vault_keyfile_path\"."
  type        = string
  default     = ""
  validation {
    condition     = try((var.vault_keyfile_path != "" && fileexists(var.vault_keyfile_path)), var.vault_keyfile_path == "")
    error_message = "The specified certificate file does not exist."
  }
}

variable "vault_size" {
  description = "The size of the deployment."
  type        = string
  default     = "development"
  validation {
    condition     = contains(["custom", "development", "minimum", "small", "large", "maximum"], var.vault_size)
    error_message = "Please use \"custom\", \"development\", \"minimum\", \"small\", \"large\" or \"maximum\"."
  }
}

variable "vault_volume_type" {
  description = "When `vault_size` is set to `custom`, specify your own volume type here."
  type        = string
  default     = "gp2"
  validation {
    condition     = contains(["gp2", "gp3", "io1", "io2"], var.vault_volume_type)
    error_message = "Please use \"gp3\", \"gp3\", \"io1\" or \"io2\"."
  }
}
variable "vault_volume_size" {
  description = "When `vault_size` is set to `custom`, specify your own volume size (in GB) here."
  type        = number
  default     = 30
  validation {
    condition     = var.vault_volume_size >= 8
    error_message = "Please use a minimum of \"8\"."
  }
}

variable "vault_volume_iops" {
  description = "When `vault_size` is set to `custom`, specify your own volume iops here. (Maximum 50 times the `volume_size`.)"
  type        = number
  default     = 400
  validation {
    condition     = var.vault_volume_iops >= 0
    error_message = "Please us a positive number, such as \"2500\"."
  }
}

variable "vault_node_amount" {
  description = "The amount of instances to deploy, by not specifying the value, the optimum amount is calculated."
  type        = number
  default     = 3
  validation {
    condition     = var.vault_node_amount == null ? true : var.vault_node_amount % 2 == 1 && var.vault_node_amount >= 3 && var.vault_node_amount <= 5
    error_message = "Please use an odd number for amount, like 3 or 5."
  }
}

variable "vault_enable_ui" {
  description = "Expose (or hide) a web user interface."
  type        = bool
  default     = true
}

variable "vault_allowed_cidr_blocks" {
  description = "What CIDR blocks are allowed to access Vault."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "vault_aws_vpc_id" {
  description = "The VPC identifier to deploy in. Fill this value when you want the Vault installation to be done in an existing VPC."
  type        = string
  default     = ""
}

variable "vault_create_bastionhost" {
  description = "A bastion host is optional and would allow you to login to the instances."
  type        = bool
  default     = true
}

# TODO: This feels cluncky, try to calculate the cidr block.
variable "vault_vpc_cidr_block_start" {
  description = "The first two octets of the VPC cidr."
  type        = string
  default     = "172.16"
}

variable "vault_tags" {
  description = "Tags to add to resources."
  type        = map(string)
  default = {
    owner     = "david gidony",
    terraform = "true",
    env       = "test"
  }
}

variable "vault_asg_instance_lifetime" {
  description = "The amount of seconds after which to replace the instances."
  type        = number
  default     = 0
  validation {
    condition     = var.vault_asg_instance_lifetime == 0 || (var.vault_asg_instance_lifetime >= 86400 && var.vault_asg_instance_lifetime <= 31536000)
    error_message = "Use \"0\" to remove the parameter or a value between \"86400\" and \"31536000\"."
  }
}

variable "vault_aws_certificate_arn" {
  description = "The ARN to an existing certificate."
  type        = string
  default     = "arn:aws:acm:eu-west-2:391026464511:certificate/62db92a0-208d-4363-b616-21a30bc0c7d4"
  validation {
    condition     = can(regex("^arn:aws:acm:", var.vault_aws_certificate_arn))
    error_message = "Please specify a valid ARN, starting with \"arn:aws:acm:\"."
  }
}

variable "vault_log_level" {
  description = "Specifies the Vault log level to use."
  type        = string
  default     = "info"
  validation {
    condition     = contains(["trace", "debug", "error", "warn", "info"], var.vault_log_level)
    error_message = "Please use \"trace\", \"debug\", \"error\", \"warn\" or \"info\"."
  }
}

variable "vault_default_lease_time" {
  description = "Specifies the default lease duration for tokens and secrets."
  type        = string
  default     = "768h"
  validation {
    condition     = can(regex("^[1-9][0-9]*(s|m|h)", var.vault_default_lease_time))
    error_message = "Please use a positive number, followed by the duration indicator."
  }
}

variable "vault_max_lease_time" {
  description = "Specifies the maximum lease duration for tokens and secrets."
  type        = string
  default     = "768h"
  validation {
    condition     = can(regex("^[1-9][0-9]*(s|m|h)$", var.vault_max_lease_time))
    error_message = "Please use a positive number, followed by the duration indicator."
  }
}

variable "vault_data_path" {
  description = "The absolute path where Vault should place data."
  type        = string
  default     = "/opt/vault"
  validation {
    condition     = can(regex("^/", var.vault_data_path))
    error_message = "Please use an absolute path like \"/my/vault\"."
  }
}

variable "vault_private_subnet_ids" {
  description = "The ids of the private subnets to deploy to. These subnets should have a NAT gateway. Only required when `vault_aws_vpc_id` is set."
  type        = list(string)
  default     = []
}

variable "vault_public_subnet_ids" {
  description = "The ids of the subnets to deploy the load balancer to. Use public subnets to expose the service to the internet, otherwise use private subnets. Only required when `vault_aws_vpc_id` is set."
  type        = list(string)
  default     = []
}

variable "vault_type" {
  description = "The type of installation to do, either \"enterprise\" or \"opensource\"."
  type        = string
  default     = "enterprise"
  validation {
    condition     = contains(["enterprise", "opensource"], var.vault_type)
    error_message = "Please use \"enterprise\" or \"opensource\"."
  }
}

variable "vault_license" {
  description = "The contents of the license."
  type        = string
  default     = "02MV4UU43BK5HGYYTOJZWFQMTMNNEWU33JLJDUM2SOIRFGUTTNIV2FUR2JGJHHSMBRJ5KE26SMKRMTIWSULF2E26S2NVGUIVLYLFVFU3KNIRLG2SLJO5UVSM2WPJSEOOLULJMEUZTBK5IWST3JJEZVS3KONVMW2RTNLJBTAMSZNJVTKTCXLJVVURCZORHFIZDNJ5BTA6COKRNGSTLNKEYE2RCCNVNFI23JJRBUU4DCNZHDAWKXPBZVSWCSOBRDENLGMFLVC2KPNFEXCSLJO5UWCWCOPJSFOVTGMRDWY5C2KNETMSLKJF3U22SJORGVIRLUJVKGIVKNIRVTMTSUJU3E22TLOVGXUY3YJZVGOMKNKRATAV3JJFZUS3SOGBMVQSRQLAZVE4DCK5KWST3JJF4U2RCJPFGFIRLYJRKEKM2WIRAXOT3KIF3U62SBO5LWSSLTJFWVMNDDI5WHSWKYKJYGEMRVMZSEO3DULJJUSNSJNJEXOTLKJV2E2VCFORGVIZCVJVVE2NSOKRVTMTSUNN2U6VDLGVLWSSLTJFXFE3DDNUYXAYTNIYYGCVZZOVMDGUTQMJLVK2KPNFEXSTKEJF5EYVCFPBGFIRJTKZCES6SPNJKTKT3KKU2UY2TLGVHVM33JJRBUU53DNU4WWZCXJYYES2TPNFSG2RRRMJEFC2KMINFG2YSHIZXGG6KJGZSXSSTUMIZFEMLCI5LHUSLKOBRES3JRGFREQUTQJRLVE2SMLBHGUWKXPBWES2LXNFNDEOJSLJMEU5KZK42WUWSTGF3WEMTYOBMTG23JJRBUU2C2JBNGQYTNJZWFUQZRNNMVQUTIJRMEE6LCGNJGYWJTKJYGEMRUORSEQSTIMJXE43LCGNFHISLJO5UVSV2SGJMVONLKLJLVC5C2I5DDAWKTGF3WG3JZGBNFOTRQMFLTS5KMK52GYZKTGF2FSVZVNBNDEVTULJLTKMCJNQYTSZSRHU6S4WBTPFFHUULTM4VTSNLOGY3GOV3VLFJUOOLRJF4EGQLZIVGG4QKYNZKEYODMIJQUONTGMVJHA6LKOV3GIL2ENRYHE2RVKVGG4OJSMV2UYTTTJF3DSRZQLBVXQVCMKQXXI2CXO5SEGWRRMRAWWY3BGRSFMMBTGM4FA53NKZWGC5SKKA2HASTYJFETSRBWKVDEYVLBKZIGU22XJJ2GGRBWOBQWYNTPJ5TEO3SLGJ5FAS2KKJWUOSCWGNSVU53RIZSSW3ZXNMXXGK2BKRHGQUC2M5JS6S2WLFTS6SZLNRDVA52MG5VEE6CJG5DU6YLLGZKWC2LBJBXWK2ZQKJKG6NZSIRIT2PI"
  # validation {
  #   condition     = length(var.vault_license) == 1201 || length(var.vault_license) == 0
  #   error_message = "The license should contain 1201 characters."
  # }
}

variable "vault_api_addr" {
  description = "The URL for the Vault API to advertise."
  type        = string
  default     = ""
  validation {
    condition     = can(regex("^http", var.vault_api_addr)) || length(var.vault_api_addr) == 0
    error_message = "Please use a URL like: \"https://vault.example.com:8200\"."
  }
}

variable "r53_zone_id" {
  description = "r53 hosted zone id."
  type        = string
  default     = "Z01037061JEWRULO9O9LE"
}

variable "r53_record_name" {
  description = "The name of the dns record for the load balancer."
  type        = string
  default     = "vault.dudelabxxx.com"
}

variable "vault_allowed_cidr_blocks_replication" {
  description = "What CIDR blocks are allowed to replicate."
  type        = list(string)
  default     = []
}

variable "vault_asg_cooldown_seconds" {
  description = "The cooldown period in seconds to use for the autoscaling group."
  type        = number
  default     = 300
  validation {
    condition     = var.vault_asg_cooldown_seconds >= 120 && var.vault_asg_cooldown_seconds <= 600
    error_message = "Please use a cooldown period between 120 and 600 seconds."
  }
}

variable "vault_ca_cert_path" {
  description = "The CA certificate that Vault nodes will use to sign their certificate."
  type        = string
  default     = "tls/vault_ca.crt"
  validation {
    condition     = fileexists(var.vault_ca_cert_path)
    error_message = "The specified certificate file does not exist."
  }
}

variable "vault_ca_key_path" {
  description = "The CA key that Vault nodes will use to sign their certificate."
  type        = string
  default     = "tls/vault_ca.pem"
  validation {
    condition     = fileexists(var.vault_ca_key_path)
    error_message = "The specified key file does not exist."
  }
}

variable "vault_allow_replication" {
  description = "Allow Vault replication to be used."
  type        = bool
  default     = false
}

variable "vault_enable_telemetry" {
  description = "Enable telemetry; uses a weaker health check on the ASG."
  type        = bool
  default     = false
}

variable "vault_prometheus_retention_time" {
  description = "Specifies the amount of time that Prometheus metrics are retained in memory."
  type        = string
  default     = "24h"
  validation {
    condition     = try(can(regex("^[1-9][0-9]*(s|m|h)$", var.vault_prometheus_retention_time)), var.vault_prometheus_retention_time == 0)
    error_message = "Please use time indicator, starting with a number, ending in s, m or h. 0 can also be used to disable retention."
  }
}
variable "vault_prometheus_disable_hostname" {
  description = "It is recommended to also enable the option disable_hostname to avoid having prefixed metrics with hostname."
  type        = bool
  default     = false
}

variable "vault_enable_telemetry_unauthenticated_metrics_access" {
  description = "If set to true, allows unauthenticated access to the /v1/sys/metrics endpoint."
  type        = bool
  default     = false
}

variable "vault_aws_kms_key_id" {
  description = "You can optionally bring your own AWS KMS key."
  type        = string
  default     = "a455605b-5f73-4139-bd92-eb0ec0e04934"
  validation {
    condition     = var.vault_aws_kms_key_id == "" || length(var.vault_aws_kms_key_id) >= 30
    error_message = "Please specify an AWS KMS key with a length of 30 or more."
  }
}

variable "vault_asg_warmup_seconds" {
  description = "The warm period in seconds to use for the autoscaling group and health check."
  type        = number
  default     = 300
  validation {
    condition     = var.vault_asg_warmup_seconds >= 60 && var.vault_asg_warmup_seconds <= 600
    error_message = "Please use a warmup period between 60 and 600 seconds."
  }
}

variable "vault_api_port" {
  description = "The TCP port where the API should listen."
  type        = number
  default     = 8200
  validation {
    condition     = var.vault_api_port >= 1 && var.vault_api_port <= 65535
    error_message = "Please choose a port number between 1 and 65535."
  }
}

variable "vault_replication_port" {
  description = "The TCP port where replication should listen."
  type        = number
  default     = 8201
  validation {
    condition     = var.vault_replication_port >= 1 && var.vault_replication_port <= 65535
    error_message = "Please choose a port number between 1 and 65535."
  }
}

variable "vault_aws_s3_snapshots_bucket_name" {
  description = "Specify an AWS S3 bucket to store snapshots in."
  type        = string
  default     = ""
  validation {
    condition     = (length(var.vault_aws_s3_snapshots_bucket_name) >= 3 && length(var.vault_aws_s3_snapshots_bucket_name) <= 63) || var.vault_aws_s3_snapshots_bucket_name == ""
    error_message = "Please use a bucket name between 3 and 63 characters."
  }
}

variable "vault_aws_lb_availability" {
  description = "Specify if the load balancer is exposed to the internet or not."
  type        = string
  default     = "external"
  validation {
    condition     = contains(["internal", "external"], var.vault_aws_lb_availability)
    error_message = "Please use \"internal\" or \"external\" to indicate the availability of the load balancer."
  }
}

variable "vault_extra_security_group_ids" {
  description = "Specify the security group ids that should also have access to Vault."
  type        = list(string)
  default     = []
}

variable "vault_audit_device" {
  description = "You can specify an audit device to be created. This will create a mount on the Vault nodes."
  type        = bool
  default     = false
}

variable "vault_audit_device_size" {
  description = "The size (in GB) of the audit device when `var.vault_audit_device` is enabled."
  type        = number
  default     = 16
  validation {
    condition     = var.vault_audit_device_size >= 16
    error_message = "Please use 16 (GB) or more."
  }
}

variable "vault_audit_device_path" {
  description = "The absolute pah to where Vault can store audit logs."
  type        = string
  default     = "/var/log/vault"
  validation {
    condition     = can(regex("^/", var.vault_audit_device_path))
    error_message = "Please specify an absolute path."
  }
}

variable "vault_allow_ssh" {
  description = "You can (dis-) allow SSH access to the Vault nodes."
  type        = bool
  default     = true
}

variable "vault_asg_minimum_required_memory" {
  description = "When using a custom size, the minimum amount of memory (in megabytes) can be set."
  type        = number
  default     = 512
  validation {
    condition     = var.vault_asg_minimum_required_memory >= 512
    error_message = "Please use 512 (megabytes) or more."
  }
}

variable "vault_asg_minimum_required_vcpus" {
  description = "When using a custom size, the minimum amount of vcpus can be set."
  type        = number
  default     = 1
  validation {
    condition     = var.vault_asg_minimum_required_vcpus >= 1
    error_message = "Please specify at least 1 for the CPU count."
  }
}

variable "vault_asg_cpu_manufacturer" {
  description = "You can choose the cpu manufacturer."
  type        = string
  default     = "intel"
  validation {
    condition     = contains(["amazon-web-services", "amd", "intel"], var.vault_asg_cpu_manufacturer)
    error_message = "Please choosse from \"amazon-web-services\", \"amd\" or \"intel\"."
  }
}

variable "vault_enable_cloudwatch" {
  description = "When true, installs the AWS Cloudwatch agent on the Vault nodes."
  type        = bool
  default     = false
}

variable "vault_custom_script_s3_url" {
  description = "The URL to the script stored on s3 that should run on the Vault hosts."
  type        = string
  default     = ""
  validation {
    condition     = can(regex("^s3://", var.vault_custom_script_s3_url)) || var.vault_custom_script_s3_url == ""
    error_message = "Please use an s3 URL, starting with \"s3://\"."
  }
}

variable "vault_custom_script_s3_bucket_arn" {
  description = "The arn where the custom script are stored for the Vault nodes."
  type        = string
  default     = ""
  validation {
    condition     = can(regex("^arn:aws:s3:", var.vault_custom_script_s3_bucket_arn)) || var.vault_custom_script_s3_bucket_arn == ""
    error_message = "Please specify a valid ARN, starting with \"arn:aws:s3:\"."
  }
}

variable "vault_bastion_allowed_cidr_blocks" {
  description = "What CIDR blocks are allowed to access the bastion host over SSH."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "vault_bastion_custom_script_s3_bucket_arn" {
  description = "The arn where the custom script are stored for the bastion host."
  type        = string
  default     = ""
  validation {
    condition     = can(regex("^arn:aws:s3:", var.vault_bastion_custom_script_s3_bucket_arn)) || var.vault_bastion_custom_script_s3_bucket_arn == ""
    error_message = "Please specify a valid ARN, starting with \"arn:aws:s3:\"."
  }
}

variable "vault_bastion_custom_script_s3_url" {
  description = "The URL to the script stored on s3 that should run on the bastion host."
  type        = string
  default     = ""
  validation {
    condition     = can(regex("^s3://", var.vault_bastion_custom_script_s3_url)) || var.vault_bastion_custom_script_s3_url == ""
    error_message = "Please use an s3 URL, starting with \"s3://\"."
  }
}

variable "unseal_vault" {
  description = "Should we try to unseal the vault ? - Currently only works when using a public certificate."
  type        = bool
  default     = false
}

variable "vault_bastion_create_s3_bucket" {
  description = "Should an S3 bucket be create that the bastion host can use for backups?"
  type        = bool
  default     = true
}

variable "vault_bastion_public_ip" {
  description = "Assign a public IP to the bastion host."
  type        = bool
  default     = true
}
