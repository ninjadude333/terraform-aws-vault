#!/bin/bash
yum update -y

mkdir -p "${vault_data_path}"
mkfs.ext4 /dev/sda1
mount /dev/sda1 "${vault_data_path}"
chmod 750 "${vault_data_path}"

if [ "${audit_device}" = "true" ] ; then
  mkdir -p "${audit_device_path}"
  mkfs.ext4 /dev/sdb
  mount /dev/sdb "${audit_device_path}"
  chmod 750 "${audit_device_path}"
fi

my_hostname="$(curl http://169.254.169.254/latest/meta-data/hostname)"
my_ipaddress="$(curl http://169.254.169.254/latest/meta-data/local-ipv4)"
my_instance_id="$(curl http://169.254.169.254/latest/meta-data/instance-id)"
my_region="$(curl http://169.254.169.254/latest/dynamic/instance-identity/document | grep region | cut -d\" -f4)"

if [ "${vault_custom_script_s3_url}" != "" ] ; then
  aws s3 cp "${vault_custom_script_s3_url}" /custom.sh
  sh /custom.sh
fi

if [ "${cloudwatch_monitoring}" = "true" ] ; then
  aws s3 cp "s3://vault-scripts-${random_string}/cloudwatch.sh" /cloudwatch.sh
  sh /cloudwatch.sh -n "${vault_name}" -N "$${my_hostname}" -i "$${my_instance_id}" -r "${random_string}" -p "${vault_data_path}" -s "${vault_cloudwatch_namespace}"
fi

yum install -y yum-utils
yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo

yum install -y "${vault_package}"
chown vault:vault "${vault_data_path}"

if [ "${vault_data_path}" != "/opt/vault" ] ; then
  mkdir ${vault_data_path}/data
  chown vault:vault ${vault_data_path}/data
  chmod 755 ${vault_data_path}/data
fi

if [ -d "${audit_device_path}" ] ; then
  chown vault:vault "${audit_device_path}"
fi

runuser -l ec2-user -c "vault -autocomplete-install"
setcap cap_ipc_lock=+ep "$(readlink -f "$(which vault)")"

echo '* hard core 0' >> /etc/security/limits.d/vault.conf
echo '* soft core 0' >> /etc/security/limits.d/vault.conf
ulimit -c 0

test -d "${vault_data_path}/tls" || mkdir "${vault_data_path}/tls"
chmod 0755 "${vault_data_path}/tls"
chown vault:vault "${vault_data_path}/tls"
echo "${vault_ca_key}" > "${vault_data_path}/tls/vault_ca.pem"
echo "${vault_ca_cert}" > "${vault_data_path}/tls/vault_ca.crt"
chmod 0600 "${vault_data_path}/tls/vault_ca.pem"
chown root:root "${vault_data_path}/tls/vault_ca.pem"
chmod 0644 "${vault_data_path}/tls/vault_ca.crt"
chown root:root "${vault_data_path}/tls/vault_ca.crt"

cat << EOF > "${vault_data_path}/tls/request.cfg"
[req]
distinguished_name = dn
req_extensions     = ext
prompt             = no

[dn]
organizationName       = Snake
organizationalUnitName = SnakeUnit
commonName             = vault-internal.cluster.local

[ext]
basicConstraints = CA:FALSE
keyUsage         = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName   = @alt_names

[alt_names]
IP.1 = $${my_ipaddress}
DNS.1 = $${my_hostname}
EOF

openssl req -config "${vault_data_path}/tls/request.cfg" -new -newkey rsa:2048 -nodes -keyout "${vault_data_path}/tls/vault.pem" -extensions ext -out "${vault_data_path}/tls/vault.csr"
chmod 0640 "${vault_data_path}/tls/vault.pem"
chown root:vault "${vault_data_path}/tls/vault.pem"

openssl x509 -extfile "${vault_data_path}/tls/request.cfg" -extensions ext -req -in "${vault_data_path}/tls/vault.csr" -CA "${vault_data_path}/tls/vault_ca.crt" -CAkey "${vault_data_path}/tls/vault_ca.pem" -CAcreateserial -out "${vault_data_path}/tls/vault.crt" -days 7300
chmod 0644 "${vault_data_path}/tls/vault.crt"
chown root:root "${vault_data_path}/tls/vault.crt"

cat "${vault_data_path}/tls/vault_ca.crt" >> "${vault_data_path}/tls/vault.crt"
curl https://www.amazontrust.com/repository/AmazonRootCA1.pem --output "${vault_data_path}/tls/amazon_ca.crt"
cat "${vault_data_path}/tls/amazon_ca.crt" >> "${vault_data_path}/tls/vault_ca.crt"

cat << EOF > /etc/vault.d/vault.hcl
cluster_name      = "${vault_name}"
disable_mlock     = true
ui                = ${vault_enable_ui}
api_addr          = "${api_addr}"
cluster_addr      = "https://$${my_ipaddress}:8201"
log_level         = "${log_level}"
max_lease_ttl     = "${max_lease_ttl}"
default_lease_ttl = "${default_lease_ttl}"

storage "raft" {
  path    = "${vault_data_path}/data"
  node_id = "$${my_instance_id}"
  retry_join {
    auto_join               = "provider=aws tag_key=Name tag_value=${instance_name} addr_type=private_v4 region=${region}"
    auto_join_scheme        = "https"
    leader_ca_cert_file     = "${vault_data_path}/tls/vault_ca.crt"
    leader_client_cert_file = "${vault_data_path}/tls/vault.crt"
    leader_client_key_file  = "${vault_data_path}/tls/vault.pem"
  }
}

listener "tcp" {
  address                        = "$${my_ipaddress}:8200"
  cluster_address                = "$${my_ipaddress}:8201"
  tls_key_file                   = "${vault_data_path}/tls/vault.pem"
  tls_cert_file                  = "${vault_data_path}/tls/vault.crt"
  tls_client_ca_file             = "${vault_data_path}/tls/vault_ca.crt"
  telemetry {
    unauthenticated_metrics_access = ${unauthenticated_metrics_access}
  }
}

seal "awskms" {
  region     = "${region}"
  kms_key_id = "${kms_key_id}"
}
EOF

if [ "${telemetry}" = true ] ; then
cat << EOF >> /etc/vault.d/vault.hcl

telemetry {
  prometheus_retention_time      = "${prometheus_retention_time}"
  disable_hostname               = ${prometheus_disable_hostname}
}
EOF
fi

if [ -n "${vault_license}" ] ; then
  echo "VAULT_LICENSE=${vault_license}" >> /etc/vault.d/vault.env
fi

systemctl --now enable vault

if [[ "${audit_device}" = "true" || "${cloudwatch_monitoring}" = "true" ]] ; then
  aws s3 cp "s3://vault-scripts-${random_string}/setup_logrotate.sh" /setup_logrotate.sh
  sh /setup_logrotate.sh -a "${audit_device_path}" -s "$[${audit_device_size}*4]"
fi

echo "export VAULT_ADDR=https://$${my_ipaddress}:8200" >> /etc/profile.d/vault.sh
echo "export VAULT_CACERT=${vault_data_path}/tls/vault_ca.crt" >> /etc/profile.d/vault.sh
echo "export HISTIGNORE=\"&:vault*\"" >> /etc/profile.d/vault.sh

usermod -G vault ec2-user

cat << EOF >> /usr/local/bin/aws_health.sh
#!/bin/sh

# This script checks that status of Vault and reports that status to the ASG.
# If Vault fails, the instance is replaced.

# Tell Vault how to connect.
export VAULT_ADDR=https://$${my_ipaddress}:8200
export VAULT_CACERT="${vault_data_path}/tls/vault_ca.crt"

# Get the status of Vault and report to AWS ASG.
# TODO: This check is not sufficient; 0 is returned in many cases.
if vault status > /dev/null 2>&1 ; then
  aws --region $${my_region} autoscaling set-instance-health --instance-id $${my_instance_id} --health-status Healthy
else
  aws --region $${my_region} autoscaling set-instance-health --instance-id $${my_instance_id} --health-status Unhealthy
fi
EOF

chmod 754 /usr/local/bin/aws_health.sh
sleep "${warmup}" && crontab -l | { cat; echo "* * * * * /usr/local/bin/aws_health.sh"; } | crontab -
cat << EOF >> /usr/local/bin/aws_deregister.sh
#!/bin/sh

# If an instance is terminated, de-register the instance from the target group.
# This means no traffic is sent to the node that is being terminated.
# After this deregistration, it's safe to destroy the instance.

if (curl --silent http://169.254.169.254/latest/meta-data/autoscaling/target-lifecycle-state | grep Terminated) ; then
%{ for target_group_arn in target_group_arns }
  deregister-targets --target-group-arn "${target_group_arn}" --targets $${my_instance_id}
%{ endfor }
fi
EOF

chmod 754 /usr/local/bin/aws_deregister.sh

crontab -l | { cat; echo "* * * * * /usr/local/bin/aws_deregister.sh"; } | crontab -
