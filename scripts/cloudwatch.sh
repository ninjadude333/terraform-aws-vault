#!/bin/sh

# A function to instruct on usage.
usage() {
  echo "$0 -i INSTANCE_ID -n VAULT_NAME -N INSTANCE_NAME -r RANDOM_STRING -p VAULT_PATH -s VAULT_CLOUDWATCH_NAMESPACE"
  echo ""
  exit 1
}

# Read the specified arguments.
while getopts :i:n:N:r:p:s: flag ; do
  case "${flag}" in
    i)
      instance_id="${OPTARG}"
    ;;
    n)
      vault_name="${OPTARG}"
    ;;
    N)
      instance_name="${OPTARG}"
    ;;
    r)
      random_string="${OPTARG}"
    ;;
    p)
      vault_path="${OPTARG}"
    ;;
    s)
      vault_cloudwatch_namespace="${OPTARG}"
    ;;
    \?)
      echo "The option ${OPTARG} is invalid."
      exit 1
    ;;
    :)
     echo "The argument ${OPTARG} is unknown."
     exit 1
    ;;
  esac
done

# Check that the instance_id is set.
if [ -z "${instance_id}" ] ; then
  echo "Please specify an instance id."
  echo ""
  usage
fi

# Check that the vault_name is set.
if [ -z "${vault_name}" ] ; then
  echo "Please specify a Vault name."
  echo ""
  usage
fi

# Check that the instance_name is set.
if [ -z "${instance_name}" ] ; then
  echo "Please specify an instance name."
  echo ""
  usage
fi

# Check that random_string is set.
if [ -z "${random_string}" ] ; then
  echo "Please specify an random string."
  echo ""
  usage
fi

# Check that vault_path is set.
if [ -z "${vault_path}" ] ; then
  echo "Please specify the vault path."
  echo ""
  usage
fi

# Check that vault_cloudwatch_namespace is set.
if [ -z "${vault_cloudwatch_namespace}" ] ; then
  echo "Please specify the cloudwatch namespace for vault."
  echo ""
  usage
fi

# Install the cloudwatch agent.
yum install -y amazon-cloudwatch-agent

# Make sure the folder for vault.log exists
mkdir /var/log/vault

# Configure overrides for the vault.service, STERR and STDIN are now send to Rsyslog.
# Rsyslog will write them to /var/log/vault/vault.log
mkdir /etc/systemd/system/vault.service.d
cat << EOF > /etc/systemd/system/vault.service.d/override.conf
[Service]
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=vault
EOF

# Configure Rsyslog to send messages tagged with "vault" to Vault log directory.
cat << EOF > /etc/rsyslog.d/vault.conf
if \$programname == 'vault' then /var/log/vault/vault.log
& stop
EOF
systemctl restart rsyslog.service

# Place the CloudWatch configuration.
cat << EOF > /opt/aws/amazon-cloudwatch-agent/bin/config.json
{
  "agent": {
    "metrics_collection_interval": 60,
    "run_as_user": "root"
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/cloud-init-output.log",
            "log_group_name": "${vault_name}-cloudinitlog",
            "log_stream_name": "${instance_id}",
            "retention_in_days": 7
          },
          {
            "file_path": "/var/log/vault/vault.log",
            "log_group_name": "${vault_name}-vaultlog",
            "log_stream_name": "${instance_id}",
            "retention_in_days": 7
          }
        ]
      }
    }
  },
  "metrics": {
    "namespace": "${vault_cloudwatch_namespace}",
    "aggregation_dimensions": [
      ["InstanceId","AutoScalingGroupName"],
      []
    ],
      "append_dimensions": {
        "AutoScalingGroupName": "\${aws:AutoScalingGroupName}",
        "InstanceId": "\${aws:InstanceId}"
      },
      "metrics_collected": {
        "disk": {
          "measurement": [
            "used_percent"
          ],
          "metrics_collection_interval": 60,
          "resources": [
            "/","${vault_path}"
          ]
        },
        "mem": {
          "measurement": [
          "mem_used_percent"
        ],
        "metrics_collection_interval": 60
      },
      "statsd": {
        "metrics_aggregation_interval": 60,
        "metrics_collection_interval": 10,
        "service_address": ":8125"
      }
    }
  }
}
EOF

# Initialize the Cloudwatch_agent after installation
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json