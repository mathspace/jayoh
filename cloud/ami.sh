#!/bin/bash
set -ex -o pipefail

# Due to lack of support from AWS CLI [1], default region must be set
# explicitly for AWS logging agent. This service file will set
# AWS_DEFAULT_REGION env var for the whole OS on boot and also
# specifically in /etc/awslogs/awscli.conf for log agent.
#
# [1]: https://github.com/aws/aws-cli/issues/486
cat <<"EOF" | sudo tee /opt/set_aws_default_region > /dev/null
#!/bin/bash
set -xe -o pipefail

METAURL='http://169.254.169.254/latest/dynamic/instance-identity/document'
REGION="$(curl -s $METAURL | jq -r .region)"

sed -i '/^AWS_DEFAULT_REGION/d' /etc/environment
echo "AWS_DEFAULT_REGION=$REGION" >> /etc/environment

sed -i "s/^region.*/region = $REGION/" /etc/awslogs/awscli.conf
EOF
sudo chmod +x /opt/set_aws_default_region

cat <<"EOF" | sudo tee /etc/systemd/system/aws_default_region_setter.service > /dev/null
[Unit]
Description=AWS default region setter
After=network.target
Before=cloud-init.service key_loader.service

[Service]
Type=oneshot
ExecStart=/opt/set_aws_default_region

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable aws_default_region_setter.service

# Setup AWS cloudwatch logger agent
# This requires a bunch of permissions. Below is a sample policy:
#
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Effect": "Allow",
#       "Action": [
#         "logs:CreateLogGroup",
#         "logs:CreateLogStream",
#         "logs:PutLogEvents",
#         "logs:DescribeLogStreams"
#     ],
#       "Resource": [
#         "arn:aws:logs:*:*:*"
#     ]
#   }
#  ]
# }
# 
# Logs will end up under /var/log/messages
sudo yum update -y
sudo yum install -y awslogs jq
sudo systemctl enable awslogsd.service

# Create jayoh user and paths
sudo useradd --no-create-home --shell /bin/false jayoh
sudo usermod --lock jayoh
sudo mkdir /etc/jayoh
sudo chown jayoh:jayoh /etc/jayoh
sudo chmod 700 /etc/jayoh
sudo -u jayoh mkdir /etc/jayoh/secrets
cat <<"EOF" | sudo -u jayoh tee /etc/jayoh/config.json > /dev/null
{
  "acl_file": "/etc/jayoh/secrets/acl.json",
  "server_key_file": "/etc/jayoh/secrets/server_key",
  "listen": "0.0.0.0:22"
}
EOF
sudo mkdir -p /opt
sudo mv /tmp/jayoh /opt
sudo chmod +x /opt/jayoh
sudo mv /tmp/jayoh.service /etc/systemd/system
sudo systemctl enable jayoh.service

# Server key loader will load the server private key from parameter
# store once on every boot. The parameter name is read from
# "jayoh/server_key_parameter_name" tag of the instance.
# This requires some IAM permissions. Here is a sample policy:
#
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Effect": "Allow",
#       "Action": "ec2:DescribeInstances",
#       "Resource": "*"
#     },
#     {
#       "Effect": "Allow",
#       "Action": "ssm:GetParameter*",
#       "Resource": "arn:aws:ssm:us-west-1:1234123123:parameter/jayoh/*"
#     }
#   ]
# }

cat <<"EOF" | sudo tee /opt/get_own_tag > /dev/null
#!/bin/bash
set -ex -o pipefail

METAURL='http://169.254.169.254/latest/dynamic/instance-identity/document'
INSTANCE_ID=$(curl -s $METAURL | jq -r .instanceId)

echo "$(
  aws ec2 describe-instances --filters=Name=instance-id,Values=$INSTANCE_ID |
    jq -r '.Reservations[0].Instances[].Tags[] | select(.Key=="'"$1"'") | .Value'
)"
EOF
sudo chmod +x /opt/get_own_tag

# Setup script to store server key in the right place on boot
cat <<"EOF" | sudo tee /etc/systemd/system/key_loader.service > /dev/null
[Unit]
Description=SSH server key loader
After=network.target
Before=jayoh.service

[Service]
Type=oneshot
ExecStart=/bin/bash -xe -o pipefail -c 'aws ssm get-parameter --with-decryption --name "$(/opt/get_own_tag jayoh/server_key_parameter_name)" | jq -r .Parameter.Value > /etc/jayoh/secrets/server_key'
User=jayoh
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=load_server_key
EnvironmentFile=/etc/environment

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable key_loader.service

# ACL loader will reload /etc/jayoh/secrets/acl.json once a minute from
# S3. The S3 path is read from "jayoh/acl_s3_path" tag of the instance.

cat <<"EOF" | sudo tee -a /etc/crontab > /dev/null
*  *  *  *  * root sudo -u jayoh bash -xe -o pipefail -c 'aws s3 cp "$(/opt/get_own_tag jayoh/acl_s3_path)" /etc/jayoh/secrets/acl.json' && systemctl reload jayoh.service
EOF

# tmpfs will hold its data in volatile memory and won't be written to disk when no swap is setup
echo 'tmpfs /etc/jayoh/secrets tmpfs rw,nodev,nosuid,noexec,uid=jayoh,gid=jayoh,mode=700 0 0' |
  sudo tee -a /etc/fstab > /dev/null

# awslog agent's state file will be kept on volatile memory to ensure
# the agent doesn't lock onto a log stream with specific instance ID.
echo 'tmpfs /var/lib/awslogs tmpfs rw,nodev,nosuid,noexec,uid=root,gid=root,mode=700 0 0' |
  sudo tee -a /etc/fstab > /dev/null

# And finally, move the default OpenSSH to a different port. This is kept only to provide
# debugging capabilities.
sudo sed -i 's/#Port.*/Port 2222/' /etc/ssh/sshd_config
