#!/bin/bash
set -ex -o pipefail

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
sudo yum install -y awslogs
sudo systemctl enable awslogsd.service

# Create jayoh user and paths
sudo useradd --no-create-home --shell /bin/false jayoh
sudo usermod --lock jayoh
sudo mkdir /etc/jayoh
sudo chown jayoh:jayoh /etc/jayoh
sudo chmod 700 /etc/jayoh
sudo -u jayoh mkdir /etc/jayoh/secrets
cat <<EOF | sudo -u jayoh tee /etc/jayoh/config.json
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

# tmpfs will hold its data in volatile memory and won't be written to disk when no swap is setup
echo 'tmpfs /etc/jayoh/secrets tmpfs rw,nodev,nosuid,noexec,uid=jayoh,gid=jayoh,mode=700 0 0' |
  sudo tee -a /etc/fstab

# And finally, disable default OpenSSH server
sudo systemctl disable sshd.service
