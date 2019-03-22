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
#       "Action": "ssm:GetParameters",
#       "Resource": "arn:aws:ssm:us-west-1:1234123123:parameter/jayoh-*"
#     }
#   ]
# }

cat <<"EOF" | sudo tee /opt/save_param_from_tag > /dev/null
#!/bin/bash
set -ex -o pipefail

TAGNAME="$1"
OUTFILE="$2"

METAURL='http://169.254.169.254/latest/dynamic/instance-identity/document'
export AWS_DEFAULT_REGION=$(curl -s $METAURL | jq -r .region)
INSTANCE_ID=$(curl -s $METAURL | jq -r .instanceId)

SERVER_KEY_PARAM_NAME="$(
  aws ec2 describe-instances --filters=Name=instance-id,Values=$INSTANCE_ID |
    jq -r '.Reservations[0].Instances[].Tags[] | select(.Key=="'"$TAGNAME"'") | .Value'
)"
aws ssm get-parameter --with-decryption --name "$SERVER_KEY_PARAM_NAME" |
  jq -r .Parameter.Value > "$OUTFILE"
EOF
sudo chmod +x /opt/save_param_from_tag

cat <<"EOF" | sudo tee /etc/systemd/system/key_loader.service > /dev/null
[Unit]
Description=SSH server key loader
After=network.target
Before=jayoh.service

[Service]
Type=oneshot
ExecStart=/opt/save_param_from_tag jayoh/server_key_parameter_name /etc/jayoh/secrets/server_key
User=jayoh
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=load_server_key
EOF

# ACL loader will reload /etc/jayoh/secrets/acl.json once a minute from
# parameter store. The parameter name is read from
# "jayoh/acl_parameter_name" tag of the instance.

cat <<"EOF" | sudo tee -a /etc/crontab > /dev/null
*  *  *  *  * root sudo -u jayoh /opt/save_param_from_tag jayoh/acl_parameter_name /etc/jayoh/secrets/acl.json && systemctl reload jayoh.service
EOF

# tmpfs will hold its data in volatile memory and won't be written to disk when no swap is setup
echo 'tmpfs /etc/jayoh/secrets tmpfs rw,nodev,nosuid,noexec,uid=jayoh,gid=jayoh,mode=700 0 0' |
  sudo tee -a /etc/fstab

# And finally, disable default OpenSSH server
sudo systemctl disable sshd.service
