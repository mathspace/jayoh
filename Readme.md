**This project is in alpha stage. Do not use in production.**

*jayoh* is a SSH jump server. Also known as *bastion* server, it is a
gateway to a private network. Instead of hardening every host in the
infrastructure, you harden this one host and firewall the rest, reducing
the attack surface.

*jayoh* is not a full fledged SSH server. In fact, it's intentionally
crippled to only forwarding TCP traffic. For example, you cannot login
to a shell session on the jump host and run commands.

*jayoh* is written in pure Go with the help of `x/crypto/ssh` package
which is well maintained by authors of Go and used extensively in
various production projects.

# Build

Build the app using standard Go toolchain:

```sh
git clone https://github.com/oxplot/jayoh.git
cd jayoh
go build
```

Above will create the single file binary `jayoh` in the root.

# Build AMI image

Packer is used to build AMIs in the regions defined in `ami/ami.json`:

```sh
./build sh
```

# Run

**Generate a new server key:**

```sh
ssh-keygen -t ed25519 -f server_key -N ''
```

**Create a simple Access Control List (ACL) file:**

```sh
cat <<EOF > acl.json

{
  "users": {
    "mike": {
      "passwords": [
        "$2y$04$7l9Q0nw9Kvcll9W8LP7yOeFkPXtTt.54LCs9GurIurHbCAQVVzKg6"
      ],
      "keys": [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKpJwH2AIGntbSJ5jGiVD4ub8Fb/BqhzCPwMGB/uibdb"
      ],
      "groups": ["dev"]
    }
  },
  "rules": {
    "all-local": {
      "host_patterns": ["127.0.0.0/8", "www.google.com"],
      "groups": ["dev"]
    }
  }
}

EOF
```

Few notes:

* This ACL defines a user `mike` that can authenticate with either a
  bcrypt hashed password, or a SSH key.
* `$2y$04$7l9Q0nw9Kvcl...` is a bcrypt hash of password `123456`.
* `ssh-ed25519 AAAAC3N...` is a SSH public key (usually found under
  `~/.ssh/id_rsa.pub`.
* The ACL defines a single rule called `all-local` (this is just a
  label) that allows all users belonging to group `dev` to access all
  IPs under the `127.0.0.0/8` subnet and the exact host name
  `www.google.com`.
* There is currently no way to specify wildcard domain names, only IP
  ranges.

**Create the main configuration file:**

```sh
cat <<EOF > config.json

{
  "acl_file": "acl.json",
  "server_key_file": "server_key",
  "listen": "127.0.0.1:2222"
}

EOF
```

**Run the *jayoh* server:**

```sh
./jayoh -config config.json
```

# Connect

*jayoh* does not support shell login. This is by design. Hence you need
to specify a second host to connect to.

## Port forwarding

Following from the examples so far, let's say you have a webserver
running on port 8080 on the same machine where *jayoh* is running.
Following will setup a tunnel to access the webserver:

```sh
ssh -N -L 8181:127.0.0.1:8080 jayoh-host
```

`-N` prevents SSH from opening a shell session in addition to the TCP
port forward.

## Tunnel for SSH

You can also use *jayoh* to tunnel another SSH connection:

```sh
ssh -N target-server -o 'ProxyCommand ssh jayoh-host -W target-server:22'
```
