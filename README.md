# Sample home vault

This is an example that mirrors the Vault setup I use at home. It is managed by Terraform
and is used for the following things:

* Store secrets (duh)
  * Mainly bootstrap SSH keys/certs for my hosts
  * Certificates generated by Letsencrypt
* Maintain my own PKI
* Maintain my own SSH CA

Note that I use Dex as an identity backend for human users.

## Key-value backends
There are a few KV backends exposed

* `<env>/kv`: general key valoue mount per env
* `adm-creds/kv`: Stores the approle roleid and secretif for the created approles
* `hosts/kv`: This one is created but not managed further by terraform, it is used
  by the [vault creds](https://github.com/thomas-maurice/sample-home-vault/blob/master/scripts/vault_creds/main.go)
  to store the hosts ssh certs, wireguard keys and so on.
* `ci/kv`: Stores variables that are managed manually for CI jobs.

## Run it

Start the docker container
```
$ docker-compose up
```

Then run terraform (0.14 or something)

```
$ terraform plan
& terraform apply
```

Feel free to explore vault at [localhost](http://localhost:8200), token: `devtoken`

## Register hosts
You can register example hosts with the script in `scripts/vault_creds/main.go`

First modify the `hosts.yml` file to change the `hostMountAccessor` by the
output of the `terraform apply`, like

```
Apply complete! Resources: 0 added, 0 changed, 0 destroyed.

Outputs:

hosts_mount_accessor = "auth_approle_0651e1da"
```

Then run

```bash
$ export VAULT_ADDR=http://127.0.0.1:8200
$ export VAULT_TOKEN=devtoken
$ go run scripts/vault_creds/main.go
```