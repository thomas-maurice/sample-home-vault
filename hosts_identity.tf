resource "vault_policy" "host_read_oidc_token" {
  name = "host-oidc-token"

  policy = <<EOT
path "identity/oidc/token/host" {
  capabilities = ["read"]
}
EOT
}

resource "vault_policy" "host_read_kv" {
  name = "host-read-kv"

  policy = <<EOT
path "hosts/kv/data/hosts/+/wireguard-pubkey" {
  capabilities = ["read"]
}
path "hosts/kv/data/common/*" {
  capabilities = ["read"]
}
EOT
}

resource "vault_policy" "host_read_prod_certificates" {
  name = "host-read-prod-certificates"

  policy = <<EOT
path "prod/kv/data/certificates/+" {
  capabilities = ["read"]
}
EOT
}

resource "vault_policy" "host_sign_tls_cert" {
  name = "host-sign-tls-certificate"

  policy = <<EOT
path "prod/pki/pki_intermediate/issue/server" {
  capabilities = ["update"]
}
path "stag/pki/pki_intermediate/issue/server" {
  capabilities = ["update"]
}
path "dev/pki/pki_intermediate/issue/server" {
  capabilities = ["update"]
}
EOT
}

resource "vault_policy" "host_sign_ssh_cert" {
  name = "host-sign-ssh-certificate"

  policy = <<EOT
path "prod/ssh/sign/host" {
  capabilities = ["update"]
}
path "stag/ssh/sign/host" {
  capabilities = ["update"]
}
path "dev/ssh/sign/host" {
  capabilities = ["update"]
}
EOT
}

resource "vault_policy" "host_read_certs" {
  name = "host-read-certs"

  policy = <<EOT
path "prod/kv/data/certificates/*" {
  capabilities = ["read"]
}
EOT
}