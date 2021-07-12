resource "vault_policy" "read_only" {
  for_each = toset(local.envs)

  name = "${each.value}-read-only"

  policy = <<EOT
path "${each.value}/*" {
  capabilities = ["read"]
}
EOT
}

resource "vault_policy" "vault_admin" {
  name = "vault-admin"

  policy = <<EOT
path "*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOT
}

resource "vault_policy" "admin" {
  for_each = toset(local.envs)

  name = "${each.value}-admin"

  policy = <<EOT
path "${each.value}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOT
}

resource "vault_policy" "ssh_sign_user" {
  for_each = toset(local.envs)

  name = "${each.value}-ssh-sign-user"

  policy = <<EOT
path "${each.value}/ssh/sign/user" {
  capabilities = ["create", "read", "update", "list"]
}

path "${each.value}/ssh/config/ca" {
  capabilities = ["read"]
}
EOT
}

resource "vault_policy" "ssh_sign_host" {
  for_each = toset(local.envs)

  name = "${each.value}-ssh-sign-host"

  policy = <<EOT
path "${each.value}/ssh/sign/host" {
  capabilities = ["create", "read", "update", "list"]
}

path "${each.value}/ssh/config/ca" {
  capabilities = ["read"]
}
EOT
}

resource "vault_policy" "kv_readonly" {
  for_each = toset(local.envs)

  name = "${each.value}-kv-read-only"

  policy = <<EOT
path "${each.value}/kv/*" {
  capabilities = ["read"]
}
EOT
}

resource "vault_policy" "kv_read_write" {
  for_each = toset(local.envs)

  name = "${each.value}-kv-read-write"

  policy = <<EOT
path "${each.value}/kv/*" {
  capabilities = ["create", "read", "update", "list"]
}
EOT
}

resource "vault_policy" "kv_admin" {
  for_each = toset(local.envs)

  name = "${each.value}-kv-admin"

  policy = <<EOT
path "${each.value}/kv/*" {
  capabilities = ["create", "read", "update", "list", "delete"]
}
EOT
}

resource "vault_policy" "pki_client_sign" {
  for_each = toset(local.envs)

  name = "${each.value}-pki-client-sign"

  policy = <<EOT
path "${each.value}/pki/pki_intermediate/issue/client" {
  capabilities = ["create", "read", "update", "list"]
}
EOT
}

resource "vault_policy" "pki_svc_sign" {
  for_each = toset(local.envs)

  name = "${each.value}-pki-svc-sign"

  policy = <<EOT
path "${each.value}/pki/pki_intermediate/issue/service" {
  capabilities = ["create", "read", "update", "list"]
}
EOT
}

resource "vault_policy" "pki_server_sign" {
  for_each = toset(local.envs)

  name = "${each.value}-pki-server-sign"

  policy = <<EOT
path "${each.value}/pki/pki_intermediate/issue/server" {
  capabilities = ["create", "read", "update", "list"]
}
EOT
}

resource "vault_policy" "ci_creds" {
  name = "ci"

  policy = <<EOT
path "ci/kv/data/ci/*" {
  capabilities = ["read", "list"]
}
path "ci/kv/data/certificates/*" {
  capabilities = ["create", "update", "list"]
}
path "prod/ssh/sign/ci" {
  capabilities = ["create", "read", "update", "list"]
}
path "prod/ssh/config/ca" {
  capabilities = ["read"]
}
path "identity/oidc/token/ci" {
  capabilities = ["read"]
}
EOT
}

resource "vault_policy" "svc_read_oidc_token" {
  name = "svc-oidc-token"

  policy = <<EOT
path "identity/oidc/token/service" {
  capabilities = ["read"]
}
EOT
}

resource "vault_policy" "human_read_oidc_token" {
  name = "human-oidc-token"

  policy = <<EOT
path "identity/oidc/token/human" {
  capabilities = ["read"]
}
EOT
}

resource "vault_policy" "certs" {
  name = "certs"

  policy = <<EOT
path "prod/kv/data/certificates/*" {
  capabilities = ["create", "read", "update", "list"]
}

path "dev/kv/data/certificates/*" {
  capabilities = ["create", "read", "update", "list"]
}

path "stag/kv/data/certificates/*" {
  capabilities = ["create", "read", "update", "list"]
}
EOT
}