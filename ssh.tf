resource "vault_mount" "ssh" {
  for_each = toset(local.envs)

  path = "${each.value}/ssh"
  type = "ssh"
}

resource "vault_ssh_secret_backend_ca" "ssh_ca" {
  for_each             = toset(local.envs)
  backend              = vault_mount.ssh[each.key].path
  generate_signing_key = true
}

resource "vault_ssh_secret_backend_role" "ssh_sign_user" {
  for_each = toset(local.envs)

  name                    = "user"
  backend                 = vault_mount.ssh[each.key].path
  key_type                = "ca"
  allow_user_certificates = true
  allow_host_certificates = false
  allowed_users           = "*"
  max_ttl                 = local.one_day
  ttl                     = local.one_day
  default_extensions = {
    "permit-pty"              = "",
    "permit-agent-forwarding" = "",
    "permit-port-forwarding"  = ""
  }
  algorithm_signer = "rsa-sha2-512"
}

resource "vault_ssh_secret_backend_role" "ssh_sign_host" {
  for_each = toset(local.envs)

  name                    = "host"
  backend                 = vault_mount.ssh[each.key].path
  key_type                = "ca"
  allow_user_certificates = false
  allow_host_certificates = true
  max_ttl                 = local.one_year
  ttl                     = local.one_year
  algorithm_signer        = "rsa-sha2-512"
}

resource "vault_ssh_secret_backend_role" "ssh_sign_ci" {
  for_each = toset(local.envs)

  name                    = "ci"
  backend                 = vault_mount.ssh[each.key].path
  key_type                = "ca"
  allow_user_certificates = true
  allow_host_certificates = false
  allowed_users           = "ci"
  max_ttl                 = local.one_day
  ttl                     = local.one_day
  default_extensions = {
    "permit-pty"              = "",
    "permit-agent-forwarding" = "",
    "permit-port-forwarding"  = ""
  }
  algorithm_signer = "rsa-sha2-512"
}
