resource "vault_mount" "pki_root" {
  for_each                  = toset(local.envs)
  path                      = "${each.value}/pki/pki_root"
  type                      = "pki"
  default_lease_ttl_seconds = local.ten_years
  max_lease_ttl_seconds     = local.ten_years
}

resource "vault_mount" "pki_intermediate" {
  for_each                  = toset(local.envs)
  path                      = "${each.value}/pki/pki_intermediate"
  type                      = "pki"
  default_lease_ttl_seconds = local.ten_years
  max_lease_ttl_seconds     = local.ten_years
}

resource "vault_pki_secret_backend_config_urls" "config_urls" {
  for_each             = toset(local.envs)
  backend              = vault_mount.pki_root[each.key].path
  issuing_certificates = ["${var.vault_address}/v1/${each.value}/pki/pki_root/ca/pem"]
}

resource "vault_pki_secret_backend_config_urls" "config_urls_int" {
  for_each             = toset(local.envs)
  backend              = vault_mount.pki_intermediate[each.key].path
  issuing_certificates = ["${var.vault_address}/v1/${each.value}/pki/pki_intermediate/ca/pem"]
}

resource "vault_pki_secret_backend_root_cert" "root_certificate" {
  for_each = toset(local.envs)
  backend  = vault_mount.pki_root[each.key].path

  type         = "internal"
  common_name  = "${var.pki_domain} root CA (${each.value})"
  ttl          = local.ten_years
  format       = "pem"
  key_type     = "ec"
  key_bits     = 521
  organization = "${each.value}-${var.pki_domain}"
}

resource "vault_pki_secret_backend_intermediate_cert_request" "intermediate" {
  for_each = toset(local.envs)
  backend  = vault_mount.pki_intermediate[each.key].path

  type         = "internal"
  common_name  = "${var.pki_domain} intermediate CA (${each.value})"
  organization = "${each.value}-${var.pki_domain}"
  key_type     = "ec"
  key_bits     = 521
}

resource "vault_pki_secret_backend_root_sign_intermediate" "intermediate" {
  for_each = toset(local.envs)
  backend  = vault_mount.pki_root[each.key].path

  ttl                  = local.ten_years
  csr                  = vault_pki_secret_backend_intermediate_cert_request.intermediate[each.key].csr
  common_name          = "${var.pki_domain} intermediate CA (${each.value})"
  exclude_cn_from_sans = true
  organization         = "${each.value}-${var.pki_domain}"
  format               = "pem"
}

resource "vault_pki_secret_backend_intermediate_set_signed" "intermediate" {
  for_each    = toset(local.envs)
  backend     = vault_mount.pki_intermediate[each.key].path
  certificate = vault_pki_secret_backend_root_sign_intermediate.intermediate[each.key].certificate
}

resource "vault_pki_secret_backend_role" "server_certs" {
  for_each = toset(local.envs)
  backend  = vault_mount.pki_intermediate[each.key].path
  name     = "server"
  ttl      = local.one_month
  max_ttl  = local.one_month

  allowed_domains = [
    var.pki_domain,
  ]

  key_usage = [
    "DigitalSignature",
    "KeyAgreement",
    "KeyEncipherment",
  ]

  allow_subdomains   = true
  allow_glob_domains = true
  allow_any_name     = true
  server_flag        = true
  client_flag        = false
  key_type           = "ec"
  key_bits           = 224
}

resource "vault_pki_secret_backend_role" "client_certs" {
  for_each = toset(local.envs)
  backend  = vault_mount.pki_intermediate[each.key].path
  name     = "client"
  ttl      = 36000
  max_ttl  = 36000

  allow_any_name = true

  key_usage = [
    "DigitalSignature",
    "KeyAgreement",
    "KeyEncipherment",
  ]

  server_flag = false
  client_flag = true
  key_type    = "ec"
  key_bits    = 224
}

resource "vault_pki_secret_backend_role" "service_certs" {
  for_each = toset(local.envs)
  backend  = vault_mount.pki_intermediate[each.key].path
  name     = "service"
  ttl      = 360000
  max_ttl  = 360000

  allow_any_name = true
  ou             = ["service"]

  key_usage = [
    "DigitalSignature",
    "KeyAgreement",
    "KeyEncipherment",
  ]

  server_flag = false
  client_flag = true
  key_type    = "ec"
  key_bits    = 224
}
