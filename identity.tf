resource "vault_identity_oidc" "server" {
  issuer = var.vault_address
}

resource "vault_identity_oidc_key" "key" {
  name             = "key"
  algorithm        = "ES256"
  rotation_period  = local.one_day
  verification_ttl = local.one_day
}

resource "vault_identity_oidc_role" "service" {
  name     = "service"
  key      = vault_identity_oidc_key.key.name
  template = <<EOF
{
  "groups": {{identity.entity.groups.names}},
  "nbf": {{time.now}}
}
EOF
}

resource "vault_identity_oidc_role" "host" {
  name     = "host"
  key      = vault_identity_oidc_key.key.name
  template = <<EOF
{
  "groups": {{identity.entity.groups.names}},
  "nbf": {{time.now}}
}
EOF
}

resource "vault_identity_oidc_key_allowed_client_id" "service" {
  key_name          = vault_identity_oidc_key.key.name
  allowed_client_id = vault_identity_oidc_role.service.client_id
}

resource "vault_identity_entity" "generic_service" {
  for_each = toset(local.envs)

  name     = "${each.value}-generic-service"
  policies = []
}

resource "vault_identity_group" "generic_service" {
  for_each = toset(local.envs)

  name = "${each.value}-generic-service"
  policies = [
    "${each.value}-pki-svc-sign",
    "${each.value}-pki-server-sign",
    "${each.value}-pki-client-sign",
  ]

  member_entity_ids = [
    vault_identity_entity.generic_service[each.key].id
  ]
}

resource "vault_identity_group" "oidc_generic_service" {
  for_each = toset(local.envs)

  name = "${each.value}-oidc-generic-service"
  policies = [
    vault_policy.svc_read_oidc_token.name,
  ]

  member_group_ids = [
    vault_identity_group.generic_service[each.key].id
  ]
}

resource "vault_identity_oidc_role" "human" {
  name     = "human"
  key      = vault_identity_oidc_key.key.name
  template = <<EOF
{
  "groups": {{identity.entity.groups.names}},
  "nbf": {{time.now}}
}
EOF
}

resource "vault_identity_oidc_key_allowed_client_id" "human" {
  key_name          = vault_identity_oidc_key.key.name
  allowed_client_id = vault_identity_oidc_role.human.client_id
}

# CI
resource "vault_identity_entity" "ci_service" {
  name     = "ci"
  policies = []
}

resource "vault_identity_group" "ci_service" {
  name = "ci"
  policies = [
    "ci",
  ]

  member_entity_ids = [
    vault_identity_entity.ci_service.id
  ]
}

resource "vault_identity_oidc_role" "ci" {
  name     = "ci"
  key      = vault_identity_oidc_key.key.name
  template = <<EOF
{
  "groups": {{identity.entity.groups.names}},
  "nbf": {{time.now}}
}
EOF
}

resource "vault_identity_group" "oidc_ci" {
  name = "oidc-ci"
  policies = [
    vault_policy.svc_read_oidc_token.name,
  ]

  member_group_ids = [
    vault_identity_group.ci_service.id
  ]
}

resource "vault_identity_oidc_key_allowed_client_id" "ci" {
  key_name          = vault_identity_oidc_key.key.name
  allowed_client_id = vault_identity_oidc_role.ci.client_id
}

resource "vault_identity_oidc_key_allowed_client_id" "host" {
  key_name          = vault_identity_oidc_key.key.name
  allowed_client_id = vault_identity_oidc_role.host.client_id
}
