resource "vault_auth_backend" "approle" {
  for_each = toset(local.envs)

  path = "${each.value}/app"
  type = "approle"
}

resource "vault_approle_auth_backend_role" "generic_service" {
  for_each = toset(local.envs)

  backend   = vault_auth_backend.approle[each.key].path
  role_name = "${each.value}-generic-service"
}

resource "vault_approle_auth_backend_role_secret_id" "generic_service" {
  for_each = toset(local.envs)

  backend   = vault_auth_backend.approle[each.key].path
  role_name = vault_approle_auth_backend_role.generic_service[each.key].role_name
}

resource "vault_identity_entity_alias" "generic_service_service_alias" {
  for_each = toset(local.envs)

  name           = vault_approle_auth_backend_role.generic_service[each.key].role_id
  mount_accessor = vault_auth_backend.approle[each.key].accessor
  canonical_id   = vault_identity_entity.generic_service[each.key].id
}

resource "vault_generic_secret" "generic_service_credentials" {
  for_each = toset(local.envs)

  path = "${vault_mount.adm_creds.path}/${each.value}/approle/${vault_approle_auth_backend_role.generic_service[each.key].role_name}"

  data_json = <<EOT
{
  "role_id"  : "${vault_approle_auth_backend_role.generic_service[each.key].role_id}",
  "secret_id": "${vault_approle_auth_backend_role_secret_id.generic_service[each.key].secret_id}",
  "backend"  : "${vault_auth_backend.approle[each.key].path}"
}
EOT
}
