
resource "vault_approle_auth_backend_role" "ci_service" {
  backend   = vault_auth_backend.approle["prod"].path
  role_name = "ci"
}

resource "vault_approle_auth_backend_role_secret_id" "ci_service" {
  backend   = vault_auth_backend.approle["prod"].path
  role_name = vault_approle_auth_backend_role.ci_service.role_name
}

resource "vault_identity_entity_alias" "ci_service_service_alias" {
  name           = vault_approle_auth_backend_role.ci_service.role_id
  mount_accessor = vault_auth_backend.approle["prod"].accessor
  canonical_id   = vault_identity_entity.ci_service.id
}

resource "vault_generic_secret" "ci_service_credentials" {
  path = "${vault_mount.adm_creds.path}/prod/approle/${vault_approle_auth_backend_role.ci_service.role_name}"

  data_json = <<EOT
{
  "role_id"  : "${vault_approle_auth_backend_role.ci_service.role_id}",
  "secret_id": "${vault_approle_auth_backend_role_secret_id.ci_service.secret_id}",
  "backend"  : "${vault_auth_backend.approle["prod"].path}"
}
EOT
}
