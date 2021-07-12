resource "vault_identity_entity" "snapshot_agent" {
  name     = "snapshot_agent"
  policies = ["snapshot-agent"]
}

resource "vault_approle_auth_backend_role" "snapshot_agent" {
  backend   = vault_auth_backend.approle["prod"].path
  role_name = "snapshot_agent"
}

resource "vault_approle_auth_backend_role_secret_id" "snapshot_agent" {
  backend   = vault_auth_backend.approle["prod"].path
  role_name = vault_approle_auth_backend_role.snapshot_agent.role_name
}

resource "vault_identity_entity_alias" "snapshot_agent_alias" {
  name           = vault_approle_auth_backend_role.snapshot_agent.role_id
  mount_accessor = vault_auth_backend.approle["prod"].accessor
  canonical_id   = vault_identity_entity.snapshot_agent.id
}

resource "vault_generic_secret" "snapshot_agent_credentials" {
  path = "${vault_mount.adm_creds.path}/prod/approle/${vault_approle_auth_backend_role.snapshot_agent.role_name}"

  data_json = <<EOT
{
  "role_id"  : "${vault_approle_auth_backend_role.snapshot_agent.role_id}",
  "secret_id": "${vault_approle_auth_backend_role_secret_id.snapshot_agent.secret_id}",
  "backend"  : "${vault_auth_backend.approle["prod"].path}"
}
EOT
}

resource "vault_policy" "snapshot_agent" {
  name = "snapshot-agent"

  policy = <<EOT
path "/sys/storage/raft/snapshot"
{
  capabilities = ["read"]
}
EOT
}