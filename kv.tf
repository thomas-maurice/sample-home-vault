resource "vault_mount" "kv" {
  for_each = toset(local.envs)

  path = "${each.value}/kv"
  type = "kv"
  options = {
    version = 2
  }
}

resource "vault_mount" "adm_creds" {
  path = "adm-creds/kv"
  type = "kv"
  options = {
    version = 2
  }
}

resource "vault_mount" "hosts_kv" {
  path = "hosts/kv"
  type = "kv"
  options = {
    version = 2
  }
}

resource "vault_mount" "ci_kv" {
  path = "ci/kv"
  type = "kv"
  options = {
    version = 2
  }
}