resource "vault_auth_backend" "hosts_approle" {
  path = "hosts/app"
  type = "approle"
}