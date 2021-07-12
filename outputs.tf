resource "local_file" "pki_ca_chain_file" {
  for_each = toset(local.envs)

  sensitive_content    = "${vault_pki_secret_backend_root_sign_intermediate.intermediate[each.key].certificate}\n${vault_pki_secret_backend_root_cert.root_certificate[each.key].certificate}"
  filename             = "${path.cwd}/output/certs/CA_chain-${each.value}.crt"
  file_permission      = "0600"
  directory_permission = "0700"
}

resource "local_file" "pki_ca_file" {
  for_each = toset(local.envs)

  sensitive_content    = vault_pki_secret_backend_root_cert.root_certificate[each.key].certificate
  filename             = "${path.cwd}/output/certs/CA-${each.value}.crt"
  file_permission      = "0600"
  directory_permission = "0700"
}

resource "local_file" "pki_int_file" {
  for_each = toset(local.envs)

  sensitive_content    = vault_pki_secret_backend_root_sign_intermediate.intermediate[each.key].certificate
  filename             = "${path.cwd}/output/certs/CA_Int-${each.value}.crt"
  file_permission      = "0600"
  directory_permission = "0700"
}

resource "local_file" "ssh_ca_pubkey_file" {
  for_each = toset(local.envs)

  sensitive_content    = vault_ssh_secret_backend_ca.ssh_ca[each.key].public_key
  filename             = "${path.cwd}/output/certs/CA_ssh-${each.value}.pub"
  file_permission      = "0600"
  directory_permission = "0700"
}

output "hosts_mount_accessor" {
  value = vault_auth_backend.hosts_approle.accessor
}