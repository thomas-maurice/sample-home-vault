variable "vault_root_token" {
  description = "Vault root token"
  default = "devtoken"
}

variable "vault_address" {
  description = "Vault address"
  default = "http://127.0.0.1:8200"
}

variable "pki_domain" {
  description = "Vault domain for the pki"
  default = "example.com"
}