#!/bin/bash

if ! [ -f /etc/default/vault_creds ]; then
    echo "credentials file /etc/default/vault_creds does not exist"
    exit 1
fi;

while IFS="" read -r v || [ -n "$v" ]; do
    echo export "${v?}";
done < /etc/default/vault_creds