#!/bin/bash

eval "$(load-vault-credentials.sh)"

function _vault_login() {
    local tkn
    tkn=$(vault write -format=json "${VAULT_APPROLE_PATH}"/login role_id="${VAULT_APPROLE_ROLE_ID}" secret_id="${VAULT_APPROLE_SECRET_ID}" | jq -r .auth.client_token)

    # shellcheck disable=SC2181
    if [ $? -ne 0 ]; then
        echo $?
        echo "could not log into vault"
        return 1
    fi;
    if [ -z "${tkn}" ]; then
        echo "could not log into vault"
        return 1
    fi;
    export VAULT_TOKEN=${tkn}
    echo "successfully logged into vault"
}

_vault_login