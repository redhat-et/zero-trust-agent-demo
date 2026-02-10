# Commands

Get the admin token

```shell
export ADMIN_TOKEN=$(curl -sX POST -d 'client_id=admin-cli' -d 'username=admin' -d 'password=SECRET_ADMIN_PASSWORD' -d 'grant_type=password' https://KEYCLOAK_URL/realms/master/protocol/openid-connect/token | jq -r '.access_token')
```

Note: `ADMIN_TOKEN` is usually created with just one minute TTL so don't be surprised if you have to renew it all the time.

You can use a helper function:

```shell
get_admin_token() {
  curl -s -X POST "https://keycloak.example.com/realms/master/protocol/openid-connect/token" \
    -d "grant_type=client_credentials" \
    -d "client_id=admin-cli" \
    -d "client_secret=$ADMIN_SECRET" | jq -r '.access_token'
}
```

Or, if you use admin password

```shell
get_admin_token() {
  curl -s -X POST "https://keycloak.example.com/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" \
    -d "username=admin" \
    -d "password=$ADMIN_PASSWORD" | jq -r '.access_token'
}
```

Then, you can use it inline `curl -s "...endpoint..." -H "Authorization: Bearer $(get_admin_token)"`


Create the `agent-service` client:

```shell
curl -X POST "https://keycloak.example.com/admin/realms/spiffe-demo/clients" \
  -H "Authorization: Bearer $(get_admin_token)" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "agent-service",
    "enabled": true,
    "clientAuthenticatorType": "client-secret",
    "serviceAccountsEnabled": true,
    "standardFlowEnabled": false,
    "directAccessGrantsEnabled": true,
    "publicClient": false
  }'
```

Create the `document-service` client:

```shell
curl -X POST "https://keycloak.example.com/admin/realms/spiffe-demo/clients" \
  -H "Authorization: Bearer $(get_admin_token)" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "document-service",
    "enabled": true,
    "clientAuthenticatorType": "client-secret",
    "serviceAccountsEnabled": true,
    "standardFlowEnabled": false,
    "publicClient": false
  }'
```

Get list of clients

```shell
curl -s "https://keycloak.example.com/admin/realms/spiffe-demo/clients" \
    -H "Authorization: Bearer $(get_admin_token)"  | jq '.[].clientId'
```

Get client UUID:

```shell
CLIENT_UUID=$(curl -s "https://keycloak.example.com/admin/realms/spiffe-demo/clients?clientId=agent-service" \
    -H "Authorization: Bearer $(get_admin_token)" | jq -r '.[0].id')
```

Get client secret:

```shell
curl -s "https://keycloak.example.com/admin/realms/spiffe-demo/clients/$CLIENT_UUID/client-secret" \
    -H "Authorization: Bearer $(get_admin_token)" | jq -r '.value'
```

Now the fun part - let's get a token and exchange it.

  Step 3: Get an initial token from agent-service:

  AGENT_SECRET="<your-agent-service-secret>"

  AGENT_TOKEN=$(curl -s -X POST "https://keycloak.example.com/realms/spiffe-demo/protocol/openid-connect/token" \
    -d "grant_type=client_credentials" \
    -d "client_id=agent-service" \
    -d "client_secret=$AGENT_SECRET" | jq -r '.access_token')

  echo $AGENT_TOKEN

  Step 4: Try the token exchange (this might fail - that's the learning!):

  curl -s -X POST "https://keycloak.example.com/realms/spiffe-demo/protocol/openid-connect/token" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    -d "client_id=agent-service" \
    -d "client_secret=$AGENT_SECRET" \
    -d "subject_token=$AGENT_TOKEN" \
    -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "audience=document-service" | jq

