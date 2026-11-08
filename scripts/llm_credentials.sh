#!/usr/bin/env bash
# Short-lived model credentials for pi in GitHub Actions, through workload identity federation
# instead of stored API keys. The job needs `permissions: id-token: write`.
#
#   llm_credentials.sh start <anthropic|openai>    fetch once, then refresh every minute until
#                                                   the job ends
#   llm_credentials.sh refresh <anthropic|openai>  fetch once
#
# GitHub's OIDC tokens last about five minutes, and each provider's credential expires no later
# than the token it was exchanged for, so a run longer than that needs the background refresh.
#
# anthropic: writes a fresh GitHub token to $ANTHROPIC_IDENTITY_TOKEN_FILE. The Anthropic SDK in
#   pi exchanges it using ANTHROPIC_FEDERATION_RULE_ID, ANTHROPIC_ORGANIZATION_ID and
#   ANTHROPIC_SERVICE_ACCOUNT_ID, and rereads the file before each refresh. Each token can be
#   exchanged only once.
# openai: exchanges a GitHub token for an OpenAI access token using OPENAI_IDENTITY_PROVIDER_ID,
#   OPENAI_SERVICE_ACCOUNT_ID and OPENAI_WIF_AUDIENCE, and writes it to pi's auth.json, which pi
#   rereads when the file changes.
set -euo pipefail
umask 077

# The functions below return on failure explicitly: `set -e` does not apply inside a function
# called from `refresh || ...`, and a failed fetch must never overwrite a working credential.

github_token() {
  local audience
  audience=$(jq -rn --arg a "$1" '$a | @uri') || return 1
  curl -fsS --retry 3 -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
    "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$audience" | jq -re .value
}

# write <path> <content>: replace the file in one step so a reader never sees a partial write.
write() {
  printf '%s' "$2" > "$1.tmp" && mv "$1.tmp" "$1"
}

refresh_anthropic() {
  local token
  token=$(github_token https://api.anthropic.com) || return 1
  write "${ANTHROPIC_IDENTITY_TOKEN_FILE:?}" "$token"
}

refresh_openai() {
  local token access dir
  token=$(github_token "${OPENAI_WIF_AUDIENCE:?}") || return 1
  access=$(jq -n --arg token "$token" --arg provider "${OPENAI_IDENTITY_PROVIDER_ID:?}" \
      --arg account "${OPENAI_SERVICE_ACCOUNT_ID:?}" \
      '{grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token_type: "urn:ietf:params:oauth:token-type:jwt", subject_token: $token,
        identity_provider_id: $provider, service_account_id: $account}' |
    curl -fsS --retry 3 https://auth.openai.com/oauth/token -H 'Content-Type: application/json' -d @- |
    jq -re .access_token) || return 1
  dir=${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}
  mkdir -p "$dir" || return 1
  write "$dir/auth.json" "$(jq -n --arg key "$access" '{openai: {type: "api_key", key: $key}}')"
}

refresh() {
  case "$1" in
    anthropic | openai) "refresh_$1" ;;
    *) echo "no federated credentials for provider '$1'" >&2; return 1 ;;
  esac
}

usage="usage: llm_credentials.sh start|refresh <anthropic|openai>"
case "${1:-}" in
  start)
    refresh "${2:?$usage}"
    nohup bash "${BASH_SOURCE[0]}" loop "$2" </dev/null >>"${RUNNER_TEMP:-/tmp}/llm-credentials.log" 2>&1 &
    ;;
  refresh) refresh "${2:?$usage}" ;;
  loop)
    while sleep 60; do
      refresh "$2" || echo "$(date -u +%FT%TZ) $2 credential refresh failed"
    done
    ;;
  *) echo "$usage" >&2; exit 1 ;;
esac
