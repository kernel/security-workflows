#!/usr/bin/env bash
# Short-lived model credentials for pi in GitHub Actions, through workload identity federation
# instead of stored API keys. The job needs `permissions: id-token: write`.
#
#   llm_credentials.sh start <provider>...    fetch once, then refresh in the background
#   llm_credentials.sh refresh <provider>...  fetch once
#   llm_credentials.sh stop                   stop refreshing, delete the credentials and print
#                                              the refresh log
#
# Providers are anthropic, openai and openrouter.
#
# GitHub's OIDC tokens last about five minutes, and each provider's credential expires no later
# than the token it was exchanged for, so a run longer than that needs the background refresh.
# It runs every $LLM_CREDENTIALS_INTERVAL seconds (default 30) until `stop` or the end of the job.
#
# anthropic: writes a fresh GitHub token to $ANTHROPIC_IDENTITY_TOKEN_FILE. The Anthropic SDK in
#   pi exchanges it using ANTHROPIC_FEDERATION_RULE_ID, ANTHROPIC_ORGANIZATION_ID and
#   ANTHROPIC_SERVICE_ACCOUNT_ID, and rereads the file before each refresh. Each token can be
#   exchanged only once, and the SDK retries a failed refresh by rereading the file, so the file
#   rotates well inside the 90 seconds between the SDK's first refresh attempt and its deadline.
# openai: exchanges a GitHub token for an OpenAI access token using OPENAI_IDENTITY_PROVIDER_ID,
#   OPENAI_SERVICE_ACCOUNT_ID and OPENAI_WIF_AUDIENCE, and sets it as the openai entry of pi's
#   auth.json, which pi rereads when the file changes. Other entries are kept.
# openrouter: exchanges a GitHub token with audience $OPENROUTER_WIF_AUDIENCE (default
#   https://openrouter.ai) for an OpenRouter access token using OPENROUTER_FEDERATION_POLICY_ID.
#   It writes the token to $OPENROUTER_ACCESS_TOKEN_FILE for callers that read it per request, and
#   sets it as the openrouter entry of pi's auth.json.
set -euo pipefail
umask 077

state=${RUNNER_TEMP:-/tmp}
pidfile=$state/llm-credentials.pid
log=$state/llm-credentials.log
auth=${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}/auth.json

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
  local token access current
  token=$(github_token "${OPENAI_WIF_AUDIENCE:?}") || return 1
  access=$(jq -n --arg token "$token" --arg provider "${OPENAI_IDENTITY_PROVIDER_ID:?}" \
      --arg account "${OPENAI_SERVICE_ACCOUNT_ID:?}" \
      '{grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token_type: "urn:ietf:params:oauth:token-type:jwt", subject_token: $token,
        identity_provider_id: $provider, service_account_id: $account}' |
    curl -fsS --retry 3 https://auth.openai.com/oauth/token -H 'Content-Type: application/json' -d @- |
    jq -re .access_token) || return 1
  mkdir -p "$(dirname "$auth")" || return 1
  current='{}'
  if [ -s "$auth" ]; then
    current=$(cat "$auth") || return 1
  fi
  # A file that isn't valid JSON is an error rather than something to overwrite.
  current=$(jq -e --arg key "$access" '.openai = {type: "api_key", key: $key}' <<<"$current") || return 1
  write "$auth" "$current"
}

refresh_openrouter() {
  local token body access current
  token=$(github_token "${OPENROUTER_WIF_AUDIENCE:-https://openrouter.ai}") || return 1
  body=$(jq -rn --arg token "$token" --arg policy "${OPENROUTER_FEDERATION_POLICY_ID:?}" \
      '{grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
        federation_policy_id: $policy, subject_token: $token}
       | to_entries | map("\(.key)=\(.value | @uri)") | join("&")') || return 1
  access=$(printf '%s' "$body" |
    curl -fsS --retry 3 https://openrouter.ai/api/v1/oauth/token \
      -H 'Content-Type: application/x-www-form-urlencoded' -d @- |
    jq -re .access_token) || return 1
  mkdir -p "$(dirname "$auth")" || return 1
  current='{}'
  if [ -s "$auth" ]; then
    current=$(cat "$auth") || return 1
  fi
  current=$(jq -e --arg key "$access" '.openrouter = {type: "api_key", key: $key}' <<<"$current") || return 1
  write "${OPENROUTER_ACCESS_TOKEN_FILE:?}" "$access" || return 1
  write "$auth" "$current"
}

# refresh <provider>...: every provider is attempted, and the call fails if any of them did.
refresh() {
  local provider status=0
  for provider in "$@"; do
    case "$provider" in
      anthropic | openai | openrouter) "refresh_$provider" || { echo "$(date -u +%FT%TZ) $provider credential refresh failed"; status=1; } ;;
      *) echo "no federated credentials for provider '$provider'" >&2; status=1 ;;
    esac
  done
  return "$status"
}

stop_loop() {
  local group _
  if [ -f "$pidfile" ]; then
    # The loop leads its own process group, so this also stops a refresh in flight before the
    # credentials are deleted below.
    group=$(cat "$pidfile")
    kill -TERM -- "-$group" 2>/dev/null || true
    for _ in $(seq 50); do
      kill -0 -- "-$group" 2>/dev/null || break
      sleep 0.1
    done
    kill -KILL -- "-$group" 2>/dev/null || true
    rm -f "$pidfile"
  fi
}

stop() {
  local status=0 updated
  stop_loop
  if [ -n "${ANTHROPIC_IDENTITY_TOKEN_FILE:-}" ]; then
    rm -f "$ANTHROPIC_IDENTITY_TOKEN_FILE" "$ANTHROPIC_IDENTITY_TOKEN_FILE.tmp"
  fi
  if [ -n "${OPENROUTER_ACCESS_TOKEN_FILE:-}" ]; then
    rm -f "$OPENROUTER_ACCESS_TOKEN_FILE" "$OPENROUTER_ACCESS_TOKEN_FILE.tmp"
  fi
  rm -f "$auth.tmp"
  if [ -s "$auth" ]; then
    if updated=$(jq -e 'del(.openai, .openrouter)' "$auth"); then
      write "$auth" "$updated"
    else
      echo "$auth is not valid JSON; left it as is" >&2
      status=1
    fi
  fi
  if [ -s "$log" ]; then
    echo "Credential refresh log:"
    cat "$log"
  fi
  return "$status"
}

usage="usage: llm_credentials.sh start|refresh <anthropic|openai|openrouter>... | stop"
case "${1:-}" in
  start)
    # A second start replaces the first loop rather than orphaning it.
    stop_loop
    shift
    [ "$#" -gt 0 ] || { echo "$usage" >&2; exit 1; }
    refresh "$@"
    setsid bash "${BASH_SOURCE[0]}" loop "$@" </dev/null >>"$log" 2>&1 &
    for _ in $(seq 50); do
      [ -s "$pidfile" ] && exit 0
      sleep 0.1
    done
    echo "credential refresh loop did not start" >&2
    exit 1
    ;;
  refresh)
    shift
    [ "$#" -gt 0 ] || { echo "$usage" >&2; exit 1; }
    refresh "$@"
    ;;
  stop) stop ;;
  loop)
    echo "$$" > "$pidfile"
    shift
    while sleep "${LLM_CREDENTIALS_INTERVAL:-30}"; do
      refresh "$@" || true
    done
    ;;
  *) echo "$usage" >&2; exit 1 ;;
esac
