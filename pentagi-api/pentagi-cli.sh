#!/usr/bin/env bash
# PentAGI CLI Script — Created by Cyra for LEGENDX
# Usage: source pentagi-api/pentagi-cli.sh
# Then call any pentagi_* function

# ============================================================
# CONFIGURATION
# ============================================================
PENTAGI_BASE_URL="${PENTAGI_BASE_URL:-https://4.186.41.26:8443}"
PENTAGI_API="${PENTAGI_BASE_URL}/api/v1"
PENTAGI_SESSION="${PENTAGI_SESSION_FILE:-$HOME/.pentagi-session}"
PENTAGI_DEFAULT_PROVIDER="${PENTAGI_DEFAULT_PROVIDER:-MAIN}"

# VPS for direct DB access (pentagi_get_chats)
PENTAGI_VPS_IP="${PENTAGI_VPS_IP:-4.186.41.26}"
PENTAGI_VPS_USER="${PENTAGI_VPS_USER:-legendx}"
PENTAGI_VPS_PASS="${PENTAGI_VPS_PASS:-Legendx1234#}"
PENTAGI_DB_NAME="${PENTAGI_DB_NAME:-pentagidb}"
PENTAGI_DB_USER="${PENTAGI_DB_USER:-postgres}"
PENTAGI_DB_PASS="${PENTAGI_DB_PASS:-LegendXPG2026}"

# ============================================================
# HELPERS
# ============================================================
_pentagi_pretty() {
    if command -v jq &>/dev/null; then
        jq '.' 2>/dev/null || cat
    else
        cat
    fi
}

_pentagi_curl() {
    local method="$1"; shift
    local endpoint="$1"; shift
    curl -sk -X "$method" \
        -b "$PENTAGI_SESSION" \
        -c "$PENTAGI_SESSION" \
        -H "Content-Type: application/json" \
        "$@" \
        "${PENTAGI_API}${endpoint}"
}

_pentagi_get()    { _pentagi_curl GET    "$@" | _pentagi_pretty; }
_pentagi_post()   { _pentagi_curl POST   "$@" | _pentagi_pretty; }
_pentagi_put()    { _pentagi_curl PUT    "$@" | _pentagi_pretty; }
_pentagi_delete() { _pentagi_curl DELETE "$@" | _pentagi_pretty; }

_pentagi_vps_sql() {
    local sql="$1"
    sshpass -p "$PENTAGI_VPS_PASS" ssh -o StrictHostKeyChecking=no \
        "${PENTAGI_VPS_USER}@${PENTAGI_VPS_IP}" \
        "sudo docker exec -i pgvector psql -U $PENTAGI_DB_USER -d $PENTAGI_DB_NAME -c \"$sql\"" 2>/dev/null
}

# ============================================================
# AUTH
# ============================================================
pentagi_login() {
    local mail="${1:?Usage: pentagi_login <email> <password>}"
    local pass="${2:?Usage: pentagi_login <email> <password>}"
    echo "Logging in as $mail..."
    _pentagi_post "/auth/login" -d "{\"mail\":\"$mail\",\"password\":\"$pass\"}"
    echo "Session saved to $PENTAGI_SESSION"
}

pentagi_logout() {
    _pentagi_get "/auth/logout"
    rm -f "$PENTAGI_SESSION"
    echo "Logged out."
}

pentagi_whoami() {
    _pentagi_get "/user"
}

# ============================================================
# PROVIDERS
# ============================================================
pentagi_get_providers() {
    _pentagi_get "/providers"
}

# ============================================================
# FLOWS — CRUD
# ============================================================
pentagi_create_flow() {
    local input="${1:?Usage: pentagi_create_flow <description> [provider]}"
    local provider="${2:-$PENTAGI_DEFAULT_PROVIDER}"
    echo "Creating flow with provider: $provider"
    _pentagi_post "/flows/" -d "{\"input\":\"$input\",\"provider\":\"$provider\"}"
}

pentagi_get_flows() {
    _pentagi_get "/flows/"
}

# Alias
pentagi_status() {
    pentagi_get_flows
}

pentagi_get_flow() {
    local id="${1:?Usage: pentagi_get_flow <flowID>}"
    _pentagi_get "/flows/$id"
}

pentagi_delete_flow() {
    local id="${1:?Usage: pentagi_delete_flow <flowID>}"
    _pentagi_delete "/flows/$id"
}

pentagi_patch_flow() {
    local id="${1:?Usage: pentagi_patch_flow <flowID> <json_data>}"
    local data="${2:?Usage: pentagi_patch_flow <flowID> <json_data>}"
    _pentagi_put "/flows/$id" -d "$data"
}

# ============================================================
# FLOW CONTROL
# ============================================================
pentagi_stop_flow() {
    local id="${1:?Usage: pentagi_stop_flow <flowID>}"
    _pentagi_curl POST "/flows/$id/control/abort" | _pentagi_pretty
}

pentagi_pause_flow() {
    local id="${1:?Usage: pentagi_pause_flow <flowID>}"
    _pentagi_curl POST "/flows/$id/control/pause" | _pentagi_pretty
}

pentagi_resume_flow() {
    local id="${1:?Usage: pentagi_resume_flow <flowID>}"
    _pentagi_curl POST "/flows/$id/control/resume" | _pentagi_pretty
}

pentagi_steer_flow() {
    local id="${1:?Usage: pentagi_steer_flow <flowID> <message>}"
    local msg="${2:?Usage: pentagi_steer_flow <flowID> <message>}"
    _pentagi_curl POST "/flows/$id/control/steer" -d "{\"message\":\"$msg\"}" | _pentagi_pretty
}

pentagi_finish_flow() {
    # Finish = abort (there's no separate "finish" — abort stops the flow)
    pentagi_stop_flow "$@"
}

pentagi_get_control_state() {
    local id="${1:?Usage: pentagi_get_control_state <flowID>}"
    _pentagi_get "/flows/$id/control"
}

# ============================================================
# FLOW PROGRESS, FINDINGS, COST, TIMELINE, ATTACK PATHS
# ============================================================
pentagi_get_progress() {
    local id="${1:?Usage: pentagi_get_progress <flowID>}"
    _pentagi_get "/flows/$id/progress"
}

pentagi_get_findings() {
    local id="${1:?Usage: pentagi_get_findings <flowID>}"
    _pentagi_get "/flows/$id/findings"
}

pentagi_get_cost() {
    local id="${1:?Usage: pentagi_get_cost <flowID>}"
    _pentagi_get "/flows/$id/cost"
}

pentagi_get_timeline() {
    local id="${1:?Usage: pentagi_get_timeline <flowID>}"
    _pentagi_get "/flows/$id/timeline"
}

pentagi_get_attack_paths() {
    local id="${1:?Usage: pentagi_get_attack_paths <flowID>}"
    _pentagi_get "/flows/$id/attack-paths"
}

# ============================================================
# TASKS & SUBTASKS
# ============================================================
pentagi_get_tasks() {
    local id="${1:?Usage: pentagi_get_tasks <flowID>}"
    _pentagi_get "/flows/$id/tasks/"
}

pentagi_get_task() {
    local fid="${1:?Usage: pentagi_get_task <flowID> <taskID>}"
    local tid="${2:?Usage: pentagi_get_task <flowID> <taskID>}"
    _pentagi_get "/flows/$fid/tasks/$tid"
}

pentagi_get_subtasks() {
    local id="${1:?Usage: pentagi_get_subtasks <flowID>}"
    _pentagi_get "/flows/$id/subtasks/"
}

pentagi_get_task_subtasks() {
    local fid="${1:?Usage: pentagi_get_task_subtasks <flowID> <taskID>}"
    local tid="${2:?Usage: pentagi_get_task_subtasks <flowID> <taskID>}"
    _pentagi_get "/flows/$fid/tasks/$tid/subtasks/"
}

pentagi_get_task_subtask() {
    local fid="${1:?Usage: pentagi_get_task_subtask <flowID> <taskID> <subtaskID>}"
    local tid="${2:?Usage: pentagi_get_task_subtask <flowID> <taskID> <subtaskID>}"
    local sid="${3:?Usage: pentagi_get_task_subtask <flowID> <taskID> <subtaskID>}"
    _pentagi_get "/flows/$fid/tasks/$tid/subtasks/$sid"
}

pentagi_get_task_graph() {
    local fid="${1:?Usage: pentagi_get_task_graph <flowID> <taskID>}"
    local tid="${2:?Usage: pentagi_get_task_graph <flowID> <taskID>}"
    _pentagi_get "/flows/$fid/tasks/$tid/graph"
}

# ============================================================
# LOGS (all types)
# ============================================================
pentagi_get_logs() {
    local id="${1:?Usage: pentagi_get_logs <flowID> [limit]}"
    local limit="${2:-20}"
    _pentagi_get "/flows/$id/msglogs/?limit=$limit"
}

pentagi_get_agent_logs() {
    local id="${1:?Usage: pentagi_get_agent_logs <flowID>}"
    _pentagi_get "/flows/$id/agentlogs/"
}

pentagi_get_search_logs() {
    local id="${1:?Usage: pentagi_get_search_logs <flowID>}"
    _pentagi_get "/flows/$id/searchlogs/"
}

pentagi_get_term_logs() {
    local id="${1:?Usage: pentagi_get_term_logs <flowID>}"
    _pentagi_get "/flows/$id/termlogs/"
}

pentagi_get_vecstore_logs() {
    local id="${1:?Usage: pentagi_get_vecstore_logs <flowID>}"
    _pentagi_get "/flows/$id/vecstorelogs/"
}

pentagi_get_assistant_logs() {
    local id="${1:?Usage: pentagi_get_assistant_logs <flowID>}"
    _pentagi_get "/flows/$id/assistantlogs/"
}

# ============================================================
# CHAT MESSAGES (Direct DB query)
# ============================================================
pentagi_get_chats() {
    local id="${1:?Usage: pentagi_get_chats <flowID> [limit]}"
    local limit="${2:-50}"
    echo "Fetching last $limit messages for flow $id..."
    _pentagi_vps_sql "SELECT id, created_at, type, message, LEFT(result, 200) as result FROM msglogs WHERE flow_id = $id ORDER BY created_at DESC LIMIT $limit;"
}

pentagi_get_chats_full() {
    local id="${1:?Usage: pentagi_get_chats_full <flowID> [limit]}"
    local limit="${2:-50}"
    echo "Fetching last $limit full messages for flow $id..."
    _pentagi_vps_sql "SELECT * FROM msglogs WHERE flow_id = $id ORDER BY created_at DESC LIMIT $limit;"
}

# ============================================================
# GRAPH & REPORT
# ============================================================
pentagi_get_flow_graph() {
    local id="${1:?Usage: pentagi_get_flow_graph <flowID>}"
    _pentagi_get "/flows/$id/graph"
}

pentagi_get_report() {
    # Report is typically the flow graph + findings combined
    local id="${1:?Usage: pentagi_get_report <flowID>}"
    echo "=== FLOW DETAILS ==="
    pentagi_get_flow "$id"
    echo -e "\n=== PROGRESS ==="
    pentagi_get_progress "$id"
    echo -e "\n=== FINDINGS ==="
    pentagi_get_findings "$id"
    echo -e "\n=== TIMELINE ==="
    pentagi_get_timeline "$id"
}

# ============================================================
# ASSISTANTS
# ============================================================
pentagi_create_assistant() {
    local fid="${1:?Usage: pentagi_create_assistant <flowID> <message>}"
    local msg="${2:?Usage: pentagi_create_assistant <flowID> <message>}"
    _pentagi_post "/flows/$fid/assistants/" -d "{\"input\":\"$msg\"}"
}

pentagi_get_assistants() {
    local fid="${1:?Usage: pentagi_get_assistants <flowID>}"
    _pentagi_get "/flows/$fid/assistants/"
}

# ============================================================
# SCREENSHOTS
# ============================================================
pentagi_get_screenshots() {
    local id="${1:?Usage: pentagi_get_screenshots <flowID>}"
    _pentagi_get "/flows/$id/screenshots/"
}

# ============================================================
# CONTAINERS
# ============================================================
pentagi_get_containers() {
    _pentagi_get "/containers/"
}

pentagi_get_flow_containers() {
    local id="${1:?Usage: pentagi_get_flow_containers <flowID>}"
    _pentagi_get "/flows/$id/containers/"
}

# ============================================================
# USERS & SYSTEM
# ============================================================
pentagi_get_users() {
    _pentagi_get "/users/"
}

pentagi_create_user() {
    local mail="${1:?Usage: pentagi_create_user <email> <password> <name>}"
    local pass="${2:?Usage: pentagi_create_user <email> <password> <name>}"
    local name="${3:?Usage: pentagi_create_user <email> <password> <name>}"
    _pentagi_post "/users/" -d "{\"mail\":\"$mail\",\"password\":\"$pass\",\"name\":\"$name\"}"
}

pentagi_get_usage() {
    _pentagi_get "/usage/"
}

pentagi_get_flow_usage() {
    local id="${1:?Usage: pentagi_get_flow_usage <flowID>}"
    _pentagi_get "/flows/$id/usage/"
}

pentagi_get_info() {
    curl -sk "${PENTAGI_API}/info" | _pentagi_pretty
}

# ============================================================
# PROMPTS
# ============================================================
pentagi_get_prompts() {
    _pentagi_get "/prompts/"
}

pentagi_get_prompt() {
    local type="${1:?Usage: pentagi_get_prompt <promptType>}"
    _pentagi_get "/prompts/$type"
}

# ============================================================
# API TOKENS
# ============================================================
pentagi_create_token() {
    local name="${1:?Usage: pentagi_create_token <name>}"
    _pentagi_post "/tokens/" -d "{\"name\":\"$name\"}"
}

pentagi_list_tokens() {
    _pentagi_get "/tokens/"
}

# ============================================================
# HELP
# ============================================================
pentagi_help() {
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                   PentAGI CLI — by Cyra                      ║
╠══════════════════════════════════════════════════════════════╣
║  AUTH                                                        ║
║    pentagi_login <email> <password>                          ║
║    pentagi_logout                                            ║
║    pentagi_whoami                                            ║
║                                                              ║
║  FLOWS                                                       ║
║    pentagi_create_flow <desc> [provider]  (default: MAIN)    ║
║    pentagi_get_flows / pentagi_status                        ║
║    pentagi_get_flow <id>                                     ║
║    pentagi_delete_flow <id>                                  ║
║    pentagi_stop_flow <id>       (abort)                      ║
║    pentagi_pause_flow <id>                                   ║
║    pentagi_resume_flow <id>                                  ║
║    pentagi_steer_flow <id> <msg>                             ║
║    pentagi_finish_flow <id>     (alias for stop)             ║
║    pentagi_get_control_state <id>                            ║
║                                                              ║
║  PROGRESS & FINDINGS                                         ║
║    pentagi_get_progress <id>                                 ║
║    pentagi_get_findings <id>                                 ║
║    pentagi_get_cost <id>                                     ║
║    pentagi_get_timeline <id>                                 ║
║    pentagi_get_attack_paths <id>                             ║
║    pentagi_get_report <id>      (combined view)              ║
║                                                              ║
║  TASKS & SUBTASKS                                            ║
║    pentagi_get_tasks <flowID>                                ║
║    pentagi_get_task <flowID> <taskID>                        ║
║    pentagi_get_subtasks <flowID>                             ║
║    pentagi_get_task_subtasks <flowID> <taskID>               ║
║    pentagi_get_task_graph <flowID> <taskID>                  ║
║                                                              ║
║  LOGS                                                        ║
║    pentagi_get_logs <id> [limit=20]     (msg logs)           ║
║    pentagi_get_agent_logs <id>                               ║
║    pentagi_get_search_logs <id>                              ║
║    pentagi_get_term_logs <id>                                ║
║    pentagi_get_vecstore_logs <id>                            ║
║    pentagi_get_assistant_logs <id>                           ║
║                                                              ║
║  CHAT (Direct DB)                                            ║
║    pentagi_get_chats <id> [limit=50]                         ║
║    pentagi_get_chats_full <id> [limit=50]                    ║
║                                                              ║
║  PROVIDERS                                                   ║
║    pentagi_get_providers                                     ║
║                                                              ║
║  ASSISTANTS                                                  ║
║    pentagi_create_assistant <flowID> <msg>                   ║
║    pentagi_get_assistants <flowID>                           ║
║                                                              ║
║  GRAPH                                                       ║
║    pentagi_get_flow_graph <id>                               ║
║                                                              ║
║  SCREENSHOTS                                                 ║
║    pentagi_get_screenshots <id>                              ║
║                                                              ║
║  CONTAINERS                                                  ║
║    pentagi_get_containers                                    ║
║    pentagi_get_flow_containers <id>                          ║
║                                                              ║
║  USERS & SYSTEM                                              ║
║    pentagi_get_users                                         ║
║    pentagi_create_user <email> <pass> <name>                 ║
║    pentagi_get_usage                                         ║
║    pentagi_get_flow_usage <id>                               ║
║    pentagi_get_info                                          ║
║                                                              ║
║  PROMPTS                                                     ║
║    pentagi_get_prompts                                       ║
║    pentagi_get_prompt <type>                                 ║
║                                                              ║
║  TOKENS                                                      ║
║    pentagi_create_token <name>                               ║
║    pentagi_list_tokens                                       ║
║                                                              ║
║  Config: PENTAGI_BASE_URL, PENTAGI_DEFAULT_PROVIDER          ║
╚══════════════════════════════════════════════════════════════╝
EOF
}

echo "✅ PentAGI CLI loaded! Type 'pentagi_help' for commands."
echo "   Default provider: $PENTAGI_DEFAULT_PROVIDER"
echo "   Base URL: $PENTAGI_BASE_URL"
