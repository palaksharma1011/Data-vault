#!/usr/bin/env bash
# Black-box check of the security fixes against a RUNNING server.
#   ./scripts/verify-fixes.sh                 # defaults: http://localhost:8080, admin / Admin@123
#   BASE=http://host:8080 ADMIN_PW='...' ./scripts/verify-fixes.sh
# Needs: bash, curl, python3. Safe to re-run (creates throw-away users/files).
# NOTE: if MFA is enabled on `admin` (or VAULT_REQUIRE_MFA=true) the admin login step
# will report an MFA challenge; run this against a fresh instance instead.
set -u
BASE="${BASE:-http://localhost:8080}"
ADMIN_PW="${ADMIN_PW:-Admin@123}"
RUN="$(date +%s)"
PASS=0; FAIL=0
ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1 (got $2)"; else bad "$1 (expected $3, got $2)"; fi; }
jget() { python3 -c "import sys,json
try: d=json.load(sys.stdin); v=d
except Exception: print(''); sys.exit()
for k in sys.argv[1].split('.'):
    v=v.get(k,'') if isinstance(v,dict) else ''
print(v if v is not None else '')" "$1"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
api()  { # api METHOD PATH TOKEN [JSON]
  local m="$1" p="$2" t="$3" b="${4:-}"
  if [ -n "$b" ]; then curl -s -X "$m" "$BASE$p" -H "Authorization: Bearer $t" -H 'Content-Type: application/json' -d "$b"
  else curl -s -X "$m" "$BASE$p" -H "Authorization: Bearer $t"; fi; }
apicode() { local m="$1" p="$2" t="$3" b="${4:-}"
  if [ -n "$b" ]; then code -X "$m" "$BASE$p" -H "Authorization: Bearer $t" -H 'Content-Type: application/json' -d "$b"
  else code -X "$m" "$BASE$p" -H "Authorization: Bearer $t"; fi; }
login() { curl -s -X POST "$BASE/api/login" -H 'Content-Type: application/json' -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jget token; }
upload() { # upload TOKEN CLASS NAME CONTENT  -> prints file id
  local tmp; tmp="$(mktemp)"; printf '%s' "$4" > "$tmp"
  curl -s -X POST "$BASE/api/files/upload" -H "Authorization: Bearer $1" \
    -F "classification=$2" -F "file=@$tmp;filename=$3" | jget id; rm -f "$tmp"; }

echo "== Setup =="
ADM="$(login admin "$ADMIN_PW")"
[ -n "$ADM" ] || { echo "Cannot log in as admin (wrong password, MFA enabled, or locked out)."; exit 2; }
for u in "emp$RUN:EmployeePass1:EMPLOYEE" "mgr$RUN:ManagerPass12:HR_MANAGER"; do
  IFS=: read -r n p r <<<"$u"
  api POST /api/users "$ADM" "{\"username\":\"$n\",\"password\":\"$p\",\"role\":\"$r\"}" >/dev/null
done
EMP="$(login "emp$RUN" EmployeePass1)"
echo "  admin + users ready"

echo; echo "== #1 Classification is enforced =="
HC="$(upload "$ADM" HIGHLY_CONFIDENTIAL "board-$RUN.txt" "HC-SECRET-$RUN")"
check "policy giving EMPLOYEE access to HIGHLY_CONFIDENTIAL is rejected" \
  "$(apicode POST /api/policies "$ADM" "{\"resourceId\":\"$HC\",\"role\":\"EMPLOYEE\",\"actions\":[\"DOWNLOAD\"]}")" 400
check "employee DOWNLOAD of HIGHLY_CONFIDENTIAL is denied" \
  "$(apicode POST "/api/files/$HC/access" "$EMP" '{"action":"DOWNLOAD"}')" 403
echo "  (to prove the ENGINE also blocks a bad policy row, see VERIFYING_FIXES.md §1)"

echo; echo "== #2 DELETE deletes and returns no data =="
INT="$(upload "$ADM" INTERNAL "memo-$RUN.txt" "MEMO-BODY-$RUN")"
api POST /api/policies "$ADM" "{\"resourceId\":\"$INT\",\"role\":\"EMPLOYEE\",\"actions\":[\"DELETE\"]}" >/dev/null
RESP="$(api POST "/api/files/$INT/access" "$EMP" '{"action":"DELETE"}')"
case "$RESP" in *MEMO-BODY*|*'"content"'*) bad "DELETE response leaked file data";; *) ok "DELETE response contains no file data";; esac
check "response says deleted" "$(echo "$RESP" | jget deleted)" True
case "$(api GET /api/files "$ADM")" in *"$INT"*) bad "file still listed after DELETE";; *) ok "file is gone from the list";; esac

echo; echo "== #3 No storage metadata in file listings =="
LIST="$(api GET /api/files "$EMP")$(api GET /api/files "$ADM")"
leak=0; for w in encPath wrappedKey nonce '\.enc' ownerId; do echo "$LIST" | grep -q "$w" && { bad "listing leaks '$w'"; leak=1; }; done
[ $leak = 0 ] && ok "listing exposes only id, name, classification, size, uploadedAt"

echo; echo "== #4 Input validation =="
check "role BANANA rejected"   "$(apicode POST /api/policies "$ADM" "{\"resourceId\":\"$HC\",\"role\":\"BANANA\",\"actions\":[\"READ\"]}")" 400
check "action FLY rejected"    "$(apicode POST /api/policies "$ADM" "{\"resourceId\":\"$HC\",\"role\":\"HR_MANAGER\",\"actions\":[\"FLY\"]}")" 400
check "unknown resource rejected" "$(apicode POST /api/policies "$ADM" '{"resourceId":"file_nope","role":"HR","actions":["READ"]}')" 400
check "weak password rejected" "$(apicode POST /api/users "$ADM" '{"username":"weakling","password":"abc","role":"HR"}')" 400

echo; echo "== #5 Login brute-force protection =="
for i in 1 2 3 4 5; do c="$(code -X POST "$BASE/api/login" -H 'Content-Type: application/json' -d "{\"username\":\"lock$RUN\",\"password\":\"bad$i\"}")"; [ "$c" = 401 ] || bad "attempt $i expected 401, got $c"; done
check "6th attempt is rate-limited" "$(code -X POST "$BASE/api/login" -H 'Content-Type: application/json' -d "{\"username\":\"lock$RUN\",\"password\":\"bad6\"}")" 429

echo; echo "== #6 Audit trail covers security events =="
AUD="$(api GET '/api/audit?limit=500' "$ADM")"
for ev in LOGIN USER_CREATE FILE_UPLOAD POLICY_CREATE; do
  echo "$AUD" | grep -q "\"action\":\"$ev\"" && ok "audit contains $ev events" || bad "no $ev events in audit"
done
echo "$AUD" | grep -q '"action":"LOGIN","decision":"DENY"' && ok "failed logins are recorded" || bad "failed logins not recorded"
VER="$(api GET /api/audit/verify "$ADM")"
check "hash chain verifies" "$(echo "$VER" | jget ok)" True

echo; echo "== Admin has no implicit access =="
PUB="$(upload "$ADM" PUBLIC "pub-$RUN.txt" "public")"
check "admin READ with no policy is denied" "$(apicode POST "/api/files/$PUB/access" "$ADM" '{"action":"READ"}')" 403

echo; echo "== Logout =="
T2="$(login "emp$RUN" EmployeePass1)"
api POST /api/logout "$T2" >/dev/null
check "token is dead after logout" "$(apicode GET /api/me "$T2")" 401

echo; echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
