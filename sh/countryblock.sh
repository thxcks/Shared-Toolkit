#!/bin/bash

BLOCK_COUNTRIES=""
USE_CIDR=false

# ---------- checks -----------------------------------------------------------
if ! command -v curl &>/dev/null; then
  echo "ERROR: curl is required but not installed."; exit 1
fi

# ---------- prompt for user --------------------------------------------------
echo "Enter user:"
read -r user

# ---------- list available log files -----------------------------------------
echo "~~~~~~~~~~~~~"
echo "# User Logs #"
echo "~~~~~~~~~~~~~"
ls -lhS /home/$user/access-logs/

echo "Enter which log file you wish to check:"
read -r log_file

echo "#######################################################"
echo "Please note, this log starts at:" $(head -1 /home/$user/access-logs/$log_file | awk '{print $4}' | tr -d [)
echo "#######################################################"
echo ""

LOG_FILE="/home/$user/access-logs/$log_file"

if [[ ! -f "$LOG_FILE" ]]; then
  echo "ERROR: Log file '$LOG_FILE' not found."
  exit 1
fi

# ---------- extract unique IPs -----------------------------------------------
UNIQUE_IPS=$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$LOG_FILE" | sort -u)
TOTAL_UNIQUE=$(echo "$UNIQUE_IPS" | grep -c . || true)
TOTAL_REQUESTS=$(grep -cE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$LOG_FILE" || true)

echo "Found $TOTAL_UNIQUE unique IPs across $TOTAL_REQUESTS requests. Looking up countries..." >&2
echo "" >&2

# ---------- batch lookup via ip-api.com (free, no key, 100 IPs per request) --
declare -A IP_COUNTRY
declare -A COUNTRY_IPS
declare -A COUNTRY_NAME

batch_lookup() {
  local batch=("$@")
  local json="["
  for ip in "${batch[@]}"; do
    json+="{\"query\":\"$ip\"},"
  done
  json="${json%,}]"

  local result
  result=$(curl -s --max-time 15 -X POST \
    -H "Content-Type: application/json" \
    -d "$json" \
    "http://ip-api.com/batch?fields=query,countryCode,country")

  while IFS= read -r line; do
    local ip cc name
    ip=$(echo   "$line" | grep -oP '(?<="query":")[^"]+')
    cc=$(echo   "$line" | grep -oP '(?<="countryCode":")[^"]+')
    name=$(echo "$line" | grep -oP '(?<="country":")[^"]+')
    [[ -z "$cc" || "$cc" == "null" ]] && cc="UNKNOWN" && name="Unknown/Private"
    IP_COUNTRY["$ip"]="$cc"
    COUNTRY_IPS["$cc"]+="$ip "
    COUNTRY_NAME["$cc"]="$name"
  done < <(echo "$result" | grep -oP '\{[^}]+\}')
}

# Process in batches of 100
IPS_ARRAY=()
while IFS= read -r ip; do
  [[ -z "$ip" ]] && continue
  IPS_ARRAY+=("$ip")
  if [[ ${#IPS_ARRAY[@]} -eq 100 ]]; then
    batch_lookup "${IPS_ARRAY[@]}"
    IPS_ARRAY=()
  fi
done <<< "$UNIQUE_IPS"
[[ ${#IPS_ARRAY[@]} -gt 0 ]] && batch_lookup "${IPS_ARRAY[@]}"

# ---------- count requests per country ---------------------------------------
declare -A COUNTRY_COUNT
while IFS= read -r line; do
  local_ip=$(echo "$line" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
  [[ -z "$local_ip" ]] && continue
  code="${IP_COUNTRY[$local_ip]:-UNKNOWN}"
  COUNTRY_COUNT["$code"]=$(( ${COUNTRY_COUNT["$code"]:-0} + 1 ))
done < "$LOG_FILE"

# ---------- print summary ----------------------------------------------------
echo "=============================================="
echo " Request Summary by Country"
echo "=============================================="
printf "  %-8s %-30s %s\n" "Code" "Country" "Requests"
printf "  %-8s %-30s %s\n" "--------" "------------------------------" "--------"

for code in $(for k in "${!COUNTRY_COUNT[@]}"; do
                echo "$k ${COUNTRY_COUNT[$k]}"
              done | sort -k2 -rn | awk '{print $1}'); do
  printf "  %-8s %-30s %s\n" \
    "$code" \
    "${COUNTRY_NAME[$code]:-Unknown}" \
    "${COUNTRY_COUNT[$code]}"
done

echo ""
echo "  Total requests : $TOTAL_REQUESTS"
echo "  Unique IPs     : $TOTAL_UNIQUE"
echo "=============================================="

# ---------- prompt if --block not supplied -----------------------------------
if [[ -z "$BLOCK_COUNTRIES" ]]; then
  echo "" >&2
  printf "Block which country codes? (comma-separated, e.g. CN,RU — or ENTER to skip): " >&2
  read -r BLOCK_COUNTRIES
fi
[[ -z "$BLOCK_COUNTRIES" ]] && exit 0

# ---------- output .htaccess rules to stdout ---------------------------------
IFS=',' read -ra CODES <<< "$BLOCK_COUNTRIES"

echo ""
echo "# ============================================================"
echo "# .htaccess Blocklist — generated $(date)"
echo "# Blocked countries: $BLOCK_COUNTRIES"
echo "# ============================================================"
echo ""
echo "Order Allow,Deny"
echo "Allow from all"
echo ""

for code in "${CODES[@]}"; do
  code=$(echo "$code" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')
  ips="${COUNTRY_IPS[$code]}"

  if [[ -z "$ips" ]]; then
    echo "# No IPs found in log for: $code"
    continue
  fi

  echo "# --- $code — ${COUNTRY_NAME[$code]:-Unknown} (${COUNTRY_COUNT[$code]:-0} requests) ---"

  if $USE_CIDR; then
    declare -A SEEN_CIDR
    for ip in $ips; do
      cidr=$(echo "$ip" | awk -F. '{print $1"."$2"."$3".0/24"}')
      if [[ -z "${SEEN_CIDR[$cidr]}" ]]; then
        echo "Deny from $cidr"
        SEEN_CIDR["$cidr"]=1
      fi
    done
    unset SEEN_CIDR
  else
    for ip in $ips; do
      echo "Deny from $ip"
    done
  fi

  echo ""
done
