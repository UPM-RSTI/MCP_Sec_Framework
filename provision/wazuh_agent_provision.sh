#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

AGENT_VERSION="$1"     
AGENT_DEB_REV="$2"        
WAZUH_SERVER_IP="$3"   

apt-get update -y
apt-get install -y curl gnupg apt-transport-https lsb-release

# Oficial Wazuh repo
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor > /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update -y

DEB_FILE="wazuh-agent_${AGENT_VERSION}-${AGENT_DEB_REV}_amd64.deb"
DEB_URL="https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/${DEB_FILE}"

echo "[INFO] Trying to download Wazuh agent from ${DEB_URL}"
if curl -fSL "${DEB_URL}" -o "/tmp/${DEB_FILE}"; then
  echo "[INFO] Installing ${DEB_FILE} via dpkg"
  dpkg -i "/tmp/${DEB_FILE}" || apt-get install -y -f
else
  echo "[WARN] Could not download ${DEB_FILE}, falling back to repo package wazuh-agent"
  if ! apt-get install -y wazuh-agent; then
    echo "[ERROR] Unable to install wazuh-agent from repo or direct .deb" >&2
    exit 1
  fi
fi

apt-mark hold wazuh-agent

# 1. CONFIGURATION OF THE AGENT TO CONNECT TO THE MANAGER
sed -i "s#<address>MANAGER_IP</address>#<address>${WAZUH_SERVER_IP}</address>#" /var/ossec/etc/ossec.conf || true

if ! grep -q "<address>${WAZUH_SERVER_IP}</address>" /var/ossec/etc/ossec.conf; then
  awk '
  /<\/ossec_config>/ && !done {
    print "  <client>";
    print "    <server>";
    print "      <address>'"${WAZUH_SERVER_IP}"'</address>";
    print "      <port>1514</port>";
    print "      <protocol>tcp</protocol>";
    print "    </server>";
    print "  </client>";
    done=1
  }
  { print }
  ' /var/ossec/etc/ossec.conf > /tmp/ossec.client.new && mv /tmp/ossec.client.new /var/ossec/etc/ossec.conf
fi

# # Directory for Cypher output
# install -d /home/vagrant/kafka-wazuh/cypher/cypher-output

# # Clean previous <localfile> for our Cypher JSON (if any)
# awk -v path="/home/vagrant/kafka-wazuh/cypher/cypher-output/cypher-monitoring.json" '
#   BEGIN { inblk=0; buf="" }
#   /<localfile>/ { inblk=1; buf=$0; next }
#   inblk {
#     buf = buf RS $0
#     if ($0 ~ /<\/localfile>/) {
#       if (buf !~ path) print buf
#       inblk=0; buf=""
#     }
#     next
#   }
#   { print }
# ' /var/ossec/etc/ossec.conf > /tmp/ossec.nolocal && mv /tmp/ossec.nolocal /var/ossec/etc/ossec.conf

# # Add <localfile> for our Cypher JSON output, an also for Docker container logs
# awk '
#   /<\/ossec_config>/ && !done {
#     print "  <localfile>";
#     print "    <log_format>json</log_format>";
#     print "    <location>/home/vagrant/kafka-wazuh/cypher/cypher-output/cypher-monitoring.json</location>";
#     print "    <label key=\"source\">cypher</label>";
#     print "  </localfile>";
#     done=1
#   }
#   { print }
# ' /var/ossec/etc/ossec.conf > /tmp/ossec.final && mv /tmp/ossec.final /var/ossec/etc/ossec.conf

# 2. DOCKER-LISTENER BLOCK
awk '
  /<\/ossec_config>/ && !done {
    print "  <wodle name=\"docker-listener\">";
    print "    <disabled>no</disabled>";
    print "  </wodle>";
    done=1
  }
  { print }
' /var/ossec/etc/ossec.conf > /tmp/ossec.docker && mv /tmp/ossec.docker /var/ossec/etc/ossec.conf
# --------------------------------------------------------------------

apt-get install -y netcat-openbsd

# 3. AGENT REGISTRATION
HOSTNAME="$(hostname -s)"

if [[ "$HOSTNAME" == "client1-flower" ]]; then
    AGENT_NAME="client1"
elif [[ "$HOSTNAME" == "client2-flower" ]]; then
    AGENT_NAME="client2"
elif [[ "$HOSTNAME" == "node1" ]]; then
    AGENT_NAME="vm1"
elif [[ "$HOSTNAME" == "node2" ]]; then
    AGENT_NAME="vm2"
elif [[ "$HOSTNAME" == "c4-vuln" ]]; then
    AGENT_NAME="vulnerable"
else
    AGENT_NAME="$HOSTNAME"
    echo "[WARN] Unrecognized hostname '${HOSTNAME}', using it as agent name."
fi

WAZUH_API_URL="https://${WAZUH_SERVER_IP}:55000"
WAZUH_API_USER="wazuh-wui"         
WAZUH_API_PASS="MyS3cr37P450r.*-"       

echo "[INFO] Preparing to register agent: ${AGENT_NAME}"

# Wait for enrollment service
for i in {1..30}; do
  nc -z "${WAZUH_SERVER_IP}" 1515 && break
  sleep 3
done

# Get API token (to delete old agent)
echo "[INFO] Requesting API token from Wazuh manager..."
API_TOKEN="$(
  curl -s -k -u "${WAZUH_API_USER}:${WAZUH_API_PASS}" \
    -X POST "${WAZUH_API_URL}/security/user/authenticate" \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['data']['token'])"
)"
if [ -z "$API_TOKEN" ]; then
  echo "[WARN] Could not obtain API token. Skipping cleanup."
else
  echo "[INFO] Token obtained. Removing any existing agent named '${AGENT_NAME}'..."

  # Obtain existing agent IDs with that name
  AGENT_IDS="$(
    curl -sk -H "Authorization: Bearer ${API_TOKEN}" \
      "${WAZUH_API_URL}/agents?name=${AGENT_NAME}" \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); items=d.get("data", {}).get("affected_items", []); print(",".join(i["id"] for i in items if "id" in i))'
  )"

  # Delete existing agents with that name
  if [ -n "$AGENT_IDS" ]; then
    echo "[INFO] Found existing agents with IDs: ${AGENT_IDS}"
    curl -sk -X DELETE \
      "${WAZUH_API_URL}/agents?agents_list=${AGENT_IDS}" \
      -H "Authorization: Bearer ${API_TOKEN}" >/dev/null 2>&1 || true

    echo "[INFO] Agents deleted successfully."
  else
    echo "[INFO] No agents found with name '${AGENT_NAME}'."
  fi
fi


# Register again with clean state
echo "[INFO] Running agent-auth..."
if ! /var/ossec/bin/agent-auth -m "${WAZUH_SERVER_IP}" -p 1515 -A "${AGENT_NAME}"; then
  echo "[WARN] Agent-auth can't connect to ${WAZUH_SERVER_IP}:1515."
  echo "[WARN] Agent installed but not registered." >&2
fi

echo "[OK] wazuh-agent installed and registered as '${AGENT_NAME}' (manager=${WAZUH_SERVER_IP})"
