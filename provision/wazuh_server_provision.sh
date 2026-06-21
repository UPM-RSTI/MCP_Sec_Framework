#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

WZ_REPO="$1"       # p.ej. https://github.com/wazuh/wazuh-docker.git
WZ_VERSION="$2"    # p.ej. v4.14.0
FLASK_PORT="$3"    # p.ej. 5010
WAZUH_SERVER_IP="$4"   

# 1) Instalation of Wazuh multi-node via Docker Compose
apt-get update -y
apt-get install -y ca-certificates curl gnupg lsb-release net-tools

echo 'vm.max_map_count=262144' | tee /etc/sysctl.d/99-wazuh.conf
sysctl -w vm.max_map_count=262144
sysctl -p /etc/sysctl.d/99-wazuh.conf || true

apt-get update -y
apt-get install -y docker.io docker-compose
usermod -aG docker vagrant || true

docker --version || true
docker-compose --version || true

apt-get update -y
apt-get install -y git python3-venv python3-pip

rm -rf /opt/wazuh-docker
git clone "$WZ_REPO" /opt/wazuh-docker -b "$WZ_VERSION"

cd /opt/wazuh-docker/multi-node

if [ ! -d config/wazuh_indexer_ssl_certs ]; then
  docker-compose -f generate-indexer-certs.yml run --rm generator
fi

docker-compose up -d

echo "[INFO] Esperando a managers..."
for i in {1..20}; do
  if docker ps --format '{{.Names}}' | grep -qE 'multi-node_wazuh\.master_1|multi-node_wazuh\.worker_1'; then
    break
  fi
  sleep 3
done

# 2) API Flask
# Local API flask to receive threats
install -d /opt/ccdrif-api

cat >/opt/ccdrif-api/app.py <<PY
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.post("/api/threat")
def threat():
    data = request.get_json(silent=True) or {}
    print(f"[THREAT] {data}", flush=True)
    return jsonify({"ok": True}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=${FLASK_PORT})
PY

python3 -m venv /opt/ccdrif-api/venv
/opt/ccdrif-api/venv/bin/pip install flask

cat >/etc/systemd/system/ccdrif-api.service <<UNIT
[Unit]
Description=CC-DRIF Flask receiver
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=/opt/ccdrif-api
ExecStart=/opt/ccdrif-api/venv/bin/python /opt/ccdrif-api/app.py
Restart=always

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now ccdrif-api

# 3) Copy custom rules
for C in $(docker ps --format '{{.Names}}' | grep -E 'multi-node_wazuh\.master_1|multi-node_wazuh\.worker_1'); do
  if [ -f /vagrant/rules.xml ]; then
    echo "[INFO] Copying rules.xml to $C"
    docker cp /vagrant/rules.xml "$C":/var/ossec/etc/rules/local_rules.xml
  else
    echo "[WARN] /vagrant/rules.xml not found, not copying to $C"
  fi
  echo "[OK] $C rules ready"
done

# 3.1) Copy custom decoders and restart managers 
for C in $(docker ps --format '{{.Names}}' | grep -E 'multi-node_wazuh\.master_1|multi-node_wazuh\.worker_1'); do
  if [ -f /vagrant/decoders.xml ]; then
    echo "[INFO] Copying decoders.xml to $C"
    docker cp /vagrant/decoders.xml "$C":/var/ossec/etc/decoders/local_decoders.xml
  else
    echo "[WARN] /vagrant/rules.xml not found, not copying to $C"
  fi

  docker exec "$C" /var/ossec/bin/wazuh-control restart
  echo "[OK] $C restarted after copying rules"
done

# 4) Integration custom-threat-forward
cat >/tmp/custom-threat-forward.py <<'PY'
#!/usr/bin/env python3
import sys, json, urllib.request, time, uuid, datetime as dt

def iso_z(dt_obj=None):
    if dt_obj is None:
        dt_obj = dt.datetime.utcnow()
    return dt_obj.replace(microsecond=int(dt_obj.microsecond/1000)*1000).isoformat(timespec="milliseconds")+"Z"

def to_iso_z(s):
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(str(s).replace("Z","+00:00")).astimezone(dt.timezone.utc).replace(tzinfo=None).isoformat(timespec="milliseconds")+"Z"
    except Exception:
        return None

def load_alert(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        data = f.read().strip()
    try:
        return json.loads(data)
    except Exception:
        return json.loads(data.splitlines()[-1])

def get(alert, key):
    d = alert.get('data') or {}
    return d.get(key, alert.get(key))

def parse_desc(desc):
    name = (desc or "").strip() or "Alert"
    primary = None
    if "->" in name:
        parts = [p.strip() for p in name.split("->")]
        if parts:
            name = parts[0] or name
        if len(parts) >= 2:
            primary = parts[1]
            if " (" in primary:
                primary = primary.split(" (", 1)[0].strip()
    if not primary:
        primary = "Unknown-Asset"
    return name, primary

def build_description(alert):
    fn = get(alert, 'filename')
    o, n = get(alert, 'old_size'), get(alert, 'new_size')
    tm = get(alert, 'text_modified')
    desc = []
    if fn and (o is not None and n is not None):
        desc.append(f"The file '{fn}' was modified (size changed from {o} to {n} bytes).")
    elif fn:
        desc.append(f"The file '{fn}' was modified.")
    else:
        desc.append("A key-related configuration file was modified.")
    if tm:
        desc.append(f"Text modified: {tm[:100]}")
    return " ".join(desc)[:300]

def build_payload(alert):
    wid = alert.get('id') or str(uuid.uuid4())
    fecha = to_iso_z(alert.get('timestamp') or alert.get('@timestamp')) or iso_z()
    rdesc = (alert.get('rule') or {}).get('description', '')
    name, primary_asset = parse_desc(rdesc)
    description = build_description(alert)
    return {
        "id": wid,
        "fecha": fecha,
        "name": name,
        "threat": name,
        "primary_asset": primary_asset,
        "description": description
    }

def post_json(url, payload, retries=2, timeout=5):
    body = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
    last = None
    for _ in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                r.read()
                return
        except Exception as e:
            last = e
            time.sleep(1)
    raise last

def main():
    if len(sys.argv) < 4:
        sys.exit(1)
    alert = load_alert(sys.argv[1])
    payload = build_payload(alert)
    post_json(sys.argv[3], payload)
    print("OK")

if __name__ == '__main__':
    main()
PY

# 4.1) Wrapper SHELL that uses Wazuh to execute python script
cat >/tmp/custom-threat-forward <<'SH'
#!/bin/sh
if [ -x /var/ossec/framework/python/bin/python3 ]; then
    PYTHON=/var/ossec/framework/python/bin/python3
else
    PYTHON=/usr/bin/env python3
fi

exec "$PYTHON" /var/ossec/integrations/custom-threat-forward.py "$@"
SH

chmod 750 /tmp/custom-threat-forward /tmp/custom-threat-forward.py


# 5) Copy integration script to managers
for C in multi-node_wazuh.master_1 multi-node_wazuh.worker_1; do
  docker cp /tmp/custom-threat-forward "$C":/var/ossec/integrations/custom-threat-forward
  docker cp /tmp/custom-threat-forward.py "$C":/var/ossec/integrations/custom-threat-forward.py
  docker exec "$C" bash -lc '
    chmod 750 /var/ossec/integrations/custom-threat-forward /var/ossec/integrations/custom-threat-forward.py
    chown root:wazuh /var/ossec/integrations/custom-threat-forward /var/ossec/integrations/custom-threat-forward.py
  '
done

# 6) Add integration to ossec.conf
HOOK_URL="http://${WAZUH_SERVER_IP}:${FLASK_PORT}/api/threat"

for C in multi-node_wazuh.master_1 multi-node_wazuh.worker_1; do
  docker exec "$C" bash -lc '
CONF=/var/ossec/etc/ossec.conf
if grep -q "<name>custom-threat-forward</name>" "$CONF"; then
  echo "[INFO] ($HOSTNAME) integration already present in ossec.conf, skipping."
  exit 0
fi
cp -f "$CONF" "$CONF.bak"
cat >/tmp/add_integration.awk << "AWK"
{
  if (!done && index($0, "</ossec_config>")) {
    print "  <integration>"
    print "    <name>custom-threat-forward</name>"
    print "    <hook_url>'"$HOOK_URL"'</hook_url>"
    print "    <alert_format>json</alert_format>"
    print "    <level>3</level>"
    print "  </integration>"
    done = 1
  }
  print
}
AWK
awk -f /tmp/add_integration.awk "$CONF" > "$CONF.new" && mv "$CONF.new" "$CONF"
rm -f /tmp/add_integration.awk
'
done

# 8) Restart Wazuh managers to apply changes
for C in multi-node_wazuh.master_1 multi-node_wazuh.worker_1; do
  docker exec "$C" /var/ossec/bin/wazuh-control restart
done

echo "[OK] Wazuh multi-node + integration + API Flask deployed"
