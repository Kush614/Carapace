#!/usr/bin/env bash
# Carapace one-command bootstrap (Final Demo Spec §15).
# Brings up: kind cluster + Calico + 3 sites + Lobster Trap + demo API +
# frontend, then smoke-tests. ~45-90s on a machine with Docker.
#
# Requires: docker, kind, kubectl, python3, the real ./bin/lobstertrap.
# No Docker/kind?  ->  CARAPACE_EXECUTOR=mock ./demo.sh   (SIM, spec §17)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

MOCK="${CARAPACE_EXECUTOR:-kube}"

if [ "$MOCK" != "mock" ]; then
  echo "==> [1/6] kind cluster"
  kind get clusters 2>/dev/null | grep -qx carapace-edge \
    || kind create cluster --config manifests/kind-cluster.yaml

  echo "==> [2/6] Calico (so NetworkPolicy is REAL)"
  kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.2/manifests/calico.yaml
  kubectl -n kube-system rollout status ds/calico-node --timeout=180s

  echo "==> [3/6] sites (3 namespaces x 4 nginx + spine + canary)"
  # The 3 Namespace docs contain no __NS__ (re-applied each pass, which is
  # idempotent); the templated workload docs get this pass's namespace.
  for NS in site-sj-01 site-sj-02 site-oak-01; do
    sed "s/__NS__/$NS/g" manifests/sites.yaml | kubectl apply -f -
  done
  for NS in site-sj-01 site-sj-02 site-oak-01; do
    kubectl wait --for=condition=ready pod --all -n "$NS" --timeout=120s || true
  done
else
  echo "==> SIM mode (CARAPACE_EXECUTOR=mock) — no cluster"
fi

echo "==> [4/6] Lobster Trap (real Veea binary, if present)"
if [ -x ./bin/lobstertrap ] || [ -x ./bin/lobstertrap.exe ]; then
  LT=./bin/lobstertrap; [ -x ./bin/lobstertrap.exe ] && LT=./bin/lobstertrap.exe
  "$LT" serve \
    --backend "${GEMINI_OPENAI_COMPAT_URL:-https://generativelanguage.googleapis.com}" \
    --policy configs/carapace_lt_policy.yaml --listen :8080 \
    --no-dashboard >/tmp/lobstertrap.log 2>&1 &
else
  echo "    (no binary — Lobster Trap verdict is synthesized in demo_api)"
fi

echo "==> [5/6] Carapace demo API :8000"
CARAPACE_EXECUTOR="$MOCK" python3 -m uvicorn carapace.demo_api:app \
  --port 8000 >/tmp/carapace-api.log 2>&1 &

echo "==> [6/6] frontend :3000"
python3 -m http.server 3000 --directory frontend >/tmp/carapace-fe.log 2>&1 &

sleep 4
echo "==> smoke test"
curl -fsS http://localhost:8000/v1/health && echo
echo
echo "  Carapace ready:"
echo "   • before/after demo : http://localhost:3000/final.html"
echo "   • scenario explorer : http://localhost:3000/index.html"
echo "   • API health        : http://localhost:8000/v1/health"
