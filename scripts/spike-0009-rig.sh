#!/bin/sh
# The local cluster RFC 0009's ground-truth spike runs against, for the rows a laptop can answer.
#
#   scripts/spike-0009-rig.sh up     create the kind cluster and install what the rows read
#   scripts/spike-0009-rig.sh down   delete it
#
# What this rig can and cannot settle is the point of it. It answers the DevWorkspace Operator
# rows and the three ingress-controller rows, because those are somebody else's software behaving
# the way it behaves whether or not Che is in front of it. It cannot answer the Che rows (the user
# namespace's label, the OIDC client, the shape of a token) or the OpenShift row: those need the
# cluster the feature is actually for, and `scripts/spike-0009.sh` is written to run there too.
#
# Two deliberate choices worth knowing about:
#
#   - DevWorkspace Operator is installed standalone, with `basic` routing, not the `che` routing
#     class. That is why the rows it answers are about DWO's own behaviour — one object per
#     endpoint, the devfile field's spelling, the annotations surviving — and never about which
#     ingress class or host suffix a workspace ends up with, which Che decides and this rig does
#     not model.
#   - ingress-nginx is pinned to two worker processes. Under rootless podman the kind node hits a
#     pids limit and nginx's `worker_processes auto` never comes up. That is a property of the
#     laptop, not of ingress-nginx, and it changes nothing any row reads.
set -eu

CLUSTER="${SPIKE_CLUSTER:-weebo-spike}"
DWO_VERSION="${SPIKE_DWO_VERSION:-v0.43.0}"
KIND_EXPERIMENTAL_PROVIDER="${KIND_EXPERIMENTAL_PROVIDER:-podman}"
export KIND_EXPERIMENTAL_PROVIDER

for tool in kind kubectl helm jq; do
  command -v "$tool" >/dev/null 2>&1 || { printf '%s is required\n' "$tool" >&2; exit 2; }
done

up() {
  kind get clusters 2>/dev/null | grep -qx "$CLUSTER" ||
    kind create cluster --name "$CLUSTER" --wait 180s

  helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx >/dev/null 2>&1 || true
  helm repo add traefik https://traefik.github.io/charts >/dev/null 2>&1 || true
  helm repo add haproxy-ingress https://haproxy-ingress.github.io/charts >/dev/null 2>&1 || true
  helm repo update >/dev/null

  printf 'installing ingress-nginx\n'
  helm upgrade --install ingress-nginx ingress-nginx/ingress-nginx \
    -n ingress-nginx --create-namespace \
    --set controller.service.type=ClusterIP \
    --set controller.ingressClassResource.name=nginx \
    --set controller.ingressClassResource.default=false \
    --set controller.publishService.enabled=false \
    --set controller.config.worker-processes="2" \
    --wait --timeout 10m >/dev/null

  printf 'installing traefik\n'
  helm upgrade --install traefik traefik/traefik -n traefik --create-namespace \
    --set service.type=ClusterIP \
    --set ingressClass.name=traefik \
    --set ingressClass.isDefaultClass=false \
    --wait --timeout 10m >/dev/null

  printf 'installing haproxy-ingress\n'
  helm upgrade --install haproxy haproxy-ingress/haproxy-ingress -n haproxy --create-namespace \
    --set controller.service.type=ClusterIP \
    --set controller.ingressClassResource.enabled=true \
    --set controller.ingressClassResource.name=haproxy \
    --wait --timeout 10m >/dev/null

  printf 'installing cert-manager (DevWorkspace Operator needs it off OpenShift)\n'
  cert=$(curl -sS https://api.github.com/repos/cert-manager/cert-manager/releases/latest | jq -r .tag_name)
  kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/$cert/cert-manager.yaml" >/dev/null
  kubectl -n cert-manager rollout status deploy/cert-manager-webhook --timeout=300s >/dev/null

  printf 'installing DevWorkspace Operator %s\n' "$DWO_VERSION"
  # The combined manifest assumes its namespace exists; applying it twice would work too, and
  # creating it outright says why rather than leaving a retry looking like flakiness.
  kubectl create namespace devworkspace-controller >/dev/null 2>&1 || true
  kubectl apply -f "https://raw.githubusercontent.com/devfile/devworkspace-operator/$DWO_VERSION/deploy/deployment/kubernetes/combined.yaml" >/dev/null
  kubectl -n devworkspace-controller rollout status deploy/devworkspace-controller-manager --timeout=300s >/dev/null

  printf 'starting one workspace, so row 3 has an object to read\n'
  kubectl apply -f - >/dev/null <<'FIXTURE'
apiVersion: controller.devfile.io/v1alpha1
kind: DevWorkspaceOperatorConfig
metadata:
  name: devworkspace-operator-config
  namespace: devworkspace-controller
config:
  routing:
    clusterHostSuffix: 127.0.0.1.nip.io
    defaultRoutingClass: basic
---
apiVersion: v1
kind: Namespace
metadata:
  name: weebo-spike-ws
---
apiVersion: workspace.devfile.io/v1alpha2
kind: DevWorkspace
metadata:
  name: spike-ws
  namespace: weebo-spike-ws
spec:
  started: true
  template:
    attributes:
      controller.devfile.io/storage-type: ephemeral
    components:
      - name: app
        container:
          image: docker.io/library/nginx:1.27-alpine
          memoryLimit: 256Mi
          endpoints:
            # Two exposed endpoints, because the row being read is "one routing object per
            # endpoint" and one endpoint cannot tell that apart from "one per workspace". The
            # annotations are here because the question is whether DWO carries them across; the
            # container itself never has to start for either fact to be readable.
            - name: web
              targetPort: 8080
              exposure: public
              protocol: http
              annotation:
                hardening.weebo.io/endpoint-auth: "managed"
                hardening.weebo.io/rules: "open:/healthz"
            - name: api
              targetPort: 8081
              exposure: public
              protocol: http
FIXTURE
  # The workspace pod crash-loops: nginx cannot run as the user DWO injects. The routing objects
  # are created during startup regardless, and they are the whole point — so this waits for the
  # objects rather than for a phase that will never be Running.
  i=0
  while [ "$i" -lt 60 ]; do
    count=$(kubectl -n weebo-spike-ws get ingress -l controller.devfile.io/devworkspace_id \
      -o json 2>/dev/null | jq '.items | length')
    [ "${count:-0}" -ge 2 ] && break
    i=$((i + 1))
    sleep 2
  done
  printf 'routing objects: %s\n' "${count:-0}"
  printf '\nrig up. now: scripts/spike-0009.sh --live\n'
}

down() {
  kind delete cluster --name "$CLUSTER"
}

# The six lines that make community haproxy-ingress satisfy the forward-auth contract, and the
# reason RFC 0009 calls them a *prerequisite* rather than part of the dialect: they live in the
# controller's own ConfigMap, which belongs to whoever installed the controller. An annotation
# cannot do this job — a per-ingress `config-backend` snippet is emitted *after* the auth call in
# the generated configuration, so it changes what the application sees and never what the gate was
# asked. Proven, both ways, by row 5 of scripts/spike-0009.sh.
PREREQUISITE='http-request del-header X-Auth-Request-User
http-request del-header X-Auth-Request-Groups
http-request del-header X-Auth-Request-Email
http-request set-header X-Forwarded-Host %[req.hdr(host)]
http-request set-header X-Forwarded-Uri %[pathq]
http-request set-header X-Forwarded-Method %[method]'

prerequisite() { # prerequisite on|off
  cm=$(kubectl -n haproxy get cm -o name 2>/dev/null | grep haproxy-ingress | head -1)
  [ -n "$cm" ] || { printf 'no haproxy-ingress ConfigMap in namespace haproxy\n' >&2; exit 1; }
  case "${1:-}" in
    on) value="$PREREQUISITE" ;;
    off) value="" ;;
    *) printf 'usage: %s prerequisite on|off\n' "$0" >&2; exit 2 ;;
  esac
  kubectl -n haproxy patch "$cm" --type merge \
    -p "$(printf '%s' "$value" | jq -R -s '{data: {"config-frontend": .}}')" >/dev/null
  printf 'haproxy-ingress prerequisite: %s (give it ~20s to reload)\n' "$1"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  prerequisite) prerequisite "${2:-}" ;;
  *) printf 'usage: %s up|down|prerequisite on|off\n' "$0" >&2; exit 2 ;;
esac
