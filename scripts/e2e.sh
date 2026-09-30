#!/bin/sh
# The nightly end-to-end rig: a kind cluster running real Eclipse Che, real DevWorkspace Operator,
# a real identity provider, and this repo's own images and charts on top — the one tier where a
# workspace actually starts, a NetworkPolicy actually drops a packet and a browser-shaped request
# actually crosses an ingress controller. Everything below it (unit, envtest, conformance) proves
# the code; this proves the code meets the platform it was written for.
#
#   scripts/e2e.sh build                 build every image the suites need, tagged :e2e
#   scripts/e2e.sh up [suite]            cluster + ingress + Keycloak + cert-manager + DWO + Che
#                                        (`up kubearmor` also gives the node a working AppArmor)
#   scripts/e2e.sh addons <suite>        what one suite needs on top (kubearmor, identity, ...)
#   scripts/e2e.sh deploy <suite>        load the :e2e images, install the charts for one suite
#   scripts/e2e.sh diag [dir]            dump every pod, event and log worth reading after a failure
#   scripts/e2e.sh down                  delete the cluster and the CA
#
# Suites: workspace | kubearmor | endpoint-auth | identity. `task e2e SUITE=<suite>` runs the
# whole sequence plus the Rust suite of the same name (crates/weebo-si-e2e/tests/<suite>.rs).
#
# **Every upstream is pinned**, unlike the spike rig this grew out of (scripts/spike-0009-che.sh):
# a nightly that floats on `latest` fails on somebody else's release and reads as ours. Bumping a
# pin is a one-line diff here; `docs/ci.md` *Known gaps* records what cannot be pinned by digest.
#
# Runs under docker (CI) or rootless podman (a laptop): E2E_RUNTIME picks, and defaults to
# whichever is installed, docker first.
set -eu

CLUSTER=weebo-e2e
DOMAIN=127.0.0.1.nip.io
SSO_HOST="sso.$DOMAIN"
ISSUER="https://$SSO_HOST/realms/che"
STATE=/tmp/weebo-si-e2e
NAMESPACE=weebo-si-hardening
REPO_ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)

# --- pins -------------------------------------------------------------------------------------------
INGRESS_NGINX_CHART=4.15.1
CERT_MANAGER_VERSION=v1.21.2
KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:26.4
DWO_VERSION=v0.43.0
CHE_OPERATOR_VERSION=7.122.0
KUBEARMOR_VERSION=v1.7.4
KUBE_RBAC_PROXY_IMAGE=quay.io/brancz/kube-rbac-proxy
KUBE_RBAC_PROXY_TAG=v0.23.0
ARGOCD_VERSION=v3.5.3
AUTHENTIK_IMAGE=ghcr.io/goauthentik/server:2026.5.7
WEEBO_AUTHENTIK_CHART=0.15.0
POSTGRES_IMAGE=docker.io/library/postgres:16-alpine
REDIS_IMAGE=docker.io/library/redis:7-alpine
NGINX_IMAGE=docker.io/nginxinc/nginx-unprivileged:1.29-alpine

if [ -z "${E2E_RUNTIME:-}" ]; then
  if command -v docker >/dev/null 2>&1; then E2E_RUNTIME=docker; else E2E_RUNTIME=podman; fi
fi
KIND_EXPERIMENTAL_PROVIDER=$E2E_RUNTIME
export KIND_EXPERIMENTAL_PROVIDER

say() { printf '==> %s\n' "$*"; }
die() { printf 'e2e: %s\n' "$*" >&2; exit 1; }

need() {
  for tool in "$@"; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
  done
}

# Poll `$2` (a shell command string) until it succeeds or `$1` seconds pass.
wait_for() {
  deadline=$(( $(date +%s) + $1 ))
  while ! sh -c "$2" >/dev/null 2>&1; do
    [ "$(date +%s)" -lt "$deadline" ] || die "timed out after $1s waiting for: $2"
    sleep 5
  done
}

# Run a command up to three times: GitHub's release downloads and the chart repos answer the
# occasional 5xx, and a nightly that dies on one reads as ours.
retry() {
  for attempt in 1 2 3; do
    "$@" && return 0
    [ "$attempt" -lt 3 ] || return 1
    printf 'e2e: attempt %s failed, retrying: %s\n' "$attempt" "$1" >&2
    sleep 15
  done
}

# --- one certificate authority for the whole rig ------------------------------------------------------
#
# Keycloak's certificate, every Ingress certificate cert-manager issues (`ClusterIssuer e2e-ca`)
# and the bundle the endpoint gateway trusts through `extraCa` all chain to this one root, and the
# Rust suites trust it too (E2E_CA_FILE). One root is what makes "the gateway can reach a private
# issuer" a property the suite exercises rather than a flag it turns off.

make_ca() {
  mkdir -p "$STATE"
  [ -f "$STATE/ca.crt" ] && return 0
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -subj "/CN=weebo-si e2e CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$STATE/ca.key" -out "$STATE/ca.crt" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$SSO_HOST" \
    -keyout "$STATE/sso.key" -out "$STATE/sso.csr" 2>/dev/null
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$SSO_HOST" > "$STATE/sso.ext"
  openssl x509 -req -in "$STATE/sso.csr" -days 30 \
    -CA "$STATE/ca.crt" -CAkey "$STATE/ca.key" -CAcreateserial \
    -extfile "$STATE/sso.ext" -out "$STATE/sso.crt" 2>/dev/null
}

# --- the realm ----------------------------------------------------------------------------------------
#
# Three people in two teams, so every "may this person open that endpoint" row has a subject who
# may and one who may not: alice and carol share team-payments, bob is alone in team-data.
# Passwords equal usernames; nothing here outlives the cluster.

realm_user() {
  # $1 username, $2 group
  cat <<USER
    {
      "username": "$1", "email": "$1@weebo.si", "emailVerified": true, "enabled": true,
      "firstName": "$1", "lastName": "E2E",
      "credentials": [{ "type": "password", "value": "$1", "temporary": false }],
      "groups": ["/$2"]
    }
USER
}

groups_mapper() {
  cat <<'MAPPER'
        {
          "name": "groups", "protocol": "openid-connect",
          "protocolMapper": "oidc-group-membership-mapper",
          "config": { "claim.name": "groups", "full.path": "false", "access.token.claim": "true",
                      "id.token.claim": "true", "userinfo.token.claim": "true" }
        }
MAPPER
}

realm_json() {
  cat <<REALM
{
  "realm": "che",
  "enabled": true,
  "sslRequired": "none",
  "groups": [{ "name": "team-payments" }, { "name": "team-data" }],
  "users": [
$(realm_user alice team-payments),
$(realm_user bob team-data),
$(realm_user carol team-payments)
  ],
  "clients": [
    {
      "clientId": "che-client", "enabled": true, "publicClient": false,
      "secret": "che-client-secret", "standardFlowEnabled": true,
      "directAccessGrantsEnabled": true, "redirectUris": ["*"], "webOrigins": ["*"],
      "protocolMappers": [
        {
          "name": "kubernetes-audience", "protocol": "openid-connect",
          "protocolMapper": "oidc-audience-mapper",
          "config": { "included.client.audience": "kubernetes", "access.token.claim": "true",
                      "id.token.claim": "true" }
        },
$(groups_mapper)
      ]
    },
    {
      "clientId": "endpoint-gateway", "enabled": true, "publicClient": false,
      "secret": "endpoint-gateway-secret", "standardFlowEnabled": true,
      "directAccessGrantsEnabled": true, "serviceAccountsEnabled": true,
      "redirectUris": ["*"], "webOrigins": ["*"],
      "attributes": { "backchannel.logout.session.required": "true" },
      "protocolMappers": [
        {
          "name": "gateway-audience", "protocol": "openid-connect",
          "protocolMapper": "oidc-audience-mapper",
          "config": { "included.client.audience": "endpoint-gateway",
                      "access.token.claim": "true" }
        },
$(groups_mapper)
      ]
    },
    { "clientId": "kubernetes", "enabled": true, "publicClient": true,
      "standardFlowEnabled": true, "redirectUris": ["*"] }
  ]
}
REALM
}

install_sso() {
  kubectl create namespace sso --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n sso create secret tls sso-tls --cert="$STATE/sso.crt" --key="$STATE/sso.key" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  realm_json > "$STATE/realm.json"
  jq -e . "$STATE/realm.json" >/dev/null || die "the generated realm is not valid JSON"
  kubectl -n sso create configmap realm --from-file=che-realm.json="$STATE/realm.json" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl apply -f - >/dev/null <<MANIFEST
apiVersion: apps/v1
kind: Deployment
metadata: { name: keycloak, namespace: sso }
spec:
  replicas: 1
  selector: { matchLabels: { app: keycloak } }
  template:
    metadata: { labels: { app: keycloak } }
    spec:
      containers:
        - name: keycloak
          image: $KEYCLOAK_IMAGE
          args: ["start-dev", "--import-realm"]
          env:
            - { name: KC_BOOTSTRAP_ADMIN_USERNAME, value: admin }
            - { name: KC_BOOTSTRAP_ADMIN_PASSWORD, value: admin }
            - { name: KC_HTTP_ENABLED, value: "true" }
            - { name: KC_HOSTNAME, value: "https://$SSO_HOST" }
            - { name: KC_HOSTNAME_STRICT, value: "false" }
            - { name: KC_PROXY_HEADERS, value: xforwarded }
          ports: [{ containerPort: 8080 }]
          volumeMounts: [{ name: realm, mountPath: /opt/keycloak/data/import }]
          readinessProbe:
            httpGet: { path: /realms/che/.well-known/openid-configuration, port: 8080 }
            initialDelaySeconds: 20
            periodSeconds: 5
            failureThreshold: 60
      volumes: [{ name: realm, configMap: { name: realm } }]
---
apiVersion: v1
kind: Service
metadata: { name: keycloak, namespace: sso }
spec:
  selector: { app: keycloak }
  ports: [{ name: http, port: 8080, targetPort: 8080 }]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: keycloak
  namespace: sso
  annotations: { nginx.ingress.kubernetes.io/proxy-buffer-size: 16k }
spec:
  ingressClassName: nginx
  tls: [{ hosts: ["$SSO_HOST"], secretName: sso-tls }]
  rules:
    - host: $SSO_HOST
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: { service: { name: keycloak, port: { number: 8080 } } }
MANIFEST
  kubectl -n sso rollout status deploy/keycloak --timeout=900s >/dev/null
}

# See scripts/spike-0009-che.sh for why each of these two exists: pods resolve every
# `*.127.0.0.1.nip.io` name to the ingress controller through CoreDNS, and the apiserver — on the
# node's own network namespace, where cluster DNS does not exist — through /etc/hosts.
cluster_dns() {
  kubectl -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}' > "$STATE/Corefile"
  sed -i '/rewrite stop {/,/^ *}/d' "$STATE/Corefile"
  awk '
    /^[[:space:]]*kubernetes / && !done {
      print "        rewrite stop {"
      print "          name regex ^(.*\\.)?127\\.0\\.0\\.1\\.nip\\.io\\.?$ ingress-nginx-controller.ingress-nginx.svc.cluster.local"
      print "          answer auto"
      print "        }"
      done = 1
    }
    { print }
  ' "$STATE/Corefile" > "$STATE/Corefile.new"
  kubectl -n kube-system create configmap coredns --from-file=Corefile="$STATE/Corefile.new" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n kube-system rollout restart deploy/coredns >/dev/null
  kubectl -n kube-system rollout status deploy/coredns --timeout=180s >/dev/null
}

node_hosts() {
  ip=$(kubectl -n ingress-nginx get svc ingress-nginx-controller -o jsonpath='{.spec.clusterIP}')
  [ -n "$ip" ] || die "no ingress-nginx ClusterIP yet"
  "$E2E_RUNTIME" exec "$CLUSTER-control-plane" sh -c \
    "grep -v ' $SSO_HOST\$' /etc/hosts > /tmp/hosts.new && cat /tmp/hosts.new > /etc/hosts && echo '$ip $SSO_HOST' >> /etc/hosts"
}

install_cert_manager() {
  kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.yaml" >/dev/null
  for deploy in cert-manager cert-manager-webhook cert-manager-cainjector; do
    kubectl -n cert-manager rollout status "deploy/$deploy" --timeout=300s >/dev/null
  done
  kubectl -n cert-manager create secret tls e2e-ca --cert="$STATE/ca.crt" --key="$STATE/ca.key" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  # The webhook answers before it is ready to validate, so the first ClusterIssuer can bounce.
  wait_for 180 "kubectl apply -f - <<'ISSUER'
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata: { name: e2e-ca }
spec: { ca: { secretName: e2e-ca } }
ISSUER"
}

# `*.127.0.0.1.nip.io` from the rig CA, in the two places that serve it: ingress-nginx's default
# certificate, and Che's own `tlsSecretName`.
wildcard_certificate() {
  for ns in ingress-nginx eclipse-che; do
    kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
    kubectl apply -f - >/dev/null <<CERT
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: wildcard, namespace: $ns }
spec:
  secretName: $( [ "$ns" = eclipse-che ] && echo che-tls || echo wildcard-tls )
  issuerRef: { name: e2e-ca, kind: ClusterIssuer }
  dnsNames: ["$DOMAIN", "*.$DOMAIN"]
  secretTemplate:
    labels: { app.kubernetes.io/part-of: che.eclipse.org }
CERT
    kubectl -n "$ns" wait certificate/wildcard --for=condition=Ready --timeout=180s >/dev/null
  done
}

install_che() {
  kubectl create namespace devworkspace-controller --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl apply -f "https://raw.githubusercontent.com/devfile/devworkspace-operator/$DWO_VERSION/deploy/deployment/kubernetes/combined.yaml" >/dev/null
  kubectl -n devworkspace-controller rollout status deploy/devworkspace-controller-manager --timeout=600s >/dev/null
  wait_for 300 "kubectl -n devworkspace-controller get endpoints devworkspace-controller-manager-service -o jsonpath='{.subsets[0].addresses[0].ip}' | grep -q ."
  # DWO defaults every workspace container to `imagePullPolicy: Always`, which sends kubelet to
  # https://localhost/v2/ for the `localhost/…:e2e` images `kind load` already put on the node.
  # The global config is what every other DWOC — Che's own, and the suites' — is merged over.
  wait_for 120 "kubectl apply -f - <<'DWOC'
apiVersion: controller.devfile.io/v1alpha1
kind: DevWorkspaceOperatorConfig
metadata: { name: devworkspace-operator-config, namespace: devworkspace-controller }
config: { workspace: { imagePullPolicy: IfNotPresent } }
DWOC"

  kubectl create namespace eclipse-che --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  # Server-side: the CheCluster CRD is larger than a client-side apply's annotation can hold.
  kubectl apply --server-side --force-conflicts \
    -f "https://raw.githubusercontent.com/eclipse-che/che-operator/$CHE_OPERATOR_VERSION/deploy/deployment/kubernetes/combined.yaml" >/dev/null
  kubectl -n eclipse-che rollout status deploy/che-operator --timeout=600s >/dev/null
  kubectl -n eclipse-che create configmap e2e-ca-bundle --from-file=e2e-ca.crt="$STATE/ca.crt" \
    --dry-run=client -o yaml |
    kubectl label -f - --local -o yaml \
      app.kubernetes.io/part-of=che.eclipse.org app.kubernetes.io/component=ca-bundle |
    kubectl apply -f - >/dev/null
  kubectl apply -f - >/dev/null <<SECRET
apiVersion: v1
kind: Secret
metadata:
  name: che-oauth-secret
  namespace: eclipse-che
  labels: { app.kubernetes.io/part-of: che.eclipse.org }
stringData: { oAuthSecret: che-client-secret }
SECRET
  wait_for 300 "kubectl apply -f - <<CLUSTER
apiVersion: org.eclipse.che/v2
kind: CheCluster
metadata: { name: eclipse-che, namespace: eclipse-che }
spec:
  networking:
    domain: $DOMAIN
    tlsSecretName: che-tls
    auth:
      identityProviderURL: '$ISSUER'
      oAuthClientName: che-client
      oAuthSecret: che-oauth-secret
      identityToken: id_token
  devEnvironments:
    defaultNamespace: { autoProvision: true, template: <username>-che }
    storage: { pvcStrategy: per-workspace }
    imagePullPolicy: IfNotPresent
CLUSTER"
  say "waiting for Che to become Active (this pulls several GB)"
  wait_for 1800 "kubectl -n eclipse-che get checluster eclipse-che -o jsonpath='{.status.chePhase}' | grep -qx Active"
}

# A kind node cannot enforce AppArmor out of the box, and KubeArmor on a runner kernel without
# BPF-LSM has nothing else: the node's /sys/kernel/security is an empty directory rather than the
# host's securityfs, and containerd applies no profile unless `apparmor_parser` exists (the node
# image ships none) and its own environment has no `container=` (the node image sets one). So the
# kubearmor suite's node gets the host's securityfs bound in, the parser installed, the variable
# unset for containerd, and containerd restarted to re-probe — it decides once, at start.
kind_config() {
  if [ "${1:-}" != kubearmor ]; then
    printf '%s\n' "$REPO_ROOT/scripts/kind-e2e.yaml"
    return 0
  fi
  cat "$REPO_ROOT/scripts/kind-e2e.yaml" - > "$STATE/kind-e2e.yaml" <<'MOUNT'
      - hostPath: /sys/kernel/security
        containerPath: /sys/kernel/security
MOUNT
  printf '%s\n' "$STATE/kind-e2e.yaml"
}

node_apparmor() {
  node="$CLUSTER-control-plane"
  "$E2E_RUNTIME" exec "$node" test -d /sys/kernel/security/apparmor ||
    die "the host's securityfs has no AppArmor: this runner cannot enforce with it"
  # policy-rc.d keeps the package from starting apparmor.service, which would load Debian's own
  # profiles into the host kernel.
  #
  # Debian 12's parser is pinned to an old feature set, and containerd's generated default profile
  # has no `unix` rule: loaded into the runner's newer kernel, it refuses every unix socket, and
  # nginx cannot even start its workers ("socketpair() failed … Permission denied"). So the pin
  # goes, and a permissive `cri-containerd.apparmor.d` is loaded before containerd restarts —
  # containerd only generates that profile when none of the name is loaded. Every pod KubeArmor
  # does not select runs under it; the profiles the suite asserts on are KubeArmor's own.
  "$E2E_RUNTIME" exec -i "$node" sh -c 'cat > /etc/apparmor.d/cri-containerd.apparmor.d' <<'PROFILE'
#include <tunables/global>
profile cri-containerd.apparmor.d flags=(attach_disconnected,mediate_deleted) {
  capability,
  network,
  unix,
  file,
  mount,
  remount,
  umount,
  pivot_root,
  ptrace,
  signal,
  dbus,
  change_profile -> **,
}
PROFILE
  "$E2E_RUNTIME" exec "$node" sh -c '
    printf "#!/bin/sh\nexit 101\n" > /usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d &&
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends apparmor >/dev/null &&
    rm -f /usr/sbin/policy-rc.d &&
    sed -i "/^policy-features=/d" /etc/apparmor/parser.conf &&
    apparmor_parser -r /etc/apparmor.d/cri-containerd.apparmor.d &&
    mkdir -p /etc/systemd/system/containerd.service.d &&
    printf "[Service]\nUnsetEnvironment=container\n" > /etc/systemd/system/containerd.service.d/apparmor.conf &&
    systemctl daemon-reload && systemctl restart containerd' ||
    die "could not install apparmor on the node"
  # The four conditions containerd's own probe checks, and our profile in place of its own, so a node that still cannot apply a profile
  # stops the rig here rather than as a pod refused three steps later.
  # shellcheck disable=SC2016 # expanded on the node, not here
  "$E2E_RUNTIME" exec "$node" sh -c '
    test -d /sys/kernel/security/apparmor && test -x /sbin/apparmor_parser &&
    grep -q "^Y" /sys/module/apparmor/parameters/enabled &&
    grep -q "^cri-containerd.apparmor.d " /sys/kernel/security/apparmor/profiles &&
    ! tr "\0" "\n" < /proc/$(pidof containerd)/environ | grep -q "^container="' ||
    die "the node still cannot apply AppArmor profiles"
  wait_for 120 "kubectl get nodes -o jsonpath='{.items[0].status.conditions[?(@.type==\"Ready\")].status}' | grep -qx True"
}

up() {
  suite=${1:-}
  need kind kubectl helm jq openssl curl "$E2E_RUNTIME"
  make_ca
  if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    kind create cluster --config "$(kind_config "$suite")" --wait 300s
  fi
  kubectl config use-context "kind-$CLUSTER" >/dev/null
  if [ "$suite" = kubearmor ]; then
    say "AppArmor on the node"
    node_apparmor
  fi

  say "cert-manager $CERT_MANAGER_VERSION"
  install_cert_manager
  say "a wildcard certificate for every rig host"
  wildcard_certificate

  say "ingress-nginx $INGRESS_NGINX_CHART"
  # ClusterIP and no hostPort — see scripts/kind-che.yaml, point 3. Two workers because rootless
  # podman's pids limit stops `worker_processes auto` coming up. The default certificate is the
  # rig's wildcard, so a workspace Ingress Che writes without a TLS secret of its own still chains
  # to the one CA the suites trust.
  retry helm upgrade --install ingress-nginx ingress-nginx \
    --repo https://kubernetes.github.io/ingress-nginx --version "$INGRESS_NGINX_CHART" \
    -n ingress-nginx --create-namespace \
    --set controller.service.type=ClusterIP \
    --set controller.ingressClassResource.default=true \
    --set controller.config.worker-processes="2" \
    --set controller.allowSnippetAnnotations=false \
    --set controller.admissionWebhooks.enabled=false \
    --set controller.extraArgs.default-ssl-certificate=ingress-nginx/wildcard-tls \
    --wait --timeout 10m >/dev/null
  cluster_dns
  node_hosts

  say "Keycloak ($KEYCLOAK_IMAGE)"
  install_sso
  say "DevWorkspace Operator $DWO_VERSION and Eclipse Che $CHE_OPERATOR_VERSION"
  install_che
  say "Che is Active on https://eclipse-che.$DOMAIN"
}

# --- addons -------------------------------------------------------------------------------------------

addon_kubearmor() {
  say "KubeArmor $KUBEARMOR_VERSION"
  # The chart floats every image on `stable`/`latest` and points kube-rbac-proxy at the retired
  # gcr.io/kubebuilder registry, so each image is pinned here; the relay is only a log fan-out
  # and has no image at this version, so it is off.
  retry helm upgrade --install kubearmor kubearmor \
    --repo https://kubearmor.github.io/charts --version "$KUBEARMOR_VERSION" \
    -n kubearmor --create-namespace \
    --set kubearmor.image.tag="$KUBEARMOR_VERSION" \
    --set kubearmorInit.image.tag="$KUBEARMOR_VERSION" \
    --set kubearmorController.image.tag="$KUBEARMOR_VERSION" \
    --set kubeRbacProxy.image.repository="$KUBE_RBAC_PROXY_IMAGE" \
    --set kubeRbacProxy.image.tag="$KUBE_RBAC_PROXY_TAG" \
    --set kubearmorRelay.enabled=false >/dev/null
  # The controller's pod securityContext hard-codes `runAsNonRoot` with no `runAsUser`, and the
  # $KUBEARMOR_VERSION controller image ships without a numeric USER (`stable` has 1000), so the
  # kubelet refuses it. The chart has no knob for it: give the pod the UID the image should declare.
  kubectl -n kubearmor patch deploy/kubearmor-controller --type=merge \
    -p '{"spec":{"template":{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":1000,"runAsGroup":1000}}}}}' >/dev/null
  kubectl -n kubearmor rollout status deploy/kubearmor-controller --timeout=900s >/dev/null
  kubectl -n kubearmor rollout status ds/kubearmor --timeout=900s >/dev/null
  # `kubearmor.io/enforcer` is written by KubeArmor's operator (its snitch job), which this chart
  # does not ship; kubearmor-controller only injects profiles into pods on a node so labelled. It
  # is set here to what the snitch would write — and only once the node's own kubelet and
  # containerd can apply the profile (`node_apparmor`), since a label the node cannot honour gets
  # every new pod refused with "AppArmor is not enabled on the host".
  wait_for 120 "kubectl -n kubearmor logs ds/kubearmor -c kubearmor | grep -q 'Initialized KubeArmor Enforcer'"
  if "$E2E_RUNTIME" exec "$CLUSTER-control-plane" test -x /sbin/apparmor_parser &&
    kubectl -n kubearmor logs ds/kubearmor -c kubearmor | grep -q 'Initialized AppArmor Enforcer'; then
    kubectl label nodes --all kubearmor.io/enforcer=apparmor --overwrite >/dev/null
  fi
  # Which enforcer the node ended up with is what the suite asserts against; print it here so a
  # failed run's log says it without anybody opening the diagnostics.
  printf 'kubearmor enforcer: %s\n' \
    "$(kubectl get nodes -o jsonpath='{.items[0].metadata.labels.kubearmor\.io/enforcer}')"
}

# Authentik the way weebo-authentik's own E2E runs it (bootstrap token, no setup wizard), but as
# in-cluster Deployments rather than docker compose, so the operator reaches it by Service name.
addon_authentik() {
  say "Authentik ($AUTHENTIK_IMAGE)"
  kubectl create namespace authentik --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl apply -f - >/dev/null <<MANIFEST
apiVersion: v1
kind: Secret
metadata: { name: authentik-env, namespace: authentik }
stringData:
  AUTHENTIK_SECRET_KEY: e2e-only-not-a-real-secret-key-0123456789
  AUTHENTIK_REDIS__HOST: redis
  AUTHENTIK_POSTGRESQL__HOST: postgresql
  AUTHENTIK_POSTGRESQL__USER: authentik
  AUTHENTIK_POSTGRESQL__NAME: authentik
  AUTHENTIK_POSTGRESQL__PASSWORD: e2e-only-not-a-real-secret
  AUTHENTIK_BOOTSTRAP_EMAIL: akadmin@e2e.local
  AUTHENTIK_BOOTSTRAP_PASSWORD: e2e-only-not-a-real-secret
  AUTHENTIK_BOOTSTRAP_TOKEN: e2e-bootstrap-token-not-a-real-secret
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: postgresql, namespace: authentik }
spec:
  selector: { matchLabels: { app: postgresql } }
  template:
    metadata: { labels: { app: postgresql } }
    spec:
      containers:
        - name: postgresql
          image: $POSTGRES_IMAGE
          env:
            - { name: POSTGRES_DB, value: authentik }
            - { name: POSTGRES_USER, value: authentik }
            - { name: POSTGRES_PASSWORD, value: e2e-only-not-a-real-secret }
          readinessProbe: { exec: { command: [pg_isready, -d, authentik, -U, authentik] } }
---
apiVersion: v1
kind: Service
metadata: { name: postgresql, namespace: authentik }
spec: { selector: { app: postgresql }, ports: [{ port: 5432 }] }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: redis, namespace: authentik }
spec:
  selector: { matchLabels: { app: redis } }
  template:
    metadata: { labels: { app: redis } }
    spec:
      containers: [{ name: redis, image: $REDIS_IMAGE }]
---
apiVersion: v1
kind: Service
metadata: { name: redis, namespace: authentik }
spec: { selector: { app: redis }, ports: [{ port: 6379 }] }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: authentik-server, namespace: authentik }
spec:
  selector: { matchLabels: { app: authentik-server } }
  template:
    metadata: { labels: { app: authentik-server } }
    spec:
      containers:
        - name: server
          image: $AUTHENTIK_IMAGE
          args: [server]
          envFrom: [{ secretRef: { name: authentik-env } }]
          ports: [{ containerPort: 9000 }]
          readinessProbe:
            exec: { command: [ak, healthcheck] }
            periodSeconds: 10
            failureThreshold: 90
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: authentik-worker, namespace: authentik }
spec:
  selector: { matchLabels: { app: authentik-worker } }
  template:
    metadata: { labels: { app: authentik-worker } }
    spec:
      containers:
        - name: worker
          image: $AUTHENTIK_IMAGE
          args: [worker]
          envFrom: [{ secretRef: { name: authentik-env } }]
---
apiVersion: v1
kind: Service
metadata: { name: authentik-server, namespace: authentik }
spec: { selector: { app: authentik-server }, ports: [{ name: http, port: 9000 }] }
MANIFEST
  kubectl -n authentik rollout status deploy/authentik-server --timeout=1200s >/dev/null

  say "weebo-authentik $WEEBO_AUTHENTIK_CHART"
  # The chart defaults the image tag to its bare appVersion (0.15.0), but the operator image is
  # only ever published with a `v` prefix (v0.15.0) — so the tag is set explicitly.
  retry helm upgrade --install weebo-authentik oci://ghcr.io/batleforc/charts/weebo-authentik \
    --version "$WEEBO_AUTHENTIK_CHART" -n weebo-authentik --create-namespace \
    --set image.tag="v$WEEBO_AUTHENTIK_CHART" \
    --set replicaCount=1 --set podDisruptionBudget.enabled=false \
    --set certManager.createIssuer=false \
    --set certManager.issuerRef.name=e2e-ca --set certManager.issuerRef.kind=ClusterIssuer \
    --wait --timeout 10m >/dev/null
  kubectl apply -f - >/dev/null <<'INSTANCE'
apiVersion: v1
kind: Secret
metadata: { name: authentik-token, namespace: weebo-authentik }
stringData: { token: e2e-bootstrap-token-not-a-real-secret }
---
apiVersion: authentik.weebo.io/v1alpha1
kind: AuthentikInstance
metadata: { name: e2e }
spec:
  url: http://authentik-server.authentik.svc:9000/api/v3
  tokenSecretRef: { name: authentik-token, namespace: weebo-authentik, key: token }
INSTANCE
}

# Argo CD, one AppProject, and a Helm repository served from inside the cluster — so the
# Application the operator writes is synced from a chart this repo owns, with no dependency on a
# registry being reachable at 3 a.m.
addon_argocd() {
  say "Argo CD $ARGOCD_VERSION"
  kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl apply --server-side --force-conflicts -n argocd \
    -f "https://raw.githubusercontent.com/argoproj/argo-cd/$ARGOCD_VERSION/manifests/install.yaml" >/dev/null
  for deploy in argocd-server argocd-repo-server argocd-applicationset-controller; do
    kubectl -n argocd rollout status "deploy/$deploy" --timeout=600s >/dev/null
  done
  kubectl -n argocd rollout status statefulset/argocd-application-controller --timeout=600s >/dev/null

  say "the in-cluster chart repository"
  rm -rf "$STATE/charts" && mkdir -p "$STATE/charts"
  helm package "$REPO_ROOT/e2e/charts/che-user" -d "$STATE/charts" >/dev/null
  helm repo index "$STATE/charts" --url http://charts.charts.svc:8080 >/dev/null
  kubectl create namespace charts --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n charts create configmap charts --from-file="$STATE/charts" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl apply -f - >/dev/null <<MANIFEST
apiVersion: apps/v1
kind: Deployment
metadata: { name: charts, namespace: charts }
spec:
  selector: { matchLabels: { app: charts } }
  template:
    metadata: { labels: { app: charts } }
    spec:
      containers:
        - name: nginx
          image: $NGINX_IMAGE
          ports: [{ containerPort: 8080 }]
          volumeMounts: [{ name: charts, mountPath: /usr/share/nginx/html }]
      volumes: [{ name: charts, configMap: { name: charts } }]
---
apiVersion: v1
kind: Service
metadata: { name: charts, namespace: charts }
spec: { selector: { app: charts }, ports: [{ port: 8080 }] }
---
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata: { name: weebo-dev, namespace: argocd }
spec:
  sourceRepos: ["http://charts.charts.svc:8080"]
  destinations: [{ server: https://kubernetes.default.svc, namespace: "*-che" }]
  clusterResourceWhitelist: [{ group: "", kind: Namespace }]
MANIFEST
  kubectl -n charts rollout status deploy/charts --timeout=300s >/dev/null
}

addons() {
  case "${1:-}" in
    workspace | endpoint-auth) ;;
    kubearmor) addon_kubearmor ;;
    identity) addon_authentik; addon_argocd ;;
    *) die "addons: unknown suite '${1:-}' (workspace|kubearmor|endpoint-auth|identity)" ;;
  esac
}

# --- images -------------------------------------------------------------------------------------------

IMAGES="weebo-si-operator endpoint-gateway preauth-proxy passwd-append e2e-workspace"

build() {
  need "$E2E_RUNTIME"
  cd "$REPO_ROOT"
  # Tagged under `localhost/` so the name is the same whichever runtime built it: docker would
  # otherwise say `docker.io/library/…` and podman `localhost/…`, and the charts need one answer.
  "$E2E_RUNTIME" build -f crates/weebo-si-operator/Containerfile -t localhost/weebo-si-operator:e2e .
  "$E2E_RUNTIME" build -f bins/endpoint-gateway/Containerfile -t localhost/endpoint-gateway:e2e .
  "$E2E_RUNTIME" build -f bins/preauth-proxy/Containerfile -t localhost/preauth-proxy:e2e .
  "$E2E_RUNTIME" build -f bins/passwd-append/Containerfile -t localhost/passwd-append:e2e .
  # The workspace image adopts passwd-append exactly as docs/bricks/passwd-append.md says to, so a
  # wrong line in that page fails this build rather than a user's.
  "$E2E_RUNTIME" build -f e2e/images/workspace/Containerfile -t localhost/e2e-workspace:e2e \
    --build-arg PASSWD_APPEND_IMAGE=localhost/passwd-append:e2e e2e/images/workspace
}

load_images() {
  for image in $IMAGES; do
    if [ "$E2E_RUNTIME" = docker ]; then
      kind load docker-image "localhost/$image:e2e" --name "$CLUSTER" >/dev/null
    else
      # kind cannot read podman's store directly; an archive is the portable hand-over.
      "$E2E_RUNTIME" save -o "$STATE/$image.tar" "localhost/$image:e2e" >/dev/null
      kind load image-archive "$STATE/$image.tar" --name "$CLUSTER" >/dev/null
      rm -f "$STATE/$image.tar"
    fi
  done
}

# --- our charts ---------------------------------------------------------------------------------------

deploy_operator() {
  suite=$1
  set -- --set image.repository=localhost/weebo-si-operator --set image.tag=e2e \
    --set image.pullPolicy=Never
  case "$suite" in
    workspace) set -- "$@" --set registryConfig.rbac.enabled=true ;;
    kubearmor) set -- "$@" --set kubearmorPolicy.rbac.enabled=true ;;
    endpoint-auth) set -- "$@" --set endpointAuth.rbac.enabled=true --set endpointAuth.dialect=Nginx ;;
    identity) set -- "$@" --set identity.rbac.enabled=true --set identity.argoNamespace=argocd ;;
  esac
  # Helm needs the namespace to exist before it can store the release, and the chart's own
  # Namespace would then clash with it — so it is created here, pre-labelled out of the webhook's
  # scope before anything can be admitted, and the chart is told not to render one.
  kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl label namespace "$NAMESPACE" hardening.weebo.io/exclude=true --overwrite >/dev/null
  helm upgrade --install weebo-si-operator "$REPO_ROOT/charts/weebo-si-operator" \
    -n "$NAMESPACE" -f "$REPO_ROOT/e2e/values/weebo-si-operator.yaml" "$@" \
    --set namespace.create=false --wait --timeout 10m
  # `--wait` returns once the webhook pods are Ready, which can be before kube-proxy routes the
  # Service to them — and a suite's first write then meets `connection refused` under
  # `failurePolicy: Fail`. A server-side dry run takes the apiserver's own path to the webhook.
  cat > "$STATE/probe-devworkspace.yaml" <<'PROBE'
apiVersion: workspace.devfile.io/v1alpha2
kind: DevWorkspace
metadata: { name: e2e-webhook-probe, namespace: default }
spec: { started: false, template: {} }
PROBE
  wait_for 180 "! kubectl apply --dry-run=server -f '$STATE/probe-devworkspace.yaml' 2>&1 | grep -q 'failed calling webhook'"
}

deploy_gateway() {
  kubectl -n "$NAMESPACE" create secret generic endpoint-gateway-session-keys \
    --from-literal=keys="$(openssl rand -base64 32)" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n "$NAMESPACE" create secret generic endpoint-gateway-oidc \
    --from-literal=client-secret=endpoint-gateway-secret --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n "$NAMESPACE" create configmap e2e-ca --from-file=ca.crt="$STATE/ca.crt" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  helm upgrade --install endpoint-gateway "$REPO_ROOT/charts/endpoint-gateway" \
    -n "$NAMESPACE" -f "$REPO_ROOT/e2e/values/endpoint-gateway.yaml" \
    --set image.repository=localhost/endpoint-gateway --set image.tag=e2e \
    --set image.pullPolicy=Never --wait --timeout 10m
}

deploy() {
  suite=${1:-}
  case "$suite" in
    workspace | kubearmor | endpoint-auth | identity) ;;
    *) die "deploy: unknown suite '$suite'" ;;
  esac
  kubectl config use-context "kind-$CLUSTER" >/dev/null
  say "loading the :e2e images"
  load_images
  say "weebo-si-operator (suite $suite)"
  deploy_operator "$suite"
  if [ "$suite" = endpoint-auth ]; then
    say "endpoint-gateway"
    deploy_gateway
  fi
}

# --- after a failure ----------------------------------------------------------------------------------

diag() {
  out=${1:-$STATE/diag}
  mkdir -p "$out"
  kubectl get nodes -o wide > "$out/nodes.txt" 2>&1 || true
  kubectl get pods -A -o wide > "$out/pods.txt" 2>&1 || true
  kubectl get events -A --sort-by=.lastTimestamp > "$out/events.txt" 2>&1 || true
  kubectl get weebosiconfigs,weebositeams,weebosiusers -o yaml > "$out/weebo-objects.yaml" 2>&1 || true
  kubectl get devworkspaces -A -o yaml > "$out/devworkspaces.yaml" 2>&1 || true
  kubectl get checluster -A -o yaml > "$out/checluster.yaml" 2>&1 || true
  kubectl get networkpolicies,ingresses -A -o yaml > "$out/networking.yaml" 2>&1 || true
  # AppArmor denials land in the host kernel's log, not in any pod's — the one place a profile
  # refusing a process explains itself.
  { sudo -n dmesg 2>/dev/null || dmesg 2>/dev/null; } | grep -i apparmor | tail -n 500 > "$out/dmesg-apparmor.txt" || true
  for ns in "$NAMESPACE" eclipse-che devworkspace-controller sso kubearmor authentik weebo-authentik argocd \
    ingress-nginx kube-system; do
    kubectl get namespace "$ns" >/dev/null 2>&1 || continue
    for pod in $(kubectl -n "$ns" get pods -o name 2>/dev/null); do
      kubectl -n "$ns" logs "$pod" --all-containers --prefix --tail=2000 \
        > "$out/logs-$ns-$(basename "$pod").txt" 2>&1 || true
    done
  done
  printf 'diagnostics in %s\n' "$out"
}

down() {
  kind delete cluster --name "$CLUSTER"
  rm -rf "$STATE"
}

case "${1:-}" in
  build) build ;;
  up) up "${2:-}" ;;
  addons) addons "${2:-}" ;;
  deploy) deploy "${2:-}" ;;
  diag) diag "${2:-}" ;;
  down) down ;;
  *) printf 'usage: %s build|up [suite]|addons <suite>|deploy <suite>|diag [dir]|down\n' "$0" >&2; exit 2 ;;
esac
