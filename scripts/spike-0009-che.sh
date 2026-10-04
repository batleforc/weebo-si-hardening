#!/bin/sh
# An Eclipse Che installation on kind, for the three rows of RFC 0009's ground-truth spike that
# only a Che cluster can answer: the label Che puts on a user namespace, the OIDC client's
# discovery document, and the shape of a token a developer can fetch.
#
#   scripts/spike-0009-che.sh up      build it (slow: several GB of images)
#   scripts/spike-0009-che.sh token   print an access token for the test user
#   scripts/spike-0009-che.sh rows    run the three rows against it
#   scripts/spike-0009-che.sh down    delete the cluster
#
# **What this can and cannot stand in for.** Row 2 is Che's own behaviour and transfers: the label
# Che stamps on a user namespace is the same label whoever installed Che did not choose. Rows 7
# and 8 are about *your identity provider*, and this rig runs a Keycloak realm that this script
# wrote — so what they establish here is "the gateway's assumptions hold against a Keycloak realm
# shaped like Che's", which is worth knowing and is not the same claim as "they hold against
# yours". Run them again on the real cluster; that is why `scripts/spike-0009.sh` takes
# `--issuer` and `--token` rather than hard-coding anything.
#
# Keycloak rather than Dex, which is the usual choice for Che on kind, for exactly that reason:
# Dex has no back-channel logout and no refresh-token grant for this shape of client, so row 7
# would report a difference that says something about Dex and nothing about the design.
set -eu

CLUSTER=weebo-che
# Traefik chart 41.6.1 is Traefik v3.7.13.
TRAEFIK_CHART=41.6.1
DOMAIN=127.0.0.1.nip.io
SSO_HOST="sso.$DOMAIN"
ISSUER="https://$SSO_HOST/realms/che"
# The rig's certificate authority outlives a run on purpose: the kind node bind-mounts it when the
# cluster is created and `up` re-reads it on every re-run. `down` deletes it.
STATE=${SPIKE_CHE_STATE:-${TMPDIR:-/tmp}/weebo-si-che}
REPO_ROOT=$(unset CDPATH; cd -- "$(dirname -- "$0")/.." && pwd)
KIND_EXPERIMENTAL_PROVIDER="${KIND_EXPERIMENTAL_PROVIDER:-podman}"
export KIND_EXPERIMENTAL_PROVIDER

for tool in kind kubectl helm jq openssl curl; do
  command -v "$tool" >/dev/null 2>&1 || { printf '%s is required\n' "$tool" >&2; exit 2; }
done

# Everything else a run writes (the realm, the Corefile, the test user's token) lives in a per-run
# directory, removed on exit along with any port-forward left running.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/weebo-si-che-run.XXXXXX")
# shellcheck disable=SC2317,SC2329  # invoked from the EXIT trap below, which shellcheck cannot see.
cleanup() {
  if [ -n "${FORWARD_PID:-}" ]; then kill "$FORWARD_PID" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# --- the certificate the apiserver has to trust before the cluster exists ------------------------

make_ca() {
  mkdir -p "$STATE"
  # kind wants an absolute hostPath, and SPIKE_CHE_STATE may have been given as a relative one.
  STATE=$(unset CDPATH; cd -- "$STATE" && pwd)
  printf 'certificate authority in %s (kept until "down")\n' "$STATE"
  [ -f "$STATE/sso-ca.crt" ] && return 0
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -subj "/CN=weebo-si spike CA" \
    -keyout "$STATE/sso-ca.key" -out "$STATE/sso-ca.crt" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes \
    -subj "/CN=$SSO_HOST" \
    -keyout "$STATE/sso.key" -out "$STATE/sso.csr" 2>/dev/null
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$SSO_HOST" > "$STATE/sso.ext"
  openssl x509 -req -in "$STATE/sso.csr" -days 3650 \
    -CA "$STATE/sso-ca.crt" -CAkey "$STATE/sso-ca.key" -CAcreateserial \
    -extfile "$STATE/sso.ext" -out "$STATE/sso.crt" 2>/dev/null
}

# kind does not expand environment variables in its config, so the CA's hostPath is substituted
# into a per-run copy; scripts/kind-che.yaml keeps the default path as the placeholder.
kind_config() {
  placeholder=/tmp/weebo-si-che/sso-ca.crt
  grep -qF "$placeholder" "$REPO_ROOT/scripts/kind-che.yaml" || {
    printf 'scripts/kind-che.yaml no longer mounts %s; update kind_config\n' "$placeholder" >&2
    exit 1
  }
  sed "s|$placeholder|$STATE/sso-ca.crt|" "$REPO_ROOT/scripts/kind-che.yaml"
}

# --- the realm ------------------------------------------------------------------------------------
#
# Shaped like the one Che is installed against: a public client for Che itself, a confidential one
# for `endpoint-gateway`, an audience mapper on each (the apiserver only accepts a token whose
# `aud` names it, and RFC 0009's bearer branch only accepts one whose `aud` names the gateway), a
# groups claim, and one user to be.

realm_json() {
  cat <<'REALM'
{
  "realm": "che",
  "enabled": true,
  "sslRequired": "none",
  "registrationAllowed": false,
  "groups": [{ "name": "team-payments" }],
  "users": [
    {
      "username": "alice",
      "email": "alice@weebo.si",
      "emailVerified": true,
      "enabled": true,
      "firstName": "Alice",
      "lastName": "Example",
      "credentials": [{ "type": "password", "value": "alice", "temporary": false }],
      "groups": ["/team-payments"]
    }
  ],
  "clients": [
    {
      "clientId": "che-client",
      "enabled": true,
      "publicClient": false,
      "secret": "che-client-secret",
      "standardFlowEnabled": true,
      "directAccessGrantsEnabled": true,
      "redirectUris": ["*"],
      "webOrigins": ["*"],
      "protocolMappers": [
        {
          "name": "kubernetes-audience",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-audience-mapper",
          "config": {
            "included.client.audience": "kubernetes",
            "access.token.claim": "true",
            "id.token.claim": "true"
          }
        },
        {
          "name": "groups",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-group-membership-mapper",
          "config": {
            "claim.name": "groups",
            "full.path": "false",
            "access.token.claim": "true",
            "id.token.claim": "true",
            "userinfo.token.claim": "true"
          }
        }
      ]
    },
    {
      "clientId": "endpoint-gateway",
      "enabled": true,
      "publicClient": false,
      "secret": "endpoint-gateway-secret",
      "standardFlowEnabled": true,
      "directAccessGrantsEnabled": true,
      "serviceAccountsEnabled": true,
      "redirectUris": ["*"],
      "webOrigins": ["*"],
      "attributes": { "backchannel.logout.session.required": "true" },
      "protocolMappers": [
        {
          "name": "gateway-audience",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-audience-mapper",
          "config": {
            "included.client.audience": "endpoint-gateway",
            "access.token.claim": "true"
          }
        },
        {
          "name": "groups",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-group-membership-mapper",
          "config": {
            "claim.name": "groups",
            "full.path": "false",
            "access.token.claim": "true",
            "id.token.claim": "true"
          }
        }
      ]
    },
    {
      "clientId": "kubernetes",
      "enabled": true,
      "publicClient": true,
      "standardFlowEnabled": true,
      "redirectUris": ["*"]
    }
  ]
}
REALM
}

install_sso() {
  kubectl create namespace sso >/dev/null 2>&1 || true
  kubectl -n sso create secret tls sso-tls \
    --cert="$STATE/sso.crt" --key="$STATE/sso.key" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  realm_json > "$WORK/realm.json"
  kubectl -n sso create configmap realm --from-file=che-realm.json="$WORK/realm.json" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl apply -f - >/dev/null <<MANIFEST
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak
  namespace: sso
spec:
  replicas: 1
  selector:
    matchLabels: { app: keycloak }
  template:
    metadata:
      labels: { app: keycloak }
    spec:
      containers:
        - name: keycloak
          image: quay.io/keycloak/keycloak:26.4
          args: ["start-dev", "--import-realm"]
          env:
            - { name: KC_BOOTSTRAP_ADMIN_USERNAME, value: admin }
            - { name: KC_BOOTSTRAP_ADMIN_PASSWORD, value: admin }
            - { name: KC_HTTP_ENABLED, value: "true" }
            - { name: KC_HOSTNAME, value: "https://$SSO_HOST" }
            - { name: KC_HOSTNAME_STRICT, value: "false" }
            - { name: KC_PROXY_HEADERS, value: xforwarded }
          ports:
            - containerPort: 8080
          volumeMounts:
            - { name: realm, mountPath: /opt/keycloak/data/import }
          readinessProbe:
            httpGet: { path: /realms/che/.well-known/openid-configuration, port: 8080 }
            initialDelaySeconds: 20
            periodSeconds: 5
            failureThreshold: 60
      volumes:
        - name: realm
          configMap: { name: realm }
---
apiVersion: v1
kind: Service
metadata:
  name: keycloak
  namespace: sso
spec:
  selector: { app: keycloak }
  ports: [{ name: http, port: 8080, targetPort: 8080 }]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: keycloak
  namespace: sso
spec:
  ingressClassName: traefik
  tls:
    - hosts: ["$SSO_HOST"]
      secretName: sso-tls
  rules:
    - host: $SSO_HOST
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: { service: { name: keycloak, port: { number: 8080 } } }
MANIFEST
  kubectl -n sso rollout status deploy/keycloak --timeout=600s >/dev/null
  printf 'identity provider at %s\n' "$ISSUER"
}

# `*.127.0.0.1.nip.io` resolves to 127.0.0.1, which is the wrong answer for every pod: its
# 127.0.0.1 is its own, and Traefik is not listening there. One rewrite, to Traefik's Service,
# fixes all of Che's hostnames at once, including the per-workspace endpoint hosts nobody can enumerate in advance, which is why
# this is a wildcard rewrite rather than a list of hosts entries.
cluster_dns() {
  kubectl -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}' > "$WORK/Corefile"
  # Strip any rewrite this script inserted before inserting one, because `up` is meant to be
  # re-runnable and a guard that only skips leaves five identical rules behind the first time it
  # is wrong.
  sed -i '/rewrite stop {/,/^ *}/d' "$WORK/Corefile"
  awk '
    /^[[:space:]]*kubernetes / && !done {
      print "        rewrite stop {"
      print "          name regex ^(.*\\.)?127\\.0\\.0\\.1\\.nip\\.io\\.?$ traefik.traefik.svc.cluster.local"
      print "          answer auto"
      print "        }"
      done = 1
    }
    { print }
  ' "$WORK/Corefile" > "$WORK/Corefile.new"
  kubectl -n kube-system create configmap coredns \
    --from-file=Corefile="$WORK/Corefile.new" --dry-run=client -o yaml |
    kubectl apply -f - >/dev/null
  kubectl -n kube-system rollout restart deploy/coredns >/dev/null
  kubectl -n kube-system rollout status deploy/coredns --timeout=180s >/dev/null
}

# The apiserver is an OIDC relying party and has to resolve the issuer's hostname itself. It runs
# on the node's network namespace, where cluster DNS does not exist and the CoreDNS rewrite above
# cannot help — so the node gets one hosts entry pointing at the ingress controller's ClusterIP,
# which node-originated traffic can reach through the same kube-proxy rules a pod uses. This is
# what replaces the hostPort that would otherwise break `kubernetes.default` for every pod.
node_hosts() {
  ip=$(kubectl -n traefik get svc traefik -o jsonpath='{.spec.clusterIP}')
  [ -n "$ip" ] || { printf 'no traefik ClusterIP yet\n' >&2; exit 1; }
  # Rewritten in place rather than with `sed -i`: /etc/hosts is a bind mount inside the node, so
  # the rename sed does is "Device or resource busy".
  podman exec "$CLUSTER-control-plane" sh -c \
    "t=\$(mktemp) && grep -v ' $SSO_HOST\$' /etc/hosts > \"\$t\" && cat \"\$t\" > /etc/hosts && rm -f \"\$t\" && echo '$ip $SSO_HOST' >> /etc/hosts"
  printf 'node resolves %s to %s\n' "$SSO_HOST" "$ip"
}

up() {
  make_ca
  if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    kind_config > "$WORK/kind-che.yaml"
    kind create cluster --config "$WORK/kind-che.yaml" --wait 300s
  fi

  printf 'installing traefik %s\n' "$TRAEFIK_CHART"
  # **No hostPort**, and this is the one setting on this rig that is not a preference. A hostPort
  # of 443 makes the CNI's portmap rules claim port 443 for the ingress pod *inside the node*, so
  # every pod's connection to `kubernetes.default` — a ClusterIP on 443 — is refused, and anything
  # holding an in-cluster API client dies at startup with no error of its own. Measured both ways
  # on this cluster: with the hostPort a pod gets `Connection refused` from `10.96.0.1:443`, and
  # `200` within fifteen seconds of scaling the controller to zero. The apiserver reaches the
  # ingress through the node's /etc/hosts instead — see `node_hosts` below. The chart sets no
  # hostPort by default, and the Service is ClusterIP rather than the chart's LoadBalancer.
  #
  # The default IngressClass, so an Ingress written without a class still lands on Traefik.
  helm upgrade --install traefik traefik --repo https://traefik.github.io/charts --version "$TRAEFIK_CHART" \
    -n traefik --create-namespace \
    --set service.spec.type=ClusterIP \
    --set ingressClass.isDefaultClass=true \
    --wait --timeout 10m >/dev/null

  printf 'pointing cluster DNS and the node at the ingress controller\n'
  cluster_dns
  node_hosts

  printf 'installing the identity provider\n'
  install_sso

  printf 'installing cert-manager\n'
  cert=$(curl -sS https://api.github.com/repos/cert-manager/cert-manager/releases/latest | jq -r .tag_name)
  kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/$cert/cert-manager.yaml" >/dev/null
  kubectl -n cert-manager rollout status deploy/cert-manager-webhook --timeout=300s >/dev/null

  printf 'installing DevWorkspace Operator\n'
  kubectl create namespace devworkspace-controller >/dev/null 2>&1 || true
  kubectl apply -f "https://raw.githubusercontent.com/devfile/devworkspace-operator/v0.43.0/deploy/deployment/kubernetes/combined.yaml" >/dev/null
  kubectl -n devworkspace-controller rollout status deploy/devworkspace-controller-manager --timeout=300s >/dev/null

  printf 'installing Eclipse Che\n'
  kubectl create namespace eclipse-che >/dev/null 2>&1 || true
  # Server-side: the CheCluster CRD's schema is larger than the 256 KiB a client-side apply can
  # stash in `kubectl.kubernetes.io/last-applied-configuration`.
  kubectl apply --server-side --force-conflicts \
    -f "https://raw.githubusercontent.com/eclipse-che/che-operator/main/deploy/deployment/kubernetes/combined.yaml" >/dev/null
  kubectl -n eclipse-che rollout status deploy/che-operator --timeout=600s >/dev/null
  # Che's components get their trust store from a ConfigMap carrying these two labels — without
  # it che-server reaches the issuer and refuses it, `PKIX path building failed`, which reads like
  # a Che bug and is this rig's self-signed certificate.
  kubectl -n eclipse-che create configmap spike-ca-bundle \
    --from-file=spike-ca.crt="$STATE/sso-ca.crt" --dry-run=client -o yaml |
    kubectl label -f - --local -o yaml \
      app.kubernetes.io/part-of=che.eclipse.org \
      app.kubernetes.io/component=ca-bundle |
    kubectl apply -f - >/dev/null

  printf 'creating the CheCluster\n'
  # The CRD takes either a plain value (deprecated) or the name of a Secret carrying it under the
  # `oAuthSecret` key — and that Secret is only read when it carries Che's own part-of label.
  kubectl -n eclipse-che apply -f - >/dev/null <<SECRET
apiVersion: v1
kind: Secret
metadata:
  name: che-oauth-secret
  namespace: eclipse-che
  labels:
    app.kubernetes.io/part-of: che.eclipse.org
stringData:
  oAuthSecret: che-client-secret
SECRET
  # Written against the CRD schema this operator installed rather than from memory:
  # `networking.auth` is where the identity provider goes, `identityToken: id_token` is the
  # default off OpenShift and is stated anyway because it is the claim the gateway's own
  # `claims.username` has to agree with.
  kubectl apply -f - >/dev/null <<CLUSTER
apiVersion: org.eclipse.che/v2
kind: CheCluster
metadata:
  name: eclipse-che
  namespace: eclipse-che
spec:
  networking:
    domain: $DOMAIN
    # che-operator writes \`kubernetes.io/ingress.class: nginx\` and its nginx annotations on every
    # Ingress unless this map is non-empty, and a workspace Ingress carries only that annotation —
    # no ingressClassName. Naming Traefik here is what puts Che's routes on the controller this
    # rig actually runs.
    annotations:
      kubernetes.io/ingress.class: traefik
    auth:
      identityProviderURL: "$ISSUER"
      oAuthClientName: che-client
      oAuthSecret: che-oauth-secret
      identityToken: id_token
  devEnvironments:
    defaultNamespace:
      autoProvision: true
      template: <username>-che
    storage:
      pvcStrategy: per-user
CLUSTER
  printf '\nwaiting for Che (this pulls several GB)\n'
  i=0
  phase=
  while [ "$i" -lt 120 ]; do
    phase=$(kubectl -n eclipse-che get checluster eclipse-che -o jsonpath='{.status.chePhase}' 2>/dev/null)
    [ "$phase" = "Active" ] && break
    i=$((i + 1))
    sleep 10
  done
  printf 'CheCluster phase: %s\n' "${phase:-unknown}"
  printf '\nnext: scripts/spike-0009-che.sh rows\n'
}

# Nothing is published to the host, so both of these reach the identity provider the same way a
# person would have to: one forwarded port, torn down after. The discovery document row does not
# care that the URL it is read through is not the issuer's own — it reads fields, and the issuer
# value inside the document is the real one.
LOCAL_SSO=http://127.0.0.1:18080/realms/che

forward() {
  kubectl -n sso port-forward svc/keycloak 18080:8080 >/dev/null 2>&1 &
  FORWARD_PID=$!
  sleep 3
}

unforward() {
  [ -n "${FORWARD_PID:-}" ] && kill "$FORWARD_PID" 2>/dev/null
  FORWARD_PID=
}

token() {
  forward
  curl -sS "$LOCAL_SSO/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=endpoint-gateway \
    -d client_secret=endpoint-gateway-secret \
    -d username=alice -d password=alice -d scope=openid | jq -r .access_token
  unforward
}

rows() {
  token > "$WORK/token"
  forward
  "$REPO_ROOT/scripts/spike-0009.sh" --row 2
  "$REPO_ROOT/scripts/spike-0009.sh" --row 7 --issuer "$LOCAL_SSO"
  "$REPO_ROOT/scripts/spike-0009.sh" --row 8 --token "$WORK/token"
  unforward
}

down() {
  kind delete cluster --name "$CLUSTER"
  rm -rf "$STATE"
}

case "${1:-}" in
  up) up ;;
  token) token ;;
  rows) rows ;;
  down) down ;;
  *) printf 'usage: %s up|token|rows|down\n' "$0" >&2; exit 2 ;;
esac
