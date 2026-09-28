#!/bin/sh
# RFC 0009's ground-truth spike: the facts that RFC asserts from documentation, read back from a
# cluster instead.
#
#   scripts/spike-0009.sh                  the read-only rows, against the current kube context
#   scripts/spike-0009.sh --live           also the router rows, which create objects
#   scripts/spike-0009.sh --row 6          one row
#   scripts/spike-0009.sh --issuer URL     row 7, against an OIDC discovery document
#   scripts/spike-0009.sh --token FILE     row 8, against a token a developer can fetch ("-": stdin)
#   scripts/spike-0009.sh --markdown       the record block for docs/bricks/endpoint-gateway.md
#   scripts/spike-0009.sh --keep           leave the live fixtures behind for poking at
#
# Each row prints the command that established it, because the point of the spike is that the next
# reader is not asked to take RFC 0009's word for these — or this script's.
#
# Verdicts. SETTLED: the cluster says what the RFC assumed. DIFFERS: it does not, and something in
# the implementation is wrong until it is changed. SKIPPED: this cluster cannot answer this row —
# no Che, no OpenShift, no such ingress controller. Only DIFFERS fails the run: a cluster without
# OpenShift is not a failed spike, it is a cluster without OpenShift.
#
# The read-only rows are safe against a real Che installation and create nothing. --live creates a
# namespace (default: weebo-spike), a stub, and one Ingress per ingress controller it finds; it is
# how rows 5, 6 and 9 get answered, and it is why they are not the default.
set -eu

# What RFC 0009 assumes. Kept as constants so a row that DIFFERS names both values, and so the
# next reader can see the claim without reading the row's plumbing.
EXPECTED_DWO_IDENTITY="system:serviceaccount:devworkspace-controller:devworkspace-controller-serviceaccount"
EXPECTED_NS_LABEL="app.kubernetes.io/part-of"
EXPECTED_NS_LABEL_VALUE="che.eclipse.org"
CHE_USERNAME_ANNOTATION="che.eclipse.org/username"
DWO_ID_LABEL="controller.devfile.io/devworkspace_id"

# The stub's markers. Each one is a claim about somebody else's software: if the marker arrives,
# that router passed the thing through; if it does not, it did not.
BODY_MARKER="SPIKE-BODY-MARKER"
COOKIE_MARKER="spike_session=deadbeef"
BACKEND_MARKER="SPIKE-BACKEND-REACHED"

NS="weebo-spike"
STUB_IMAGE="docker.io/library/nginx:1.27-alpine"
CLIENT_IMAGE="docker.io/curlimages/curl:8.11.1"
live=0
keep=0
markdown=0
only_row=""
issuer=""
token_file=""

usage() {
  cat <<'USAGE'
usage: spike-0009.sh [--live] [--keep] [--markdown] [--row N] [--issuer URL] [--token FILE]
                     [--namespace NS]
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --live) live=1 ;;
    --keep) keep=1 ;;
    --markdown) markdown=1 ;;
    --row) shift; only_row="${1:-}" ;;
    --issuer) shift; issuer="${1:-}" ;;
    --token) shift; token_file="${1:-}" ;;
    --namespace) shift; NS="${1:-}" ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

RESULTS=$(mktemp)
NOTES=$(mktemp)
# shellcheck disable=SC2329  # invoked from the EXIT trap below, which shellcheck cannot see.
cleanup_tmp() { rm -f "$RESULTS" "$NOTES"; }
trap cleanup_tmp EXIT

# --- output -----------------------------------------------------------------------------------

heading() {
  [ "$markdown" = 1 ] && return 0
  printf '\n\033[1m── row %s · %s\033[0m\n' "$1" "$2"
}

shown() { # shown <label> <value>
  [ "$markdown" = 1 ] && return 0
  printf '  %-11s %s\n' "$1" "$2"
}

ran() { # ran <command> — the line a reader re-runs
  [ "$markdown" = 1 ] && return 0
  printf '  \033[2m$ %s\033[0m\n' "$1"
}

record() { # record <row> <title> <verdict> <observed>
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >>"$RESULTS"
  [ "$markdown" = 1 ] && return 0
  case "$3" in
    SETTLED) printf '  %-11s \033[32m%s\033[0m — %s\n' verdict "$3" "$4" ;;
    DIFFERS) printf '  %-11s \033[31m%s\033[0m — %s\n' verdict "$3" "$4" ;;
    *)       printf '  %-11s \033[33m%s\033[0m — %s\n' verdict "$3" "$4" ;;
  esac
}

note() { printf '%s\n' "$1" >>"$NOTES"; [ "$markdown" = 1 ] || printf '  %-11s %s\n' note "$1"; }

wanted() { # wanted <row> — is this row in this run
  [ -z "$only_row" ] || [ "$only_row" = "$1" ]
}

# --- cluster helpers --------------------------------------------------------------------------

k() { kubectl "$@"; }

have_cluster() { kubectl version -o json >/dev/null 2>&1; }

has_kind() { # has_kind <resource> — is this kind served by the apiserver
  kubectl api-resources --no-headers 2>/dev/null | awk '{print $1}' | grep -qx "$1"
}

che_namespaces() {
  k get ns -o json 2>/dev/null |
    jq -r --arg a "$CHE_USERNAME_ANNOTATION" \
      '.items[] | select(.metadata.annotations[$a] // empty) | .metadata.name'
}

# --- row 1 · DevWorkspace Operator's identity ---------------------------------------------------
#
# Guard row 2 allows this subject unconditionally, so a wrong value here is not a rejected request
# in a log: it is every workspace endpoint in the cluster failing to be created, by a rule that
# reads correct.

row_1() {
  wanted 1 || return 0
  heading 1 "DevWorkspace Operator's identity"
  shown assumption "$EXPECTED_DWO_IDENTITY"
  cmd="kubectl get deploy -A -l app.kubernetes.io/name=devworkspace-controller -o jsonpath=..."
  ran "$cmd"
  found=$(k get deploy -A -l app.kubernetes.io/name=devworkspace-controller -o json 2>/dev/null |
    jq -r '.items[] | "system:serviceaccount:\(.metadata.namespace):\(.spec.template.spec.serviceAccountName)"' |
    sort -u | head -5)
  if [ -z "$found" ]; then
    # The label is itself an assumption. Fall back to the controller's own name before concluding
    # that DWO is absent, so "the label moved" and "DWO is not installed" stay distinguishable.
    found=$(k get deploy -A -o json 2>/dev/null |
      jq -r '.items[] | select(.metadata.name | test("devworkspace-controller")) |
             "system:serviceaccount:\(.metadata.namespace):\(.spec.template.spec.serviceAccountName)"' |
      sort -u | head -5)
    [ -n "$found" ] && note "found by name, not by app.kubernetes.io/name=devworkspace-controller"
  fi
  if [ -z "$found" ]; then
    record 1 "DWO identity" SKIPPED "no DevWorkspace Operator deployment in this cluster"
    return 0
  fi
  shown observed "$found"
  if [ "$found" = "$EXPECTED_DWO_IDENTITY" ]; then
    record 1 "DWO identity" SETTLED "$found"
  else
    record 1 "DWO identity" DIFFERS "$found"
  fi
}

# --- row 2 · the label on a Che user namespace --------------------------------------------------
#
# The webhook's namespaceSelector and the gateway's whole index scope hang on this one label. Wrong
# means the feature silently covers nothing, which is the failure mode that looks like success.

row_2() {
  wanted 2 || return 0
  heading 2 "the label Che puts on a user namespace"
  shown assumption "$EXPECTED_NS_LABEL=$EXPECTED_NS_LABEL_VALUE"
  ran "kubectl get ns -o json | jq '.items[] | select(.metadata.annotations[\"$CHE_USERNAME_ANNOTATION\"])'"
  namespaces=$(che_namespaces)
  if [ -z "$namespaces" ]; then
    record 2 "Che namespace label" SKIPPED "no namespace carries $CHE_USERNAME_ANNOTATION — no Che here"
    return 0
  fi
  first=$(printf '%s\n' "$namespaces" | head -1)
  labels=$(k get ns "$first" -o json | jq -r '.metadata.labels // {} | to_entries[] | "\(.key)=\(.value)"')
  shown observed "$first: $(printf '%s' "$labels" | tr '\n' ' ')"
  if printf '%s\n' "$labels" | grep -qx "$EXPECTED_NS_LABEL=$EXPECTED_NS_LABEL_VALUE"; then
    count=$(printf '%s\n' "$namespaces" | wc -l | tr -d ' ')
    missing=0
    for ns in $namespaces; do
      k get ns "$ns" -o json |
        jq -e --arg k "$EXPECTED_NS_LABEL" --arg v "$EXPECTED_NS_LABEL_VALUE" \
          '.metadata.labels[$k] == $v' >/dev/null 2>&1 || missing=$((missing + 1))
    done
    if [ "$missing" -eq 0 ]; then
      record 2 "Che namespace label" SETTLED "$count/$count Che namespaces carry it"
    else
      record 2 "Che namespace label" DIFFERS "$missing of $count Che namespaces do not carry it"
    fi
  else
    record 2 "Che namespace label" DIFFERS "$first carries $CHE_USERNAME_ANNOTATION but not the label"
  fi
}

# --- row 3 · one routing object per exposed endpoint, annotations carried -----------------------
#
# The per-object annotation model and the devfile path both assume it: one Ingress per endpoint,
# and the endpoint's own annotations landing on that object rather than being dropped by DWO.

row_3() {
  wanted 3 || return 0
  heading 3 "one routing object per exposed endpoint"
  shown assumption "one Ingress per exposed endpoint, carrying the endpoint's annotations"
  ran "kubectl get ingress -A -l $DWO_ID_LABEL -o json"
  ingresses=$(k get ingress -A -l "$DWO_ID_LABEL" -o json 2>/dev/null || printf '{"items":[]}')
  count=$(printf '%s' "$ingresses" | jq '.items | length')
  if [ "$count" -eq 0 ]; then
    record 3 "routing object per endpoint" SKIPPED "no DWO-labelled Ingress — start a workspace first"
    return 0
  fi
  # Rules per object, and hosts per object: more than one of either means the assumption that a
  # host maps to exactly one endpoint's policy does not hold.
  shape=$(printf '%s' "$ingresses" | jq -r '
    [.items[] | {rules: (.spec.rules | length),
                 hosts: ([.spec.rules[].host] | unique | length),
                 paths: ([.spec.rules[].http.path[]?] | length)}]
    | "objects=\(length) max_rules=\([.[].rules] | max) max_hosts=\([.[].hosts] | max)"')
  shown observed "$shape"
  endpoint_keys=$(printf '%s' "$ingresses" |
    jq -r '[.items[].metadata.annotations // {} | keys[]] | unique | join(", ")')
  shown annotations "$endpoint_keys"
  note "the endpoint-name key above is what a devfile annotation has to survive as"
  if printf '%s' "$shape" | grep -q 'max_rules=1 max_hosts=1'; then
    record 3 "routing object per endpoint" SETTLED "$shape"
  else
    record 3 "routing object per endpoint" DIFFERS "$shape"
  fi

  # 3a — how a devfile spells it. RFC 0009's developer-facing snippet says `annotations`; the
  # schema the apiserver enforces is what decides, and a workspace whose devfile uses the other
  # spelling is refused outright rather than gated wrongly.
  spelling=$(k get crd devworkspaces.workspace.devfile.io -o json 2>/dev/null | jq -r '
    .spec.versions[] | select(.name=="v1alpha2") |
    .schema.openAPIV3Schema.properties.spec.properties.template.properties.components.items
      .properties.container.properties.endpoints.items.properties | keys | join(",")' 2>/dev/null)
  if [ -z "$spelling" ]; then
    record 3a "the devfile endpoint field" SKIPPED "no DevWorkspace CRD to read the schema from"
  else
    shown schema "$spelling"
    if printf '%s' "$spelling" | tr ',' '\n' | grep -qx annotations; then
      record 3a "the devfile endpoint field" SETTLED "an endpoint takes 'annotations'"
    elif printf '%s' "$spelling" | tr ',' '\n' | grep -qx annotation; then
      record 3a "the devfile endpoint field" DIFFERS "an endpoint takes 'annotation', singular"
    else
      record 3a "the devfile endpoint field" DIFFERS "an endpoint takes neither: $spelling"
    fi
  fi

  # 3b — and whether what a developer wrote there reaches the object the gate reads.
  carried=$(printf '%s' "$ingresses" | jq -r '
    [.items[].metadata.annotations // {} | keys[]
     | select(startswith("controller.devfile.io/") or test("ingress.kubernetes.io/") | not)]
    | unique | join(", ")')
  if [ -z "$carried" ]; then
    record 3b "endpoint annotations carried" SKIPPED "no workspace here declares endpoint annotations"
  else
    shown carried "$carried"
    record 3b "endpoint annotations carried" SETTLED "$carried"
  fi
}

# --- row 4 · OpenShift ---------------------------------------------------------------------------
#
# The ReverseProxy dialect rests on three properties of a router this repo has never run against.

row_4() {
  wanted 4 || return 0
  heading 4 "OpenShift: Route, the router's Service, and spec.to"
  shown assumption "DWO publishes Routes; the router serves a selector-less Service; spec.to is local-only"
  ran "kubectl get routes -A -l $DWO_ID_LABEL -o json"
  if ! has_kind routes; then
    record 4 "OpenShift Route" SKIPPED "route.openshift.io/v1 is not served here — not OpenShift"
    return 0
  fi
  routes=$(k get routes -A -l "$DWO_ID_LABEL" -o json 2>/dev/null || printf '{"items":[]}')
  rcount=$(printf '%s' "$routes" | jq '.items | length')
  shown observed "$rcount DWO-labelled Route(s)"
  selector=$(k -n openshift-ingress get svc router-default -o json 2>/dev/null |
    jq -c '.spec.selector // "absent"' || printf 'unreadable')
  shown router-svc "selector=$selector"
  kinds=$(printf '%s' "$routes" | jq -r '[.items[].spec.to.kind] | unique | join(",")')
  shown spec.to "kinds=$kinds"
  if [ "$rcount" -gt 0 ]; then
    record 4 "OpenShift Route" SETTLED "$rcount Routes, spec.to kinds=$kinds, router selector=$selector"
  else
    record 4 "OpenShift Route" SKIPPED "OpenShift, but no DWO-labelled Route to read"
  fi
}

# --- the live rig --------------------------------------------------------------------------------
#
# One stub serving two ports: an /auth that always refuses, with a body, a Set-Cookie and a
# WWW-Authenticate on the refusal, and a backend that says it was reached. Every router row below
# is the same two questions — did my annotation reach the auth service at all, and what of its
# refusal reached the caller.

live_manifests() {
  cat <<MANIFEST
apiVersion: v1
kind: Namespace
metadata:
  name: $NS
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: spike-stub
  namespace: $NS
data:
  default.conf: |
    log_format spike escape=json '{"tag":"AUTHREQ","method":"\$request_method","uri":"\$request_uri",'
      '"arg_host":"\$arg_host","arg_uri":"\$arg_uri","arg_method":"\$arg_method","arg_proto":"\$arg_proto",'
      '"xf_host":"\$http_x_forwarded_host","xf_uri":"\$http_x_forwarded_uri",'
      '"xf_method":"\$http_x_forwarded_method","xf_proto":"\$http_x_forwarded_proto",'
      '"x_real_ip":"\$http_x_real_ip","xff":"\$http_x_forwarded_for","host_header":"\$http_host"}';
    server {
      listen 8080;
      access_log /dev/stdout spike;
      location = /auth {
        add_header Set-Cookie "$COOKIE_MARKER; Path=/; HttpOnly" always;
        add_header WWW-Authenticate 'Bearer realm="spike", error="invalid_token"' always;
        add_header X-Spike-Auth "denied" always;
        return 401 '{"reason":"$BODY_MARKER"}';
      }
      location = /allow {
        add_header X-Auth-Request-User "spike-user" always;
        return 200 'allowed';
      }
      location / { return 404 'no such stub route'; }
    }
    server {
      listen 8081;
      access_log /dev/stdout spike;
      location / { return 200 '$BACKEND_MARKER'; }
    }
    # The other three answers a gate can give, each of which a router treats differently: a
    # navigation challenge, an allow that re-mints a cookie, and an allow that names nobody.
    server {
      listen 8082;
      access_log /dev/stdout spike;
      location = /auth-302 {
        add_header Set-Cookie "$COOKIE_MARKER; Path=/" always;
        return 302 http://login.example.test/start;
      }
      location = /auth-ok {
        add_header Set-Cookie "spike_session=remint; Path=/" always;
        add_header X-Auth-Request-User "spike-user" always;
        return 200 'ok';
      }
      location = /auth-bare { return 200 'ok'; }
    }
    # What the application sees. A router that lets a caller's own X-Auth-Request-User through is
    # a router on which the gate's identity headers are worthless.
    server {
      listen 8083;
      access_log /dev/stdout spike;
      location / { return 200 'echo user=\$http_x_auth_request_user groups=\$http_x_auth_request_groups'; }
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: spike-stub
  namespace: $NS
spec:
  replicas: 1
  selector:
    matchLabels: { app: spike-stub }
  template:
    metadata:
      labels: { app: spike-stub }
    spec:
      containers:
        - name: nginx
          image: $STUB_IMAGE
          ports:
            - containerPort: 8080
            - containerPort: 8081
            - containerPort: 8082
            - containerPort: 8083
          volumeMounts:
            - name: conf
              mountPath: /etc/nginx/conf.d
      volumes:
        - name: conf
          configMap: { name: spike-stub }
---
apiVersion: v1
kind: Service
metadata:
  name: spike-auth
  namespace: $NS
spec:
  selector: { app: spike-stub }
  ports:
    - { name: http, port: 8080, targetPort: 8080 }
    - { name: shapes, port: 8082, targetPort: 8082 }
---
apiVersion: v1
kind: Service
metadata:
  name: spike-backend
  namespace: $NS
spec:
  selector: { app: spike-stub }
  ports:
    - { name: http, port: 8081, targetPort: 8081 }
    - { name: echo, port: 8083, targetPort: 8083 }
---
apiVersion: v1
kind: Pod
metadata:
  name: spike-client
  namespace: $NS
spec:
  containers:
    - name: curl
      image: $CLIENT_IMAGE
      command: ["sleep", "3600"]
MANIFEST
}

live_setup() {
  live_manifests | k apply -f - >/dev/null
  k -n "$NS" rollout status deploy/spike-stub --timeout=180s >/dev/null
  k -n "$NS" wait --for=condition=Ready pod/spike-client --timeout=180s >/dev/null
}

# shellcheck disable=SC2329  # invoked from the EXIT trap installed once the rig is up.
live_teardown() {
  [ "$keep" = 1 ] && return 0
  k delete ns "$NS" --wait=false >/dev/null 2>&1 || true
}

fetch() { # fetch <url> <host-header> [extra curl args...] — full response, headers and body
  url="$1"; hosthdr="$2"; shift 2
  k -n "$NS" exec spike-client -- \
    curl -sS -i -m 15 -H "Host: $hosthdr" "$@" "$url" 2>/dev/null || printf 'CURL-FAILED'
}

status_of() { printf '%s\n' "$1" | awk 'NR==1 {print $2}'; }

has_header() { # has_header <response> <name> <needle>
  printf '%s\n' "$1" | grep -i "^$2:" | grep -qi "$3"
}

last_authreq() { # the auth stub's view of the last request it was handed
  k -n "$NS" logs deploy/spike-stub --tail=200 2>/dev/null |
    grep AUTHREQ | grep -v '"uri":"/allow"' | tail -1
}

controller_service() { # controller_service <namespace-hint> <label>
  k get svc -A -l "$2" -o json 2>/dev/null |
    jq -r '.items[] | select(.spec.type != "ExternalName") |
           "\(.metadata.name).\(.metadata.namespace).svc.cluster.local"' | head -1
}

# --- row 5 · community haproxy-ingress -----------------------------------------------------------
#
# RFC 0009's bullet asks for two facts: the annotation names, and whether a non-2xx auth response
# comes back verbatim. Both are true. The rows numbered 5a..5d are what asking them turned up —
# this controller builds the auth request by *copying the caller's own headers*, which is a
# different contract from Traefik's and decides three things the RFC assumed rather than checked.
#
# 5a..5c are reported against whatever this controller is configured with, because that is the
# question worth asking: they fail on a default install and pass once the controller carries the
# prerequisite in scripts/spike-0009-rig.sh (`prerequisite on`). Run the row both ways — the
# difference between the two runs is exactly what the prerequisite buys, and it is the argument
# for requiring an admin to assert it rather than assuming it.

row_5() {
  wanted 5 || return 0
  heading 5 "community haproxy-ingress: the annotation names, and the refusal"
  shown assumption "haproxy-ingress.github.io/auth-url + auth-headers-succeed; non-2xx returned verbatim"
  class=$(k get ingressclass -o json 2>/dev/null |
    jq -r '.items[] | select(.spec.controller | test("haproxy")) | .metadata.name' | head -1)
  if [ -z "$class" ]; then
    record 5 "haproxy-ingress" SKIPPED "no haproxy IngressClass in this cluster"
    return 0
  fi
  svc=$(controller_service haproxy "app.kubernetes.io/name=haproxy-ingress")
  [ -n "$svc" ] || svc=$(k get svc -A -o json |
    jq -r '.items[] | select(.metadata.name | test("haproxy")) |
           "\(.metadata.name).\(.metadata.namespace).svc.cluster.local"' | head -1)
  if [ -z "$svc" ]; then
    record 5 "haproxy-ingress" SKIPPED "haproxy IngressClass $class, but no Service to call"
    return 0
  fi
  ran "kubectl apply -f - <<< 'Ingress with haproxy-ingress.github.io/auth-url' ; curl via $svc"
  haproxy_ingresses "$class"
  sleep 12

  # The RFC's bullet.
  response=$(fetch "http://$svc/actuator/health" spike-haproxy.example.test -X POST)
  code=$(status_of "$response")
  seen=$(last_authreq)
  shown status "$code"
  shown auth-saw "${seen:-nothing — the annotation did not reach the controller}"
  if [ -z "$seen" ]; then
    record 5 "haproxy-ingress" DIFFERS "auth-url never reached the stub"
    return 0
  fi
  body=no; cookie=no; challenge=no
  printf '%s' "$response" | grep -q "$BODY_MARKER" && body=yes
  has_header "$response" set-cookie "$COOKIE_MARKER" && cookie=yes
  has_header "$response" www-authenticate Bearer && challenge=yes
  shown verbatim "body=$body cookie=$cookie www-authenticate=$challenge"
  if [ "$code" = 401 ] && [ "$body" = yes ] && [ "$cookie" = yes ] && [ "$challenge" = yes ]; then
    record 5 "haproxy-ingress" SETTLED "auth-url honoured; a 401 comes back with body, cookie and challenge"
  else
    record 5 "haproxy-ingress" DIFFERS "status=$code body=$body cookie=$cookie challenge=$challenge"
  fi

  # 5a — the four inputs the decision is made from. The auth request is a fixed path and a copy of
  # the caller's headers: there is no X-Forwarded-Host, -Uri or -Method unless the caller sent one.
  inputs=$(printf '%s' "$seen" |
    jq -r '"xf_host=\(if .xf_host == "" then "absent" else .xf_host end)" +
           " xf_uri=\(if .xf_uri == "" then "absent" else .xf_uri end)" +
           " xf_method=\(if .xf_method == "" then "absent" else .xf_method end)" +
           " path=\(.uri) method=\(.method)"')
  shown inputs "$inputs"
  case "$inputs" in
    *xf_host=absent*)
      record 5a "the gate's four inputs" DIFFERS \
        "$inputs — no controller prerequisite installed, so the gate cannot know the host or the path" ;;
    *)
      record 5a "the gate's four inputs" SETTLED "$inputs — the controller prerequisite is in place" ;;
  esac

  # 5b — and since the copy is verbatim, a caller can state one.
  fetch "http://$svc/actuator/health" spike-haproxy.example.test \
    -H "X-Forwarded-Host: forged.example.test" >/dev/null
  sleep 2
  forged=$(last_authreq | jq -r '.xf_host')
  shown forged "X-Forwarded-Host arrived as: ${forged:-absent}"
  if [ "$forged" = "forged.example.test" ]; then
    record 5b "a caller-stated host" DIFFERS \
      "a caller's X-Forwarded-Host reaches the gate verbatim — install the prerequisite, which overwrites it"
  else
    record 5b "a caller-stated host" SETTLED "a caller's X-Forwarded-Host is overwritten before the gate sees it"
  fi

  # 5c — the identity headers, on an allow that names nobody. Traefik strips every header it is
  # told to read from the auth response; this controller only overwrites the ones that response
  # actually carried.
  echoed=$(fetch "http://$svc/x" spike-haproxy-bare.example.test -H "X-Auth-Request-User: forged-admin")
  shown application "$(printf '%s' "$echoed" | tail -1)"
  if printf '%s' "$echoed" | grep -q "user=forged-admin"; then
    record 5c "identity header injection" DIFFERS \
      "a caller's X-Auth-Request-User reaches the application — the prerequisite's del-header lines close it"
  else
    record 5c "identity header injection" SETTLED "a caller's X-Auth-Request-User is stripped"
  fi

  # 5d — the navigation challenge.
  redirect=$(fetch "http://$svc/x" spike-haproxy-302.example.test)
  rcode=$(status_of "$redirect")
  shown challenge-302 "$rcode"
  if [ "$rcode" = 302 ]; then
    record 5d "a 302 from the gate" SETTLED "passed through with its Location and Set-Cookie"
  else
    record 5d "a 302 from the gate" DIFFERS "the caller got $rcode"
  fi
}

haproxy_ingresses() { # haproxy_ingresses <class>
  cat <<INGRESS | k apply -f - >/dev/null
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: spike-haproxy
  namespace: $NS
  annotations:
    haproxy-ingress.github.io/auth-url: "http://spike-auth.$NS.svc.cluster.local:8080/auth"
    # auth-method "*" preserves the caller's method — without it every request is a GET to the
    # gate, and a rule that names a method decides the wrong way. auth-headers-request narrows
    # what is copied out of the caller's own request: with the default "*", anything the gate
    # reads is something the caller can state.
    haproxy-ingress.github.io/auth-method: "*"
    haproxy-ingress.github.io/auth-headers-request: "cookie,authorization,x-real-ip,x-forwarded-host,x-forwarded-uri,x-forwarded-method,x-forwarded-proto"
    haproxy-ingress.github.io/auth-headers-succeed: "x-auth-request-user,x-auth-request-groups,x-auth-request-email"
spec:
  ingressClassName: $1
  rules:
    - host: spike-haproxy.example.test
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: { service: { name: spike-backend, port: { number: 8081 } } }
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: spike-haproxy-bare
  namespace: $NS
  annotations:
    haproxy-ingress.github.io/auth-url: "http://spike-auth.$NS.svc.cluster.local:8082/auth-bare"
    haproxy-ingress.github.io/auth-headers-succeed: "x-auth-request-user,x-auth-request-groups,x-auth-request-email"
spec:
  ingressClassName: $1
  rules:
    - host: spike-haproxy-bare.example.test
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: { service: { name: spike-backend, port: { number: 8083 } } }
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: spike-haproxy-302
  namespace: $NS
  annotations:
    haproxy-ingress.github.io/auth-url: "http://spike-auth.$NS.svc.cluster.local:8082/auth-302"
spec:
  ingressClassName: $1
  rules:
    - host: spike-haproxy-302.example.test
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: { service: { name: spike-backend, port: { number: 8081 } } }
INGRESS
}

# --- row 6 · ingress-nginx -----------------------------------------------------------------------
#
# The RFC's bullet is 6: do the nginx variables interpolate in auth-url without
# allow-snippet-annotations. They do. 6a..6d are the consequences of *how* this controller
# implements auth_request, and three of them contradict something RFC 0009 says elsewhere.

row_6() {
  wanted 6 || return 0
  heading 6 "ingress-nginx: variables in auth-url, and what the controller does with the answer"
  shown assumption "\$host, \$request_uri, \$request_method and \$scheme interpolate without allow-snippet-annotations"
  class=$(k get ingressclass -o json 2>/dev/null |
    jq -r '.items[] | select(.spec.controller | test("ingress-nginx")) | .metadata.name' | head -1)
  if [ -z "$class" ]; then
    record 6 "ingress-nginx" SKIPPED "no ingress-nginx IngressClass in this cluster"
    return 0
  fi
  svc=$(controller_service nginx "app.kubernetes.io/name=ingress-nginx")
  if [ -z "$svc" ]; then
    record 6 "ingress-nginx" SKIPPED "ingress-nginx IngressClass $class, but no Service to call"
    return 0
  fi
  ran "kubectl apply -f - <<< 'Ingress with nginx.ingress.kubernetes.io/auth-url=...?host=\$host&...' ; curl via $svc"
  nginx_ingresses "$class"
  sleep 12

  response=$(fetch "http://$svc/actuator/health" spike-nginx-nosignin.example.test -X POST)
  code=$(status_of "$response")
  seen=$(last_authreq)
  shown status "$code (no auth-signin)"
  shown auth-saw "${seen:-nothing — the annotation did not reach the controller}"
  if [ -z "$seen" ]; then
    record 6 "ingress-nginx" DIFFERS "auth-url never reached the stub — annotation refused or unsupported"
    return 0
  fi
  interpolated=$(printf '%s' "$seen" |
    jq -r '"host=\(.arg_host) uri=\(.arg_uri) method=\(.arg_method) proto=\(.arg_proto)"')
  shown variables "$interpolated"
  case "$interpolated" in
    *'host=spike-nginx-nosignin.example.test'*'uri=/actuator/health'*'method=POST'*)
      record 6 "ingress-nginx auth-url" SETTLED "$interpolated" ;;
    *)
      record 6 "ingress-nginx auth-url" DIFFERS "auth-url reached the stub but carried $interpolated" ;;
  esac

  # 6a — what of the refusal reaches the caller. Only the header does.
  body=no; cookie=no; challenge=no
  printf '%s' "$response" | grep -q "$BODY_MARKER" && body=yes
  has_header "$response" set-cookie "$COOKIE_MARKER" && cookie=yes
  has_header "$response" www-authenticate Bearer && challenge=yes
  shown verbatim "body=$body cookie=$cookie www-authenticate=$challenge"
  if [ "$body" = yes ] && [ "$challenge" = yes ]; then
    record 6a "a refusal, verbatim" SETTLED "body=$body cookie=$cookie www-authenticate=$challenge"
  else
    record 6a "a refusal, verbatim" DIFFERS "body=$body cookie=$cookie www-authenticate=$challenge"
  fi

  # 6b — a 302 from the gate. nginx's auth_request accepts 2xx, 401 and 403 and calls everything
  # else a server error, which is why auth-signin exists at all.
  redirect=$(fetch "http://$svc/x" spike-nginx-302.example.test)
  rcode=$(status_of "$redirect")
  shown challenge-302 "the caller got $rcode"
  if [ "$rcode" = 302 ]; then
    record 6b "a 302 from the gate" SETTLED "passed through"
  else
    record 6b "a 302 from the gate" DIFFERS "the caller got $rcode, not the gate's redirect"
  fi

  # 6c — and with auth-signin, which the dialect writes, the gate's 401 becomes a redirect for
  # every caller, curl included.
  signin=$(fetch "http://$svc/actuator/health" spike-nginx.example.test -X POST)
  scode=$(status_of "$signin")
  location=$(printf '%s\n' "$signin" | grep -i '^location:' | head -1 | tr -d '\r')
  shown with-signin "$scode ${location:-no Location}"
  if [ "$scode" = 401 ]; then
    record 6c "auth-signin and the challenge" SETTLED "a POST still gets 401"
  else
    record 6c "auth-signin and the challenge" DIFFERS "a POST gets $scode — the gate's challenge shape is overridden"
  fi

  # 6d — the sliding re-mint, which needs a Set-Cookie on an *allow* to reach the browser. It does,
  # unless the application's own answer is not 2xx.
  ok=$(fetch "http://$svc/x" spike-nginx-ok.example.test)
  ok404=$(fetch "http://$svc/nope" spike-nginx-ok404.example.test)
  always=$(fetch "http://$svc/nope" spike-nginx-ok404-always.example.test)
  remint=no; remint404=no; remint_always=no
  has_header "$ok" set-cookie "spike_session=remint" && remint=yes
  has_header "$ok404" set-cookie "spike_session=remint" && remint404=yes
  has_header "$always" set-cookie "spike_session=remint" && remint_always=yes
  shown re-mint "application 2xx: $remint / 404: $remint404 / 404 with auth-always-set-cookie: $remint_always"
  # Two claims, not one: that the default drops the cookie, and that the annotation the dialect
  # writes is what puts it back. The second is the one that would rot silently if this row only
  # ever measured the default.
  if [ "$remint" = yes ] && [ "$remint_always" = yes ]; then
    record 6d "Set-Cookie on an allow" SETTLED \
      "reaches the caller on a 2xx; on a 404 the default drops it (non-2xx=$remint404) and auth-always-set-cookie restores it"
  else
    record 6d "Set-Cookie on an allow" DIFFERS \
      "2xx=$remint non-2xx=$remint404 non-2xx with auth-always-set-cookie=$remint_always"
  fi

  # 6e — the injection Traefik's conformance run proves for Traefik.
  echoed=$(fetch "http://$svc/x" spike-nginx-bare.example.test -H "X-Auth-Request-User: forged-admin")
  shown application "$(printf '%s' "$echoed" | tail -1)"
  if printf '%s' "$echoed" | grep -q "user=forged-admin"; then
    record 6e "identity header injection" DIFFERS "a caller's X-Auth-Request-User reaches the application"
  else
    record 6e "identity header injection" SETTLED "a caller's X-Auth-Request-User is stripped"
  fi
}

nginx_ingresses() { # nginx_ingresses <class>
  auth="http://spike-auth.$NS.svc.cluster.local:8080/auth?host=\$host&uri=\$request_uri&method=\$request_method&proto=\$scheme"
  headers="X-Auth-Request-User,X-Auth-Request-Groups,X-Auth-Request-Email"
  cat <<INGRESS | k apply -f - >/dev/null
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: spike-nginx
  namespace: $NS
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "$auth"
    nginx.ingress.kubernetes.io/auth-response-headers: "$headers"
    nginx.ingress.kubernetes.io/auth-signin: "http://spike-auth.$NS.svc.cluster.local:8080/oidc/start?rd=\$scheme://\$host\$request_uri"
spec:
  ingressClassName: $1
  rules:
    - host: spike-nginx.example.test
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: { service: { name: spike-backend, port: { number: 8081 } } }
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: spike-nginx-nosignin
  namespace: $NS
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "$auth"
    nginx.ingress.kubernetes.io/auth-response-headers: "$headers"
spec:
  ingressClassName: $1
  rules:
    - host: spike-nginx-nosignin.example.test
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: { service: { name: spike-backend, port: { number: 8081 } } }
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: spike-nginx-302
  namespace: $NS
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "http://spike-auth.$NS.svc.cluster.local:8082/auth-302"
spec:
  ingressClassName: $1
  rules:
    - host: spike-nginx-302.example.test
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: { service: { name: spike-backend, port: { number: 8081 } } }
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: spike-nginx-ok
  namespace: $NS
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "http://spike-auth.$NS.svc.cluster.local:8082/auth-ok"
    nginx.ingress.kubernetes.io/auth-response-headers: "$headers"
spec:
  ingressClassName: $1
  rules:
    - host: spike-nginx-ok.example.test
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: { service: { name: spike-backend, port: { number: 8081 } } }
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: spike-nginx-ok404
  namespace: $NS
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "http://spike-auth.$NS.svc.cluster.local:8082/auth-ok"
    nginx.ingress.kubernetes.io/auth-response-headers: "$headers"
spec:
  ingressClassName: $1
  rules:
    - host: spike-nginx-ok404.example.test
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: { service: { name: spike-auth, port: { number: 8080 } } }
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: spike-nginx-ok404-always
  namespace: $NS
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "http://spike-auth.$NS.svc.cluster.local:8082/auth-ok"
    nginx.ingress.kubernetes.io/auth-response-headers: "$headers"
    nginx.ingress.kubernetes.io/auth-always-set-cookie: "true"
spec:
  ingressClassName: $1
  rules:
    - host: spike-nginx-ok404-always.example.test
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: { service: { name: spike-auth, port: { number: 8080 } } }
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: spike-nginx-bare
  namespace: $NS
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "http://spike-auth.$NS.svc.cluster.local:8082/auth-bare"
    nginx.ingress.kubernetes.io/auth-response-headers: "$headers"
spec:
  ingressClassName: $1
  rules:
    - host: spike-nginx-bare.example.test
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: { service: { name: spike-backend, port: { number: 8083 } } }
INGRESS
}

# --- row 9 · Traefik -----------------------------------------------------------------------------
#
# The one property the two-cookie design cannot work without: a non-2xx from forwardAuth reaching
# the browser unaltered, Set-Cookie included. The conformance suite proves the body and the
# WWW-Authenticate; the cookie on a refusal is the part it cannot reach without an issuer.

row_9() {
  wanted 9 || return 0
  heading 9 "Traefik: a forwardAuth refusal, Set-Cookie included, reaching the caller"
  shown assumption "a non-2xx from forwardAuth reaches the caller unaltered, body and Set-Cookie included"
  class=$(k get ingressclass -o json 2>/dev/null |
    jq -r '.items[] | select(.spec.controller | test("traefik")) | .metadata.name' | head -1)
  if [ -z "$class" ]; then
    record 9 "traefik refusal" SKIPPED "no traefik IngressClass in this cluster"
    return 0
  fi
  api=traefik.io/v1alpha1
  has_kind middlewares || { record 9 "traefik refusal" SKIPPED "no Middleware CRD"; return 0; }
  k get crd middlewares.traefik.containo.us >/dev/null 2>&1 && api=traefik.containo.us/v1alpha1
  svc=$(controller_service traefik "app.kubernetes.io/name=traefik")
  if [ -z "$svc" ]; then
    record 9 "traefik refusal" SKIPPED "traefik IngressClass $class, but no Service to call"
    return 0
  fi
  ran "kubectl apply -f - <<< 'Middleware forwardAuth + Ingress naming it' ; curl via $svc"
  cat <<MIDDLEWARE | k apply -f - >/dev/null
apiVersion: $api
kind: Middleware
metadata:
  name: spike-auth
  namespace: $NS
spec:
  forwardAuth:
    address: "http://spike-auth.$NS.svc.cluster.local:8080/auth"
    authResponseHeaders: ["X-Auth-Request-User", "X-Auth-Request-Groups", "X-Auth-Request-Email"]
    addAuthCookiesToResponse: ["spike_session"]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: spike-traefik
  namespace: $NS
  annotations:
    traefik.ingress.kubernetes.io/router.middlewares: "$NS-spike-auth@kubernetescrd"
spec:
  ingressClassName: $class
  rules:
    - host: spike-traefik.example.test
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: { service: { name: spike-backend, port: { number: 8081 } } }
MIDDLEWARE
  sleep 8
  response=$(fetch "http://$svc/actuator/health" spike-traefik.example.test -X POST)
  code=$(status_of "$response")
  seen=$(last_authreq)
  shown status "$code"
  shown auth-saw "${seen:-nothing}"
  body=no; cookie=no; challenge=no
  printf '%s' "$response" | grep -q "$BODY_MARKER" && body=yes
  has_header "$response" set-cookie "$COOKIE_MARKER" && cookie=yes
  has_header "$response" www-authenticate Bearer && challenge=yes
  shown verbatim "body=$body cookie=$cookie www-authenticate=$challenge"
  if [ "$code" = 401 ] && [ "$body" = yes ] && [ "$cookie" = yes ] && [ "$challenge" = yes ]; then
    record 9 "traefik refusal" SETTLED "401 with body, Set-Cookie and WWW-Authenticate intact"
  else
    record 9 "traefik refusal" DIFFERS "status=$code body=$body cookie=$cookie www-authenticate=$challenge"
  fi
}

# --- row 7 · the Che OIDC client -----------------------------------------------------------------

row_7() {
  wanted 7 || return 0
  heading 7 "the Che OIDC client's discovery document"
  shown assumption "backchannel_logout_supported, a sid claim, a refresh token, and a groups claim"
  if [ -z "$issuer" ]; then
    record 7 "OIDC discovery" SKIPPED "no --issuer given"
    return 0
  fi
  url="${issuer%/}/.well-known/openid-configuration"
  ran "curl -sS $url"
  doc=$(curl -sS -m 15 "$url" 2>/dev/null || printf '')
  if [ -z "$doc" ] || ! printf '%s' "$doc" | jq -e .issuer >/dev/null 2>&1; then
    record 7 "OIDC discovery" SKIPPED "no discovery document at $url"
    return 0
  fi
  summary=$(printf '%s' "$doc" | jq -r '
    "backchannel_logout=\(.backchannel_logout_supported // false)" +
    " backchannel_session=\(.backchannel_logout_session_supported // false)" +
    " introspection=\(if .introspection_endpoint then "yes" else "no" end)" +
    " refresh_token=\(if (.grant_types_supported // []) | index("refresh_token") then "yes" else "no" end)" +
    " groups_claim=\(if (.claims_supported // []) | index("groups") then "yes" else "no" end)"')
  shown observed "$summary"
  case "$summary" in
    *backchannel_logout=true*refresh_token=yes*)
      record 7 "OIDC discovery" SETTLED "$summary" ;;
    *)
      record 7 "OIDC discovery" DIFFERS "$summary" ;;
  esac
}

# --- row 8 · the shape of a token a developer can actually fetch ---------------------------------
#
# Five facts turn into configuration: audiences, authorized_parties, introspection.enabled, the
# ID-token discriminator, and one line of advice. The sixth — whether Che's gateway forwards the
# user's access token into the workspace — was looked at and is "no".

row_8() {
  wanted 8 || return 0
  heading 8 "the token a developer can fetch from this realm"
  shown assumption "a JWT with aud, azp, an exp, and no nonce"
  if [ -z "$token_file" ]; then
    record 8 "token shape" SKIPPED "no --token given"
    return 0
  fi
  if [ "$token_file" = "-" ]; then
    token=$(cat)
  else
    token=$(cat "$token_file")
  fi
  token=$(printf '%s' "$token" | tr -d ' \n\r')
  ran "scripts/spike-0009.sh --token <file>   # decodes the payload, calls nothing"
  dots=$(printf '%s' "$token" | tr -cd '.' | wc -c | tr -d ' ')
  if [ "$dots" != 2 ]; then
    shown observed "not a JWT: $dots dots — an opaque token"
    record 8 "token shape" DIFFERS "opaque access token: bearer.introspection.enabled must be on"
    return 0
  fi
  payload=$(printf '%s' "$token" | cut -d. -f2 | tr '_-' '/+')
  case $(( ${#payload} % 4 )) in
    2) payload="$payload==" ;;
    3) payload="$payload=" ;;
    *) ;;
  esac
  claims=$(printf '%s' "$payload" | base64 -d 2>/dev/null || printf '')
  if [ -z "$claims" ]; then
    record 8 "token shape" DIFFERS "the payload did not decode as base64url"
    return 0
  fi
  summary=$(printf '%s' "$claims" | jq -r '
    "aud=\(.aud // "absent")" +
    " azp=\(.azp // "absent")" +
    " lifetime=\(if .exp and .iat then "\(.exp - .iat)s" else "unknown" end)" +
    " nonce=\(if .nonce then "present" else "absent" end)" +
    " at_hash=\(if .at_hash then "present — this is an ID token" else "absent" end)" +
    " sid=\(if .sid then "present" else "absent" end)"')
  shown observed "$summary"
  case "$summary" in
    *'at_hash=present'*) record 8 "token shape" DIFFERS "$summary" ;;
    *'aud=absent'*)      record 8 "token shape" DIFFERS "$summary" ;;
    *)                   record 8 "token shape" SETTLED "$summary" ;;
  esac
}

# --- run -----------------------------------------------------------------------------------------

for tool in kubectl jq; do
  command -v "$tool" >/dev/null 2>&1 || { printf '%s is required\n' "$tool" >&2; exit 2; }
done

if ! have_cluster; then
  printf 'no reachable cluster: kubectl has no current context\n' >&2
  exit 2
fi

row_1
row_2
row_3
row_4
row_7
row_8

if [ "$live" = 1 ]; then
  if wanted 5 || wanted 6 || wanted 9; then
    [ "$markdown" = 1 ] || printf '\n\033[2mstanding up the live rig in namespace %s\033[0m\n' "$NS"
    live_setup
    trap 'live_teardown; cleanup_tmp' EXIT
    row_5
    row_6
    row_9
  fi
else
  wanted 5 && record 5 "haproxy-ingress" SKIPPED "needs --live"
  wanted 6 && record 6 "ingress-nginx" SKIPPED "needs --live"
  wanted 9 && record 9 "traefik refusal" SKIPPED "needs --live"
fi

if [ "$markdown" = 1 ]; then
  bt=$(printf '\140')
  printf '| Row | Fact | Verdict | Observed |\n| --- | ---- | ------- | -------- |\n'
  while IFS="$(printf '\t')" read -r row title verdict observed; do
    printf '| %s | %s | %s%s%s | %s |\n' "$row" "$title" "$bt" "$verdict" "$bt" "$observed"
  done <"$RESULTS"
else
  printf '\n\033[1m── summary\033[0m\n'
  while IFS="$(printf '\t')" read -r row title verdict observed; do
    printf '  %-3s %-28s %-8s %s\n' "$row" "$title" "$verdict" "$observed"
  done <"$RESULTS"
fi

differs=$(grep -c '	DIFFERS	' "$RESULTS" || true)
[ "$differs" = 0 ] || exit 1
exit 0
