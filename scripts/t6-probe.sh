#!/bin/sh
# RFC 0017's T6 probe: when `image-rewrite` sends a pod's image to the mirror, does the kubelet
# offer the mirror a pull secret keyed on the *upstream* host? The RFC assumes not (the kubelet
# matches secrets on the image it pulls, i.e. the rewritten one); this checks it on a real node.
#
#   scripts/t6-probe.sh        run the three cases below and print a markdown block for §17;
#                              exits 0 if the assumption holds, 1 if not, 2 if inconclusive
#
# Read from outcomes, so it needs no access to the mirror's logs. Every pod pulls with
# `imagePullPolicy: Always`, so the kubelet goes to the registry even when the image is cached:
#
#   C  no secret                                  the mirror serves the image anonymously
#   B  a bogus secret keyed on the mirror's host  the mirror refuses a credential it is offered
#   A  the same secret keyed on the upstream host the question: pulls like C if the secret was
#                                                 not offered to the mirror, fails like B if it was
#
# C must pull and B must fail for A to mean anything; otherwise the verdict is "inconclusive"
# (the mirror requires auth, ignores bad credentials, or the node holds its own credential for
# it). The bogus username is unique per run, so grepping the mirror's access log for it settles
# an inconclusive run by hand.
#
# Environment:
#   T6_NAMESPACE  required: a workspace namespace (`hardening.weebo.io/workspace-namespace`)
#                 inside `imageRewrite.namespaceSelector`, with the feature in `Enforce`, where
#                 `imagePolicy` admits the rewritten image and a restricted pod may run
#   T6_IMAGE      a public upstream image a rule rewrites, with an explicit registry host.
#                 Default: quay.io/libpod/busybox, pinned as in the runtime matrix
#   T6_TIMEOUT    seconds to wait for each pull to settle. Default: 180
#   KUBECONFIG    the cluster, as for kubectl
set -eu

NAMESPACE=${T6_NAMESPACE:?set T6_NAMESPACE to a workspace namespace image-rewrite applies to}
IMAGE=${T6_IMAGE:-quay.io/libpod/busybox@sha256:a9286defaba7b3a519d585ba0e37d0b2cbee74ebfe590960b0b1d6a5e97d1e1d}
TIMEOUT=${T6_TIMEOUT:-180}
RUN=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
SENTINEL="t6-probe-$RUN"

say() { printf '%s\n' "$*" >&2; }
die() { say "t6-probe: $*"; exit 1; }

# The registry host of an image reference: its first component, when that reads as a host.
host_of() {
  first=${1%%/*}
  case "$first" in
    *.* | *:* | localhost) printf '%s' "$first" ;;
    *) return 1 ;;
  esac
}

# shellcheck disable=SC2317,SC2329  # invoked from the trap below, which shellcheck cannot see.
cleanup() {
  kubectl delete pod,secret -n "$NAMESPACE" -l "t6-probe=$RUN" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

for tool in kubectl jq od; do
  command -v "$tool" >/dev/null || die "$tool is not on PATH"
done
upstream=$(host_of "$IMAGE") || die "T6_IMAGE needs an explicit registry host: $IMAGE"

labels=$(kubectl get namespace "$NAMESPACE" -o json) || die "no namespace $NAMESPACE"
printf '%s' "$labels" | jq -e '.metadata.labels["hardening.weebo.io/workspace-namespace"] != null' >/dev/null ||
  die "$NAMESPACE is not a workspace namespace: the pod webhook does not see it"
mode=$(kubectl get weebosiconfig cluster -o jsonpath='{.spec.features.imageRewrite.mode}')
[ "$mode" = Enforce ] || die "imageRewrite.mode is '${mode:-absent}', not Enforce: nothing is rewritten"

# One restricted, short-lived pod; `$2` names its pull secret, empty for none.
pod() {
  secrets=null
  [ -n "$2" ] && secrets="[{\"name\": \"$2\"}]"
  cat <<POD
{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": { "name": "$1", "namespace": "$NAMESPACE", "labels": { "t6-probe": "$RUN" } },
  "spec": {
    "restartPolicy": "Never",
    "imagePullSecrets": $secrets,
    "securityContext": {
      "runAsNonRoot": true, "runAsUser": 65534, "runAsGroup": 65534,
      "seccompProfile": { "type": "RuntimeDefault" }
    },
    "containers": [{
      "name": "probe",
      "image": "$IMAGE",
      "imagePullPolicy": "Always",
      "command": ["true"],
      "resources": {
        "requests": { "cpu": "10m", "memory": "16Mi" },
        "limits": { "cpu": "50m", "memory": "32Mi" }
      },
      "securityContext": {
        "allowPrivilegeEscalation": false,
        "capabilities": { "drop": ["ALL"] }
      }
    }]
  }
}
POD
}

# What the webhook makes of the image, without creating anything.
mirrored=$(pod t6-probe-dry-run "" | kubectl create --dry-run=server -o jsonpath='{.spec.containers[0].image}' -f -) ||
  die "a dry-run pod was refused in $NAMESPACE (see above): the probe pod must be admitted there"
[ "$mirrored" != "$IMAGE" ] || die "$IMAGE was not rewritten in $NAMESPACE: no rule covers $upstream, or the namespace is outside imageRewrite.namespaceSelector"
mirror=$(host_of "$mirrored") || die "the rewritten image has no registry host: $mirrored"
say "t6-probe: $IMAGE -> $mirrored (sentinel user $SENTINEL)"

secret() { # name server
  kubectl create secret docker-registry "$1" -n "$NAMESPACE" --docker-server="$2" \
    --docker-username="$SENTINEL" --docker-password="$RUN" >/dev/null
  kubectl label secret "$1" -n "$NAMESPACE" "t6-probe=$RUN" >/dev/null
}

# Create the pod, then wait for the pull to settle: `pulled`, or `refused: <kubelet message>`.
case_result() { # pod-name secret-name
  pod "$1" "$2" | kubectl create -f - >/dev/null
  deadline=$(($(date +%s) + TIMEOUT))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    state=$(kubectl get pod "$1" -n "$NAMESPACE" -o json)
    phase=$(printf '%s' "$state" | jq -r '.status.phase')
    reason=$(printf '%s' "$state" | jq -r '.status.containerStatuses[0].state.waiting.reason // ""')
    case "$phase/$reason" in
      Running/* | Succeeded/* | Failed/)
        echo pulled
        return
        ;;
      */ErrImagePull | */ImagePullBackOff)
        message=$(kubectl get events -n "$NAMESPACE" --field-selector "involvedObject.name=$1,reason=Failed" \
          -o jsonpath='{.items[0].message}')
        echo "refused: ${message:-$reason}"
        return
        ;;
    esac
    sleep 3
  done
  echo "unsettled after ${TIMEOUT}s"
}

secret "t6-mirror-$RUN" "$mirror"
secret "t6-upstream-$RUN" "$upstream"
c=$(case_result "t6-c-$RUN" "")
b=$(case_result "t6-b-$RUN" "t6-mirror-$RUN")
a=$(case_result "t6-a-$RUN" "t6-upstream-$RUN")
node=$(kubectl get pod "t6-a-$RUN" -n "$NAMESPACE" -o jsonpath='{.spec.nodeName}')
runtime=$(kubectl get node "$node" -o jsonpath='{.status.nodeInfo.kubeletVersion}, {.status.nodeInfo.containerRuntimeVersion}')

status=0
case "$c|$b|$a" in
  pulled\|refused*\|pulled) verdict="holds: the upstream-keyed secret was not offered to the mirror" ;;
  pulled\|refused*\|refused*) verdict="does NOT hold: the upstream-keyed secret was offered to the mirror" status=1 ;;
  *) verdict="inconclusive: C must pull and B must be refused; grep the mirror's access log for $SENTINEL" status=2 ;;
esac

cat <<REPORT
**T6 probe, $(date -u +%Y-%m-%d).** \`$IMAGE\` rewritten to \`$mirrored\` in \`$NAMESPACE\`;
node \`$node\` ($runtime); sentinel user \`$SENTINEL\`.

| Case | Pull secret | Outcome |
| --- | --- | --- |
| C | none | $c |
| B | bogus, keyed on \`$mirror\` | $b |
| A | bogus, keyed on \`$upstream\` | $a |

Assumption $verdict.
REPORT
exit "$status"
