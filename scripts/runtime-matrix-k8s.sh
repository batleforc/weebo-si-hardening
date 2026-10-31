#!/bin/sh
# The cluster tier of the runtime matrix: the same scenarios as scripts/runtime-matrix.sh, run as
# Pods, one per runtime class × profile × scenario, the way a build workspace would run.
#
#   scripts/runtime-matrix-k8s.sh           run against the current kubectl context
#   scripts/runtime-matrix-k8s.sh clean     delete the namespace it works in
#
# Each Pod has `hostUsers: false`, the profile as a `Localhost` seccomp profile, the runtime class
# under test, and `procMount: Unmasked` for the scenarios that need it. The namespace carries a
# Pod Security level (PSA_LEVEL), so a refusal at admission — a level that does not admit
# `procMount: Unmasked` on a user-namespaced pod, for instance — is a result like any other.
#
# The nodes need the profiles under /var/lib/kubelet/seccomp/profiles/ (deploy/seccomp/) and, for
# a runtime class other than `default`, the RuntimeClass objects in
# e2e/runtime-matrix/runtimeclasses.yaml with their handler installed. See docs/runtime-matrix.md.
#
# Environment:
#   RUNTIME_CLASSES  runtime classes to compare; `default` means no runtimeClassName (the node's
#                    default handler). Default: "default".
#   PROFILES         profile names, without .json. Default: the three production profiles.
#   SCENARIOS_ONLY   space-separated scenario ids to run. Default: all.
#   PSA_LEVEL        the namespace's enforce level. Default: baseline.
#   PSA_VERSION      its enforce-version. Default: latest.
#   NAMESPACE        Default: weebo-runtime-matrix.
#   POD_TIMEOUT      seconds to wait for one Pod. Default: 300.
#   OUT              also write the table to this file.
set -eu

RUNTIME_CLASSES=${RUNTIME_CLASSES:-default}
PROFILES=${PROFILES:-"weebo-container-build weebo-container-build-chroot weebo-workspace"}
PSA_LEVEL=${PSA_LEVEL:-baseline}
PSA_VERSION=${PSA_VERSION:-latest}
NAMESPACE=${NAMESPACE:-weebo-runtime-matrix}
POD_TIMEOUT=${POD_TIMEOUT:-300}

# Same images, same digests as the local tier.
BUILDAH=quay.io/buildah/stable@sha256:77a555756c942f4f0e2916a2a95bace8f109622201b3b70b008a597cf5b7aa69
PODMAN=quay.io/podman/stable@sha256:90c7dcc328ae74710338fbb37f4505fafe38e63c93cfa61b43e1907d0817871a
BUSYBOX=quay.io/libpod/busybox@sha256:a9286defaba7b3a519d585ba0e37d0b2cbee74ebfe590960b0b1d6a5e97d1e1d

CTX="mkdir -p /tmp/ctx && printf 'FROM $BUSYBOX\\nRUN echo built > /built\\n' > /tmp/ctx/Containerfile"
# id | image | /proc | command
SCENARIOS="buildah-chroot|$BUILDAH|masked|$CTX && buildah build --storage-driver=overlay -t t /tmp/ctx
buildah-oci|$BUILDAH|unmasked|$CTX && buildah build --isolation oci --network host --storage-driver=overlay -t t /tmp/ctx
podman-build|$PODMAN|masked|$CTX && podman build -t t /tmp/ctx
podman-run|$PODMAN|masked|podman run --rm $BUSYBOX echo ran
podman-run-detached|$PODMAN|unmasked|podman run -d --name s $BUSYBOX sleep 60 && podman exec s true && podman rm -f -t0 s"

if [ "${1:-}" = clean ]; then
  kubectl delete namespace "$NAMESPACE" --ignore-not-found --wait=false
  exit 0
fi

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl label namespace "$NAMESPACE" --overwrite \
  "pod-security.kubernetes.io/enforce=$PSA_LEVEL" \
  "pod-security.kubernetes.io/enforce-version=$PSA_VERSION" >/dev/null

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
table="$tmp/table.md"
{
  echo "| Runtime class | Profile | Scenario | Result |"
  echo "| --- | --- | --- | --- |"
} > "$table"

pod_yaml() { # name image proc runtime_class profile command
  printf 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: %s\n  namespace: %s\n' "$1" "$NAMESPACE"
  printf '  labels: {app.kubernetes.io/part-of: weebo-runtime-matrix}\n'
  printf 'spec:\n  restartPolicy: Never\n  hostUsers: false\n'
  [ "$4" != default ] && printf '  runtimeClassName: %s\n' "$4"
  printf '  securityContext:\n    runAsUser: 1000\n    runAsGroup: 1000\n'
  printf '    seccompProfile: {type: Localhost, localhostProfile: profiles/%s.json}\n' "$5"
  printf '  containers:\n    - name: scenario\n      image: %s\n' "$2"
  printf '      command: ["sh", "-c"]\n'
  # The command as a YAML double-quoted scalar: escape backslashes, then quotes.
  printf '      args: ["%s"]\n' "$(printf '%s' "$6" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"
  printf '      securityContext:\n        allowPrivilegeEscalation: true\n'
  [ "$3" = unmasked ] && printf '        procMount: Unmasked\n'
  return 0
}

for rc in $RUNTIME_CLASSES; do
  for profile in $PROFILES; do
    echo "$SCENARIOS" | while IFS='|' read -r id image proc cmd; do
      if [ -n "${SCENARIOS_ONLY:-}" ]; then
        case " $SCENARIOS_ONLY " in *" $id "*) ;; *) continue ;; esac
      fi
      name=$(printf '%s-%s-%s' "$rc" "$profile" "$id" | sed 's/weebo-//; s/container-build/cb/' | cut -c 1-63)
      kubectl -n "$NAMESPACE" delete pod "$name" --ignore-not-found --wait=true >/dev/null
      pod_yaml "$name" "$image" "$proc" "$rc" "$profile" "$cmd" > "$tmp/pod.yaml"
      if ! kubectl apply -f "$tmp/pod.yaml" > "$tmp/apply" 2>&1; then
        cell="❌ admission: $(tr '\n' ' ' < "$tmp/apply" | sed 's/.*violates/violates/' | cut -c 1-110 | tr '|' '/')"
      else
        cell="❌ timeout"
        waited=0
        while [ "$waited" -lt "$POD_TIMEOUT" ]; do
          phase=$(kubectl -n "$NAMESPACE" get pod "$name" -o jsonpath='{.status.phase}')
          waiting=$(kubectl -n "$NAMESPACE" get pod "$name" \
            -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null || true)
          case "$phase:$waiting" in
            Succeeded:*) cell="✅"; break ;;
            Failed:*)
              why=$(kubectl -n "$NAMESPACE" logs "$name" 2>/dev/null \
                | grep -m 1 -iE 'not permitted|denied|error' | cut -c 1-80 | tr '|' '/')
              code=$(kubectl -n "$NAMESPACE" get pod "$name" \
                -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}')
              cell="❌ ${why:-exit $code}"
              break ;;
            *:CreateContainerError | *:CreateContainerConfigError | *:RunContainerError | \
              *:ErrImagePull | *:ImagePullBackOff | *:InvalidImageName)
              msg=$(kubectl -n "$NAMESPACE" get pod "$name" \
                -o jsonpath='{.status.containerStatuses[0].state.waiting.message}' | cut -c 1-90 | tr '|' '/')
              cell="❌ $waiting: $msg"
              break ;;
          esac
          sleep 3
          waited=$((waited + 3))
        done
        kubectl -n "$NAMESPACE" delete pod "$name" --wait=false >/dev/null 2>&1 || true
      fi
      echo "| $rc | $profile | $id ($proc) | $cell |" >> "$table"
    done
  done
done

cat "$table"
if [ -n "${OUT:-}" ]; then cp "$table" "$OUT"; fi
