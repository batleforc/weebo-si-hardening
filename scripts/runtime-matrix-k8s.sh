#!/bin/sh
# The cluster tier of the runtime matrix: the same scenarios as scripts/runtime-matrix.sh, run as
# Pods, one per runtime class × profile × scenario, the way a build workspace would run.
#
#   scripts/runtime-matrix-k8s.sh           run against the current kubectl context
#   scripts/runtime-matrix-k8s.sh check     same, and fail if a cell differs from what is expected
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
#   RENDER_ONLY      set to 1 to print the Pods' YAML and touch no cluster.
#
# Admission and start are told apart. Every Pod first goes through a server-side dry run, so the
# namespace's Pod Security level answers for it even when nothing can start. Then, per runtime
# class, a preflight Pod (busybox, `hostUsers: false`, RuntimeDefault seccomp) must succeed before
# the scenarios run: when user-namespaced Pods cannot start on the node at all, the matrix says so
# in a minute, with the node's full error, instead of timing out on every cell.
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

if [ "${RENDER_ONLY:-}" != 1 ]; then
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl label namespace "$NAMESPACE" --overwrite \
  "pod-security.kubernetes.io/enforce=$PSA_LEVEL" \
  "pod-security.kubernetes.io/enforce-version=$PSA_VERSION" >/dev/null
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
table="$tmp/table.md"
{
  echo "| Runtime class | Profile | Scenario | Result |"
  echo "| --- | --- | --- | --- |"
} > "$table"

# Why a Pod is not starting: its first FailedCreatePodSandBox (or Failed) event, in full. The later
# events are "combined from similar events" and cut the message.
pod_failure() { # name
  kubectl -n "$NAMESPACE" get events --field-selector "involvedObject.name=$1" \
    --sort-by=.firstTimestamp -o jsonpath='{range .items[*]}{.reason}: {.message}{"\n"}{end}' \
    < /dev/null 2>/dev/null | grep -m 1 -E '^(FailedCreatePodSandBox|Failed|FailedMount):' || true
}

# What a profile should do, as in scripts/runtime-matrix.sh. A sandboxed runtime that ignores the
# pod's filter (gVisor, Kata by default) passes under weebo-workspace and fails `check`: that is
# the point of the row.
expected() { # profile proc
  case "$1:$2" in
    weebo-container-build:*) echo pass ;;
    weebo-workspace:*) echo fail ;;
    weebo-container-build-chroot:masked) echo pass ;;
    weebo-container-build-chroot:unmasked) echo fail ;;
    *) echo "" ;;
  esac
}

pod_yaml() { # name image proc runtime_class profile command
  printf 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: %s\n  namespace: %s\n' "$1" "$NAMESPACE"
  printf '  labels: {app.kubernetes.io/part-of: weebo-runtime-matrix}\n'
  printf 'spec:\n  restartPolicy: Never\n  hostUsers: false\n'
  [ "$4" != default ] && printf '  runtimeClassName: %s\n' "$4"
  printf '  securityContext:\n    runAsUser: 1000\n    runAsGroup: 1000\n'
  if [ "$5" = RuntimeDefault ]; then
    printf '    seccompProfile: {type: RuntimeDefault}\n'
  else
    printf '    seccompProfile: {type: Localhost, localhostProfile: profiles/%s.json}\n' "$5"
  fi
  printf '  containers:\n    - name: scenario\n      image: %s\n' "$2"
  printf '      command: ["sh", "-c"]\n'
  # The command as a YAML double-quoted scalar: escape backslashes, then quotes.
  printf '      args: ["%s"]\n' "$(printf '%s' "$6" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"
  printf '      securityContext:\n        allowPrivilegeEscalation: true\n'
  [ "$3" = unmasked ] && printf '        procMount: Unmasked\n'
  return 0
}

notes="$tmp/notes.md"
: > "$notes"

# preflight runtime_class: 0 when a plain user-namespaced Pod runs to completion.
preflight() {
  name=$(printf 'preflight-%s' "$1" | cut -c 1-63)
  pod_yaml "$name" "$BUSYBOX" masked "$1" RuntimeDefault "true" > "$tmp/preflight.yaml"
  kubectl -n "$NAMESPACE" delete pod "$name" --ignore-not-found --wait=true >/dev/null < /dev/null
  kubectl apply -f "$tmp/preflight.yaml" >/dev/null < /dev/null || return 1
  waited=0
  while [ "$waited" -lt 90 ]; do
    case $(kubectl -n "$NAMESPACE" get pod "$name" -o jsonpath='{.status.phase}' < /dev/null) in
      Succeeded) kubectl -n "$NAMESPACE" delete pod "$name" --wait=false >/dev/null 2>&1; return 0 ;;
      Failed) break ;;
    esac
    [ -n "$(pod_failure "$name")" ] && [ "$waited" -ge 30 ] && break
    sleep 3
    waited=$((waited + 3))
  done
  {
    echo "**Preflight failed for runtime class \`$1\`**: a busybox Pod with \`hostUsers: false\` and"
    echo "RuntimeDefault seccomp did not start, so no scenario ran; the cells only say whether the Pod"
    echo "was admitted. The node's error:"
    echo
    echo '```'
    pod_failure "$name"
    echo '```'
    echo
  } >> "$notes"
  kubectl -n "$NAMESPACE" describe pod "$name" < /dev/null >&2 || true
  kubectl -n "$NAMESPACE" delete pod "$name" --wait=false >/dev/null 2>&1 || true
  return 1
}

for rc in $RUNTIME_CLASSES; do
  runnable=1
  if [ "${RENDER_ONLY:-}" != 1 ] && ! preflight "$rc"; then runnable=0; fi
  for profile in $PROFILES; do
    # printf, not echo: dash's echo would expand the \n inside a command into a line break.
    printf '%s\n' "$SCENARIOS" | while IFS='|' read -r id image proc cmd; do
      if [ -n "${SCENARIOS_ONLY:-}" ]; then
        case " $SCENARIOS_ONLY " in *" $id "*) ;; *) continue ;; esac
      fi
      name=$(printf '%s-%s-%s' "$rc" "$profile" "$id" | sed 's/weebo-//; s/container-build/cb/' | cut -c 1-63)
      pod_yaml "$name" "$image" "$proc" "$rc" "$profile" "$cmd" > "$tmp/pod.yaml"
      if [ "${RENDER_ONLY:-}" = 1 ]; then echo "---"; cat "$tmp/pod.yaml"; continue; fi
      kubectl -n "$NAMESPACE" delete pod "$name" --ignore-not-found --wait=true >/dev/null < /dev/null
      if ! kubectl apply --dry-run=server -f "$tmp/pod.yaml" > "$tmp/apply" 2>&1 < /dev/null; then
        cell="❌ admission: $(tr '\n' ' ' < "$tmp/apply" | sed 's/.*violates/violates/' | cut -c 1-110 | tr '|' '/')"
      elif [ "$runnable" = 0 ]; then
        cell="admitted, not run (preflight failed)"
      elif ! kubectl apply -f "$tmp/pod.yaml" > "$tmp/apply" 2>&1 < /dev/null; then
        cell="❌ apply: $(tr '\n' ' ' < "$tmp/apply" | cut -c 1-110 | tr '|' '/')"
      else
        cell="❌ timeout"
        waited=0
        while [ "$waited" -lt "$POD_TIMEOUT" ]; do
          phase=$(kubectl -n "$NAMESPACE" get pod "$name" -o jsonpath='{.status.phase}' < /dev/null)
          waiting=$(kubectl -n "$NAMESPACE" get pod "$name" \
            -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' < /dev/null 2>/dev/null || true)
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
        if [ "$cell" = "❌ timeout" ]; then
          last=$(pod_failure "$name" | cut -c 1-200 | tr '|' '/')
          cell="❌ timeout (${phase:-?}${waiting:+/$waiting}) ${last}"
        fi
        kubectl -n "$NAMESPACE" delete pod "$name" --wait=false >/dev/null 2>&1 || true
      fi
      exp=$(expected "$profile" "$proc")
      got=fail
      [ "$cell" = "✅" ] && got=pass
      case "$cell" in "❌ admission"*|admitted*|"❌ timeout"*|"❌ apply"*|"❌ CreateContainer"*|"❌ ErrImage"*|"❌ ImagePull"*) got=broken ;; esac
      if [ -n "$exp" ] && [ "$got" != "$exp" ]; then
        cell="$cell ⚠ expected $exp"
        echo x >> "$tmp/mismatches"
      fi
      echo "| $rc | $profile | $id ($proc) | $cell |" >> "$table"
    done
  done
done

[ "${RENDER_ONLY:-}" = 1 ] && exit 0
if [ -s "$notes" ]; then { echo; cat "$notes"; } >> "$table"; fi
cat "$table"
if [ -n "${OUT:-}" ]; then cp "$table" "$OUT"; fi
mismatches=0
[ -f "$tmp/mismatches" ] && mismatches=$(wc -l < "$tmp/mismatches")
if [ "${1:-}" = check ] && [ "$mismatches" -gt 0 ]; then
  echo "runtime-matrix-k8s: $mismatches cell(s) differ from what is expected" >&2
  exit 1
fi
