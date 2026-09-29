{{- define "preauth-proxy.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "preauth-proxy.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "preauth-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "preauth-proxy.labels" -}}
helm.sh/chart: {{ include "preauth-proxy.chart" . }}
app.kubernetes.io/name: {{ include "preauth-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "preauth-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "preauth-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
The container image reference. `image.digest` wins when set (`repo@sha256:…`, immutable — what a
release's cosign signature is bound to); otherwise `repo:tag`, where the tag defaults to the chart's
appVersion, which the release workflow sets from the same `v*` git tag that produced the image.
*/}}
{{- define "preauth-proxy.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end -}}

{{/*
`values.config` as the YAML text the ConfigMap carries: a string verbatim, a map through toYaml.
*/}}
{{- define "preauth-proxy.configText" -}}
{{- if kindIs "string" .Values.config -}}
{{- .Values.config -}}
{{- else -}}
{{- toYaml .Values.config -}}
{{- end -}}
{{- end -}}

{{/*
Render-time consistency checks between `values.config` (which the binary reads) and the pod spec
(which the kubelet reads). Emits nothing; `fail`s on a mismatch.

- `config.listen`'s port must be `containerPort`: the probes, the Service's `targetPort: http` and
  the NetworkPolicy all follow the container port, so a mismatch is a pod nothing can reach.
- `preStopSleepSeconds` must leave room for the drain: preStop < grace, and
  preStop + `limits.drain_timeout_secs` < grace, or the kubelet SIGKILLs mid-drain.
- The startupProbe budget must cover the startup acquisition's worst case,
  `limits.connect_timeout_secs + limits.response_timeout_secs`.

Defaults mirror `Limits::default()` in bins/preauth-proxy/src/domain/config.rs.
*/}}
{{- define "preauth-proxy.validate" -}}
{{- $cfg := fromYaml (include "preauth-proxy.configText" .) -}}
{{- if hasKey $cfg "Error" -}}
{{- fail (printf "config is not valid YAML: %v" (get $cfg "Error")) -}}
{{- end -}}
{{- $listen := toString (required "config.listen is required (the proxy's bind address, e.g. \"[::]:8080\")" (get $cfg "listen")) -}}
{{- $port := regexFind "[0-9]+$" $listen -}}
{{- if ne $port (toString .Values.containerPort) -}}
{{- fail (printf "config.listen (%s) binds port %q but containerPort is %v — set them to the same port, or the probes, Service and NetworkPolicy aim at a port nothing listens on" $listen $port .Values.containerPort) -}}
{{- end -}}
{{- $limits := default (dict) (get $cfg "limits") -}}
{{- $drain := int (default 20 (get $limits "drain_timeout_secs")) -}}
{{- $connect := int (default 5 (get $limits "connect_timeout_secs")) -}}
{{- $response := int (default 60 (get $limits "response_timeout_secs")) -}}
{{- $preStop := int .Values.preStopSleepSeconds -}}
{{- $grace := int .Values.terminationGracePeriodSeconds -}}
{{- if ge $preStop $grace -}}
{{- fail (printf "preStopSleepSeconds (%d) must be less than terminationGracePeriodSeconds (%d) — the sleep counts against the grace period, so SIGTERM would never arrive before SIGKILL" $preStop $grace) -}}
{{- end -}}
{{- if ge (add $preStop $drain) $grace -}}
{{- fail (printf "preStopSleepSeconds (%d) + config.limits.drain_timeout_secs (%d) must be less than terminationGracePeriodSeconds (%d), or the kubelet kills the proxy mid-drain" $preStop $drain $grace) -}}
{{- end -}}
{{- $budget := mul (int .Values.startupProbe.periodSeconds) (int .Values.startupProbe.failureThreshold) -}}
{{- if le $budget (add $connect $response) -}}
{{- fail (printf "startupProbe budget (periodSeconds × failureThreshold = %ds) must exceed the startup acquisition's worst case, config.limits.connect_timeout_secs + response_timeout_secs = %ds" $budget (add $connect $response)) -}}
{{- end -}}
{{- end -}}
