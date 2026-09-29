{{- define "endpoint-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "endpoint-gateway.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s" (include "endpoint-gateway.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "endpoint-gateway.labels" -}}
app.kubernetes.io/name: {{ include "endpoint-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: weebo-si-hardening
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{- define "endpoint-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "endpoint-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "endpoint-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "endpoint-gateway.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
The container image reference. `image.digest` wins when set (`repo@sha256:…`, immutable — what a
release's cosign signature is bound to); otherwise `repo:tag`, where the tag defaults to the chart's
appVersion, which the release workflow sets from the same `v*` git tag that produced the image.
*/}}
{{- define "endpoint-gateway.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end -}}
