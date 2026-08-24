{{/*
Chart name, truncated and DNS-1123-safe.
*/}}
{{- define "weebo-si-operator.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name — the release name if it already contains the chart name, the
chart name plus release name otherwise. Standard `helm create` scaffold, no chart-specific
detail here.
*/}}
{{- define "weebo-si-operator.fullname" -}}
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

{{- define "weebo-si-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Labels shared by every object this chart renders.
*/}}
{{- define "weebo-si-operator.labels" -}}
helm.sh/chart: {{ include "weebo-si-operator.chart" . }}
app.kubernetes.io/name: {{ include "weebo-si-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels — a subset of the above, and the only ones a Deployment's `spec.selector` and
its pod template may share, since that field is immutable after creation.
*/}}
{{- define "weebo-si-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "weebo-si-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "weebo-si-operator.webhook.selectorLabels" -}}
{{ include "weebo-si-operator.selectorLabels" . }}
app.kubernetes.io/component: webhook
{{- end -}}

{{- define "weebo-si-operator.controller.selectorLabels" -}}
{{ include "weebo-si-operator.selectorLabels" . }}
app.kubernetes.io/component: controller
{{- end -}}

{{- define "weebo-si-operator.webhookServiceAccountName" -}}
{{- if .Values.serviceAccount.webhook.create -}}
{{- default (printf "%s-webhook" (include "weebo-si-operator.fullname" .)) .Values.serviceAccount.webhook.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.webhook.name -}}
{{- end -}}
{{- end -}}

{{- define "weebo-si-operator.controllerServiceAccountName" -}}
{{- if .Values.serviceAccount.controller.create -}}
{{- default (printf "%s-controller" (include "weebo-si-operator.fullname" .)) .Values.serviceAccount.controller.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.controller.name -}}
{{- end -}}
{{- end -}}

{{/*
The webhook Service's name — named separately because the MutatingWebhookConfiguration's
`clientConfig.service.name` and the certificate's DNS names both need it independent of any
`app.kubernetes.io/component` suffixing rules that might change.
*/}}
{{- define "weebo-si-operator.webhookServiceName" -}}
{{- printf "%s-webhook" (include "weebo-si-operator.fullname" .) -}}
{{- end -}}

{{- define "weebo-si-operator.tlsSecretName" -}}
{{- default (printf "%s-tls" (include "weebo-si-operator.webhookServiceName" .)) .Values.certificates.secretName -}}
{{- end -}}

{{- define "weebo-si-operator.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
