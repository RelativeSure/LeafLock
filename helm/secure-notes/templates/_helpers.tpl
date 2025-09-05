{{/*
Expand the name of the chart.
*/}}
{{- define "secure-notes.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "secure-notes.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "secure-notes.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "secure-notes.labels" -}}
helm.sh/chart: {{ include "secure-notes.chart" . }}
{{ include "secure-notes.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Values.commonLabels }}
{{ toYaml .Values.commonLabels }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "secure-notes.selectorLabels" -}}
app.kubernetes.io/name: {{ include "secure-notes.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Backend labels
*/}}
{{- define "secure-notes.backend.labels" -}}
helm.sh/chart: {{ include "secure-notes.chart" . }}
{{ include "secure-notes.backend.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: backend
{{- if .Values.commonLabels }}
{{ toYaml .Values.commonLabels }}
{{- end }}
{{- end }}

{{/*
Backend selector labels
*/}}
{{- define "secure-notes.backend.selectorLabels" -}}
app.kubernetes.io/name: {{ include "secure-notes.name" . }}-backend
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: backend
{{- end }}

{{/*
Frontend labels
*/}}
{{- define "secure-notes.frontend.labels" -}}
helm.sh/chart: {{ include "secure-notes.chart" . }}
{{ include "secure-notes.frontend.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: frontend
{{- if .Values.commonLabels }}
{{ toYaml .Values.commonLabels }}
{{- end }}
{{- end }}

{{/*
Frontend selector labels
*/}}
{{- define "secure-notes.frontend.selectorLabels" -}}
app.kubernetes.io/name: {{ include "secure-notes.name" . }}-frontend
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: frontend
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "secure-notes.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "secure-notes.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Backend service name
*/}}
{{- define "secure-notes.backend.serviceName" -}}
{{ include "secure-notes.fullname" . }}-backend
{{- end }}

{{/*
Frontend service name
*/}}
{{- define "secure-notes.frontend.serviceName" -}}
{{ include "secure-notes.fullname" . }}-frontend
{{- end }}

{{/*
Backend deployment name
*/}}
{{- define "secure-notes.backend.deploymentName" -}}
{{ include "secure-notes.fullname" . }}-backend
{{- end }}

{{/*
Frontend deployment name
*/}}
{{- define "secure-notes.frontend.deploymentName" -}}
{{ include "secure-notes.fullname" . }}-frontend
{{- end }}

{{/*
ConfigMap name
*/}}
{{- define "secure-notes.configMapName" -}}
{{ include "secure-notes.fullname" . }}-config
{{- end }}

{{/*
Secret name
*/}}
{{- define "secure-notes.secretName" -}}
{{ include "secure-notes.fullname" . }}-secret
{{- end }}

{{/*
Backend image
*/}}
{{- define "secure-notes.backend.image" -}}
{{- $registry := .Values.backend.image.registry | default .Values.global.imageRegistry -}}
{{- $repository := .Values.backend.image.repository -}}
{{- $tag := .Values.backend.image.tag | default .Chart.AppVersion -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry $repository $tag -}}
{{- else -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end -}}
{{- end }}

{{/*
Frontend image
*/}}
{{- define "secure-notes.frontend.image" -}}
{{- $registry := .Values.frontend.image.registry | default .Values.global.imageRegistry -}}
{{- $repository := .Values.frontend.image.repository -}}
{{- $tag := .Values.frontend.image.tag | default .Chart.AppVersion -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry $repository $tag -}}
{{- else -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end -}}
{{- end }}

{{/*
PostgreSQL service name from subchart
*/}}
{{- define "secure-notes.postgresql.serviceName" -}}
{{- if .Values.postgresql.enabled }}
{{- include "postgresql.v1.primary.fullname" .Subcharts.postgresql }}
{{- end }}
{{- end }}

{{/*
Redis service name from subchart
*/}}
{{- define "secure-notes.redis.serviceName" -}}
{{- if .Values.redis.enabled }}
{{- include "redis.fullname" .Subcharts.redis }}-master
{{- end }}
{{- end }}

{{/*
Database URL
*/}}
{{- define "secure-notes.databaseUrl" -}}
{{- if .Values.postgresql.enabled }}
{{- $host := include "secure-notes.postgresql.serviceName" . }}
{{- $port := .Values.postgresql.primary.service.ports.postgresql | default 5432 }}
{{- $database := .Values.postgresql.auth.database }}
{{- $username := .Values.postgresql.auth.username }}
{{- printf "postgres://%s:$(POSTGRES_PASSWORD)@%s:%v/%s?sslmode=require" $username $host $port $database }}
{{- else }}
{{- .Values.externalDatabase.url | default "postgres://postgres:password@localhost:5432/notes" }}
{{- end }}
{{- end }}

{{/*
Redis URL
*/}}
{{- define "secure-notes.redisUrl" -}}
{{- if .Values.redis.enabled }}
{{- $host := include "secure-notes.redis.serviceName" . }}
{{- $port := .Values.redis.master.service.ports.redis | default 6379 }}
{{- printf "%s:%v" $host $port }}
{{- else }}
{{- .Values.externalRedis.url | default "localhost:6379" }}
{{- end }}
{{- end }}

{{/*
Common annotations
*/}}
{{- define "secure-notes.annotations" -}}
{{- if .Values.commonAnnotations }}
{{ toYaml .Values.commonAnnotations }}
{{- end }}
{{- end }}

{{/*
Pod annotations for backend
*/}}
{{- define "secure-notes.backend.podAnnotations" -}}
checksum/config: {{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
checksum/secret: {{ include (print $.Template.BasePath "/secret.yaml") . | sha256sum }}
{{- if .Values.backend.deployment.annotations }}
{{ toYaml .Values.backend.deployment.annotations }}
{{- end }}
{{- end }}

{{/*
Pod annotations for frontend
*/}}
{{- define "secure-notes.frontend.podAnnotations" -}}
checksum/config: {{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
{{- if .Values.frontend.deployment.annotations }}
{{ toYaml .Values.frontend.deployment.annotations }}
{{- end }}
{{- end }}

{{/*
Return the proper image pull secrets
*/}}
{{- define "secure-notes.imagePullSecrets" -}}
{{- $pullSecrets := list }}
{{- if .Values.global.imagePullSecrets }}
  {{- $pullSecrets = .Values.global.imagePullSecrets }}
{{- end }}
{{- if .Values.backend.image.pullSecrets }}
  {{- $pullSecrets = concat $pullSecrets .Values.backend.image.pullSecrets }}
{{- end }}
{{- if .Values.frontend.image.pullSecrets }}
  {{- $pullSecrets = concat $pullSecrets .Values.frontend.image.pullSecrets }}
{{- end }}
{{- if (not (empty $pullSecrets)) }}
imagePullSecrets:
{{- range $pullSecrets }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Validate required values
*/}}
{{- define "secure-notes.validateRequiredValues" -}}
{{- if and (not .Values.postgresql.enabled) (not .Values.externalDatabase.url) }}
  {{- fail "Either postgresql must be enabled or externalDatabase.url must be provided" }}
{{- end }}
{{- if and (not .Values.redis.enabled) (not .Values.externalRedis.url) }}
  {{- fail "Either redis must be enabled or externalRedis.url must be provided" }}
{{- end }}
{{- end }}

{{/*
Generate backend environment variables
*/}}
{{- define "secure-notes.backend.env" -}}
- name: PORT
  value: {{ .Values.backend.env.PORT | quote }}
- name: DATABASE_URL
  value: {{ include "secure-notes.databaseUrl" . | quote }}
- name: REDIS_URL
  value: {{ include "secure-notes.redisUrl" . | quote }}
- name: CORS_ORIGINS
  value: {{ .Values.config.backend.corsOrigins | quote }}
- name: JWT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "secure-notes.secretName" . }}
      key: jwt-secret
- name: SERVER_ENCRYPTION_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "secure-notes.secretName" . }}
      key: server-encryption-key
{{- if .Values.postgresql.enabled }}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.postgresql.auth.existingSecret | default (printf "%s-postgresql" .Release.Name) }}
      key: {{ .Values.postgresql.auth.secretKeys.userPasswordKey | default "password" }}
{{- end }}
{{- if .Values.redis.enabled }}
- name: REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.redis.auth.existingSecret | default (printf "%s-redis" .Release.Name) }}
      key: {{ .Values.redis.auth.existingSecretPasswordKey | default "redis-password" }}
{{- end }}
{{- end }}