{{/*
Full name of the resource.
*/}}
{{- define "keycloak-wasm-auth.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Secret name for sensitive credentials.
*/}}
{{- define "keycloak-wasm-auth.secretName" -}}
{{- if .Values.existingSecret }}
{{- .Values.existingSecret }}
{{- else }}
{{- include "keycloak-wasm-auth.fullname" . }}
{{- end }}
{{- end }}

{{/*
Base Keycloak realm URL.
*/}}
{{- define "keycloak-wasm-auth.realmUrl" -}}
{{- printf "https://%s/realms/%s" .Values.keycloak.host .Values.keycloak.realm }}
{{- end }}

{{/*
Issuer URL.
*/}}
{{- define "keycloak-wasm-auth.issuer" -}}
{{- if .Values.keycloak.endpoints.issuer }}
{{- .Values.keycloak.endpoints.issuer }}
{{- else }}
{{- include "keycloak-wasm-auth.realmUrl" . }}
{{- end }}
{{- end }}

{{/*
Authorization endpoint.
*/}}
{{- define "keycloak-wasm-auth.authEndpoint" -}}
{{- if .Values.keycloak.endpoints.authorization }}
{{- .Values.keycloak.endpoints.authorization }}
{{- else }}
{{- printf "%s/protocol/openid-connect/auth" (include "keycloak-wasm-auth.realmUrl" .) }}
{{- end }}
{{- end }}

{{/*
Token endpoint.
*/}}
{{- define "keycloak-wasm-auth.tokenEndpoint" -}}
{{- if .Values.keycloak.endpoints.token }}
{{- .Values.keycloak.endpoints.token }}
{{- else }}
{{- printf "%s/protocol/openid-connect/token" (include "keycloak-wasm-auth.realmUrl" .) }}
{{- end }}
{{- end }}

{{/*
JWKS URI.
*/}}
{{- define "keycloak-wasm-auth.jwksUri" -}}
{{- if .Values.keycloak.endpoints.jwks }}
{{- .Values.keycloak.endpoints.jwks }}
{{- else }}
{{- printf "%s/protocol/openid-connect/certs" (include "keycloak-wasm-auth.realmUrl" .) }}
{{- end }}
{{- end }}

{{/*
Logout endpoint.
*/}}
{{- define "keycloak-wasm-auth.logoutEndpoint" -}}
{{- if .Values.keycloak.endpoints.logout }}
{{- .Values.keycloak.endpoints.logout }}
{{- else }}
{{- printf "%s/protocol/openid-connect/logout" (include "keycloak-wasm-auth.realmUrl" .) }}
{{- end }}
{{- end }}

{{/*
Envoy upstream cluster for Keycloak.
*/}}
{{- define "keycloak-wasm-auth.upstreamCluster" -}}
{{- printf "outbound|443||%s" .Values.keycloak.host }}
{{- end }}
