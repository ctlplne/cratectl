{{- define "cratectl.selector" -}}
app.kubernetes.io/name: cratectl
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end -}}

{{- define "cratectl.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: [ALL]
{{- end -}}

{{- define "cratectl.databaseEnv" -}}
- name: CRATECTL_DSN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.postgres.runtimeSecret | quote }}
      key: {{ .Values.postgres.dsnKey | quote }}
{{- end -}}
