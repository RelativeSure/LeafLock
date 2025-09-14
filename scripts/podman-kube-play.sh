#!/bin/bash
# Alternative to podman-compose using podman play kube

# Generate pod spec
cat > leaflock-pod.yaml << 'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: leaflock
  labels:
    app: leaflock
spec:
  hostname: leaflock
  restartPolicy: Always
  containers:
  - name: postgres
    image: docker.io/postgres:15-alpine
    env:
    - name: POSTGRES_PASSWORD
      value: "ChangeMe123!"
    - name: POSTGRES_DB
      value: "notes"
    ports:
    - containerPort: 5432
    volumeMounts:
    - name: postgres-data
      mountPath: /var/lib/postgresql/data
  - name: redis
    image: docker.io/redis:7-alpine
    ports:
    - containerPort: 6379
    volumeMounts:
    - name: redis-data
      mountPath: /data
  - name: backend
    image: localhost/leaflock-backend:latest
    ports:
    - containerPort: 8080
      hostPort: 8080
    env:
    - name: DATABASE_URL
      value: "postgres://postgres:ChangeMe123!@localhost:5432/notes?sslmode=require"
  - name: frontend
    image: localhost/leaflock-frontend:latest
    ports:
    - containerPort: 8080
      hostPort: 3000
  volumes:
  - name: postgres-data
    persistentVolumeClaim:
      claimName: postgres-pvc
  - name: redis-data
    persistentVolumeClaim:
      claimName: redis-pvc
YAML

# Play the kube file
podman play kube leaflock-pod.yaml
