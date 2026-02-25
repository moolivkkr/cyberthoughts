# Workload Identity Framework: Zero Trust Architecture with Certificate-Based mTLS

## Executive Summary

This document presents a **unified workload identity framework** that integrates:
- **SPIFFE/SPIRE** as the foundational workload identity system
- **Certificate-based mTLS** for all workload-to-workload communication
- **Zero trust architecture** with continuous verification
- **Your Trust Broker** as the root of trust across all environments
- **HR/IAM integration** for automated lifecycle management
- **Cloud-native integration** (AWS, GCP, Kubernetes, VMs, bare metal)

This framework ensures **no static credentials**, **automatic mTLS**, and **identity-driven policy enforcement** across your entire 250K+ endpoint infrastructure.

---

## Part 1: Workload Identity Framework Architecture

### 1.1 Unified Identity Fabric

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    WORKLOAD IDENTITY FRAMEWORK                               │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                        IDENTITY LAYER                                   │ │
│  │                                                                         │ │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐           │ │
│  │  │   Human      │    │  Machine     │    │  Workload    │           │ │
│  │  │  Identities  │    │  Identities  │    │  Identities  │           │ │
│  │  │              │    │              │    │              │           │ │
│  │  │ - Employees  │    │ - Servers    │    │ - Pods       │           │ │
│  │  │ - Contractors│    │ - Laptops    │    │ - Functions  │           │ │
│  │  │ - Partners   │    │ - Mobile     │    │ - Services   │           │ │
│  │  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘           │ │
│  │         │                    │                    │                   │ │
│  │         └────────────────────┴────────────────────┘                   │ │
│  │                              │                                         │ │
│  │                              │ Unified Identity                        │ │
│  │                              ▼                                         │ │
│  │         ┌─────────────────────────────────────────────┐               │ │
│  │         │  SPIFFE IDENTITY (Universal Format)         │               │ │
│  │         │  spiffe://trust-domain/path/to/workload     │               │ │
│  │         └─────────────────────────────────────────────┘               │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                              │                                              │
│                              │ Attested Identity                            │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                    ATTESTATION LAYER                                     │ │
│  │                                                                          │ │
│  │  ┌────────────────┐  ┌─────────────────┐  ┌──────────────────┐        │ │
│  │  │  K8s           │  │  AWS IAM        │  │  GCP IAM         │        │ │
│  │  │  Attestation   │  │  Attestation    │  │  Attestation     │        │ │
│  │  │                │  │                 │  │                  │        │ │
│  │  │ - ServiceAcct  │  │ - EC2 Instance  │  │ - GCE Instance   │        │ │
│  │  │ - Pod UID      │  │ - IAM Role      │  │ - Service Acct   │        │ │
│  │  │ - Namespace    │  │ - Instance ID   │  │ - Project ID     │        │ │
│  │  └────────────────┘  └─────────────────┘  └──────────────────┘        │ │
│  │                                                                          │ │
│  │  ┌────────────────┐  ┌─────────────────┐  ┌──────────────────┐        │ │
│  │  │  Unix/Linux    │  │  Azure MSI      │  │  x509 Cert       │        │ │
│  │  │  Attestation   │  │  Attestation    │  │  Attestation     │        │ │
│  │  │                │  │                 │  │                  │        │ │
│  │  │ - Process UID  │  │ - Managed ID    │  │ - Client Cert    │        │ │
│  │  │ - Binary Path  │  │ - Resource ID   │  │ - Serial Number  │        │ │
│  │  └────────────────┘  └─────────────────┘  └──────────────────┘        │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                              │                                              │
│                              │ Verified Identity                            │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                    CERTIFICATE LAYER                                     │ │
│  │                                                                          │ │
│  │               ┌──────────────────────────────────┐                      │ │
│  │               │  SPIRE Server (CA Function)      │                      │ │
│  │               │  - Issues X.509 SVIDs            │                      │ │
│  │               │  - 1 hour TTL (default)          │                      │ │
│  │               │  - Automatic rotation            │                      │ │
│  │               └────────────┬─────────────────────┘                      │ │
│  │                            │                                             │ │
│  │                            │ Upstream CA                                 │ │
│  │                            ▼                                             │ │
│  │               ┌──────────────────────────────────┐                      │ │
│  │               │  YOUR TRUST BROKER               │                      │ │
│  │               │  (Vault + EJBCA)                 │                      │ │
│  │               │  - Root of trust                 │                      │ │
│  │               │  - Crypto-agility                │                      │ │
│  │               │  - PQC ready                     │                      │ │
│  │               └────────────┬─────────────────────┘                      │ │
│  │                            │                                             │ │
│  │                            │ Trust Chain                                 │ │
│  │                            ▼                                             │ │
│  │               ┌──────────────────────────────────┐                      │ │
│  │               │  OFFLINE ROOT CA                 │                      │ │
│  │               │  (FIPS 140-2 Level 3 HSM)        │                      │ │
│  │               └──────────────────────────────────┘                      │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                              │                                              │
│                              │ mTLS Everywhere                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                    ENFORCEMENT LAYER                                     │ │
│  │                                                                          │ │
│  │  ┌────────────────┐  ┌─────────────────┐  ┌──────────────────┐        │ │
│  │  │  Network       │  │  Application    │  │  Platform        │        │ │
│  │  │  Enforcement   │  │  Enforcement    │  │  Enforcement     │        │ │
│  │  │                │  │                 │  │                  │        │ │
│  │  │ - Istio mTLS   │  │ - SDK (Go/Java) │  │ - OPA/Kyverno    │        │ │
│  │  │ - Envoy Proxy  │  │ - Native TLS    │  │ - K8s Policies   │        │ │
│  │  │ - AuthzPolicy  │  │ - gRPC mTLS     │  │ - RBAC           │        │ │
│  │  └────────────────┘  └─────────────────┘  └──────────────────┘        │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 SPIFFE/SPIRE as Foundation

**Why SPIFFE/SPIRE for Workload Identity:**

1. **Universal Identity Format**
   - `spiffe://company.com/ns/production/sa/api-service`
   - Works across Kubernetes, VMs, cloud, on-prem
   - Language and platform agnostic

2. **Cryptographic Identity**
   - X.509-SVID (certificate-based)
   - JWT-SVID (token-based) for lightweight use cases
   - Automatic rotation without workload restart

3. **Attestation-Based Trust**
   - Workload identity derived from platform (K8s, AWS, GCP)
   - No static credentials in config files
   - Defense against credential theft

4. **Zero Trust Native**
   - Every workload gets unique identity
   - Continuous identity verification
   - Least privilege by default

### 1.3 Architecture: SPIRE Deployment Topology

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MULTI-REGION SPIRE DEPLOYMENT                             │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                      GLOBAL SPIRE ROOT SERVER                           │ │
│  │                      spiffe://company.com                               │ │
│  │                                                                         │ │
│  │  - Issues intermediate CA certs to regional servers                    │ │
│  │  - 1-year intermediate validity                                        │ │
│  │  - Federation authority for cross-region trust                         │ │
│  │  - Backed by YOUR TRUST BROKER                                         │ │
│  └──────────────────┬────────────────────┬─────────────────────┬──────────┘ │
│                     │                    │                     │            │
│       ┌─────────────▼─────────┐  ┌──────▼──────────┐  ┌──────▼────────┐  │
│       │ SPIRE Server          │  │ SPIRE Server    │  │ SPIRE Server  │  │
│       │ US-EAST-1 (AWS)       │  │ US-WEST-2 (AWS) │  │ EU (GCP)      │  │
│       │                       │  │                 │  │               │  │
│       │ Trust Domain:         │  │ Trust Domain:   │  │ Trust Domain: │  │
│       │ us-east.company.com   │  │ us-west         │  │ eu.company    │  │
│       └───────┬───────────────┘  └────────┬────────┘  └───────┬───────┘  │
│               │                           │                    │          │
│       ┌───────▼───────┐          ┌────────▼────────┐  ┌───────▼───────┐  │
│       │ SPIRE Agents  │          │ SPIRE Agents    │  │ SPIRE Agents  │  │
│       │               │          │                 │  │               │  │
│       │ - EKS Nodes   │          │ - EKS Nodes     │  │ - GKE Nodes   │  │
│       │ - EC2 VMs     │          │ - EC2 VMs       │  │ - GCE VMs     │  │
│       │ - Lambda (ext)│          │ - Lambda (ext)  │  │ - Cloud Run   │  │
│       └───────┬───────┘          └────────┬────────┘  └───────┬───────┘  │
│               │                           │                    │          │
│       ┌───────▼────────────────────────┐  │                    │          │
│       │  WORKLOADS                     │  │                    │          │
│       │  ┌──────────────────────────┐  │  │                    │          │
│       │  │ Pod: api-service         │  │  │                    │          │
│       │  │ SVID:                    │  │  │                    │          │
│       │  │ spiffe://us-east         │  │  │                    │          │
│       │  │   .company.com/          │  │  │                    │          │
│       │  │   ns/prod/sa/api         │  │  │                    │          │
│       │  └──────────────────────────┘  │  │                    │          │
│       └────────────────────────────────┘  │                    │          │
└───────────────────────────────────────────┴────────────────────┴──────────────┘
                                            │
                                            │ Federation
                                            │ (Bundle Exchange)
                                            ▼
              ┌──────────────────────────────────────────┐
              │  CROSS-REGION SERVICE CALLS              │
              │  us-east Pod → eu-west Pod               │
              │  mTLS with federated trust bundles       │
              └──────────────────────────────────────────┘
```

---

## Part 2: Zero Trust Implementation

### 2.1 Zero Trust Principles with Workload Identity

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ZERO TRUST CONTROL PLANE                                  │
│                                                                              │
│  1. VERIFY EXPLICITLY                                                        │
│     ┌────────────────────────────────────────────────────────────────────┐  │
│     │ Every request authenticated with workload certificate (SVID)       │  │
│     │ - Source identity: spiffe://company.com/ns/prod/sa/frontend        │  │
│     │ - Destination identity: spiffe://company.com/ns/prod/sa/backend    │  │
│     │ - Context: Time, location, device health (for user access)         │  │
│     └────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  2. LEAST PRIVILEGE ACCESS                                                   │
│     ┌────────────────────────────────────────────────────────────────────┐  │
│     │ Identity-based policies enforce minimum required permissions       │  │
│     │                                                                     │  │
│     │ Example: Frontend can only call /api/users (read), not /admin     │  │
│     │                                                                     │  │
│     │ apiVersion: security.istio.io/v1                                   │  │
│     │ kind: AuthorizationPolicy                                          │  │
│     │ spec:                                                              │  │
│     │   action: ALLOW                                                    │  │
│     │   rules:                                                           │  │
│     │   - from:                                                          │  │
│     │     - source:                                                      │  │
│     │         principals:                                                │  │
│     │         - "spiffe://company.com/ns/prod/sa/frontend"              │  │
│     │     to:                                                            │  │
│     │     - operation:                                                   │  │
│     │         methods: ["GET"]                                           │  │
│     │         paths: ["/api/users/*"]                                    │  │
│     └────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  3. ASSUME BREACH                                                            │
│     ┌────────────────────────────────────────────────────────────────────┐  │
│     │ Short-lived credentials (1 hour SVID TTL)                          │  │
│     │ Network microsegmentation (deny-by-default)                        │  │
│     │ Continuous monitoring & anomaly detection                          │  │
│     │ Automatic certificate rotation                                     │  │
│     └────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 mTLS Everywhere Implementation

**Every Connection Uses mTLS:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    mTLS CONNECTION MATRIX                                    │
│                                                                              │
│  Connection Type          │  Certificate Source    │  TTL   │  Protocol     │
│  ─────────────────────────┼────────────────────────┼────────┼──────────────│
│  Pod → Pod (K8s)          │  SPIRE Agent           │  1h    │  mTLS (Envoy)│
│  VM → Pod                 │  SPIRE Agent           │  1h    │  mTLS (SDK)  │
│  Lambda → API Gateway     │  AWS Private CA        │  7d    │  TLS 1.3     │
│  User → VPN Gateway       │  Trust Broker (EJBCA)  │  1y    │  IKEv2 mTLS  │
│  Device → Wi-Fi (802.1X)  │  SCEP via MDM          │  1y    │  EAP-TLS     │
│  Service → Database       │  SPIRE Agent           │  1h    │  PostgreSQL  │
│  OpAMP Supervisor → SIEM  │  Trust Broker (Vault)  │  90d   │  mTLS (HTTP) │
│  Browser → Web App        │  Let's Encrypt         │  90d   │  TLS 1.3     │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Example: Pod-to-Pod mTLS (Istio + SPIRE)**

```yaml
# SPIRE Server Integration with Istio
apiVersion: v1
kind: ConfigMap
metadata:
  name: istio-spire-config
  namespace: istio-system
data:
  mesh: |
    defaultConfig:
      proxyMetadata:
        SPIFFE_ENDPOINT_SOCKET: unix:///run/spire/sockets/agent.sock
    
    trustDomain: company.com
    
    # Use SPIRE for workload certificates instead of Istiod
    ca:
      address: unix:///run/spire/sockets/agent.sock
      tlsSettings:
        mode: DISABLE
      
    # Certificate TTL from SPIRE
    certificatesRefreshDuration: 30m  # Rotate at 50% of 1h TTL

---
# DaemonSet: SPIRE Agent on each node
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: spire-agent
  namespace: spire
spec:
  template:
    spec:
      hostPID: true
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      
      containers:
      - name: spire-agent
        image: gcr.io/spiffe-io/spire-agent:1.8.0
        args:
          - -config
          - /run/spire/config/agent.conf
        
        volumeMounts:
        - name: spire-config
          mountPath: /run/spire/config
        - name: spire-agent-socket
          mountPath: /run/spire/sockets
          readOnly: false
        - name: spire-token
          mountPath: /var/run/secrets/tokens
        
        livenessProbe:
          exec:
            command: ["/opt/spire/bin/spire-agent", "healthcheck", "-shallow"]
          initialDelaySeconds: 15
          periodSeconds: 60
      
      volumes:
      - name: spire-agent-socket
        hostPath:
          path: /run/spire/sockets
          type: DirectoryOrCreate
      - name: spire-token
        projected:
          sources:
          - serviceAccountToken:
              path: spire-agent
              expirationSeconds: 7200
              audience: spire-server

---
# SPIRE Agent Configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: spire-agent
  namespace: spire
data:
  agent.conf: |
    agent {
      data_dir = "/run/spire"
      log_level = "INFO"
      server_address = "spire-server.spire.svc.cluster.local"
      server_port = "8081"
      socket_path = "/run/spire/sockets/agent.sock"
      trust_bundle_path = "/run/spire/bundle/bundle.crt"
      trust_domain = "company.com"
    }
    
    plugins {
      NodeAttestor "k8s_psat" {
        plugin_data {
          cluster = "production-us-east-1"
        }
      }
      
      KeyManager "disk" {
        plugin_data {
          directory = "/run/spire/data"
        }
      }
      
      WorkloadAttestor "k8s" {
        plugin_data {
          skip_kubelet_verification = true
        }
      }
      
      WorkloadAttestor "unix" {
        plugin_data {}
      }
    }
```

### 2.3 Policy-Driven Access Control

**Identity-Based Authorization (No IP-Based Rules):**

```yaml
# Istio AuthorizationPolicy: Only allow specific workloads
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: payments-api-authz
  namespace: production
spec:
  selector:
    matchLabels:
      app: payments-api
  
  action: ALLOW
  
  rules:
  # Rule 1: Frontend can read payment status
  - from:
    - source:
        principals:
        - "spiffe://company.com/ns/production/sa/frontend-web"
        - "spiffe://company.com/ns/production/sa/frontend-mobile"
    to:
    - operation:
        methods: ["GET"]
        paths: ["/v1/payments/*/status"]
  
  # Rule 2: Order service can create payments
  - from:
    - source:
        principals:
        - "spiffe://company.com/ns/production/sa/order-service"
    to:
    - operation:
        methods: ["POST"]
        paths: ["/v1/payments"]
  
  # Rule 3: Admin service has full access
  - from:
    - source:
        principals:
        - "spiffe://company.com/ns/production/sa/admin-service"
    to:
    - operation:
        methods: ["GET", "POST", "PUT", "DELETE"]
        paths: ["/v1/payments/*"]
    when:
    - key: request.auth.claims[role]
      values: ["admin"]

---
# OPA Gatekeeper: Enforce SPIFFE identity in all policies
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequirespiffeidentity
spec:
  crd:
    spec:
      names:
        kind: K8sRequireSpiffeIdentity
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequirespiffeidentity
        
        violation[{"msg": msg}] {
          # All pods must have SPIRE agent socket mounted
          input.request.kind.kind == "Pod"
          not has_spire_socket(input.request.object)
          msg := sprintf("Pod %v must have SPIRE agent socket mounted", 
                        [input.request.object.metadata.name])
        }
        
        has_spire_socket(pod) {
          volume := pod.spec.volumes[_]
          volume.name == "spire-agent-socket"
          volume.hostPath.path == "/run/spire/sockets"
        }

---
# Constraint: Enforce SPIFFE identity in production namespace
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequireSpiffeIdentity
metadata:
  name: require-spiffe-production
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces:
      - production
      - staging
```

---

## Part 3: Integration with Your Trust Broker

### 3.1 SPIRE Upstream CA Configuration

**SPIRE Server connects to Vault as Upstream CA:**

```hcl
# SPIRE Server Configuration
server {
  bind_address = "0.0.0.0"
  bind_port = "8081"
  trust_domain = "company.com"
  data_dir = "/opt/spire/data"
  log_level = "INFO"
  ca_ttl = "24h"
  default_x509_svid_ttl = "1h"
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type = "postgres"
      connection_string = "postgresql://spire:password@postgres:5432/spire"
    }
  }
  
  KeyManager "disk" {
    plugin_data {
      keys_path = "/opt/spire/data/keys.json"
    }
  }
  
  # Vault as Upstream CA (Production)
  UpstreamAuthority "vault" {
    plugin_data {
      vault_addr = "https://vault.company.com:8200"
      pki_mount_point = "pki_int/spire"
      ca_cert_path = "/opt/spire/conf/vault-ca.pem"
      
      # Kubernetes auth method
      k8s_auth {
        role = "spire-server"
        token_path = "/var/run/secrets/tokens/vault-token"
      }
      
      # Certificate parameters
      cert_ttl = "24h"
      
      # Subject configuration
      namespace = "company"
    }
  }
  
  # Node attestation
  NodeAttestor "k8s_psat" {
    plugin_data {
      clusters = {
        "production-us-east-1" = {
          service_account_allow_list = ["spire:spire-agent"]
        }
      }
    }
  }
  
  NodeAttestor "aws_iid" {
    plugin_data {
      # AWS EC2 instance identity document verification
    }
  }
  
  NodeAttestor "gcp_iit" {
    plugin_data {
      # GCP instance identity token verification
    }
  }
}
```

**Vault PKI Configuration for SPIRE:**

```bash
# Enable PKI secrets engine for SPIRE
vault secrets enable -path=pki_int/spire pki

# Configure intermediate CA for SPIRE
vault write pki_int/spire/intermediate/generate/internal \
  common_name="SPIRE Intermediate CA" \
  ttl=87600h  # 10 years

# Sign intermediate with root CA (your Trust Broker)
vault write pki_root/root/sign-intermediate \
  csr=@pki_int_spire.csr \
  format=pem_bundle \
  ttl=87600h

# Set signed certificate
vault write pki_int/spire/intermediate/set-signed \
  certificate=@signed_certificate.pem

# Create role for SPIRE server
vault write pki_int/spire/roles/spire-intermediate \
  allowed_domains="company.com" \
  allow_subdomains=true \
  allow_bare_domains=false \
  allow_localhost=false \
  client_flag=true \
  server_flag=true \
  code_signing_flag=false \
  email_protection_flag=false \
  key_type="rsa" \
  key_bits=2048 \
  key_usage="DigitalSignature,KeyEncipherment,CertSign,CRLSign" \
  ext_key_usage="ServerAuth,ClientAuth" \
  ttl="24h" \
  max_ttl="24h"

# Configure automatic rotation
vault write pki_int/spire/config/auto-tidy \
  enabled=true \
  tidy_cert_store=true \
  tidy_revoked_certs=true \
  safety_buffer="72h"
```

### 3.2 Trust Chain Verification

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CERTIFICATE TRUST CHAIN                                   │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  WORKLOAD SVID (Leaf Certificate)                                      │ │
│  │  Subject: spiffe://company.com/ns/prod/sa/api-service                  │ │
│  │  Issuer: CN=SPIRE Server, O=Company Inc                                │ │
│  │  Validity: 1 hour                                                      │ │
│  │  Serial: 4A:3B:2C:1D:EE:FF:00:11:22:33                                 │ │
│  │                                                                         │ │
│  │  Signed by: SPIRE Server                                               │ │
│  └────────────────────────────────────┬───────────────────────────────────┘ │
│                                       │                                     │
│                                       │ Chain of Trust                      │
│                                       ▼                                     │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  SPIRE INTERMEDIATE CA                                                  │ │
│  │  Subject: CN=SPIRE Intermediate CA, O=Company Inc                      │ │
│  │  Issuer: CN=Vault Intermediate CA, O=Company Inc                       │ │
│  │  Validity: 1 year                                                      │ │
│  │  Serial: 7F:8E:9D:0C:1B:2A:39:48:57:66                                 │ │
│  │                                                                         │ │
│  │  Signed by: Vault PKI                                                  │ │
│  └────────────────────────────────────┬───────────────────────────────────┘ │
│                                       │                                     │
│                                       │ Chain of Trust                      │
│                                       ▼                                     │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  VAULT INTERMEDIATE CA                                                  │ │
│  │  Subject: CN=Vault Intermediate CA, O=Company Inc                      │ │
│  │  Issuer: CN=Company Root CA, O=Company Inc                             │ │
│  │  Validity: 5 years                                                     │ │
│  │  Serial: 1A:2B:3C:4D:5E:6F:07:18:29:30                                 │ │
│  │                                                                         │ │
│  │  Signed by: Offline Root CA                                            │ │
│  └────────────────────────────────────┬───────────────────────────────────┘ │
│                                       │                                     │
│                                       │ Root of Trust                       │
│                                       ▼                                     │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  OFFLINE ROOT CA                                                        │ │
│  │  Subject: CN=Company Root CA, O=Company Inc                            │ │
│  │  Issuer: CN=Company Root CA, O=Company Inc (self-signed)               │ │
│  │  Validity: 20 years                                                    │ │
│  │  Serial: 01                                                            │ │
│  │  Storage: FIPS 140-2 Level 3 HSM (air-gapped)                          │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Part 4: HR/IAM Integration with Workload Identity

### 4.1 Employee Termination → Workload Access Revocation

```python
class WorkloadIdentityLifecycleManager:
    """
    Manages workload identity lifecycle based on HR events
    """
    
    def handle_employee_termination(self, employee_id, employee_email):
        """
        Comprehensive termination workflow
        """
        # 1. Revoke user certificates (existing process)
        self.revoke_user_certificates(employee_id)
        
        # 2. Revoke SPIRE registrations for user-specific workloads
        self.revoke_spire_entries_for_user(employee_id)
        
        # 3. Remove from IAM groups affecting workload access
        self.remove_from_iam_groups(employee_id)
        
        # 4. Update Kubernetes RBAC
        self.remove_k8s_role_bindings(employee_email)
        
        # 5. Revoke cloud platform identities
        self.revoke_aws_iam_roles(employee_id)
        self.revoke_gcp_service_accounts(employee_id)
        
        # 6. Update service mesh AuthorizationPolicies
        self.update_istio_policies_remove_principal(employee_email)
        
        # 7. Audit log
        self.audit_log.write({
            'event': 'employee_termination_workload_cleanup',
            'employee_id': employee_id,
            'timestamp': datetime.utcnow()
        })
    
    def revoke_spire_entries_for_user(self, employee_id):
        """
        Remove SPIRE registrations for user-specific workloads
        Example: Developer's personal namespace workloads
        """
        # Query SPIRE server for entries with user ID in selector
        entries = self.spire_api.list_entries(
            selectors=[
                f"k8s:ns:{employee_id}-dev",
                f"k8s:sa:user-{employee_id}"
            ]
        )
        
        for entry in entries:
            # Delete SPIRE registration
            self.spire_api.delete_entry(entry.id)
            
            # This automatically prevents new SVID issuance
            # Existing SVIDs expire within 1 hour (TTL)
    
    def update_istio_policies_remove_principal(self, employee_email):
        """
        Remove terminated employee from all AuthorizationPolicies
        """
        # List all AuthorizationPolicies
        policies = self.k8s_api.list_authorization_policies()
        
        for policy in policies:
            principal = f"cluster.local/ns/*/sa/{employee_email}"
            
            if principal in policy.spec.rules.from.source.principals:
                # Remove principal
                policy.spec.rules.from.source.principals.remove(principal)
                
                # Update policy
                self.k8s_api.update_authorization_policy(policy)
```

### 4.2 Role Change → Workload Permission Update

```python
def handle_role_change(employee_id, old_role, new_role):
    """
    Update workload permissions based on role change
    Example: Developer → SRE
    """
    employee = hr_api.get_employee(employee_id)
    
    # 1. Update Kubernetes RBAC
    # Remove old role binding
    k8s_api.delete_role_binding(
        name=f"{employee_id}-{old_role}",
        namespace=employee['department']
    )
    
    # Create new role binding
    k8s_api.create_role_binding(
        name=f"{employee_id}-{new_role}",
        namespace=employee['department'],
        role_ref={
            'apiGroup': 'rbac.authorization.k8s.io',
            'kind': 'ClusterRole',
            'name': new_role  # e.g., 'sre-engineer'
        },
        subjects=[{
            'kind': 'User',
            'name': employee['email'],
            'apiGroup': 'rbac.authorization.k8s.io'
        }]
    )
    
    # 2. Update SPIRE registrations with new selectors
    # SRE role gets access to production namespace workloads
    if new_role == 'sre-engineer':
        spire_api.create_entry(
            spiffe_id=f"spiffe://company.com/sre/{employee_id}",
            parent_id="spiffe://company.com/spire-server",
            selectors=[
                f"k8s:ns:production",
                f"k8s:sa:{employee['email']}"
            ],
            ttl=3600,  # 1 hour
            admin=False
        )
    
    # 3. Update Istio AuthorizationPolicies
    # Grant SRE access to monitoring dashboards
    create_or_update_authorization_policy(
        name='monitoring-dashboard-access',
        namespace='observability',
        rules=[{
            'from': [{
                'source': {
                    'principals': [
                        f"spiffe://company.com/sre/{employee_id}"
                    ]
                }
            }],
            'to': [{
                'operation': {
                    'methods': ['GET', 'POST'],
                    'paths': ['/grafana/*', '/prometheus/*']
                }
            }]
        }]
    )
    
    # 4. Update cloud IAM roles
    if new_role == 'sre-engineer':
        # AWS: Grant read-only production access
        aws_iam.attach_user_policy(
            UserName=employee['email'],
            PolicyArn='arn:aws:iam::aws:policy/ReadOnlyAccess'
        )
        
        # GCP: Grant Logging Viewer role
        gcp_iam.add_iam_policy_binding(
            resource=f"projects/{project_id}",
            member=f"user:{employee['email']}",
            role='roles/logging.viewer'
        )
```

---

## Part 5: Observability & Monitoring

### 5.1 Workload Identity Monitoring

**Key Metrics to Track:**

```yaml
# Prometheus Metrics
# SVID issuance rate
spire_server_svid_issued_total{spiffe_id=~"spiffe://company.com/.*"}

# SVID rotation failures
spire_agent_svid_rotation_failures_total

# mTLS connection success/failure
envoy_cluster_ssl_connection_error{cluster_name=~".*"}

# Certificate expiry (should never happen with 1h TTL)
certmanager_certificate_expiration_timestamp_seconds{namespace="spire"} - time() < 3600

# Authorization policy denials
istio_requests_total{response_code="403",source_workload=~".*"}

# Workload identity verification failures
spire_server_node_attestation_failures_total
spire_server_workload_attestation_failures_total
```

**Dashboard: Workload Identity Health**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    WORKLOAD IDENTITY DASHBOARD                               │
│                                                                              │
│  ┌──────────────────────────┐  ┌──────────────────────────────────────────┐│
│  │  SVID Issuance Rate      │  │  Active Workload Identities              ││
│  │  📈 2,450/min            │  │  🔑 45,231 total                         ││
│  │  ✅ Healthy              │  │  📊 By namespace:                        ││
│  └──────────────────────────┘  │     - production: 12,450                 ││
│                                │     - staging: 8,920                     ││
│  ┌──────────────────────────┐  │     - development: 23,861                ││
│  │  mTLS Success Rate       │  └──────────────────────────────────────────┘│
│  │  ✅ 99.97%               │                                              │
│  │  🔴 Failures: 45/min     │  ┌──────────────────────────────────────────┐│
│  └──────────────────────────┘  │  Authorization Policy Denials            ││
│                                │  🚫 125 denials (last hour)              ││
│  ┌──────────────────────────┐  │  Top denied workloads:                   ││
│  │  Certificate Expiry      │  │  1. frontend-web → admin-api (95)       ││
│  │  ⚠️  5 certs < 30min     │  │  2. data-pipeline → user-db (18)        ││
│  │  🟢 0 expired            │  │  3. mobile-app → internal-api (12)      ││
│  └──────────────────────────┘  └──────────────────────────────────────────┘│
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  Recent Identity Changes (HR Events)                                 │  │
│  │  - john.doe@company.com terminated → 5 identities revoked (2min ago)│  │
│  │  - jane.smith@company.com role changed → policies updated (15min ago)│ │
│  │  - bob.jones@company.com device lost → device cert revoked (1h ago) │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Audit Logging

**Comprehensive Audit Trail:**

```sql
-- Unified Audit Log Schema
CREATE TABLE workload_identity_audit (
    audit_id UUID PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    
    -- Identity
    spiffe_id VARCHAR(255),
    workload_type VARCHAR(50), -- pod, vm, function
    workload_name VARCHAR(255),
    namespace VARCHAR(100),
    
    -- Operation
    operation VARCHAR(50), -- svid_issued, svid_rotated, authz_granted, authz_denied
    result VARCHAR(20), -- success, failure
    
    -- Context
    source_ip INET,
    destination_service VARCHAR(255),
    http_method VARCHAR(10),
    http_path VARCHAR(500),
    response_code INTEGER,
    
    -- HR/IAM Context (if applicable)
    triggered_by_hr_event BOOLEAN,
    hr_event_id VARCHAR(100),
    employee_id VARCHAR(50),
    
    -- Security
    tls_version VARCHAR(10),
    cipher_suite VARCHAR(100),
    certificate_serial VARCHAR(40),
    
    -- Metadata
    additional_context JSONB
);

-- Indexes
CREATE INDEX idx_spiffe_id ON workload_identity_audit(spiffe_id);
CREATE INDEX idx_timestamp ON workload_identity_audit(timestamp DESC);
CREATE INDEX idx_operation ON workload_identity_audit(operation);
CREATE INDEX idx_authz_denied ON workload_identity_audit(operation) 
    WHERE operation = 'authz_denied';
```

**Sample Audit Entry:**

```json
{
  "audit_id": "661e9500-f39c-51e5-b827-557766551001",
  "timestamp": "2025-12-12T14:22:33.445Z",
  "spiffe_id": "spiffe://company.com/ns/production/sa/payment-service",
  "workload_type": "pod",
  "workload_name": "payment-service-7d5f8c9b-vx4mz",
  "namespace": "production",
  "operation": "authz_denied",
  "result": "failure",
  "source_ip": "10.20.30.40",
  "destination_service": "admin-api.production.svc.cluster.local",
  "http_method": "POST",
  "http_path": "/v1/admin/users/delete",
  "response_code": 403,
  "triggered_by_hr_event": false,
  "tls_version": "TLSv1.3",
  "cipher_suite": "TLS_AES_256_GCM_SHA384",
  "certificate_serial": "5B:4C:3D:2E:1F:00:AA:BB:CC:DD",
  "additional_context": {
    "reason": "insufficient_permissions",
    "required_permission": "admin:users:delete",
    "workload_permissions": ["payment:read", "payment:write"],
    "authorization_policy": "admin-api-authz",
    "envoy_decision": "RBAC: access denied"
  }
}
```

---

## Part 6: Migration Strategy

### 6.1 Phased Rollout

**Phase 1: Infrastructure (Month 1-2)**
```
✅ Deploy SPIRE Server in all regions
✅ Install SPIRE Agents on all K8s nodes
✅ Configure SPIRE → Vault upstream CA
✅ Deploy test workloads with SPIFFE identity
✅ Verify 1-hour SVID rotation works

**Phase 2: Service Mesh Integration (Month 3-4)**
✅ Deploy Istio with SPIRE integration
✅ Enable mTLS in PERMISSIVE mode (accept both mTLS and plaintext)
✅ Migrate 10% of services to use SPIFFE-based mTLS
✅ Deploy Kyverno policies to require SPIRE socket
✅ Test cross-namespace service-to-service calls

**Phase 3: Policy Enforcement (Month 5-6)**
✅ Switch Istio to STRICT mTLS mode
✅ Deploy AuthorizationPolicies for all critical services
✅ Migrate remaining 90% of services
✅ Enable OPA Gatekeeper admission control
✅ Remove all IP-based firewall rules (replace with identity-based)

**Phase 4: HR/IAM Integration (Month 7-8)**
✅ Integrate HR system events → Trust Broker
✅ Automate SPIRE entry revocation on employee termination
✅ Implement role-based SPIRE registration updates
✅ Test full termination workflow (<5 min complete)
✅ Deploy compliance monitoring dashboards

**Phase 5: Cloud Expansion (Month 9-12)**
✅ Extend SPIRE to AWS EC2 instances (IAM attestation)
✅ Extend SPIRE to GCP GCE instances (IAM attestation)
✅ Implement SPIRE federation between regions
✅ Migrate VMs from static credentials to SPIFFE identity
✅ OpAMP Supervisor integration with SPIRE

### 6.2 Backward Compatibility

**Supporting Legacy Systems During Migration:**

```yaml
# Dual-Mode Service: Accepts both legacy and SPIFFE-based auth
apiVersion: v1
kind: Service
metadata:
  name: legacy-api
  namespace: production
  annotations:
    # Allow both mTLS and plaintext during migration
    security.istio.io/tlsMode: PERMISSIVE
spec:
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  - name: https-legacy
    port: 8443
    targetPort: 8443  # Legacy TLS with static certs
  selector:
    app: legacy-api

---
# AuthorizationPolicy: Allow both SPIFFE and legacy cert subjects
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: legacy-api-dual-auth
  namespace: production
spec:
  selector:
    matchLabels:
      app: legacy-api
  action: ALLOW
  rules:
  # Modern: SPIFFE-based identity
  - from:
    - source:
        principals:
        - "spiffe://company.com/ns/*/sa/*"
  # Legacy: x509 certificate subject
  - from:
    - source:
        principals:
        - "CN=old-service.company.com,O=Company Inc"
    when:
    - key: source.certificate
      values: ["*"]  # Has any client certificate
  
  # Deprecation notice after 90 days
  - to:
    - operation:
        paths: ["/health", "/metrics"]
    when:
    - key: request.headers[x-legacy-auth]
      values: ["true"]
```

---

## Part 7: Advanced Scenarios

### 7.1 Multi-Cloud Workload Federation

**Scenario: AWS EKS workload calls GCP GKE workload**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CROSS-CLOUD SERVICE CALL                                  │
│                                                                              │
│  AWS EKS (us-east-1)                        GCP GKE (europe-west1)          │
│  ┌────────────────────────┐                ┌────────────────────────┐      │
│  │  Payment Service Pod   │                │  Fraud Detection Pod   │      │
│  │                        │                │                        │      │
│  │  SPIFFE ID:            │────── mTLS ───►│  SPIFFE ID:            │      │
│  │  spiffe://us-east      │                │  spiffe://eu-west      │      │
│  │    .company.com/       │                │    .company.com/       │      │
│  │    ns/prod/            │                │    ns/prod/            │      │
│  │    sa/payment          │                │    sa/fraud-detect     │      │
│  │                        │                │                        │      │
│  │  Certificate from:     │                │  Certificate from:     │      │
│  │  SPIRE Server (AWS)    │                │  SPIRE Server (GCP)    │      │
│  └────────────────────────┘                └────────────────────────┘      │
│           │                                          │                      │
│           │ Trust Bundle                   Trust Bundle │                  │
│           ▼                                          ▼                      │
│  ┌────────────────────────┐                ┌────────────────────────┐      │
│  │  SPIRE Server (AWS)    │◄─── Bundle ───►│  SPIRE Server (GCP)    │      │
│  │  Trust Domain:         │   Federation   │  Trust Domain:         │      │
│  │  us-east.company.com   │                │  eu-west.company.com   │      │
│  └────────────────────────┘                └────────────────────────┘      │
│           │                                          │                      │
│           └──────────────────┬───────────────────────┘                      │
│                              │                                              │
│                              │ Root Trust                                   │
│                              ▼                                              │
│                  ┌────────────────────────┐                                 │
│                  │  YOUR TRUST BROKER     │                                 │
│                  │  (Vault + EJBCA)       │                                 │
│                  └────────────────────────┘                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

**SPIRE Federation Configuration:**

```hcl
# SPIRE Server (AWS) - Federation Configuration
server {
  federation {
    bundle_endpoint {
      address = "0.0.0.0"
      port = 8443
      
      # ACME for bundle endpoint TLS
      acme {
        domain_name = "spire-us-east.company.com"
        email = "platform-team@company.com"
        tos_accepted = true
      }
    }
    
    federates_with "eu-west.company.com" {
      bundle_endpoint_url = "https://spire-eu-west.company.com:8443"
      bundle_endpoint_profile "https_spiffe" {
        endpoint_spiffe_id = "spiffe://eu-west.company.com/spire-server"
      }
    }
  }
}

# SPIRE Server (GCP) - Federation Configuration
server {
  federation {
    bundle_endpoint {
      address = "0.0.0.0"
      port = 8443
      
      acme {
        domain_name = "spire-eu-west.company.com"
        email = "platform-team@company.com"
        tos_accepted = true
      }
    }
    
    federates_with "us-east.company.com" {
      bundle_endpoint_url = "https://spire-us-east.company.com:8443"
      bundle_endpoint_profile "https_spiffe" {
        endpoint_spiffe_id = "spiffe://us-east.company.com/spire-server"
      }
    }
  }
}
```

**Istio Cross-Cloud Authorization:**

```yaml
# Allow AWS payment service to call GCP fraud detection
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: fraud-detection-cross-cloud
  namespace: production
spec:
  selector:
    matchLabels:
      app: fraud-detection
  action: ALLOW
  rules:
  - from:
    - source:
        principals:
        # Federated identity from AWS
        - "spiffe://us-east.company.com/ns/production/sa/payment-service"
    to:
    - operation:
        methods: ["POST"]
        paths: ["/v1/fraud/check"]
```

### 7.2 Serverless Integration (Lambda, Cloud Functions)

**AWS Lambda with SPIFFE Identity:**

```python
# Lambda function with SPIRE Workload API
import os
import grpc
from spiffe import SpiffeWorkloadAPIClient

def lambda_handler(event, context):
    """
    Lambda function with SPIFFE identity for outbound calls
    """
    # Connect to SPIRE Agent (Lambda Extension)
    spiffe_socket = os.environ.get('SPIFFE_ENDPOINT_SOCKET', 
                                   'unix:///tmp/spire-agent/api.sock')
    
    # Get workload SVID
    with SpiffeWorkloadAPIClient(spiffe_socket) as client:
        svid = client.fetch_x509_svid()
        
        # Use SVID for mTLS to internal service
        response = requests.post(
            'https://internal-api.company.com/v1/process',
            json=event,
            cert=(svid.cert_chain(), svid.private_key()),
            verify=svid.trust_bundle()
        )
        
        return {
            'statusCode': 200,
            'body': response.text
        }
```

**Lambda Layer: SPIRE Agent Extension**

```bash
# Create Lambda layer with SPIRE agent
mkdir -p layer/extensions
cd layer/extensions

# Download SPIRE agent binary
wget https://github.com/spiffe/spire/releases/download/v1.8.0/spire-1.8.0-linux-amd64-musl.tar.gz
tar -xzf spire-1.8.0-linux-amd64-musl.tar.gz
mv spire-1.8.0/bin/spire-agent ./spire-agent-extension

# Extension script
cat > spire-agent-extension << 'SCRIPT'
#!/bin/bash
/opt/extensions/spire-agent-binary run \
  -config /opt/extensions/agent.conf \
  -logLevel INFO
SCRIPT

chmod +x spire-agent-extension

# Create layer
cd ..
zip -r spire-agent-layer.zip extensions/
aws lambda publish-layer-version \
  --layer-name spire-agent \
  --zip-file fileb://spire-agent-layer.zip \
  --compatible-runtimes python3.11 python3.12
```

### 7.3 Database mTLS with SPIFFE Identity

**PostgreSQL with Client Certificate Authentication:**

```yaml
# Kubernetes Deployment with SPIRE for DB access
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-service
spec:
  template:
    spec:
      serviceAccountName: api-service-sa
      
      containers:
      - name: api-service
        image: company/api-service:v1.2.3
        
        env:
        # Database connection with mTLS
        - name: DB_HOST
          value: "postgres.production.svc.cluster.local"
        - name: DB_PORT
          value: "5432"
        - name: DB_NAME
          value: "api_production"
        - name: DB_SSLMODE
          value: "verify-full"
        
        # SPIRE socket for certificate
        - name: SPIFFE_ENDPOINT_SOCKET
          value: "unix:///run/spire/sockets/agent.sock"
        
        volumeMounts:
        - name: spire-agent-socket
          mountPath: /run/spire/sockets
          readOnly: true
      
      volumes:
      - name: spire-agent-socket
        hostPath:
          path: /run/spire/sockets
          type: Directory

---
# SPIRE Entry for database client
# Created via SPIRE Server API or kubectl plugin
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: api-service-db-client
spec:
  spiffeIDTemplate: "spiffe://company.com/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}"
  podSelector:
    matchLabels:
      app: api-service
  workloadSelectorTemplates:
    - "k8s:ns:production"
    - "k8s:sa:api-service-sa"
  dnsNameTemplates:
    - "api-service.production.svc.cluster.local"
```

**PostgreSQL Configuration (pg_hba.conf):**

```conf
# Trust certificates from SPIRE CA
hostssl  all  all  0.0.0.0/0  cert clientcert=verify-full

# Map SPIFFE ID to PostgreSQL role
# Certificate CN: spiffe://company.com/ns/production/sa/api-service-sa
# Maps to PostgreSQL role: api_service_role
```

**PostgreSQL Role Mapping (pg_ident.conf):**

```conf
# MAPNAME    SYSTEM-USERNAME                                         PG-USERNAME
spiffe-map   spiffe://company.com/ns/production/sa/api-service-sa   api_service_role
spiffe-map   spiffe://company.com/ns/production/sa/batch-job-sa     batch_job_role
```

**Application Code (Python example):**

```python
import psycopg2
from spiffe import WorkloadApiClient

def get_db_connection():
    """
    Connect to PostgreSQL using SPIFFE SVID for mTLS
    """
    # Fetch SVID from SPIRE agent
    with WorkloadApiClient() as client:
        svid = client.fetch_x509_svid()
        
        # Write certificate and key to temporary files
        cert_file = '/tmp/svid_cert.pem'
        key_file = '/tmp/svid_key.pem'
        ca_file = '/tmp/trust_bundle.pem'
        
        with open(cert_file, 'w') as f:
            f.write(svid.cert_chain())
        with open(key_file, 'w') as f:
            f.write(svid.private_key())
        with open(ca_file, 'w') as f:
            f.write(svid.trust_bundle())
        
        # Connect with mTLS
        conn = psycopg2.connect(
            host=os.environ['DB_HOST'],
            port=os.environ['DB_PORT'],
            database=os.environ['DB_NAME'],
            sslmode='verify-full',
            sslcert=cert_file,
            sslkey=key_file,
            sslrootcert=ca_file
        )
        
        return conn
```

---

## Part 8: Security Hardening

### 8.1 Defense in Depth

**Layer 1: Platform Attestation**
- Kubernetes: ServiceAccount token verification
- AWS: EC2 instance identity document + IAM role
- GCP: GCE instance identity token + service account
- Prevents unauthorized workloads from obtaining identity

**Layer 2: Workload Attestation**
- Unix UID verification
- Binary path validation
- Container image digest verification
- Ensures only approved code gets identity

**Layer 3: Certificate Pinning (Optional)**
```python
# Pin expected SPIFFE ID in client code
EXPECTED_BACKEND_SPIFFE_ID = "spiffe://company.com/ns/prod/sa/backend-api"

def verify_peer_identity(connection):
    """
    Verify peer's SPIFFE ID matches expected
    """
    peer_cert = connection.getpeercert()
    peer_spiffe_id = extract_spiffe_id_from_cert(peer_cert)
    
    if peer_spiffe_id != EXPECTED_BACKEND_SPIFFE_ID:
        raise SecurityError(f"Unexpected peer identity: {peer_spiffe_id}")
```

**Layer 4: Rate Limiting by Identity**
```yaml
# Envoy rate limit based on source SPIFFE ID
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: rate-limit-by-identity
  namespace: production
spec:
  configPatches:
  - applyTo: HTTP_FILTER
    match:
      listener:
        filterChain:
          filter:
            name: "envoy.filters.network.http_connection_manager"
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.filters.http.ratelimit
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.ratelimit.v3.RateLimit
          domain: production
          rate_limit_service:
            grpc_service:
              envoy_grpc:
                cluster_name: rate_limit_cluster
          
          # Descriptors based on source SPIFFE ID
          descriptors:
          - entries:
            - key: source_spiffe_id
              value: "spiffe://company.com/ns/prod/sa/untrusted-service"
            rate_limit:
              requests_per_unit: 10
              unit: MINUTE
```

**Layer 5: Anomaly Detection**
```python
# Monitor unusual SVID issuance patterns
def detect_anomalies():
    """
    Alert on suspicious SPIRE activity
    """
    # Spike in SVID requests from single workload
    if svid_requests_last_5min(workload_id) > 1000:
        alert("Possible compromised workload", workload_id)
    
    # SVID requests from unexpected namespace
    if svid_request_namespace not in ALLOWED_NAMESPACES:
        alert("SVID request from unauthorized namespace")
    
    # Failed attestation attempts
    if failed_attestations_last_hour(node_id) > 10:
        alert("Possible node compromise", node_id)
```

### 8.2 Incident Response

**Scenario: Compromised Workload**

```python
def handle_compromised_workload(workload_spiffe_id):
    """
    Incident response for compromised workload
    """
    # 1. Immediately delete SPIRE entry
    spire_api.delete_entry_by_spiffe_id(workload_spiffe_id)
    
    # 2. Existing SVIDs expire within 1 hour (TTL)
    # No need to revoke - just wait for expiration
    
    # 3. Block network traffic from workload
    create_network_policy(
        name='block-compromised-workload',
        namespace=extract_namespace(workload_spiffe_id),
        deny_from_pods=[
            {'matchLabels': extract_labels(workload_spiffe_id)}
        ]
    )
    
    # 4. Quarantine pod
    k8s_api.label_pod(
        pod_name=extract_pod_name(workload_spiffe_id),
        labels={'security-quarantine': 'true'}
    )
    
    # 5. Terminate pod (if safe to do so)
    k8s_api.delete_pod(extract_pod_name(workload_spiffe_id))
    
    # 6. Forensics: Capture logs and pod state before deletion
    collect_forensics(workload_spiffe_id)
    
    # 7. Audit log
    audit_log.write({
        'event': 'compromised_workload_response',
        'spiffe_id': workload_spiffe_id,
        'actions': [
            'spire_entry_deleted',
            'network_blocked',
            'pod_quarantined',
            'pod_terminated'
        ],
        'timestamp': datetime.utcnow()
    })
    
    # 8. Alert security team
    send_pagerduty_alert(
        severity='critical',
        title=f'Compromised Workload: {workload_spiffe_id}',
        details='Automated containment actions taken'
    )
```

---

## Part 9: Cost Optimization

### 9.1 Certificate TTL Trade-offs

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TTL vs COST ANALYSIS                                      │
│                                                                              │
│  Certificate TTL   │ Rotation Frequency │ CA Load │ Security │ Cost        │
│  ─────────────────┼────────────────────┼─────────┼──────────┼──────────── │
│  1 hour (SPIRE)    │ Every 30 min       │ High    │ Best     │ Negligible  │
│  24 hours (Istio)  │ Every 12 hours     │ Medium  │ Great    │ Negligible  │
│  7 days (ECS)      │ Every 3.5 days     │ Low     │ Good     │ $50/month   │
│  90 days (OpAMP)   │ Every 60 days      │ Very Low│ Moderate │ Included    │
│  1 year (User)     │ Annual             │ Minimal │ Adequate │ Included    │
└─────────────────────────────────────────────────────────────────────────────┘

Recommendation: 
- Ephemeral workloads: 1-hour TTL (SPIRE) - maximum security, no cost impact
- Service mesh: 24-hour TTL (Istio + cert-manager) - balanced
- Security agents: 90-day TTL (OpAMP) - reduces CA load
- Human users: 1-year TTL (MDM/VPN) - user convenience
```

### 9.2 Infrastructure Costs

**SPIRE Deployment (250K endpoints):**

```
Regional SPIRE Servers:
- 3 regions × 3 servers (HA) = 9 EC2 instances (m5.xlarge)
- Cost: ~$1,500/month

SPIRE Agents:
- DaemonSet on K8s nodes (no extra cost)
- VM agents (minimal CPU/memory overhead)
- Cost: Negligible

Trust Broker (Vault + EJBCA):
- Already deployed for PKI
- SPIRE adds minimal load
- Cost: $0 incremental

AWS Private CA:
- Short-lived mode: $50/month per CA
- 3 CAs (dev/staging/prod): $150/month

GCP Certificate Authority Service:
- DevOps tier: $200/month per pool
- 2 pools (staging/prod): $400/month

Total Infrastructure: ~$2,050/month

Cost per Endpoint: $0.008/month (250K endpoints)

ROI:
- Eliminated static credentials = Reduced breach risk
- Automated cert lifecycle = Saved 2 FTE headcount (~$300K/year)
- Compliance benefits = Avoided potential fines
```

---

## Part 10: Success Metrics

### 10.1 Key Performance Indicators

**Security Metrics:**
- 🎯 **Zero static credentials** in production (Target: 100%)
- 🎯 **mTLS coverage** (Target: 100% of service-to-service)
- 🎯 **Mean Time to Revoke** on termination (Target: <5 minutes)
- 🎯 **Failed authorization rate** (Baseline: establish first month)
- 🎯 **Certificate expiry incidents** (Target: 0 per quarter)

**Operational Metrics:**
- 🎯 **SVID issuance success rate** (Target: >99.9%)
- 🎯 **Certificate rotation failures** (Target: <0.1%)
- 🎯 **SPIRE Server uptime** (Target: 99.95%)
- 🎯 **Mean Time to Identity** for new workload (Target: <30 seconds)

**Compliance Metrics:**
- 🎯 **Audit trail completeness** (Target: 100% of cert operations)
- 🎯 **HR event → Identity revocation SLA** (Target: <5 min)
- 🎯 **Policy enforcement coverage** (Target: 100% of namespaces)
- 🎯 **Zero trust maturity score** (Target: Level 5/5)

### 10.2 Quarterly Review Template

```markdown
# Q1 2026 Workload Identity Program Review

## Achievements
- ✅ Migrated 95% of workloads to SPIFFE identity (Target: 90%)
- ✅ Eliminated 2,345 static credentials
- ✅ Achieved 99.97% mTLS coverage
- ✅ Mean Time to Revoke: 3.2 minutes (Target: <5 min)

## Metrics
- SVID issuance rate: 2,450/min (up from 1,800/min last quarter)
- Active workload identities: 45,231
- Authorization policy denials: 125/hour (down from 450/hour - improved policies)
- Zero certificate expiry incidents

## Challenges
- Lambda integration requires custom extension (workaround deployed)
- Cross-region federation occasionally hits rate limits (optimization in progress)
- 5% legacy systems still on static certs (migration plan Q2)

## Next Quarter Goals
- 100% workload coverage (eliminate remaining 5% legacy)
- Implement database mTLS for all RDS instances
- Deploy SPIRE to on-premises datacenter
- Reduce authorization policy denials by 50%
```

---

## Conclusion

This workload identity framework provides:

**1. Universal Identity**
- SPIFFE/SPIRE as common identity layer across all platforms
- Works seamlessly in Kubernetes, VMs, cloud, on-prem
- No static credentials anywhere in infrastructure

**2. Zero Trust Foundation**
- Every workload verified via attestation
- mTLS enforced for all service-to-service communication
- Identity-based policies replace IP-based rules
- Continuous verification (1-hour certificate TTL)

**3. Enterprise Integration**
- HR system events automatically trigger identity lifecycle
- <5 minute revocation SLA on employee termination
- MDM integration for mobile devices
- Cloud IAM integration (AWS IRSA, GCP Workload Identity)

**4. Operational Excellence**
- Automatic certificate rotation (no manual intervention)
- Comprehensive audit trail linking certs to HR events
- Real-time monitoring and alerting
- Graceful migration path from legacy systems

**5. Crypto-Agility Ready**
- Trust Broker provides root of trust
- Easy algorithm swap capability
- PQC migration path established
- Multiple certificate authorities for resilience

This architecture positions you for the next decade of zero trust computing while maintaining the ultra-short TTL, crypto-agility, and compliance focus that defines your current PKI strategy.

