# Container Security & Service Mesh Integration with Enterprise PKI Architecture

## Executive Summary

This document extends the Enterprise PKI Architecture to address:
- **Container security** on AWS (ECS/EKS) and GCP (GKE)
- **Service mesh sidecar patterns** (Istio, Linkerd) for automatic mTLS
- **Policy enforcement** (OPA Gatekeeper, Kyverno)
- **Cloud-native certificate management** integration
- **Workload identity** patterns eliminating static credentials
- **Runtime security** and threat detection

---

## Part 1: Cloud-Native Container Security

### AWS Container Security Architecture

#### 1.1 AWS ECS Service Connect with Private CA

**ECS Service Connect TLS Integration (Released 2023)**

```
┌─────────────────────────────────────────────────────────────┐
│                    ECS SERVICE CONNECT                        │
│                                                               │
│  ┌──────────┐         Automatic         ┌──────────┐        │
│  │ Service A├────────►  mTLS   ────────►│ Service B│        │
│  │  + Envoy │         (7-day TTL)       │  + Envoy │        │
│  └──────────┘                           └──────────┘        │
│       │                                       │              │
│       │ Certificate Request                   │              │
│       └───────────────────┬───────────────────┘              │
│                           ▼                                  │
│              ┌─────────────────────────┐                     │
│              │  AWS Private CA         │                     │
│              │  (Short-lived mode)     │                     │
│              └─────────────────────────┘                     │
└─────────────────────────────────────────────────────────────┘
```

**Key Features:**
- **Automatic certificate lifecycle**: ECS manages issuance, distribution, rotation
- **Short-lived certificates**: Default 7-day validity, rotates every 5 days
- **Zero code changes**: mTLS transparent to application
- **Cost optimization**: AWS Private CA short-lived mode ($50/month vs $400/month)
- **Secrets management**: Private keys stored in AWS Secrets Manager with KMS encryption
- **No certificate revocation needed**: Short TTL makes CRLs/OCSP unnecessary

**Integration with Your Trust Broker:**

```yaml
# ECS Task Definition with Service Connect TLS
{
  "family": "my-service",
  "networkMode": "awsvpc",
  "serviceConnectConfiguration": {
    "enabled": true,
    "namespace": "my-namespace",
    "services": [{
      "portName": "api",
      "clientAliases": [{"port": 8080}],
      "tls": {
        "roleArn": "arn:aws:iam::account:role/ECSServiceConnectTLS",
        "issuerCertificateAuthority": {
          "awsPcaAuthorityArn": "arn:aws:acm-pca:region:account:certificate-authority/ca-id"
        },
        "kmsKey": "arn:aws:kms:region:account:key/key-id"
      }
    }]
  }
}
```

**Recommendation for Your Architecture:**
- **Hybrid approach**: Use AWS Private CA as a subordinate CA under your Trust Broker
- **Trust Broker as Root**: Your offline root CA issues intermediate to AWS Private CA
- **ECS Service Connect**: Handles ephemeral workload certs (<7 days)
- **OpAMP Supervisor**: Manages longer-lived agent certs (90 days) via your Trust Broker

#### 1.2 AWS EKS Certificate Management

**Three Integration Patterns:**

**Pattern 1: AWS Private CA + cert-manager**
```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: aws-pca-issuer
spec:
  acmePCA:
    arn: arn:aws:acm-pca:region:account:certificate-authority/ca-id
    region: us-east-1
```

**Pattern 2: External Vault Integration**
```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: vault-issuer
spec:
  vault:
    path: pki_int/sign/kubernetes
    server: https://vault.company.com
    auth:
      kubernetes:
        role: cert-manager
        mountPath: /v1/auth/kubernetes
```

**Pattern 3: SPIFFE/SPIRE for Workload Identity**
```
┌────────────────────────────────────────────────────────┐
│                    EKS CLUSTER                          │
│                                                         │
│  ┌─────────────┐      ┌─────────────┐                 │
│  │   Pod A     │◄────►│   Pod B     │                 │
│  │ SPIRE Agent │ mTLS │ SPIRE Agent │                 │
│  └──────┬──────┘      └──────┬──────┘                 │
│         │                     │                         │
│         │   SVID Request      │                         │
│         └──────────┬──────────┘                         │
│                    ▼                                    │
│           ┌─────────────────┐                          │
│           │  SPIRE Server   │                          │
│           │  (1-hour SVIDs) │                          │
│           └────────┬────────┘                          │
│                    │                                    │
│                    │ Trust Bundle                       │
│                    ▼                                    │
│           ┌─────────────────┐                          │
│           │  Your CA        │                          │
│           │  (Trust Broker) │                          │
│           └─────────────────┘                          │
└────────────────────────────────────────────────────────┘
```

**AWS-Specific Security Features:**

1. **IAM Roles for Service Accounts (IRSA)**
   - Eliminates static credentials for AWS API access
   - Pod assumes IAM role via OIDC federation
   - Temporary credentials automatically rotated

2. **AWS Secrets Manager + External Secrets Operator**
   ```yaml
   apiVersion: external-secrets.io/v1beta1
   kind: SecretStore
   metadata:
     name: aws-secretsmanager
   spec:
     provider:
       aws:
         service: SecretsManager
         region: us-east-1
         auth:
           jwt:
             serviceAccountRef:
               name: external-secrets-sa
   ```

3. **Amazon GuardDuty for EKS Runtime Monitoring**
   - Detects malicious activity in containers
   - Runtime threat detection without agents
   - Monitors file access, process execution, network connections

4. **AWS Signer for Container Image Signing**
   - Sign container images before deployment
   - Verify signatures at admission time
   - Integrates with Amazon ECR

---

### GCP Container Security Architecture

#### 2.1 GKE Workload Identity Federation

**The Gold Standard for Eliminating Static Credentials**

```
┌───────────────────────────────────────────────────────────┐
│                    GKE CLUSTER                             │
│                                                            │
│  ┌──────────────────────────────────────┐                │
│  │  Pod with Workload Identity          │                │
│  │  ┌────────────────────────────────┐  │                │
│  │  │ Application Code               │  │                │
│  │  │ (No static credentials!)       │  │                │
│  │  └────────────────────────────────┘  │                │
│  │                 │                     │                │
│  │                 │ GoogleCredentials   │                │
│  │                 │ .getApplicationDefault()            │
│  │                 ▼                     │                │
│  │  ┌────────────────────────────────┐  │                │
│  │  │ K8s ServiceAccount (KSA)       │  │                │
│  │  │ Annotation: iam.gke.io/gcp-sa  │  │                │
│  │  └────────────────────────────────┘  │                │
│  └──────────────────│───────────────────┘                │
│                     │                                     │
│                     │ Token Exchange (1 hour TTL)         │
│                     ▼                                     │
│         ┌────────────────────────────┐                   │
│         │ GCP Service Account (GSA)  │                   │
│         │ With IAM Bindings          │                   │
│         └────────────────────────────┘                   │
└───────────────────────────────────────────────────────────┘
```

**Implementation:**

```bash
# Enable Workload Identity on cluster
gcloud container clusters create my-cluster \
  --workload-pool=PROJECT_ID.svc.id.goog

# Create GCP Service Account
gcloud iam service-accounts create trust-broker-sa

# Create K8s Service Account with annotation
kubectl create serviceaccount trust-broker-ksa
kubectl annotate serviceaccount trust-broker-ksa \
  iam.gke.io/gcp-service-account=trust-broker-sa@PROJECT_ID.iam.gserviceaccount.com

# Bind IAM permissions
gcloud iam service-accounts add-iam-policy-binding \
  trust-broker-sa@PROJECT_ID.iam.gserviceaccount.com \
  --role=roles/iam.workloadIdentityUser \
  --member="serviceAccount:PROJECT_ID.svc.id.goog[NAMESPACE/trust-broker-ksa]"
```

**Benefits:**
- **No static credentials**: No service account keys to manage
- **Short-lived tokens**: 1-hour default, automatic rotation
- **Fine-grained permissions**: Per-workload IAM bindings
- **Audit trail**: All access logged in Cloud Audit Logs
- **Cross-cloud support**: Works with AWS, Azure via Workload Identity Federation

#### 2.2 GKE Certificate Authority Service (CAS) Integration

**GCP's Managed PKI Solution**

```yaml
# cert-manager with GCP CAS
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: gcp-cas-issuer
spec:
  googleCASIssuer:
    project: my-project
    location: us-central1
    caPoolId: my-ca-pool
    auth:
      workloadIdentity:
        serviceAccountRef:
          name: cert-manager-sa
```

**Integration with Your Architecture:**
- **GCP CAS as subordinate CA** under your Trust Broker
- **Automatic tier**: $75/month, up to 3M certs
- **DevOps tier**: $200/month for custom policies
- **Short-lived cert optimization**: Reduces cost vs traditional PKI

#### 2.3 GKE Security Features

**1. GKE Autopilot (Security by Default)**
- Shielded nodes enabled (secure boot, vTPM)
- Workload Identity enforced
- Automatic node upgrades
- Network policies enabled
- Pod Security Standards enforced

**2. Binary Authorization**
- Enforce image signing requirements
- Attestation-based deployment policies
- Integration with Artifact Registry vulnerability scanning

**3. GKE Sandbox (gVisor)**
- Kernel-level isolation for untrusted workloads
- Intercepts syscalls in userspace
- Reduces container escape risk

**4. Network Policies & Private Clusters**
- Control plane not exposed to internet
- Nodes only have private IPs
- Authorized networks for API access

---

## Part 2: Service Mesh Security with Istio

### 3.1 Istio mTLS Architecture

**How Istio Automates mTLS Between Services**

```
┌────────────────────────────────────────────────────────────┐
│                    ISTIO SERVICE MESH                       │
│                                                             │
│  ┌─────────────────┐         mTLS         ┌──────────────┐ │
│  │  Service A Pod  │◄──────────────────►│ Service B Pod│ │
│  │  ┌───────────┐  │                     │ ┌──────────┐ │ │
│  │  │    App    │  │                     │ │   App    │ │ │
│  │  └─────▲─────┘  │                     │ └────▲─────┘ │ │
│  │        │        │                     │      │       │ │
│  │        │ HTTP   │                     │      │ HTTP  │ │
│  │  ┌─────▼─────┐  │                     │ ┌────▼─────┐ │ │
│  │  │   Envoy   │  │   TLS 1.3 + mTLS    │ │  Envoy   │ │ │
│  │  │  Sidecar  │◄─┼────────────────────►│ │ Sidecar  │ │ │
│  │  └─────┬─────┘  │   (24h cert TTL)    │ └────┬─────┘ │ │
│  └────────┼────────┘                     └──────┼───────┘ │
│           │                                      │         │
│           │ Certificate Request (at startup)    │         │
│           └──────────────┬─────────────────────┘         │
│                          ▼                                │
│              ┌────────────────────────┐                   │
│              │  ISTIOD (CA)          │                   │
│              │  - Signs SVID certs    │                   │
│              │  - 24h validity        │                   │
│              │  - 12h rotation        │                   │
│              │  - Secret Discovery    │                   │
│              └───────────┬────────────┘                   │
│                          │                                │
│                          │ Trust Bundle                   │
│                          ▼                                │
│              ┌────────────────────────┐                   │
│              │  Root CA              │                   │
│              │  (Your Trust Broker)  │                   │
│              └────────────────────────┘                   │
└────────────────────────────────────────────────────────────┘
```

**Key Features:**

1. **Automatic Certificate Management**
   - Istiod acts as Certificate Authority
   - Issues SVID (SPIFFE Verifiable Identity Document) certificates
   - Default: 24-hour validity, 12-hour rotation
   - Delivered via Secret Discovery Service (SDS)

2. **Zero Code Changes**
   - Application speaks HTTP to localhost (Envoy sidecar)
   - Envoy handles TLS handshake transparently
   - mTLS enforced without application awareness

3. **Three mTLS Modes**
   - **PERMISSIVE** (default): Accept both plaintext and mTLS
   - **STRICT**: Only accept mTLS traffic
   - **DISABLE**: No mTLS (not recommended)

4. **Identity-Based Policy Enforcement**
   - Authorization policies based on SPIFFE identity
   - Service-to-service access control
   - Request authentication (JWT validation)

### 3.2 Istio Certificate Management Integration

**Option 1: Istio with Built-in CA (Development/Testing)**
```yaml
# Use Istio's self-signed CA
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  meshConfig:
    defaultConfig:
      proxyMetadata:
        ISTIO_META_CERT_TTL: "24h"
```

**Option 2: Istio with cert-manager (Production)**

```yaml
# Install istio-csr (cert-manager integration)
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: istio-ca
  namespace: istio-system
spec:
  vault:
    path: pki_int/sign/istio
    server: https://vault.company.com
    caBundle: <base64-ca-cert>
    auth:
      kubernetes:
        role: istio-cert-manager
        mountPath: /v1/auth/kubernetes
        secretRef:
          name: issuer-vault-token
          key: token

---
# Istio configuration to use cert-manager
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  values:
    pilot:
      env:
        ENABLE_CA_SERVER: false  # Disable built-in CA
        EXTERNAL_CA: ISTIOD_RA_KUBERNETES_API
  components:
    pilot:
      k8s:
        env:
          - name: CERT_SIGNER_DOMAIN
            value: "cert-manager.io"
```

**Option 3: Istio with External CA (Your Trust Broker)**

```yaml
# Plugin custom CA certificates
apiVersion: v1
kind: Secret
metadata:
  name: cacerts
  namespace: istio-system
type: Opaque
data:
  ca-cert.pem: <base64-root-cert>
  ca-key.pem: <base64-root-key>
  cert-chain.pem: <base64-cert-chain>
  root-cert.pem: <base64-root-cert>

---
# Istio will use these certificates
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  components:
    pilot:
      k8s:
        env:
          - name: ROOT_CA_DIR
            value: /etc/cacerts
```

**Recommendation for Your Architecture:**
- **Development**: Istio built-in CA (fast setup)
- **Production**: **cert-manager + Vault issuer** → connects to your Trust Broker
- **Extreme scale**: **SPIFFE/SPIRE** with custom upstream CA integration

### 3.3 Istio Security Policies

**PeerAuthentication (mTLS Mode)**
```yaml
# Mesh-wide STRICT mTLS
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
```

**AuthorizationPolicy (Access Control)**
```yaml
# Only allow productpage to call reviews service
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: reviews-viewer
  namespace: default
spec:
  selector:
    matchLabels:
      app: reviews
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/default/sa/bookinfo-productpage"]
    to:
    - operation:
        methods: ["GET"]
```

### 3.4 Istio vs SPIFFE/SPIRE Comparison

| Feature | Istio | SPIFFE/SPIRE |
|---------|-------|--------------|
| **Primary Use Case** | Service mesh with mTLS | Workload identity framework |
| **Certificate TTL** | 24 hours (configurable) | 1 hour (typical) |
| **Identity Format** | SPIFFE (cluster.local/ns/default/sa/my-app) | SPIFFE (spiffe://trust-domain/path) |
| **Deployment** | K8s-only | K8s, VMs, bare metal, cloud |
| **Control Plane** | Istiod (single binary) | SPIRE Server + Agents |
| **Features** | Traffic routing, observability, security | Identity attestation only |
| **Complexity** | Medium (K8s-native) | High (nested topology) |
| **Recommendation** | **Use for K8s-only** | **Use for hybrid/multi-cloud** |

**When to Use SPIRE Over Istio:**
- Multi-cloud workload identity (AWS, GCP, on-prem)
- Non-containerized workloads (VMs, bare metal)
- Extreme certificate TTL requirements (<1 hour)
- Service mesh agnostic (works with Linkerd, Consul)

---

## Part 3: Policy Enforcement - OPA Gatekeeper vs Kyverno

### 4.1 Why Policy Engines Matter for Security

**Problem Statement:**
- Developers can accidentally deploy privileged containers
- Images from untrusted registries can enter cluster
- Containers running as root create security risks
- Missing resource limits can cause denial-of-service
- Sensitive data in plaintext ConfigMaps

**Solution: Admission Controllers**
- Intercept API requests before objects are persisted
- Validate against security policies
- Mutate objects to enforce standards
- Generate supporting resources automatically

### 4.2 OPA Gatekeeper Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    KUBERNETES API SERVER                    │
│                                                             │
│  Developer deploys Pod ────────────────────────────┐       │
│                                                     │       │
│                                                     ▼       │
│  ┌──────────────────────────────────────────────────────┐ │
│  │  ADMISSION CONTROLLERS                               │ │
│  │  ┌──────────────┐    ┌──────────────┐              │ │
│  │  │  Validating  │    │  Mutating    │              │ │
│  │  │  Webhook     │    │  Webhook     │              │ │
│  │  └──────┬───────┘    └──────┬───────┘              │ │
│  └─────────┼──────────────────┼─────────────────────────┘ │
│            │                  │                           │
│            └────────┬─────────┘                           │
│                     │                                     │
│                     │ Webhook Call                        │
│                     ▼                                     │
│         ┌────────────────────────────┐                   │
│         │  OPA GATEKEEPER CONTROLLER │                   │
│         │  ┌──────────────────────┐  │                   │
│         │  │  Rego Policy Engine  │  │                   │
│         │  └──────────────────────┘  │                   │
│         │  ┌──────────────────────┐  │                   │
│         │  │  Constraint Templates│  │                   │
│         │  └──────────────────────┘  │                   │
│         │  ┌──────────────────────┐  │                   │
│         │  │  Constraints (CRDs)  │  │                   │
│         │  └──────────────────────┘  │                   │
│         └────────────────────────────┘                   │
│                     │                                     │
│                     │ Allow/Deny                          │
│                     ▼                                     │
│              Object Created or Rejected                   │
└────────────────────────────────────────────────────────────┘
```

**Example Policy: Disallow Privileged Containers**

```yaml
# Constraint Template (reusable)
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spspprivilegedcontainer
spec:
  crd:
    spec:
      names:
        kind: K8sPSPPrivilegedContainer
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8spspprivileged
        
        violation[{"msg": msg}] {
          c := input_containers[_]
          c.securityContext.privileged
          msg := sprintf("Privileged container not allowed: %v", [c.name])
        }

---
# Constraint (policy instance)
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPPrivilegedContainer
metadata:
  name: psp-privileged-container
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces:
      - "production"
      - "staging"
```

### 4.3 Kyverno Architecture

```
┌────────────────────────────────────────────────────────────┐
│                    KUBERNETES API SERVER                    │
│                                                             │
│  Developer deploys Pod ────────────────────────────┐       │
│                                                     │       │
│                                                     ▼       │
│  ┌──────────────────────────────────────────────────────┐ │
│  │  ADMISSION CONTROLLERS                               │ │
│  │  ┌──────────────┐    ┌──────────────┐              │ │
│  │  │  Validating  │    │  Mutating    │              │ │
│  │  │  Webhook     │    │  Webhook     │              │ │
│  │  └──────┬───────┘    └──────┬───────┘              │ │
│  └─────────┼──────────────────┼─────────────────────────┘ │
│            │                  │                           │
│            └────────┬─────────┘                           │
│                     │                                     │
│                     │ Webhook Call                        │
│                     ▼                                     │
│         ┌────────────────────────────┐                   │
│         │  KYVERNO CONTROLLER        │                   │
│         │  ┌──────────────────────┐  │                   │
│         │  │  Policy Engine       │  │                   │
│         │  │  (YAML-based)        │  │                   │
│         │  └──────────────────────┘  │                   │
│         │  ┌──────────────────────┐  │                   │
│         │  │  ClusterPolicies     │  │                   │
│         │  │  (CRDs)              │  │                   │
│         │  └──────────────────────┘  │                   │
│         └────────────────────────────┘                   │
│                     │                                     │
│                     │ Allow/Deny/Mutate/Generate          │
│                     ▼                                     │
│              Object Created or Rejected                   │
└────────────────────────────────────────────────────────────┘
```

**Example Policy: Disallow Privileged Containers**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged-containers
spec:
  validationFailureAction: Enforce  # or Audit
  background: true
  rules:
  - name: privileged-containers
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Privileged mode is not allowed"
      pattern:
        spec:
          containers:
          - =(securityContext):
              =(privileged): "false"
```

### 4.4 Comparison: OPA Gatekeeper vs Kyverno

| Feature | OPA Gatekeeper | Kyverno | Winner |
|---------|---------------|---------|---------|
| **Policy Language** | Rego (DSL) | YAML (K8s-native) | **Kyverno** ✓ |
| **Learning Curve** | Steep (new language) | Minimal (YAML) | **Kyverno** ✓ |
| **Maturity** | CNCF Graduated | CNCF Incubating | **OPA** ✓ |
| **Use Beyond K8s** | Yes (microservices, Terraform, APIs) | Kubernetes-only | **OPA** ✓ |
| **Mutation** | Assign (complex) | YAML patches (intuitive) | **Kyverno** ✓ |
| **Generation** | No | Yes (auto-create resources) | **Kyverno** ✓ |
| **Policy Library** | gatekeeper-library | kyverno-policies | Tie |
| **Testing Tools** | conftest, Gator | kyvernoctl test | Tie |
| **Exception Handling** | Custom logic | Built-in PolicyException | **Kyverno** ✓ |
| **Performance** | Optimized for speed | Lightweight | Tie |
| **Community** | Broad (multi-platform) | Kubernetes-focused | Depends |

**Recommendation:**
- **Use Kyverno if**: Team is K8s-native, want YAML policies, need mutation/generation
- **Use OPA if**: Multi-platform policies (Terraform, APIs, CI/CD), complex logic, Rego expertise
- **Use Both**: OPA for complex validation, Kyverno for mutation/generation

### 4.5 Security Policies for Your Architecture

**Certificate Management Policies**

```yaml
# Kyverno: Enforce cert-manager annotations
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-cert-manager
spec:
  rules:
  - name: require-tls-annotation
    match:
      resources:
        kinds:
        - Ingress
    validate:
      message: "Ingress must use cert-manager for TLS"
      pattern:
        metadata:
          annotations:
            cert-manager.io/cluster-issuer: "?*"

---
# Kyverno: Generate NetworkPolicy for mTLS
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: generate-network-policy
spec:
  rules:
  - name: generate-default-deny
    match:
      resources:
        kinds:
        - Namespace
    exclude:
      resources:
        namespaces:
        - kube-system
        - istio-system
    generate:
      kind: NetworkPolicy
      name: default-deny-ingress
      namespace: "{{request.object.metadata.name}}"
      data:
        spec:
          podSelector: {}
          policyTypes:
          - Ingress
```

**OPA Gatekeeper: Enforce Image Signing**

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequireImageSignature
metadata:
  name: require-signed-images
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces:
      - "production"
  parameters:
    trustedIssuers:
      - "AWS Signer"
      - "Sigstore Cosign"
```

---

## Part 4: OpAMP Supervisor + Service Mesh Integration

### 5.1 Architecture: OpAMP Supervisor in Service Mesh

```
┌──────────────────────────────────────────────────────────────┐
│                    KUBERNETES POD                             │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Application Container                                 │  │
│  │  - Logs to stdout                                      │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Istio Envoy Sidecar                                   │  │
│  │  - Handles mTLS for app traffic                        │  │
│  │  - Certificate from Istiod (24h TTL)                   │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  OpAMP Supervisor Sidecar                              │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │  Manages Security Agents:                        │  │  │
│  │  │  - CrowdStrike Falcon                            │  │  │
│  │  │  - Trellix EDR                                   │  │  │
│  │  │  - Sysmon                                        │  │  │
│  │  │  - OSQuery                                       │  │  │
│  │  └──────────────────────────────────────────────────┘  │  │
│  │                                                          │  │
│  │  Certificate Management:                                │  │
│  │  - Requests cert from Trust Broker (90d TTL)           │  │
│  │  - Converts to vendor format (PEM/JKS)                 │  │
│  │  - Hot reload for agent restart                        │  │
│  │  - Dual-path logging:                                  │  │
│  │    * Execution logs → OTEL → SIEM                      │  │
│  │    * Security events → Vendor SaaS                     │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
                              │
                              │ mTLS (90d certs)
                              ▼
                    ┌──────────────────────┐
                    │  Trust Broker        │
                    │  (Vault + EJBCA)     │
                    └──────────────────────┘
```

**Key Design Decisions:**

1. **Separation of Concerns**
   - **Istio Envoy**: Application traffic mTLS (24h certs)
   - **OpAMP Supervisor**: Security agent management (90d certs)
   - Different TTLs for different risk profiles

2. **Certificate Hierarchy**
   ```
   Offline Root CA
   ├── Intermediate: Istio CA (24h leaf certs)
   │   └── Service-to-service mTLS
   └── Intermediate: Agent CA (90d leaf certs)
       └── Security agent mTLS
   ```

3. **Policy Enforcement Integration**
   ```yaml
   # Kyverno: Enforce OpAMP supervisor on security-critical pods
   apiVersion: kyverno.io/v1
   kind: ClusterPolicy
   metadata:
     name: inject-opamp-supervisor
   spec:
     rules:
     - name: require-opamp-sidecar
       match:
         resources:
           kinds:
           - Pod
           selector:
             matchLabels:
               security-tier: "high"
       validate:
         message: "High security pods must have OpAMP supervisor"
         pattern:
           spec:
             containers:
             - name: opamp-supervisor
   ```

---

## Part 5: Integration Recommendations

### 6.1 Reference Architecture: AWS EKS + Istio + Vault

```
┌────────────────────────────────────────────────────────────────┐
│                      AWS CLOUD                                  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  EKS CLUSTER (us-east-1)                                 │  │
│  │                                                           │  │
│  │  ┌─────────────────────────────────────────────────┐    │  │
│  │  │  ISTIO SERVICE MESH                             │    │  │
│  │  │  - mTLS between services (24h certs)            │    │  │
│  │  │  - PeerAuthentication: STRICT                   │    │  │
│  │  │  - Certificate source: cert-manager → Vault     │    │  │
│  │  └─────────────────────────────────────────────────┘    │  │
│  │                                                           │  │
│  │  ┌─────────────────────────────────────────────────┐    │  │
│  │  │  KYVERNO POLICIES                               │    │  │
│  │  │  - Require image signatures                     │    │  │
│  │  │  - Disallow privileged containers               │    │  │
│  │  │  - Enforce resource limits                      │    │  │
│  │  │  - Generate NetworkPolicies                     │    │  │
│  │  └─────────────────────────────────────────────────┘    │  │
│  │                                                           │  │
│  │  ┌─────────────────────────────────────────────────┐    │  │
│  │  │  cert-manager                                    │    │  │
│  │  │  - ClusterIssuer: vault-issuer                  │    │  │
│  │  │  - Manages Istio certificates                   │    │  │
│  │  │  - IRSA for Vault authentication                │    │  │
│  │  └─────────────────────────────────────────────────┘    │  │
│  │                                                           │  │
│  │  ┌─────────────────────────────────────────────────┐    │  │
│  │  │  WORKLOAD PODS                                   │    │  │
│  │  │  - App container                                │    │  │
│  │  │  - Istio Envoy sidecar                          │    │  │
│  │  │  - OpAMP supervisor (security pods only)        │    │  │
│  │  └─────────────────────────────────────────────────┘    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                          │                                      │
│                          │ IRSA (IAM Role for Service Account) │
│                          ▼                                      │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  VAULT (HA Cluster)                                      │  │
│  │  - PKI Secrets Engine                                    │  │
│  │  - Short-lived certs (<90d)                              │  │
│  │  - Role-based policies                                   │  │
│  └─────────────────────┬────────────────────────────────────┘  │
│                        │                                        │
│                        │ Subordinate CA relationship            │
│                        ▼                                        │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  AWS Private CA (Subordinate CA)                         │  │
│  │  - For ECS Service Connect (7d certs)                    │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
                          │
                          │ Trust hierarchy
                          ▼
        ┌────────────────────────────────────────┐
        │  YOUR OFFLINE ROOT CA                  │
        │  (FIPS 140-2 Level 3 HSM)              │
        │  - Issues intermediates to:            │
        │    * Vault                             │
        │    * AWS Private CA                    │
        │    * GCP CAS                           │
        └────────────────────────────────────────┘
```

### 6.2 Reference Architecture: GCP GKE + Istio + CAS

```
┌────────────────────────────────────────────────────────────────┐
│                      GCP CLOUD                                  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  GKE AUTOPILOT CLUSTER (us-central1)                     │  │
│  │  - Workload Identity enabled                             │  │
│  │  - Shielded nodes (secure boot + vTPM)                   │  │
│  │  - Binary Authorization enforced                         │  │
│  │  - Private cluster (no public IPs)                       │  │
│  │                                                           │  │
│  │  ┌─────────────────────────────────────────────────┐    │  │
│  │  │  ISTIO SERVICE MESH                             │    │  │
│  │  │  - mTLS between services (24h certs)            │    │  │
│  │  │  - Certificate source: cert-manager → GCP CAS   │    │  │
│  │  └─────────────────────────────────────────────────┘    │  │
│  │                                                           │  │
│  │  ┌─────────────────────────────────────────────────┐    │  │
│  │  │  OPA GATEKEEPER                                 │    │  │
│  │  │  - CIS Kubernetes Benchmark policies            │    │  │
│  │  │  - Audit mode → Enforce (progressive rollout)   │    │  │
│  │  └─────────────────────────────────────────────────┘    │  │
│  │                                                           │  │
│  │  ┌─────────────────────────────────────────────────┐    │  │
│  │  │  cert-manager                                    │    │  │
│  │  │  - ClusterIssuer: gcp-cas-issuer                │    │  │
│  │  │  - Workload Identity for GCP auth               │    │  │
│  │  └─────────────────────────────────────────────────┘    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                          │                                      │
│                          │ Workload Identity Federation         │
│                          ▼                                      │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  GCP Certificate Authority Service (CAS)                 │  │
│  │  - DevOps tier ($200/month)                              │  │
│  │  - Custom policies for Istio certs                       │  │
│  └─────────────────────┬────────────────────────────────────┘  │
│                        │                                        │
│                        │ Subordinate CA relationship            │
│                        ▼                                        │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  YOUR OFFLINE ROOT CA                                    │  │
│  │  (Issues intermediate to GCP CAS)                        │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

### 6.3 Multi-Cloud Architecture with SPIFFE/SPIRE

**For Your Hybrid Environment (250K endpoints across AWS, GCP, On-Prem)**

```
┌────────────────────────────────────────────────────────────────┐
│                    SPIRE FEDERATION                             │
│                                                                 │
│  ┌─────────────┐       ┌─────────────┐      ┌──────────────┐  │
│  │ AWS EKS     │       │ GCP GKE     │      │ On-Prem K8s  │  │
│  │             │       │             │      │              │  │
│  │ SPIRE Agent │◄─────►│ SPIRE Agent │◄────►│ SPIRE Agent  │  │
│  │ (1h SVIDs)  │       │ (1h SVIDs)  │      │ (1h SVIDs)   │  │
│  └──────┬──────┘       └──────┬──────┘      └──────┬───────┘  │
│         │                     │                     │          │
│         │ Attestation         │                     │          │
│         ▼                     ▼                     ▼          │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  SPIRE SERVER (Nested Topology)                         │  │
│  │  - Trust Domain: company.com                            │  │
│  │  - Node attestation (AWS IAM, GCP IAM, x509)           │  │
│  │  - Workload attestation (K8s SA, Unix UID)            │  │
│  │  - Bundle federation between regions                    │  │
│  └────────────────────────┬────────────────────────────────┘  │
│                           │                                    │
│                           │ Upstream CA                        │
│                           ▼                                    │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  YOUR TRUST BROKER (Vault + EJBCA)                       │ │
│  │  - Issues intermediate to SPIRE Server                   │ │
│  │  - 1-year intermediate cert validity                     │ │
│  └────────────────────┬─────────────────────────────────────┘ │
│                       │                                        │
│                       │ Root of trust                          │
│                       ▼                                        │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  OFFLINE ROOT CA (FIPS 140-2 Level 3 HSM)                │ │
│  └──────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────┘
```

---

## Part 6: Additional Considerations

### 7.1 Runtime Security & Threat Detection

**AWS GuardDuty ECS Runtime Monitoring**
- Detects cryptocurrency mining
- Identifies container escape attempts
- Monitors file access patterns
- Integrates with EventBridge for automated response

**GKE Security Posture Dashboard**
- CIS Kubernetes Benchmark compliance
- Workload vulnerability scanning
- Network policy violations
- Binary Authorization policy status

**Falco (CNCF) - Runtime Threat Detection**
```yaml
# Detect privileged container spawning shell
- rule: Privileged Container Spawned Shell
  desc: Detect shell in privileged container
  condition: >
    spawned_process and
    container and
    container.privileged=true and
    proc.name in (shell_binaries)
  output: >
    Shell spawned in privileged container
    (user=%user.name container=%container.name shell=%proc.name)
  priority: CRITICAL
```

### 7.2 Supply Chain Security

**Image Signing & Verification**

1. **AWS Signer + Amazon ECR**
   ```bash
   # Sign image
   aws signer put-signing-profile --profile-name ecr-signing
   aws signer start-signing-job \
     --source s3://bucket/image-sha \
     --destination s3://bucket/signed \
     --profile-name ecr-signing
   
   # Verify with admission controller
   ```

2. **Cosign + Sigstore (Open Source)**
   ```bash
   # Sign image
   cosign sign --key cosign.key $IMAGE_URI
   
   # Verify in admission
   cosign verify --key cosign.pub $IMAGE_URI
   ```

3. **Policy Enforcement**
   ```yaml
   # Kyverno: Verify image signatures
   apiVersion: kyverno.io/v1
   kind: ClusterPolicy
   metadata:
     name: verify-image-signatures
   spec:
     validationFailureAction: Enforce
     rules:
     - name: check-signature
       match:
         resources:
           kinds:
           - Pod
       verifyImages:
       - imageReferences:
         - "*.amazonaws.com/*"
         attestors:
         - count: 1
           entries:
           - keys:
               publicKeys: |-
                 -----BEGIN PUBLIC KEY-----
                 ...
                 -----END PUBLIC KEY-----
   ```

### 7.3 Network Security & Zero Trust

**AWS: Security Groups + Network Policies**
```yaml
# EKS Network Policy (Calico)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-allow-frontend
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
```

**GKE: VPC-native clusters + Private Service Connect**
- Pods get routable IPs in VPC
- Network policies enforced at VPC level
- Private connectivity to Google APIs
- No internet gateway required

**Service Mesh Network Policies**
```yaml
# Istio AuthorizationPolicy (replaces K8s NetworkPolicy)
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: frontend-to-api
spec:
  selector:
    matchLabels:
      app: api
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/default/sa/frontend"]
    to:
    - operation:
        methods: ["GET", "POST"]
        paths: ["/api/*"]
```

### 7.4 Observability & Audit

**Certificate Monitoring**
```yaml
# Prometheus Alert: Certificate Expiry
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: certificate-alerts
spec:
  groups:
  - name: certificates
    rules:
    - alert: CertificateExpiringSoon
      expr: certmanager_certificate_expiration_timestamp_seconds - time() < 86400 * 7
      annotations:
        summary: Certificate expiring in <7 days
        description: "{{ $labels.name }} expires in {{ $value | humanizeDuration }}"
```

**Policy Violation Dashboard**
```yaml
# Grafana Dashboard for Kyverno/Gatekeeper
- Validation failures by policy
- Mutation count by policy
- Audit scan results
- Compliance score by namespace
```

### 7.5 Disaster Recovery & Certificate Rotation

**Scenario: Root CA Compromise**

1. **Immediate Actions**
   - Revoke compromised root from all trust stores
   - Generate new offline root (air-gapped ceremony)
   - Issue new intermediates to Vault, AWS PCA, GCP CAS

2. **Gradual Rollout**
   - Dual-root trust period (30-90 days)
   - All systems trust both old and new roots
   - New certificates issued from new root
   - Old certificates expire naturally

3. **Automation**
   ```yaml
   # Kyverno: Inject dual CA bundle
   apiVersion: kyverno.io/v1
   kind: ClusterPolicy
   metadata:
     name: inject-dual-ca-bundle
   spec:
     rules:
     - name: add-ca-bundle
       match:
         resources:
           kinds:
           - ConfigMap
           names:
           - ca-bundle
       mutate:
         patchStrategicMerge:
           data:
             ca-bundle.crt: |-
               -----BEGIN CERTIFICATE-----
               (old root)
               -----END CERTIFICATE-----
               -----BEGIN CERTIFICATE-----
               (new root)
               -----END CERTIFICATE-----
   ```

**Scenario: Quantum Computer Attack (Y-Day)**

1. **Pre-Y-Day (Now - 2030)**
   - Deploy hybrid certificates (RSA + ML-DSA)
   - Cryptographic agility framework operational
   - Quarterly "crypto swap" drills

2. **Y-Day Response**
   - Algorithm swap executed in <24 hours
   - Switch from RSA to ML-DSA-only certs
   - All systems already trust ML-DSA root
   - Ultra-short TTLs (1-24h) limit exposure window

3. **Post-Y-Day**
   - Deprecate RSA entirely
   - Monitor for quantum decryption attempts
   - Full PQC environment

---

## Part 7: Implementation Roadmap

### Phase 1: Foundation (Q1 2025)
- ✅ Deploy Vault + EJBCA as Trust Broker
- ✅ Implement cert-manager in K8s clusters
- ✅ Deploy Kyverno/OPA for policy enforcement
- ✅ Enable AWS Private CA for ECS Service Connect
- ✅ Enable GCP CAS for GKE workloads

### Phase 2: Service Mesh (Q2 2025)
- ✅ Deploy Istio in pilot clusters (10% traffic)
- ✅ Integrate Istio with cert-manager → Vault
- ✅ PeerAuthentication: PERMISSIVE mode
- ✅ Migrate 50% of workloads to service mesh
- ✅ Deploy Falco for runtime security

### Phase 3: Workload Identity (Q3 2025)
- ✅ Enable AWS IRSA for all EKS clusters
- ✅ Enable GCP Workload Identity for all GKE clusters
- ✅ Eliminate static credentials (service account keys)
- ✅ PeerAuthentication: STRICT mode
- ✅ AuthorizationPolicies for zero-trust network

### Phase 4: OpAMP + Security Agents (Q4 2025)
- ✅ Deploy OpAMP supervisor to security-critical pods
- ✅ Integrate CrowdStrike, Trellix via OpAMP
- ✅ Dual-path logging (OTEL + vendor SaaS)
- ✅ Certificate lifecycle automation (90d TTL)
- ✅ GuardDuty/GKE Security alerts to SIEM

### Phase 5: Post-Quantum Prep (2026)
- ✅ Test hybrid certificates (RSA + ML-DSA)
- ✅ Deploy ML-DSA to 10% of fleet
- ✅ HSM firmware updates for PQC support
- ✅ Quarterly crypto-agility drills

### Phase 6: Multi-Cloud Federation (2026-2027)
- ✅ Deploy SPIRE for workload identity (if needed)
- ✅ Bundle federation between AWS, GCP, on-prem
- ✅ Cross-cloud service mesh (if required)
- ✅ Unified policy enforcement across clouds

---

## Conclusion

Your existing PKI architecture is exceptionally well-positioned for cloud-native integration. The key enhancements are:

1. **Service Mesh Adoption**: Istio provides automatic mTLS with minimal operational overhead
2. **Workload Identity**: Eliminate static credentials using AWS IRSA and GCP Workload Identity
3. **Policy Enforcement**: Kyverno for K8s-native policies, OPA for complex logic
4. **Cloud-Native Certificate Management**: AWS Private CA for ECS, GCP CAS for GKE
5. **Dual TTL Strategy**: Ultra-short (1-24h) for ephemeral, medium (90d) for agents
6. **OpAMP Integration**: Manages security agents independently from app traffic
7. **Quantum Readiness**: Hybrid certificates and crypto-agility drills

The architecture maintains your core principles (zero-trust, ultra-short TTLs, crypto-agility) while leveraging cloud-native capabilities for scale and automation.

