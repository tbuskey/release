#!/bin/bash

# trustee install
# Installs and configures the Trustee Operator for Confidential Containers
# Can run standalone or as part of sandboxed-containers-operator-pre chain
#
# Usage:
#   ./sandboxed-containers-operator-trustee-install-commands.sh
#
# Environment variables (all optional):
#   INSTALL_TRUSTEE             - Enable/disable trustee installation (default: false)
#   TRUSTEE_USE_CONFIG_CR       - Use new TrusteeConfig CR approach (default: true)
#   TRUSTEE_PROFILE             - Profile type: "Permissive" or "Restrictive" (default: "Permissive")
#   TRUSTEE_USE_CERT_MANAGER    - Use cert-manager for TLS certificates in Restrictive mode (default: true)
#   TRUSTEE_CATALOG_SOURCE_NAME - Catalog source name (default: from osc-config or "redhat-operators")
#   TRUSTEE_NAMESPACE           - Trustee operator namespace (default: "trustee-operator-system")
#   TRUSTEE_CONFIG_NAME         - TrusteeConfig CR name (default: "trusteeconfig-sample")
#   TRUSTEE_URL_USE_HTTP        - Use HTTP instead of HTTPS (default: false)
#   TRUSTEE_URL_USE_NODEPORT    - Use nodePort instead of route (default: false)
#   TRUSTEE_INSECURE_HTTP       - Enable insecure HTTP in KBS (default: false, DEPRECATED: use TRUSTEE_PROFILE=Permissive)
#   TRUSTEE_TESTING             - Use permissive policy (default: false, DEPRECATED: use TRUSTEE_PROFILE=Permissive)
#   TRUSTEE_ORG                 - Certificate organization (default: "Red Hat OpenShift")
#   TRUSTEE_CN                  - Certificate common name (default: "kbs-trustee-operator-system")
#   KBSCONFIG_OUTPUT_FILE       - KbsConfig YAML output file (default: "kbsconfig.yaml")
#   KBS_SERVICE_TYPE            - KBS service type (default: "NodePort")
#   KBS_DEPLOYMENT_TYPE         - KBS deployment type (default: "AllInOneDeployment")
#   KBS_SECRET_RESOURCES        - Comma-separated secret resources (default: "kbsres1,cosign-public-key,security-policy,attestation-token")
#   KBS_ENABLE_TDX              - Enable TDX configuration (default: "false")
#   VCEK_SECRET_NAME            - VCEK certificate secret for disconnected SNP (default: "", disabled)
#   VCEK_MOUNT_PATH             - VCEK certificate mount path (default: "/etc/kbs/snp/ek")
#   SHARED_DIR                  - Directory for outputs (default: current directory)
#
# Examples:
#   # New TrusteeConfig approach (default) - Permissive profile for development
#   INSTALL_TRUSTEE=true TRUSTEE_PROFILE=Permissive ./sandboxed-containers-operator-trustee-install-commands.sh
#
#   # New TrusteeConfig approach - Restrictive profile for production with cert-manager
#   INSTALL_TRUSTEE=true TRUSTEE_PROFILE=Restrictive TRUSTEE_USE_CERT_MANAGER=true ./sandboxed-containers-operator-trustee-install-commands.sh
#
#   # Legacy manual KbsConfig approach (for compatibility)
#   INSTALL_TRUSTEE=true TRUSTEE_USE_CONFIG_CR=false TRUSTEE_TESTING=true ./sandboxed-containers-operator-trustee-install-commands.sh
#
#   # Disconnected environment with VCEK certificates
#   INSTALL_TRUSTEE=true TRUSTEE_PROFILE=Restrictive VCEK_SECRET_NAME=vcek-secret ./sandboxed-containers-operator-trustee-install-commands.sh

set -euo pipefail

# Check if trustee installation is enabled
INSTALL_TRUSTEE="${INSTALL_TRUSTEE:-false}"
if [[ "${INSTALL_TRUSTEE}" != "true" ]]; then
    echo "=== Trustee installation is disabled (INSTALL_TRUSTEE=${INSTALL_TRUSTEE}) ==="
    echo "Set INSTALL_TRUSTEE=true to enable trustee installation"
    echo "Skipping trustee installation..."
    exit 0
fi

echo "=== Trustee installation is enabled (INSTALL_TRUSTEE=${INSTALL_TRUSTEE}) ==="

# Configuration options

# New TrusteeConfig CR approach (default: true)
TRUSTEE_USE_CONFIG_CR="${TRUSTEE_USE_CONFIG_CR:-true}"

# Determine profile type - handle backward compatibility
if [ -n "${TRUSTEE_PROFILE:-}" ]; then
    # Use explicit TRUSTEE_PROFILE if set
    TRUSTEE_PROFILE="${TRUSTEE_PROFILE}"
elif [ "${TRUSTEE_TESTING:-false}" == "true" ]; then
    # Backward compatibility: TRUSTEE_TESTING=true → Permissive
    TRUSTEE_PROFILE="Permissive"
    echo "Note: TRUSTEE_TESTING is deprecated, use TRUSTEE_PROFILE=Permissive instead"
else
    # Default to Permissive for CI/testing, can be changed to Restrictive for production
    TRUSTEE_PROFILE="${TRUSTEE_PROFILE:-Permissive}"
fi

# Validate profile type
if [[ "${TRUSTEE_PROFILE}" != "Permissive" && "${TRUSTEE_PROFILE}" != "Restrictive" ]]; then
    echo "Error: TRUSTEE_PROFILE must be 'Permissive' or 'Restrictive', got: ${TRUSTEE_PROFILE}"
    exit 1
fi

# cert-manager integration for Restrictive mode (default: true if available)
TRUSTEE_USE_CERT_MANAGER="${TRUSTEE_USE_CERT_MANAGER:-true}"

# TrusteeConfig CR name
TRUSTEE_CONFIG_NAME="${TRUSTEE_CONFIG_NAME:-trusteeconfig-sample}"

# Set TRUSTEE_URL_USE_HTTP=true to use HTTP instead of HTTPS for Trustee URL (insecure - for testing only)
TRUSTEE_URL_USE_HTTP="${TRUSTEE_URL_USE_HTTP:-false}"
# Set TRUSTEE_URL_USE_NODEPORT=true to use nodeIP:nodePort instead of route hostname
TRUSTEE_URL_USE_NODEPORT="${TRUSTEE_URL_USE_NODEPORT:-false}"
# Set TRUSTEE_INSECURE_HTTP=true to enable insecure HTTP in KBS config (DEPRECATED: use TRUSTEE_PROFILE)
TRUSTEE_INSECURE_HTTP="${TRUSTEE_INSECURE_HTTP:-false}"
if [ "${TRUSTEE_INSECURE_HTTP}" == "true" ]; then
    echo "Note: TRUSTEE_INSECURE_HTTP is deprecated, consider using TRUSTEE_PROFILE=Permissive instead"
fi
# Set TRUSTEE_TESTING=true to use permissive resource policy for development/testing (DEPRECATED)
TRUSTEE_TESTING="${TRUSTEE_TESTING:-false}"
# Set TRUSTEE_ORG to customize the Organization (O) value in certificates (default: "Red Hat OpenShift")
TRUSTEE_ORG="${TRUSTEE_ORG:-Red Hat OpenShift}"
# Set TRUSTEE_CN to customize the Common Name (CN) value in certificates (default: "kbs-trustee-operator-system")
TRUSTEE_CN="${TRUSTEE_CN:-kbs-trustee-operator-system}"

# Disconnected environment support
VCEK_SECRET_NAME="${VCEK_SECRET_NAME:-}"
VCEK_MOUNT_PATH="${VCEK_MOUNT_PATH:-/etc/kbs/snp/ek}"
# Set TRUSTEE_CATALOG_SOURCE_NAME to specify the catalog source for operator subscription
# If not set, try to read from osc-config ConfigMap, otherwise default to "redhat-operators"
if [ -z "${TRUSTEE_CATALOG_SOURCE_NAME:-}" ]; then
    # Try to get catalog source name from osc-config ConfigMap created by env-cm step
    OSC_CONFIG_CATALOG=$(oc get configmap osc-config -n default '-o=jsonpath={.data.catalogsourcename}' 2>/dev/null || echo "")
    if [ -n "$OSC_CONFIG_CATALOG" ]; then
        TRUSTEE_CATALOG_SOURCE_NAME="$OSC_CONFIG_CATALOG"
        echo "Using catalog source from osc-config: ${TRUSTEE_CATALOG_SOURCE_NAME}"
    else
        TRUSTEE_CATALOG_SOURCE_NAME="redhat-operators"
        echo "Using default catalog source: ${TRUSTEE_CATALOG_SOURCE_NAME}"
    fi
else
    echo "Using TRUSTEE_CATALOG_SOURCE_NAME environment variable: ${TRUSTEE_CATALOG_SOURCE_NAME}"
fi

# KbsConfig configuration variables
TRUSTEE_NAMESPACE="${TRUSTEE_NAMESPACE:-trustee-operator-system}"
KBSCONFIG_OUTPUT_FILE="${KBSCONFIG_OUTPUT_FILE:-kbsconfig.yaml}"
KBS_SERVICE_TYPE="${KBS_SERVICE_TYPE:-NodePort}"
KBS_DEPLOYMENT_TYPE="${KBS_DEPLOYMENT_TYPE:-AllInOneDeployment}"
KBS_SECRET_RESOURCES="${KBS_SECRET_RESOURCES:-kbsres1,cosign-public-key,security-policy,attestation-token}"
KBS_ENABLE_TDX="${KBS_ENABLE_TDX:-false}"

# Function to wait for an operator subscription and CSV to finish installation
# Parameters:
#   $1: subscription_name - Name of the subscription
#   $2: namespace - Namespace where the subscription exists
#   $3: max_attempts - Maximum number of attempts (default: 60)
#   $4: sleep_seconds - Seconds to sleep between attempts (default: 10)
# Returns: 0 if successful, 1 if failed
# Example:
#   wait_for_operator_subscription "trustee-operator" "trustee-operator-system"
#   wait_for_operator_subscription "my-operator" "my-namespace" 120 5
wait_for_operator_subscription() {
    local subscription_name="$1"
    local namespace="$2"
    local max_attempts="${3:-60}"
    local sleep_seconds="${4:-10}"

    if [ -z "$subscription_name" ] || [ -z "$namespace" ]; then
        echo "Error: subscription_name and namespace are required parameters"
        return 1
    fi

    # Wait for subscription to reach AtLatestKnown state
    echo "Waiting for subscription '${subscription_name}' to be ready (state: AtLatestKnown)..."
    local subscription_ready=false

    for i in $(seq 1 "$max_attempts"); do
        local subscription_state=""

        subscription_state=$(oc get subscription "${subscription_name}" -n "${namespace}" '-o=jsonpath={.status.state}' 2>/dev/null )
        if [[ "$subscription_state" == "AtLatestKnown" ]]; then
            subscription_ready=true
            echo "Subscription is ready (state: AtLatestKnown)"
            break
        fi
        echo "Waiting for subscription to be ready... (attempt $i/$max_attempts, current state: ${subscription_state:-unknown})"
        sleep "$sleep_seconds"
    done

    if [ "$subscription_ready" = false ]; then
        echo "Warning: Subscription '${subscription_name}' did not reach AtLatestKnown state after $((max_attempts * sleep_seconds)) seconds"
        echo "Please check the subscription status with: oc get subscription ${subscription_name} -n ${namespace} -o yaml"
        return 1
    fi

    # Get the CSV name from the subscription
    local csv_name=""
    csv_name=$(oc get subscription "${subscription_name}" -n "${namespace}" '-o=jsonpath={.status.installedCSV}' 2>/dev/null )

    if [ -z "$csv_name" ]; then
        echo "Warning: Could not get installedCSV from subscription '${subscription_name}'"
        echo "Please check the subscription status with: oc get subscription ${subscription_name} -n ${namespace} -o yaml"
        return 1
    fi

    # Wait for the operator CSV to be installed
    local installed=false

    for i in $(seq 1 "$max_attempts"); do
        # Check if CSV (ClusterServiceVersion) is in Succeeded phase with InstallSucceeded reason
        local csv_status
        csv_status=$(oc get csv "${csv_name}" -n "${namespace}" '-o=jsonpath={.status.phase}{.status.reason}' 2>/dev/null )
        if [[ "$csv_status" == "SucceededInstallSucceeded" ]]; then
            installed=true
            echo "CSV '${csv_name}' finished!"
            break
        fi
        echo "Waiting for CSV ... (attempt $i/$max_attempts, current status: ${csv_status:-unknown})"
        sleep "$sleep_seconds"
    done

    if [ "$installed" = false ]; then
        echo "Warning: CSV '${csv_name}' did not finish after $((max_attempts * sleep_seconds)) seconds"
        echo "Please check the subscription status with: oc get subscription ${subscription_name} -n ${namespace}"
        echo "And check the CSV status with: oc get csv ${csv_name} -n ${namespace} -o yaml"
        return 1
    fi

    return 0
}

# Function to subscribe to the Trustee Operator
# Parameters:
#   $1: catalog_source - Name of the catalog source (default: TRUSTEE_CATALOG_SOURCE_NAME or "redhat-operators")
#   $2: source_namespace - Namespace of the catalog source (default: "openshift-marketplace")
#   $3: channel - Subscription channel (default: "stable")
# Example:
#   subscribe_to_trustee_operator                                    # Use TRUSTEE_CATALOG_SOURCE_NAME or default
#   subscribe_to_trustee_operator "certified-operators"              # Override catalog source
#   subscribe_to_trustee_operator "my-catalog" "openshift-marketplace" "stable"
subscribe_to_trustee_operator() {
    local catalog_source="${1:-${TRUSTEE_CATALOG_SOURCE_NAME}}"
    local source_namespace="${2:-openshift-marketplace}"
    local channel="${3:-stable}"
    local operator_namespace="trustee-operator-system"

    echo "=== Subscribing to Trustee Operator ==="
    echo "Catalog Source: ${catalog_source}"
    echo "Source Namespace: ${source_namespace}"
    echo "Channel: ${channel}"
    echo "Operator Namespace: ${operator_namespace}"

    # Create the namespace if it doesn't exist
    if ! resource_exists "namespace" "${operator_namespace}"; then
        echo "Creating namespace '${operator_namespace}'..."
        oc create namespace "${operator_namespace}"
    else
        echo "Namespace '${operator_namespace}' already exists"
    fi

    # Create OperatorGroup if it doesn't exist
    if ! resource_exists "operatorgroup" "trustee-operator-group" "${operator_namespace}"; then
        echo "Creating OperatorGroup 'trustee-operator-group'..."
        cat > trustee-operatorgroup.yaml << EOF
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: trustee-operator-system
  namespace: ${operator_namespace}
spec:
  targetNamespaces:
  - ${operator_namespace}
EOF
        oc apply -f trustee-operatorgroup.yaml
        echo "Created OperatorGroup"
    else
        echo "OperatorGroup 'trustee-operator-group' already exists"
    fi

    # Create Subscription if it doesn't exist
    if ! resource_exists "subscription" "trustee-operator" "${operator_namespace}"; then
        echo "Creating Subscription 'trustee-operator'..."
        cat > trustee-subscription.yaml << EOF
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: trustee-operator
  namespace: ${operator_namespace}
spec:
  channel: ${channel}
  name: trustee-operator
  source: ${catalog_source}
  sourceNamespace: ${source_namespace}
  installPlanApproval: Automatic
EOF
        oc apply -f trustee-subscription.yaml
        echo "Creating Subscription"
    else
        echo "Subscription 'trustee-operator' already exists"
    fi

    # Wait for subscription and CSV to finish
    if ! wait_for_operator_subscription "trustee-operator" "${operator_namespace}"; then
        echo "Failed to complete trustee-operator subscription"
        return 1
    fi

    echo ""

    echo "=== Trustee Operator subscription completed ==="
}

# Function to create cert-manager Issuer and Certificates for Restrictive profile
# Parameters:
#   $1: namespace - Namespace for the resources (default: "trustee-operator-system")
#   $2: issuer_name - Name of the Issuer (default: "kbs-issuer")
# Example:
#   create_cert_manager_certificates
#   create_cert_manager_certificates "trustee-operator-system" "my-issuer"
create_cert_manager_certificates() {
    local namespace="${1:-trustee-operator-system}"
    local issuer_name="${2:-kbs-issuer}"

    echo "=== Creating cert-manager Issuer and Certificates ==="

    # Check if cert-manager is available
    if ! oc api-resources | grep -q "cert-manager.io"; then
        echo "Warning: cert-manager API not found. Please install cert-manager Operator for Red Hat OpenShift"
        echo "Falling back to manual certificate generation..."
        return 1
    fi

    echo "Creating self-signed Issuer: ${issuer_name}..."
    cat > cert-manager-issuer.yaml << EOF
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: ${issuer_name}
  namespace: ${namespace}
spec:
  selfSigned: {}
EOF
    oc apply -f cert-manager-issuer.yaml

    echo "Creating HTTPS certificate..."
    cat > cert-manager-https-cert.yaml << EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: kbs-https
  namespace: ${namespace}
spec:
  dnsNames:
    - kbs-service
  secretName: trustee-tls-cert
  issuerRef:
    name: ${issuer_name}
EOF
    oc apply -f cert-manager-https-cert.yaml

    echo "Creating token verification certificate..."
    cat > cert-manager-token-cert.yaml << EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: kbs-token
  namespace: ${namespace}
spec:
  dnsNames:
    - kbs-service
  secretName: trustee-token-cert
  issuerRef:
    name: ${issuer_name}
  privateKey:
    algorithm: ECDSA
    encoding: PKCS8
    size: 256
EOF
    oc apply -f cert-manager-token-cert.yaml

    echo "Waiting for certificates to be ready..."
    local max_attempts=30
    local sleep_seconds=2

    for i in $(seq 1 "$max_attempts"); do
        local https_ready=""
        local token_ready=""
        https_ready=$(oc get certificate kbs-https -n "${namespace}" '-o=jsonpath={.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "")
        token_ready=$(oc get certificate kbs-token -n "${namespace}" '-o=jsonpath={.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "")

        if [[ "$https_ready" == "True" && "$token_ready" == "True" ]]; then
            echo "Certificates are ready!"
            return 0
        fi
        echo "Waiting for certificates to be ready... (attempt $i/$max_attempts)"
        sleep "$sleep_seconds"
    done

    echo "Warning: Certificates did not become ready after $((max_attempts * sleep_seconds)) seconds"
    echo "Please check certificate status with: oc get certificates -n ${namespace}"
    return 1
}

# Function to export cert-manager certificates (for debugging/verification)
# Parameters:
#   $1: namespace - Namespace (default: "trustee-operator-system")
#   $2: output_dir - Directory to export certificates (default: current directory)
# Example:
#   export_cert_manager_certificates
#   export_cert_manager_certificates "trustee-operator-system" "/tmp/certs"
export_cert_manager_certificates() {
    local namespace="${1:-trustee-operator-system}"
    local output_dir="${2:-.}"

    echo "Exporting cert-manager certificates to ${output_dir}..."

    if resource_exists "secret" "trustee-tls-cert" "${namespace}"; then
        oc get secret trustee-tls-cert -n "${namespace}" -o json | jq -r '.data."tls.crt"' | base64 --decode > "${output_dir}/https.crt"
        echo "Exported HTTPS certificate to: ${output_dir}/https.crt"
    fi

    if resource_exists "secret" "trustee-token-cert" "${namespace}"; then
        oc get secret trustee-token-cert -n "${namespace}" -o json | jq -r '.data."tls.crt"' | base64 --decode > "${output_dir}/token.crt"
        echo "Exported token certificate to: ${output_dir}/token.crt"
    fi
}

# Function to create TrusteeConfig CR (NEW APPROACH)
# Parameters:
#   $1: namespace - Namespace (default: "trustee-operator-system")
#   $2: name - TrusteeConfig name (default: "trusteeconfig-sample")
#   $3: profile_type - "Permissive" or "Restrictive" (default: "Permissive")
#   $4: service_type - Service type (default: "ClusterIP")
#   $5: https_secret - HTTPS TLS secret name (optional, for Restrictive profile)
#   $6: token_secret - Token TLS secret name (optional, for Restrictive profile)
# Returns: 0 if successful, 1 if failed
# Example:
#   create_trustee_config_cr
#   create_trustee_config_cr "trustee-operator-system" "trusteeconfig-sample" "Restrictive" "NodePort" "trustee-tls-cert" "trustee-token-cert"
create_trustee_config_cr() {
    local namespace="${1:-trustee-operator-system}"
    local name="${2:-trusteeconfig-sample}"
    local profile_type="${3:-Permissive}"
    local service_type="${4:-ClusterIP}"
    local https_secret="${5:-}"
    local token_secret="${6:-}"

    echo "=== Creating TrusteeConfig CR ==="
    echo "Name: ${name}"
    echo "Namespace: ${namespace}"
    echo "Profile: ${profile_type}"
    echo "Service Type: ${service_type}"

    # Validate profile type
    if [[ "${profile_type}" != "Permissive" && "${profile_type}" != "Restrictive" ]]; then
        echo "Error: profile_type must be 'Permissive' or 'Restrictive'"
        return 1
    fi

    local output_file="trusteeconfig-${profile_type,,}.yaml"

    if [[ "${profile_type}" == "Restrictive" ]]; then
        # Restrictive profile requires TLS certificates
        if [ -z "$https_secret" ] || [ -z "$token_secret" ]; then
            echo "Error: Restrictive profile requires https_secret and token_secret parameters"
            return 1
        fi

        echo "Creating Restrictive TrusteeConfig CR..."
        cat > "${output_file}" << EOF
apiVersion: confidentialcontainers.org/v1alpha1
kind: TrusteeConfig
metadata:
  labels:
    app.kubernetes.io/name: trusteeconfig
    app.kubernetes.io/instance: ${name}
    app.kubernetes.io/part-of: trustee-operator
    app.kubernetes.io/managed-by: kustomize
    app.kubernetes.io/created-by: trustee-operator
  name: ${name}
  namespace: ${namespace}
spec:
  profileType: Restrictive
  kbsServiceType: ${service_type}
  httpsSpec:
    tlsSecretName: ${https_secret}
  attestationTokenVerificationSpec:
    tlsSecretName: ${token_secret}
EOF
    else
        # Permissive profile - no TLS certificates needed
        echo "Creating Permissive TrusteeConfig CR..."
        cat > "${output_file}" << EOF
apiVersion: confidentialcontainers.org/v1alpha1
kind: TrusteeConfig
metadata:
  labels:
    app.kubernetes.io/name: trusteeconfig
    app.kubernetes.io/instance: ${name}
    app.kubernetes.io/part-of: trustee-operator
    app.kubernetes.io/managed-by: kustomize
    app.kubernetes.io/created-by: trustee-operator
  name: ${name}
  namespace: ${namespace}
spec:
  profileType: Permissive
  kbsServiceType: ${service_type}
EOF
    fi

    # Apply the TrusteeConfig CR
    oc apply -f "${output_file}"

    echo "Waiting for TrusteeConfig to be processed..."
    sleep 5

    # Wait for KbsConfig to be created by the operator
    local max_attempts=30
    local sleep_seconds=2

    for i in $(seq 1 "$max_attempts"); do
        local kbsconfig_name=""
        kbsconfig_name=$(oc get trusteeconfig "${name}" -n "${namespace}" '-o=jsonpath={.status.kbsConfigRef.name}' 2>/dev/null || echo "")

        if [ -n "$kbsconfig_name" ]; then
            echo "TrusteeConfig created KbsConfig: ${kbsconfig_name}"
            echo "TrusteeConfig CR created successfully!"
            return 0
        fi
        echo "Waiting for TrusteeConfig to create KbsConfig... (attempt $i/$max_attempts)"
        sleep "$sleep_seconds"
    done

    echo "Warning: TrusteeConfig did not create KbsConfig after $((max_attempts * sleep_seconds)) seconds"
    echo "Please check TrusteeConfig status with: oc get trusteeconfig ${name} -n ${namespace} -o yaml"
    return 1
}

# Function to get KbsConfig name from TrusteeConfig
# Parameters:
#   $1: trusteeconfig_name - TrusteeConfig CR name
#   $2: namespace - Namespace (default: "trustee-operator-system")
# Returns: KbsConfig name via echo
# Example:
#   KBSCONFIG_NAME=$(get_kbsconfig_from_trusteeconfig "trusteeconfig-sample")
get_kbsconfig_from_trusteeconfig() {
    local trusteeconfig_name="$1"
    local namespace="${2:-trustee-operator-system}"

    local kbsconfig_name=""
    kbsconfig_name=$(oc get trusteeconfig "${trusteeconfig_name}" -n "${namespace}" '-o=jsonpath={.status.kbsConfigRef.name}' 2>/dev/null || echo "")

    if [ -z "$kbsconfig_name" ]; then
        echo "Warning: Could not get KbsConfig name from TrusteeConfig ${trusteeconfig_name}" >&2
        return 1
    fi

    echo "$kbsconfig_name"
}

# Function to update TrusteeConfig-generated ConfigMap
# Parameters:
#   $1: configmap_name - ConfigMap name (auto-generated by TrusteeConfig)
#   $2: namespace - Namespace (default: "trustee-operator-system")
#   $3: key - ConfigMap data key to update
#   $4: value - New value for the key
# Example:
#   update_trusteeconfig_configmap "trusteeconfig-sample-rvps-reference-values" "trustee-operator-system" "reference-values.json" "${NEW_JSON}"
update_trusteeconfig_configmap() {
    local configmap_name="$1"
    local namespace="${2:-trustee-operator-system}"
    local key="$3"
    local value="$4"

    if [ -z "$configmap_name" ] || [ -z "$key" ]; then
        echo "Error: configmap_name and key are required"
        return 1
    fi

    echo "Updating ConfigMap ${configmap_name} key ${key}..."

    if ! resource_exists "configmap" "${configmap_name}" "${namespace}"; then
        echo "Error: ConfigMap ${configmap_name} does not exist in namespace ${namespace}"
        return 1
    fi

    # Create a patch file
    local patch_file="cm-patch-${configmap_name}.yaml"
    cat > "${patch_file}" << EOF
data:
  ${key}: |
$(echo "$value" | sed 's/^/    /')
EOF

    oc patch configmap "${configmap_name}" -n "${namespace}" --type merge --patch-file "${patch_file}"
    rm -f "${patch_file}"

    echo "Updated ConfigMap ${configmap_name}"
    return 0
}

# Function to update KbsConfig for disconnected environment (VCEK certificates)
# Parameters:
#   $1: kbsconfig_name - KbsConfig name
#   $2: namespace - Namespace (default: "trustee-operator-system")
#   $3: vcek_secret_name - VCEK secret name
#   $4: mount_path - Mount path (default: "/etc/kbs/snp/ek")
# Example:
#   update_kbsconfig_vcek "trusteeconfig-sample-kbs-config" "trustee-operator-system" "vcek-secret" "/etc/kbs/snp/ek"
update_kbsconfig_vcek() {
    local kbsconfig_name="$1"
    local namespace="${2:-trustee-operator-system}"
    local vcek_secret_name="$3"
    local mount_path="${4:-/etc/kbs/snp/ek}"

    if [ -z "$kbsconfig_name" ] || [ -z "$vcek_secret_name" ]; then
        echo "Error: kbsconfig_name and vcek_secret_name are required"
        return 1
    fi

    echo "Updating KbsConfig ${kbsconfig_name} with VCEK certificate..."

    if ! resource_exists "kbsconfig" "${kbsconfig_name}" "${namespace}"; then
        echo "Error: KbsConfig ${kbsconfig_name} does not exist"
        return 1
    fi

    if ! resource_exists "secret" "${vcek_secret_name}" "${namespace}"; then
        echo "Error: VCEK secret ${vcek_secret_name} does not exist"
        return 1
    fi

    # Create patch to add kbsLocalCertCacheSpec
    cat > kbsconfig-vcek-patch.json << EOF
{
  "spec": {
    "kbsLocalCertCacheSpec": {
      "secrets": [
        {
          "secretName": "${vcek_secret_name}",
          "mountPath": "${mount_path}"
        }
      ]
    }
  }
}
EOF

    oc patch kbsconfig "${kbsconfig_name}" -n "${namespace}" --type merge --patch-file kbsconfig-vcek-patch.json
    rm -f kbsconfig-vcek-patch.json

    echo "Updated KbsConfig with VCEK certificate configuration"
    return 0
}

# Function to create authentication secret for KBS
create_authentication_secret() {
    echo "Creating authentication secret..."
    if resource_exists "secret" "kbs-auth-public-key"; then
        echo "Secret 'kbs-auth-public-key' already exists"
    else
        echo "Generating authentication keys..."
        # Generate private key using ed25519 algorithm
        openssl genpkey -algorithm ed25519 > privateKey

        # Generate public key from private key
        openssl pkey -in privateKey -pubout -out publicKey

        # Create the secret with public key
        oc create secret generic kbs-auth-public-key --from-file=publicKey -n trustee-operator-system

        echo "Created kbs-auth-public-key secret"
    fi
}

# Function to create kbs-config ConfigMap
create_kbs_config_cm() {
    echo "Creating kbs-config ConfigMap..."
    cat > kbs-config-cm.yaml << EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: kbs-config-cm
  namespace: trustee-operator-system
data:
  kbs-config.toml: |
    [http_server]
    sockets = ["0.0.0.0:8080"]
    insecure_http = ${TRUSTEE_INSECURE_HTTP}

    [admin]
    insecure_api = true
    auth_public_key = "/etc/auth-secret/publicKey"

    [attestation_token]
    insecure_key = true
    attestation_token_type = "CoCo"

    [attestation_service]
    type = "coco_as_builtin"
    work_dir = "/opt/confidential-containers/attestation-service"
    policy_engine = "opa"

      [attestation_service.attestation_token_broker]
      type = "Ear"
      policy_dir = "/opt/confidential-containers/attestation-service/policies"

      [attestation_service.attestation_token_config]
      duration_min = 5

      [attestation_service.rvps_config]
      type = "BuiltIn"

        [attestation_service.rvps_config.storage]
        type = "LocalJson"
        file_path = "/opt/confidential-containers/rvps/reference-values/reference-values.json"

    [[plugins]]
    name = "resource"
    type = "LocalFs"
    dir_path = "/opt/confidential-containers/kbs/repository"

    [policy_engine]
    policy_path = "/opt/confidential-containers/opa/policy.rego"
EOF
}

# Function to create RVPS reference values ConfigMap
create_rvps_configmap() {
    echo "Creating RVPS reference values ConfigMap..."
    cat > rvps-configmap.yaml << EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: rvps-reference-values
  namespace: trustee-operator-system
data:
  reference-values.json: |
    [
    ]
EOF
# internal docs suitable for testing with the kbs-client
#   reference-values.json: |
#    [
#      {
#        "name": "svn",
#        "expiration": "2027-01-01T00:00:00Z",
#        "value" : 1
#      },
#      {
#        "name": "major_version",
#        "expiration": "2027-01-01T00:00:00Z",
#        "value" : 1
#      },
#      {
#        "name": "minimum_minor_version",
#        "expiration": "2027-01-01T00:00:00Z",
#        "value" : 4
#      }
#    ]
#}

# Function to create KBS resource secret
# Parameters:
#   $1: secret_name - Name of the secret to create
#   $@: key=value pairs - Secret data as key=value pairs
# Example: create_kbs_resource_secret "kbsres1" "key1=res1val1" "key2=res1val2"
create_kbs_resource_secret() {
    local secret_name="$1"
    shift
    local secret_data=("$@")

    echo "Creating KBS resource secret '${secret_name}'..."
    if resource_exists "secret" "${secret_name}"; then
        echo "Secret '${secret_name}' already exists"
    else
        echo "Creating new secret '${secret_name}'..."

        # Build the oc create secret command with from-literal arguments
        local cmd="oc create secret generic ${secret_name}"
        for item in "${secret_data[@]}"; do
            cmd="${cmd} --from-literal ${item}"
        done
        cmd="${cmd} -n trustee-operator-system"

        eval "${cmd}"
        echo "Created ${secret_name} secret"
    fi
}

# Function to create resource policy ConfigMap
# Parameters:
#   $1: filename - Name of the YAML file to create
#   $2: default_allow - "true" or "false" to set default allow policy
#   $3+: allow_rules - (optional) Array of allow rules to add when default_allow is false
# Example:
#   create_resource_policy_cm "resource-policy.yaml" "false" 'input["submods"]["cpu"]["ear.status"] == "affirming"'
#   create_resource_policy_cm "trustee-resource-policy-dev.yaml" "true"
create_resource_policy_cm() {
    local filename="$1"
    local default_allow="$2"
    shift 2
    local allow_rules=("$@")

    echo "Creating resource policy ConfigMap..."

    if [[ "${default_allow}" == "true" ]]; then
        echo "Using permissive resource policy (default allow = true)..."
        # Permissive policy for development/testing
        # WARNING: This allows all resource requests - use only for testing!
        cat > "${filename}" << 'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: resource-policy
  namespace: trustee-operator-system
data:
  policy.rego:
    package policy
    default allow = true
EOF
    else
        echo "Using restrictive resource policy (default allow = false)..."
        cat > "${filename}" << 'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: resource-policy
  namespace: trustee-operator-system
data:
  policy.rego: |
    package policy
    default allow = false
EOF
        # Add allow rules if provided
        if [ ${#allow_rules[@]} -gt 0 ]; then
            for rule in "${allow_rules[@]}"; do
                cat >> "${filename}" << EOF
    allow {
      ${rule}
    }
EOF
            done
        fi
    fi
}

# Function to create attestation token secret
# Parameters:
#   $1: cn - Common Name (CN) for the certificate subject
#   $2: org - Organization (O) for the certificate subject (default: TRUSTEE_ORG)
# Example:
#   create_attestation_token_secret "my-service-name" "My Organization"
#   create_attestation_token_secret "${TRUSTEE_CN}" "${TRUSTEE_ORG}"  # Uses config variables
create_attestation_token_secret() {
    local cn="$1"
    local org="${2:-${TRUSTEE_ORG}}"

    echo "Creating attestation token secret..."
    if resource_exists "secret" "attestation-token"; then
        echo "Secret 'attestation-token' already exists"
    else
        echo "Generating attestation token key and certificate..."
        # Generate private elliptic curve SSL key
        openssl ecparam -name prime256v1 -genkey -noout -out token.key

        # Generate self-signed SSL/TLS certificate
        openssl req -new -x509 -key token.key -out token.crt -days 365 \
            -subj "/CN=${cn}/O=${org}"

        # Create the secret
        oc create secret generic attestation-token \
            --from-file=token.crt \
            --from-file=token.key \
            -n trustee-operator-system

        echo "Created attestation-token secret"
    fi
}

# Function to create attestation policy ConfigMap
# Based on the comprehensive default_cpu.rego from internal documentation
create_attestation_policy_cm() {
    echo "Creating comprehensive attestation policy ConfigMap..."
    echo "Supports: Sample, SNP, TDX, Azure vTPM SNP, Azure vTPM TDX, SE"
    cat > attestation-policy.yaml << 'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: attestation-policy
  namespace: trustee-operator-system
data:
  default_cpu.rego: |
    package policy

    import rego.v1

    # Restrictive attestation policy - validates attestations strictly
    # This policy is used to generate an EAR Appraisal.
    # Specifically it generates an AR4SI result.

    # For the `executables` trust claim, the value 33 stands for
    # "Runtime memory includes executables, scripts, files, and/or
    #  objects which are not recognized."
    default executables := 33

    # For the `hardware` trust claim, the value 97 stands for
    # "A Verifier does not recognize an Attester's hardware or
    #  firmware, but it should be recognized."
    default hardware := 97

    # For the `configuration` trust claim the value 36 stands for
    # "Elements of the configuration relevant to security are
    #  unavailable to the Verifier."
    default configuration := 36

    ##### Sample

    # For the `executables` trust claim, the value 3 stands for
    # "Only a recognized genuine set of approved executables have
    #  been loaded during the boot process."
    executables := 3 if {
      # The sample attester does not report any launch digest.
      # This is an example of how a real platform might validate executables.
      input.sample.launch_digest in data.reference.launch_digest
    }

    # For the `hardware` trust claim, the value 2 stands for
    # "An Attester has passed its hardware and/or firmware
    #  verifications needed to demonstrate that these are genuine/
    #  supported.
    hardware := 2 if {
      input.sample.svn in data.reference.svn
      input.sample.platform_version.major == data.reference.major_version
      input.sample.platform_version.minor >= data.reference.minimum_minor_version
    }

    # For the 'configuration' trust claim 2 stands for
    # "The configuration is a known and approved config."
    #
    # In this case, check that debug mode isn't turned on.
    # The sample platform is just an example.
    # For the sample platform, the debug claim is always false.
    # The sample platform should only be used for testing.
    configuration := 2 if {
      input.sample.debug == false
    }

    ##### SNP
    executables := 3 if {
      # In the future, we might calculate this measurement here various components
      input.snp.measurement in data.reference.snp_launch_measurement
    }

    hardware := 2 if {
      # Check the reported TCB to validate the ASP FW
      input.snp.reported_tcb_bootloader in data.reference.snp_bootloader
      input.snp.reported_tcb_microcode in data.reference.snp_microcode
      input.snp.reported_tcb_snp in data.reference.snp_snp_svn
      input.snp.reported_tcb_tee in data.reference.snp_tee_svn
    }

    # For the 'configuration' trust claim 2 stands for
    # "The configuration is a known and approved config."
    #
    # For this, we compare all the configuration fields.
    configuration := 2 if {
      input.snp.policy_debug_allowed == false
      input.snp.policy_migrate_ma == false
      input.snp.platform_smt_enabled == data.reference.snp_smt_enabled
      input.snp.platform_tsme_enabled == data.reference.snp_tsme_enabled
      input.snp.policy_abi_major == data.reference.snp_guest_abi_major
      input.snp.policy_abi_minor == data.reference.snp_guest_abi_minor
      input.snp.policy_single_socket == data.reference.snp_single_socket
      input.snp.policy_smt_allowed == data.reference.snp_smt_allowed
    }

    # For the `configuration` trust claim 3 stands for
    # "The configuration includes or exposes no known
    #  vulnerabilities."
    #
    # In this check, we do not specifically check every
    # configuration value, but we make sure that some key
    # configurations (like debug_allowed) are set correctly.
    else := 3 if {
      input.snp.policy_debug_allowed == false
      input.snp.policy_migrate_ma == false
    }

    ##### TDX
    executables := 3 if {
      # Check the kernel, initrd, and cmdline (including dmverity parameters) measurements
      input.tdx.quote.body.rtmr_1 in data.reference.rtmr_1
      input.tdx.quote.body.rtmr_2 in data.reference.rtmr_2
      tdx_uefi_event_tdvfkernel_ok
      tdx_uefi_event_tdvfkernelparams_ok
    }

    # Support for Grub boot used by GKE
    else := 4 if {
      # Check the kernel, initrd, and cmdline (including dmverity parameters) measurements
      input.tdx.quote.body.rtmr_1 in data.reference.rtmr_1
      input.tdx.quote.body.rtmr_2 in data.reference.rtmr_2
    }

    hardware := 2 if {
      # Check the quote is a TDX quote signed by Intel SGX Quoting Enclave
      input.tdx.quote.header.tee_type == "81000000"
      input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"

      # Check TDX Module version and its hash. Also check OVMF code hash.
      input.tdx.quote.body.mr_seam in data.reference.mr_seam
      input.tdx.quote.body.tcb_svn in data.reference.tcb_svn
      input.tdx.quote.body.mr_td in data.reference.mr_td

      # Check TCB status
      input.tdx.tcb_status == "UpToDate"

      # Check collateral expiration status
      input.tdx.collateral_expiration_status == "0"
      # Check against allowed advisory ids
      # allowed_advisory_ids := {"INTEL-SA-00837"}
      # attester_advisory_ids := {id | id := input.attester_advisory_ids[_]}
      # object.subset(allowed_advisory_ids, attester_advisory_ids)

      # Check against disallowed advisory ids
      # disallowed_advisory_ids := {"INTEL-SA-00837"}
      # attester_advisory_ids := {id | id := input.tdx.advisory_ids[_]} # convert array to set
      # intersection := attester_advisory_ids & disallowed_advisory_ids
      # count(intersection) == 0
    }

    configuration := 2 if {
      # Check the TD has the expected attributes (e.g., debug not enabled) and features.
      input.tdx.td_attributes.debug == false
      input.tdx.quote.body.xfam in data.reference.xfam
    }

    tdx_uefi_event_tdvfkernel_ok if {
      event := input.tdx.uefi_event_logs[_]
      event.type_name == "EV_EFI_BOOT_SERVICES_APPLICATION"
      "File(kernel)" in event.details.device_paths

      digest := event.digests[_]
      digest.digest == data.reference.tdvfkernel
    }

    tdx_uefi_event_tdvfkernelparams_ok if {
      event := input.tdx.uefi_event_logs[_]
      event.type_name == "EV_EVENT_TAG"
      event.details.string == "LOADED_IMAGE::LoadOptions"

      digest := event.digests[_]
      digest.digest == data.reference.tdvfkernelparams
    }

    ##### Azure vTPM SNP
    executables := 3 if {
      input.azsnpvtpm.measurement in data.reference.measurement
      input.azsnpvtpm.tpm.pcr11 in data.reference.snp_pcr11
    }

    hardware := 2 if {
      # Check the reported TCB to validate the ASP FW
      input.azsnpvtpm.reported_tcb_bootloader in data.reference.tcb_bootloader
      input.azsnpvtpm.reported_tcb_microcode in data.reference.tcb_microcode
      input.azsnpvtpm.reported_tcb_snp in data.reference.tcb_snp
      input.azsnpvtpm.reported_tcb_tee in data.reference.tcb_tee
    }

    # For the 'configuration' trust claim 2 stands for
    # "The configuration is a known and approved config."
    #
    # For this, we compare all the configuration fields.
    configuration := 2 if {
      input.azsnpvtpm.platform_smt_enabled in data.reference.smt_enabled
      input.azsnpvtpm.platform_tsme_enabled in data.reference.tsme_enabled
      input.azsnpvtpm.policy_abi_major in data.reference.abi_major
      input.azsnpvtpm.policy_abi_minor in data.reference.abi_minor
      input.azsnpvtpm.policy_single_socket in data.reference.single_socket
      input.azsnpvtpm.policy_smt_allowed in data.reference.smt_allowed
    }

    ##### Azure vTPM TDX
    executables := 3 if {
      input.aztdxvtpm.tpm.pcr11 in data.reference.tdx_pcr11
    }

    hardware := 2 if {
      # Check the quote is a TDX quote signed by Intel SGX Quoting Enclave
      input.aztdxvtpm.quote.header.tee_type == "81000000"
      input.aztdxvtpm.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"

      # Check TDX Module version and its hash. Also check OVMF code hash.
      input.aztdxvtpm.quote.body.mr_seam in data.reference.mr_seam
      input.aztdxvtpm.quote.body.tcb_svn in data.reference.tcb_svn
      input.aztdxvtpm.quote.body.mr_td in data.reference.mr_td
    }

    configuration := 2 if {
      input.aztdxvtpm.quote.body.xfam in data.reference.xfam
    }

    ##### SE TODO
EOF
}


# Function to create security policy configuration file
# Parameters:
#   $1: filename - Name of the JSON file to create
#   $2: default_type - Default policy type (e.g., "insecureAcceptAnything", "reject")
#   $3+: transport_configs - Optional transport configurations in format "registry|type|keyPath"
# Example:
#   create_security_policy "security-policy-config.json" "insecureAcceptAnything" \
#       "ghcr.io/confidential-containers/test-container-image-rs|sigstoreSigned|kbs:///default/cosign-public-key/test"
create_security_policy() {
    local filename="$1"
    local default_type="$2"
    shift 2
    local transport_configs=("$@")

    echo "Creating security policy configuration..."
   cat >> "${filename}" << EOF
{
    "default": [
        {
        "type": "${default_type}"
        }
    ],
EOF
    # Check if transport configurations are provided
    if [ ${#transport_configs[@]} -eq 0 ]; then
        # No transports - create empty transports object and end file
        cat >> "${filename}" << EOF
    "transports": {}
}

EOF
    else
        # Start the JSON file with default policy and docker transports
        cat >> "${filename}" << EOF
    "transports": {
        "docker": {
EOF
        # Add transport configurations
        local first=true
        for config in "${transport_configs[@]}"; do
            # Parse config: registry|type|keyPath
            IFS='|' read -r registry type keyPath <<< "${config}"

            # Add comma before next entry (except for first entry)
            if [ "$first" = false ]; then
                echo "," >> "${filename}"
            fi
            first=false

            # Add the transport configuration
            cat >> "${filename}" << EOF
            "${registry}": [
                {
                    "type": "${type}",
                    "keyPath": "${keyPath}"
                }
            ]
EOF
        done

        # Close the JSON structure
        cat >> "${filename}" << 'EOF'

        }
    }
}
EOF
    fi
}

# Function to create initdata.toml configuration file
# Parameters:
#   $1: trustee_url - The Trustee/KBS service URL
#   $2: kbs_cert - The KBS certificate (optional, empty string to skip cert)
#   $3: output_file - Output filename (default: "initdata.toml")
# Returns: 0 if successful, 1 if failed
# Example:
#   create_initdata_config "${TRUSTEE_URL}" "${KBS_CERT}"
#   create_initdata_config "${TRUSTEE_URL}" "" "my-initdata.toml"  # without cert
create_initdata_config() {
    local trustee_url="$1"
    local kbs_cert="$2"
    local output_file="${3:-initdata.toml}"

    if [ -z "$trustee_url" ]; then
        echo "Error: trustee_url is required"
        return 1
    fi

    echo "Creating initdata configuration file: ${output_file}"

    # Create the base configuration with or without cert
    if [ -n "$kbs_cert" ]; then
        # Include certificate in configuration
        cat > "${output_file}" << EOF
algorithm = "sha384"
version = "0.1.0"

[data]
"aa.toml" = '''
[token_configs]
[token_configs.coco_as]

url = '${trustee_url}'

[token_configs.kbs]
url = '${trustee_url}'
cert = """
${kbs_cert}
"""
'''

"cdh.toml" = '''
socket = 'unix:///run/confidential-containers/cdh.sock'
credentials = []

[kbc]
name = 'cc_kbc'
url = '${trustee_url}'
kbs_cert = """
${kbs_cert}
"""
'''
EOF
    else
        # Configuration without certificate
        cat > "${output_file}" << EOF
algorithm = "sha384"
version = "0.1.0"

[data]
"aa.toml" = '''
[token_configs]
[token_configs.coco_as]

url = '${trustee_url}'

[token_configs.kbs]
url = '${trustee_url}'
'''

"cdh.toml" = '''
socket = 'unix:///run/confidential-containers/cdh.sock'
credentials = []

[kbc]
name = 'cc_kbc'
url = '${trustee_url}'
'''
EOF
    fi

    # Add the policy.rego section (common to both cases)
    cat >> "${output_file}" << 'EOF'

"policy.rego" = '''
package agent_policy

default AddARPNeighborsRequest := true
default AddSwapRequest := true
default CloseStdinRequest := true
default CopyFileRequest := true
default CreateContainerRequest := true
default CreateSandboxRequest := true
default DestroySandboxRequest := true
default ExecProcessRequest := false
default GetMetricsRequest := true
default GetOOMEventRequest := true
default GuestDetailsRequest := true
default ListInterfacesRequest := true
default ListRoutesRequest := true
default MemHotplugByProbeRequest := true
default OnlineCPUMemRequest := true
default PauseContainerRequest := true
default PullImageRequest := true
default ReadStreamRequest := false
default RemoveContainerRequest := true
default RemoveStaleVirtiofsShareMountsRequest := true
default ReseedRandomDevRequest := true
default ResumeContainerRequest := true
default SetGuestDateTimeRequest := true
default SetPolicyRequest := true
default SignalProcessRequest := true
default StartContainerRequest := true
default StartTracingRequest := true
default StatsContainerRequest := true
default StopTracingRequest := true
default TtyWinResizeRequest := true
default UpdateContainerRequest := true
default UpdateEphemeralMountsRequest := true
default UpdateInterfaceRequest := true
default UpdateRoutesRequest := true
default WaitProcessRequest := true
default WriteStreamRequest := true
'''
EOF

    echo "Created initdata configuration: ${output_file}"
    return 0
}

# Function to create patch script for peer-pods-cm ConfigMap
# Parameters:
#   $1: initdata_string - The INITDATA string to embed in the script
#   $2: output_file - Output filename (default: "patch_peer_pods_cm.sh")
#   $3: namespace - Target namespace (default: "openshift-sandboxed-containers-operator")
# Returns: 0 if successful, 1 if failed
# Example:
#   create_patch_peer_pods_cm_script "${INITDATA_STRING}"
#   create_patch_peer_pods_cm_script "${INITDATA_STRING}" "my-patch.sh" "my-namespace"
create_patch_peer_pods_cm_script() {
    local initdata_string="$1"
    local output_file="${2:-patch_peer_pods_cm.sh}"
    local namespace="${3:-openshift-sandboxed-containers-operator}"

    if [ -z "$initdata_string" ]; then
        echo "Error: initdata_string is required"
        return 1
    fi

    echo "Creating patch script for peer-pods-cm: ${output_file}"

    cat > "${output_file}" << EOF
#!/bin/bash

# Script to patch peer-pods-cm ConfigMap with INITDATA_STRING
# Generated by trustee_configure.sh

set -euo pipefail

echo "=== Patching peer-pods-cm with INITDATA_STRING ==="

# INITDATA_STRING was generated on the trustee cluster
INITDATA_STRING=${initdata_string}
echo "Loaded INITDATA_STRING (length: \${#INITDATA_STRING})"

# Check if peer-pods-cm ConfigMap exists
if ! oc get configmap peer-pods-cm -n ${namespace} >/dev/null 2>&1; then
    echo "Error: peer-pods-cm ConfigMap not found!"
    echo "Please create the ConfigMap first"
    exit 1
fi

# Patch the ConfigMap
echo "Patching peer-pods-cm ConfigMap with INITDATA..."
oc patch configmap peer-pods-cm -n ${namespace} \\
    --type merge -p "{\\"data\\":{\\"INITDATA\\":\\"\${INITDATA_STRING}\\"}}"

echo "Successfully patched peer-pods-cm ConfigMap with INITDATA"
echo "ConfigMap peer-pods-cm now contains the updated INITDATA configuration"
EOF

    chmod +x "${output_file}"
    echo "Created executable patch script: ${output_file}"
    return 0
}

# Function to create and apply RVPS ConfigMap update with PCR8 hash
# Parameters:
#   $1: initdata_file - Path to initdata.toml file for hash calculation
#   $2: namespace - Namespace for the ConfigMap (default: "trustee-operator-system")
#   $3: output_file - Output YAML filename (default: "rvps-configmap-update.yaml")
#   $4: pcr03_value - PCR03 hash value (optional)
#   $5: pcr09_value - PCR09 hash value (optional)
#   $6: pcr11_value - PCR11 hash value (optional)
#   $7: pcr12_value - PCR12 hash value (optional)
# Returns: 0 if successful, 1 if failed
# Example:
#   create_rvps_configmap_update "initdata.toml"
#   create_rvps_configmap_update "initdata.toml" "trustee-operator-system" "rvps.yaml"
create_rvps_configmap_update() {
    local initdata_file="${1:-initdata.toml}"
    local namespace="${2:-trustee-operator-system}"
    local output_file="${3:-rvps-configmap-update.yaml}"
    local pcr03_value="${4:-3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969}"
    local pcr09_value="${5:-22e306eac888c8393203858a8b4b7b8f36f3d1434fc4dd044e6b20c6fa43c4d9}"
    local pcr11_value="${6:-53e58bd6ebb6103c18fd19093cb1bcd0a9235685ad642a6d0981ce8314f5e81d}"
    local pcr12_value="${7:-0000000000000000000000000000000000000000000000000000000000000000}"

    if [ ! -f "$initdata_file" ]; then
        echo "Error: initdata file '${initdata_file}' not found"
        return 1
    fi

    echo "Calculating PCR8 hash for RVPS reference values..."

    # Step 1: Calculate SHA-256 hash of initdata file
    local hash=""
    hash=$(sha256sum "${initdata_file}" | cut -d' ' -f1)
    echo "${initdata_file} SHA-256 hash: $hash"

    # Step 2: Set initial PCR value (32 bytes of 0s)
    local initial_pcr=0000000000000000000000000000000000000000000000000000000000000000

    # Step 3: Calculate PCR8 hash by combining initial_pcr and hash
    local pcr08_value=""
    pcr08_value=$(echo -n "$initial_pcr$hash" | xxd -r -p | sha256sum | cut -d' ' -f1)
    echo "PCR8_HASH for RVPS: $pcr08_value"

    # Create RVPS ConfigMap update with the calculated PCR8 hash
    echo "Creating RVPS reference values update with PCR8 hash..."
    cat > "${output_file}" << EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: rvps-reference-values
  namespace: ${namespace}
data:
  reference-values.json: |
    [
     {
        "name": "pcr03",
        "expiration": "2025-12-12T00:00:00Z",
        "hash-value": [
          {
                "alg": "sha256",
                "value": "${pcr03_value}"
          }
        ]
     },
     {
        "name": "pcr08",
        "expiration": "2025-12-12T00:00:00Z",
        "hash-value": [
          {
                "alg": "sha256",
                "value": "${pcr08_value}"
          }
        ]
     },
     {
        "name": "pcr09",
        "expiration": "2025-12-12T00:00:00Z",
        "hash-value": [
          {
                "alg": "sha256",
                "value": "${pcr09_value}"
          }
        ]
     },
     {
        "name": "pcr11",
        "expiration": "2025-12-12T00:00:00Z",
        "hash-value": [
          {
                "alg": "sha256",
                "value": "${pcr11_value}"
          }
        ]
     },
     {
        "name": "pcr12",
        "expiration": "2025-12-12T00:00:00Z",
        "hash-value": [
          {
                "alg": "sha256",
                "value": "${pcr12_value}"
          }
        ]
     }
    ]
EOF

    # Apply the updated RVPS ConfigMap
    oc apply -f "${output_file}"
    echo "Updated RVPS reference values with PCR8 hash: $pcr08_value"

    return 0
}

# Function to create KbsConfig custom resource YAML
# Parameters:
#   $1: namespace - Namespace for the KbsConfig (default: "trustee-operator-system")
#   $2: output_file - Output YAML filename (default: "kbsconfig.yaml")
#   $3: service_type - Service type (default: "NodePort", options: NodePort, ClusterIP, LoadBalancer)
#   $4: deployment_type - Deployment type (default: "AllInOneDeployment")
#   $5: secret_resources - Comma-separated list of secret resources (default: "kbsres1,cosign-public-key,security-policy,attestation-token")
#   $6: enable_tdx - Enable TDX config (default: "false")
# Returns: 0 if successful, 1 if failed
# Example:
#   create_kbsconfig_yaml
#   create_kbsconfig_yaml "trustee-operator-system" "kbsconfig.yaml" "ClusterIP"
#   create_kbsconfig_yaml "trustee-operator-system" "kbsconfig.yaml" "NodePort" "AllInOneDeployment" "kbsres1,cosign-public-key"
create_kbsconfig_yaml() {
    local namespace="${1:-trustee-operator-system}"
    local output_file="${2:-kbsconfig.yaml}"
    local service_type="${3:-NodePort}"
    local deployment_type="${4:-AllInOneDeployment}"
    local secret_resources="${5:-kbsres1,cosign-public-key,security-policy,attestation-token}"
    local enable_tdx="${6:-false}"

    echo "Creating KbsConfig custom resource YAML: ${output_file}"

    # Convert comma-separated list to JSON array format
    local secret_resources_json=""
    secret_resources_json="${secret_resources//,/\",\"}"
    secret_resources_json="[\"${secret_resources_json}\"]"

    cat > "${output_file}" << EOF
apiVersion: confidentialcontainers.org/v1alpha1
kind: KbsConfig
metadata:
  labels:
    app.kubernetes.io/name: kbsconfig
    app.kubernetes.io/instance: kbsconfig
    app.kubernetes.io/part-of: trustee-operator
    app.kubernetes.io/managed-by: kustomize
    app.kubernetes.io/created-by: trustee-operator
  name: kbsconfig
  namespace: ${namespace}
spec:
  kbsConfigMapName: kbs-config-cm
  kbsRvpsRefValuesConfigMapName: rvps-reference-values
  kbsAttestationPolicyConfigMapName: attestation-policy # optional
  kbsResourcePolicyConfigMapName: resource-policy
  kbsHttpsKeySecretName: kbs-https-key
  kbsHttpsCertSecretName: kbs-https-certificate
  kbsAuthSecretName: kbs-auth-public-key
  kbsSecretResources: ${secret_resources_json}
  kbsServiceType: ${service_type}
  kbsDeploymentType: ${deployment_type}
EOF

    # Add TDX config if enabled
    if [[ "${enable_tdx}" == "true" ]]; then
        cat >> "${output_file}" << 'EOF'
# Intel TDX configuration
tdxConfigSpec:
  kbsTdxConfigMapName: tdx-config
EOF
    else
        cat >> "${output_file}" << 'EOF'
# Uncomment the following lines if using Intel TDX:
# tdxConfigSpec:
#   kbsTdxConfigMapName: tdx-config
EOF
    fi

    echo "Created KbsConfig YAML: ${output_file}"
    return 0
}

# Function to get the KBS route hostname
# Parameters:
#   $1: max_attempts - Maximum number of attempts to get the route (default: 10)
#   $2: sleep_seconds - Seconds to sleep between attempts (default: 2)
# Returns: Route hostname via echo
# Example:
#   ROUTE_HOST=$(get_route_host)
#   ROUTE_HOST=$(get_route_host 20 3)  # 20 attempts, 3 seconds between attempts
get_route_host() {
    local max_attempts="${1:-10}"
    local sleep_seconds="${2:-2}"
    local route_host=""

    for i in $(seq 1 "$max_attempts"); do
        route_host=$(oc get route kbs-service -n trustee-operator-system '-o=jsonpath={.spec.host}' 2>/dev/null || echo "")
        if [ -n "$route_host" ]; then
            break
        fi
        echo "Waiting for route to be available... (attempt $i/$max_attempts)" >&2
        sleep "$sleep_seconds"
    done

    if [ -z "$route_host" ]; then
        echo "Warning: Could not get route hostname, using default" >&2
        route_host="kbs-service-trustee-operator-system.apps.cluster.local"
    fi

    echo "$route_host"
}

# Function to check if a Kubernetes resource exists
# Parameters:
#   $1: resource_type - Type of resource (secret, configmap, deployment, etc.)
#   $2: resource_name - Name of the resource
#   $3: namespace - Namespace to check (default: trustee-operator-system)
# Returns: 0 if exists, 1 if not exists
# Example:
#   if resource_exists "secret" "kbs-auth-public-key"; then
#       echo "Secret exists"
#   fi
#   if resource_exists "configmap" "my-config" "default"; then
#       echo "ConfigMap exists in default namespace"
#   fi
resource_exists() {
    local resource_type="$1"
    local resource_name="$2"
    local namespace="${3:-trustee-operator-system}"

    if oc get "${resource_type}" "${resource_name}" -n "${namespace}" >/dev/null 2>&1; then
        return 0  # exists
    else
        return 1  # does not exist
    fi
}

# Function to create HTTPS certificate secret for KBS service
# Parameters:
#   $1: route_host - Route hostname for Subject Alternative Name
#   $2: cn - Common Name (CN) for the certificate subject
#   $3: org - Organization (O) for the certificate subject (default: TRUSTEE_ORG)
#   $4: key_file - Filename for the private key (default: tls.key)
#   $5: cert_file - Filename for the certificate (default: tls.crt)
# Example:
#   create_https_certificate_secret "kbs-service.apps.cluster.local" "my-service-name" "My Organization"
#   create_https_certificate_secret "${ROUTE_HOST}" "${TRUSTEE_CN}" "${TRUSTEE_ORG}"  # Uses config variables
#   create_https_certificate_secret "${ROUTE_HOST}" "${TRUSTEE_CN}" "" "my-key.key" "my-cert.crt"  # Uses TRUSTEE_ORG with custom files
create_https_certificate_secret() {
    local route_host="$1"
    local cn="$2"
    local org="${3:-${TRUSTEE_ORG}}"
    local key_file="${4:-tls.key}"
    local cert_file="${5:-tls.crt}"

    echo "Creating HTTPS certificate secret for KBS service..."
    if resource_exists "secret" "kbs-https-certificate"; then
        echo "Secret 'kbs-https-certificate' already exists"
    else
        echo "Generating HTTPS certificate for KBS service..."
        echo "Generating certificate for hostname: $route_host"

        # Generate private SSL/TLS key and certificate for HTTPS
        openssl req -x509 -nodes -days 365 \
            -newkey rsa:2048 \
            -keyout "${key_file}" \
            -out "${cert_file}" \
            -subj "/CN=${cn}/O=${org}" \
            -addext "subjectAltName=DNS:${route_host}"

        # Create the secret with the certificate
        oc create secret generic kbs-https-certificate \
            --from-file="${cert_file}" \
            -n trustee-operator-system

        # Create the secret with the private key
        oc create secret generic kbs-https-key \
            --from-file="${key_file}" \
            -n trustee-operator-system

        echo "Created kbs-https-certificate secret"
    fi
}

# create an ingress & route
# route will be named kbs-service-xxxx
# host:80 will be redirected to kbs-service:8080
create_ingress_to_kbs_service() {
    echo "Creating ingress to KBS service..."
    DOMAIN=$(oc get ingress.config/cluster '-o=jsonpath={.spec.domain}')
    HOST="kbs-service-trustee-operator-system.${DOMAIN}"

    cat > ingress-to-kbs-service.yaml << EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kbs-service
spec:
  rules:
  - host: ${HOST}
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: kbs-service # Must match the Service name
            port:
              number: 8080 # Must match the Service port
EOF
}

echo "=== Configuring Trustee for Confidential Containers ==="
echo "TRUSTEE_URL_USE_HTTP: ${TRUSTEE_URL_USE_HTTP}"
echo "TRUSTEE_URL_USE_NODEPORT: ${TRUSTEE_URL_USE_NODEPORT}"
echo "TRUSTEE_INSECURE_HTTP: ${TRUSTEE_INSECURE_HTTP}"
echo "TRUSTEE_TESTING: ${TRUSTEE_TESTING}"
echo "TRUSTEE_ORG: ${TRUSTEE_ORG}"
echo "TRUSTEE_CN: ${TRUSTEE_CN}"
echo "TRUSTEE_CATALOG_SOURCE_NAME: ${TRUSTEE_CATALOG_SOURCE_NAME}"

# Configure Trustee Operator
echo "=== Installing & Configuring Trustee Operator ==="

# Create trustee-operator-system namespace if it doesn't exist
echo "Ensuring trustee-operator-system namespace exists..."
if resource_exists "namespace" "trustee-operator-system"; then
    echo "Namespace 'trustee-operator-system' already exists"
else
    echo "Creating namespace 'trustee-operator-system'..."
    oc create namespace trustee-operator-system
fi

# Check if trustee operator is subscribed, if not subscribe to it
echo "Checking for trustee operator subscription..."
if resource_exists "subscription" "trustee-operator" "trustee-operator-system"; then
    echo "Trustee operator subscription already exists"
else
    echo "Trustee operator not subscribed, subscribing now..."
    subscribe_to_trustee_operator "${TRUSTEE_CATALOG_SOURCE_NAME}"
fi

# ============================================================================
# MAIN CONFIGURATION PATH: TrusteeConfig CR (New Approach) vs KbsConfig (Legacy)
# ============================================================================

if [[ "${TRUSTEE_USE_CONFIG_CR}" == "true" ]]; then
    echo "=== Using NEW TrusteeConfig CR approach ==="
    echo "Profile: ${TRUSTEE_PROFILE}"
    echo "Service Type: ${KBS_SERVICE_TYPE}"

    # Create edge route for KBS service (required before TrusteeConfig)
    echo "Creating edge route for KBS service..."
    if resource_exists "route" "kbs-service"; then
        echo "Route 'kbs-service' already exists"
    else
        echo "Creating new edge route 'kbs-service'..."
        oc create route edge --service=kbs-service --port=kbs-port -n trustee-operator-system || true
        # Route may not be created until service exists, which is created by TrusteeConfig
    fi

    # Handle Restrictive profile with TLS certificates
    if [[ "${TRUSTEE_PROFILE}" == "Restrictive" ]]; then
        echo "=== Restrictive Profile: Setting up TLS certificates ==="

        # Try to use cert-manager if available
        if [[ "${TRUSTEE_USE_CERT_MANAGER}" == "true" ]]; then
            echo "Attempting to use cert-manager for TLS certificates..."
            if create_cert_manager_certificates "${TRUSTEE_NAMESPACE}"; then
                echo "✓ cert-manager certificates created successfully"
                HTTPS_SECRET="trustee-tls-cert"
                TOKEN_SECRET="trustee-token-cert"
            else
                echo "⚠ cert-manager not available, falling back to manual certificate generation"
                TRUSTEE_USE_CERT_MANAGER=false
            fi
        fi

        # Fallback to manual certificate generation
        if [[ "${TRUSTEE_USE_CERT_MANAGER}" == "false" ]]; then
            echo "Using manual OpenSSL certificate generation..."

            # Get route hostname (may not exist yet)
            ROUTE_HOST=$(get_route_host 5 1 || echo "kbs-service")

            # Create HTTPS certificate secret
            if ! resource_exists "secret" "trustee-tls-cert"; then
                echo "Generating HTTPS TLS certificate..."
                openssl req -x509 -nodes -days 365 \
                    -newkey rsa:2048 \
                    -keyout trustee-tls.key \
                    -out trustee-tls.crt \
                    -subj "/CN=${TRUSTEE_CN}/O=${TRUSTEE_ORG}" \
                    -addext "subjectAltName=DNS:${ROUTE_HOST},DNS:kbs-service"

                oc create secret tls trustee-tls-cert \
                    --cert=trustee-tls.crt \
                    --key=trustee-tls.key \
                    -n trustee-operator-system

                echo "✓ Created trustee-tls-cert secret"
            fi

            # Create token verification certificate secret
            if ! resource_exists "secret" "trustee-token-cert"; then
                echo "Generating token verification certificate..."
                openssl ecparam -name prime256v1 -genkey -noout -out trustee-token.key
                openssl req -new -x509 -key trustee-token.key -out trustee-token.crt -days 365 \
                    -subj "/CN=${TRUSTEE_CN}/O=${TRUSTEE_ORG}"

                oc create secret tls trustee-token-cert \
                    --cert=trustee-token.crt \
                    --key=trustee-token.key \
                    -n trustee-operator-system

                echo "✓ Created trustee-token-cert secret"
            fi

            HTTPS_SECRET="trustee-tls-cert"
            TOKEN_SECRET="trustee-token-cert"
        fi

        # Create TrusteeConfig CR with Restrictive profile
        create_trustee_config_cr "${TRUSTEE_NAMESPACE}" "${TRUSTEE_CONFIG_NAME}" "Restrictive" "${KBS_SERVICE_TYPE}" "${HTTPS_SECRET}" "${TOKEN_SECRET}"
    else
        # Permissive profile - no TLS certificates needed
        echo "=== Permissive Profile: No TLS certificates required ==="
        create_trustee_config_cr "${TRUSTEE_NAMESPACE}" "${TRUSTEE_CONFIG_NAME}" "Permissive" "${KBS_SERVICE_TYPE}"
    fi

    # Get the KbsConfig name created by TrusteeConfig
    echo "Fetching KbsConfig name from TrusteeConfig..."
    KBSCONFIG_NAME=$(get_kbsconfig_from_trusteeconfig "${TRUSTEE_CONFIG_NAME}" "${TRUSTEE_NAMESPACE}" || echo "")

    if [ -z "$KBSCONFIG_NAME" ]; then
        echo "Warning: Could not get KbsConfig name, using default"
        KBSCONFIG_NAME="${TRUSTEE_CONFIG_NAME}-kbs-config"
    else
        echo "KbsConfig name: ${KBSCONFIG_NAME}"
    fi

    # ============================================================================
    # Create MANDATORY security-policy secret (must exist before pods start)
    # ============================================================================
    echo ""
    echo "=== Creating MANDATORY security-policy (image signature verification) ==="
    echo "⚠ WARNING: This is MANDATORY! Without it, ALL pods will fail to start!"
    echo ""

    SECURITY_POLICY_FILE="security-policy-insecureAcceptAnything.json"
    create_security_policy "${SECURITY_POLICY_FILE}" "insecureAcceptAnything"

    if ! resource_exists "secret" "security-policy"; then
        echo "Creating security-policy secret..."
        oc create secret generic security-policy --from-file=osc="${SECURITY_POLICY_FILE}" -n trustee-operator-system
        echo "✓ Created security-policy secret"
    else
        echo "✓ security-policy secret already exists"
    fi

    # Add security-policy to KbsConfig secret resources if not already present
    echo "Ensuring security-policy is in KbsConfig secret resources..."
    oc patch kbsconfig "${KBSCONFIG_NAME}" -n "${TRUSTEE_NAMESPACE}" --type=json \
        -p='[{"op":"add", "path":"/spec/kbsSecretResources/-", "value":"security-policy"}]' 2>/dev/null || true

    # Create cosign public key for image signature verification
    if ! resource_exists "secret" "cosign-public-key"; then
        echo "Creating cosign public key secret..."
        openssl genpkey -algorithm ed25519 > cosign-private.key
        openssl pkey -in cosign-private.key -pubout -out cosign-public.key
        oc create secret generic cosign-public-key --from-file=test=cosign-public.key -n trustee-operator-system
        echo "✓ Created cosign-public-key secret"
    fi

    # Add cosign-public-key to KbsConfig secret resources if not already present
    oc patch kbsconfig "${KBSCONFIG_NAME}" -n "${TRUSTEE_NAMESPACE}" --type=json \
        -p='[{"op":"add", "path":"/spec/kbsSecretResources/-", "value":"cosign-public-key"}]' 2>/dev/null || true

    # Handle disconnected environment (VCEK certificates) if configured
    if [ -n "${VCEK_SECRET_NAME}" ]; then
        echo "=== Configuring disconnected environment (VCEK certificates) ==="
        if resource_exists "secret" "${VCEK_SECRET_NAME}" "${TRUSTEE_NAMESPACE}"; then
            update_kbsconfig_vcek "${KBSCONFIG_NAME}" "${TRUSTEE_NAMESPACE}" "${VCEK_SECRET_NAME}" "${VCEK_MOUNT_PATH}"
            echo "✓ VCEK certificate configuration added to KbsConfig"
        else
            echo "Warning: VCEK_SECRET_NAME=${VCEK_SECRET_NAME} specified but secret does not exist"
            echo "Please create the secret with: oc create secret generic ${VCEK_SECRET_NAME} --from-file ./certs -n ${TRUSTEE_NAMESPACE}"
        fi
    fi

    # Skip to INITDATA generation (TrusteeConfig handles all the configuration)
    echo "=== TrusteeConfig CR approach completed ==="
    echo "The operator has automatically created:"
    echo "  ✓ attestation-policy ConfigMap (${TRUSTEE_CONFIG_NAME}-attestation-policy)"
    echo "  ✓ resource-policy ConfigMap (${TRUSTEE_CONFIG_NAME}-resource-policy)"
    echo "  ✓ rvps-reference-values ConfigMap (${TRUSTEE_CONFIG_NAME}-rvps-reference-values)"
    echo "  ✓ kbs-config ConfigMap (${TRUSTEE_CONFIG_NAME}-kbs-config)"
    echo "  ✓ auth-secret Secret (${TRUSTEE_CONFIG_NAME}-auth-secret)"
    echo "  ✓ kbsres1 Secret (sample resource)"
    echo "  ✓ KbsConfig CR (${KBSCONFIG_NAME})"
    if [[ "${TRUSTEE_PROFILE}" == "Restrictive" ]]; then
        echo "  ✓ TLS certificates (${HTTPS_SECRET}, ${TOKEN_SECRET})"
    fi
    echo ""
    echo "To customize the generated configuration, you can edit the ConfigMaps:"
    echo "  oc edit cm ${TRUSTEE_CONFIG_NAME}-attestation-policy -n ${TRUSTEE_NAMESPACE}"
    echo "  oc edit cm ${TRUSTEE_CONFIG_NAME}-resource-policy -n ${TRUSTEE_NAMESPACE}"
    echo "  oc edit cm ${TRUSTEE_CONFIG_NAME}-rvps-reference-values -n ${TRUSTEE_NAMESPACE}"
    echo ""
    echo "Note: After editing policies, restart the trustee deployment:"
    echo "  oc rollout restart deployment/trustee-deployment -n ${TRUSTEE_NAMESPACE}"
    echo ""

else
    # ============================================================================
    # LEGACY PATH: Manual KbsConfig creation (OLD APPROACH)
    # ============================================================================
    echo "=== Using LEGACY manual KbsConfig approach ==="
    echo "Consider using TRUSTEE_USE_CONFIG_CR=true for simplified configuration"
    echo ""

# Create edge route for KBS service (with TLS termination)
echo "Creating edge route for KBS service..."
if resource_exists "route" "kbs-service"; then
    echo "Route 'kbs-service' already exists"
else
    echo "Creating new edge route 'kbs-service'..."
    oc create route edge --service=kbs-service --port=kbs-port -n trustee-operator-system
fi

# Create authentication secret for KBS
create_authentication_secret

# Create kbs-config ConfigMap
create_kbs_config_cm
oc apply -f kbs-config-cm.yaml

create_rvps_configmap
oc apply -f rvps-configmap.yaml

# Create KBS resource secret (example secret for clients)
create_kbs_resource_secret "kbsres1" "key1=res1val1" "key2=res1val2"

# Create resource policy ConfigMap
if [[ "${TRUSTEE_TESTING}" == "true" ]]; then
    RESOURCE_POLICY_FILE="trustee-resource-policy-dev.yaml"
    create_resource_policy_cm "${RESOURCE_POLICY_FILE}" "true"
else
    RESOURCE_POLICY_FILE="resource-policy.yaml"
    # IMPORTANT: Must use cpu0 (not cpu) to match actual EAR token structure
    create_resource_policy_cm "${RESOURCE_POLICY_FILE}" "false" 'input["submods"]["cpu0"]["ear.status"] == "affirming"'
fi

echo "Applying resource policy ConfigMap ${RESOURCE_POLICY_FILE}..."
oc apply -f "${RESOURCE_POLICY_FILE}"

# Create attestation token secret
create_attestation_token_secret "${TRUSTEE_CN}" "${TRUSTEE_ORG}"

# Create attestation policy ConfigMap
create_attestation_policy_cm
oc apply -f attestation-policy.yaml

# ============================================================================
# MANDATORY: Create security policy configuration for image signature verification
# ============================================================================
# WARNING: This configuration is MANDATORY!
# Image signature verification is ALWAYS ENABLED in OSC.
# Without a security-policy secret, ALL pods will fail to start, even unsigned ones.
# This default policy uses 'insecureAcceptAnything' to accept all images.
# For production, configure proper image signature verification.
# ============================================================================
echo "=== Creating MANDATORY security-policy (image signature verification) ==="
SECURITY_POLICY_FILE="security-policy-config.json"

# Add transport configurations as needed - format: "registry|type|keyPath"
create_security_policy "${SECURITY_POLICY_FILE}" "insecureAcceptAnything" \
    "ghcr.io/confidential-containers/test-container-image-rs|sigstoreSigned|kbs:///default/cosign-public-key/test"

if resource_exists "secret" "security-policy"; then
    echo "Secret 'security-policy' already exists"
else
    echo "Creating new secret 'security-policy'..."
    oc create secret generic security-policy --from-file=osc="${SECURITY_POLICY_FILE}" -n trustee-operator-system
    echo "Created security-policy secret"
fi

echo "✓ security-policy created (MANDATORY for pod startup)"
echo "  See: image-signature-verification.md for more details"

# Create cosign public key secret for container image signature verification
# oc create secret generic cosign-public-key --from-file=test=$L/trustee-cosign-publickey.pem -n $TS
echo "Creating cosign public key secret..."
if resource_exists "secret" "cosign-public-key"; then
    echo "Secret 'cosign-public-key' already exists"
else
    echo "Generating cosign public key for container image signature verification..."
    # Generate a cosign key pair for demonstration
    # In production, you would use your actual cosign public key
    openssl genpkey -algorithm ed25519 > cosign-private.key
    openssl pkey -in cosign-private.key -pubout -out cosign-public.key

    # Create the secret
    oc create secret generic cosign-public-key \
        --from-file=test=cosign-public.key -n trustee-operator-system

    echo "Created cosign-public-key secret"
fi

# Create HTTPS certificate secret for KBS service
ROUTE_HOST=$(get_route_host 10 2)
create_https_certificate_secret "${ROUTE_HOST}" "${TRUSTEE_CN}" "${TRUSTEE_ORG}"

# The service kbs-service does not appear until after KbsConfig is created
# Create KbsConfig custom resource YAML
create_kbsconfig_yaml "${TRUSTEE_NAMESPACE}" "${KBSCONFIG_OUTPUT_FILE}" "${KBS_SERVICE_TYPE}" "${KBS_DEPLOYMENT_TYPE}" "${KBS_SECRET_RESOURCES}" "${KBS_ENABLE_TDX}"

# Apply KbsConfig custom resource
if resource_exists "kbsconfig" "kbsconfig"; then
    echo "KbsConfig 'kbsconfig' already exists, updating..."
else
    echo "Creating new KbsConfig 'kbsconfig'..."
fi
oc apply -f kbsconfig.yaml


# Create optional TDX config map for Intel Trust Domain Extensions
echo "Creating optional TDX config map..."
cat > tdx-config.yaml << 'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: tdx-config
  namespace: trustee-operator-system
data:
  sgx_default_qcnl.conf: |
    # PCCS server address
    PCCS_URL=https://api.trustedservices.intel.com/sgx/certification/v4/
    # To accept insecure HTTPS certificate, set this option to FALSE
    USE_SECURE_CERT=TRUE
EOF

oc apply -f tdx-config.yaml

    echo "=== Legacy KbsConfig approach completed ==="
    echo ""

fi  # End of TRUSTEE_USE_CONFIG_CR conditional

# ============================================================================
# COMMON CONFIGURATION: INITDATA Generation (for both approaches)
# ============================================================================

# Determine TRUSTEE_HOST based on configuration
if [[ "${TRUSTEE_URL_USE_NODEPORT}" == "true" ]]; then
    echo "Using nodeIP:nodePort for Trustee access..."

    # Get worker node IP
    NODE_IP=$(oc get node -o wide | awk '/worker/{print $6}' | tail -1)
    if [ -z "$NODE_IP" ]; then
        echo "Warning: Could not find worker node IP, trying any node..."
        NODE_IP=$(oc get node -o wide | awk 'NR>1{print $6}' | head -1)
    fi

    # Get NodePort from kbs-service
    NODE_PORT=""
    for i in {1..30}; do
        NODE_PORT=$(oc -n trustee-operator-system get service kbs-service '-o=jsonpath={.spec.ports[0].nodePort}' 2>/dev/null || echo "")
        if [ -n "$NODE_PORT" ]; then
            break
        fi
        echo "Waiting for kbs-service NodePort... (attempt $i/30)"
        sleep 10
    done

    if [ -z "$NODE_PORT" ]; then
        echo "Warning: Could not get NodePort from kbs-service"
        NODE_PORT="30000"  # fallback port
    fi

    if [ -z "$NODE_IP" ]; then
        echo "Warning: Could not get node IP"
        NODE_IP="worker-node-ip"  # fallback
    fi

    TRUSTEE_HOST="${NODE_IP}:${NODE_PORT}"
    echo "Using NodePort access - NODE_IP: ${NODE_IP}, NODE_PORT: ${NODE_PORT}"

else
    # Use route-based access (default)
    echo "Waiting for Trustee service route to be available..."
    for i in {1..30}; do
        TRUSTEE_HOST=$(oc get route kbs-service -n trustee-operator-system '-o=jsonpath={.spec.host}' 2>/dev/null || echo "")
        if [ -n "$TRUSTEE_HOST" ]; then
            break
        fi
        echo "Waiting for kbs-service route... (attempt $i/30)"
        sleep 10
    done

    if [ -z "$TRUSTEE_HOST" ]; then
        echo "Warning: Trustee service route not found after waiting. You may need to:"
        echo "1. Deploy the Trustee operator"
        echo "2. Create the KBS service and route manually"
        TRUSTEE_HOST="kbs-service-trustee-operator-system.apps.your-cluster.com"
    fi
fi

# Determine protocol based on configuration
if [[ "${TRUSTEE_URL_USE_HTTP}" == "true" ]]; then
    TRUSTEE_PROTOCOL="http"
    echo "Using HTTP protocol for Trustee (insecure - for testing only)"
else
    TRUSTEE_PROTOCOL="https"
    echo "Using HTTPS protocol for Trustee (secure)"
fi

TRUSTEE_URL="${TRUSTEE_PROTOCOL}://${TRUSTEE_HOST}"
echo "TRUSTEE_URL: \"$TRUSTEE_URL\""

# Export TRUSTEE_URL for use by other scripts
export TRUSTEE_URL
echo "Exported TRUSTEE_URL environment variable"

# Check if we need to include kbs_cert based on insecure_http setting
echo "Checking TRUSTEE_INSECURE_HTTP setting..."

if [[ "${TRUSTEE_INSECURE_HTTP}" == "true" ]]; then
    echo "TRUSTEE_INSECURE_HTTP is true, will NOT include kbs_cert in initdata"
    INCLUDE_KBS_CERT=false
else
    echo "TRUSTEE_INSECURE_HTTP is false, will include kbs_cert in initdata"
    INCLUDE_KBS_CERT=true

    # Get the TLS certificate from the kbs-https-certificate secret
    KBS_CERT=""
    if resource_exists "secret" "kbs-https-certificate"; then
        KBS_CERT=$(oc get secret kbs-https-certificate -n trustee-operator-system '-o=jsonpath={.data.tls\.crt}' | base64 -d)
        echo "Retrieved TLS certificate from kbs-https-certificate secret"
    else
        echo "Warning: kbs-https-certificate secret not found, using placeholder certificate"
        KBS_CERT="-----BEGIN CERTIFICATE-----
MIICertificatePlaceholder
-----END CERTIFICATE-----"
    fi
fi

# Generate INITDATA configuration
echo "Generating INITDATA configuration..."
if [[ "$INCLUDE_KBS_CERT" == "true" ]]; then
    create_initdata_config "${TRUSTEE_URL}" "${KBS_CERT}"
else
    create_initdata_config "${TRUSTEE_URL}" ""
fi

# Convert initdata.toml to base64 for INITDATA
INITDATA_STRING=$(gzip -c initdata.toml | base64 -w0 )
echo "INITDATA generated (length: ${#INITDATA_STRING})"


# Save INITDATA_STRING to SHARED_DIR for use by subsequent steps
if [ -n "${SHARED_DIR:-}" ]; then
    echo "Saving INITDATA_STRING to SHARED_DIR for peer-pods-cm INITDATA..."
    echo "${INITDATA_STRING}" > "${SHARED_DIR}/initdata_string.txt"
    echo "INITDATA_STRING saved to: ${SHARED_DIR}/initdata_string.txt"
else
    echo "SHARED_DIR not set, saving INITDATA_STRING to current directory..."
    echo "${INITDATA_STRING}" > initdata_string.txt
    echo "INITDATA_STRING saved to: initdata_string.txt"
fi

# Create patch script for peer-pods-cm
create_patch_peer_pods_cm_script "${INITDATA_STRING}"
# prow creates peerpods-param-cm and automation creates peer-pods-cm
echo "Use the generated patch script to update peer-pods-cm with its copy of initdata_string.txt"

# Create and apply RVPS ConfigMap update with PCR8 hash
create_rvps_configmap_update "initdata.toml"

echo "=== Trustee configuration completed successfully ==="
echo ""
echo "Configuration Approach: ${TRUSTEE_USE_CONFIG_CR:+TrusteeConfig CR (NEW)}${TRUSTEE_USE_CONFIG_CR:-Manual KbsConfig (LEGACY)}"
if [[ "${TRUSTEE_USE_CONFIG_CR}" == "true" ]]; then
    echo "Profile: ${TRUSTEE_PROFILE}"
    echo ""
    echo "Created Trustee Operator components (via TrusteeConfig CR):"
    echo "- Namespace: trustee-operator-system"
    echo "- Subscription: trustee-operator (from catalog: ${TRUSTEE_CATALOG_SOURCE_NAME})"
    echo "- TrusteeConfig: ${TRUSTEE_CONFIG_NAME} (profile: ${TRUSTEE_PROFILE})"
    echo "- Route: kbs-service (exposes KBS service externally)"
    echo ""
    echo "Auto-generated by TrusteeConfig operator:"
    echo "  ✓ KbsConfig: ${KBSCONFIG_NAME:-${TRUSTEE_CONFIG_NAME}-kbs-config}"
    echo "  ✓ ConfigMap: ${TRUSTEE_CONFIG_NAME}-kbs-config (Trustee service configuration)"
    echo "  ✓ ConfigMap: ${TRUSTEE_CONFIG_NAME}-attestation-policy (comprehensive multi-platform policy)"
    echo "  ✓ ConfigMap: ${TRUSTEE_CONFIG_NAME}-resource-policy (EAR-based policy)"
    echo "  ✓ ConfigMap: ${TRUSTEE_CONFIG_NAME}-rvps-reference-values (Reference Value Provider Service)"
    echo "  ✓ ConfigMap: ${TRUSTEE_CONFIG_NAME}-tdx-config (Intel TDX configuration)"
    echo "  ✓ Secret: ${TRUSTEE_CONFIG_NAME}-auth-secret (authentication)"
    echo "  ✓ Secret: kbsres1 (sample resource secret)"
    if [[ "${TRUSTEE_PROFILE}" == "Restrictive" ]]; then
        echo "  ✓ TLS Certificates: ${HTTPS_SECRET:-trustee-tls-cert}, ${TOKEN_SECRET:-trustee-token-cert}"
        if [[ "${TRUSTEE_USE_CERT_MANAGER}" == "true" ]]; then
            echo "    (managed by cert-manager)"
        else
            echo "    (manual OpenSSL certificates)"
        fi
    fi
    echo ""
    echo "Manually added secrets:"
    echo "  ⚠ Secret: security-policy (MANDATORY for image signature verification)"
    echo "  ✓ Secret: cosign-public-key (container image signature verification)"
    if [ -n "${VCEK_SECRET_NAME:-}" ]; then
        echo "  ✓ VCEK certificates configured for disconnected environment"
    fi
else
    echo ""
    echo "Created Trustee Operator components (Legacy manual approach):"
    echo "- Namespace: trustee-operator-system"
    echo "- Subscription: trustee-operator (from catalog: ${TRUSTEE_CATALOG_SOURCE_NAME})"
    echo "- Secret: attestation-token (SSL/TLS certificate and key)"
    echo "- Secret: kbs-auth-public-key (authentication public key)"
    echo "- Secret: kbs-https-certificate (HTTPS certificate for KBS service)"
    echo "- Secret: kbs-https-key (HTTPS private key for KBS service)"
    echo "- Secret: kbsres1 (example resource secret for clients)"
    echo "- Secret: cosign-public-key (container image signature verification)"
    echo "- Secret: security-policy (container security policy - MANDATORY)"
    echo "- ConfigMap: kbs-config-cm (Trustee service configuration)"
    echo "- ConfigMap: rvps-reference-values (Reference Value Provider Service)"
    echo "- ConfigMap: attestation-policy (OPA attestation policy)"
    echo "- ConfigMap: resource-policy (resource access policy)"
    echo "- ConfigMap: tdx-config (Intel TDX configuration - optional)"
    echo "- KbsConfig: kbsconfig (ties all components together)"
    echo "- Route: kbs-service (exposes KBS service externally)"
fi
echo ""
echo "INITDATA configuration:"
echo "- Trustee URL: ${TRUSTEE_URL}"
echo "- INITDATA string length: ${#INITDATA_STRING}"
echo "- Saved to: ${SHARED_DIR:-./}/initdata_string.txt"
echo ""
echo "Generated files:"
echo "- initdata.toml"
echo "- initdata_string.txt"
echo "- patch_peer_pods_cm.sh"
if [[ "${TRUSTEE_USE_CONFIG_CR}" == "true" ]]; then
    echo "- trusteeconfig-${TRUSTEE_PROFILE,,}.yaml"
    if [[ "${TRUSTEE_USE_CERT_MANAGER}" == "true" && "${TRUSTEE_PROFILE}" == "Restrictive" ]]; then
        echo "- cert-manager-issuer.yaml"
        echo "- cert-manager-https-cert.yaml"
        echo "- cert-manager-token-cert.yaml"
    fi
else
    echo "- kbs-config-cm.yaml"
    echo "- rvps-configmap.yaml"
    echo "- attestation-policy.yaml"
    echo "- ${RESOURCE_POLICY_FILE:-resource-policy.yaml}"
    echo "- tdx-config.yaml"
    echo "- security-policy-config.json"
    echo "- kbsconfig.yaml"
fi

# Cleanup temporary files
rm -f azure_credentials.json token.key token.crt privateKey publicKey tls.key tls.crt \
    trustee-tls.key trustee-tls.crt trustee-token.key trustee-token.crt \
    security-policy-config.json security-policy-insecureAcceptAnything.json \
    cosign-private.key cosign-public.key rvps-configmap-update.yaml \
    trustee-resource-policy-dev.yaml trustee-operatorgroup.yaml trustee-subscription.yaml \
    cm-patch-*.yaml kbsconfig-vcek-patch.json cert-manager-*.yaml

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Next Steps:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Verify Trustee deployment:"
echo "   oc get pods -n trustee-operator-system"
echo "   oc logs -n trustee-operator-system deployment/trustee-deployment"
echo ""
echo "2. (Optional) Customize policies and reference values:"
if [[ "${TRUSTEE_USE_CONFIG_CR}" == "true" ]]; then
    echo "   oc edit cm ${TRUSTEE_CONFIG_NAME}-attestation-policy -n trustee-operator-system"
    echo "   oc edit cm ${TRUSTEE_CONFIG_NAME}-resource-policy -n trustee-operator-system"
    echo "   oc edit cm ${TRUSTEE_CONFIG_NAME}-rvps-reference-values -n trustee-operator-system"
    echo ""
    echo "   After editing, restart the deployment:"
    echo "   oc rollout restart deployment/trustee-deployment -n trustee-operator-system"
else
    echo "   oc edit cm attestation-policy -n trustee-operator-system"
    echo "   oc edit cm resource-policy -n trustee-operator-system"
    echo "   oc edit cm rvps-reference-values -n trustee-operator-system"
fi
echo ""
echo "3. Install OpenShift Sandboxed Containers Operator (if not already installed)"
echo ""
echo "4. Create KataConfig to enable confidential containers"
echo ""
echo "5. Update peer-pods-cm ConfigMap with INITDATA:"
echo "   ./patch_peer_pods_cm.sh"
echo ""
echo "6. Update RVPS reference values with actual PCR measurements from your workloads"
echo ""
echo "7. Test with a confidential workload"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Important Notes:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
if [[ "${TRUSTEE_USE_CONFIG_CR}" == "true" ]]; then
    echo "✓ Using NEW TrusteeConfig CR approach (simplified, recommended)"
    echo "  - Profile: ${TRUSTEE_PROFILE}"
    echo "  - Operator auto-manages ConfigMaps and Secrets"
    echo "  - To switch profiles, delete and recreate TrusteeConfig CR"
else
    echo "⚠ Using LEGACY manual KbsConfig approach"
    echo "  - Consider migrating to TrusteeConfig CR: TRUSTEE_USE_CONFIG_CR=true"
    echo "  - See: TRUSTEE_MIGRATION_ANALYSIS.md for details"
fi
echo ""
echo "⚠ SECURITY-POLICY IS MANDATORY!"
echo "  - Image signature verification is ALWAYS enabled in OSC"
echo "  - Without security-policy secret, ALL pods will fail to start"
echo "  - Current policy: insecureAcceptAnything (accepts all images)"
echo "  - For production, configure proper signature verification"
echo "  - See: image-signature-verification.md"
echo ""
echo "📋 Reference documentation loaded from:"
echo "  - /home/tbuskey/go/src/github.com/tbuskey/osc-internal-docs/docs/deploying/operators/trustee/new-approach/"
echo ""
echo "🔧 Configuration Options:"
echo "  TRUSTEE_USE_CONFIG_CR=${TRUSTEE_USE_CONFIG_CR} (default: true)"
echo "  TRUSTEE_PROFILE=${TRUSTEE_PROFILE:-Permissive} (Permissive|Restrictive)"
echo "  TRUSTEE_USE_CERT_MANAGER=${TRUSTEE_USE_CERT_MANAGER} (for Restrictive profile)"
echo "  TRUSTEE_URL_USE_HTTP=${TRUSTEE_URL_USE_HTTP} (default: false)"
echo "  TRUSTEE_URL_USE_NODEPORT=${TRUSTEE_URL_USE_NODEPORT} (default: false)"
if [ -n "${VCEK_SECRET_NAME:-}" ]; then
    echo "  VCEK_SECRET_NAME=${VCEK_SECRET_NAME} (disconnected environment)"
fi
echo ""
echo "🌐 Exported environment variables:"
echo "  TRUSTEE_URL=${TRUSTEE_URL}"
echo "  INITDATA_STRING length: ${#INITDATA_STRING}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
