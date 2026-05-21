---
description: Debug sandboxed-containers-operator CI step failures using /pj-rehearse
args: "[job_name]"
allowed-tools:
  - Read
  - Edit
  - Write
  - Glob
  - AskUserQuestion
  - Bash(make update)
  - Bash(git *)
  - Bash(.claude/scripts/monitor-rehearsal.sh *)
  - Bash(.claude/scripts/analyze-prowjob.sh *)
  - Bash(.claude/scripts/prow-fetch.sh *)
  - Bash(.claude/scripts/trigger-rehearsal.sh *)
  - Bash(ps aux | grep *)
  - Bash(kill *)
  - Bash(sleep *)
  - Bash(date)
  - Bash(wc *)
  - Bash(grep *)
  - Bash(jq *)
  - Bash(find ci-operator/step-registry/sandboxed-containers-operator *)
  - Bash(find ci-operator/config/openshift/sandboxed-containers-operator *)
---

# OSC Step Debug - Sandboxed Containers Operator CI Step Debugging

Debug and fix sandboxed-containers-operator (OSC) CI step failures using /pj-rehearse for rapid iteration.

**Arguments**: 
- `job_name` (optional): Specific OSC job to debug (e.g., "azure-ipi-coco", "aws-ipi-peerpods")

## Scope

**This skill is ONLY for sandboxed-containers-operator CI configuration:**
- Files in `ci-operator/step-registry/sandboxed-containers-operator/`
- Config in `ci-operator/config/openshift/sandboxed-containers-operator/`
- OSC test jobs (CoCo, Kata, PeerPods)

**DO NOT use this skill for:**
- Other repositories or components
- Core Prow infrastructure changes
- Changes outside the sandboxed-containers-operator scope

## Overview

This skill provides a systematic workflow for debugging OSC CI step failures:

1. **Identify** the failing step in `ci-operator/step-registry/sandboxed-containers-operator/`
2. **Analyze** error patterns in Prow build logs
3. **Fix** issues based on common OSC patterns:
   - OLM operator installation (trustee, OSC)
   - CatalogSource readiness
   - Base images and tool availability
   - Network restrictions
   - Environment variables and secrets
   - kbs-client connectivity
   - Kata/CoCo/PeerPods specific issues
4. **Test** changes using /pj-rehearse
5. **Monitor** long-running rehearsals with background scripts
6. **Iterate** until the job passes

**Common OSC job types:**
- `azure-ipi-coco` - Confidential Containers on Azure
- `aws-ipi-coco` - Confidential Containers on AWS
- `azure-ipi-kata` - Kata Containers on Azure
- `aws-ipi-peerpods` - Peer Pods on AWS
- `aro-ipi-peerpods` - Peer Pods on ARO

## Mandatory Wrapper Usage

**CRITICAL:** This skill MUST use wrapper scripts for all Prow and GitHub access. Direct `curl` and `gh` commands are NOT allowed.

**Required wrappers (pre-approved in allowed-tools):**

**`.claude/scripts/prow-fetch.sh`** - For ALL Prow, GCS, and GitHub API access:
```bash
# Get PR checks (wraps gh pr checks internally)
.claude/scripts/prow-fetch.sh pr-checks <PR> [PATTERN]

# Fetch any Prow/GCS URL
.claude/scripts/prow-fetch.sh <URL>

# Fetch build logs
.claude/scripts/prow-fetch.sh build-log <PR> <JOB_ID> <STEP_NAME>

# Fetch job results
.claude/scripts/prow-fetch.sh finished <PR> <JOB_ID>
.claude/scripts/prow-fetch.sh started <PR> <JOB_ID>
```

**`.claude/scripts/monitor-rehearsal.sh`** - For monitoring rehearsals:
```bash
.claude/scripts/monitor-rehearsal.sh <PR> <SHORT_JOB_NAME> [DURATION_HOURS] [CHECK_INTERVAL] [STEP_NAME] [ARTIFACT_WAIT] [CONTINUE_AFTER_STEP]
```

**`.claude/scripts/analyze-prowjob.sh`** - For analyzing failures:
```bash
.claude/scripts/analyze-prowjob.sh <PROW_JOB_URL>
```

**`.claude/scripts/trigger-rehearsal.sh`** - For triggering rehearsals:
```bash
.claude/scripts/trigger-rehearsal.sh <PR> <JOB_NAME>
```

## Workflow

### 1. Identify Failing Step

Find the step in the OSC step registry:

```bash
find ci-operator/step-registry/sandboxed-containers-operator -name "*<step-name>*"
```

Common OSC steps:
- `install-trustee-operator` - Install Trustee operator for CoCo
- `env-cm` - Create environment ConfigMap and CatalogSource
- `get-kata-rpm` - Download and install Kata RPM
- `peerpods-param-cm` - Create PeerPods parameter ConfigMap
- `record-metadata` - Record test metadata

### 2. Analyze Failure

Use prowjob-analyzer for OSC-specific analysis:

```bash
.claude/scripts/analyze-prowjob.sh <PROW_URL>
```

The analyzer understands OSC test patterns:
- Metadata extraction (provider, OCP version, workload type)
- Failed step identification
- Test result summaries
- Common failure patterns (RPM installation, operator setup, etc.)

### 3. Common OSC Debugging Patterns

**OLM Operator Installation Issues:**
```yaml
# Wait for CatalogSource readiness
# Check Subscription → InstallPlan → CSV → Deployment stages
```

**CatalogSource not ready:**
```bash
# Add wait loop for brew-catalog or custom CatalogSource
# Poll for READY state before proceeding
```

**Base image issues:**
```yaml
# Use 'from: cli' for oc/kubectl only
# Use 'from: tools' for git, make, python, etc.
```

**Network restrictions:**
```yaml
# OSC CoCo tests require network access for kbs-client
restrict_network_access: false
```

**kbs-client connectivity:**
```bash
# Test resource retrieval
# Check RCA protocol: GET → 401 → POST /auth → POST /attest → GET → 200
```

### 4. File Changes Scope

**Allowed file modifications:**
- `ci-operator/step-registry/sandboxed-containers-operator/**/*`
- `ci-operator/config/openshift/sandboxed-containers-operator/**/*`
- `ci-operator/jobs/openshift/sandboxed-containers-operator/**/*` (generated only)

**NOT allowed:**
- Files outside sandboxed-containers-operator scope
- Core Prow configuration
- Other component repositories

### 5. Testing with /pj-rehearse

**Trigger rehearsal:**
```bash
.claude/scripts/trigger-rehearsal.sh <PR> <full-job-name>
```

**OSC job name pattern:**
```
periodic-ci-openshift-sandboxed-containers-operator-<branch>-<platform>-<workload>
```

Examples:
- `periodic-ci-openshift-sandboxed-containers-operator-devel-downstream-candidate-azure-ipi-coco`
- `periodic-ci-openshift-sandboxed-containers-operator-devel-downstream-candidate-aws-ipi-peerpods`

### 6. Monitor Results

**For OSC steps (often long-running):**
```bash
.claude/scripts/monitor-rehearsal.sh <PR> <pattern> 3 300 <step-name> 120 true
```

Example for install-trustee-operator:
```bash
.claude/scripts/monitor-rehearsal.sh 79244 azure-ipi-coco 3 300 install-trustee-operator 120 true
```

This monitors the step completion, waits 120s for artifacts, then continues to full job completion.

### 7. Iteration

**DO NOT push** while a rehearsal cluster is running - it will abort the cluster immediately.

**Check for active rehearsals before pushing:**
```bash
.claude/scripts/prow-fetch.sh pr-checks <PR> <pattern>
```

Only push when status is: `success`, `failure`, `aborted`, or `error` (not `pending` or `triggered`).

## OSC-Specific Knowledge

### Trustee Operator (for CoCo tests)

**Version compatibility:**
- trustee 1.1.x → kbs-client v0.17.0
- trustee 1.11.x → kbs-client v0.19.0

**Components:**
- KBS (Key Broker Service) - provides secrets/resources to confidential workloads
- Attestation Service - validates TEE evidence
- RCA protocol - Resource-Centric Authorization

**Common issues:**
- CatalogSource not ready before Subscription
- kbs-client SSL certificate errors (use HTTP in test environments)
- Resource not found (check KbsConfig published secrets)

### OSC Operator

**CatalogSources:**
- `brew-catalog` - internal builds (Pre-GA tests)
- `redhat-operators` - GA releases

**Workload types:**
- `coco` - Confidential Containers (requires trustee)
- `kata` - Kata Containers
- `peerpods` - Peer Pods (remote VMs)

### Test Flow

1. **Pre phase:** Install operators (OSC, Trustee), configure cluster
2. **Test phase:** Run openshift-extended-test with OSC filters
3. **Post phase:** Collect must-gather, cleanup

## Common Error Patterns

**"CatalogSource not READY":**
```
Solution: Add wait loop after CatalogSource creation
```

**"Subscription has no InstallPlan reference":**
```
Solution: Check CatalogSource READY state, OLM resolution errors
```

**"kbs-client: Authenticating with KBS failed":**
```
Solution: Check Trustee URL, TLS certificates, kbsres1 resource exists
```

**"Pod not ready after 150s":**
```
Solution: Add polling loop with diagnostics, check pod events
```

**"404 Not Found" for resource:**
```
Solution: Verify KbsConfig includes the resource in kbsSecretResources
```

## Example Session

```bash
# 1. Identify failing job
/osc-step-debug azure-ipi-coco

# 2. Claude will:
#    - Find the failing step in step-registry/sandboxed-containers-operator/
#    - Analyze logs with prowjob-analyzer
#    - Identify the issue (e.g., CatalogSource not ready)
#    - Make the fix (add wait loop)
#    - Run make update
#    - Commit changes
#    - Trigger rehearsal
#    - Monitor until completion
#    - Report results

# 3. On success: Done
# 4. On failure: Iterate (Claude analyzes new error, fixes, repeats)
```

## Automation Level

**This skill operates autonomously for OSC step debugging:**
- Analyzes failures automatically
- Makes fixes based on known patterns
- Triggers rehearsals and monitors results
- Iterates on failures
- **WAITS for user input** after each iteration completes

**User confirmation required for:**
- Starting a new iteration after failure/success
- Making changes outside standard patterns
- Architectural decisions

## Notes

- All changes stay within sandboxed-containers-operator scope
- Follows OSC team coding patterns and conventions
- Uses OLM stage-by-stage polling for operator installations
- Strips ANSI color codes from logs for readability
- Maps operator versions to compatible client versions
