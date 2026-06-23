# MXL (Media eXchange Layer) - Threat Model Analysis

**Date**: June 23, 2026  
**Scope**: Media eXchange Layer SDK - Open-source shared memory media exchange library  
**Methodology**: STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)

---

## 1. Executive Summary

MXL is a C++ open-source SDK enabling high-performance, zero-copy media sharing across local and distributed compute environments using shared memory and RDMA fabrics. This threat model identifies potential security risks in three primary areas:

1. **Local Shared Memory Access Control** - Reliance on UNIX file permissions for multi-process security
2. **RDMA Fabric Communication** - Network-based media transfer between hosts
3. **Resource Parsing & Validation** - JSON deserialization and flow metadata handling

---

## 2. System Architecture Overview

### 2.1 Core Components

```
┌─────────────────────────────────────────────────────────┐
│                 MXL Application Layer                    │
│  (Video processing, audio processing, data functions)   │
└────────────────┬────────────────────────────────────────┘
                 │
        ┌────────▼────────┐
        │   Flow API      │
        │  (Zero-copy)    │
        └────────┬────────┘
                 │
    ┌────────────┴────────────┬────────────────┐
    │                         │                │
┌───▼────────┐      ┌────────▼──────┐  ┌──────▼──────┐
│ Shared Mem │      │  RDMA Fabric  │  │ Local IPC   │
│ (tmpfs)    │      │  (Network)    │  │ (futex sync)│
└────────────┘      └───────────────┘  └─────────────┘
```

### 2.2 Key Data Flows

1. **Local Zero-Copy Flow**: Writer → Shared Memory (mmap) ← Reader
2. **Remote Transfer**: Local Memory → RDMA Fabric → Remote Memory
3. **Metadata Exchange**: Flow definitions (JSON) + grain headers in shared filesystem
4. **Synchronization**: Futex-based waits on memory-mapped structures

### 2.3 Deployment Models

- **Bare-metal**: Multiple processes on same host, tmpfs-backed flows
- **Containerized**: Containers sharing tmpfs volumes, namespace isolation
- **Cloud-distributed**: RDMA fabric connecting hosts across networks
- **Hybrid**: Mix of local and remote media functions

---

## 3. Trust Boundaries & Assets

### 3.1 Trust Boundaries

| Boundary | Type | Protection Mechanism |
|----------|------|----------------------|
| Same host, different users | Local IPC | UNIX file permissions (mode 0664) |
| Same container (shared namespace) | Virtual | Namespace isolation + file permissions |
| Different containers (same host) | Container | Namespace boundaries + mount points |
| Different hosts via RDMA | Network | Fabric credentials + address vector |
| Reader ↔ Writer on same memory | Memory | Futex synchronization primitives |

### 3.2 Critical Assets

| Asset | Classification | Owner | Sensitivity |
|-------|-----------------|-------|-------------|
| Media payloads (grains) | Confidentiality | Media function | HIGH (video/audio) |
| Flow metadata (JSON) | Integrity | Media function | MEDIUM |
| Timing/synchronization data | Availability | System | CRITICAL |
| Grain headers | Integrity | System | MEDIUM |
| Memory-mapped grain buffers | Confidentiality + Integrity | Media function | HIGH |
| RDMA fabric credentials | Confidentiality | System | CRITICAL |
| Flow access logs | Auditability | System | MEDIUM |

---

## 4. STRIDE Threat Analysis

### 4.1 SPOOFING

#### 4.1.1 Unauthorized Writer Claims (Local)
**Threat**: Unprivileged process claims to be the legitimate flow writer  
**Severity**: HIGH  
**Vulnerability**: 
- No process identity verification beyond UNIX uid/gid
- File locks (flock) prevent concurrent writers but don't authenticate identity
- AccessFile ('touched' by readers) lacks origin verification

**Evidence**: 
```cpp
// SharedMemory.cpp:30 - Only checks file permissions, not process identity
if ((mode == AccessMode::CREATE_READ_WRITE) && 
    ((_fd = ::open(path, OMODE_CREATE, 0664)) != -1))
```

**Exploitation Path**:
1. Attacker in same user group reads flow descriptor
2. Creates new process with same UID, opens existing flow for writing
3. Corrupts grain data while legitimate writer is not holding lock
4. Legitimate writer detects corruption too late

**Impact**: Data corruption, injection of malicious media content

#### 4.1.2 Unauthorized Reader Impersonation (Distributed)
**Threat**: Attacker spoofs a legitimate remote reader on RDMA fabric  
**Severity**: CRITICAL  
**Vulnerability**:
- Address vector construction reliant on fabric provider authentication
- No mutual TLS or challenge-response between endpoints
- Fabric credentials may be stored unencrypted on host

**Impact**: Unauthorized access to media in transit, man-in-the-middle position

#### 4.1.3 Flow Creator Spoofing
**Threat**: Unprivileged process creates flows with misleading metadata  
**Severity**: MEDIUM  
**Vulnerability**:
- Flow creation doesn't log creator identity
- NMOS resource definitions accept arbitrary metadata
- No signature verification on flow_def.json

**Impact**: Metadata poisoning, downstream processing errors

---

### 4.2 TAMPERING

#### 4.2.1 In-Flight Grain Data Modification (Local)
**Threat**: One process modifies grains while another is reading  
**Severity**: HIGH  
**Vulnerability**:
- Readers mmap in PROT_READ, but shared memory is MAP_SHARED
- Futex-based synchronization not atomic with respect to data access
- Partial grain I/O (committedSize) vulnerable to race conditions

**Evidence**: 
```cpp
// Architecture: "The important field here is the mxlGrainInfo.committedSize"
// No memory barriers between reading committedSize and accessing payload
```

**Attack Scenario**:
1. Writer commits grain partially (slice 1/8)
2. Reader observes committedSize update
3. Reader begins processing slice 1
4. Writer overwrites slice 1 with different data (race condition)
5. Reader processes corrupted data

**Impact**: Data corruption, undefined behavior, potential code execution via crafted payloads

#### 4.2.2 Grain Metadata Tampering
**Threat**: Modification of grain headers (timestamps, format, size)  
**Severity**: HIGH  
**Vulnerability**:
- Grain header (mxlGrainInfo) stored in mmap'd file alongside payload
- No checksum or cryptographic integrity protection
- Reader doesn't validate header coherence

**Impact**: Incorrect media interpretation, buffer overflow if grainSize field is crafted

#### 4.2.3 Flow Configuration Injection
**Threat**: Attacker modifies flow_def.json between creation and consumer read  
**Severity**: MEDIUM  
**Vulnerability**:
- FlowManager creates temp directory, publishes via rename (atomic)
- But flow_def.json written AFTER directory rename
- TOCTOU window exists if reader re-reads descriptor

**Evidence**:
```cpp
// FlowManager.cpp:54-78 - rename is atomic, but descriptor write is separate
bool publishFlowDirectory(...) {
    // ... rename temp → public ...
}
// Then descriptor written separately, not shown in this snippet
```

**Impact**: Parser processes attacker-controlled JSON, potential DoS or confusion

#### 4.2.4 RDMA Memory Corruption
**Threat**: Attacker sends crafted RDMA packets to corrupt remote memory  
**Severity**: CRITICAL  
**Vulnerability**:
- RDMA Write operations lack per-message authentication
- Memory region registration doesn't prevent off-bounds writes
- No replay detection on RDMA protocol

**Impact**: Remote memory corruption, execution of untrusted data

---

### 4.3 REPUDIATION

#### 4.3.1 No Flow Modification Audit Trail
**Threat**: Actor modifies flow or grains without accountable logging  
**Severity**: MEDIUM  
**Vulnerability**:
- AccessFile touched by readers but not writers
- No per-grain audit log
- Timestamps in grain header not cryptographically signed

**Evidence**: Flow design intentionally minimizes writes to support read-only readers

**Impact**: Cannot attribute grain corruption to specific actor

#### 4.3.2 RDMA Fabric Operations Unlogged
**Threat**: Network-level tampering with no forensic trail  
**Severity**: MEDIUM  
**Vulnerability**:
- RDMA operations are one-sided (target doesn't participate)
- No logging of who requested remote reads/writes
- Fabric credentials may not be audit-logged

**Impact**: Attribution impossible for attacks via RDMA

---

### 4.4 INFORMATION DISCLOSURE

#### 4.4.1 Media Content Leakage via Shared Memory
**Threat**: Unprivileged user reads media from flows they shouldn't access  
**Severity**: CRITICAL  
**Vulnerability**:
- File mode 0664 (rw-rw-r--) allows group read access
- All users in group can mmap flow files in PROT_READ
- No encryption at rest in shared memory

**Evidence**: 
```cpp
// FlowManager.cpp:56-59 - Adds group_read + others_read permissions
permissions(source,
    std::filesystem::perms::group_read | 
    std::filesystem::perms::others_read | ...
```

**Attack Scenario**:
1. Admin creates flow for confidential broadcast content
2. Attacker in same group mmap's the grain files
3. Attacker reads raw V210 video or F32 audio
4. No audit trail, data silently exfiltrated

**Impact**: Confidentiality breach of live media streams

#### 4.4.2 Metadata Disclosure
**Threat**: Sensitive flow metadata readable by unauthorized processes  
**Severity**: MEDIUM  
**Vulnerability**:
- flow_def.json contains NMOS resource definitions (readable world-wide)
- May expose source/destination, encoding parameters, timing info
- No redaction mechanism for sensitive fields

**Impact**: Information leakage (flow graph, timing analysis)

#### 4.4.3 Memory Exhaustion via Unbounded JSON
**Threat**: Attacker creates massive flow_def.json to trigger OOM  
**Severity**: MEDIUM  
**Vulnerability**:
- FlowParser uses picojson (in-memory parsing)
- MAX_WIDTH/MAX_HEIGHT limits video, but no overall doc size limit
- Complex JSON with deeply nested structures

**Impact**: DoS via resource exhaustion

#### 4.4.4 Timing Side-Channel via Futex Contention
**Threat**: Observer deduces media processing by measuring futex latency  
**Severity**: LOW  
**Vulnerability**:
- Futex-based synchronization timing correlates with writer activity
- Reader spinning on sync counter provides timing oracle
- maxSyncBatchSizeHint advertises batch sizes

**Impact**: Indirect information leakage (activity patterns, not content)

---

### 4.5 DENIAL OF SERVICE

#### 4.5.1 Flow Exhaustion Attack
**Threat**: Attacker creates thousands of flows, exhausting inode/disk space  
**Severity**: MEDIUM  
**Vulnerability**:
- No rate limiting on flow creation
- No quota system per user/group
- tmpfs can fill system memory

**Attack Scenario**:
1. Attacker creates loop: for i in 1..10000: create_flow()
2. Each flow allocates grain directories + data files
3. tmpfs (usually 50% RAM) fills completely
4. Legitimate flows cannot write, system thrashing

**Impact**: Service unavailability

#### 4.5.2 Grain Ring Buffer Overflow Attacks
**Threat**: Writer produces grains faster than reader consumes  
**Severity**: MEDIUM  
**Vulnerability**:
- No backpressure mechanism for writer overflow
- Reader can fall behind indefinitely
- Memory grows unbounded if grains aren't garbage collected

**Impact**: Memory leak, eventual OOM, service unavailability

#### 4.5.3 Lock Contention DoS
**Threat**: Attacker holds locks to block legitimate access  
**Severity**: LOW  
**Vulnerability**:
- flock-based locks are per-FD, not per-process
- Shared advisory locks don't timeout
- Stale flow detection relies on dead process cleanup

**Impact**: Temporary blocking of flow access

#### 4.5.4 Futex Exhaustion
**Threat**: Excessive futex syscalls from synchronization contention  
**Severity**: LOW  
**Vulnerability**:
- Multiple readers spinning on same futex in tight loop
- No jitter or backoff strategy
- High context switching overhead

**Impact**: CPU starvation, latency spikes

#### 4.5.5 RDMA Resource Depletion
**Threat**: Attacker opens many RDMA connections/registrations  
**Severity**: MEDIUM  
**Vulnerability**:
- No connection pooling or limits
- RDMA queues have finite entries
- Memory registration limited by HCA

**Impact**: Prevent legitimate fabric operations

---

### 4.6 ELEVATION OF PRIVILEGE

#### 4.6.1 Cross-User Flow Access via Group Membership
**Threat**: Attacker in same group modifies or reads privileged flows  
**Severity**: HIGH  
**Vulnerability**:
- Flow files mode 0664 (group writable)
- No per-flow ACL beyond UNIX permissions
- tmpfs doesn't support extended attributes

**Attack Scenario**:
1. User A (group `broadcast`) creates confidential flow
2. User B (also in `broadcast`, but untrusted) is added to group
3. User B opens flow for writing, injects corrupted frames
4. Live broadcast compromised

**Impact**: Privilege escalation within group, data integrity breach

#### 4.6.2 Namespace Escape via Fabric (Container Context)
**Threat**: Container escapes isolation via RDMA to host  
**Severity**: CRITICAL  
**Vulnerability**:
- If container is run with host RDMA device access
- Fabric credentials not namespace-isolated
- RDMA Write can target any memory region

**Impact**: Container escape, root access to host

#### 4.6.3 mmap Permissions Bypass via Symlink Race
**Threat**: Attacker uses symlink race to mmap high-privilege file  
**Severity**: MEDIUM  
**Vulnerability**:
- Path traversal possible if domain path not validated against symlinks
- open(2) follows symlinks unless O_NOFOLLOW used
- Race between access check and mmap

**Evidence**: No evidence of O_NOFOLLOW in file open calls

**Attack Scenario**:
1. Flow creator accidentally creates domain symlink to /root/secret
2. Attacker manipulates links before creator opens flow
3. Attacker gains write access to /root/secret

**Impact**: Arbitrary file read/write as flow user

#### 4.6.4 Stale Flow Lock Exploitation
**Threat**: Attacker claims "stale" lock, gains exclusive access  
**Severity**: MEDIUM  
**Vulnerability**:
```cpp
// Instance.cpp:332-334 - stale detection via lock attempt
int fd = ::open(flowDataFile.c_str(), flags);
bool active = ::flock(fd, LOCK_EX | LOCK_NB) < 0;
```
- LOCK_NB fails if lock exists, but no timeout
- Creator's process could be paused/suspended indefinitely
- Attacker assumes creator is dead, claims exclusive lock

**Impact**: Unauthorized write access to active flow

---

## 5. Detailed Vulnerability Assessment

### 5.1 Shared Memory Access Control (Severity: CRITICAL)

**Issue**: Reliance on UNIX file permissions (0664) for multi-user isolation

**Details**:
- Flows stored in tmpfs with mode 0664 (rw-rw-r--)
- Any process with group membership can read grain payload
- Media content (V210, audio/F32) unencrypted at rest
- No MAC/SELinux integration

**Root Cause**: Design prioritizes performance over isolation; assumes trusted environment

**Remediation Options**:
1. **File Encryption (Recommended)**: Encrypt grain payload with per-flow key
2. **Extended Attributes**: Use ACLs if tmpfs supports (not standard)
3. **Namespace Isolation**: Require per-flow namespace (breaks zero-copy)
4. **Credential Binding**: Validate reader UID/GID against ACL
5. **Strict Permissions**: Default to 0600, require explicit sharing

**Risk if Not Fixed**: Confidential media (e.g., unbroadcast content) disclosed to unauthorized users

---

### 5.2 Race Conditions in Grain I/O (Severity: HIGH)

**Issue**: Partial grain write vulnerable to concurrent reader modification

**Details**:
- Writer calls mxlFlowWriterOpenGrain() → mmap
- Reader can mmap same file simultaneously
- Writer updates committedSize; reader spins on futex
- No memory barrier ensures committedSize write is visible before reader access

**Example Attack**:
```cpp
// Writer commits grain in slices
for (slice = 0 to 7) {
    gInfo.committedSize += sliceSize;
    mxlFlowWriterCommitGrain(...); // Updates memory, no mb()
}

// Reader polling committedSize
while (gInfo.committedSize < expectedSize) {
    // Reader may see partial update, access uninitialized data
}
```

**Root Cause**: C++ memory model not explicitly used; futex synchronization insufficient without memory barriers

**Remediation**:
1. Use `std::atomic<size_t>` for committedSize
2. mxlFlowWriterCommitGrain() must issue memory barrier
3. Reader must acquire barrier before reading payload
4. Add validation: verify committedSize <= grainSize

**Risk if Not Fixed**: Memory corruption, reading stale/uninitialized data, potential RCE

---

### 5.3 JSON Parsing DoS (Severity: MEDIUM)

**Issue**: Unbounded JSON document parsing in flow definitions

**Details**:
- flow_def.json parsed with picojson (in-memory)
- MAX_WIDTH/MAX_HEIGHT limits (7680x4320), but overall doc size unchecked
- Deeply nested JSON or malicious arrays can exhaust memory
- No streaming parser, entire doc loaded into memory

**Attack Example**:
```json
{
  "video": [{"frame": [[[[...deeply nested...]]]]]}  // 100MB JSON
}
```

**Root Cause**: Convenient but unsafe JSON library choice; no size limits enforced at parsing

**Remediation**:
1. Limit JSON document size (e.g., 1MB max)
2. Use streaming JSON parser for large docs
3. Validate parsed object sizes before allocation
4. Add recursion depth limit to JSON parser

**Risk if Not Fixed**: DoS via OOM, service unavailability

---

### 5.4 Flow Metadata TOCTOU (Severity: MEDIUM)

**Issue**: Time-of-Check-Time-of-Use window in flow creation

**Details**:
- Temp directory created via mkdtemp (atomic)
- Directory published via rename (atomic)
- But flow_def.json written after directory rename
- Reader could race and see incomplete/missing descriptor

**Attack Scenario**:
```
1. Writer calls mxlFlowWriterCreate() → mkdtemp(.mxl-tmp-XXXXX)
2. Writer publishes directory: rename(.mxl-tmp-XXXXX → UUID.mxl-flow)
3. Reader observes UUID.mxl-flow directory (race point)
4. Reader attempts to read flow_def.json
5. Writer still writing flow_def.json (no lock)
6. Reader gets partial/corrupted JSON
```

**Root Cause**: Two-stage creation (dir + descriptor) not atomic

**Remediation**:
1. Write flow_def.json to temp dir before rename
2. Verify descriptor exists after rename with fstat check
3. Use temp directory visibility as creation signal, not descriptor

**Risk if Not Fixed**: Reader processes corrupted flow definitions, potential crashes

---

### 5.5 RDMA Fabric Security (Severity: CRITICAL)

**Issue**: RDMA operations lack authentication and encryption

**Details**:
- OFI (OpenFabrics Interface) used for RDMA transport
- RDMA Write one-sided (target doesn't authenticate)
- No per-message authentication (MAC/signature)
- No encryption in transit (unless fabric provider supports)
- Address vector construction depends on fabric provider

**Attack Scenarios**:

*Scenario 1: Man-in-the-Middle*
```
Attacker on same RDMA fabric:
1. Intercepts address vector negotiation
2. Modifies remote memory address pointers
3. RDMA Write from host A → crafted address on host B
4. Arbitrary memory write achieved
```

*Scenario 2: Replay Attack*
```
1. Attacker captures RDMA Write packets
2. Replays packets after sender has moved on
3. Stale data written to fresh grain
4. Reader processes replayed frames (deadlock potential)
```

**Root Cause**: RDMA standard doesn't mandate per-message auth; assumed fabric is trusted

**Remediation**:
1. **Required**: Fabric segmentation (private VLAN/network)
2. **Recommended**: RDMA Connection-mode (RC) with ACK verification
3. **Consider**: Application-level frame authentication (e.g., HMAC of grain)
4. **Strong**: Encrypted RDMA or vhost DPDK with mTLS

**Risk if Not Fixed**: Remote code execution, data exfiltration, service disruption

---

### 5.6 Input Validation Gaps (Severity: MEDIUM)

**Issue**: Insufficient validation of user-supplied format/size parameters

**Details**:
- Format strings in flow definition not validated against schema
- Grain size from header not validated against allocated space
- Payload location (host vs device) not checked during access

**Example**:
```cpp
// Reader trusts grain header
uint64_t grainSize = gInfo.grainSize;  // From mmap'd header, untrusted
float* audio = (float*)buffer;
for (int i = 0; i < grainSize; i++) {  // Possible OOB if grainSize > buffer
    process(audio[i]);
}
```

**Root Cause**: Trust boundary not enforced; grain header is untrusted input

**Remediation**:
1. Validate grainSize <= allocated buffer size in mmap
2. Validate format string against allowlist (e.g., "video/v210", "audio/float32")
3. Validate payloadLocation enum values
4. Check width/height against buffer capacity before allocation

**Risk if Not Fixed**: Buffer overflow, use-after-free, memory corruption

---

### 5.7 Process Identity Spoofing (Severity: HIGH)

**Issue**: No cryptographic proof of process identity

**Details**:
- Writers identified only by UID/GID in file ownership
- If UID reused (user deleted/recreated), previous user's flows accessible
- Forked process inherits file descriptors, gains writer privileges
- No per-process capability tokens

**Attack Scenario**:
```
1. User alice (UID=1001) creates flow, exits
2. New user bob gets UID=1001
3. bob opens stale flows created by alice
4. bob can write to alice's flows with no audit trail
```

**Root Cause**: POSIX user namespace design; intended for same-user access patterns

**Remediation**:
1. Require explicit process token (e.g., file with random content)
2. Validate file ownership + token presence before open
3. Use systemd-notify or container init for process identity
4. Short-lived credentials with rotation

**Risk if Not Fixed**: Unauthorized access to flows after user ID reuse

---

## 6. Threat Scenarios

### 6.1 Scenario A: Containerized Broadcast Compromise

**Context**: 
- Container platform (Docker/Kubernetes) with shared tmpfs
- Multiple tenants' media functions on same host
- One tenant compromised

**Attack Chain**:
```
1. Attacker gains RCE in Tenant A container
2. Attacker enumerates /mxl-domain (shared tmpfs)
3. Finds Tenant B's high-value flow (e.g., sports stream)
4. mmap grains in PROT_READ (file mode 0664 allows group read)
5. Read V210 raw video data, exfiltrate via side-channel
6. Or, corrupt grain headers to inject watermark/blackout
```

**Root Cause**: Shared tmpfs + group-writable permissions + no encryption

**Impact**: Confidentiality breach, integrity violation, service disruption

**Severity**: CRITICAL

---

### 6.2 Scenario B: RDMA Fabric Takeover

**Context**:
- Multi-host setup with RDMA (InfiniBand/Ethernet RDMA)
- Untrusted tenant or co-located attacker on network

**Attack Chain**:
```
1. Attacker on same RDMA fabric observes address vector negotiation
2. Attacker spoofs fabric address of Host B → Host A connection
3. Host A sends RDMA Write to "Host B" (actually attacker)
4. Attacker captures media payload (raw V210 high-res video)
5. Or, replies with malicious address, Host A overwrites own memory
```

**Root Cause**: No RDMA authentication; assumed trusted fabric

**Impact**: 
- Confidentiality: Video/audio exfiltration
- Integrity: Memory corruption, RCE
- Availability: Service hang, crash

**Severity**: CRITICAL

---

### 6.3 Scenario C: Insider Threat (Group Escalation)

**Context**:
- Broadcast facility with role-based access
- Operators in `broadcast` group, but with different permissions
- One operator accidentally added to `admin` group

**Attack Chain**:
```
1. Operator (low privilege) gains group membership in `admin`
2. Operator discovers flow created by senior engineer (mode 0664)
3. Opens flow for writing (permitted by group permissions)
4. Injects corrupted frames during live broadcast
5. Broadcast disrupted; no audit trail (no writer authentication)
```

**Root Cause**: Group-level permissions without per-user ACL; no write audit log

**Impact**: 
- Integrity: On-air broadcast compromised
- Repudiation: Can't prove who corrupted data

**Severity**: HIGH

---

### 6.4 Scenario D: Resource Exhaustion

**Context**:
- Shared MXL domain with untrusted tenant

**Attack Chain**:
```
1. Attacker creates unlimited flows in tight loop
2. Each flow allocates grain directories + data files to tmpfs
3. tmpfs (50% RAM) fills completely
4. All other media functions cannot allocate new grains
5. System enters thrashing state, becomes unresponsive
```

**Root Cause**: No quota enforcement, no rate limiting

**Impact**: Denial of Service, availability loss

**Severity**: MEDIUM

---

## 7. Risk Mitigation Strategies

### 7.1 Priority 1: CRITICAL (Implement Immediately)

| Threat | Control | Effort | Effectiveness |
|--------|---------|--------|----------------|
| Shared memory disclosure | Encrypt grain payloads | High | 95% |
| RDMA fabric tampering | Fabric segmentation (separate VLAN) | Low | 80% |
| Cross-tenant access | Per-flow credential tokens | Medium | 90% |

**Implementation Approach**:
- Add optional encryption layer to grain I/O (XChaCha20-Poly1305)
- Require explicit fabric authorization (e.g., fabric token in flow metadata)
- Validate reader credentials via token file in flow directory

---

### 7.2 Priority 2: HIGH (Implement Next Release)

| Threat | Control | Effort | Effectiveness |
|--------|---------|--------|----------------|
| Grain I/O race conditions | Atomic updates with memory barriers | High | 100% |
| Process spoofing | Per-process capability tokens | Medium | 85% |
| JSON parsing DoS | Size limits + streaming parser | Medium | 90% |

**Implementation Approach**:
```cpp
// Use std::atomic for shared state
std::atomic<uint64_t> committedSize;

// Memory barriers on update
committedSize.store(newSize, std::memory_order_release);

// Memory barrier on read
uint64_t size = committedSize.load(std::memory_order_acquire);
```

---

### 7.3 Priority 3: MEDIUM (Implement in Hardening Phase)

| Threat | Control | Effort | Effectiveness |
|--------|---------|--------|----------------|
| Flow metadata TOCTOU | Atomic creation with descriptor | Medium | 100% |
| Buffer overflow | Input validation + bounds checks | Medium | 95% |
| Flow exhaustion | Quota enforcement per user | Low | 85% |
| Lock contention DoS | Timeout on advisory locks | Low | 60% |

**Implementation Approach**:
- Write flow descriptor to temp directory before rename
- Validate all header fields: grainSize, width, height, format
- Per-user flow quota (e.g., max 1000 flows)
- Add flock timeout via signal handler or timerfd

---

### 7.4 Defense in Depth Recommendations

#### 7.4.1 Deployment Security

**For Containerized Environments**:
```yaml
# Restrict tmpfs sharing
volumes:
  - name: mxl-domain
    emptyDir:
      medium: Memory
      sizeLimit: 10Gi
      # Mount only for authorized containers
containers:
  - volumeMounts:
      - name: mxl-domain
        mountPath: /mxl-domain
        readOnly: false  # Only if writer
```

**For Bare-Metal**:
```bash
# Separate user namespaces
# Enable SELinux/AppArmor with MXL domain policy
semanage fcontext -a -t mxl_tmpfs_t "/mxl-domain(/.*)?"
restorecon -R /mxl-domain
```

#### 7.4.2 Network Security (RDMA)

```
Untrusted Network:
  - Disabled (flows only on localhost)
  
Semi-Trusted Network (same datacenter):
  - RDMA over Ethernet with fabric segmentation
  - IP routing restrictions
  
Trusted Network (isolated RDMA fabric):
  - Full RDMA capability
```

#### 7.4.3 Monitoring & Audit

**Add logging for**:
- Flow creation/deletion (creator UID, timestamp, size)
- Writer attempts on non-owned flows (rejected)
- Fabric connection establishment (endpoint IDs)
- Grain corruption detected (CRC mismatch)

**Implement**:
```cpp
MXL_LOG_WRITER_ATTEMPTED_ACCESS(flow_id, caller_uid, granted);
MXL_LOG_GRAIN_CORRUPTED(flow_id, grain_index, detected_at);
```

---

## 8. Security Testing Recommendations

### 8.1 Proposed Test Cases

1. **Unauthorized Reader Access**
   - Create flow as User A, mode 0664
   - Attempt mmap from User B (different group) → should fail
   - Attempt mmap from User B (same group) → should succeed/detect (audit)

2. **Concurrent Write Race**
   - Two writers on same flow (should fail)
   - Reader while partial grain written (verify memory ordering)

3. **Grain Overflow**
   - Write larger-than-allocated grain → verify bounds check

4. **Flow Exhaustion**
   - Create 10,000 flows → measure tmpfs impact, verify cleanup

5. **RDMA Address Spoofing**
   - Monitor RDMA traffic, inject crafted packets
   - Verify no memory corruption or unintended writes

6. **JSON Bomb**
   - Create 100MB+ flow_def.json → verify parser doesn't OOM

---

## 9. Compliance & Standards

### 9.1 Applicable Standards

- **NIST SP 800-53**: Access Control (AC), Cryptographic Protections (SC)
- **CWE**: CWE-367 (TOCTOU), CWE-416 (Use-After-Free), CWE-362 (Race Condition)
- **OWASP**: A2 Cryptographic Failures, A4 Insecure Design

### 9.2 Recommended Compliance Controls

| Control | Requirement | MXL Status |
|---------|-------------|-----------|
| AC-3 (Access Control) | Enforce least privilege | PARTIAL (file perms only) |
| SC-7 (Cryptography) | Encrypt sensitive data | NOT IMPLEMENTED |
| SI-10 (Information System Monitoring) | Audit access | MINIMAL (no writer audit) |
| SI-12 (Secure Disposal) | Sanitize memory | NOT DOCUMENTED |

---

## 10. Conclusion

MXL provides high-performance, zero-copy media exchange at the cost of simplified security assumptions (trusted environment, trusted peers). For single-organization, controlled deployments, current security is acceptable. For multi-tenant or untrusted network scenarios, significant hardening is required.

### Key Recommendations (Priority Order)

1. **Encrypt grain payloads** (CRITICAL) - Prevent media disclosure
2. **Isolate flows by user/group** (CRITICAL) - Restrict cross-tenant access
3. **Implement memory barriers** (HIGH) - Prevent race condition corruption
4. **Add fabric authentication** (HIGH) - Prevent RDMA spoofing
5. **Validate input** (HIGH) - Prevent buffer overflows
6. **Log write operations** (MEDIUM) - Enable audit trails
7. **Enforce quotas** (MEDIUM) - Prevent DoS exhaustion

### Risk Assessment Summary

| Category | Current Risk | Post-Remediation |
|----------|--------------|------------------|
| Confidentiality | **CRITICAL** | Low |
| Integrity | **HIGH** | Low |
| Availability | **MEDIUM** | Low |
| Auditability | **LOW** | Medium |

---

## Appendix A: File Permissions Analysis

```
Current:  0664 (rw-rw-r--)
├── Owner: read, write
├── Group: read, write  ← RISK: all group members can modify/read
└── Others: read        ← RISK: world-readable media content

Recommended (multi-tenant):
├── Option 1: 0600 (rw-------)  
│   └── Only owner, no group/others sharing
├── Option 2: 0660 (rw-rw----)
│   └── Owner + explicit group, no others
├── Option 3: 0644 + ACL
│   └── Default restrictive, explicit ACL for readers
└── Option 4: Encrypted 0666
    └── World accessible, but encrypted
```

---

## Appendix B: Code Review Checklist

When reviewing MXL for security:

- [ ] All file opens use O_CLOEXEC (prevent child leaks)
- [ ] All mmap'd memory validated before read
- [ ] Path traversal prevented (no .. in flow paths)
- [ ] JSON parser has size/depth limits
- [ ] futex operations checked for timeout
- [ ] Buffer sizes validated before allocation
- [ ] Process UID/GID verified, not just assumed
- [ ] RDMA regions have bounds checking
- [ ] No hardcoded credentials in code
- [ ] Error messages don't leak sensitive info

---

**Report Created**: 2026-06-23  
**Analyst**: Security Threat Modeling Team  
**Repository**: chrisjlapp/mxl  
**Version**: MXL SDK v1.0 alpha
