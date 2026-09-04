# cloud-incident-entra-id-investigation
Incident response walkthrough and technical analysis for a Microsoft Entra ID Impossible Travel alert.

# Cloud Identity Incident Investigation: Microsoft Entra ID Impossible Travel & Account Takeover

![Focus](https://img.shields.io/badge/Focus-Cloud%20Security%20%26%20Incident%20Response-blue)
![Platform](https://img.shields.io/badge/Platform-Microsoft%20Entra%20ID%20%2F%20M365-0078D4)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)

## Executive Summary

This repository documents a step-by-step SOC incident response investigation into a cloud identity compromise within a Microsoft Entra ID (formerly Azure AD) environment. The incident began with an **Impossible Travel** risk detection for user `m.alderton@thornvale-ins.com` and escalated into unauthorized mailbox access via the Microsoft Graph API and persistent account modification.

The objective of this analysis is to reconstruct the attack timeline, map adversary behaviors to the **MITRE ATT&CK** framework, identify Indicators of Compromise (IoCs), and provide actionable hardening recommendations.

---

## Technical Stack & Frameworks

* **Environment:** Microsoft Entra ID / Exchange Online / Microsoft Graph API
* **Telemetry Sources:** Entra ID Sign-in Logs, Audit Logs, Risk Detections
* **Framework:** MITRE ATT&CK for Enterprise
* **Primary Methodology:** Log Correlation, Anomaly Analysis, Identity Threat Detection & Response (ITDR)

---

## Attack Chain Overview

| Step | Phase / Alert | Key Observation | MITRE ATT&CK Mapping |
| :--- | :--- | :--- | :--- |
| **1** | Unauthorized Access | Single-factor login from Moldova without MFA | **T1078.004** (Valid Accounts: Cloud Accounts) |
| **2** | Anomaly Detection | 18-minute gap between London & Chisinau sessions | **Impossible Travel Anomaly** |
| **3** | Mailbox Enumeration | Programmatic `ListMessages` calls via Graph API | **T1114.002** (Remote Email Collection) |
| **4** | Persistence Attempt | Modification of `otherMails` user profile attribute | **T1098** (Account Manipulation) |
| **5** | Initial Access Mapping | Classification of stolen credential usage | **T1078.004** (Valid Accounts: Cloud Accounts) |
| **6** | Collection Mapping | Classification of remote email reading via API | **T1114.002** (Remote Email Collection) |

---

## Detailed Step-by-Step Investigation

### Step 1: Initial Access & Authentication Gap

* **Scenario Context:** Telemetry indicated an anomalous authentication attempt originating from an unrecognized location.
* **Observed Evidence:** A successful authentication event for `m.alderton@thornvale-ins.com` was logged at `09:02 UTC` from IP address `185.153.0.47` (Chisinau, Moldova).
* **Analyst Interpretation:** The sign-in succeeded using single-factor authentication (password-based) without MFA enforcement. This indicates a gap in Conditional Access policy coverage for this specific authentication path.
* **Finding:** The adversary gained initial access using previously compromised valid cloud credentials.

---

### Step 2: Impossible Travel Anomaly

* **Scenario Context:** Entra ID Protection evaluates geographic velocity between consecutive sign-ins for the same identity.
* **Observed Evidence:** 
  * **Session A:** `08:44 UTC` — London, UK (`89.187.44.62`)
  * **Session B:** `09:02 UTC` — Chisinau, Moldova (`185.153.0.47`)
  * Time delta: **18 minutes**.
* **Analyst Interpretation:** Physical travel between London and Chisinau within 18 minutes is physically impossible. This high-velocity anomaly strongly supports the assessment that the second session was unauthorized.
* **Finding:** Entra ID Protection correctly flagged an *Impossible Travel* high-risk alert.

---

### Step 3: Remote Email Collection via Graph API

* **Scenario Context:** Following successful authentication, audit logs were reviewed to evaluate post-exploitation activity.
* **Observed Evidence:** Audit logs recorded multiple programmatic API calls using the `ListMessages` operation under the Microsoft Graph API service principal.
* **Analyst Interpretation:** Instead of interactive webmail access (OWA), the adversary utilized automated Graph API calls to enumerate and read inbox contents.
* **Finding:** Unauthorized programmatic access and collection of user emails occurred within two minutes of initial access.

---

### Step 4: Persistence Mechanism via Profile Attribute Manipulation

* **Scenario Context:** Directory audit logs were inspected for configuration or identity modifications following the breach.
* **Observed Evidence:** The target user’s profile attribute `otherMails` was updated, adding an external, adversary-controlled email address.
* **Analyst Interpretation:** Modifying recovery or alternative email attributes establishes a potential backdoor mechanism. Depending on tenant recovery settings, this could facilitate unauthorized self-service password resets or persistent account recovery.
* **Finding:** The adversary attempted to establish persistence via directory attribute manipulation.

---

### Step 5: MITRE ATT&CK Mapping — Initial Access

* **Analysis:** The adversary used valid cloud credentials obtained prior to the incident (reportedly via phishing) to log in directly to cloud infrastructure.
* **MITRE ATT&CK Classification:** **T1078.004 — Valid Accounts: Cloud Accounts** (Tactic: *Initial Access*).

---

### Step 6: MITRE ATT&CK Mapping — Collection

* **Analysis:** The adversary programmatically read and enumerated mailbox data remotely using legitimate cloud APIs (`ListMessages`).
* **MITRE ATT&CK Classification:** **T1114.002 — Email Collection: Remote Email Collection** (Tactic: *Collection*).

---

## Indicators of Compromise (IoCs)

| Type | Indicator / Value | Context |
| :--- | :--- | :--- |
| **IPv4** | `185.153.0.47` | Adversary infrastructure (Chisinau, Moldova) |
| **IPv4** | `89.187.44.62` | Legitimate corporate location (London, UK) |
| **Account** | `m.alderton@thornvale-ins.com` | Compromised user identity |
| **API Call** | `ListMessages` (Microsoft Graph) | Unauthorized email enumeration operation |
| **Attribute** | `User.OtherMails` | Targeted attribute for persistence modification |

---

## Remediation & Hardening Recommendations

### Immediate Incident Response
1. **Revoke Sessions:** Force revocation of all active sessions and OAuth refresh tokens for `m.alderton@thornvale-ins.com`.
2. **Reset Credentials:** Enforce an immediate password reset for the compromised account.
3. **Revert Unauthorized Changes:** Remove the unauthorized external address from the `otherMails` attribute and audit all secondary authentication methods.

### Tenant Hardening & Prevention
1. **Enforce Universal CA Policies:** Require Multi-Factor Authentication (MFA) for all users and applications without exceptions.
2. **Disable Legacy Protocols:** Block legacy authentication protocols tenant-wide.
3. **Automated Risk Policies:** Configure Entra ID Protection policies to automatically block or demand password resets upon detection of *High Risk* events like Impossible Travel.

---

## Collaborators & Acknowledgments

This investigation and documentation were completed as a joint effort with **[Gabriela Guerrero (@Mggmes)](https://medium.com/@mggmes)**.

---

## Related Publications

* **Medium Narrative Walkthrough:** [Investigating an Impossible Travel Alert: A SOC Analyst Walkthrough](https://medium.com/@locuaz.lmcf/investigating-an-impossible-travel-alert-a-soc-analyst-walkthrough-425299ec3076)
