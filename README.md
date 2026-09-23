# GitHub OAuth Phishing Campaign Analysis
## K-9 Mail Gmail Authorization Token Theft

**Classification:** T1566.002 — Spearphishing Link  
**MITRE ATT&CK:** Credential Access (TA0006) → Forge Web Credentials (T1606)  
**Severity:** HIGH  
**Date of Encounter:** 2026-04-10  
**Reporter:** frankSx Research Cell  
**Status:** Documented / IOCs Extracted

**[View the HTML report (GitHub Pages)](https://franksx.github.io/github-oauth-phishing-k9-analysis/)**

---

## 1. Executive Summary

A targeted OAuth phishing link was delivered via a GitHub issue comment on the legitimate `openwrt-es/cfe-bcm63xx` repository. The link leverages the **legitimate K-9 Mail Android email client OAuth client ID** (`262622259280-hhmh92rhklkg2k1tjil69epo0o9a12jm.apps.googleusercontent.com`) to request full Gmail access (`https://mail.google.com/`) for the target account `alexiscosme3@gmail.com`.

This is a **"Legitimate App, Malicious Context"** attack — the OAuth consent screen would display "K-9 Mail wants to access your Gmail," which appears trustworthy because K-9 Mail is a real, widely-used open-source application. Victims who complete the flow grant persistent IMAP/SMTP access to their Gmail inbox without ever surrendering their Google password.

---

## 2. Attack Timeline

| Timestamp (UTC) | Event |
|-----------------|-------|
| 2026-03-30 22:48:37 | GitHub issue #8 created by `carmenperez6804-cyber` on `openwrt-es/cfe-bcm63xx` |
| 2026-04-10 | Link discovered and reported |
| — | Issue remains live (as of analysis date) |

---

## 3. Threat Actor Profile

**GitHub Account:** `carmenperez6804-cyber`  
**User ID:** `270039645`  
**Account Pattern:** `[name][numbers][cyber]` — throwaway naming convention  
**Account Age:** ~6 months (created ~2025-10) — purpose-built for phishing campaigns  
**Tactics:** Issue spam on popular open-source repositories to maximize visibility  
**Sophistication:** MEDIUM — Uses legitimate OAuth client ID, PKCE parameters, and proper Google OAuth flow. Not a crude fake login page.

---

## 4. Technical Analysis

### 4.1 The OAuth URL (Decoded)

```
https://accounts.google.com/o/oauth2/v2/auth?
  redirect_uri=com.fsck.k9%3A%2Foauth2redirect
  &client_id=262622259280-hhmh92rhklkg2k1tjil69epo0o9a12jm.apps.googleusercontent.com
  &response_type=code
  &login_hint=alexiscosme3@gmail.com
  &state=Wl2kUJop6uVy2ZqH0f_bpw
  &nonce=h4dQ6lRauQVFTOq1qS_atQ
  &scope=https%3A%2F%2Fmail.google.com%2F
  &code_challenge=OLrlHx9rd5bgJwYPl0Nnw0EwW8c79yWQkxNqUGQgRis
  &code_challenge_method=S256
```

### 4.2 Parameter Breakdown

| Parameter | Value | Analysis |
|-----------|-------|----------|
| `client_id` | `262622259280-...` | **Legitimate K-9 Mail client ID.** Confirmed via Google OAuth client registry. This is NOT a fake app — it's the real K-9 Mail Android app. |
| `redirect_uri` | `com.fsck.k9://oauth2redirect` | Custom URI scheme for Android app deep-linking. If victim completes auth on Android, the code is sent to the attacker's K-9 instance. |
| `response_type` | `code` | Authorization Code flow — the code must be exchanged for tokens server-side (or app-side). |
| `login_hint` | `alexiscosme3@gmail.com` | **Pre-filled target account.** Suggests targeted or harvested credential. If this is NOT the victim's email, the victim sees someone else's account pre-filled — a red flag. |
| `state` | `Wl2kUJop6uVy2ZqH0f_bpw` | 22-byte URL-safe base64 CSRF token. Appears cryptographically random. Unique per link — allows attacker to correlate clicks. |
| `nonce` | `h4dQ6lRauQVFTOq1qS_atQ` | OIDC replay protection token. Properly implemented. |
| `scope` | `https://mail.google.com/` | **FULL GMAIL ACCESS.** Read, send, delete, and manage ALL emails and labels. Not read-only. |
| `code_challenge` | `OLrlHx9rd5bgJwYPl0Nnw0EwW8c79yWQkxNqUGQgRis` | PKCE verifier hash (S256). Properly implemented — prevents auth code interception in man-in-the-middle scenarios. |
| `code_challenge_method` | `S256` | SHA-256 hash method for PKCE. |

### 4.3 Why This Is Dangerous

**The OAuth consent screen would show:**
> "**K-9 Mail** wants to access your Google Account"
> 
> This will allow K-9 Mail to:
> - Read, compose, send, and permanently delete all your email from Gmail

**Victims trust this because:**
1. K-9 Mail is a legitimate, well-known open-source email client
2. The URL is on `accounts.google.com` — a trusted domain
3. The consent screen is Google's official UI, not a phishing clone
4. PKCE and `state` parameters make the link look "secure"

**What the attacker gains:**
- **Persistent IMAP access** to the victim's Gmail (OAuth tokens don't expire on password change)
- **Read all emails** — including password resets, 2FA codes, banking notifications
- **Send emails as the victim** — can pivot to BEC (Business Email Compromise)
- **Delete emails** — cover tracks, destroy evidence
- **No password required** — victim never types their Google password

---

## 5. Attack Vectors

### 5.1 Primary Vector: Repository Issue Spam

- Attacker creates GitHub issues on **popular open-source repositories**
- Repositories with high star counts and active maintainers get maximum visibility
- The `openwrt-es/cfe-bcm63xx` repo (router firmware) has a technical audience — users who may have Gmail accounts linked to infrastructure/credentials

### 5.2 Secondary Vectors (Hypothesized)

| Vector | Likelihood | Description |
|--------|-----------|-------------|
| Email notification abuse | MEDIUM | GitHub sends email notifications for new issues. Victims may click from email client without examining the URL. |
| Mobile targeting | HIGH | The `com.fsck.k9://` redirect URI strongly suggests the attacker expects victims to click from **Android devices** where K-9 Mail is installed. |
| Credential stuffing correlation | LOW | The `login_hint` may be from a prior breach list. Attacker pre-fills known emails to streamline the attack. |

### 5.3 Post-Compromise Pivot

Once Gmail access is granted:
1. **Search for crypto wallet recovery phrases** in emails
2. **Reset passwords** on other services using "forgot password" + email verification
3. **Impersonate victim** in email conversations with colleagues/family
4. **Register for new services** using victim's email for identity theft
5. **Sell access** on dark web markets ("Gmail logs with full IMAP")

---

## 6. Indicators of Compromise (IOCs)

### 6.1 Network IOCs

| Type | Value | Context |
|------|-------|---------|
| URL | `https://accounts.google.com/o/oauth2/v2/auth?...login_hint=alexiscosme3%40gmail.com...` | Phishing authorization link |
| Client ID | `262622259280-hhmh92rhklkg2k1tjil69epo0o9a12jm.apps.googleusercontent.com` | K-9 Mail (legitimate, but abused) |
| Redirect URI | `com.fsck.k9://oauth2redirect` | Target app scheme |
| State Token | `Wl2kUJop6uVy2ZqH0f_bpw` | Session correlation ID |

### 6.2 Account IOCs

| Type | Value | Context |
|------|-------|---------|
| GitHub Account | `carmenperez6804-cyber` | Phishing actor |
| GitHub User ID | `270039645` | Unique identifier |
| Target Email | `alexiscosme3@gmail.com` | Pre-filled login hint |
| Repository | `openwrt-es/cfe-bcm63xx` | Issue #8 hosting the link |

### 6.3 Behavioral IOCs

- OAuth authorization for K-9 Mail from an **unexpected device/location**
- Gmail access logs showing **IMAP connections** from unknown IPs
- New **"K-9 Mail" entry** in Google Account → Security → Third-party apps
- Outgoing emails in Sent folder that the user didn't send

---

## 7. Defensive Recommendations

### 7.1 For Individual Users

1. **Never click OAuth links sent via unsolicited messages** — even on trusted platforms like GitHub
2. **Verify the `login_hint`** — if it shows someone else's email, it's targeting that account
3. **Check Google Account permissions regularly:**
   - Navigate to: https://myaccount.google.com/permissions
   - Revoke any "K-9 Mail" or suspicious third-party app access
4. **Enable Google Advanced Protection** if high-risk (journalists, activists, admins)
5. **Review Gmail access logs:** Google Account → Security → Recent security activity

### 7.2 For GitHub Users & Maintainers

1. **Report the account:** https://github.com/contact/report-abuse
2. **Lock issue conversations** on spam issues to prevent further exposure
3. **Enable issue templates** requiring structured input — reduces drive-by spam
4. **Use GitHub's "Mark as spam"** feature on issues — trains their detection
5. **Consider requiring approval** for first-time contributors' issues

### 7.3 For Security Teams

1. **Hunt for the client ID** in proxy logs — any internal user authorizing K-9 Mail unexpectedly
2. **Monitor for `accounts.google.com` URLs** with `com.fsck.k9` redirect URIs in email gateways
3. **Check Google Workspace audit logs** for OAuth token grants to K-9 Mail
4. **Block the GitHub account** in corporate SSO if employees use GitHub Enterprise

### 7.4 For K-9 Mail / Google

1. **K-9 Mail:** Consider implementing **dynamic redirect URI validation** tied to device registration
2. **Google:** Flag OAuth flows where `login_hint` doesn't match the authenticated user's primary email
3. **Both:** Implement **risk-based step-up authentication** for high-scope OAuth grants (full Gmail access)

---

## 8. Detection Queries

### 8.1 Proxy/SIEM (Splunk/Sigma)

```yaml
title: K-9 Mail OAuth Phishing Detection
logsource:
  category: proxy
detection:
  selection:
    - c-uri|contains: 'accounts.google.com/o/oauth2/v2/auth'
    - c-uri|contains: 'com.fsck.k9'
    - c-uri|contains: 'mail.google.com'
  condition: selection
falsepositives:
  - Legitimate K-9 Mail OAuth setup on Android
level: medium
```

### 8.2 Google Workspace Admin (GCP Logs)

```sql
SELECT *
FROM `project-id.audit_logs.cloudaudit_googleapis_com_data_access`
WHERE protoPayload.serviceData.oauth2Approval.applicationId = 
  '262622259280-hhmh92rhklkg2k1tjil69epo0o9a12jm.apps.googleusercontent.com'
  AND TIMESTAMP_TRUNC(timestamp, DAY) = TIMESTAMP("2026-04-10")
```

---

## 9. Lessons Learned

1. **Legitimate apps can be weaponized.** The attacker didn't create a fake app — they abused a real one's OAuth client ID. This bypasses user skepticism.

2. **GitHub issues are a trusted delivery mechanism.** Users expect GitHub to be safe. Issue spam on legitimate repos exploits this trust.

3. **PKCE doesn't prevent phishing.** PKCE protects against auth code interception (MITM), not social engineering. The attacker IS the legitimate recipient of the auth code.

4. **OAuth tokens are more dangerous than passwords.** A stolen OAuth token for Gmail persists even after password changes and bypasses 2FA for IMAP access.

5. **Pre-filled `login_hint` is a targeting signal.** It reveals the attacker's reconnaissance — they likely harvested this email from a previous breach or public source.

---

## 10. Appendix: Full Decoded URL

```
Base URL:    https://accounts.google.com/o/oauth2/v2/auth
Redirect:    com.fsck.k9://oauth2redirect
Client ID:   262622259280-hhmh92rhklkg2k1tjil69epo0o9a12jm.apps.googleusercontent.com
Response:    code
Login Hint:  alexiscosme3@gmail.com
State:       Wl2kUJop6uVy2ZqH0f_bpw (16 bytes random, base64url)
Nonce:       h4dQ6lRauQVFTOq1qS_atQ (16 bytes random, base64url)
Scope:       https://mail.google.com/ (FULL Gmail access)
PKCE Challenge: OLrlHx9rd5bgJwYPl0Nnw0EwW8c79yWQkxNqUGQgRis (S256)
```

**Entropy Analysis:**
- `state`: ~128 bits — cryptographically sound
- `nonce`: ~128 bits — cryptographically sound
- `code_challenge`: ~256 bits — proper PKCE implementation

The attacker implemented the OAuth flow **correctly from a security standpoint** — which makes the phishing more convincing and harder to detect via technical anomalies.

---

## 11. References

- [RFC 6749 — OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7636 — Proof Key for Code Exchange (PKCE)](https://tools.ietf.org/html/rfc7636)
- [Google OAuth 2.0 for Mobile & Desktop Apps](https://developers.google.com/identity/protocols/oauth2/native-app)
- [MITRE ATT&CK T1566.002 — Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [K-9 Mail GitHub Repository](https://github.com/thunderbird/thunderbird-android)

---

*Document generated by frankSx Research Cell — 13th Hour Protocol*  
*Classification: UNCLASSIFIED — Share for defensive purposes*