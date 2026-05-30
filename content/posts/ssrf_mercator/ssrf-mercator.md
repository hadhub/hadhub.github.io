---
title: "CVE-2026-49345 Mercator : SSRF To Conditional RCE"
date: "2026-05-21"
draft: true
author: "hadzah"
tags: ["cve", "web", "open-source", "mercator"]
description: "CVE-2026- Server Side Request Forgery Portscan & Conditional RCE"
---

# SSRF inside Provider feature

For PoC, check my github : https://github.com/hadhub/CVE-2026-49345-Mercator-SSRF
The Advisory : https://github.com/sourcentis/mercator/security/advisories/GHSA-6q97-4q5r-96j6

## Description

The "CVE" tab on the Mercator configuration page exposes a "Test Provider" button.
This button is intended to check that a CVE provider URL answers correctly on its `/api/dbInfo` endpoint.
The value of the `provider` field is passed as is to `curl_init()` and executed by `curl_exec()`.
No validation is applied on the scheme, on the host or on the destination IP address.

An authenticated low-privilege attacker can therefore force the Mercator server to emit arbitrary network requests.
The partial output of the target's response is returned to the page through the redirect flash message.
The resulting primitive enables internal port scanning and out-of-band interaction with unauthenticated internal services.

### Prerequisites

To reach the vulnerable function the attacker needs:

- An authenticated account holding the `configure` permission (id 262 in the seeder).
- This permission is granted by default to the `Admin`, `User` and `Cartographer` roles.
- Only the `Auditor` role lacks this permission.
- The `lowuser` account (User role) is enough to exploit the bug. This proves that the feature is not restricted to administrators.

No other server-side condition is required to trigger the base SSRF.

### Vulnerable fields

The vulnerable field is unique:

- HTTP parameter: `provider`.
- Endpoint: `POST /admin/config/parameters` with `_method=PUT` spoofing.
- Required hidden fields: `active_tab=cve` and `action=test_provider`.

The `provider` value is concatenated with the literal string `/api/dbInfo` then passed to `curl_init`.
The `#` character cancels the concatenation by turning the suffix into a URL fragment.

---

## Workflows

### Attack sequence

The diagram below describes the complete SSRF flow.
The red zone isolates the phase where the Mercator server emits an arbitrary request toward an internal target chosen by the attacker.
The partial response of that target is sent back through the redirect flash message. This forms the exploitable return channel.

{{< mermaid caption="Sequence diagram, full SSRF chain from authenticated request to internal service interaction" >}}
sequenceDiagram
    actor Attacker as Attacker (User role)
    participant Server as Mercator Server
    participant Internal as Internal Service (127.0.0.1, Redis, etc.)

    Note over Attacker,Internal: Phase 1, Attacker authentication

    Attacker->>Server: POST /login (lowuser, Lowuser123!)
    Server-->>Attacker: 302 to /admin (authenticated session)

    Note over Attacker,Internal: Phase 2, CSRF token harvest

    Attacker->>Server: GET /admin/config/parameters?tab=cve
    Server-->>Attacker: HTML form + CSRF token

    Note over Attacker,Internal: Phase 3, SSRF trigger (SOURCE)

    Attacker->>Server: POST /admin/config/parameters<br/>_method=PUT, active_tab=cve, action=test_provider<br/>provider=http://127.0.0.1:6379/path#
    Server->>Server: handleCve('test_provider', $request)<br/>testProvider($provider)

    rect rgba(242, 78, 78, 0.2)
        Note over Server,Internal: Outbound request (SINK)
        Server->>Internal: curl_init($provider . '/api/dbInfo')<br/>curl_exec()
        Internal-->>Server: Response body or connection error
    end

    Note over Attacker,Internal: Phase 4, Information disclosure

    Server-->>Attacker: 302 to /admin/config/parameters?tab=cve<br/>flash message contains target output
    Attacker->>Attacker: Read flash message<br/>(open port, banner, JSON fields)

    Note over Attacker,Internal: Phase 5, Pivot scenarios

    Attacker->>Server: provider=telnet://127.0.0.1:3306#<br/>(port scan)
    Attacker->>Server: provider=gopher://127.0.0.1:6379/_...#<br/>(Redis RCE, conditional)
{{< /mermaid >}}

With this primitive the attacker can:

- Scan internal IP ports by measuring the curl response delay.
- Reach `127.0.0.1` and `localhost`, which often host unauthenticated services.
- Pivot to a service such as Redis or Memcached to escalate to a conditional RCE.

### Application file flow (source to sink)

The diagram below maps the vulnerability across the Mercator code base.
It follows the user input from the route, traverses the `saveConfig` method then `handleCve`, and lands in `testProvider` where the raw string is passed to `curl_init`.

{{< mermaid caption="State diagram, vulnerability path through application files from provider input to curl_exec" >}}
stateDiagram-v2
    direction TB

    state "routes/web.php" as routes
    state "ConfigurationController::saveConfig" as save
    state "ConfigurationController::handleCve" as handleCve
    state "ConfigurationController::testProvider" as testProvider
    state "curl_exec, outbound request" as curl

    note right of routes
        POST /admin/config/parameters
        web.protected middleware (auth + gates)
        gates defines but does not enforce
    end note

    note right of save
        abort_if Gate denies configure
        Admin, User, Cartographer pass
        match tab cve calls handleCve
    end note

    note right of handleCve
        action test_provider
        provider value taken raw
        no URL scheme check
        no host validation
    end note

    note right of testProvider
        curl_init provider concat /api/dbInfo
        suffix bypassable with hash sign
        no scheme allowlist
        no private IP block
    end note

    note right of curl
        curl_exec hits attacker target
        response body returned to flash
        information disclosure channel
    end note

    [*] --> routes : POST /admin/config/parameters
    routes --> save : saveConfig
    save --> handleCve : match tab cve
    handleCve --> testProvider : action test_provider
    testProvider --> curl : curl_init then curl_exec
    curl --> [*] : flash success or error
{{< /mermaid >}}

Initial vulnerable code:

```php
// app/Http/Controllers/Admin/ConfigurationController.php
if ($action === 'test_provider') {
    return $this->testProvider($request->input('provider'));
}

private function testProvider(string $provider): array
{
    $client = curl_init($provider . '/api/dbInfo');
    curl_setopt($client, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($client, CURLOPT_TIMEOUT, 10);
    $response = curl_exec($client);
    curl_close($client);
    // ...
}
```

## First Remediation

Commit `2e6f761a` "fix Server-Side Request Forgery" on the `dev` branch introduces two controls inside `ConfigurationController`.

The first control is `validateProviderUrl()` which filters the URL string:

```php
private function validateProviderUrl(string $url): string
{
    if (preg_match('/[?#@]/', $url)) {
        throw new \InvalidArgumentException('Invalid provider URL.');
    }
    $parsed = parse_url($url);
    if (!$parsed || !in_array($parsed['scheme'] ?? '', ['http', 'https'], true)) {
        throw new \InvalidArgumentException('Invalid provider URL scheme.');
    }
    return $url;
}
```

The second control is `rejectPrivateHost()` which resolves the hostname and rejects private addresses:

```php
private function rejectPrivateHost(string $url): void
{
    $host = parse_url($url, PHP_URL_HOST);
    $ip   = gethostbyname($host);
    if (filter_var($ip, FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        throw new \InvalidArgumentException('Provider host resolves to a private or reserved address.');
    }
}
```

The curl call is also hardened with a protocol restriction:

```php
curl_setopt($client, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
curl_setopt($client, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
```

These two measures effectively close the multi-protocol scan and the RCE chain through `gopher://`.

## Partial bypass identified

The `rejectPrivateHost()` control validates a DNS resolution that differs from the one used by curl.
This divergence leaves two attack paths open.

**Flaw number 1, DNS rebinding**. The address validated by `gethostbyname()` is not the address curl later connects to.
There are two separate resolutions in the code. This forms a time-of-check to time-of-use, race condition (CWE-367).
The attacker supplies a hostname under their control.
That domain is served by a DNS that returns a public address on the first resolution and an internal address on the second.
The control sees the public address and lets the request through.
curl then sees the internal address and connects to it.

**Flaw number 2, A versus AAAA split**. The `gethostbyname()` function only reads the IPv4 `A` record.
The attacker publishes a hostname with an `A` record pointing to a public address.
The same name exposes an `AAAA` record pointing to `::1` or to an internal IPv6 address.
The control only inspects the `A` record and lets the request through.
curl uses `getaddrinfo` which reads the `AAAA` record and connects to the internal IPv6 address.
This flaw does not depend on a timing race. It is deterministic.

After bypass, the residual primitive is an SSRF restricted to HTTP and HTTPS schemes.
The RCE through `gopher://` is closed by the protocol restriction.
HTTP reconnaissance toward the internal network remains possible.

## Adjust Remedies

To structurally close both DNS divergence flaws, here are the minimal fixes:

- Resolve the host only once then pin the validated IP into curl with `curl_setopt($client, CURLOPT_RESOLVE, ["{$host}:{$port}:{$validatedIp}"])`. curl no longer performs a second resolution. There is only one resolution left and it is the one that was validated.
- Replace `gethostbyname()` with `dns_get_record($host, DNS_A | DNS_AAAA)`. Reject the request if any record is a private or reserved address. This closes the A versus AAAA split bypass.
- Use an explicit CIDR blocklist instead of the `filter_var` flags. Include ranges that the flags do not cover: `100.64.0.0/10` for CGNAT, `::1` for IPv6 loopback, `fc00::/7` for ULA and `fe80::/10` for IPv6 link-local. Also include IPv4-mapped IPv6 (`::ffff:0:0/96`) and normalize before the test.
- Explicitly set `CURLOPT_FOLLOWLOCATION` to `false`. This prevents a future change from reintroducing a redirect-based bypass.
- As defense in depth, restrict the provider URL to an allowlist of legitimate provider domains. The feature never needs to reach anything other than the configured provider.

The first two recommendations form the minimal mandatory fix.
They close the race condition (CWE-367) along with the A versus AAAA split bypass.
Thank you to him for the various exchanges we had by email. This application addresses many IT issues from the perspective of managing and understanding a modern and complex infrastructure.

Thank you for reading this article :D


## Demo :

{{< youtube c9ynL2_WzyQ >}}