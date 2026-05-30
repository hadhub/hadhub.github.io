---
title: "CVE-2026-49344 Mercator : Leak PII via JSON DSL"
date: "2026-05-21"
draft: true
author: "hadzah"
tags: ["cve", "web", "open-source", "mercator"]
description: "CVE-2026- Leak PII via JSON DSL"
---

# PII Extraction via JSON DSL query

For PoC, check my github : https://github.com/hadhub/CVE-2026-49344-Mercator-JSON-DSL

The advisory : https://github.com/sourcentis/mercator/security/advisories/GHSA-q3r8-3h7c-96w3

## Description

Mercator embeds a "Query Engine".
This feature allows users to enter a JSON DSL that describes a query against the application's Eloquent models.
The DSL accepts the keys `from`, `select`, `filters`, `traverse` and `output`.
The engine translates the DSL into an Eloquent query and returns the rows in JSON.

The `QueryController::execute()` method initially performs no access control on the target model.
The engine applies no allowlist on the reachable models.
Any authenticated account can therefore query the `users` table along with any model class declared under `app/Models/`.
The direct consequence is full disclosure of the application's account directory.

### Prerequisites

To reach the vulnerable function the attacker needs:

- An authenticated account in Mercator. Any role is enough.
- In the initial version, the `Auditor` role (read-only) is already sufficient since `execute()` is not protected by any `Gate::denies` call.
- The neighbouring methods `store()` and `massDestroy()` are properly guarded by `query_create` and `queries_delete`.
- The methods `schema()` and `schemaModel()` are also left without any access control.

The attack requires no administrator access and no prior server-side manipulation.

### Vulnerable fields

The DSL accepts several sensitive fields:

- `from`: source model name. No allowlist, only a regex check `/^[a-zA-Z][a-zA-Z0-9_-]*$/`.
- `select` (or `fields`): list of columns projected in the output.
- `filters`: WHERE predicates pushed into SQL. The `like` operator is part of `ALLOWED_OPERATORS`.
- `traverse` and dotted notation in `fields`: enable Eloquent relation traversal.

The `users` table is exposed via `from = "users"`.
The `password` field is `fillable` on `User` so it is accepted as a WHERE predicate.
`isHidden()` is only consulted at output rendering. It is never consulted when building the WHERE clause.

---

## Workflows

### Attack sequence

The diagram below describes the two attack paths against the Query Engine.
The red zone isolates the phase of sensitive data extraction. The flow covers the full account directory through direct projection, then the bcrypt password hash extracted blind via a boolean oracle on `meta.count`.

{{< mermaid caption="Sequence diagram, full disclosure chain from auditor authentication to PII dump and blind hash extraction" >}}
sequenceDiagram
    actor Attacker as Attacker (Auditor or User role)
    participant Server as Mercator Server
    participant Engine as Query Engine (Resolver)
    participant DB as Database

    Note over Attacker,DB: Phase 1, Attacker authentication

    Attacker->>Server: POST /login (audit, Audit123!)
    Server-->>Attacker: 302 to /admin (authenticated session)

    Note over Attacker,DB: Phase 2, CSRF token harvest

    Attacker->>Server: GET /admin/queries
    Server-->>Attacker: HTML page + CSRF token

    Note over Attacker,DB: Phase 3, Direct PII dump (SOURCE)

    Attacker->>Server: POST /admin/queries/execute<br/>{"from":"users","select":["id","login","name","email","granularity"]}
    Server->>Engine: QueryController::execute()<br/>no Gate denies check
    Engine->>DB: SELECT id, login, name, email, granularity FROM users

    rect rgba(242, 78, 78, 0.2)
        Note over Engine,DB: Sensitive data leaves the database (SINK)
        DB-->>Engine: Full account directory rows
        Engine-->>Server: JSON rows
        Server-->>Attacker: HTTP 200, complete account list
    end

    Note over Attacker,DB: Phase 4, Blind bcrypt hash extraction

    loop For each character of the bcrypt hash
        Attacker->>Server: POST /admin/queries/execute<br/>filters: password LIKE '$2y$10$a%'
        Server->>Engine: validateField OK, isHidden ignored
        Engine->>DB: SELECT COUNT(*) FROM users WHERE password LIKE ...
        DB-->>Engine: 0 or N matching rows
        Engine-->>Server: meta.count value
        Server-->>Attacker: HTTP 200, oracle bit
    end

    Note over Attacker,DB: Phase 5, Case-folded hash reconstructed

    Attacker->>Attacker: Reassemble $2y$10$... (case ambiguous due to utf8mb4_ci)
{{< /mermaid >}}

### Application file flow (source to sink)

The diagram below maps the vulnerability across the Mercator code base.
It follows the JSON DSL from the route, traverses `QueryDslValidator` which only checks syntax, passes through `QueryEngineIntrospector` which keeps no allowlist, and lands in `QueryResolver` where the SQL projection and filter on the `users` table are executed.

{{< mermaid caption="State diagram, vulnerability path through application files from DSL input to unrestricted SQL projection" >}}
stateDiagram-v2
    direction TB

    state "routes/web.php" as routes
    state "QueryController::execute" as exec
    state "QueryDslValidator::validate" as validator
    state "QueryEngineIntrospector" as introspector
    state "QueryResolver::execute" as resolver
    state "Database, users table" as db

    note right of routes
        POST /admin/queries/execute
        web.protected middleware (auth + gates)
        gates defines but does not enforce
    end note

    note right of exec
        no abort_if Gate denies query_create
        store and massDestroy are guarded
        execute, schema, schemaModel are not
    end note

    note right of validator
        from validated by regex only
        no model allowlist
        like operator accepted in filters
    end note

    note right of introspector
        listModelClasses uses glob app Models
        every concrete model is reachable
        User model is a valid target
    end note

    note right of resolver
        applyWhereOnBuilder calls validateField
        isHidden never consulted in WHERE
        password column accepted as predicate
    end note

    note right of db
        SELECT on users table executed
        full account directory returned
        blind LIKE on password column
    end note

    [*] --> routes : POST /admin/queries/execute
    routes --> exec : execute Request
    exec --> validator : validate DSL JSON
    validator --> introspector : resolve model from slug
    introspector --> resolver : forward to resolver
    resolver --> db : SELECT plus optional WHERE
    db --> [*] : JSON rows and meta count
{{< /mermaid >}}

Initial vulnerable code:

```php
// app/Http/Controllers/QueryController.php
public function execute(Request $request): JsonResponse
{
    $dsl = QueryDslValidator::validate($request->all());
    $result = $this->resolver->execute($dsl);
    // ...
}
```

To be compared with the neighbouring methods that are properly guarded:

```php
public function store(StoreSavedQueryRequest $request) {
    abort_if(Gate::denies('query_create'), Response::HTTP_FORBIDDEN, '403 Forbidden');
}
public function massDestroy(MassDestroySavedQueryRequest $request) {
    abort_if(Gate::denies('queries_delete'), Response::HTTP_FORBIDDEN, '403 Forbidden');
}
```

## First Remediation

Commit `43224e2f` "fix Missing Access Control in queries" brings two changes on the `dev` branch.

First, the `Gate::denies('query_create')` call is added at the top of `execute()`, `schema()` and `schemaModel()`:

```php
public function execute(Request $request): JsonResponse
{
    abort_if(Gate::denies('query_create'), Response::HTTP_FORBIDDEN, '403 Forbidden');
    $dsl = QueryDslValidator::validate($request->all());
    $result = $this->resolver->execute($dsl);
    // ...
}
```

The `Auditor` role is now blocked since it does not hold the `query_create` permission.

Second, a model blocklist is introduced inside the introspector:

```php
// app/Services/QueryEngine/QueryEngineIntrospector.php:12
private const EXCLUDED_MODELS = ['User', 'PasswordReset'];
```

This constant is consulted inside `listModelClasses()`:

```php
// QueryEngineIntrospector.php:199
if (in_array($modelName, self::EXCLUDED_MODELS)) {
    continue;
}
```

The request `from:"users"` is now properly rejected with a 404 status code.

## Partial bypass identified

The fix is incomplete on two aspects.

**The blocklist only covers one resolution path**. The `EXCLUDED_MODELS` constant is only consulted by `listModelClasses()`. This method only feeds the schema list and `apiNameToModelName()`. That is why `from:"users"` is properly rejected.

However, the relation traversal path never consults the blocklist.
The methods `resolveRelationMethod()` (line 95) and `resolveModelClassFromAny()` (line 20) resolve and instantiate the related models with no check.
On the resolver side, `resolveRelationPath()` (QueryResolver.php:116) and `expandRow()` (QueryResolver.php:364) behave the same way.

**The Role model exposes a direct relation to User**. In `app/Models/Role.php:56`:

```php
public function users(): BelongsToMany
{
    return $this->belongsToMany(User::class);
}
```

The attacker requests `from:"roles"` which is allowed.
The attacker adds a field pointing to the `users` relation, for example `users.login`.
The traversal resolves the relation, instantiates every linked `User` and projects the requested columns.
The supposedly unreachable `User` model is now reached through a neighbouring model that is not excluded.

Example request that bypasses the blocklist:

```bash
curl -s -b $CJ -X POST "$BASE/admin/queries/execute" -H "X-CSRF-TOKEN: $T" \
     -H "Content-Type: application/json" -H "X-Requested-With: XMLHttpRequest" \
     -d '{"from":"roles","fields":["title","users.id","users.login","users.email","users.name","users.granularity"],"output":"list","limit":1000}'
```

HTTP 200 response observed on the `dev` lab. It contains the `login` and `email` of every account:

```json
{"columns":["title","users.id","users.login","users.email","users.name","users.granularity"],
 "rows":[{"title":"Admin","users.login":"admin@admin.com","users.email":"admin@admin.com"},
         {"title":"User","users.login":"lowuser","users.email":"lowuser@lowuser.lowuser"},
         {"title":"Auditor","users.login":"audit"},
         {"title":"Cartographer","users.login":"carto"}],
 "meta":{"output":"list","from":"roles","count":4}}
```

Other relations enable the pivot: `Permission::users()`, `AuditLog::user()`, `ApplicationEvent::user()`, `SavedQuery::user()`.
The `AdminUser` model is not even part of the blocklist.

**The residual impact is still significant**. The fix raised the minimum required privilege. A read-only `Auditor` role no longer suffices. The `query_create` permission is now required. But a plain `User` account still recovers the complete account directory. This is personal data covered by the GDPR. The same account also reads the entire CMDB. This bypasses the row-level access model based on `granularity`.

## Adjust Remedies

To structurally close the relation pivot, here are the recommendations:

- Replace the blocklist with a positive allowlist of queryable models. The allowlist must be applied to every point that produces a model class: `resolveModelClass()` for both the `from` slug branch and the FQCN branch, `resolveModelClassFromAny()`, and `resolveRelationMethod()`. Authentication and administration models must not be queryable. They should be unreachable as a `from` target and as a relation target. The list to exclude covers `User`, `PasswordReset`, `AdminUser`, `Role` and `Permission`.
- Reject any traversal that lands on a model outside the allowlist. The check must be applied inside `resolveRelationPath()`, `expandRow()` and `traverseNode()`. If the related class is not allowed, the branch must be dropped.
- Apply `isHidden()` on filters as well. A column hidden on output must not be usable as a predicate inside `applyWhereOnBuilder()`. This measure closes the blind bcrypt hash extraction via `password LIKE`.
- Apply the row-level access model based on `granularity` to the engine output. The engine must respect the same access rules as the rest of the application.
- As defense in depth, store password hashes in a column with a case-sensitive collation (suffix `_bin`). This measure prevents a SQL `LIKE` from acting as a binary oracle on the hash.

The first two recommendations form the minimal fix.
They close the relation pivot that restores the full account directory disclosure.
Thank you to him for the various exchanges we had by email. This application addresses many IT issues from the perspective of managing and understanding a modern and complex infrastructure.

## Demo :

{{< youtube DIizKts6iAo >}}

Thank you for reading this article :D