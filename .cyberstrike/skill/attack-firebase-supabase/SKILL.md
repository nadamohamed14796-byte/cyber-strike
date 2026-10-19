---
name: attack-firebase-supabase
description: "Review Firebase and Supabase client-facing access rules, row-level policies, storage permissions, and tenant boundaries using synthetic fixtures."
category: "cloud-security"
version: "1.0.0"
tags: [firebase, supabase, firestore, storage, postgresql, rls, authorization]
tech_stack: [firebase, firestore, firebase-storage, supabase, postgresql, rest-api]
prerequisites: ["Authorized project or owner-provided staging fixture", "Use synthetic records and test identities"]
---

# Firebase and Supabase Access-Policy Review

## Objective
Check whether client-facing database, storage, and API policies preserve the intended user, tenant, and role boundaries. Public project identifiers or client configuration are not findings by themselves.

## Workflow
1. Identify the actual product, project/environment, database/storage service, authentication provider, and intended data-access model.
2. Review owner-provided rules, SQL migrations, RLS policies, bucket policies, edge functions, and deployment configuration before active tests.
3. Create two controlled identities and synthetic records with distinct owner/tenant markers. Document the expected read/write matrix.
4. Compare anonymous, owner, and other-test-identity access using the same harmless fixture. Verify authoritative state rather than trusting a response echo.
5. Test database reads, inserts, updates, deletes, nested relations, storage objects, signed URLs, and server/edge functions only where those surfaces exist and are authorized.
6. Review policy behavior for missing claims, stale membership, null fields, service-role credentials, and background jobs. Never put service-role keys or private credentials into client code or reports.
7. Confirm each policy boundary with a positive control and a relevant denied control. Stop once a synthetic fixture proves the policy result.

## Service-specific review

### Firebase
- Review Firestore and Realtime Database rules for default-deny behavior, path-specific owner checks, tenant membership, and field-level constraints.
- Review Storage rules separately from database rules; database authorization does not automatically protect file objects.
- Check whether client SDK access and callable/HTTP functions enforce equivalent authorization.
- Treat App Check as an abuse signal, not a replacement for data authorization.

### Supabase
- Review RLS enablement and policies for every exposed table/view, including insert/update WITH CHECK semantics and delete behavior.
- Check views, RPC functions, storage buckets, and edge functions for security-definer or service-role paths.
- Verify tenant/owner claims come from trusted auth context rather than caller-supplied JSON.
- Confirm migrations and grants match the intended production schema.

## Controlled test matrix

| Principal | Synthetic object | Expected result |
|---|---|---|
| Anonymous | Public fixture | Only documented public fields are accessible |
| Owner A | Object A | Access follows the intended policy |
| User B | Object A | Denied unless sharing is explicitly intended |
| Tenant B | Tenant A object | Denied unless cross-tenant sharing is explicitly intended |
| User B | User B object | Positive control succeeds |
| Client SDK | Restricted server function | Server independently checks identity and authorization |

## False positives
- A public project URL or anon/client key is designed to be shipped to clients.
- A table is intentionally public and contains only approved data.
- A service-role credential is present only in a protected server environment and is not exposed.
- A denied request returns a generic response; confirm state and access behavior before classifying.
- A rule looks permissive in isolation but a trusted server layer enforces the policy; verify the full path.

## Evidence and remediation
Record product/service, environment, policy source, principal, tenant, synthetic fixture, operation, expected policy, observed result, positive/negative controls, state before/after, and cleanup. Recommend least-privilege rules, explicit owner/tenant checks, RLS on exposed tables, narrow grants, server-only service credentials, and regression tests for cross-identity access.

## References
- https://firebase.google.com/docs/rules
- https://firebase.google.com/docs/firestore/security/get-started
- https://supabase.com/docs/guides/database/postgres/row-level-security
- https://supabase.com/docs/guides/storage/security/access-control
