---
name: payment-webhook-state-machine-review
description: >
  Reviews payment and billing webhook handlers for state-machine bypass,
  replay, ordering, tenant binding, amount binding, refund abuse, subscription
  drift, and reconciliation gaps. Auto-invoked when reviewing Stripe, PayPal,
  Adyen, Paddle, Lemon Squeezy, Chargebee, Recurly, Shopify billing, or custom
  payment webhooks.
tags: [appsec, payment, webhook, billing, state-machine]
role: [appsec-engineer, security-engineer]
phase: [design, build, review, operate]
frameworks: [OWASP-ASVS, OWASP-API-Security-2023, PCI-DSS-v4.0]
difficulty: intermediate
time_estimate: "45-90min"
version: "1.0.0"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[payment-webhook-handler-or-billing-module]"
---

# Payment Webhook State Machine Review

Payment providers deliver security-critical events asynchronously. A webhook
handler that accepts a valid signature but ignores event ordering, idempotency,
tenant binding, object binding, or business-state invariants can mint credits,
activate unpaid subscriptions, duplicate refunds, or drift away from the
provider's source of truth.

Use this skill to review payment and billing webhook implementations, including
Stripe, PayPal, Adyen, Paddle, Lemon Squeezy, Chargebee, Recurly, Shopify
billing, app-store server notifications, and custom invoice/payment systems.

If a target is provided via arguments, focus the review on: $ARGUMENTS

---

## Step 1: Scope the Payment State Machine

Create an explicit state model before reading individual handlers.

1. Identify payment objects: checkout session, payment intent, charge, invoice,
   refund, dispute, subscription, entitlement, credit balance, order, and user
   account.
2. Record the provider source of truth for each object. A local database row is
   not authoritative when the provider exposes a stronger canonical status.
3. List accepted webhook event types and the local state transitions they drive.
4. Identify irreversible side effects: credit allocation, entitlement unlock,
   shipment, refund issuance, coupon balance changes, downgrade cancellation,
   and ledger posting.
5. Identify replay and retry behavior from the provider. Record delivery
   windows, event IDs, retry backoff, and whether events may arrive out of
   order.

> Gate: Do not approve the handler until every accepted event type maps to an
> allowed local transition and every irreversible side effect has an idempotency
> key.

---

## Step 2: Provider Authenticity and Event Provenance

Validate that the handler authenticates the provider and preserves provenance.

### Required checks

- Verify webhook signatures using the provider's raw request body, not parsed
  or reserialized JSON.
- Reject events outside the provider's timestamp tolerance unless the provider
  explicitly supports delayed verification.
- Select the signing secret or certificate by endpoint/environment, not by
  attacker-controlled request data.
- Reject test-mode events in live environments and live events in test
  environments.
- Persist provider event ID, account ID, environment, event type, object ID,
  API version, signature timestamp, and received timestamp.
- Treat unsigned dashboard replays or manually imported events as separate
  admin workflows with approval and audit evidence.

### Vulnerable pattern

```javascript
app.post('/webhooks/stripe', express.json(), async (req, res) => {
  // VULNERABLE: parsed body prevents reliable signature verification and the
  // code trusts the event payload directly.
  const event = req.body
  await activateSubscription(event.data.object.customer)
  res.sendStatus(200)
})
```

### Safer pattern

```javascript
app.post('/webhooks/stripe', rawBodyMiddleware, async (req, res) => {
  const event = stripe.webhooks.constructEvent(
    req.rawBody,
    req.headers['stripe-signature'],
    endpointSecret,
  )

  await processPaymentEvent({
    provider: 'stripe',
    providerAccountId: event.account ?? primaryAccountId,
    eventId: event.id,
    eventType: event.type,
    objectId: event.data.object.id,
    apiVersion: event.api_version,
    livemode: event.livemode,
    rawEvent: event,
  })
  res.sendStatus(200)
})
```

---

## Step 3: Replay, Idempotency, and Atomicity

Payment providers retry events, operators replay events, and attackers may
resend captured payloads when signature windows are weak. Review the durable
idempotency boundary.

| Check | Evidence to require |
|---|---|
| Event ID uniqueness | Unique database constraint on `(provider, provider_account_id, event_id)` |
| Object transition uniqueness | Ledger or transition table keyed by provider object ID and transition |
| Atomic side effects | Transactional write that records processed event and side effect together |
| Retry behavior | Handler returns safe 2xx only after durable processing or queues with exactly-once semantics |
| Race handling | Concurrent duplicate deliveries cannot create two credits, refunds, or entitlements |

### Vulnerable pattern

```python
def handle_invoice_paid(event):
    invoice = event["data"]["object"]
    user = find_user_by_customer(invoice["customer"])

    # VULNERABLE: duplicate webhook delivery grants credits repeatedly.
    user.credits += int(invoice["metadata"]["credits"])
    user.subscription_status = "active"
    user.save()
```

### Safer pattern

```python
def handle_invoice_paid(event):
    with db.transaction():
        inserted = processed_events.insert_once(
            provider="stripe",
            account_id=event.get("account", "primary"),
            event_id=event["id"],
        )
        if not inserted:
            return

        invoice = provider.fetch_invoice(event["data"]["object"]["id"])
        transition_subscription_from_invoice(invoice)
        ledger.post_once(
            key=f"invoice-paid:{invoice['id']}",
            account_id=bound_account(invoice),
            amount=verified_credit_amount(invoice),
        )
```

---

## Step 4: Ordering and Transition Guards

Do not assume provider events arrive in business order. A secure handler must
support delayed, missing, duplicated, and out-of-order events.

### Required transition rules

- Model each local object as a state machine with allowed transitions.
- Reject or quarantine backwards transitions unless the provider state confirms
  the reversal.
- Fetch provider state for high-impact transitions instead of trusting stale
  event payload fields.
- Require monotonic versioning where available: created timestamp, invoice
  status transition timestamp, subscription period, sequence number, or provider
  object updated time.
- Store ignored events with reason codes so operators can distinguish benign
  duplicates from risky ordering gaps.

### Subscription transition matrix

| Current state | Incoming event | Required provider check | Allowed local result |
|---|---|---|---|
| `trialing` | `invoice.paid` | Invoice paid, amount due satisfied, subscription belongs to tenant | `active` |
| `active` | `invoice.payment_failed` | Latest invoice still open/unpaid and grace policy applies | `past_due` or keep `active` with grace marker |
| `past_due` | `customer.subscription.deleted` | Provider subscription canceled and no later active subscription exists | `canceled` |
| `canceled` | `invoice.paid` for old invoice | Invoice period is not newer than cancellation period | No entitlement reactivation |
| `active` | `charge.refunded` | Refund maps to current order/invoice and no replacement payment exists | Revoke or reduce entitlement according to policy |

### Vulnerable pattern

```ruby
case event.type
when "invoice.paid"
  subscription.update!(status: "active")
when "customer.subscription.deleted"
  subscription.update!(status: "canceled")
end
```

This accepts event arrival order as truth. An old `invoice.paid` replay after a
deletion can reactivate a canceled subscription.

---

## Step 5: Tenant, Account, and Object Binding

A valid webhook from a provider is not automatically valid for the local tenant
or object being modified.

Require evidence for:

- Provider customer ID maps to exactly one local account or tenant.
- Connected-account or marketplace account IDs are bound to the receiving
  endpoint and local merchant.
- Payment intent, invoice, subscription, checkout session, and order IDs are
  cross-checked against local pending records.
- Metadata is treated as a hint, not an authority. Do not trust `user_id`,
  `plan_id`, `credits`, or `tenant_id` from metadata unless it matches a
  server-created pending object.
- Currency, amount, tax, discount, coupon, and line-item IDs match the server
  quote or invoice record before fulfillment.

### High-risk cases

- Multi-tenant SaaS using one provider account for all tenants.
- Marketplace applications using Stripe Connect, PayPal partner accounts, or
  Adyen platforms.
- Checkout sessions where metadata includes a local user ID.
- Manual invoice payment links that can be reused by a different account.
- Subscription upgrades and downgrades with prorations.

---

## Step 6: Refunds, Chargebacks, Disputes, and Negative Balances

Refund and dispute webhooks must be state transitions, not ad hoc balance
updates.

| Event class | Review requirements |
|---|---|
| Refund | Bind to original charge/order; enforce one refund ledger entry per provider refund ID; handle partial refunds |
| Chargeback/dispute | Freeze or revoke disputed entitlements; preserve provider dispute ID and evidence deadline |
| Reversal | Reopen entitlement only after provider confirms dispute won or refund canceled |
| Credit balance | Prevent negative balance overflow, double deduction, and cross-currency mixing |
| Coupon/promo credit | Separate paid credits from promotional credits and define refund priority |

Finding severity is High when a replay or ordering bug can grant paid
entitlements or withdraw/refund value. It is Critical when it enables broad
account credit inflation, marketplace payout diversion, or unauthenticated
payment state changes.

---

## Step 7: Reconciliation and Drift Detection

Webhook handlers are eventually consistent. Require a reconciliation control
for every payment-derived entitlement.

Minimum evidence:

- Scheduled reconciliation compares local invoices/subscriptions/orders against
  provider state.
- Reconciliation covers missed events, handler failures, retries exhausted,
  provider account disconnects, and API-version migration.
- Drift produces an alert, ticket, or quarantine state rather than silently
  mutating entitlements.
- Manual repair paths are audited and require reason, actor, before/after
  state, and provider evidence link.

---

## Step 8: Findings and Output Format

Every finding must include enough evidence for an engineer to reproduce the
state-machine issue.

```markdown
## Payment Webhook State Machine Review Report

**Scope:** [provider, endpoint, modules reviewed]
**Provider(s):** [Stripe / PayPal / Adyen / custom]
**Objects:** [payment_intent, invoice, subscription, refund, dispute]
**Reviewer:** AI Agent -- payment-webhook-state-machine-review v1.0.0

### State Machine Summary

| Local object | Authoritative provider object | States reviewed | High-risk side effects |
|---|---|---|---|
| [subscription] | [provider subscription] | [trialing, active, past_due, canceled] | [entitlement unlock] |

### Findings

#### PAY-WH-001: [Title]
- **Severity:** [Critical|High|Medium|Low|Informational]
- **CWE:** [CWE-345 / CWE-352 / CWE-367 / CWE-841 / CWE-863 / CWE-940]
- **Provider event(s):** [event names]
- **Local state transition:** [from -> to]
- **Location:** [file:line]
- **Evidence:** [code/config/log excerpt]
- **Exploit path:** [replay, reorder, forged metadata, cross-tenant binding, refund double-apply]
- **Business impact:** [credit inflation, entitlement bypass, refund abuse, subscription drift]
- **Required fix:** [specific transaction, constraint, state check, provider fetch, reconciliation]
- **Verification:** [test or replay scenario]

### Required Evidence Tables

| Event | Event ID key | Object ID | Tenant/account binding | Amount/currency binding | Transition guard | Result |
|---|---|---|---|---|---|---|
| [invoice.paid] | [unique constraint] | [invoice id] | [customer -> tenant] | [server quote] | [allowed active transition] | [pass/fail] |

| Test case | Scenario | Expected behavior | Evidence |
|---|---|---|---|
| Replay | Same event delivered twice | One ledger entry and one entitlement change | [test/log] |
| Out-of-order | Old paid event after cancellation | No reactivation | [test/log] |
| Cross-tenant | Event object belongs to another tenant | Rejected/quarantined | [test/log] |
```

---

## Vulnerable Fixtures to Look For

Use these as prompt-level test cases when validating the skill.

1. **Replay credit inflation:** A handler increments `credits += metadata.credits`
   on every `invoice.paid` event and has no processed-event table.
2. **Out-of-order subscription reactivation:** `invoice.paid` always sets
   `status = active` even when a later cancellation exists locally or at the
   provider.
3. **Metadata tenant swap:** A checkout webhook trusts `metadata.user_id` and
   does not compare provider customer ID, checkout session ID, amount, and
   local pending order.

## Benign Fixtures That Should Not Be Flagged

1. **Idempotent ledger:** The handler stores provider event IDs under a unique
   constraint and posts ledger entries with `post_once` inside the same
   transaction.
2. **Provider-confirmed transition:** The handler fetches the latest provider
   subscription before activating entitlement and refuses stale events.
3. **Quarantined mismatch:** The handler rejects or quarantines events when
   amount, currency, connected account, or tenant binding differs from the
   server-created order.

---

## Common False Positives

- A handler acknowledges duplicate events with 2xx after confirming they were
  already processed. That is safe when the first processing was durable.
- A handler processes events asynchronously through a queue. That is safe when
  the queue consumer enforces the same idempotency and transition guards.
- Metadata is safe as a correlation hint when it is compared to a
  server-created order or checkout session and never used as sole authority.
- Local state may temporarily differ from provider state during documented
  retry windows when reconciliation and quarantine controls exist.

## References

- OWASP ASVS 4.0.3: V10, V11, V13
- OWASP API Security Top 10 2023: API1, API4, API6, API8, API10
- PCI DSS v4.0: Requirement 6, Requirement 10
- CWE-345: Insufficient Verification of Data Authenticity
- CWE-367: Time-of-check Time-of-use Race Condition
- CWE-841: Improper Enforcement of Behavioral Workflow
- CWE-863: Incorrect Authorization
- CWE-940: Improper Verification of Source of a Communication Channel
