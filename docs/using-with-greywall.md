---
id: using-with-greywall
title: Using with Greywall
---

# Using Greyproxy with Greywall

Greywall and Greyproxy are two independent products that work especially well together.

## How They Fit Together

[Greywall](../greywall) sandboxes commands by blocking direct network access and routing all traffic through a SOCKS5 proxy. [Greyproxy](/greyproxy) provides that SOCKS5 proxy, plus a live dashboard and rule engine for managing what traffic is allowed.

```
Your command → Greywall sandbox → Greyproxy SOCKS5 → Internet
                                        ↕
                                  Dashboard (port 43080)
                                  Rule engine
                                  Request review
```

## Quickest Setup

Install both with a single command:

```bash
# macOS (Homebrew)
brew tap greyhavenhq/tap
brew install greywall   # installs greyproxy as a dependency

# Or install greywall, then set up greyproxy
greywall setup
```

## Default Integration

By default, greywall routes traffic to greyproxy's SOCKS5 port at `localhost:43052` and DNS at `localhost:43053`:

```json
{
  "network": {
    "proxyUrl": "socks5://localhost:43052",
    "dnsAddr": "localhost:43053"
  }
}
```

These are greywall's defaults, so no configuration is needed if greyproxy is running on default ports.

## Using a Different SOCKS5 Proxy

Greywall is not locked to greyproxy. You can point it at any SOCKS5 proxy:

```bash
# Use a custom proxy via CLI flag
greywall --proxy socks5://localhost:1080 -- npm install

# Or via config file
```

```json
{
  "network": {
    "proxyUrl": "socks5://my-proxy.example.com:1080"
  }
}
```

## Using Greyproxy Without Greywall

Greyproxy can also be used as a standalone proxy in environments where greywall's filesystem sandboxing is not needed. For example:

- **Containerized environments**: containers already provide process and filesystem isolation; adding greyproxy gives you network visibility and control
- **Development environments**: use greyproxy's dashboard to monitor and understand traffic patterns
- **CI environments**: route build traffic through greyproxy for auditing and egress control

Simply point any tool that supports HTTP or SOCKS5 proxies at `localhost:43051` (HTTP) or `localhost:43052` (SOCKS5).

## Workflow: Building Your Allow List

A common workflow when introducing greywall + greyproxy to a new project:

1. **Start greyproxy** (`greywall setup` or `greyproxy serve`)
2. **Run your command with monitor mode**: `greywall -m -- npm install`
3. **Watch the dashboard** at `http://localhost:43080`, where pending and blocked requests appear
4. **Approve the destinations** you want to allow in the dashboard's Pending Requests view
5. **Run again**, and approved destinations now pass through automatically

This iterative approach lets you build a minimal, precise allow list rather than guessing upfront.

## Session-Scoped Network Rules

When greywall starts a sandboxed command with a profile, it pushes the profile's network rules to greyproxy as part of session creation. These rules:

- Are scoped to the container greywall is sandboxing (they never match traffic from a different container).
- Live for the duration of the session and are auto-deleted when the session ends, expires, or is superseded.
- Show up in the dashboard tagged with the **session** source so you can tell them apart from rules you created by hand.

If you start a second greywall command for the same container, the new session's rules replace the old session's rules immediately, even if the old session is still technically alive. To run a command without inheriting any profile-sourced rules, pass `--no-network-rules` to greywall: the new session is created with an empty rule set, and the previous session's rules stop matching the moment that new session is registered.

Global rules you created in the dashboard always take priority over session rules, so an organizational deny list is never overridden by a profile.

## Credential Substitution

When a sandboxed process needs API keys (for example an AI coding tool running under greywall), you usually do not want the real credentials to land in the sandbox environment. Greyproxy and greywall can cooperate to hide them: greywall registers placeholder tokens with greyproxy at session creation, and greyproxy injects the real values into outgoing requests at the MITM layer. The sandboxed process only ever sees opaque placeholders.

Global credentials stored in the greyproxy dashboard can be injected explicitly with `greywall --inject`:

```bash
greywall --inject ANTHROPIC_API_KEY -- opencode
```

See [Credential Substitution](./credentials) for the full flow and API.

## Check Status

```bash
# Check greywall dependencies including greyproxy status
greywall check
```
