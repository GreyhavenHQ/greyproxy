---
id: index
title: Greyproxy
sidebar_label: Overview
slug: /greyproxy
---

# Greyproxy

![Greyproxy dashboard](./img/dashboard.png)

Greyproxy is a managed network proxy with a built-in web dashboard, rule engine, and REST API. It wraps powerful multi-protocol tunneling capabilities with an intuitive management layer for controlling and monitoring network traffic.

Greyproxy is the recommended network proxy companion for [Greywall](/greywall), but it can also be used independently in any environment where you need a transparent proxy with live traffic management.

## Features

- **Web Dashboard**: real-time view of proxy traffic, pending requests, rules, and settings, all served from a single binary.
- **Rule Engine**: allow and deny rules with glob pattern matching on container, destination, and port.
- **Pending Requests**: review and approve or deny network requests awaiting a policy decision, interactively or via API.
- **Multi-Protocol Proxy**: HTTP, SOCKS5, and DNS proxies with forwarding chain support.
- **HTTPS Inspection (MITM)**: a built-in CA certificate lets greyproxy transparently decode TLS traffic for inspection, with automatic installation into the OS trust store.
- **LLM Conversation Tracking**: intercept Anthropic, OpenAI, and Gemini API calls and reconstruct them as full conversations with tool calls, subagents, and token counts.
- **Credential Substitution**: inject real API keys at the proxy layer so sandboxed processes never see them directly.
- **Header Redaction**: sensitive headers (Authorization, cookies, API keys, and more) are redacted before transactions are stored.
- **DNS Caching**: built-in DNS resolution and caching with hostname enrichment on requests; the cache is persisted across restarts.
- **Docker Integration (optional)**: resolves source IPs to container names when the Docker or Podman socket is available.
- **REST API and WebSocket**: full HTTP API plus a real-time event stream for companion apps and automation.
- **Single Binary**: web UI, fonts, icons, and assets are all embedded; no separate frontend to deploy.

## Default Ports

| Service       | Port    |
|---------------|---------|
| Dashboard/API | `43080` |
| HTTP Proxy    | `43051` |
| SOCKS5 Proxy  | `43052` |
| DNS Proxy     | `43053` |

The dashboard is available at [http://localhost:43080](http://localhost:43080) once running.

## Relationship with Greywall

Greywall routes all sandboxed network traffic through a SOCKS5 proxy. Greyproxy is the recommended companion that provides:

- A live dashboard showing what traffic greywall is allowing/blocking
- An interactive rule engine to define per-domain policies
- Pending request review, where you can approve or deny traffic in real time

However, **greywall can work with any SOCKS5 proxy**, and **greyproxy can work without greywall** (for example, as a network proxy in containerized environments).

See [Using Greyproxy with Greywall](/greyproxy/using-with-greywall) for integration details.

## Quick Install

```bash
# macOS via Homebrew (registers the launchd agent automatically)
brew tap greyhavenhq/tap
brew install greyproxy

# Or install via greywall (installs greyproxy as a dependency)
greywall setup
```

Prebuilt binaries for macOS (amd64, arm64) and Linux (amd64, arm64) are also published on the [Greyproxy releases page](https://github.com/GreyhavenHQ/greyproxy/releases). See the [Quickstart](/greyproxy/quickstart) for full installation instructions, including building from source.

## Acknowledgments

Greyproxy is a fork of [**GOST** (GO Simple Tunnel)](https://github.com/go-gost/gost) by [ginuerzh](https://github.com/ginuerzh). GOST is an excellent and feature-rich tunnel and proxy toolkit written in Go.

For documentation on the underlying proxy and tunnel capabilities, refer to the [GOST documentation](https://gost.run/en/).

Licensed under the [MIT License](https://github.com/GreyhavenHQ/greyproxy/blob/main/LICENSE).
