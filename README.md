# NRA Network - DNS Optimizer (Pure CLI Edition)

[![CI](https://github.com/novri-ra/NRA-Network/actions/workflows/ci.yml/badge.svg)](https://github.com/novri-ra/NRA-Network/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/novri-ra/NRA-Network)](https://github.com/novri-ra/NRA-Network/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/novri-ra/NRA-Network/total)](https://github.com/novri-ra/NRA-Network/releases/latest)

An ultra-fast, lightweight, pure terminal utility for discovering and applying the absolute fastest DNS servers for your specific network connection.

No bloat, no GUI, no dependencies. Just raw asynchronous PowerShell parallel pinging and automated network stack optimization.

## 📥 Download

**[⬇ Download Latest Release (.zip)](https://github.com/novri-ra/NRA-Network/releases/latest)**

1. Download the `.zip` from the link above.
2. Extract the archive to any folder.
3. Right-click `start_benchmark.bat` → **Run as Administrator**.

## ⚡ Features

- **Ultra-Fast Parallel Benchmark**: Tests 40+ DNS providers concurrently (Anycast, Privacy, AdBlock, Gaming, Regional) in under 5 seconds using `RunspacePools`.
- **Gaming DNS Profile**: Dedicated ECS + low-jitter DNS selection optimized for competitive gaming (CDN/matchmaking routing).
- **Anti-Hijack Detection**: Detects spoofed NXDOMAIN responses to warn you against malicious or ISP-intercepted DNS servers.
- **Dual-Stack IPv4 + IPv6**: Automatically configures both address families with provider-native or fallback Anycast IPv6 resolvers.
- **Deep Compatibility Checks**: Verifies DoH, DoT, ECS (EDNS Client Subnet), and DNSSEC support for every provider.
- **Auto-Rollback Safety Mechanism**: When applying a new DNS, it verifies live connectivity. If resolution fails, it automatically reverts to your previous configuration.
- **TCP Stack & NIC Optimizer**: Applies advanced Windows Registry tuning (DNS Cache TTLs, NetBIOS disable, LLMNR disable, NIC hardware offload tweaks).
- **Auto MTU Tuning**: Binary search algorithm to find the absolute largest non-fragmented packet size and applies it directly to your NIC.
- **Game Server Gateway Ping**: Integrated SEA gaming ping tester (Valorant, CS2, MLBB) with TCPing fallback.
- **Telemetry Export**: Outputs full benchmark details to JSON, CSV, and Markdown.

## 💻 Requirements

- Windows 10 or Windows 11
- Administrator Privileges (Handled automatically by the `.bat` launcher)
- PowerShell 5.1 (Built-in) or PowerShell 7+ (Recommended for best performance)

## 📋 Command-Line Interface

The interactive terminal renders a styled ANSI table with your results and a categorized action menu:

```text
┌──────────────────────────────────────────────────────────────┐
│  GOD-MODE ACTION MENU          Adapter: Ethernet            │
├──────────────────────────────────────────────────────────────┤
│  [ DNS PROFILES ]                                           │
│  1. Apply #1 Fastest DNS Pair (IPv4+IPv6)                   │
│  2. Apply Best Gaming DNS (ECS + Low Jitter)                │
│  3. Apply Best AdBlock DNS Pair                             │
│  4. Apply Best Privacy DNS Pair                             │
│  5. Select Custom Provider from Ranking                     │
├──────────────────────────────────────────────────────────────┤
│  [ NETWORK & LATENCY TUNING ]                               │
│  6. Auto-Detect & Apply Optimal MTU                         │
│  7. Run Windows DNS Cache, TCP & NIC Hardware Tuning        │
│  8. Test Game Server Routing (SEA Latency)                  │
├──────────────────────────────────────────────────────────────┤
│  [ MANAGEMENT & TELEMETRY ]                                 │
│  9.  Restore Previous DNS from Backup                       │
│  10. Reset to Default DHCP (ISP)                            │
│  11. Export Full Telemetry (CSV, JSON, Markdown Report)     │
├──────────────────────────────────────────────────────────────┤
│  0. Exit                                                    │
└──────────────────────────────────────────────────────────────┘
```

## 📜 License

MIT License. See `LICENSE` for more information.
