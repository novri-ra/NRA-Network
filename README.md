# NRA Network - DNS Optimizer (Pure CLI Edition)

An ultra-fast, lightweight, pure terminal utility for discovering and applying the absolute fastest DNS servers for your specific network connection.

No bloat, no GUI, no dependencies. Just raw asynchronous PowerShell parallel pinging and automated network stack optimization.

## ⚡ Features

- **Ultra-Fast Parallel Benchmark**: Tests 29+ DNS providers concurrently (Anycast, Privacy, AdBlock, Regional) in under 3 seconds using `RunspacePools`.
- **Anti-Hijack Detection**: Detects spoofed NXDOMAIN responses to warn you against malicious or ISP-intercepted DNS servers.
- **Deep Compatibility Checks**: Verifies DoH, DoT, ECS (EDNS Client Subnet), and DNSSEC support for every provider.
- **Auto-Rollback Safety Mechanism**: When applying a new DNS, it verifies live connectivity. If resolution fails, it automatically reverts to your previous configuration.
- **TCP Stack & NIC Optimizer**: Applies advanced Windows Registry tuning (DNS Cache TTLs, NetBIOS disable, LLMNR disable, NIC hardware offload tweaks).
- **Auto MTU Tuning**: Binary search algorithm to find the absolute largest non-fragmented packet size and applies it directly to your NIC.
- **Game Server Gateway Ping**: Integrated SEA gaming ping tester (Valorant, CS2, MLBB) with TCPing fallback.
- **Telemetry Export**: Outputs full benchmark details to JSON, CSV, and Markdown.

## 🚀 Quickstart

1. Download or `git clone` this repository.
2. Double-click `start_benchmark.bat`.
3. It will automatically elevate to Administrator, bypass Execution Policy restrictions safely, and launch the terminal UI.

## 💻 Requirements

- Windows 10 or Windows 11
- Administrator Privileges (Handled automatically by the `.bat` launcher)
- PowerShell 5.1 (Built-in) or PowerShell 7+ (Recommended for best performance)

## 📋 Command-Line Interface

The interactive terminal renders a styled ANSI table with your results and a fast 1-11 menu:

```text
┌──────────────────────────────────────────────────────────────┐
│  GOD-MODE ACTION MENU          Adapter: Ethernet             │
├──────────────────────────────────────────────────────────────┤
│  1. Apply #1 Fastest DNS Pair (IPv4+IPv6)                    │
│  2. Apply Best AdBlock DNS Pair                              │
│  3. Apply Best Privacy DNS Pair                              │
│  4. Select custom provider from ranking                      │
│  5. Restore Previous DNS from Backup                         │
│  6. Reset to Default DHCP (ISP)                              │
│  7. Run Windows DNS Cache & TCP Latency Tuning               │
│  8. Export Full Telemetry (CSV, JSON, Markdown Report)       │
│  10 Test Game Server Routing (SEA Latency)                   │
│  11 Auto-Detect & Apply Optimal MTU                          │
│  9. Exit                                                     │
└──────────────────────────────────────────────────────────────┘
```

## 📜 License

MIT License. See `LICENSE` for more information.
