## greyproxy benchmark – runs 2/3/4

All latencies in ms. Run 4 = no conversation tracking.

| Scenario | Mode | Run | TTFB p50 | TTFB p95 | Total p50 | Total p95 | Errors | Tput (req/s) |
|---|---|---|---|---|---|---|---|---|
| small | direct | 2 | 0.14 | 0.27 | 0.40 | 0.54 | 0 | 100.0 |
| small | direct | 3 | 0.19 | 0.34 | 0.45 | 0.63 | 0 | 100.0 |
| small | proxy | 2 | 2.68 | 3.42 | 3.50 | 4.28 | 0 | 100.0 |
| small | proxy | 3 | 3.08 | 4.05 | 3.94 | 4.94 | 2 | 99.9 |
| small | proxy | 4 no-conv | 3.08 | 4.27 | 3.93 | 5.16 | 0 | 100.0 |
| medium | direct | 2 | 0.20 | 0.35 | 4.35 | 5.51 | 0 | 100.0 |
| medium | direct | 3 | 0.23 | 0.37 | 4.42 | 5.57 | 0 | 100.0 |
| medium | proxy | 2 | 3.55 | 4.60 | 16.21 | 18.33 | 110 | 96.3 |
| medium | proxy | 3 | 3.64 | 4.51 | 16.38 | 18.74 | 113 | 96.2 |
| medium | proxy | 4 no-conv | 3.51 | 4.44 | 16.10 | 18.20 | 79 | 97.3 |
| large | direct | 2 | 1.44 | 2.10 | 26.18 | 28.95 | 0 | 99.9 |
| large | direct | 3 | 1.40 | 1.93 | 25.95 | 28.92 | 0 | 99.9 |
| large | proxy | 2 | 6.01 | 8.97 | 75.15 | 85.45 | 700 | 76.5 |
| large | proxy | 3 | 5.78 | 8.53 | 75.58 | 85.77 | 665 | 77.7 |
| large | proxy | 4 no-conv | 5.50 | 7.59 | 70.08 | 79.41 | 603 | 79.8 |

**Key takeaways:**
- TTFB overhead is ~2.5-3.5ms constant across payload sizes (proxy processing cost)
- Total latency overhead scales with body size — points to body buffering in the hot path
- Error rates: 0% small, ~3.7% medium, ~20-23% large — all at 100 req/s
- Disabling conversation tracking helped medium errors (-30%) and large latency (-7%) but is not the primary bottleneck
- Large payload errors remain ~20% even without conversation tracking — body copy path is the likely culprit
