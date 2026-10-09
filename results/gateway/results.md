# Results (gateway logging, 588 events, 2026-10-07 23:37:37)

Model: openai/gpt-oss-20b. Coverage of real tool calls in the log: 1.0 (294 of 294).

## Detection rate (%), k = 50

| Attack | M0 | M1 | M2 | M3 | M4 |
|---|---|---|---|---|---|
| Edit entry (A1) | 0 | 100 | 100 | 100 | 100 |
| Delete entry (A1) | 0 | 100 | 100 | 100 | 100 |
| Reorder entries (A1) | 0 | 100 | 100 | 100 | 100 |
| Insert forged entry (A1) | 0 | 100 | 100 | 100 | 100 |
| Truncate tail (A1) | 0 | 0 | 67 | 67 | 67 |
| Rewrite tail (A2) | 0 | 0 | 0 | 0 | 0 |
| Fork history (A2) | 0 | 0 | 100 | 100 | 100 |
| Omit event (A3b) | 0 | 0 | 0 | 0 | 0 |
| (false alarms, untouched log) | 0 | 0 | 0 | 0 | 0 |

## Sensitivity to anchor interval k

| k | Window | Mech. | Truncate | Rewrite tail | Fork |
|---|---|---|---|---|---|
| 10 | 8 | M1 | 0 | 0 | 0 |
| 10 | 8 | M2 | 67 | 0 | 100 |
| 10 | 8 | M3 | 67 | 0 | 100 |
| 10 | 8 | M4 | 67 | 0 | 100 |
| 50 | 38 | M1 | 0 | 0 | 0 |
| 50 | 38 | M2 | 67 | 0 | 100 |
| 50 | 38 | M3 | 67 | 0 | 100 |
| 50 | 38 | M4 | 67 | 0 | 100 |
| 100 | 88 | M1 | 0 | 0 | 0 |
| 100 | 88 | M2 | 67 | 0 | 100 |
| 100 | 88 | M3 | 67 | 0 | 100 |
| 100 | 88 | M4 | 67 | 0 | 100 |
| 500 | 88 | M1 | 0 | 0 | 0 |
| 500 | 88 | M2 | 67 | 0 | 100 |
| 500 | 88 | M3 | 67 | 0 | 100 |
| 500 | 88 | M4 | 67 | 0 | 100 |

## Cost, k = 50

| Mech. | Append p50 (ms) | Append p99 (ms) | Anchors | Publish p50 (ms) | Gas/anchor | USD/1k ev. L1 | USD/1k ev. L2 | Max window |
|---|---|---|---|---|---|---|---|---|
| M0 | 4.324 | 11.132 | 0 |  |  | 0.0 | 0.0 | 588 |
| M1 | 10.006 | 24.704 | 0 |  |  | 0.0 | 0.0 | 588 |
| M2 | 13.422 | 134.371 | 11 | 121.542 |  | 0.0 | 0.0 | 49 |
| M3 | 10.25 | 17.057 | 11 | 0.064 |  | 0.0 | 0.0 | 49 |
| M4 | 10.28 | 55.551 | 11 | 44.085 | 74976 | 112.464 | 0.037488 | 49 |

Assumptions: L1 gas 30.0 gwei, L2 gas 0.01 gwei, ETH $2500; execution gas only; L2 data fees not included.
