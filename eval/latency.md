# Added latency

Measured on Windows 10, Python 3.13.2, 16 logical CPUs. Command: `mcp-firewall bench --calls 300`.

## End to end over stdio

300 calls per row after 10 warm-up calls. Direct: client to sample server. Gateway: client to gateway to sample server (rules-only inspection, audit log on).

| Call | Direct p50 | Direct p95 | Through gateway p50 | Through gateway p95 | Added p50 | Added p95 |
| --- | --- | --- | --- | --- | --- | --- |
| files.read_file (report) | 3.02 ms | 3.62 ms | 8.62 ms | 10.34 ms | 5.60 ms | 6.72 ms |
| crm.run_query (aggregate query) | 2.63 ms | 3.18 ms | 3.64 ms | 8.21 ms | 1.01 ms | 5.03 ms |
| crm.run_query (customer rows, redacted) | 2.43 ms | 3.19 ms | 3.77 ms | 11.82 ms | 1.34 ms | 8.64 ms |

## Inside the gateway, over the attack suite

Time from receiving a call to returning it, minus the upstream tool and any wait for approval.

| Inspection | Calls | p50 | p95 |
| --- | --- | --- | --- |
| rules | 184 | 0.42 ms | 1.22 ms |
| rules+classifier | 184 | 224.70 ms | 366.79 ms |
