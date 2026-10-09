# agentaudit-study

Audit-log integrity mechanisms for LLM agents (research prototype).

| ID | Mechanism |
|----|-----------|
| M0 | plain SQLite log |
| M1 | signed hash chain (Ed25519) |
| M2 | M1 + RFC 3161 timestamp (OpenSSL) |
| M3 | M1 + Merkle transparency log with signed tree heads |
| M4 | M1 + on-chain anchor (Vyper contract; local chain or Base Sepolia) |

## Setup

    pip install -r requirements.txt
    pytest                      # 68 tests; OpenSSL / py-evm tests skip with a reason if missing

Windows: M2 needs `openssl.exe`. Installing Git for Windows is enough (it is found automatically),
or set `OPENSSL_BIN` to the full path.

## Try the agent

    python -m agentaudit.agent.cli --offline --tasks 8     # no network, rule-based stand-in agent
    python -m agentaudit.agent.cli --tasks 3               # live, on Groq's free tier

Live runs need a Groq API key (free from console.groq.com):

    PowerShell:   $env:GROQ_API_KEY = "your-key"
    cmd.exe:      set GROQ_API_KEY=your-key
    macOS/Linux:  export GROQ_API_KEY=your-key

Default model is `openai/gpt-oss-20b`. The client:
- keeps requests and tokens under the free-tier limits (30 req/min, 1K req/day, 8K tokens/min,
  200K tokens/day as listed on Groq's rate-limit page; check your own console, limits change),
- stops at 90% of the daily budget and tells you to rerun later,
- caches every reply in `<out>/llm_cache`, so rerunning the same tasks costs nothing,
- keeps its daily usage in `<out>/groq_budget.json`.

If Groq answers HTTP 400 about an unknown parameter, or tool calls fail, send the message back.
