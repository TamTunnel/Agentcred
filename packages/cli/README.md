# @tamtunnel/agentcred-cli

`agentcred` — issuance and inspection CLI for AgentCred passports.

```bash
export SI_WALLET_PASSPHRASE="a-strong-passphrase"
agentcred init
agentcred grant --agent-did <did> --scope purchase --amount-limit 100
agentcred issue --merchant merchant:acme.example.invalid --amount-limit 25 \
  --actions purchase --grant /tmp/grant.jwt --ttl-sec 900
agentcred verify --passport /tmp/passport.json --merchant merchant:acme.example.invalid
agentcred inspect --passport /tmp/passport.json
agentcred revoke --jti <jti> [--ttl-days 366] [--state-dir <dir>]
```

`verify` exits 0 on approval, 1 on decline (reason printed as JSON). State: `AGENTCRED_STATE_DIR` (default `~/.agentcred`).
