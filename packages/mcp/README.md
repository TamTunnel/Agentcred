# @tamtunnel/agentcred-mcp

AgentCred as an MCP server: `issue_passport`, `verify_passport`, `inspect_passport`, and `revoke` tools.

```bash
npx agentcred-mcp                                     # stdio (default)
AGENTCRED_MCP_TOKEN=secret npx agentcred-mcp --http --port 8787
```

Whoever can reach this process can ask it to sign: run one server per user, on hardware the user controls. The HTTP mode requires `AGENTCRED_MCP_TOKEN` and binds `127.0.0.1` by default.

Keystore passphrase comes from `SI_WALLET_PASSPHRASE`; state dir from `AGENTCRED_STATE_DIR`.
