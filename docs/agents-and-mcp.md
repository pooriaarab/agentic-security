# Agents and MCP: security review guide

Checked: 2026-10-25. Recheck vendor advisories before every change.
This guide is generic. It is not exhaustive.

Use `agentic-security scan` and `agentic-security audit` for the metadata pass.
See [README.md](../README.md) for their coverage and limits. Audit requires explicit `--online` permission.

## Threat model

1. Use the OWASP Top 10 for Agentic Applications 2026 as the baseline. It names ten risks, ASI01 to ASI10. Published 2025-12-09. Source: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
2. The ten risks: goal hijack, tool misuse, identity and privilege abuse, agentic supply chain, and unexpected code execution.
3. The rest: memory and context poisoning, insecure inter-agent communication, cascading failures, human-agent trust exploitation, and rogue agents.
4. Use the OWASP MCP Security Cheat Sheet for day-to-day checks. Source: https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html

## Prompt injection

5. Treat all content as untrusted. Web pages, emails, tool output, and agent messages can carry instructions.
6. The model cannot reliably separate instructions from data. Design the system for this, not against it.
7. Injected content can redirect the agent goal. This is ASI01, agent goal hijack.
8. Separate instructions from data where possible. Quote data, do not execute it. See OWASP prompt injection guidance: https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html

## Tool identity

9. Review every tool the agent can call. Check the description and the parameter schema.
10. Malicious instructions can hide in tool descriptions. This is tool poisoning.
11. A server can change its tool definitions after approval. This is a rug pull.
12. Pin tool definitions where the client supports it. The MCP cheat sheet calls this schema integrity (best practice 2).
13. Review MCP servers you did not build. See the OWASP third-party MCP server guide: https://genai.owasp.org/download/51928/

## Memory and context

14. Long-term memory can be poisoned. Stored context shapes future actions. This is ASI06.
15. Treat memory as untrusted input. Validate it before use.
16. Do not store secrets in agent memory. Memory is not a secret store.
17. Scrub memory after incidents that may have corrupted it.

## Permissions

18. Grant the least privilege. This is ASI03, identity and privilege abuse.
19. Scope OAuth grants narrowly. Over-scoped tokens are an aggregation risk. The MCP cheat sheet lists this.
20. Use short-lived credentials. Rotate them on a schedule.
21. Give each server its own identity. Do not share a token across servers.

## Untrusted tool data

22. Tool return values can inject instructions. The MCP cheat sheet names this risk (best practice 12).
23. Validate tool output before the agent acts on it.
24. Do not build shell commands from tool output. Pass values as arguments or environment variables.

## Authentication stage proof

25. Prove the auth stage at the moment of action. A cached "logged in" flag is not proof.
26. Verify the session token is still valid before a sensitive call.
27. Use a dedicated browser profile for the approved account. Prove each sign-in stage separately; never copy cookie values into logs.
28. Use OAuth with PKCE for remote MCP servers. The MCP cheat sheet requires authentication, authorization, and transport security (best practice 6).

## User presence

29. Sensitive actions need proof the user is present. ASI09 covers human-agent trust exploitation.
30. Require an interaction for destructive actions. A background agent cannot confirm.
31. Treat a confident explanation as a risk, not a reason. Confused agents can persuade.

## Approval gates

32. Show the exact action in approval prompts. Replace secret values with references that bind approval to the resolved action.
33. The approval must bind to the action that runs. An approval for a different command is not approval.
34. Log redacted arguments, the actor, and the outcome. Keep secret values outside approval records and agent context.
35. Human-in-the-loop is best practice 4 of the MCP cheat sheet.

## Sandbox and credential boundaries

36. Isolate MCP servers. A local server with host access can escape. Sandbox escapes are a listed MCP cheat sheet risk.
37. Keep credentials out of the agent context. Use a scoped credential store.
38. Separate environments by data sensitivity. Do not share one credential across prod and dev.

## Scanner coverage vs manual review

39. Scanner coverage varies. Schema checks and advisory audits do not establish that agent goals remain protected.
40. mcp-scan checks tool schemas and prompts.
    By default, it shares tool names and descriptions with the Invariant API.
    `--local-only` skips that API but still needs an OPENAI_API_KEY.
    Keep that key outside logs and agent context.
    Run a pinned version on a clean runner.
    Source: https://invariantlabs-ai.github.io/docs/mcp-scan/
41. agentic-security-scanner scans projects and MCP setups. Check its license before use. It is PolyForm Internal Use 1.0.0, not MIT. Source: https://www.npmjs.com/package/@clear-capabilities/agentic-security-scanner
42. Manual review covers: tool descriptions, approval flows, memory handling, and identity boundaries.
43. Do not copy third-party scanner code into your own tools. License terms differ.

## Source gaps

44. MCP transport details change. Recheck the cheat sheet before a deployment.
45. The OWASP third-party MCP guide version may change. Confirm the current document.
