# Raka 🛡️

> **Enterprise-grade security, governance, and reliability middleware for autonomous AI agents.**

---

## 🌟 Overview

**Raka** is an open-source security and reliability layer designed to sit between your AI applications, autonomous agents, and Large Language Models (LLMs) / tools. As AI agents gain the autonomy to execute code, query databases, and call APIs, securing them against prompt injections, data leaks, cascading loops, and hallucinations is mission-critical.

Raka acts as a zero-latency proxy and middleware suite that intercepts inputs, monitors execution states, enforces deterministic guardrails, and sanitizes outputs in real time.

---

## 🚀 Core Features

### 1. Input Security & Threat Mitigation
* **Prompt Injection Defense:** Advanced heuristics and semantic classifiers to detect and neutralize direct and indirect prompt injections.
* **PII & Secret Redaction:** Automatically masks sensitive data (API keys, SSNs, credit cards, proprietary internal metrics) before it reaches third-party LLMs.
* **Jailbreak & Toxicity Filtering:** Blocks adversarial jailbreak attempts and harmful content patterns at the gateway.

### 2. Execution Reliability & Guardrails
* **Infinite Loop & Recursion Breaker:** Detects repeating tool-call cycles or stuck execution paths and forces safe termination or human escalation.
* **Deterministic Schema Enforcement:** Ensures agent outputs or tool arguments strictly match expected JSON schemas or Pydantic models.
* **Fallback & Circuit Breakers:** Gracefully reroutes traffic to backup models or cached safe responses during upstream API outages or rate limits.

### 3. Output Validation & Factuality
* **Hallucination Shield:** Cross-references grounded knowledge bases or vector stores against generated outputs.
* **Brand & Compliance Filters:** Enforces custom corporate compliance rules and negative word lists dynamically.

### 4. Observability & Cost Governance
* **Token & Budget Control:** Set hard financial and token limits per agent session, user, or organization.
* **Distributed Tracing:** Integrates seamlessly with OpenTelemetry to trace every agent thought, reasoning step, prompt, and tool execution.

---

## 🏗️ Architecture Flow

```text
[ User / Application ] 
       │
       ▼
 ┌───────────┐     1. Inspect & Redact      ┌───────────────┐
 │    Raka    ───────────────────────────> │ Input Shield  │
 └───────────┘                              └───────────────┘
       │                                            │
       │ 2. Safe Payload                            ▼
       └──────────────────────────────────> [ LLM / Agent Core ]
                                                    │
                                                    ▼
 ┌───────────┐     4. Final Sanitize        ┌───────────────┐
 │ Response  │ <─────────────────────────── │ Output Guard  │
 └───────────┘                              └───────────────┘