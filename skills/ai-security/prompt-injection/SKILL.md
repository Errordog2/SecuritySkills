---
name: prompt-injection
description: >
  Tests LLM applications for prompt injection vulnerabilities per OWASP LLM01:2025.
  Covers direct injection (user input manipulating model behavior) and indirect
  injection (external content containing hidden instructions). Auto-invoked when
  reviewing LLM applications that process external content, build RAG pipelines,
  or accept user input that reaches a language model. Produces a test report with
  categorized findings and defense recommendations.
tags: [ai-security, prompt-injection, llm, testing]
role: [appsec-engineer, security-engineer]
phase: [build, review, operate]
frameworks: [OWASP-LLM01-2025, MITRE-ATLAS]
difficulty: advanced
time_estimate: "30-60min"
version: "1.0.3"
author: unitoneai
license: MIT
allowed-tools: Read, Grep, Glob
injection-hardened: true
argument-hint: "[target-file-or-directory]"
---

# Prompt Injection Vulnerability Assessment

This skill guides a structured security review of LLM-integrated applications for prompt injection vulnerabilities. It is aligned with **OWASP LLM01:2025 (Prompt Injection)** and **MITRE ATLAS AML.T0051 (LLM Prompt Injection)**.

## Prompt Injection Safety Notice

If a target is provided via arguments, focus the review on: $ARGUMENTS

> **This skill is strictly for DEFENSIVE security testing.** It helps development
> and security teams identify prompt injection vulnerabilities in applications they
> own and are authorized to test. All test categories describe **what to look for
> and how to defend against it** — not how to exploit third-party systems.
> Unauthorized testing against systems you do not own or have explicit permission
> to test is unethical and likely illegal. Always obtain proper authorization
> before conducting any security assessment.

## Background

Prompt injection is the most critical vulnerability class in LLM applications (ranked LLM01 by OWASP for 2025). It occurs when an attacker manipulates a language model through crafted input, causing it to deviate from its intended behavior.

The research community distinguishes two fundamental variants:

- **Direct prompt injection** — The attacker's malicious instructions are submitted directly as user input to the application. First systematically studied by Perez & Ribeiro (2022) in "Ignore Previous Prompt: Attack Techniques For Language Models," this class covers cases where user-controlled text is concatenated into the prompt sent to the LLM.

- **Indirect prompt injection** — The attacker plants malicious instructions in external content that the LLM later retrieves and processes. Greshake et al. (2023) formalized this in "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection," demonstrating that poisoned web pages, documents, and emails can hijack LLM behavior when ingested as context.

Simon Willison's prompt injection taxonomy further refines these categories by documenting real-world attack surfaces and defense limitations, providing practical grounding for security assessments.

---

## Step 1: Map the LLM Interaction Surface

Identify every point where user-supplied or externally sourced content reaches the language model. Produce a complete interaction map covering:

1. **User input channels** — Chat interfaces, form fields, API parameters, file uploads, voice input transcriptions, and any other path where a user directly provides text that is included in an LLM prompt.
2. **External content sources** — Web pages fetched by browsing tools, documents loaded into RAG pipelines, email bodies, database records, calendar entries, third-party API responses, and any other data source the LLM reads but the user does not directly control at query time.
3. **System prompt construction** — How the system prompt is assembled, whether it is static or dynamically composed, and whether any user-influenced data (e.g., user profile fields, prior conversation history) is interpolated into it.
4. **Tool and plugin interfaces** — Any tools the LLM can invoke (code execution, web search, file system access, API calls), including what parameters are LLM-controlled and what side effects each tool can produce.
5. **Multi-turn context** — How conversation history is managed, whether prior turns are truncated or summarized, and whether an attacker can influence future context through earlier messages.

**Deliverable:** A table or diagram listing each input surface, its data type, trust level, and whether it flows into the system prompt, user prompt, or tool arguments.

---

### Additional interaction surfaces for durable and transformed context

Include these surfaces in the Step 1 map even when they are not direct chat input:

- **Durable memory and profile stores:** user preferences, team memory, long-term summaries, vector-store memories, learned lessons, workflow registries, and profile fields that can persist attacker-controlled text across sessions.
- **Derived-text sources:** OCR from images/screenshots, speech-to-text transcripts, captions, alt text, generated image descriptions, EXIF/XMP metadata, and document parser side channels that become prompt text after extraction.
- **Transformation and handoff paths:** summaries, routers, tool adapters, report generators, delegated tasks, and subagent handoffs that can turn untrusted data into downstream plans or instructions.

For each surface, record source provenance, trust tier, authority level, persistence horizon, transformation path, and whether it can reach memory recall, delegated-agent instructions, or side-effecting tool arguments.

---

## Step 2: Identify Direct Injection Vectors

For each user input channel identified in Step 1, determine whether an attacker can influence the model's behavior by submitting crafted text. Examine:

- **Prompt concatenation patterns** — Is user input inserted into a prompt template without transformation? Look for string formatting, f-strings, or template literals that embed raw user input alongside system instructions.
- **Instruction boundary weakness** — Is there any delimiter or structural separation between system instructions and user input? If delimiters are used (e.g., triple quotes, XML tags), are they enforceable or can the user simply close the delimiter?
- **Multi-turn injection** — Can an attacker embed instructions in earlier conversation turns that alter the model's behavior in subsequent turns?
- **Parameter injection** — Can user-controlled values (e.g., a "name" field, a search query) that are inserted into prompts carry executable instructions?

**What to look for in code:**
- String concatenation or interpolation with user input going into LLM API calls
- Prompt templates with placeholder variables filled by user data
- Absence of input validation or sanitization before prompt assembly
- Raw inclusion of conversation history without filtering

---

### Direct-injection false-positive guardrails

Do not report a finding solely because a string contains imperative or malicious-looking wording. A valid direct-injection finding needs an authority path: the text must reach a prompt role, policy parser, durable memory, tool argument, or downstream action where it can influence behavior.

Benign examples that should be handled carefully include security training material, regression fixtures, quoted incident evidence, developer docs, shell tutorials, and runbooks. These are risky only when the application promotes the quoted text from data into higher-authority instructions or side-effecting tool calls.

Reviewers should record:

- whether suspicious-looking text is quoted/escaped and intentionally treated as data;
- whether the text can cross from data into system/developer-style instruction context;
- whether it can update durable memory, user/team profiles, learned rules, or workflow registries;
- whether it can influence a side-effecting tool call without deterministic authorization.

---

## Step 3: Identify Indirect Injection Vectors

For each external content source identified in Step 1, determine whether an adversary could plant instructions in that source that the LLM would later follow. Examine:

- **RAG pipeline inputs** — Documents, web pages, or knowledge base entries that are retrieved and inserted into the LLM context. Can an attacker contribute content to these sources?
- **Email and messaging integrations** — If the LLM processes emails or messages, an attacker can send a message containing hidden instructions.
- **Web browsing and scraping** — If the LLM fetches web content, any page it visits could contain injected instructions (including in HTML comments, hidden text, or metadata).
- **Database records** — If user-generated content stored in a database is later retrieved as LLM context, any user who can write to that database is an injection vector.
- **File uploads and document processing** — PDFs, spreadsheets, and other documents can contain text that, when extracted and sent to the LLM, functions as injected instructions.
- **API responses** — Third-party APIs whose responses are fed into the LLM context could be compromised or manipulated.

**What to look for in code:**
- Document loaders, web scrapers, or API clients whose output is inserted into prompts
- RAG retrieval pipelines that do not sanitize or attribute retrieved content
- Absence of content provenance tracking (the LLM cannot distinguish trusted instructions from retrieved content)

---

### Durable and transformed indirect injection surfaces

In addition to ordinary documents, emails, web pages, and API responses, inspect these surfaces:

- **Durable memory and profile persistence:** long-lived memories, preferences, summaries, learned procedures, team context, and vector-store recalls can preserve injected instructions beyond the original session and reintroduce them later.
- **Transformation and authority laundering:** summarizers, routers, tool adapters, report generators, and multi-agent handoffs can transform untrusted data into a "brief," "plan," "developer note," or delegated instruction that downstream components treat as authoritative.
- **Non-text and derived-text ingestion:** OCR, screenshots, video/audio transcripts, captions, alt text, metadata, and generated descriptions can carry adversarial instructions even when the original source is an image, audio file, or document attribute rather than plain text.

**Additional code patterns to inspect:**

- Memory writes or recalls (`save_memory`, `memory.upsert`, `vector_store.add`, `save_context`, `learned_rules`, `workflow_registry`, `user_profile.preferences`) that lack writer identity, source trace, trust tier, TTL, dedupe/conflict handling, or recall-time demotion to data.
- Summaries or handoff messages that lose source provenance or are inserted into system/developer-style roles despite being derived from untrusted tool output.
- Extracted OCR/transcript/metadata text used as prompt context without the same untrusted-data boundaries applied to uploaded documents and web pages.

#### Safe vs. Unsafe Authority Flow

Prompt-injection findings should be based on trust and authority flow, not on the mere presence of suspicious-looking phrases.

| Case | Treat As | Why |
|------|----------|-----|
| Quoted examples in docs, security training, test fixtures, or incident reports remain inside a data-only role and are summarized or rendered without tool authority | Usually benign | The text is intentionally preserved as evidence or training content and is not promoted into policy, system/developer instructions, or side-effecting tool arguments |
| User or retrieved text is stored as a long-lived preference, memory, or learned procedure and later recalled into high-authority context | Finding | The original untrusted instruction can survive sessions, summarization, and context truncation |
| Tool output is summarized and then sent to another agent as a plan, brief, developer message, or execution instruction without inherited provenance | Finding | The transformation launders untrusted data into a higher authority level |
| Imperative text from OCR, transcripts, alt text, captions, or metadata is treated as factual context with no source boundary | Finding when it can influence model behavior or tools | Derived text has the same injection risk as direct document or web content |
| Keyword filters block all occurrences of known attack phrases even inside escaped or quoted training material | False-positive risk | Keyword presence alone does not prove an exploitable authority path |

---

## Step 4: Test Categories

Assess the application against the following documented vulnerability categories. For each category, determine whether the application's architecture makes it susceptible and whether existing defenses mitigate the risk.

### 4.1 Goal Hijacking

The model is redirected from its intended task to an attacker-chosen task. For example, a summarization assistant is tricked into generating spam content instead of a summary. Assess whether the application enforces its intended purpose through structural constraints or relies solely on the system prompt's instructions.

**What to evaluate:**
- Can the model's task be overridden by user input that says "ignore previous instructions and instead..."?
- Does the application validate that the model's output conforms to the expected task?
- Are there structural enforcement mechanisms beyond prompt-level instructions?

### 4.2 Prompt Leaking

The attacker extracts the system prompt, revealing proprietary instructions, business logic, or security-relevant configuration. System prompts often contain information the application developer considers confidential.

**What to evaluate:**
- Does the application rely on system prompt secrecy for any security property?
- Are there output filters that detect and block system prompt content in responses?
- Does the system prompt contain sensitive information (API keys, internal URLs, business rules) that would cause harm if disclosed?

### 4.3 Privilege Escalation

The attacker causes the model to invoke tools or perform actions that should not be available given the user's authorization level. This is especially critical in agentic applications where the LLM has access to tools with side effects.

**What to evaluate:**
- Does the LLM have access to tools or capabilities beyond what is needed for its intended use case?
- Are tool invocations gated by authorization checks independent of the LLM's decision?
- Can the model be instructed to call a tool with parameters the user should not be able to specify?
- Is there separation between the LLM's permissions and the end user's permissions?

### 4.4 Data Exfiltration

The attacker causes the model to include sensitive data in its output or to transmit data to an attacker-controlled destination. This includes rendering markdown images with data-encoded URLs, generating links the user might click, or invoking tools that send data externally.

**What to evaluate:**
- Can the model render markdown images or links (a common exfiltration vector via URL-encoded data)?
- Does the model have access to sensitive data (PII, credentials, internal documents) that could be included in responses?
- Can tool calls be used to send data to arbitrary external endpoints?
- Are outputs filtered for sensitive data patterns?

### 4.5 Jailbreaking

The attacker bypasses the model's safety guidelines or the application's behavioral constraints. While jailbreaking the base model is partly a model-provider concern, application-level jailbreaking (circumventing application-specific rules) is the application developer's responsibility.

**What to evaluate:**
- Does the application add behavioral constraints beyond the base model's safety training?
- Are those constraints enforced only through prompt instructions or also through output validation?
- Does the application handle edge cases where the model might produce disallowed content?

---

### 4.6 Durable Memory Poisoning

The attacker places instructions into memory, preferences, summaries, or learned procedures that are retrieved in a future session and treated as trusted context. This is distinct from ordinary chat history because the instruction can survive context truncation, session resets, summarization, and cross-agent handoff.

**What to evaluate:**
- Who can write each memory type: user, assistant, tool, admin, automated summarizer, or another agent?
- Does every memory record carry provenance, writer identity, source trace, trust tier, timestamp, confidence, TTL/expiry, and review state?
- Is recalled memory injected as untrusted data by default, or can it become system/developer-style instruction?
- Are imperative or tool-control memories quarantined, reviewed, expired, deduplicated safely, or demoted before recall?
- Are there tests proving that remembered preferences, lessons, or summaries cannot authorize future side-effecting tool calls?

### 4.7 Authority Laundering Through Transformations

The attacker-controlled source may not directly reach a privileged prompt. Instead, it is summarized, routed, reformatted, embedded, or handed to another agent, and the derived text is then treated as trusted.

**What to evaluate:**
- Do summaries inherit the lowest trust tier of their source materials?
- Do routers and tool adapters preserve source provenance and authority metadata?
- Can a generated plan, research brief, handoff, or execution note become a higher-authority instruction for another component?
- Are deterministic policy checks required before any component converts untrusted content into instructions for tools or agents?
- Are multi-agent handoffs logged with source IDs, trust tiers, and allowed capability scope?

---

## Step 5: Defense Evaluation

Evaluate which of the following mitigations are implemented and how effectively. Note that no single defense is sufficient; a layered approach is required.

### 5.1 Input Validation and Sanitization

- Is user input validated for expected format, length, and character set before inclusion in prompts?
- Are known injection patterns (e.g., "ignore previous instructions") detected and flagged?
- Is input sanitization applied without relying on an exhaustive blocklist (which is inherently incomplete)?

### 5.2 Privilege Separation

- Does the LLM operate with least-privilege access to tools and data?
- Are sensitive operations handled by separate, constrained components rather than the LLM itself?
- Is there an authorization layer between the LLM and backend systems that enforces the end user's actual permissions?

### 5.3 Human-in-the-Loop

- Are high-impact or irreversible actions (sending emails, modifying data, executing code) gated by human confirmation?
- Is the confirmation prompt designed so the human can meaningfully evaluate the action before approving?
- Are there thresholds for when human review is required vs. when automated execution is permitted?

### 5.4 Output Filtering

- Are model outputs validated against expected formats and content policies before being returned to the user or acted upon?
- Is there detection for sensitive data (PII, credentials, system prompt content) in outputs?
- Are rendered outputs (markdown, HTML) sanitized to prevent exfiltration via image tags or links?

### 5.5 Canary Tokens in System Prompts

- Does the system prompt include canary strings that, if they appear in the model's output, indicate a prompt leaking attempt?
- Is there automated detection and alerting when canary tokens appear in responses?

### 5.6 Instruction Hierarchy

- Does the application use a model or framework that supports instruction hierarchy (system instructions take precedence over user instructions)?
- Is the system prompt structurally separated from user input (e.g., via the API's system message role) rather than concatenated in a single string?
- Are retrieved documents and external content clearly demarcated as data, not instructions?
- Do summaries, memories, OCR/transcript output, and multi-agent handoff messages preserve their original authority tier instead of being reintroduced as developer/system-like instructions?
- Is there a policy that prohibits authority upgrades for untrusted content unless a deterministic, auditable approval path explicitly allows it?

### 5.7 Adaptive Attack Resilience

> **Warning:** Static prompt injection defenses (hardcoded system prompts, simple keyword filtering) are demonstrably insufficient against adaptive attackers. PISmith (Yin et al. 2026) achieved highest attack success rates across 13 benchmarks using RL-optimized adaptive black-box attacks.

- **Continuous red-team evaluation:** Prompt injection defenses must be evaluated continuously, not as a one-time test. Adaptive attackers iteratively refine their payloads against deployed defenses. Schedule recurring red-team assessments using automated adversarial tooling alongside manual expert testing.
- **Agentic benchmark suites:** For applications where LLMs invoke tools or take autonomous actions, standard prompt injection benchmarks are insufficient. Use agentic-specific benchmark suites that test injection in the context of tool use and multi-step workflows:
  - **InjecAgent** -- Tests indirect prompt injection in agentic settings where the LLM processes external content and has tool access.
  - **AgentDojo** -- Evaluates agent robustness against injection attacks across diverse tool-use scenarios with realistic adversarial content.
  - **fabraix/playground** (https://github.com/fabraix/playground) -- Open-source library of AI agent exploit PoCs that can serve as a test harness for validating direct and indirect injection defenses against published attack patterns.

### 5.8 Memory, Transformation, and Derived-Text Controls

- **Memory write controls:** Require explicit authorization, source trace ID, writer identity, trust tier, memory type, TTL, review state, and revocation path before durable memory can influence future prompts.
- **Recall-time demotion:** Inject recalled memories, preferences, and summaries as data unless a separate policy engine upgrades them for a narrowly defined purpose.
- **Dedupe and conflict review:** Near-duplicate or conflicting memories should be staged for review instead of silently replacing safe guidance with newer attacker-influenced text.
- **Provenance preservation:** Summaries, reports, tool adapter outputs, and delegated-agent messages must inherit the lowest trust tier and source IDs of their inputs.
- **Derived-text handling:** OCR, transcript, alt-text, caption, and metadata extraction must label source type, extraction confidence, and trust tier, then apply the same untrusted-data boundaries as document and web ingestion.
- **Regression fixtures:** Include benign quoted attack strings in docs/tests/runbooks and vulnerable fixtures where the same strings are promoted into privileged roles or tool calls, so reviewers can reduce false positives without missing real authority-flow bugs.

---

## Step 6: Report Findings

Compile findings into a structured report using the classification and output format below.

### Findings Classification

Each finding should be assigned a severity based on potential impact:

| Severity | Criteria |
|----------|----------|
| **Critical** | Attacker can exfiltrate sensitive data, escalate privileges to perform unauthorized actions, or fully hijack the application's behavior via external content in a RAG pipeline. Exploitation requires no special access beyond normal application use. |
| **High** | Attacker can reliably override the application's intended behavior, extract the system prompt, or cause the model to invoke unintended tools. Some user interaction may be required. |
| **Medium** | Attacker can partially influence model behavior, extract non-sensitive system prompt fragments, or cause the model to produce off-task output. Exploitation is inconsistent or requires specific conditions. |
| **Low** | Minor deviations from intended behavior with limited security impact. The model can be coaxed into slightly off-topic responses but cannot be made to perform harmful actions. |
| **Informational** | Defense-in-depth recommendations. No demonstrated vulnerability but an identified gap in defensive layering. |

### Output Format

```
## Prompt Injection Assessment Report

### Summary
- Application: [name]
- Assessment date: [date]
- Scope: [what was tested]
- Overall risk: [Critical / High / Medium / Low]

### Interaction Surface Map
[Table from Step 1]

### Authority and Persistence Map
| Source | Trust Tier | Authority Level | Persistence Horizon | Transformation Path | Tool/Side Effect Reachable? |
|--------|------------|-----------------|---------------------|---------------------|-----------------------------|
| [source] | [trusted / untrusted / mixed] | [system / developer / user / data / tool output / memory] | [single turn / session / durable] | [summary, recall, router, handoff, none] | [yes/no] |

### Findings

#### Finding [N]: [Title]
- Category: [Goal Hijacking | Prompt Leaking | Privilege Escalation | Data Exfiltration | Jailbreaking | Durable Memory Poisoning | Authority Laundering]
- Vector: [Direct | Indirect]
- Severity: [Critical | High | Medium | Low | Informational]
- Location: [file path and line numbers, or architectural component]
- Source Provenance: [user input / retrieved document / tool output / OCR / transcript / memory / summary / handoff]
- Authority Transition: [data-to-instruction path, or "none"]
- Persistence Horizon: [single turn / session / durable / unknown]
- Description: [What the vulnerability is and why it matters]
- Evidence: [Code pattern or architectural observation that demonstrates the issue]
- Recommendation: [Specific defensive measure to implement]

### Defense Posture Summary
[Table summarizing which defenses from Step 5 are present, partially present, or absent]

### Recommendations
[Prioritized list of defensive improvements]
```

---

## Framework Reference

| Framework | Identifier | Description |
|-----------|-----------|-------------|
| OWASP Top 10 for LLMs (2025) | LLM01 | Prompt Injection — Direct and indirect manipulation of LLM behavior through crafted input |
| MITRE ATLAS | AML.T0051 | LLM Prompt Injection — Techniques for crafting inputs that cause LLMs to deviate from intended behavior |

---

## Common Pitfalls

1. **Testing only direct injection and ignoring indirect injection.** Indirect injection through RAG pipelines, emails, and fetched web content is often a larger attack surface than direct user input. Applications that ingest external content are exposed to any adversary who can influence that content, which is frequently a much broader set of attackers than those with direct application access.

2. **Relying on prompt instructions as a security boundary.** System prompts that say "never reveal these instructions" or "always refuse harmful requests" are not enforceable security controls. They are behavioral suggestions to a probabilistic model. Security-critical constraints must be enforced through code, not through natural language instructions to the LLM.

3. **Assuming input blocklists are sufficient.** Blocklisting known injection phrases (e.g., "ignore previous instructions") is trivially bypassed through paraphrasing, encoding, or language switching. Input validation should focus on allowlisting expected input formats rather than blocklisting known attacks.

4. **Granting the LLM excessive tool access.** Applications that give the LLM access to powerful tools (file system writes, email sending, database modifications, code execution) without independent authorization checks create high-severity privilege escalation risk. Every tool the LLM can invoke should have its own authorization gate that does not depend on the LLM's judgment.

5. **Failing to treat retrieved content as untrusted.** RAG pipelines often insert retrieved document chunks directly into the prompt with no distinction from system instructions. The LLM cannot inherently distinguish "this is data to reason about" from "this is an instruction to follow." Retrieved content should be explicitly demarcated and, where possible, processed through a model or layer that enforces instruction hierarchy.

6. **Flagging quoted training text without an authority path.** Security lessons, regression tests, runbooks, and incident reports often contain malicious-looking strings. Do not report them solely because they contain imperative words. Report them when the text can be promoted into higher-authority prompt roles, policy parsers, durable memory, or side-effecting tool arguments.

7. **Ignoring durable memory poisoning.** Long-lived user preferences, summaries, vector memories, and learned procedures can preserve untrusted instructions after the original attack context disappears. Memory writes need provenance, trust tier, review state, TTL, conflict handling, and recall-time demotion.

8. **Losing provenance during summaries and handoffs.** Tool output, web pages, retrieved documents, and emails can become dangerous when summarized into plans, briefs, or delegated-agent instructions. Derived content must inherit the source trust tier and must not become a higher-authority instruction without deterministic policy approval.

9. **Overlooking OCR, transcripts, and metadata.** Modern multimodal systems turn images, video, audio, captions, alt text, and metadata into prompt text. These derived text sources must be labeled and bounded as untrusted input, not treated as neutral facts.

---

## References

- OWASP Top 10 for Large Language Model Applications (2025), LLM01: Prompt Injection — https://genai.owasp.org
- MITRE ATLAS, AML.T0051: LLM Prompt Injection — https://atlas.mitre.org
- Perez, F. & Ribeiro, I. (2022). "Ignore Previous Prompt: Attack Techniques For Language Models." arXiv:2211.09527.
- Greshake, K. et al. (2023). "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection." arXiv:2302.12173.
- Willison, S. Prompt Injection taxonomy and ongoing research — https://simonwillison.net
- Yin, X. et al. "PISmith: RL-Optimized Adaptive Black-Box Prompt Injection Attacks" (2026) -- arXiv:2603.13026
- fabraix/playground — Open-source AI agent exploit library for testing injection defenses — https://github.com/fabraix/playground
