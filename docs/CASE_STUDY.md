# Case Study: LLM Agent Security Benchmark

## Problem

Tool-using LLM agents can make API calls, browse content, retrieve documents, or trigger business actions. Prompt-only safety rules are not enough when the model can be manipulated by user input or retrieved content.

The project asks a practical engineering question: how do we stop an untrusted model from executing unsafe actions while still letting it complete useful work?

## Solution

The runtime places a policy-enforced tool gateway between the model and every external action. The LLM can suggest a tool call, but the gateway checks allowlists, parameters, data boundaries, approvals, and leakage rules before the action is executed.

A benchmark harness evaluates multiple baselines and turns security regression checks into a CI gate.

## Architecture

- Agent orchestrator receives tasks and proposed tool calls.
- Tool gateway acts as the policy enforcement point.
- OPA policies act as the policy decision point.
- Mock tools and services make tests reproducible.
- Benchmark runner compares guarded and unguarded baselines.
- CI workflow fails when attack success or leakage exceeds thresholds.

## Engineering Choices

- Enforcement is outside the model, which keeps the control boundary reviewable.
- Policy-as-code makes decisions auditable and version-controlled.
- Synthetic canaries test leakage without using real secrets.
- Baseline comparison makes the security benefit measurable.
- Offline tests keep the project reproducible without API keys.

## Security And Reliability Controls

- Tool allowlisting.
- URL and parameter validation.
- Data boundary checks.
- Approval flow for high-risk actions.
- Audit traces with correlation IDs.
- CI security gate using benchmark thresholds.

## Operational Value

The benchmark turns agent-security controls into measurable release criteria. Teams can compare enforcement strategies, inspect policy decisions, and reject changes that increase attack success or data leakage.

## Next Improvements

- Add a minimal web report for benchmark results.
- Add more enterprise workflow scenarios.
- Add policy coverage reports.
- Add a short demo video using synthetic tasks.
