# TASC

**Trace-Aware Serving Controller**

TASC is an offline inference-policy lab. It searches measured serving policies
on development traces, freezes one nominee, and confirms that exact policy on a
group-disjoint holdout before a human considers production rollout.

The project is deliberately fail-closed: synthetic evidence can demonstrate the
workflow, but it can never produce a production-ready status.

> Standalone project by Rachitt Shah. Detailed usage and architecture arrive in
> later build phases.
