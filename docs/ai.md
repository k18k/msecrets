---
layout: default
title: AI agents
description: Teach AI coding agents to use msecrets without ever seeing a secret.
eyebrow: Agent skill
lead: One command teaches Claude Code, Codex, Cursor, GitHub Copilot, Gemini CLI, and other coding agents how your secrets work, and that they never get to see them.
permalink: /ai/
hero_shell: |-
  npx msecrets skill
  git add .claude/skills .agents/skills
---

## What the agent learns

msecrets ships an [Agent Skill](https://agentskills.io): instructions that coding agents load when a task touches
secrets. Agents that have it:

<div class="cards three">
  <article class="card accent">
    <span class="kicker">Code</span>
    <h3>Use the typed SDK</h3>
    <p>They read secrets through <code>createClient(file)</code> from one module, handle secrets that only some environments have, and treat a type error as a missing secret instead of casting it away.</p>
  </article>
  <article class="card blue">
    <span class="kicker">Hands off</span>
    <h3>Never see a value</h3>
    <p>They never run <code>get</code>, <code>export</code>, or the terminal UI, never ask you to paste a secret, and never edit <code>msecrets.json</code> by hand. They only run <code>ls</code> and <code>check</code>, which need no key.</p>
  </article>
  <article class="card gold">
    <span class="kicker">Guide</span>
    <h3>Tell you what to run</h3>
    <p>When code needs a new secret, they give you the exact <code>msecrets set</code> command for your terminal, and explain joining, access, and deployment when you ask.</p>
  </article>
</div>

They also know how to wire `injectEnv` for libraries that read `process.env`, write tests with fake secrets
instead of real ones, set up a machine key for a deployment, and what each SDK error means.

The rules are instructions, not a sandbox: an agent that can run commands as you can technically run
`msecrets get` with your key. Keep agents that run unattended on machines without your msecrets key.

## Install

### In your project (recommended)

```bash
npx msecrets skill
```

This writes the skill to `.claude/skills/msecrets/SKILL.md` (Claude Code) and `.agents/skills/msecrets/SKILL.md`
(Codex, Cursor, GitHub Copilot, Gemini CLI, and other agents that read `.agents/skills`) at the root of your git
repository. Commit both, and every teammate's agent knows msecrets. The skill comes from the installed
`@msecrets/ui`, so it always matches your version; run `npx msecrets skill` again after upgrading.

### For yourself, in every project

```bash
npx msecrets skill --global       # ~/.claude/skills and ~/.agents/skills
```

### Other ways

```bash
npx skills add k18k/msecrets      # the skills CLI, for many more agents
```

In Claude Code, as a plugin that updates with the repository:

```
/plugin install msecrets --marketplace k18k/msecrets
```

`npx msecrets skill --print` prints the skill, for agents with their own instruction files.

## Working with an agent

You keep the values; the agent writes the code. A typical change:

1. You: "Send error reports to Sentry in staging and production."
2. The agent adds `secrets.SENTRY_DSN` handling to the code (it is `string | undefined` once scoped) and asks you
   to run:

   ```bash
   npx msecrets set SENTRY_DSN --env staging
   npx msecrets set SENTRY_DSN --env production
   npx msecrets scope SENTRY_DSN staging production
   ```

3. You run them in your terminal; the prompt hides what you type. The agent runs `npx msecrets check`, and you
   commit `msecrets.json` with the code.

Values that nobody needs to know, like a random session key, the agent can generate and pipe straight into
`msecrets set` so the value is never printed.

## What is in the skill

The full text is
[`packages/ui/skills/msecrets/SKILL.md`](https://github.com/k18k/msecrets/blob/master/packages/ui/skills/msecrets/SKILL.md).
It is plain Markdown: read it to know exactly what your agents are told.
