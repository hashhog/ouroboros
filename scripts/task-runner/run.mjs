#!/usr/bin/env node
/**
 * Ouroboros Parity Task Runner
 *
 * Automates working through PARITY_GAPS.md tasks by invoking the Claude Agent
 * SDK with a fresh session per task.  Each task gets its own context — no
 * manual /compact or "next task" needed.
 *
 * Usage:
 *   node run.mjs                        # run all tasks sequentially
 *   node run.mjs --dry-run              # show tasks without executing
 *   node run.mjs --list                 # list all tasks
 *   node run.mjs --from=3.1             # start from task 3.1
 *   node run.mjs --task=2.1             # run only task 2.1
 *   node run.mjs --continue-on-failure  # don't stop on first failure
 *   node run.mjs --no-verify            # skip verification step
 *   node run.mjs --model=sonnet         # use a specific model
 *   node run.mjs --effort=high          # set effort level (low/medium/high)
 */

import { query } from "@anthropic-ai/claude-agent-sdk";
import { readFile, writeFile, mkdir } from "fs/promises";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { parseTasks } from "./parse-tasks.mjs";

// ── Paths ──────────────────────────────────────────────────────────────
const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..", "..");
const DEFAULT_TASKS_FILE = join(ROOT, "PARITY_GAPS.md");
const LOG_DIR = join(ROOT, ".parity-task-logs");

// ── CLI argument parsing ───────────────────────────────────────────────
function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    dryRun: false,
    list: false,
    from: null,
    task: null,
    continueOnFailure: false,
    noVerify: false,
    model: undefined,
    effort: "high",
    file: null,
    help: false,
  };

  for (const arg of args) {
    if (arg === "--dry-run") opts.dryRun = true;
    else if (arg === "--list") opts.list = true;
    else if (arg === "--continue-on-failure") opts.continueOnFailure = true;
    else if (arg === "--no-verify") opts.noVerify = true;
    else if (arg === "--help" || arg === "-h") opts.help = true;
    else if (arg.startsWith("--from=")) opts.from = arg.split("=")[1];
    else if (arg.startsWith("--task=")) opts.task = arg.split("=")[1];
    else if (arg.startsWith("--model=")) opts.model = arg.split("=")[1];
    else if (arg.startsWith("--effort=")) opts.effort = arg.split("=")[1];
    else if (arg.startsWith("--file=")) opts.file = arg.split("=")[1];
    else {
      console.error(`Unknown argument: ${arg}`);
      process.exit(1);
    }
  }

  return opts;
}

function printHelp() {
  console.log(`
Ouroboros Parity Task Runner
============================
Automates PARITY_GAPS.md tasks using the Claude Agent SDK.
Each task runs in a fresh session — no manual context clearing needed.

Usage:
  node run.mjs [options]

Options:
  --dry-run              Show tasks and prompts without executing
  --list                 List all tasks with IDs and names
  --from=TASK_ID         Start from a specific task (e.g. --from=3.1)
  --task=TASK_ID         Run only a specific task (e.g. --task=2.1)
  --continue-on-failure  Don't stop when a task fails
  --no-verify            Skip the verification step after each task
  --model=MODEL          Model to use (e.g. sonnet, opus, haiku)
  --effort=LEVEL         Effort level: low, medium, high (default: high)
  -h, --help             Show this help

Examples:
  node run.mjs --list
  node run.mjs --dry-run
  node run.mjs --task=1.1
  node run.mjs --from=3.1 --continue-on-failure
  node run.mjs --model=sonnet --effort=medium
`.trim());
}

// ── Task execution ─────────────────────────────────────────────────────

/**
 * Build the full prompt for a task.
 * Includes the parsed prompt from PARITY_GAPS.md plus context.
 */
function buildPrompt(task, opts) {
  const parts = [
    `You are working on the ouroboros Bitcoin full node project.`,
    ``,
    `## Task ${task.id}: ${task.name}`,
    ``,
    `### Files`,
    task.files,
    ``,
  ];

  if (task.steps) {
    parts.push(`### Steps`, task.steps, ``);
  }

  parts.push(`### Implementation`, task.prompt, ``);

  if (!opts.noVerify && task.verify) {
    parts.push(
      `### Verification`,
      `After making all changes, verify by running:`,
      task.verify,
      ``,
      `If tests fail, fix the issues before finishing.`,
    );
  }

  return parts.join("\n");
}

/**
 * Run a single task via the Claude Agent SDK.
 * Returns { success, result, cost, duration, error }.
 */
async function runTask(task, opts) {
  const prompt = buildPrompt(task, opts);
  const startTime = Date.now();

  console.log(`\n${"═".repeat(70)}`);
  console.log(`  TASK ${task.id}: ${task.name}`);
  console.log(`  Files: ${task.files}`);
  console.log(`  Priority: ${task.priority}`);
  console.log(`${"═".repeat(70)}\n`);

  if (opts.dryRun) {
    console.log("  [DRY RUN] Prompt:\n");
    for (const line of prompt.split("\n")) {
      console.log(`    ${line}`);
    }
    return { success: true, dryRun: true, duration: 0, cost: 0 };
  }

  try {
    /** @type {import("@anthropic-ai/claude-agent-sdk").Options} */
    const sdkOpts = {
      cwd: ROOT,
      allowedTools: [
        "Read",
        "Edit",
        "Write",
        "Bash",
        "Grep",
        "Glob",
        "Agent",
      ],
      effort: opts.effort,
      persistSession: false, // ephemeral — no need to resume
    };

    if (opts.model) {
      sdkOpts.extraArgs = { model: opts.model };
    }

    let resultText = "";
    let totalCost = 0;
    let lastAssistantText = "";

    const conversation = query({ prompt, options: sdkOpts });

    for await (const message of conversation) {
      switch (message.type) {
        case "assistant": {
          // Print assistant text incrementally
          const content = message.message?.content;
          if (Array.isArray(content)) {
            for (const block of content) {
              if (block.type === "text") {
                // Print only the new portion
                const newText = block.text.slice(lastAssistantText.length);
                if (newText) process.stdout.write(newText);
                lastAssistantText = block.text;
              }
            }
          }
          // Reset for next assistant message
          lastAssistantText = "";
          break;
        }

        case "result": {
          resultText = message.result || "";
          totalCost = message.total_cost_usd || 0;
          if (message.is_error) {
            console.error(`\n  [ERROR] ${resultText}`);
            return {
              success: false,
              result: resultText,
              cost: totalCost,
              duration: Date.now() - startTime,
              error: resultText,
            };
          }
          break;
        }
      }
    }

    const duration = Date.now() - startTime;
    return { success: true, result: resultText, cost: totalCost, duration };
  } catch (err) {
    const duration = Date.now() - startTime;
    console.error(`\n  [EXCEPTION] ${err.message}`);
    return {
      success: false,
      result: "",
      cost: 0,
      duration,
      error: err.message,
    };
  }
}

// ── Main ───────────────────────────────────────────────────────────────
async function main() {
  const opts = parseArgs();

  if (opts.help) {
    printHelp();
    return;
  }

  // Parse tasks from the specified file (or default)
  const tasksFile = opts.file ? join(ROOT, opts.file) : DEFAULT_TASKS_FILE;
  const allTasks = await parseTasks(tasksFile);

  if (allTasks.length === 0) {
    console.error(`No tasks found in ${tasksFile}`);
    process.exit(1);
  }

  // --list: just show tasks and exit
  if (opts.list) {
    console.log(`\nFound ${allTasks.length} tasks in PARITY_GAPS.md:\n`);
    for (const t of allTasks) {
      console.log(`  ${t.id.padEnd(5)} [${t.priority.padEnd(6)}] ${t.name}`);
    }
    console.log();
    return;
  }

  // Filter tasks
  let tasks = allTasks;
  if (opts.task) {
    tasks = allTasks.filter((t) => t.id === opts.task);
    if (tasks.length === 0) {
      console.error(
        `Task ${opts.task} not found. Available: ${allTasks.map((t) => t.id).join(", ")}`,
      );
      process.exit(1);
    }
  } else if (opts.from) {
    const idx = allTasks.findIndex((t) => t.id === opts.from);
    if (idx === -1) {
      console.error(
        `Task ${opts.from} not found. Available: ${allTasks.map((t) => t.id).join(", ")}`,
      );
      process.exit(1);
    }
    tasks = allTasks.slice(idx);
  }

  console.log(`\nOuroboros Parity Task Runner`);
  console.log(`${"─".repeat(40)}`);
  console.log(`Tasks:    ${tasks.length} of ${allTasks.length}`);
  console.log(`Dry run:  ${opts.dryRun}`);
  console.log(`Model:    ${opts.model || "(default)"}`);
  console.log(`Effort:   ${opts.effort}`);
  console.log(`Verify:   ${!opts.noVerify}`);
  console.log(`Stop on fail: ${!opts.continueOnFailure}`);

  // Create log directory
  await mkdir(LOG_DIR, { recursive: true });

  // Run each task
  const results = [];
  for (let i = 0; i < tasks.length; i++) {
    const task = tasks[i];

    console.log(`\n  [${i + 1}/${tasks.length}] Starting task ${task.id}...`);

    const result = await runTask(task, opts);
    results.push({ ...task, ...result });

    const elapsed = (result.duration / 1000).toFixed(1);
    const status = result.dryRun ? "DRY" : result.success ? "OK" : "FAIL";
    const costStr = result.cost ? ` ($${result.cost.toFixed(4)})` : "";
    console.log(`\n  [${status}] Task ${task.id} — ${elapsed}s${costStr}`);

    // Write per-task log
    if (!opts.dryRun) {
      const logContent = [
        `Task: ${task.id} ${task.name}`,
        `Status: ${status}`,
        `Elapsed: ${elapsed}s`,
        `Cost: $${(result.cost || 0).toFixed(4)}`,
        ``,
        `--- Prompt ---`,
        buildPrompt(task, opts),
        ``,
        `--- Result ---`,
        result.result || "(no result)",
        result.error ? `\n--- Error ---\n${result.error}` : "",
      ].join("\n");

      await writeFile(join(LOG_DIR, `task-${task.id}.log`), logContent);
    }

    // Stop on failure unless --continue-on-failure
    if (!result.success && !opts.continueOnFailure && !opts.dryRun) {
      console.error(
        `\n  Task ${task.id} failed. Stopping.`,
      );
      console.error(
        `  Use --continue-on-failure to skip, or resume with --from=${task.id}`,
      );
      break;
    }
  }

  // ── Summary ──────────────────────────────────────────────────────────
  console.log(`\n${"═".repeat(70)}`);
  console.log(`  SUMMARY`);
  console.log(`${"═".repeat(70)}`);

  for (const r of results) {
    const status = r.dryRun ? "DRY" : r.success ? " OK" : "ERR";
    const elapsed = ((r.duration || 0) / 1000).toFixed(1);
    const cost = r.cost ? ` $${r.cost.toFixed(4)}` : "";
    console.log(
      `  [${status}] ${r.id.padEnd(5)} ${r.name.padEnd(45)} ${elapsed.padStart(6)}s${cost}`,
    );
  }

  const passed = results.filter((r) => r.success).length;
  const failed = results.filter((r) => !r.success).length;
  const totalCost = results.reduce((s, r) => s + (r.cost || 0), 0);
  const totalTime = results.reduce((s, r) => s + (r.duration || 0), 0);

  console.log(`\n  ${passed} passed, ${failed} failed, ${results.length} total`);
  console.log(`  Total time: ${(totalTime / 1000).toFixed(1)}s`);
  if (totalCost > 0) console.log(`  Total cost: $${totalCost.toFixed(4)}`);

  // Write summary JSON
  await writeFile(
    join(LOG_DIR, "summary.json"),
    JSON.stringify(
      {
        timestamp: new Date().toISOString(),
        tasks: results.map((r) => ({
          id: r.id,
          name: r.name,
          success: r.success,
          dryRun: r.dryRun || false,
          duration_ms: r.duration || 0,
          cost_usd: r.cost || 0,
          error: r.error || null,
        })),
        totals: { passed, failed, total: results.length, cost_usd: totalCost },
      },
      null,
      2,
    ),
  );

  console.log(`\n  Logs saved to: ${LOG_DIR}/`);

  if (failed > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
