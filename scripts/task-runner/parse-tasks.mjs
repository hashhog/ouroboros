/**
 * Parse PARITY_GAPS.md into structured task objects.
 *
 * Each task has: id, name, tier, priority, files, steps, prompt, verify.
 * Strikethrough (already-implemented) tasks are skipped.
 */

import { readFile } from "fs/promises";

/**
 * @typedef {Object} Task
 * @property {string} id       - e.g. "1.1", "3.2"
 * @property {string} name     - e.g. "Per-Transaction Sigops Cost Limit"
 * @property {string} tier     - e.g. "Tier 1: Consensus Correctness (High Priority)"
 * @property {string} priority - "High" | "Medium" | "Low"
 * @property {string} files    - affected files
 * @property {string} steps    - step-by-step plan (markdown)
 * @property {string} prompt   - the implementation prompt
 * @property {string} verify   - verification command / instructions
 */

/**
 * Parse all actionable (non-strikethrough) tasks from PARITY_GAPS.md.
 *
 * @param {string} filepath - path to PARITY_GAPS.md
 * @returns {Promise<Task[]>}
 */
export async function parseTasks(filepath) {
  const content = await readFile(filepath, "utf-8");
  const tasks = [];

  // Track current tier heading
  let currentTier = "";
  let currentPriority = "";

  // Split by lines and walk through
  const lines = content.split("\n");
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Detect tier headings: ## Tier N: ...
    const tierMatch = line.match(/^## (Tier \d+:.+)/);
    if (tierMatch) {
      currentTier = tierMatch[1].trim();
      // Extract priority from tier heading
      const prioMatch = currentTier.match(/\((High|Medium|Low) Priority\)/i);
      currentPriority = prioMatch ? prioMatch[1] : "Medium";
      i++;
      continue;
    }

    // Detect task headings: ### N.N Task Name
    const taskMatch = line.match(/^### (\d+\.\d+)\s+(.+)/);
    if (taskMatch) {
      const [, id, name] = taskMatch;

      // Skip strikethrough tasks
      if (name.startsWith("~~")) {
        i++;
        continue;
      }

      // Parse the task body until next ### or ## or ---
      const task = {
        id,
        name: name.trim(),
        tier: currentTier,
        priority: currentPriority,
        files: "",
        steps: "",
        prompt: "",
        verify: "",
      };

      i++;
      i = parseTaskBody(lines, i, task);
      tasks.push(task);
      continue;
    }

    i++;
  }

  return tasks;
}

/**
 * Parse the body of a single task section.
 * Modifies `task` in place and returns the new line index.
 */
function parseTaskBody(lines, start, task) {
  let i = start;
  let section = null; // "gap" | "files" | "steps" | "prompt" | "verify"

  while (i < lines.length) {
    const line = lines[i];

    // Stop at next task or tier heading
    if (line.match(/^###? /)) break;
    // Stop at section divider (but only if not inside a section)
    if (line.match(/^---\s*$/) && section !== "prompt") break;

    // Detect sub-sections
    if (line.match(/^\*\*Files?:\*\*/i)) {
      task.files = line.replace(/^\*\*Files?:\*\*\s*/i, "").trim();
      section = "files";
      i++;
      continue;
    }

    if (line.match(/^\*\*Steps:\*\*/i)) {
      section = "steps";
      i++;
      continue;
    }

    if (line.match(/^\*\*Prompt:\*\*/i)) {
      section = "prompt";
      i++;
      continue;
    }

    if (line.match(/^\*\*Verify:\*\*/i)) {
      task.verify = line.replace(/^\*\*Verify:\*\*\s*/i, "").trim();
      section = "verify";
      i++;
      continue;
    }

    // Accumulate content into current section
    if (section === "steps") {
      task.steps += line + "\n";
    } else if (section === "prompt") {
      // Prompt lines are blockquoted (> prefix) — strip the prefix
      if (line.startsWith(">")) {
        task.prompt += line.replace(/^>\s?/, "") + "\n";
      } else if (line.trim() === "") {
        // Blank line inside prompt block — keep it
        task.prompt += "\n";
      } else {
        // Non-blockquote, non-blank line → prompt section ended
        section = null;
      }
    } else if (section === "verify") {
      // Verify can span multiple lines
      if (line.trim()) {
        task.verify += " " + line.trim();
      }
    }

    i++;
  }

  // Trim accumulated text
  task.steps = task.steps.trim();
  task.prompt = task.prompt.trim();
  task.verify = task.verify.trim();

  return i;
}
