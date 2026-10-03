# Use dots with a clear completion contract

Start in native dots Activity. In the desktop app, open your dot's profile → Activity → the task. It shows progress, files, results and requests for input. A request may need a decision, app connection, sign-in or approval before work continues. [Official controls](https://learn.chatgpt.com/docs/dots/controls).

## Give one outcome and the evidence that closes it

Use a short brief such as:

> Prepare a local synthetic decision-review demo. Complete means I can run it, inspect a decision and its evidence, and see the tested limitations. Use only the task-owned folder. Do not publish, contact anyone, import private state, or change permissions. Return the artifact path, run steps, real test results, blockers and decisions needing me.

That is a suggested working method, not a product feature. Ask for evidence of the visible result, not just a message that a process completed. The official docs explicitly advise reviewing output and errors because a completed run does not establish that the requested result was achieved or delivered. [Tasks and memory](https://learn.chatgpt.com/docs/dots/tasks-and-memory).

## Scope parallel work

Write down each task's owner, narrow goal, allowed inputs, expected artifact, dependency and acceptance check. Keep one person/task responsible for integrating the results. Ask workers to report their last observed result and its time, blocker, next action and evidence. Avoid two tasks editing the same file concurrently unless the coordination is explicit.

Dots can delegate background work in parallel. Local tasks need the connected computer online with the app open; a preconfigured cloud coding environment has different execution requirements. A new task has its own conversation and does not automatically inherit every conversation. [Official task guidance](https://learn.chatgpt.com/docs/dots/tasks-and-memory).

## Interpret the state before reacting

- **Running/process alive:** work may be executing; inspect the latest result and observation time to assess progress.
- **Waiting for you:** open the specific request. Review its scope and destination before responding; a dashboard summary cannot authorize it.
- **Tool/access failure:** ask which step failed, what was completed, and which supported access or setup is missing. Do not weaken or bypass safeguards to make the status green.
- **Stale/unknown:** ask for a fresh observation. Silence or an old status does not prove success or failure.
- **Claimed complete:** open the artifact, check the requested result, read the reported checks and errors, and verify delivery in the intended place.

These interpretations are operational advice. Native Activity can show running and waiting chats; availability and filters depend on the surface. [Notifications and Activity](https://learn.chatgpt.com/docs/notifications).

## Stop the right thing

Pause stops the dot's current main task. It does not stop all delegated tasks or cancel scheduled runs. Open a delegated task in Activity to stop that task; use Scheduled to disable/delete the recurring task. Completed actions are not undone. [Official stop-work distinctions](https://learn.chatgpt.com/docs/dots/controls).

## What this prototype adds—and what to compare

The demo is an authored synthetic snapshot. Imported JSON is a point-in-time producer report, evaluated at its opening/recheck time. The default mode is offline. A separate opt-in generic local producer feed is documented in LOCAL_AGENT_SETUP.md; it reads only deliberately published public-safe summaries. No supported dots task API has been wired, and no private agent state is read. The prototype's review idea is recommendations + concise rationale + trade-offs + disagreement alongside provenance and dated evidence; it does not expose internal reasoning, prompts or logs.

Try the native UI and this guide first. Keep the dashboard only if its compact comparison saves a real decision or makes uncertainty easier to see. Record that difference in FEEDBACK.md. Existing open-source agent dashboards and inboxes are precedents; there is no first/only claim here.

Documentation checked 2026-10-02. Product interfaces can change; follow current official instructions and visible requests.
