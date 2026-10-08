// f ück — publish a store bucket to its git repo, and manage push targets.
//
// The store is ~/.f/ucks/<bucket>/. A "push target" is { name, url, ref } and
// the bucket name IS the link: `f uck push -r mine` publishes ~/.f/ucks/mine/.
//
// Two kinds of bucket, because a git bucket is now the clone of its repo:
//
//   CLONE bucket (has .git)  — the bucket has no separate "content" to copy, it
//     already *is* the repo. Push commits its working changes, integrates the
//     remote, and pushes, using the bucket's own origin. No work clone is used:
//     there is nothing to mirror.
//
//   COPY bucket (no .git)    — a local source, or a bucket installed before
//     buckets became clones. These still go the old way: a persistent work clone
//     at ~/.f/uck-work/<name>/ is synced from the target, the named uck dirs are
//     overwritten from the store, and the result is committed and pushed.
//
// For a clone bucket:
//   - default: commit dirty tracked files, fetch, rebase, push. A conflict
//     aborts the rebase (bucket left as it was, nothing pushed) and says how to
//     resolve it in the bucket.
//   - --no-rebase: commit, then push without integrating. Git rejects that
//     unless it is a fast-forward, and the rejection names --no-rebase as the
//     reason. Nothing is ever force-pushed.
//
// Zero deps (node:fs, node:path, node:child_process).

import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

const F = path.join(process.env.HOME ?? "", ".f");
const REPO_FILE = path.join(F, "f.repo.json");

function loadTargets() {
  try {
    const raw = JSON.parse(fs.readFileSync(REPO_FILE, "utf8"));
    if (Array.isArray(raw.targets)) return raw.targets;
  } catch {}
  return [];
}
function saveTargets(targets) {
  fs.mkdirSync(F, { recursive: true });
  fs.writeFileSync(REPO_FILE, JSON.stringify({ targets }, null, 2) + "\n");
}
function findTarget(name) {
  return loadTargets().find((t) => t.name === name) ?? null;
}

function storeBucketDir(bucket) {
  return path.join(F, "ucks", bucket);
}

/** Is this bucket the clone of its repo? */
function isCloneBucket(bucket) {
  return fs.existsSync(path.join(storeBucketDir(bucket), ".git"));
}

/**
 * Map uck name -> its directory inside `root`, at any depth.
 *
 * Depth matters now that a git bucket is the clone: the repo's own layout is
 * intact, so a uck may sit at <repo>/foo/index.js or <repo>/tools/foo/index.js.
 * The old one-level readdir could only see the first, which is what made a
 * nested uck invisible — it read as "a repo with no entry point".
 *
 * A uck dir is a leaf: we do not descend into it, so a uck's own subdirs (a
 * vendored tree with its own index.js, say) are not mistaken for ucks.
 * node_modules and dot-dirs are skipped — .git's contents are never walked
 * even one entry deep.
 */
function uckDirsIn(root) {
  const out = {};
  const walk = (dir) => {
    if (fs.existsSync(path.join(dir, "index.js"))) {
      out[path.basename(dir)] = dir;
      return;
    }
    let entries;
    try {
      entries = fs.readdirSync(dir);
    } catch {
      return;
    }
    for (const e of entries.sort()) {
      if (e === "node_modules" || e.startsWith(".")) continue;
      const full = path.join(dir, e);
      try {
        if (fs.statSync(full).isDirectory()) walk(full);
      } catch {
        /* dangling symlink or raced removal: skip */
      }
    }
  };
  if (fs.existsSync(root)) walk(root);
  return out;
}

/** List uck names present in a store bucket (any depth in a clone bucket). */
function bucketUcks(bucket) {
  return Object.keys(uckDirsIn(storeBucketDir(bucket))).sort();
}

/**
 * Path *inside the repo* of a bucket's uck: "fj", or "tools/fj".
 * Push needs it: in a clone bucket the uck is not at the bucket root, so "what
 * did this uck touch" is a pathspec of its repo-relative dir.
 */
function uckRelPath(bucket, name) {
  const dir = uckDirsIn(storeBucketDir(bucket))[name];
  if (!dir) return null;
  return path.relative(storeBucketDir(bucket), dir) || ".";
}

function git(cmd, cwd) {
  return execSync(`git ${cmd}`, { cwd, stdio: ["pipe", "pipe", "pipe"], timeout: 120_000 }).toString().trim();
}

/**
 * git that returns { ok, stdout, stderr } instead of throwing, for commands we
 * handle.
 *
 * stdout is NOT trimmed. Callers that test it for emptiness do not care, but
 * `git status --porcelain` is position-sensitive: " M path" means
 * modified-unstaged and its path begins at index 3. Trimming the whole output
 * shaves the leading column off the first line and silently mis-parses it.
 */
function gitTry(cmd, cwd) {
  try {
    const out = execSync(`git ${cmd}`, { cwd, stdio: ["pipe", "pipe", "pipe"], timeout: 120_000 }).toString();
    return { ok: true, stdout: out, stderr: "" };
  } catch (e) {
    // Keep the whole error: git's explanation is on err.stderr, not err.message.
    return { ok: false, stdout: "", stderr: e };
  }
}

function workDir(name) {
  return path.join(F, "uck-work", name);
}

/** Ensure a persistent work clone for the target exists and is up to date. Returns {ref, head}. */
function ensureWorkClone(target) {
  const wd = workDir(target.name);
  const ref = target.ref ?? "HEAD";
  if (!fs.existsSync(path.join(wd, ".git"))) {
    fs.mkdirSync(path.dirname(wd), { recursive: true });
    const r = gitTry(`clone ${target.url} ${wd}`);
    if (!r.ok) throw new Error(`clone failed for ${target.name}: ${firstLine(r.stderr)}`);
    if (target.ref) {
      const co = gitTry(`checkout ${target.ref}`, wd);
      if (!co.ok) throw new Error(`checkout ${target.ref} failed: ${firstLine(co.stderr)}`);
    }
  } else {
    const fr = gitTry(`fetch origin`, wd);
    if (!fr.ok) throw new Error(`fetch failed for ${target.name}: ${firstLine(fr.stderr)}`);
  }
  // Make the work clone non-interactive by default, so any git command an
  // operator (or LLM) runs in it — including 'git rebase' during conflict
  // resolution — never hangs waiting for an editor.
  gitTry(`config core.editor true`, wd);
  gitTry(`config rebase.autoStash false`, wd);
  return wd;
}

/**
 * First non-empty line of a failure.
 *
 * Accepts the Error, not just a string: execSync reports git's own output on
 * err.stderr while err.message is only "Command failed: git ...". Reading the
 * message — as an earlier version did — turned "nothing to commit" into
 * "Command failed: git commit ...", which sends you hunting for a quoting bug.
 */
function firstLine(e) {
  if (e && typeof e === "object") {
    const err = e;
    const detail =
      (err.stderr && String(err.stderr).trim()) || (err.stdout && String(err.stdout).trim()) || "";
    if (detail) return detail.split("\n").find((l) => l.trim()) ?? "";
    e = err.message ?? String(err);
  }
  return String(e ?? "").split("\n").find((l) => l.trim()) ?? "";
}

/**
 * A rejected `git push`, phrased for whoever ran it.
 *
 * Push's first stderr line is always "To <url>", which says nothing; the real
 * diagnosis is the " ! [rejected] main -> main (fetch first)" line, and the
 * "hint:" block under it is boilerplate that repeats on every rejection. So
 * keep the rejection, drop the hints, and name the fix for the reason git gave.
 *
 * The fix depends on `rebase`, which is why this is a function rather than
 * git's text echoed. Under --no-rebase a rejection is the flag working as
 * designed, so "just pull and retry" would argue with the flag just passed.
 */
function pushRejected(bucket, bucketDir, branch, pr, committed, rebase) {
  const lines = String(pr.stderr ?? "")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !/^hint:/.test(l) && !l.startsWith("To "));
  const reason = lines.find((l) => l.includes("[rejected]")) ?? lines[0] ?? "push rejected";
  const m = /\(([^)]*)\)/.exec(reason);
  const why = m ? m[1] : "";
  const state = committed
    ? `your changes are committed in ${bucketDir} but not pushed`
    : "nothing was committed or pushed";

  let fix;
  if (why === "fetch first" || why === "non-fast-forward") {
    fix = rebase
      ? `the rebase did not move the bucket onto ${branch}; integrate it yourself:\n` +
        `    git -C ${bucketDir} pull --rebase origin ${branch} && git -C ${bucketDir} push origin ${branch}`
      : `--no-rebase pushes without integrating the remote, and this is not a fast-forward.\n` +
        `    drop --no-rebase to rebase first, or: git -C ${bucketDir} pull --rebase origin ${branch}`;
  } else if (/permission denied|authentication failed|could not read remote/i.test(reason)) {
    fix = `check access to the bucket's origin: git -C ${bucketDir} remote -v`;
  } else if (/nothing to push|up-to-date/i.test(reason)) {
    fix = "the remote already has this commit; nothing to do";
  } else {
    fix = `inspect it: git -C ${bucketDir} status -sb && git -C ${bucketDir} log --oneline -3`;
  }

  return (
    `push rejected for bucket '${bucket}' (${branch}): ${why || reason}\n` +
    `  ${state}.\n` +
    `  fix: ${fix}`
  );
}

/**
 * Compare repo URLs loosely, for the mismatch note only — never to choose a
 * push destination.
 *
 * Parse it; do not regex-strip it. Stripping `ssh://` then matching
 * `user@host:` cannot work: what remains is `git@host/g/r`, with a SLASH after
 * the host, so the scp-style rule (which needs a colon) never fires and the
 * leftover `git@` makes every ssh-vs-https pair compare unequal. Against the
 * operator's own config — f.repo.json says `ssh://git@forgejo.kensand.net/…`
 * where f.config.json says `https://forgejo.kensand.net/…` — that is a false
 * MISMATCH on the one setup this uck exists for.
 */
function normalizeUrl(u) {
  let s = String(u || "").trim().toLowerCase();
  if (!s) return "";
  s = s.replace(/^git\+/, "");
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//.exec(s);
  if (scheme) {
    s = s.slice(scheme[0].length);
  } else {
    // scp-style user@host:path  ->  user@host/path
    const scp = /^([^/]+?):(?!\/)/.exec(s);
    if (scp) s = scp[1] + "/" + s.slice(scp[0].length);
  }
  return s
    .replace(/^[^@/]+@/, "") // userinfo
    .replace(/^([^/]+):\d+\//, "$1/") // port
    .replace(/\.git$/, "")
    .replace(/\/+$/, "");
}

/** Shell-quote one argument so no path or URL is interpolated by the shell. */
function quote(s) {
  return "'" + String(s).replace(/'/g, "'\\''") + "'";
}

/** The remote-tracking ref for the target's branch (origin/<ref>, or origin/HEAD if ref unset). */
function upstreamRef(wd, target) {
  if (target.ref) return `origin/${target.ref}`;
  // Default branch: resolve origin/HEAD if set, else the current branch's upstream.
  // Each is trimmed HERE rather than in gitTry, which must hand back raw
  // output for porcelain parsing (see gitTry): an untrimmed "origin/main\n"
  // interpolated into `git rebase ${up}` is a ref with a newline in it.
  const one = (r) => (r.ok ? r.stdout.trim() : "");
  const head = one(gitTry("rev-parse --abbrev-ref origin/HEAD", wd));
  if (head) return head;
  const up = one(gitTry("rev-parse --abbrev-ref --symbolic-full-name @{u}", wd));
  if (up) return up;
  // Fallback: whatever branch we're on, assume same name on origin.
  const cur = one(gitTry("rev-parse --abbrev-ref HEAD", wd));
  return `origin/${cur || "master"}`;
}

/**
 * Push named ucks (or all ucks in the bucket when names is empty) from the
 * store bucket to the target repo.
 *
 * rebase=true (default): persistent work clone + real rebase. On a rebase
 * conflict, stops and reports how to resolve/abort in the work clone.
 * rebase=false: fresh-clone → overwrite → commit → push (FF-only, store wins).
 */
function push(bucket, target, names, rebase = true) {
  const bucketDir = storeBucketDir(bucket);
  if (!fs.existsSync(bucketDir)) {
    throw new Error(`no such bucket in store: ${bucket} (is it installed?)`);
  }
  const ucks = names.length ? names : bucketUcks(bucket);
  if (!ucks.length) throw new Error(`nothing to push to ${target.name}`);
  const present = bucketUcks(bucket);
  for (const n of ucks)
    if (!present.includes(n))
      // Names here are uck DIRECTORIES (what bucketUcks lists). For a uck whose
      // index.js is at the repo root that is the bucket name, not the `name:`
      // its register() returns — say so, or the obvious next move is to retry
      // with the command name and get the same error back.
      throw new Error(
        `no uck directory '${n}' in bucket ${bucket} (have: ${present.join(", ") || "none"})\n` +
          `  names are directory names under the bucket, not the command a uck registers`,
      );

  if (isCloneBucket(bucket)) return pushCloneBucket(bucket, bucketDir, target, ucks, rebase);

  const applyStore = (wd) => {
    for (const n of ucks) {
      const src = uckDirsIn(bucketDir)[n];
      if (!src) continue;
      const rel = uckRelPath(bucket, n);
      const dest = path.join(wd, rel === "." ? "" : rel);
      fs.rmSync(dest, { recursive: true, force: true });
      fs.mkdirSync(dest, { recursive: true });
      fs.cpSync(src, dest, {
        recursive: true,
        // node_modules is installed per uck by f; it is never repo content.
        filter: (srcPath) => !srcPath.includes("node_modules"),
      });
    }
  };

  if (!rebase) {
    // --- FF-only path: fresh shallow clone → overwrite → commit → push. ---
    const tmp = path.join(F, ".push-" + Date.now().toString(36));
    fs.mkdirSync(tmp, { recursive: true });
    const work = path.join(tmp, "work");
    try {
      const cloneArgs = target.ref ? `clone --depth 1 --branch ${target.ref} ${target.url} ${work}` : `clone --depth 1 ${target.url} ${work}`;
      const cr = gitTry(cloneArgs);
      if (!cr.ok) throw new Error(`clone failed: ${firstLine(cr.stderr)}`);
      applyStore(work);
      const status = gitTry("status --porcelain", work);
      if (status.stdout) {
        git("add -A", work);
        git(`commit -m "f uck: update ${ucks.join(", ")}"`, work);
        const pr = gitTry("push", work);
        if (!pr.ok) throw new Error(`push rejected (non-fast-forward). Pull/merge and retry.\n${pr.stderr}`);
      } else {
        process.stderr.write(`f uck: nothing changed for ${target.name}\n`);
      }
      for (const n of ucks) process.stderr.write(`f uck: pushed ${n} → ${target.name}\n`);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
    return;
  }

  // --- Rebase path: persistent work clone. ---
  const wd = ensureWorkClone(target);
  const up = upstreamRef(wd, target);

  // 1. Apply store changes as a commit (if anything changed).
  applyStore(wd);
  const status = gitTry("status --porcelain", wd);
  if (status.stdout) {
    git("add -A", wd);
    git(`commit -m "f uck: update ${ucks.join(", ")}"`, wd);
  }

  // 2. Rebase onto the remote's latest. On a conflict: abort and error — no
  //    auto-resolution. The user pulls and pushes manually.
  const upExists = gitTry(`rev-parse --verify ${up}`, wd).ok;
  if (upExists) {
    const rb = gitTry(`rebase ${up}`, wd); // work clone has core.editor=true (non-interactive)
    if (!rb.ok) {
      // Gather what conflicted (if any) before cleaning up.
      const unmerged = gitTry("diff --name-only --diff-filter=U", wd).stdout.split("\n").filter(Boolean);
      const remoteTip = gitTry(`rev-parse --short ${up}`, wd).stdout;
      const localTip = gitTry("rev-parse --short HEAD", wd).stdout;
      const behind = gitTry(`rev-list --count HEAD..${up}`, wd).stdout; // remote commits we don't have
      gitTry(`rebase --abort`, wd); // leave the work clone clean

      const files = unmerged.length
        ? "conflicting files:\n  " + unmerged.join("\n  ")
        : "no unmerged files listed (history-level conflict — the remote branch diverged)";
      throw new Error(
`PUSH CONFLICT for target '${target.name}' (rebase of local onto ${up} failed).

What happened:
  The remote branch ${up} (tip ${remoteTip || "?"}) has commits that the store's changes
  conflict with. f rebases the store's changes onto the remote before pushing;
  that rebase could not be applied cleanly, so f aborted it and pushed nothing.
  (local and remote have diverged; remote is ${behind || "?"} commit(s) ahead of where local branched)

${files}

How to fix (pick one), all in the work clone:
  cd ${wd}

  Option A — reconcile manually (keep both sides' work):
    # (f already aborted the rebase, so the work clone is clean — start fresh)
    git rebase ${up}                        # replay local commits onto the remote
    # a conflict will appear; edit the conflicted files to the content you want
    # (or copy the store's version over a uck the store should win), then:
    git rebase --continue                   # or: git rebase --abort to bail out
    git push
    # after, the work clone is up to date; re-run the push to sync the store:
    f uck push -r ${target.name}

  Option B — store wins (discard remote's conflicting uck changes, keep store):
    git reset --hard ${up}                       # take the remote as the base
    # overwrite the uck(s) with the store's copy, then:
    f uck push -r ${target.name} --no-rebase      # fresh-clone, store overwrites, push

  Option C — inspect first:
    git log --oneline --graph --all             # see the divergence
    git diff ${up} HEAD                          # see what differs

  The store (source of truth for the uck code) is at: ${storeBucketDir(bucket)}
  The work clone is a scratch git repo — it is safe to delete and re-push.`);
    }
  }

  // 3. Push (rebase keeps history linear, so this fast-forwards).
  const pr = gitTry("push", wd);
  if (!pr.ok) {
    throw new Error(`push failed for ${target.name}: ${firstLine(pr.stderr)}\n(work clone: ${wd})`);
  }
  for (const n of ucks) process.stderr.write(`f uck: pushed ${n} → ${target.name}\n`);
}

/**
 * Publish a bucket that is the clone of its repo.
 *
 * Deliberately does NOT use the registered target's url/ref as the destination:
 * the bucket has an origin, and pushing this repo's history into a different
 * repo's refs is how you corrupt a remote. The target supplies the *bucket name*
 * (bucket name == target name) and the message; a differing url is reported by
 * `repo ls`, not honoured here.
 */
function pushCloneBucket(bucket, bucketDir, target, ucks, rebase) {
  if (!gitTry("remote get-url origin", bucketDir).ok)
    throw new Error(`bucket ${bucket} has no origin remote; nothing to push to`);

  // Which requested ucks changed, counting TRACKED files only?
  //
  // Tracked-only matters: node_modules, the .f-source.json provenance file and
  // the package.json module markers that `f up` writes are all untracked but
  // present in a clone bucket. A plain porcelain status lists them, so treating
  // them as "this uck changed" makes every uck look dirty on every push.
  const allSpecs = ucks.map((n) => uckRelPath(bucket, n)).filter((rel) => rel && rel !== ".");
  // A uck whose index.js is at the repo root has no subdir, so its pathspec is
  // empty — and `git add -A --` with nothing after the -- means "everything",
  // which would stage unrelated files. Refuse instead of committing a surprise.
  // Only reachable when the repo IS one uck; plain git is the right tool there.
  if (!allSpecs.length)
    throw new Error(
      `bucket ${bucket} is a single uck spanning the whole repo (${ucks.join(", ")}), ` +
        `so there is no subset to commit\n` +
        `  push it with git: git -C ${bucketDir} add -A && git -C ${bucketDir} commit -m … && git -C ${bucketDir} push`,
    );

  const dirty = gitTry(
    "status --porcelain --untracked-files=no -- " + allSpecs.map(quote).join(" "),
    bucketDir,
  );
  if (!dirty.ok) throw new Error(`git status failed in ${bucketDir}: ${firstLine(dirty.stderr)}`);

  // Porcelain v1 is "XY path": two status columns, a space, then the path at
  // index 3. Match the tail with a regex rather than counting columns, and do
  // not trim lines (see gitTry). An earlier version trimmed, parsed every path
  // as ools/deep/index.js, found nothing dirty, skipped the commit — and the
  // rebase then failed on the still-uncommitted edit and was reported as a
  // PUSH CONFLICT.
  const dirtyPaths = dirty.stdout
    .split("\n")
    .filter((l) => l.length > 3)
    .map((l) => /^.{3}(.*)$/.exec(l)?.[1] ?? "")
    .map((f) => f.split(" -> ").pop().trim()) // rename: the new path
    .filter(Boolean);

  // Commit only the ucks that actually changed, so the message names what
  // changed and an unmentioned dirty uck is not dragged along.
  const touched = ucks.filter((n) => {
    const rel = uckRelPath(bucket, n);
    return rel && rel !== "." && dirtyPaths.some((f) => f === rel || f.startsWith(rel + "/"));
  });

  let committed = false;
  if (touched.length) {
    const specs = touched.map((n) => uckRelPath(bucket, n)).map(quote).join(" ");
    const add = gitTry(`add -A -- ${specs}`, bucketDir);
    if (!add.ok) throw new Error(`git add failed in ${bucketDir}: ${firstLine(add.stderr)}`);
    const cm = gitTry(`commit -m ${quote("f uck: update " + touched.join(", "))}`, bucketDir);
    if (!cm.ok) throw new Error(`git commit failed in ${bucketDir}: ${firstLine(cm.stderr)}`);
    committed = true;
  }

  // The bucket's OWN upstream, not the target's ref: a target's `ref` is where
  // that target publishes, and a bucket is a different repo. Using it here would
  // rebase the bucket onto an unrelated branch. Prove it exists too — an
  // unverifiable ref silently skips the rebase and then fails at push with a
  // non-fast-forward that reads like a broken push.
  const branch = gitTry("rev-parse --abbrev-ref HEAD", bucketDir).stdout.trim();
  if (!branch || branch === "HEAD")
    throw new Error(`bucket ${bucket} is in detached HEAD; check out its branch before pushing`);
  const up = `origin/${branch}`;

  // Fetch before integrating. Otherwise "integrate the remote" means rebasing
  // onto wherever origin/<branch> was left the last time anything reached the
  // network, which quietly "succeeds" and then dies at push with (fetch first).
  // A clone bucket has no work clone to fetch for, so this is the only fetch.
  // Being offline is not fatal: say so, and let the push fail or stand on its own.
  if (rebase) {
    const ft = gitTry("fetch --quiet origin", bucketDir);
    if (!ft.ok)
      process.stderr.write(
        `f uck: fetch failed for ${bucket}, integrating the last-seen ${up}: ${firstLine(ft.stderr)}\n`,
      );
    if (!gitTry(`rev-parse --verify --quiet ${up}`, bucketDir).ok)
      throw new Error(
        `bucket ${bucket} has no ${up} to integrate; its origin has no branch "${branch}"\n` +
          `  publish it: git -C ${bucketDir} push -u origin ${branch}`,
      );

    const rb = gitTry(`rebase ${up}`, bucketDir);
    if (!rb.ok) {
      const unmerged = gitTry("diff --name-only --diff-filter=U", bucketDir).stdout
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean);
      // Always abort: a half-applied rebase in the bucket is worse than a failed
      // push, because the next `f up` would reset a repo mid-rebase.
      gitTry("rebase --abort", bucketDir);
      const behind = gitTry(`rev-list --count HEAD..${up}`, bucketDir).stdout.trim();
      const tip = gitTry(`rev-parse --short ${up}`, bucketDir).stdout.trim();
      throw new Error(
        `PUSH CONFLICT for bucket '${bucket}' (rebasing onto ${up} failed).\n` +
          `\n` +
          `The bucket is a git working tree, so this is ordinary divergence: its work branched\n` +
          `before ${up} (tip ${tip || "?"}), which is ${behind || "?"} commit(s) ahead. The rebase\n` +
          `was aborted, the bucket is as it was, and nothing was pushed.\n` +
          `\n` +
          (unmerged.length ? "conflicting files:\n  " + unmerged.join("\n  ") + "\n" : "") +
          `\n` +
          `Resolve it in the bucket:\n` +
          `  cd ${bucketDir}\n` +
          `  git rebase ${up}          # edit conflicts, then git rebase --continue\n` +
          `  git push                  # or: git rebase --abort to give up\n` +
          `\n` +
          `Note: f up resets this bucket to its remote, so unpushed edits in the store only\n` +
          `survive until the next update.`,
      );
    }
  }

  // How many commits were waiting to be published, measured BEFORE the push:
  // the push moves origin/<branch> up to HEAD, so asking afterwards always
  // answers 0 and "published a pending commit" becomes unreportable. An earlier
  // version asked after and told the user "already published; nothing to do" on
  // the very run that had just landed their work.
  const pending = committed
    ? 1
    : Number(gitTry(`rev-list --count ${up}..HEAD`, bucketDir).stdout.trim()) || 0;

  const pr = gitTry(`push origin ${quote(branch)}`, bucketDir);
  if (!pr.ok) throw new Error(pushRejected(bucket, bucketDir, branch, pr, committed, rebase));
  // Two separate facts, and collapsing them lies in exactly one case:
  //   - did THIS run create a commit?                 (committed)
  //   - did THIS run publish work from an earlier one? (pending)
  // After a --no-rebase rejection the work sits committed but unpushed, so the
  // next run commits nothing (touched is empty) yet publishes that commit. Call
  // that "no local change" and the user reads "nothing was waiting" on the run
  // that finally landed it.
  if (committed)
    process.stderr.write(`f uck: ${bucket}: published ${touched.join(", ")}\n`);
  else if (pending > 0)
    process.stderr.write(
      `f uck: ${bucket}: no working-tree changes; published ${pending} pending commit(s)\n`,
    );
  else
    process.stderr.write(`f uck: ${bucket}: already published; nothing to do\n`);
}

function usage(msg) {
  const line = msg ? `f uck: ${msg}\n` : "";
  process.stderr.write(
    line +
      "usage: f uck <cmd>\n" +
      "  repo add <name> <url> [--ref <ref>]   register a push target\n" +
      "  repo ls                               list push targets\n" +
      "  repo rm <name>                        unregister a target\n" +
      "  push [<uck>...] [-r <name>]           publish a bucket to its repo\n" +
      "      [--no-rebase]                       FF-only push (default: rebase)\n"
  );
  process.exit(1);
}

export function register(ctx) {
  return {
    name: "uck",
    desc: "push store ucks to a git repo (bucket name = target name)",
    uckApi: { loadTargets, saveTargets, push, bucketUcks },
    run: (argv, args) => {
      const a = [...(args._ ?? [])];
      let rName = null;
      let ref = null;
      let rebase = true;
      const pos = [];
      for (let i = 0; i < a.length; i++) {
        if (a[i] === "-r" || a[i] === "--repo") { rName = a[++i]; }
        else if (a[i] === "--ref") { ref = a[++i]; }
        else if (a[i] === "--no-rebase") { rebase = false; }
        else if (a[i] === "--rebase") { rebase = true; }
        else pos.push(a[i]);
      }
      const [cmd, ...rest] = pos;

      switch (cmd) {
        case "repo": {
          const sub = rest[0];
          if (sub === "add") {
            const name = rest[1], url = rest[2];
            if (!name || !url) return usage("repo add needs <name> <url>");
            const targets = loadTargets();
            const i = targets.findIndex((t) => t.name === name);
            const t = { name, url, ref: ref ?? null };
            if (i >= 0) targets[i] = t;
            else targets.push(t);
            saveTargets(targets);
            process.stderr.write(`f uck: target ${name} → ${url}${ref ? ` @ ${ref}` : ""}\n`);
          } else if (sub === "rm") {
            const name = rest[1];
            if (!name) return usage("repo rm needs <name>");
            const targets = loadTargets().filter((t) => t.name !== name);
            saveTargets(targets);
            process.stderr.write(`f uck: removed target ${name}\n`);
          } else if (sub === "ls" || !sub) {
            const targets = loadTargets();
            if (!targets.length) return process.stderr.write("f uck: no push targets (use `f uck repo add`)\n");
            for (const t of targets) {
              const ucks = bucketUcks(t.name);
              const clone = isCloneBucket(t.name);
              const origin = clone
                ? gitTry("remote get-url origin", storeBucketDir(t.name)).stdout.trim()
                : "";
              // A clone bucket pushes to its own origin, so show that rather
              // than the target's url, and flag a difference: honouring the
              // target url would push one repo into another's refs.
              const where = clone ? origin || t.url : t.url;
              const clash =
                clone && origin && normalizeUrl(origin) !== normalizeUrl(t.url)
                  ? "\tMISMATCH: bucket pushes to its own origin"
                  : "";
              process.stdout.write(
                `${t.name}\t${where}${t.ref ? ` @ ${t.ref}` : ""}\t` +
                  `[ ${ucks.join(", ") || "no ucks in store"} ]` +
                  `\t(${clone ? "clone" : "copy"})${clash}\n`,
              );
            }
          } else return usage(`unknown repo subcommand: ${sub}`);
          break;
        }
        case "push": {
          const names = rest;
          const target = rName ? findTarget(rName) : (loadTargets().length === 1 ? loadTargets()[0] : null);
          if (!target) {
            const t = loadTargets();
            if (rName && !t.some((x) => x.name === rName)) return usage(`no such target: ${rName} (see 'f uck repo ls')`);
            return usage(t.length ? "specify a target with -r <name>" : "no push targets (use `f uck repo add`)");
          }
          try {
            push(target.name, target, names, rebase);
          } catch (e) {
            process.stderr.write(`f uck: ${e.message}\n`);
            process.exit(1);
          }
          break;
        }
        default:
          usage();
      }
    },
  };
}

export default { register };
