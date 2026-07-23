#!/usr/bin/env python3
"""
proxy247 — VPLink Proxy Hunter Deployer & Manager
One-command management: accounts, deployment, testing, and monitoring.
"""

import os, sys, json, time, random, string, shutil, tempfile, subprocess, base64, urllib.request, urllib.error, argparse, re
from pathlib import Path

# ── ANSI helpers ──────────────────────────────────────────
C = "\033[36m"; G = "\033[32m"; Y = "\033[33m"; R = "\033[31m"
B = "\033[1m"; M = "\033[35m"; N = "\033[0m"; D = "\033[2m"

_STDIN_TTY = sys.stdin.isatty()
VERSION = "1.0.0"
CONFIG_DIR = Path.home() / ".proxy247"
ACCOUNTS_FILE = CONFIG_DIR / "accounts.json"
DEPLOYMENTS_FILE = CONFIG_DIR / "deployments.json"
SETTINGS_FILE = CONFIG_DIR / "settings.json"
TEMPLATE_REPO = "adittaya/workflow-proxy"
GITHUB_API = "https://api.github.com"


# ── TUI toolkit (self-contained, no external deps) ───────

def _say(text):       print(f"  {text}")
def _ok(text):        print(f"  {G}✓{N} {text}")
def _warn(text):      print(f"  {Y}{text}{N}")
def _fail(text):      print(f"  {R}{text}{N}")
def _dim(text):       print(f"  {D}{text}{N}")
def _prompt(text):    return input(f"  {C}?{N} {B}{text}{N} ").strip()

_hline = f"  {C}────────────────────────────────────────────{N}"
_dash  = f"  {D}{'─'*44}{N}"

def _header(text):
    pad = max(2, 44 - len(text))
    print()
    print(f"  {C}╭{'─'*44}╮{N}")
    print(f"  {C}│{N}   {B}{text}{N}{' ' * (pad - 3)}  {C}│{N}")
    print(f"  {C}╰{'─'*44}╯{N}")
    print()

def _choose(opts):
    for i, o in enumerate(opts, 1):
        print(f"    {C}{i:>2}{N}) {o}")
    print()
    while True:
        raw = input(f"  {B}Select{N} [1-{len(opts)}, 0=back] {C}»{N} ").strip()
        if raw == "0": return -1
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(opts): return idx
        print(f"  {Y}Enter a number 1-{len(opts)} or 0 to go back.{N}")

def _confirm(text):
    raw = input(f"  {C}?{N} {text} {D}(y/N){N} ").strip().lower()
    return raw == "y"

def _pause():
    try:
        input(f"\n  {D}Press Enter to continue...{N}")
    except (EOFError, KeyboardInterrupt):
        pass

def _input_secret(prompt):
    import getpass
    return getpass.getpass(f"  {C}?{N} {B}{prompt}{N} ").strip()


# ── JSON helpers ─────────────────────────────────────────

def _load_json(path):
    if path.exists():
        with open(path) as f: return json.load(f)
    return {}

def _save_json(path, data):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f: json.dump(data, f, indent=2)

def load_accounts():    return _load_json(ACCOUNTS_FILE)
def save_accounts(d):   _save_json(ACCOUNTS_FILE, d)
def load_deployments(): return _load_json(DEPLOYMENTS_FILE)
def save_deployments(d): _save_json(DEPLOYMENTS_FILE, d)
def get_setting(k):     return _load_json(SETTINGS_FILE).get(k)
def set_setting(k, v):  s = _load_json(SETTINGS_FILE); s[k] = v; _save_json(SETTINGS_FILE, s)

# ── Supabase config (persistent, shared across deployments) ──
SUPABASE_KEYS = ["supabase_url", "supabase_key", "supabase_secret"]

def get_db_config():
    s = _load_json(SETTINGS_FILE)
    return {k: s.get(k, "") for k in SUPABASE_KEYS}

def set_db_config(url, key, secret):
    s = _load_json(SETTINGS_FILE)
    if url:  s["supabase_url"] = url
    if key:  s["supabase_key"] = key
    if secret: s["supabase_secret"] = secret
    _save_json(SETTINGS_FILE, s)

def _resolve_supabase(args):
    cfg = get_db_config()
    supabase_url = args.supabase_url or cfg["supabase_url"] or _prompt("Supabase URL")
    supabase_key = args.supabase_key or cfg["supabase_key"] or _prompt("Supabase anon/public key")
    supabase_secret = args.supabase_secret or cfg["supabase_secret"] or _input_secret("Supabase service/secret key")
    if supabase_url and supabase_key and supabase_secret:
        set_db_config(supabase_url, supabase_key, supabase_secret)
    return supabase_url, supabase_key, supabase_secret


# ── GitHub API ────────────────────────────────────────────

def _api(token, method, path, data=None):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "proxy247/1.0",
    }
    body = json.dumps(data).encode() if data is not None else None
    if data is not None: headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{GITHUB_API}{path}", data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode() if e.fp else ""
        raise SystemExit(f"  {R}GitHub API error {e.code}:{N} {detail}")
    except urllib.error.URLError as e:
        raise SystemExit(f"  {R}Network error:{N} {e.reason}")

def _encrypt_secret(public_key_content, secret_value):
    import nacl.bindings
    from base64 import b64decode, b64encode
    pk = b64decode(public_key_content)
    encrypted = nacl.bindings.crypto_box_seal(secret_value.encode(), pk)
    return b64encode(encrypted).decode()

def _set_secret(token, owner, repo, name, value):
    pub = _api(token, "GET", f"/repos/{owner}/{repo}/actions/secrets/public-key")
    encrypted = _encrypt_secret(pub["key"], value)
    _api(token, "PUT", f"/repos/{owner}/{repo}/actions/secrets/{name}",
         {"encrypted_value": encrypted, "key_id": pub["key_id"]})

def _trigger_workflow(token, owner, repo):
    _api(token, "POST", f"/repos/{owner}/{repo}/actions/workflows/hunt.yml/dispatches",
         {"ref": "main"})

def _get_workflow_id(token, owner, repo):
    wfs = _api(token, "GET", f"/repos/{owner}/{repo}/actions/workflows")
    for wf in wfs.get("workflows", []):
        if wf["path"].endswith("hunt.yml"):
            return wf["id"], wf["state"]
    return None, None

def _set_workflow_state(token, owner, repo, disable=True):
    wid, state = _get_workflow_id(token, owner, repo)
    if not wid: _fail("Workflow hunt.yml not found"); return False
    if disable and state == "disabled_inactivity":
        _ok("Workflow already disabled (inactivity)"); return True
    if disable and state == "disabled_manually":
        _ok("Workflow already disabled"); return True
    if not disable and state == "active":
        _ok("Workflow already active"); return True
    action = "disable" if disable else "enable"
    _api(token, "PUT", f"/repos/{owner}/{repo}/actions/workflows/{wid}/{action}")
    return True


# ── Account commands ─────────────────────────────────────

def _verify_token(token):
    try:
        user = _api(token, "GET", "/user")
        login = user.get("login", "?")
        return True, login
    except SystemExit:
        return False, None

def cmd_login(args):
    _header("🔑 Login with GitHub Token")
    _say("Paste your GitHub personal access token (classic, repo scope).")
    _say("It will be validated before saving.\n")
    token = args.token or _prompt("GitHub token")
    if not token: _fail("Token is required"); return
    ok, login = _verify_token(token)
    if not ok:
        _fail("Token rejected — check it has repo scope and is valid")
        return
    accounts = load_accounts()
    if login in accounts:
        accounts[login]["token"] = token
        accounts[login]["created_at"] = time.time()
        _ok(f"Updated token for existing account '{login}'")
    else:
        accounts[login] = {"token": token, "created_at": time.time()}
        _ok(f"Authenticated as {G}{login}{N}")
    save_accounts(accounts)
    set_setting("active_account", login)
    _ok(f"Account '{login}' set as active")

def cmd_account_add(args):
    name = args.name or _prompt("Account name") or "default"
    token = args.token or _prompt("GitHub token (classic PAT, repo scope)")
    if not name or not token:
        _fail("Name and token are required"); return
    ok, login = _verify_token(token)
    if not ok:
        _fail("Token rejected — check it has repo scope and is valid")
        return
    accounts = load_accounts()
    accounts[name] = {"token": token, "github_user": login, "created_at": time.time()}
    save_accounts(accounts)
    set_setting("active_account", name)
    _ok(f"Account '{name}' added (authenticated as {C}{login}{N}) and set as active")

def cmd_account_list(_args):
    accounts = load_accounts(); active = get_setting("active_account")
    if not accounts: _warn("No accounts. Use 'proxy247 login'"); return
    _say(f"{'':3} {C}{'Name':20}{N} {'Active':6} {'GitHub User':20} {'Created':20}")
    _say(f"{'':3} {D}{'─'*20}{N} {'─'*6} {'─'*20} {'─'*20}")
    for name, info in accounts.items():
        mark = f"{G}●{N}" if name == active else f"{D}○{N}"
        gh = info.get("github_user", "?")
        added = time.strftime("%Y-%m-%d %H:%M", time.localtime(info.get("created_at", 0)))
        _say(f"  {mark:3} {name:20} {f'{G}YES{N}' if name == active else '':6} {gh:20} {added:20}")

def cmd_account_switch(args):
    accounts = load_accounts()
    if not args.name:
        if not accounts: _warn("No accounts."); return
        _say(f"Available: {', '.join(accounts.keys())}")
        args.name = _prompt("Switch to")
    if args.name not in accounts: _fail(f"Account '{args.name}' not found"); return
    set_setting("active_account", args.name)
    _ok(f"Switched to '{args.name}'")

def cmd_account_remove(args):
    accounts = load_accounts()
    if args.name not in accounts: _fail(f"Account '{args.name}' not found"); return
    if not _confirm(f"Remove account '{args.name}'?"): _say("Cancelled"); return
    del accounts[args.name]; save_accounts(accounts)
    if get_setting("active_account") == args.name:
        remaining = list(accounts.keys())
        set_setting("active_account", remaining[0] if remaining else None)
    _ok(f"Removed '{args.name}'")


# ── Deploy commands ─────────────────────────────────────

def _git_env():
    env = os.environ.copy()
    env.setdefault("GIT_AUTHOR_NAME", "proxy247")
    env.setdefault("GIT_AUTHOR_EMAIL", "proxy247@users.noreply.github.com")
    env.setdefault("GIT_COMMITTER_NAME", "proxy247")
    env.setdefault("GIT_COMMITTER_EMAIL", "proxy247@users.noreply.github.com")
    return env

def _git_run(args, cwd=None):
    r = subprocess.run(args, cwd=cwd, capture_output=True, text=True, env=_git_env())
    if r.returncode != 0:
        err = r.stderr.strip() or r.stdout.strip() or f"exit code {r.returncode}"
        raise SystemExit(f"  {R}git error:{N} {err}")
    return r

def _deploy_one(active, token, repo_name, supabase_url, supabase_key, supabase_secret, template_dir=None):
    _say(f"\n  {C}── {repo_name} ──{N}")
    _say(f"  {C}▸{N} Creating repository ...")
    repo = _api(token, "POST", "/user/repos", {
        "name": repo_name, "private": False, "auto_init": True,
        "description": "VPLink Proxy Hunter — automated proxy scanning pipeline"
    })
    clone_url = repo["clone_url"]
    _ok(f"Created {repo['html_url']}")
    _say(f"  {C}▸{N} Pushing hunter code ...")
    with tempfile.TemporaryDirectory(prefix="proxy247-") as tmpdir:
        if template_dir:
            tgt = Path(tmpdir) / repo_name
            shutil.copytree(template_dir, tgt)
        else:
            tgt = Path(tmpdir) / repo_name
            _git_run(["git", "clone", "--depth=1", f"https://github.com/{TEMPLATE_REPO}.git", str(tgt)])
            subprocess.run(["rm", "-rf", str(tgt / ".git")])
        _git_run(["git", "init", "-b", "main"], cwd=tgt)
        _git_run(["git", "add", "-A"], cwd=tgt)
        _git_run(["git", "commit", "-m", "initial deploy by proxy247"], cwd=tgt)
        authed = clone_url.replace("https://", f"https://{token}@")
        _git_run(["git", "remote", "add", "origin", authed], cwd=tgt)
        _git_run(["git", "push", "-u", "origin", "main", "--force"], cwd=tgt)
    _say(f"  {C}▸{N} Configuring GitHub Secrets ...")
    for sn, sv in [("SUPABASE_URL", supabase_url), ("SUPABASE_SERVICE_KEY", supabase_secret),
                   ("GH_PAT", token), ("LOOP_TRIGGER_TOKEN", token)]:
        _set_secret(token, active, repo_name, sn, sv)
    _ok("Secrets set")
    deps = load_deployments()
    deps[repo_name] = {"account": active, "key": supabase_url, "repo_url": repo["html_url"], "created_at": time.time()}
    save_deployments(deps)
    _say(f"  {C}▸{N} Triggering first run ...")
    _trigger_workflow(token, active, repo_name)
    _ok("Workflow dispatched")
    return repo_name, repo["html_url"]

def _update_one(active, token, repo_name, supabase_url, supabase_key, supabase_secret, template_dir=None):
    _say(f"\n  {C}── {repo_name} ──{N}")
    _say(f"  {C}▸{N} Cloning existing repo ...")
    with tempfile.TemporaryDirectory(prefix="proxy247-update-") as tmpdir:
        tgt = Path(tmpdir) / repo_name
        _git_run(["git", "clone", "--depth=5",
                   f"https://{token}@github.com/{active}/{repo_name}.git", str(tgt)])
        if template_dir:
            _say(f"  {C}▸{N} Copying updated template ...")
            for item in template_dir.iterdir():
                if item.name == ".git":
                    continue
                dest = tgt / item.name
                if item.is_dir():
                    if dest.exists():
                        shutil.rmtree(dest)
                    shutil.copytree(item, dest)
                else:
                    shutil.copy2(item, dest)
        else:
            _say(f"  {C}▸{N} Pulling latest from template ...")
            _git_run(["git", "remote", "add", "upstream",
                       f"https://github.com/{TEMPLATE_REPO}.git"], cwd=tgt)
            _git_run(["git", "fetch", "upstream"], cwd=tgt)
            _git_run(["git", "checkout", "main"], cwd=tgt)
            _git_run(["git", "merge", "upstream/main", "--allow-unrelated-histories",
                       "-m", "update by proxy247"], cwd=tgt)
        _say(f"  {C}▸{N} Pushing updated code ...")
        _git_run(["git", "add", "-A"], cwd=tgt)
        _git_run(["git", "commit", "-m", "update by proxy247"], cwd=tgt)
        _git_run(["git", "push", "origin", "main", "--force"], cwd=tgt)
    _say(f"  {C}▸{N} Configuring GitHub Secrets ...")
    for sn, sv in [("SUPABASE_URL", supabase_url), ("SUPABASE_SERVICE_KEY", supabase_secret),
                   ("GH_PAT", token), ("LOOP_TRIGGER_TOKEN", token)]:
        _set_secret(token, active, repo_name, sn, sv)
    _ok("Secrets set")
    deps = load_deployments()
    if repo_name not in deps:
        deps[repo_name] = {"account": active, "created_at": time.time()}
    deps[repo_name]["updated_at"] = time.time()
    save_deployments(deps)
    _say(f"  {C}▸{N} Triggering workflow ...")
    _trigger_workflow(token, active, repo_name)
    _ok("Done")
    return repo_name

def cmd_deploy_update(args):
    accounts = load_accounts(); active = get_setting("active_account")
    if not active or active not in accounts: _fail("No active account."); return
    token = accounts[active]["token"]
    deps = load_deployments()
    account_deps = {k: v for k, v in deps.items() if v.get("account") == active}
    if not account_deps:
        _fail("No deployments on this account."); return
    repo_name = getattr(args, "name", None)
    supabase_url, supabase_key, supabase_secret = _resolve_supabase(args)
    _hline
    _say(f"{C}Updating template on {active}{N} ...")
    _say("Fetching latest template ...")
    with tempfile.TemporaryDirectory(prefix="proxy247-tpl-") as tmpdir:
        template_dir = Path(tmpdir) / "template"
        _git_run(["git", "clone", "--depth=1", f"https://github.com/{TEMPLATE_REPO}.git", str(template_dir)])
        if repo_name:
            if repo_name not in account_deps:
                _fail(f"Deployment '{repo_name}' not found on {active}."); return
            _update_one(active, token, repo_name, supabase_url, supabase_key, supabase_secret, template_dir)
        else:
            _say(f"Found {C}{len(account_deps)}{N} deployments. Updating all ...")
            updated = 0
            for name, info in sorted(account_deps.items()):
                _update_one(active, token, name, supabase_url, supabase_key, supabase_secret, template_dir)
                updated += 1
                time.sleep(2)
            _ok(f"\nUpdated {C}{updated}{N} deployments.")
    print()

def cmd_deploy(args):
    accounts = load_accounts(); active = get_setting("active_account")
    if not active or active not in accounts: _fail("No active account. Add one first: proxy247 account add"); return
    token = accounts[active]["token"]
    repo_name = args.name or ""
    if not repo_name:
        auto = _prompt("Repo name (enter for random)")
        repo_name = auto or "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    supabase_url, supabase_key, supabase_secret = _resolve_supabase(args)
    _hline
    _say(f"Deploying hunter to {C}{active}/{repo_name}{N} ...")
    rname, rurl = _deploy_one(active, token, repo_name, supabase_url, supabase_key, supabase_secret)
    print()
    print(f"  {G}╭{'─'*46}╮{N}")
    print(f"  {G}│{N}  {B}✓ DEPLOYED SUCCESSFULLY{N}{' ' * 24} {G}│{N}")
    print(f"  {G}├{'─'*46}┤{N}")
    print(f"  {G}│{N}  Repo:  {C}{rurl:<39}{N} {G}│{N}")
    print(f"  {G}│{N}  Name:  {C}{repo_name:<39}{N} {G}│{N}")
    print(f"  {G}│{N}  SB URL:{C}{supabase_url:<38}{N} {G}│{N}")
    print(f"  {G}╰{'─'*46}╯{N}")
    print(f"\n  Run {C}proxy247 test {repo_name}{N} to verify it works.\n")

def cmd_bulk_deploy(args):
    accounts = load_accounts(); active = get_setting("active_account")
    if not active or active not in accounts: _fail("No active account."); return
    token = accounts[active]["token"]
    count = args.count
    if not count:
        try: count = int(_prompt("How many hunters to create") or "0")
        except ValueError: _fail("Enter a number"); return
    if count < 1 or count > 1000: _fail("Count must be 1-1000"); return
    supabase_url, supabase_key, supabase_secret = _resolve_supabase(args)
    _say(f"Bulk deploying {C}{count}{N} hunters as {C}{active}{N}")
    if not _confirm(f"Create {count} repos with random names?"): _say("Cancelled"); return
    if count > 100:
        _warn(f"Large batch ({count}) — expect ~30s per repo due to API + git operations.")
        _warn(f"GitHub may suspend accounts for rapid mass-creation.")
        if not _confirm(f"Continue with {count} repos?"): _say("Cancelled"); return
    print()
    _say(f"{C}▸{N} Cloning template (one-time)...")
    with tempfile.TemporaryDirectory(prefix="proxy247-bulk-") as tmpdir:
        template_dir = Path(tmpdir) / "template"
        _git_run(["git", "clone", "--depth=1", f"https://github.com/{TEMPLATE_REPO}.git", str(template_dir)])
        subprocess.run(["rm", "-rf", str(template_dir / ".git")])
        ok, fail = 0, 0
        for i in range(count):
            rname = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
            try:
                _deploy_one(active, token, rname, supabase_url, supabase_key, supabase_secret, template_dir)
                ok += 1
            except SystemExit as e:
                _fail(f"  {rname}: {e}")
                fail += 1
            except Exception as e:
                _fail(f"  {rname}: {e}")
                fail += 1
            if (i + 1) % 10 == 0 or i == count - 1:
                _say(f"  Progress: {i+1}/{count} ({ok} ok, {fail} failed)")
    print()
    print(f"  {G}╭{'─'*46}╮{N}")
    print(f"  {G}│{N}  {B}✓ BULK DEPLOY COMPLETE{N}{' ' * 24} {G}│{N}")
    print(f"  {G}├{'─'*46}┤{N}")
    print(f"  {G}│{N}  {G}Success:{N} {ok:<5} {' ' * 32} {G}│{N}")
    print(f"  {G}│{N}  {R}Failed:{N}  {fail:<5} {' ' * 32} {G}│{N}")
    print(f"  {G}╰{'─'*46}╯{N}")
    print(f"\n  Run {C}proxy247 list{N} to see all deployments.\n")

def cmd_deploy_list(_args):
    deps = load_deployments()
    if not deps: _warn("No deployments."); return
    _say(f"  {C}{'Name':25} {'Account':20} {'Supabase':15} {'Created':20}{N}")
    _say(f"  {D}{'─'*25} {'─'*20} {'─'*15} {'─'*20}{N}")
    for name, info in sorted(deps.items()):
        created = time.strftime("%Y-%m-%d %H:%M", time.localtime(info.get("created_at", 0)))
        _say(f"  {name:25} {info.get('account','?'):20} {str(info.get('key','?'))[:15]:15} {created:20}")

def cmd_deploy_remove(args):
    deps = load_deployments()
    if args.name not in deps: _fail(f"Deployment '{args.name}' not found"); return
    info = deps[args.name]
    accounts = load_accounts()
    token = accounts.get(info["account"], {}).get("token")
    if token and _confirm(f"Also delete the GitHub repo '{info['account']}/{args.name}'?"):
        _say(f"  {C}▸{N} Deleting repo (waiting 2s for rate limit) ...")
        time.sleep(2)
        _api(token, "DELETE", f"/repos/{info['account']}/{args.name}")
        _ok("Repo deleted")
    del deps[args.name]; save_deployments(deps)
    _ok(f"Deployment '{args.name}' removed")

def cmd_nuke_all(_args):
    deps = load_deployments()
    if not deps: _warn("No deployments to nuke."); return
    accounts = load_accounts()
    _header("💥 NUKE ALL DEPLOYMENTS")
    _say(f"  {R}This will delete {len(deps)} GitHub repos and remove all deployments.{N}")
    _say(f"  {Y}Repos to delete:{N}")
    for name, info in sorted(deps.items()):
        _say(f"    {C}▸{N} {info.get('account','?')}/{name}")
    print()
    if len(deps) > 20:
        _warn(f"Large batch ({len(deps)} repos) — deleting too fast will get your account suspended!")
        _warn(f"GitHub rate limit: ~10 deletions/minute safe threshold.")
        _say(f"  {Y}Recommendation: delete max 20 at a time, wait 5 minutes, then continue.{N}")
        if not _confirm(f"Delete ALL {len(deps)} repos anyway? (risky)"): _say("Cancelled"); return
    if not _confirm(f"Delete ALL {len(deps)} repos permanently?"): _say("Cancelled"); return
    if not _confirm(f"Are you absolutely sure? This cannot be undone."): _say("Cancelled"); return
    print()
    ok, fail = 0, 0
    for i, (name, info) in enumerate(sorted(deps.items())):
        account = info.get("account", "?")
        token = accounts.get(account, {}).get("token")
        _say(f"  {C}▸{N} Deleting {account}/{name} ...")
        try:
            if token:
                _api(token, "DELETE", f"/repos/{account}/{name}")
            ok += 1
            _ok(f"  Deleted {account}/{name}")
        except Exception as e:
            fail += 1
            _fail(f"  Failed {account}/{name}: {e}")
        if i < len(deps) - 1:
            time.sleep(2)
    save_deployments({})
    print()
    print(f"  {G}╭{'─'*44}╮{N}")
    print(f"  {G}│{N}  {B}💥 NUKE COMPLETE{N}{' ' * 26} {G}│{N}")
    print(f"  {G}├{'─'*44}┤{N}")
    print(f"  {G}│{N}  {G}Deleted:{N} {ok:<5} {' ' * 30} {G}│{N}")
    print(f"  {G}│{N}  {R}Failed:{N}  {fail:<5} {' ' * 30} {G}│{N}")
    print(f"  {G}╰{'─'*44}╯{N}\n")


# ── Database Config ──────────────────────────────────────

def cmd_db_configure(_args):
    cfg = get_db_config()
    _header("🗄️  Database Configuration")
    _say("Configure Supabase credentials once — they persist for all deployments.\n")
    print(f"  Current:  {C}{cfg['supabase_url'] or '(not set)'}{N}")
    print(f"  Key:      {D}{'set' if cfg['supabase_key'] else '(not set)'}{N}")
    print(f"  Secret:   {D}{'set' if cfg['supabase_secret'] else '(not set)'}{N}")
    print()
    if not _confirm("Update database credentials?"): return
    url = _prompt("Supabase URL") or cfg["supabase_url"]
    key = _prompt("Supabase anon/public key") or cfg["supabase_key"]
    secret = _input_secret("Supabase service/secret key") or cfg["supabase_secret"]
    set_db_config(url, key, secret)
    _ok("Database configuration saved")

def cmd_db_show(_args):
    cfg = get_db_config()
    _header("🗄️  Database Configuration")
    _say(f"URL:       {C}{cfg['supabase_url'] or '(not set)'}{N}")
    _say(f"Service:   {D}{'✓ set' if cfg['supabase_key'] else '✗ not set'}{N}")
    _say(f"Secret:    {D}{'✓ set' if cfg['supabase_secret'] else '✗ not set'}{N}")

def cmd_db_premium(_args):
    cfg = get_db_config()
    if not cfg.get("supabase_url") or not cfg.get("supabase_secret"):
        _fail("Supabase not configured. Run 'proxy247 db config' first"); return
    url = cfg["supabase_url"].rstrip("/")
    key = cfg.get("supabase_secret") or cfg.get("supabase_key", "")
    _header("★ Premium Proxies")
    _say("Premium = residential + VPLINK-verified\n")
    headers = {"apikey": key, "Authorization": f"Bearer {key}", "Accept": "application/json",
               "Prefer": "count=exact"}
    def _cnt(params):
        try:
            q = f"{url}/rest/v1/proxy_results?select=id&{params}"
            req = urllib.request.Request(q, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as r:
                cr = r.headers.get("content-range", "")
                return int(cr.split("/")[-1]) if "/" in cr else 0
        except Exception: return 0
    total = _cnt("")
    residential = _cnt("type=eq.residential")
    dc = _cnt("type=eq.datacenter")
    vp = _cnt("vplink_ok=eq.true")
    prem = min(residential, vp)
    print(f"  {'Total proxies':20} {total}")
    print(f"  {G}{'Residential':20}{N} {residential}")
    print(f"  {Y}{'Datacenter':20}{N} {dc}")
    print(f"  {C}{'VPLINK verified':20}{N} {vp}")
    print(f"  {'Unknown':20} {total - residential - dc}")
    print(f"  {M}{'★ Premium (res+vp)':20}{N} {prem}")
    if prem > 0:
        _ok(f"{prem} premium proxies ready for use")
    else:
        _warn("No premium proxies — keep the hunter running")
    print()

# ── Stop / Start ─────────────────────────────────────────

def _get_deployment_info(name):
    deps = load_deployments()
    if name not in deps: _fail(f"Deployment '{name}' not found"); return None
    info = deps[name]
    accounts = load_accounts()
    token = accounts.get(info["account"], {}).get("token")
    if not token: _fail(f"Account '{info['account']}' not found"); return None
    return info["account"], name, token, info.get("key", "?")

def cmd_stop(args):
    r = _get_deployment_info(args.name)
    if not r: return
    owner, repo, token, key = r
    _say(f"Stopping {C}{owner}/{repo}{N} ...")
    if _set_workflow_state(token, owner, repo, disable=True):
        _ok(f"Hunter stopped for '{args.name}'")

def cmd_start(args):
    r = _get_deployment_info(args.name)
    if not r: return
    owner, repo, token, key = r
    _say(f"Starting {C}{owner}/{repo}{N} ...")
    if _set_workflow_state(token, owner, repo, disable=False):
        _ok(f"Hunter started for '{args.name}'")

# ── Analytics ───────────────────────────────────────────

def _fetch_run_logs(token, owner, repo, run_id):
    import io, zipfile
    url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs/{run_id}/logs"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}", "User-Agent": "proxy247/1.0",
    })
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
    except Exception:
        return ""
    try:
        text_parts = []
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            for name in z.namelist():
                if name.endswith(".txt"):
                    text_parts.append(z.read(name).decode(errors="replace"))
        return "\n".join(text_parts)
    except zipfile.BadZipFile:
        return raw.decode(errors="replace")

def _parse_run_logs(text):
    ips = []; lines = text.split("\n")
    stats = {"total": 0, "residential": 0, "datacenter": 0, "vplink_ok": 0}
    for line in lines:
        m = re.search(r"Total proxies:\s+(\d+)", line)
        if m: stats["total"] = int(m.group(1))
        m = re.search(r"Residential:\s+(\d+)", line)
        if m: stats["residential"] = int(m.group(1))
        m = re.search(r"Datacenter:\s+(\d+)", line)
        if m: stats["datacenter"] = int(m.group(1))
        m = re.search(r"VPLINK verified:\s+(\d+)", line)
        if m: stats["vplink_ok"] = int(m.group(1))
        # Detect proxy IPs from vplink-hunter --list output
        m = re.search(r"\[(R|D|.)\]\s+(\d+\.\d+\.\d+\.\d+):(\d+)", line)
        if m and m.group(2) not in ips: ips.append(m.group(2))
    return ips, stats

def _analyze_deployment(name, info, token):
    owner, repo = info["account"], name
    try:
        runs = _api(token, "GET", f"/repos/{owner}/{repo}/actions/runs?per_page=10")
    except SystemExit:
        return None
    wf = runs.get("workflow_runs", [])
    total, success, failed, all_ips = 0, 0, 0, []
    agg_stats = {"total": 0, "residential": 0, "datacenter": 0, "vplink_ok": 0}
    for r in wf:
        total += 1; c = r.get("conclusion", "")
        if c == "success": success += 1
        elif c in ("failure", "cancelled", "timed_out"): failed += 1
        if r.get("status") == "completed" and r.get("conclusion"):
            logs = _fetch_run_logs(token, owner, repo, r["id"])
            ips, s = _parse_run_logs(logs)
            all_ips.extend(ips)
            for k in agg_stats: agg_stats[k] += s[k]
    return {"total_runs": total, "success": success, "failed": failed,
            "other": total - success - failed,
            "ips": all_ips, "unique_ips": len(set(all_ips)),
            "hunt_stats": agg_stats}

def _print_analytics(name, info, r, is_aggregate=False):
    tag = f"{B}Aggregate ({len(name)} deployments){N}" if is_aggregate else f"{B}{name}{N} ({C}{info['account']}{N})"
    hs = r.get("hunt_stats", {})
    prem = min(hs.get('residential', 0), hs.get('vplink_ok', 0))
    print(f"  {tag}")
    print(f"  {'Runs:':20} {r['total_runs']}")
    print(f"  {G}{'✓ Succeeded:':20}{N} {r['success']}")
    print(f"  {R}{'✗ Failed:':20}{N} {r['failed']}")
    print(f"  {'Other:':20} {r['other']}")
    print(f"  {'Proxies discovered:':20} {r['unique_ips']}")
    print(f"")
    print(f"  {B}Database Statistics (cumulative):{N}")
    print(f"  {'Total proxies':20} {hs.get('total', 0)}")
    print(f"  {G}{'Residential':20}{N} {hs.get('residential', 0)}")
    print(f"  {Y}{'Datacenter':20}{N} {hs.get('datacenter', 0)}")
    print(f"  {C}{'VPLINK verified':20}{N} {hs.get('vplink_ok', 0)}")
    print(f"  {M}{'★ Premium (res+vp)':20}{N} {prem}")
    print()

def cmd_analytics(args):
    deps = load_deployments(); accounts = load_accounts()
    if args.name and args.name not in deps: _fail(f"Deployment '{args.name}' not found"); return
    _header("📊 Analytics Report")
    if args.aggregate or not args.name:
        all_ips = []
        total_s, total_f, total_r, total_ip, dep_count = 0, 0, 0, 0, 0
        for name, info in sorted(deps.items()):
            token = accounts.get(info["account"], {}).get("token")
            if not token: continue
            _say(f"  Scanning {C}{name}{N} ...")
            r = _analyze_deployment(name, info, token)
            if not r: continue
            total_r += r["total_runs"]; total_s += r["success"]; total_f += r["failed"]
            all_ips.extend(r["ips"]); total_ip += r["unique_ips"]; dep_count += 1
        print()
        if dep_count == 0: _warn("No deployments found."); return
        agg = {"total_runs": total_r, "success": total_s, "failed": total_f,
               "other": total_r - total_s - total_f,
               "ips": all_ips, "unique_ips": len(set(all_ips))}
        _print_analytics([d for d in deps], None, agg, is_aggregate=True)
        return
    name, info = args.name, deps[args.name]
    token = accounts.get(info["account"], {}).get("token")
    if not token: _fail(f"Account '{info['account']}' not found"); return
    r = _analyze_deployment(name, info, token)
    if not r: return
    _print_analytics(name, info, r)

def cmd_analytics_all(_args):
    cmd_analytics(argparse.Namespace(name=None, aggregate=True))

# ── Check / Test / Status ───────────────────────────────

def cmd_check(args):
    deps = load_deployments()
    if args.name not in deps:
        _fail(f"Deployment '{args.name}' not found"); return
    info = deps[args.name]
    accounts = load_accounts()
    token = accounts.get(info["account"], {}).get("token")
    if not token: _fail(f"Account '{info['account']}' not found"); return
    owner, repo = info["account"], args.name
    _header("🔍 Latest Workflow Run")
    try:
        runs = _api(token, "GET", f"/repos/{owner}/{repo}/actions/runs?per_page=1")
    except SystemExit:
        return
    wf_runs = runs.get("workflow_runs", [])
    if not wf_runs:
        _warn("No workflow runs found yet. Trigger one:")
        _say(f"  proxy247 test {args.name}"); return
    r = wf_runs[0]
    status = r.get("status", "?")
    conclusion = r.get("conclusion")
    created = r.get("created_at", "").replace("T", " ").replace("Z", "")
    updated = r.get("updated_at", "").replace("T", " ").replace("Z", "")
    color = G if conclusion == "success" else (R if conclusion in ("failure","cancelled","timed_out") else Y)
    print(f"  {B}Run#{r['id']}{N}  {color}{conclusion or status}{N}")
    print(f"  {'Created:':14} {created}")
    print(f"  {'Updated:':14} {updated}")
    print(f"  {'Branch:':14} {r.get('head_branch','?')}")
    print(f"  {'Commit:':14} {r.get('head_commit',{}).get('message','?')[:60]}")
    print(f"  {'URL:':14} {r.get('html_url','')}")
    print()
    if conclusion != "success" and status != "completed":
        _ok("Still running — use 'proxy247 test' to monitor live")

def cmd_test(args):
    deps = load_deployments()
    if args.name not in deps:
        _fail(f"Deployment '{args.name}' not found")
        _say(f"Available: {', '.join(sorted(deps.keys()))}"); return
    info = deps[args.name]
    accounts = load_accounts()
    token = accounts.get(info["account"], {}).get("token")
    if not token: _fail(f"Account '{info['account']}' not found"); return
    owner, repo_name = info["account"], args.name
    _hline
    _say(f"Testing: {C}{owner}/{repo_name}{N}")
    _say(f"{C}▸{N} Dispatching workflow ...")
    _trigger_workflow(token, owner, repo_name)
    _say(f"{C}▸{N} Waiting for run to start ...")
    run_id = None
    for _ in range(12):
        time.sleep(5)
        runs = _api(token, "GET", f"/repos/{owner}/{repo_name}/actions/runs?per_page=1&status=queued")
        all_runs = runs.get("workflow_runs", [])
        if all_runs: run_id = all_runs[0]["id"]; break
    if not run_id:
        for _ in range(12):
            time.sleep(5)
            runs = _api(token, "GET", f"/repos/{owner}/{repo_name}/actions/runs?per_page=1")
            all_runs = runs.get("workflow_runs", [])
            if all_runs and all_runs[0]["status"] != "completed":
                run_id = all_runs[0]["id"]; break
    if not run_id:
        _fail("Could not detect a running workflow. Check:")
        _say(f"  https://github.com/{owner}/{repo_name}/actions"); return
    _ok(f"Run started #{run_id}")
    _say(f"{C}▸{N} Monitoring (every 15s) ...")
    last_status = ""
    for _ in range(40):
        time.sleep(15)
        run = _api(token, "GET", f"/repos/{owner}/{repo_name}/actions/runs/{run_id}")
        status = run.get("status", "?"); conclusion = run.get("conclusion")
        line = f"status: {status}" + (f", conclusion: {conclusion}" if conclusion else "")
        if line != last_status:
            _say(f"  {C}▸{N} {line}")
            last_status = line
        if status == "completed":
            passed = conclusion == "success"
            if passed:
                print(f"\n  {G}╭{'─'*46}╮{N}")
                print(f"  {G}│{N}  {B}✓ AUTOMATION TEST PASSED{N}{' ' * 22} {G}│{N}")
                print(f"  {G}│{N}  Check the log at the URL below{' ' * 16} {G}│{N}")
                print(f"  {G}╰{'─'*46}╯{N}")
            else:
                print(f"\n  {R}╭{'─'*46}╮{N}")
                print(f"  {R}│{N}  {B}✗ AUTOMATION TEST FAILED{N}{' ' * 22} {R}│{N}")
                print(f"  {R}│{N}  Conclusion: {conclusion:<32} {R}│{N}")
                print(f"  {R}╰{'─'*46}╯{N}")
            print(f"\n      {run.get('html_url', '')}\n"); return
    _warn("Timed out. Check manually:")
    _say(f"  https://github.com/{owner}/{repo_name}/actions\n")

def cmd_status(_args):
    accounts = load_accounts(); active = get_setting("active_account")
    deps = load_deployments()
    _header("System Status")
    _say(f"{'Active account:':18} {C}{active or 'none'}{N}")
    _say(f"{'Accounts:':18} {len(accounts)}")
    _say(f"{'Deployments:':18} {len(deps)}")
    print()
    if not deps: _warn("No deployments. Use 'proxy247 deploy'"); return
    stale = []
    for name, info in sorted(deps.items()):
        accounts_data = load_accounts()
        token = accounts_data.get(info["account"], {}).get("token")
        status_str = "?"
        if token:
            try:
                _api(token, "GET", f"/repos/{info['account']}/{name}")
                runs = _api(token, "GET", f"/repos/{info['account']}/{name}/actions/runs?per_page=1")
                for r in runs.get("workflow_runs", []):
                    status_str = r.get("conclusion") or r.get("status", "?")
            except SystemExit:
                status_str = f"{R}deleted{N}"
                stale.append(name)
            except Exception:
                status_str = f"{R}err{N}"
        color = G if status_str == "success" else (Y if status_str in ("in_progress","queued","pending") else R)
        print(f"  {color}{'●':3}{N} {B}{name}{N}")
        print(f"      {'Account:':12} {info.get('account','?'):15} {'SB URL:':8} {str(info.get('key','?'))[:30]}")
        print(f"      {'Status:':12} {color}{status_str}{N}")
        print(f"      {'URL:':12} {info.get('repo_url','')}")
        print()
    if stale:
        for name in stale:
            del deps[name]
        save_deployments(deps)
        _warn(f"Cleaned {len(stale)} stale deployment(s): {', '.join(stale)}")


# ── Menu system ──────────────────────────────────────────

def _summary_block():
    accounts = load_accounts(); active = get_setting("active_account")
    deps = load_deployments()
    _hline
    a = f"accounts: {len(accounts)}  ({G}{active}{N} active)" if active else f"accounts: {len(accounts)}  ({R}none active{N})"
    _say(f"{'  📦':4} {a}   |   deployments: {len(deps)}")
    _hline

def _menu_accounts():
    while True:
        accounts = load_accounts(); active = get_setting("active_account")
        _header("👤 Account Management")
        if accounts:
            _say(f"  Active: {G if active else ''}{active or 'none'}{N}")
            _dash
            for name in sorted(accounts.keys()):
                mark  = f"{G}●{N}" if name == active else f"{D}○{N}"
                extra = f"  {G}(active){N}" if name == active else ""
                _say(f"  {mark} {B}{name}{N}{extra}")
            _dash
        else:
            _warn("No accounts configured.")
        print()
        choice = _choose(["📋 List accounts", "🔑 Login with token", "➕ Add account", "🔀 Switch account", "🗑 Remove account"])
        if choice < 0: return
        if choice == 0:
            cmd_account_list(None); _pause()
        elif choice == 1:
            cmd_login(argparse.Namespace(token=None)); _pause()
        elif choice == 2:
            name = _prompt("Account name") or "default"
            token = _prompt("GitHub token (classic PAT, repo scope)")
            cmd_account_add(argparse.Namespace(name=name, token=token)); _pause()
        elif choice == 3:
            if not accounts: _warn("No accounts."); _pause(); continue
            _say(f"Available: {', '.join(accounts.keys())}")
            name = _prompt("Switch to")
            cmd_account_switch(argparse.Namespace(name=name))
        elif choice == 4:
            if not accounts: _warn("No accounts."); _pause(); continue
            name = _prompt("Account to remove")
            cmd_account_remove(argparse.Namespace(name=name))

def _menu_deployments():
    while True:
        deps = load_deployments(); active = get_setting("active_account")
        _header("🚀 Deployment Management")
        _say(f"  Deployments: {len(deps)}  |  Active account: {G if active else ''}{active or 'none'}{N}")
        if deps:
            _dash
            for name, info in sorted(deps.items()):
                key = info.get('key', '?')
                print(f"  {C}■{N} {B}{name}{N}  ({C}{key}{N})  →  {D}{info.get('account','?')}{N}")
            _dash
        print()
        choice = _choose(["📋 List deployments", "🚀 Deploy new hunter", "📦 Bulk deploy",
                          "📈 Analytics", "★ Premium count", "🧪 Test deployment",
                          "🔍  Check latest run",
                          "⏹  Stop hunter", "▶️  Start hunter",
                          "🗑 Remove deployment", "⚡ Quick deploy (bare-bones)",
                          "🔄  Update template on ALL repos",
                          "💥 Nuke all repos"])
        if choice < 0: return
        if choice == 0:
            cmd_deploy_list(None); _pause()
        elif choice == 1:
            cmd_deploy(argparse.Namespace(name=None, key=None,
                        supabase_url=None, supabase_key=None, supabase_secret=None)); _pause()
        elif choice == 2:
            cmd_bulk_deploy(argparse.Namespace(count=None,
                            supabase_url=None, supabase_key=None, supabase_secret=None)); _pause()
        elif choice == 3:
            cmd_db_premium(None); _pause()
        elif choice in (4, 5, 6, 7, 8):
            if not deps: _warn("No deployments."); _pause(); continue
            if len(deps) == 1:
                name = next(iter(deps))
            else:
                _say(f"\n  Deployments: {', '.join(sorted(deps.keys()))}")
                name = _prompt("Deployment name")
            if choice == 4: cmd_analytics(argparse.Namespace(name=name, aggregate=False)); _pause()
            elif choice == 5: cmd_test(argparse.Namespace(name=name))
            elif choice == 6: cmd_check(argparse.Namespace(name=name)); _pause()
            elif choice == 7: cmd_stop(argparse.Namespace(name=name))
            elif choice == 8: cmd_start(argparse.Namespace(name=name))
            elif choice == 9: cmd_deploy_remove(argparse.Namespace(name=name))
        elif choice == 10:
            accts = load_accounts()
            if not accts: _warn("No accounts. Add one first."); _pause(); continue
            name = _prompt("Repo name (enter for random)")
            cmd_deploy(argparse.Namespace(name=name or None,
                        supabase_url=None, supabase_key=None, supabase_secret=None)); _pause()
        elif choice == 11:
            cmd_deploy_update(argparse.Namespace(name=None,
                        supabase_url=None, supabase_key=None, supabase_secret=None)); _pause()
        elif choice == 12:
            cmd_nuke_all(None); _pause()

def cmd_wizard(_args):
    if not _STDIN_TTY:
        _fail("Interactive menu requires a terminal.")
        _say("Use CLI flags instead:")
        _say("  proxy247 account add default --token ghp_xxxxx")
        _say("  proxy247 deploy new --name my-hunter --supabase-url ...")
        return
    try:
        _run_menu()
    except KeyboardInterrupt:
        print(f"\n  {Y}Bye.{N}\n")
    except SystemExit:
        pass

def _run_menu():
    while True:
        accounts = load_accounts(); active = get_setting("active_account")
        deps = load_deployments()
        print(f"\n  {C}╭{'─'*44}╮{N}")
        print(f"  {C}│{N}   {B}proxy247 v{VERSION}{N}  —  {D}VPLink Proxy Hunter Manager{N}  {C}│{N}")
        print(f"  {C}╰{'─'*44}╯{N}")
        _summary_block()
        print()
        choice = _choose([
            f"👤  Account Management      {D}{len(accounts)} account(s){N}",
            f"🚀  Deployment Management   {D}{len(deps)} deployment(s){N}",
            f"📊  Status & Monitoring     {D}live workflow health{N}",
            f"🗄️  Database Config         {D}persistent Supabase credentials{N}",
            f"📈  Analytics & Reports     {D}views, destinations, success/fail{N}",
            f"📖  Help / All Commands     {D}CLI reference{N}",
        ])
        if choice < 0:
            print(f"  {Y}Bye.{N}\n"); break
        if choice == 0:      _menu_accounts()
        elif choice == 1:    _menu_deployments()
        elif choice == 2:    cmd_status(None); _pause()
        elif choice == 3:    cmd_db_configure(None); _pause()
        elif choice == 4:    cmd_analytics(argparse.Namespace(name=None, aggregate=True)); _pause()
        elif choice == 5:
            _header("📖 CLI Reference")
            print(f"    {C}proxy247{N}                   Interactive menu (this)")
            print(f"    {C}proxy247 setup{N}             Same as above")
            print(f"    {C}proxy247 account add{N}        Add a GitHub account")
            print(f"    {C}proxy247 account list{N}       List accounts")
            print(f"    {C}proxy247 account switch{N}     Switch active account")
            print(f"    {C}proxy247 account remove{N}     Remove an account")
            print(f"    {C}proxy247 deploy new{N}         Create a new deployment")
            print(f"    {C}proxy247 deploy bulk{N}        Bulk-deploy N hunters")
            print(f"    {C}proxy247 deploy list{N}         List deployments")
            print(f"    {C}proxy247 deploy remove{N}       Remove a deployment")
            print(f"    {C}proxy247 deploy nuke-all{N}     Delete ALL repos + records")
            print(f"    {C}proxy247 deploy update{N}       Re-deploy updated template to repos")
            print(f"    {C}proxy247 test <name>{N}         Test a deployment (dispatch + monitor)")
            print(f"    {C}proxy247 check <name>{N}        Check latest run status (no dispatch)")
            print(f"    {C}proxy247 stop <name>{N}         Stop (disable) hunter")
            print(f"    {C}proxy247 start <name>{N}        Start (enable) hunter")
            print(f"    {C}proxy247 db config{N}           Set Supabase credentials (persistent)")
            print(f"    {C}proxy247 db show{N}             Show current DB config")
            print(f"    {C}proxy247 db premium{N}          Count premium proxies in DB")
            print(f"    {C}proxy247 analytics{N}             Aggregate analytics across all deployments")
            print(f"    {C}proxy247 analytics <name>{N}      Analytics for a single deployment")
            print(f"    {C}proxy247 status{N}               Show overall status")
            print()
            print(f"  {B}Flags:{N}")
            print(f"    account add default {C}--token ghp_xxxxx{N}")
            print(f"    login {C}ghp_xxxxx{N}")
            print(f"    deploy new {C}--name my-hunter --supabase-url ...{N}")
            print(f"      {C}--supabase-url <url> --supabase-key <key>{N}")
            print(f"      {C}--supabase-secret <secret>{N}")
            _pause()


# ── Main entry point ─────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="proxy247",
        description="VPLink Proxy Hunter Deployer & Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  proxy247                       Interactive management menu
  proxy247 account add           Add a GitHub account
  proxy247 account list          List all accounts
  proxy247 deploy new            Deploy hunter relay
  proxy247 deploy bulk <N>       Bulk-deploy N automations
  proxy247 deploy list           List deployments
  proxy247 deploy remove <name>  Remove a deployment
  proxy247 deploy nuke-all       Delete ALL repos + records
  proxy247 deploy update [name]  Re-deploy updated template to repos
  proxy247 test <name>           Test (dispatch + monitor)
  proxy247 check <name>          Check latest run (no dispatch)
  proxy247 stop <name>           Stop (disable) hunter
  proxy247 start <name>          Start (enable) hunter
  proxy247 db config            Set Supabase credentials (persistent)
  proxy247 db show              Show current DB config
  proxy247 db premium           Count premium proxies in DB
  proxy247 analytics            Aggregate analytics across all deployments
  proxy247 analytics <name>     Analytics for a single deployment
  proxy247 status               Show overall status
        """
    )
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("setup", aliases=["menu"], help="Interactive management menu")
    p.set_defaults(func=cmd_wizard)

    acct = sub.add_parser("account", help="Manage GitHub accounts")
    acct_sub = acct.add_subparsers(dest="subcmd")
    p = acct_sub.add_parser("add", help="Add a GitHub account")
    p.add_argument("name", nargs="?", help="Account name")
    p.add_argument("--token", help="GitHub personal access token")
    p.set_defaults(func=cmd_account_add)
    p = acct_sub.add_parser("list", help="List accounts")
    p.set_defaults(func=cmd_account_list)
    p = acct_sub.add_parser("switch", help="Switch active account")
    p.add_argument("name", nargs="?", help="Account name")
    p.set_defaults(func=cmd_account_switch)
    p = acct_sub.add_parser("remove", help="Remove an account")
    p.add_argument("name", help="Account name")
    p.set_defaults(func=cmd_account_remove)

    dep = sub.add_parser("deploy", help="Deploy hunter")
    dep_sub = dep.add_subparsers(dest="subcmd")
    p = dep_sub.add_parser("new", aliases=["create"], help="Create a new deployment")
    p.add_argument("--name", help="Repository name (default: random)")
    p.add_argument("--supabase-url", help="Supabase project URL")
    p.add_argument("--supabase-key", help="Supabase anon key")
    p.add_argument("--supabase-secret", help="Supabase service key")
    p.set_defaults(func=cmd_deploy)
    p = dep_sub.add_parser("bulk", help="Bulk-deploy multiple hunters")
    p.add_argument("count", nargs="?", type=int, help="Number of hunters to create")
    p.add_argument("--supabase-url", help="Supabase project URL")
    p.add_argument("--supabase-key", help="Supabase anon key")
    p.add_argument("--supabase-secret", help="Supabase service key")
    p.set_defaults(func=cmd_bulk_deploy)
    p = dep_sub.add_parser("list", help="List deployments")
    p.set_defaults(func=cmd_deploy_list)
    p = dep_sub.add_parser("remove", help="Remove a deployment")
    p.add_argument("name", help="Deployment name")
    p.set_defaults(func=cmd_deploy_remove)
    p = dep_sub.add_parser("nuke-all", aliases=["nuke"], help="Delete ALL deployed repos")
    p.set_defaults(func=cmd_nuke_all)
    p = dep_sub.add_parser("update", aliases=["upgrade"], help="Re-deploy updated template to existing repos")
    p.add_argument("name", nargs="?", help="Deployment name (omit for all)")
    p.add_argument("--supabase-url", help="Supabase project URL")
    p.add_argument("--supabase-key", help="Supabase anon key")
    p.add_argument("--supabase-secret", help="Supabase service key")
    p.set_defaults(func=cmd_deploy_update)

    p = sub.add_parser("test", help="Test a deployment")
    p.add_argument("name", help="Deployment name")
    p.set_defaults(func=cmd_test)

    p = sub.add_parser("db", help="Configure persistent Supabase database")
    db_sub = p.add_subparsers(dest="subcmd")
    p = db_sub.add_parser("config", help="Set database credentials")
    p.set_defaults(func=cmd_db_configure)
    p = db_sub.add_parser("show", help="Show current database config")
    p.set_defaults(func=cmd_db_show)
    p = db_sub.add_parser("premium", help="Count premium proxies (residential + VPLINK-verified)")
    p.set_defaults(func=cmd_db_premium)

    p = sub.add_parser("analytics", aliases=["stats"],
                       help="View analytics per deployment or full account")
    p.add_argument("name", nargs="?", help="Deployment name (omit for aggregate)")
    p.set_defaults(func=cmd_analytics)

    p = sub.add_parser("check", help="Check latest workflow run status (no dispatch)")
    p.add_argument("name", help="Deployment name")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("stop", help="Stop (disable) hunter for a deployment")
    p.add_argument("name", help="Deployment name")
    p.set_defaults(func=cmd_stop)

    p = sub.add_parser("start", help="Start (enable) hunter for a deployment")
    p.add_argument("name", help="Deployment name")
    p.set_defaults(func=cmd_start)

    p = sub.add_parser("login", help="Login with GitHub token (validates & saves)")
    p.add_argument("token", nargs="?", help="GitHub token")
    p.set_defaults(func=cmd_login)

    p = sub.add_parser("status", help="Show overall status")
    p.set_defaults(func=cmd_status)

    args = parser.parse_args()

    if not args.command:
        cmd_wizard(args)
        return

    if args.command == "deploy" and not getattr(args, "subcmd", None):
        args.func = cmd_deploy
    if args.command in ("analytics", "stats") and not getattr(args, "name", None):
        args.aggregate = True
    if args.command == "db" and not getattr(args, "subcmd", None):
        args.func = cmd_db_show

    try:
        args.func(args)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print(f"\n  {Y}Interrupted.{N}\n")
    except Exception as e:
        print(f"\n  {R}[!] Error:{N} {e}\n", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
