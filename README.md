**What each folder is for**

**.github/workflows/ holds security-watch.yml**, the GitHub Actions workflow. It runs watch.py on a schedule (9 AM, 2 PM and 7 PM Lagos time) or when you start it manually.

**tests/ holds test_watch.py**, the automated checks for watch.py. They run on fake data and never touch Slack or your real alert history.

**state/ holds state.json**, the script’s memory of what it has already reported, so nothing is alerted twice. It isn’t stored on main. The workflow keeps it on a separate branch called security-state and loads it into state/ at the start of each run. You’ll only see this folder locally if you clone that branch.

----------------------------------------------------------------------------------------------------

**What each file is for**

**watch.py** is the scanner. It reads your inventory, checks public vulnerability sources (OSV, NVD, CISA KEV, cve.now and others), and posts findings to Slack. It also generates the monthly overview.

**inventory.yml** lists everything you use: packages and versions, tools, aliases, news keywords and the team registry. Each entry also says which team owns it.

**requirements.txt** lists the Python libraries watch.py needs (requests and pyyaml). The workflow installs them on every run.

**.github/workflows/security-watch.yml** is the GitHub Actions workflow. It sets the schedule, runs watch.py, loads and saves the state, and alerts Slack if a run fails.

**tests/test_watch.p**y is the set of automated checks for watch.py. It’s optional and doesn’t affect the scheduled runs.

**state/state.json** is the script’s memory of what it has already reported, so nothing is alerted twice. It lives on the security-state branch rather than on main.


----------------------------------------------------------------------------------------------------

**How to replicate Security Watch, step by step**
1. Decide what to watch. List every package, tool and service you use, with versions. This becomes inventory.yml. The scanner only works against this list.

2. Add owners. Create a team registry at the top of inventory.yml and tag each item with its team(s). This is how alerts say who should act.

3. Pick your public sources. The data comes from free feeds: OSV (package advisories), CISA KEV (vulnerabilities known to be exploited), NVD (severity scores), cve.now (fresh CVEs) and the npm registry (version lookups). No code of yours is ever read.

4. Write the scanner (watch.py). 
In order, it:
->loads the inventory and resolves version ranges;
->asks the sources what’s vulnerable;
->matches advisories to your inventory, rejecting look-alikes like a WordPress plugin with “Express” in its name;
->formats each finding as the 8 fixed fields (Find in the last section the 8 fixed fields).

5. Give it a memory (state.json). After each run, save what you’ve already reported so nothing is announced twice. The first run is a silent “baseline” that records everything and sends nothing.

6. Connect Slack. Create an incoming webhook in Slack and store its URL as a GitHub secret named SLACK_WEBHOOK_URL. Never paste it into code.

7. Schedule it with GitHub Actions. The workflow file runs watch.py at set times, keeps the state on a separate security-state branch, and pings Slack if a run fails.

8. Add safety rules. News mode only reports scores of 9.5 or higher, capped at 20 items. A monthly overview counts each CVE once.

9. Test it. Write automated checks with fake data (tests/test_watch.py) so later edits can’t quietly bring old bugs back.

10. Dry run first. Run python watch.py --dry-run locally to see the report without posting anything, then switch the schedule on.

----------------------------------------------------------------------------------------------------

Each finding in the report has a CVE line as its header, followed by these **eight fields** in this order:

**Severity** is how serious the flaw is, for example “High (CVSS 7.5)”. It can also include the EPSS exploit-likelihood score.

**Affected technology** names the package and version from your inventory. It ends with either “Confirmed match in the inventory.” or “Unverified match in the inventory.”, which says how solid the match is. Neither one proves the version is running in production.

**Affected team/s** lists the owners from your inventory, or “Unmapped” if none is recorded.

**Potential impact** is a short summary of what the flaw allows.

**Relevance** says why it matters to the named teams and asks them to check four things: whether it’s deployed, whether the version is affected, whether the vulnerable feature is on, and whether a fix is needed.

**Exploitation status** is one of two exact phrases: “Actively exploited in the wild” (when it is on CISA KEV) or “Cannot confirm actively exploited in the wild status”.

**Recommended action** gives next steps, such as verify, upgrade to the fixed version if the advisory names one, or apply mitigations.

**Source** has links to the advisory.
