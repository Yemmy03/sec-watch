**What each folder is for**

**.github/workflows/ holds security-watch.yml**, the GitHub Actions workflow. It runs watch.py on a schedule (9 AM, 2 PM and 7 PM Lagos time) or when you start it manually.

**tests/ holds test_watch.py**, the automated checks for watch.py. They run on fake data and never touch Slack or your real alert history.

**state/ holds state.json**, the script’s memory of what it has already reported, so nothing is alerted twice. It isn’t stored on main. The workflow keeps it on a separate branch called security-state and loads it into state/ at the start of each run. You’ll only see this folder locally if you clone that branch.


**What each file is for**

**watch.py** is the scanner. It reads your inventory, checks public vulnerability sources (OSV, NVD, CISA KEV, cve.now and others), and posts findings to Slack. It also generates the monthly overview.

**inventory.yml** lists everything you use: packages and versions, tools, aliases, news keywords and the team registry. Each entry also says which team owns it.

**requirements.txt** lists the Python libraries watch.py needs (requests and pyyaml). The workflow installs them on every run.

**.github/workflows/security-watch.yml** is the GitHub Actions workflow. It sets the schedule, runs watch.py, loads and saves the state, and alerts Slack if a run fails.

**tests/test_watch.p**y is the set of automated checks for watch.py. It’s optional and doesn’t affect the scheduled runs.

**state/state.json** is the script’s memory of what it has already reported, so nothing is alerted twice. It lives on the security-state branch rather than on main.
