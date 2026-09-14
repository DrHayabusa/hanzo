# Wordlists

Twelve bundled adapters take a `wordlist` argument (gobuster, ffuf, dirb, dirsearch,
feroxbuster, wfuzz, arjun, dnsenum and others). Their upstream defaults point at Kali
paths such as `/usr/share/wordlists/dirb/common.txt`. On any host without that file the
scanner fails with a confusing error, so HANZO offers the lists that actually exist.

## What HANZO does

- Discovery walks a set of roots and lists every readable, non-empty `.txt`, `.lst`,
  `.dic`, `.words` or `.wordlist` file it finds. Nothing is invented: with no wordlist
  installed the catalog is empty and says so.
- Each wordlist field in the command launcher gets a dropdown of those files, grouped
  (web content, DNS, usernames, passwords, API, fuzzing, network) and ranked so the
  closest match to the adapter default comes first.
- The field stays a normal text box, so **any custom path can be typed** instead.
- If the adapter default is not present on the worker, HANZO substitutes a real list and
  says so in the field note rather than silently sending a path that cannot work.

## Search roots

In order of preference:

1. `HANZO_WORDLIST_DIRS` — your own directories, separated by `:`
2. `<project>/wordlists` — a project-local clone, never committed
3. `/usr/share/wordlists`, `/usr/share/seclists`, `/opt/SecLists`, `/opt/seclists`,
   `/usr/share/dirb/wordlists`, `/usr/share/dirbuster/wordlists`,
   `/usr/share/wfuzz/wordlist`, `/usr/share/metasploit-framework/data/wordlists`,
   `/usr/local/share/wordlists`

## Installing

```bash
bash scripts/install_wordlists.sh          # apt seclists on Kali, else a clone
bash scripts/install_wordlists.sh --apt    # force the Kali package
bash scripts/install_wordlists.sh --opt    # clone into /opt/SecLists
bash scripts/install_wordlists.sh --project # clone into ./wordlists/SecLists
```

On Kali the package is the right choice:

```bash
sudo apt-get install -y seclists
```

A full SecLists checkout needs roughly **1 GB unpacked, and about 2.3 GB during a git
clone** before the `.git` directory is removed. Check free space first; a clone that runs
out of disk leaves a partial checkout. Keeping only `Discovery` and `Usernames` is enough
for web application work and costs about 550 MB.

## API

```
GET  /api/arsenal/wordlists            # grouped catalog of what exists
GET  /api/arsenal/wordlists?refresh=1  # bypass the discovery cache
POST /api/arsenal/wordlists/resolve    # {"path": "..."} -> exists / readable / error
```

## MCP

The central facade exposes the same information to an agent:

- `list_wordlists(group, contains, limit)` — discovered lists, filtered
- `check_wordlist(path)` — confirm a path before running a tool with it

Both report the real state of the worker. A wordlist that is not there is reported as
missing, never as ready.
