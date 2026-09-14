"""Read-only catalog of the bundled HexStrike /api/tools POST adapters.

Metadata is extracted from source, never by importing or executing a tool.
Presence is not a functional test. Conditional parameters remain backend-validated.
"""
import ast
import shutil
from functools import lru_cache
from pathlib import Path


GROUPS = {
    "network": ("Network & infrastructure", "nmap nmap-advanced rustscan masscan autorecon enum4linux enum4linux-ng netexec smbmap rpcclient nbtscan arp-scan responder"),
    "recon": ("Reconnaissance & discovery", "amass subfinder fierce dnsenum gau waybackurls katana hakrawler httpx paramspider"),
    "web": ("Web application testing", "gobuster nuclei dirb nikto sqlmap wpscan ffuf feroxbuster dotdotpwn xsser wfuzz dirsearch arjun x8 jaeles dalfox http-framework browser-agent burpsuite-alternative zap wafw00f"),
    "api": ("API & token analysis", "api_fuzzer graphql_scanner jwt_analyzer api_schema_analyzer"),
    "cloud": ("Cloud, containers & IaC", "prowler trivy scout-suite cloudmapper pacu kube-hunter kube-bench docker-bench-security clair falco checkov terrascan"),
    "password": ("Password auditing", "hydra john hashcat hashpump"),
    "binary": ("Binary analysis & debugging", "gdb radare2 binwalk ropgadget checksec xxd strings objdump ghidra pwntools one-gadget libc-database gdb-peda angr ropper pwninit"),
    "forensics": ("Forensics & file analysis", "volatility volatility3 foremost steghide exiftool"),
    "simulation": ("Advanced lab simulation", "metasploit msfvenom"),
    "utilities": ("Data utilities", "anew qsreplace uro"),
}
ALIASES = {"nmap-advanced":"nmap", "scout-suite":"scout", "metasploit":"msfconsole", "volatility":"volatility",
           "volatility3":"vol", "one-gadget":"one_gadget", "ropgadget":"ROPgadget", "ghidra":"analyzeHeadless",
           "gdb-peda":"gdb", "libc-database":"find", "zap":"zap.sh", "enum4linux-ng":"enum4linux-ng"}
# These require Python/browser/runtime checks rather than a fabricated executable.
COMPOSITE = {"http-framework", "browser-agent", "burpsuite-alternative", "api_fuzzer", "graphql_scanner",
             "jwt_analyzer", "api_schema_analyzer", "pwntools", "angr", "gdb-peda", "libc-database", "cloudmapper"}


def literal(node, fallback=None):
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        return fallback


@lru_cache(maxsize=4)
def _schemas(filename, modified):
    tree = ast.parse(Path(filename).read_text(encoding="utf-8"))
    commands = []
    for fn in tree.body:
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        routes = []
        for decorator in fn.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute) or decorator.func.attr != "route" or not decorator.args:
                continue
            route = literal(decorator.args[0], "")
            methods = next((literal(k.value, []) for k in decorator.keywords if k.arg == "methods"), [])
            if isinstance(route, str) and route.startswith("/api/tools/") and "POST" in methods:
                routes.append(route)
        if not routes:
            continue
        fields, variable_fields = {}, {}
        calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and n.func.attr == "get" and isinstance(n.func.value, ast.Name)
                 and n.func.value.id in {"params", "data"} and n.args and isinstance(literal(n.args[0]), str)]
        for node in sorted(calls, key=lambda n:n.lineno):
            name = literal(node.args[0])
            default = literal(node.args[1]) if len(node.args) > 1 else None
            dtype = "bool" if isinstance(default, bool) else "int" if isinstance(default, int) else "float" if isinstance(default, float) else "array" if isinstance(default, list) else "object" if isinstance(default, dict) else "str"
            fields.setdefault(name, {"name":name, "type":dtype, "default":default, "required":False})
            for assign in ast.walk(fn):
                if isinstance(assign, ast.Assign) and assign.value is node:
                    for target in assign.targets:
                        if isinstance(target, ast.Name): variable_fields[target.id] = name
        for node in ast.walk(fn):
            if isinstance(node, ast.If) and isinstance(node.test, ast.UnaryOp) and isinstance(node.test.op, ast.Not) and isinstance(node.test.operand, ast.Name):
                name = variable_fields.get(node.test.operand.id)
                # Mark only direct empty-value guards, not alternative/conditional routes.
                if name in fields and any(isinstance(child, ast.Return) and isinstance(child.value, ast.Tuple)
                                          and any(literal(value) == 400 for value in child.value.elts)
                                          for child in node.body):
                    fields[name]["required"] = True
        for endpoint in routes:
            tool = endpoint.removeprefix("/api/tools/")
            group = next((key for key, (_, names) in GROUPS.items() if tool in names.split()), "utilities")
            commands.append({"id":tool, "label":tool.replace("_", " "), "endpoint":endpoint, "tool":ALIASES.get(tool,tool),
                             "fields":list(fields.values()), "description":ast.get_docstring(fn) or f"HexStrike {tool} adapter", "category":group,
                             "schema_source":"Bundled route source; conditional arguments are validated by the adapter."})
    return commands


def build_catalog(project_dir):
    source = Path(project_dir) / "hexstrike_server.py"
    commands = _schemas(str(source), source.stat().st_mtime_ns)
    categories = []
    for key, (label, _) in GROUPS.items():
        items = []
        for spec in commands:
            if spec["category"] == key:
                item = dict(spec)
                item["installed"] = None if item["id"] in COMPOSITE else bool(shutil.which(item["tool"]))
                item["readiness"] = "runtime_check_required" if item["installed"] is None else "executable_present" if item["installed"] else "not_installed"
                items.append(item)
        if items: categories.append({"id":key, "label":label, "commands":sorted(items, key=lambda x:x["label"])})
    return {"categories":categories, "command_count":len(commands), "category_count":len(categories),
            "message":"Every bundled /api/tools POST adapter is listed. Inventory-only binaries are not invented API commands. Presence is not execution validation."}
