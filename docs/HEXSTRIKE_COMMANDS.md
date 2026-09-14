# HexStrike GUI command reference

Generated from the bundled route definitions: **90 commands / 10 categories**. This is API coverage, not proof that all binaries are installed or all commands have been executed.

Open **Security tools**, choose a category and command, review the generated fields and exact request, then confirm your own scope. Advanced arguments remain powerful; review tool documentation and output. Conditional parameters are still backend-validated. The separate inventory includes names without a tool POST endpoint; the GUI does not invent endpoints for those.

## Network & infrastructure

| Command | API endpoint | Input fields |
| --- | --- | --- |
| arp-scan | `/api/tools/arp-scan` | `target`,`interface`,`local_network`,`timeout`,`retry`,`additional_args` |
| autorecon | `/api/tools/autorecon` | `target`*,`output_dir`,`port_scans`,`service_scans`,`heartbeat`,`timeout`,`additional_args` |
| enum4linux | `/api/tools/enum4linux` | `target`*,`additional_args` |
| enum4linux-ng | `/api/tools/enum4linux-ng` | `target`*,`username`,`password`,`domain`,`shares`,`users`,`groups`,`policy`,`additional_args` |
| masscan | `/api/tools/masscan` | `target`*,`ports`,`rate`,`interface`,`router_mac`,`source_ip`,`banners`,`additional_args` |
| nbtscan | `/api/tools/nbtscan` | `target`*,`verbose`,`timeout`,`additional_args` |
| netexec | `/api/tools/netexec` | `target`*,`protocol`,`username`,`password`,`hash`,`module`,`additional_args` |
| nmap | `/api/tools/nmap` | `target`*,`scan_type`,`ports`,`additional_args`,`use_recovery` |
| nmap-advanced | `/api/tools/nmap-advanced` | `target`*,`scan_type`,`ports`,`timing`,`nse_scripts`,`os_detection`,`version_detection`,`aggressive`,`stealth`,`additional_args` |
| responder | `/api/tools/responder` | `interface`*,`analyze`,`wpad`,`force_wpad_auth`,`fingerprint`,`duration`,`additional_args` |
| rpcclient | `/api/tools/rpcclient` | `target`*,`username`,`password`,`domain`,`commands`,`additional_args` |
| rustscan | `/api/tools/rustscan` | `target`*,`ports`,`ulimit`,`batch_size`,`timeout`,`scripts`,`additional_args` |
| smbmap | `/api/tools/smbmap` | `target`*,`username`,`password`,`domain`,`additional_args` |

## Reconnaissance & discovery

| Command | API endpoint | Input fields |
| --- | --- | --- |
| amass | `/api/tools/amass` | `domain`*,`mode`,`additional_args` |
| dnsenum | `/api/tools/dnsenum` | `domain`*,`dns_server`,`wordlist`,`additional_args` |
| fierce | `/api/tools/fierce` | `domain`*,`dns_server`,`additional_args` |
| gau | `/api/tools/gau` | `domain`*,`providers`,`include_subs`,`blacklist`,`additional_args` |
| hakrawler | `/api/tools/hakrawler` | `url`*,`depth`,`forms`,`robots`,`sitemap`,`wayback`,`additional_args` |
| httpx | `/api/tools/httpx` | `target`*,`probe`,`tech_detect`,`status_code`,`content_length`,`title`,`web_server`,`threads`,`additional_args` |
| katana | `/api/tools/katana` | `url`*,`depth`,`js_crawl`,`form_extraction`,`output_format`,`additional_args` |
| paramspider | `/api/tools/paramspider` | `domain`*,`level`,`exclude`,`output`,`additional_args` |
| subfinder | `/api/tools/subfinder` | `domain`*,`silent`,`all_sources`,`additional_args` |
| waybackurls | `/api/tools/waybackurls` | `domain`*,`get_versions`,`no_subs`,`additional_args` |

## Web application testing

| Command | API endpoint | Input fields |
| --- | --- | --- |
| arjun | `/api/tools/arjun` | `url`*,`method`,`wordlist`,`delay`,`threads`,`stable`,`additional_args` |
| browser-agent | `/api/tools/browser-agent` | `action`,`url`*,`headless`,`wait_time`,`proxy_port`,`active_tests` |
| burpsuite-alternative | `/api/tools/burpsuite-alternative` | `target`*,`scan_type`,`headless`,`max_depth`,`max_pages` |
| dalfox | `/api/tools/dalfox` | `url`,`pipe_mode`,`blind`,`mining_dom`,`mining_dict`,`custom_payload`,`additional_args` |
| dirb | `/api/tools/dirb` | `url`*,`wordlist`,`additional_args` |
| dirsearch | `/api/tools/dirsearch` | `url`*,`extensions`,`wordlist`,`threads`,`recursive`,`additional_args` |
| dotdotpwn | `/api/tools/dotdotpwn` | `target`*,`module`,`additional_args` |
| feroxbuster | `/api/tools/feroxbuster` | `url`*,`wordlist`,`threads`,`additional_args` |
| ffuf | `/api/tools/ffuf` | `url`*,`wordlist`,`mode`,`match_codes`,`additional_args` |
| gobuster | `/api/tools/gobuster` | `url`*,`mode`,`wordlist`,`additional_args`,`use_recovery` |
| http-framework | `/api/tools/http-framework` | `action`,`url`*,`method`,`data`,`headers`,`cookies`,`max_depth`,`max_pages`,`rules`,`host`*,`include_subdomains`,`request`,`location`,`params`,`payloads`,`base_data`,`max_requests` |
| jaeles | `/api/tools/jaeles` | `url`*,`signatures`,`config`,`threads`,`timeout`,`additional_args` |
| nikto | `/api/tools/nikto` | `target`*,`additional_args` |
| nuclei | `/api/tools/nuclei` | `target`*,`severity`,`tags`,`template`,`additional_args`,`use_recovery` |
| sqlmap | `/api/tools/sqlmap` | `url`*,`data`,`additional_args` |
| wafw00f | `/api/tools/wafw00f` | `target`*,`additional_args` |
| wfuzz | `/api/tools/wfuzz` | `url`*,`wordlist`,`additional_args` |
| wpscan | `/api/tools/wpscan` | `url`*,`additional_args` |
| x8 | `/api/tools/x8` | `url`*,`wordlist`,`method`,`body`,`headers`,`additional_args` |
| xsser | `/api/tools/xsser` | `url`*,`params`,`additional_args` |
| zap | `/api/tools/zap` | `target`,`scan_type`,`api_key`,`daemon`,`port`,`host`,`format`,`output_file`,`additional_args` |

## API & token analysis

| Command | API endpoint | Input fields |
| --- | --- | --- |
| api fuzzer | `/api/tools/api_fuzzer` | `base_url`*,`endpoints`,`methods`,`wordlist` |
| api schema analyzer | `/api/tools/api_schema_analyzer` | `schema_url`*,`schema_type` |
| graphql scanner | `/api/tools/graphql_scanner` | `endpoint`*,`introspection`,`query_depth`,`test_mutations` |
| jwt analyzer | `/api/tools/jwt_analyzer` | `jwt_token`*,`target_url` |

## Cloud, containers & IaC

| Command | API endpoint | Input fields |
| --- | --- | --- |
| checkov | `/api/tools/checkov` | `directory`,`framework`,`check`,`skip_check`,`output_format`,`additional_args` |
| clair | `/api/tools/clair` | `image`*,`config`,`output_format`,`additional_args` |
| cloudmapper | `/api/tools/cloudmapper` | `action`,`account`,`config`,`additional_args` |
| docker-bench-security | `/api/tools/docker-bench-security` | `checks`,`exclude`,`output_file`,`additional_args` |
| falco | `/api/tools/falco` | `config_file`,`rules_file`,`output_format`,`duration`,`additional_args` |
| kube-bench | `/api/tools/kube-bench` | `targets`,`version`,`config_dir`,`output_format`,`additional_args` |
| kube-hunter | `/api/tools/kube-hunter` | `target`,`remote`,`cidr`,`interface`,`active`,`report`,`additional_args` |
| pacu | `/api/tools/pacu` | `session_name`,`modules`,`data_services`,`regions`,`additional_args` |
| prowler | `/api/tools/prowler` | `provider`,`profile`,`region`,`checks`,`output_dir`,`output_format`,`additional_args` |
| scout-suite | `/api/tools/scout-suite` | `provider`,`profile`,`report_dir`,`services`,`exceptions`,`additional_args` |
| terrascan | `/api/tools/terrascan` | `scan_type`,`iac_dir`,`policy_type`,`output_format`,`severity`,`additional_args` |
| trivy | `/api/tools/trivy` | `scan_type`,`target`*,`output_format`,`severity`,`output_file`,`additional_args` |

## Password auditing

| Command | API endpoint | Input fields |
| --- | --- | --- |
| hashcat | `/api/tools/hashcat` | `hash_file`*,`hash_type`*,`attack_mode`,`wordlist`,`mask`,`additional_args` |
| hashpump | `/api/tools/hashpump` | `signature`,`data`,`key_length`,`append_data`,`additional_args` |
| hydra | `/api/tools/hydra` | `target`,`service`,`username`,`username_file`,`password`,`password_file`,`additional_args` |
| john | `/api/tools/john` | `hash_file`*,`wordlist`,`format`,`additional_args` |

## Binary analysis & debugging

| Command | API endpoint | Input fields |
| --- | --- | --- |
| angr | `/api/tools/angr` | `binary`*,`script_content`,`find_address`,`avoid_addresses`,`analysis_type`,`additional_args` |
| binwalk | `/api/tools/binwalk` | `file_path`*,`extract`,`additional_args` |
| checksec | `/api/tools/checksec` | `binary`* |
| gdb | `/api/tools/gdb` | `binary`*,`commands`,`script_file`,`additional_args` |
| gdb-peda | `/api/tools/gdb-peda` | `binary`,`commands`,`attach_pid`,`core_file`,`additional_args` |
| ghidra | `/api/tools/ghidra` | `binary`*,`project_name`,`script_file`,`analysis_timeout`,`output_format`,`additional_args` |
| libc-database | `/api/tools/libc-database` | `action`,`symbols`,`libc_id`,`additional_args` |
| objdump | `/api/tools/objdump` | `binary`*,`disassemble`,`additional_args` |
| one-gadget | `/api/tools/one-gadget` | `libc_path`*,`level`,`additional_args` |
| pwninit | `/api/tools/pwninit` | `binary`*,`libc`,`ld`,`template_type`,`additional_args` |
| pwntools | `/api/tools/pwntools` | `script_content`,`target_binary`,`target_host`,`target_port`,`exploit_type`,`additional_args` |
| radare2 | `/api/tools/radare2` | `binary`*,`commands`,`additional_args` |
| ropgadget | `/api/tools/ropgadget` | `binary`*,`gadget_type`,`additional_args` |
| ropper | `/api/tools/ropper` | `binary`*,`gadget_type`,`quality`,`arch`,`search_string`,`additional_args` |
| strings | `/api/tools/strings` | `file_path`*,`min_len`,`additional_args` |
| xxd | `/api/tools/xxd` | `file_path`*,`offset`,`length`,`additional_args` |

## Forensics & file analysis

| Command | API endpoint | Input fields |
| --- | --- | --- |
| exiftool | `/api/tools/exiftool` | `file_path`*,`output_format`,`tags`,`additional_args` |
| foremost | `/api/tools/foremost` | `input_file`*,`output_dir`,`file_types`,`additional_args` |
| steghide | `/api/tools/steghide` | `action`,`cover_file`*,`embed_file`*,`passphrase`,`output_file`,`additional_args` |
| volatility | `/api/tools/volatility` | `memory_file`*,`plugin`*,`profile`,`additional_args` |
| volatility3 | `/api/tools/volatility3` | `memory_file`*,`plugin`*,`output_file`,`additional_args` |

## Advanced lab simulation

| Command | API endpoint | Input fields |
| --- | --- | --- |
| metasploit | `/api/tools/metasploit` | `module`*,`options` |
| msfvenom | `/api/tools/msfvenom` | `payload`*,`format`,`output_file`,`encoder`,`iterations`,`additional_args` |

## Data utilities

| Command | API endpoint | Input fields |
| --- | --- | --- |
| anew | `/api/tools/anew` | `input_data`*,`output_file`,`additional_args` |
| qsreplace | `/api/tools/qsreplace` | `urls`*,`replacement`,`additional_args` |
| uro | `/api/tools/uro` | `urls`*,`whitelist`,`blacklist`,`additional_args` |

An asterisk marks an inferred non-empty requirement. Fields may be conditional on another option. Read the route and upstream tool help when using advanced operations.
