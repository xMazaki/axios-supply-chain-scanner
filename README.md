# axios-supply-chain-scanner

Scanner for the axios npm supply chain attack disclosed on 2026-03-31.

Checks Docker containers and bare Linux hosts for indicators of compromise related to the `axios@1.14.1` / `axios@0.30.4` / `plain-crypto-js@4.2.1` RAT dropper. Read-only — the script makes no changes to your system.

---

## Background

On March 31, 2026, two malicious versions of axios were published to npm using the compromised credentials of the project's lead maintainer. Both versions injected a hidden dependency — `plain-crypto-js@4.2.1` — whose sole purpose was to run a `postinstall` script deploying a cross-platform remote access trojan (RAT) targeting macOS, Windows, and Linux.

The malware connected to a C2 server (`sfrclak.com:8000`), downloaded platform-specific payloads, then self-deleted and replaced its own `package.json` with a clean copy to evade detection.

**Compromised versions**

| Package | Version |
|---|---|
| axios | 1.14.1 |
| axios | 0.30.4 |
| plain-crypto-js | 4.2.1 |
| @shadanai/openclaw | 2026.3.28-2, 2026.3.28-3, 2026.3.31-1, 2026.3.31-2 |
| @qqbrowser/openclaw-qbot | 0.0.130 |

**Safe versions:** `axios@1.14.0` (1.x) and `axios@0.30.3` (0.x)

---

## What the scanner checks

- Presence of `node_modules/plain-crypto-js` (presence alone is sufficient evidence of compromise)
- axios version installed in `node_modules`
- `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` for IOC strings
- Secondary malicious packages (`@shadanai/openclaw`, `@qqbrowser/openclaw-qbot`)
- Active or recent network connections to the C2 domain
- Leftover RAT artifacts in `/tmp` and `/var/tmp`

If Docker is running, each live container is scanned individually. If not, the script falls back to scanning the host filesystem across standard project directories.

---

## Usage

```bash
# download
curl -O https://raw.githubusercontent.com/xMazaki/axios-supply-chain-scanner/main/axios-scan.sh

# run as root for full filesystem access
chmod +x axios-scan.sh
sudo bash axios-scan.sh
```

No dependencies beyond bash and standard Debian/Ubuntu utilities (`find`, `grep`, `ss`). Docker CLI is used only if available.

---

## Output

```
  axios supply chain attack — scanner
  2026-03-31 | read-only, no changes made

>>  Docker containers detected — scanning each one

  [OK]      [my-api] clean
             axios installed: 1.14.0
  [HIT]     [my-frontend] node_modules/plain-crypto-js found — dropper likely executed
             path: /app/node_modules/plain-crypto-js
  [HIT]     [my-frontend] axios@1.14.1 installed (compromised version)

>>  Network — C2 indicator check (host)

  [OK]      No active C2 connections detected

--------------------------------------------------------------------------------
  SCAN COMPLETE
  Findings : 2
  Warnings : 0
--------------------------------------------------------------------------------

  SYSTEM LIKELY COMPROMISED — recommended actions:

  1.  Assume all credentials on this system are stolen
      Rotate: SSH keys, API tokens, DB passwords, cloud IAM, env vars
  ...
```

---

## If you get a hit

The RAT self-deletes after execution. Finding `node_modules/plain-crypto-js` in your container or on the host means the dropper already ran — even if there's no other visible trace.

**Immediate steps:**

1. Rotate all credentials accessible from the affected machine (SSH keys, API tokens, cloud credentials, database passwords, environment variables)
2. Downgrade axios — `npm install axios@1.14.0` (1.x) or `npm install axios@0.30.3` (0.x)
3. Block the C2 at network level — `iptables -A OUTPUT -d sfrclak.com -j DROP`
4. Audit CI/CD pipeline runs between `2026-03-31 00:21 UTC` and `03:15 UTC` — any build that ran `npm install` during that window may have distributed the compromised package to production
5. Consider a full rebuild of affected containers or machines — the filesystem state cannot be fully trusted after a self-erasing RAT

---

## Notes

The malware self-destructs and replaces its `package.json` after execution. A negative scan result does not guarantee a clean system if you ran `npm install` between `2026-03-31 00:21 UTC` and `03:15 UTC`. In that case, rotating credentials is recommended regardless.

---

## References

- [StepSecurity — full technical analysis](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)
- [Socket — malware analysis](https://socket.dev/blog/axios-npm-package-compromised)
- [GitHub issue — axios/axios#10604](https://github.com/axios/axios/issues/10604)
- [The Hacker News](https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html)

---

## License

MIT
