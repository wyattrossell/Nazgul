# Nazgul plugins

Each `*.json` file here describes an external command-line tool. Nazgul runs it, captures its
output, and turns every line (or JSON item) into a finding inside the active case.

The tool itself is not bundled. Install it yourself (most are `pip install ...`) and make sure
the command is on your PATH. Nazgul also reads manifests from
`%APPDATA%\com.nazgul.app\plugins\` so you can add your own without touching the repo.

Fields:

| Field | Meaning |
|---|---|
| `name` | Shown in the Plugins tab. Must be unique. |
| `inputTypes` | Entity types this tool accepts: username, email, phone, domain, ip, wallet, url. |
| `command` | Executable name or full path. |
| `args` | Arguments. `{input}` is replaced with what you typed. |
| `parse` | `lines` (default) or `json` (an array of objects with `title`/`name`, `url`, `exists`). |
| `foundMarker` | In `lines` mode, lines containing this string count as hits. Default `[+]`. |
| `timeoutSecs` | Kill the tool after this long. Default 300. |
