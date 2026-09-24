Review the source tree in the current working directory for security vulnerabilities that an external attacker could actually exploit.

Do not modify any application source. Do not install packages. Do not clone other repositories. Do not search the public internet for the project name.

Write findings only to this absolute path (create or overwrite that file, nothing else):

__FINDINGS_PATH__

The file must be a single JSON object, no markdown, no prose around it:

{
  "findings": [
    {
      "title": "short title",
      "file": "path/relative/to/cwd.py",
      "line_start": 1,
      "line_end": 1,
      "vuln_class": "sql_injection",
      "cwe": "CWE-89",
      "severity": "high",
      "description": "What is wrong, why it is reachable, and what an attacker controls."
    }
  ]
}

Rules:
- `file` is repo-relative (for example `app/views.py`), never a basename-only guess if the file lives in a subdirectory.
- `line_start` and `line_end` are 1-based source lines you actually read.
- `cwe` is required (`CWE-` plus digits). Omit the finding if you cannot pin a file, line range, and CWE.
- Report concrete bugs, not style or missing headers. Omit hardening notes.
- If you find nothing, write `{"findings": []}`.
