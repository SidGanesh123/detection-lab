# Command-Line Obfuscation Detection

Scored KQL detection for obfuscated command lines on Windows endpoints.

| | |
| --- | --- |
| **Table** | `DeviceProcessEvents` (Defender for Endpoint) |
| **MITRE** | T1027.010 — Command Obfuscation · T1059 — Command and Scripting Interpreter |
| **Status** | Experimental — UNTESTED (as of 10/18/2026) |
| **Tests** | `../tests/commandline_obfuscation_vectors.md` |

**Status: not yet executed/tested.** The vectors are written but have not been run —
I don't currently have a tenant or sandbox with the telemetry to validate
against

## Why this isn't a keyword list

Signature detection for obfuscation loses by construction, the attacker's whole
goal is to make the keyword unmatchable. `"has "powershell"` is defeated by
`p^o^w^e^r^s^h^e^l^l`, same technique, zero behavioural change.

So this rule doesn't look for bad strings. It looks for the **structural
fingerprint of a string that has been deliberately altered**, and it scores
several weak signals rather than trusting any single one.

## Signals

| ID | Signal | Weight | What it catches |
| --- | --- | --- | --- |
| **SIG-A** | Revealed keyword after de-obfuscation | 6 | Strips escape/concat characters, then checks whether a suspicious keyword appears that wasn't visible in the raw string |
| **SIG-B** | Encoded-command flag | 4 | `-EncodedCommand` and every valid abbreviation (`-e`, `-en`, `-enc`…) followed by a base64 blob (utilizes RegEx)|
| **SIG-D** | Env-var substring construction | 4 | `%PROGRAMDATA:~0,1%` style slicing, assembling a word from pieces of legitimate variables |
| **SIG-C** | Long base64 blob | 3 | 60+ base64-alphabet characters anywhere in the line |
| **SIG-E** | Character-code reassembly | 3 | `[char]`, `[convert]::`, `-join` — building a string from numeric codes (Concat)|
| **SIG-F** | Format operator / reversal | 2 | `-f` reordering, `[-1..-100]`, `::Reverse` (Reorder) |


### The two signals that matter most

**SIG-A is the core idea.** A keyword that only exists *after* de-obfuscation
has no legitimate explanation — there is no reason to hide a word from a parser
that is about to execute it anyway. 

**SIG-D covers the case SIG-A can't.** Where SIG-A reveals a word hiding behind
escape characters, SIG-D catches a technique where the word is never in the
string at all — it's assembled at runtime from substrings of environment
variables.

## Known limitations

- **Threshold is uncalibrated.** Chosen so SIG-A fires alone and no pair of weak
  signals can. First step with real telemetry: run as a hunt, histogram the
  scores, set the cut-off where the benign-positive rate is acceptable.
- **Command lines only.** Obfuscation inside a downloaded script body never
  touches a command line. Partner detection is script-block logging, **Event ID 4104**.
- **Weak signals can stack past the threshold** without any technique signal
  matching. 