# PII Redactor

Bidirectional PII replacement: scrubs personally identifiable information from requests before they reach the LLM, then restores the originals in responses before they reach the user. The upstream model never sees real PII.

> **Not for production use.** The regex patterns are simplistic and will miss many PII forms (non-Western names, various phone formats, addresses, national IDs). A production redactor should use a dedicated NER model (spaCy, Presidio, or a cloud DLP API). The mapping is also stored in memory and lost on restart.

## What it does

- Hooks both `http-request` and `http-response`, filtered to known LLM API hosts with JSON content type
- Detects names (capitalized word pairs), email addresses, US SSNs, and US phone numbers
- Replaces each unique PII value with a stable placeholder (`PERSON_A`, `EMAIL_B`, `SSN_C`, etc.)
- On responses, replaces placeholders back with the original values
- The mapping is maintained in memory for the lifetime of the process

## Example

Request (what the app sends):
```
Summarize the case file for John Doe (john.doe@example.com, SSN 123-45-6789)
```

What the LLM sees:
```
Summarize the case file for PERSON_A (EMAIL_A, SSN_A)
```

Response from LLM:
```
PERSON_A's case file contains three documents filed under SSN_A.
```

What the app receives:
```
John Doe's case file contains three documents filed under 123-45-6789.
```

## Run

```bash
uv run middleware.py
```

```bash
greyproxy serve --middleware ws://localhost:9000/middleware
```
