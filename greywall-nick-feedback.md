# Greywall Feedback from Nick (April 7, 2026)

Source: `#internalai>user feedback` topic in Zulip

---

## Pain Points

1. **Dotfiles Access Required**
   - Greywall needs at least read access to `~/.*` dotfiles or a lot of stuff will fail
   - Without dotfiles, package caches, git config, etc., most dev processes would fail

2. **Filesystem Deny-by-Default Too Restrictive**
   - "seems like most dev processes would fail with that model"
   - User basically never wants filesystem blocking, otherwise they can't do anything useful (can't read dotfiles, use git, launch processes like chomer, etc.)

3. **No Clear Way to Stop greyproxy**
   - greyproxy not listed in `brew services`
   - Users don't know how to stop the service

4. **Root Certificate Installation Without Warning**
   - Installed a rootcert on computer without warning
   - "our internal security team will yell at me / ban the tool if they see that happen without warning"

5. **Learning Mode Confusing**
   - After running `--learning`, unclear what happens next
   - Screenshot shows it seems to "launch after that" but user not certain

6. **Profile System Unclear**
   - Network rules not saved in profile file (`greywall profile show codex`)
   - User asked "where do these get saved" - answered "in a db for greyproxy"
   - Confusion around execution-time vs profile-based rules

---

## Bugs Reports

1. **Code Snippet Error on Marketing Site**
   - Should be `--learn` but marketing site shows something else
   - Screenshot shows incorrect code snippet

2. **Broken Documentation Links**
   - https://github.com/GreyhavenHQ/greyproxy#documentation returns 404

3. **Localhost Connections Fails**
   - Connecting to devservers spawned by the agent fails
   - Should auto-allow connection to `127.0.0.1:*` if the process listening on that socket is a subprocess of the codex/claude/sandbox process

---

## Feature Requests / Proposals

1. **Sudo Permission Warning**
   - When greywall requests `sudo` permissions, should show a line explaining what it needs it for
   - Example: `[greywall] Requesting sudo permission (needed for network and filesystem filtering using SomeAppleXyzApiFramework)`

2. **Option to Unblock All Filesystem at Startup**
   - Add an option at startup when asking what profile to want to unblock all filesystem access
   - User request: "can you add an option at startup when it asks what profile you want to unblock all filesystem access?"

3. **Filesystem Watch Without Blocking**
   - "are you able to watch filesystem access without blocking? even thats good enough"
   - Would accept observability over blocking

4. **Better Profile Persistence**
   - Suggestion for two commands:
     ```
     # block nothing, show me everything and let me choose yes/no
     greywatch --learn --profile=abc codex ...

     # run in locked down mode using the profile
     greywall --profile=abc codex ...
     ```
   - Separation between "learning/watch" mode and "blocking" mode

5. **AI Bot for GitHub Issues**
   - Request for AI bot that can make GitHub issues
   - Reference to Linear bot: `@linear make a ticket for this an assign to me, include all the context from this thread + the screenshots`

6. **Zulip Enhancement**
   - "damn zulip needs to add a `copy messages as markdown` here"

7. **Unified UI Architecture**
   - Suggestion: host on separate port and iframe in unified UI
   - Alternative: separate watch mode vs block mode in UI

---

## Feedback Summary

- **Primary frustration**: Filesystem deny-by-default is too restrictive for development use
- **Adoption concern**: "I don't see a proper path to remove it honestly, because EVERY setup is different, and security standard is different to everyone"
- **Security concern**: Root cert installation needs warning for enterprise users
- **Learning curve**: Profile system and rules storage is confusing
