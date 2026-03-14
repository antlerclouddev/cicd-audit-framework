# GitHub Setup Guide — Push Your Project & Make It Public

This guide picks up after WORKFLOW-GUIDE.md Phase 5 (tool is installed
and tests pass). It walks you from zero GitHub knowledge to having your
project live on github.com.

---

## PART 1 — Create a GitHub Account (skip if you have one)

1. Go to https://github.com
2. Click **Sign up**
3. Choose a username (this appears on your profile — pick something professional,
   e.g. your name or business name)
4. Verify your email address

---

## PART 2 — Install Git on Fedora 43

```bash
# Check if git is already installed
git --version
```

If you see `git version 2.x.x` you can skip to Part 3.
If you see `command not found`:

```bash
sudo dnf install git -y
git --version   # confirm it worked
```

---

## PART 3 — Tell Git Who You Are

Git needs a name and email for every commit (a save point in your code history).
This only needs to be done once on your machine.

```bash
git config --global user.name "Your Full Name"
git config --global user.email "you@example.com"
```

Use the same email you registered on GitHub.

Verify:
```bash
git config --list | grep user
```
Expected:
```
user.name=Your Full Name
user.email=you@example.com
```

---

## PART 4 — Set Up Authentication (How Your Machine Proves It's You)

GitHub no longer accepts passwords for pushing code. You need either
a **Personal Access Token (PAT)** or **SSH keys**.

PAT is easier for beginners. SSH is better long-term. Do one of them.

---

### Option A — Personal Access Token (PAT) — Easier

1. Log in to github.com
2. Click your profile photo (top right) → **Settings**
3. Scroll down the left sidebar → **Developer settings**
4. Click **Personal access tokens** → **Tokens (classic)**
5. Click **Generate new token** → **Generate new token (classic)**
6. Give it a name like `fedora-laptop`
7. Set expiration to 90 days (or No expiration for convenience)
8. Check the box for **repo** (this gives full access to your repos)
9. Click **Generate token** at the bottom
10. **Copy the token immediately** — you can only see it once.
    It looks like: `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx`
11. Save it somewhere safe (password manager, or a text file NOT in the project)

When git asks for your password, paste this token instead.

**Make git remember it** so you don't type it every time:

```bash
git config --global credential.helper store
```

The first time you push, you'll type your GitHub username and paste the token.
After that, git remembers it automatically.

---

### Option B — SSH Keys — More Secure, No Typing After Setup

```bash
# 1. Generate an SSH key pair (press Enter for all prompts to use defaults)
ssh-keygen -t ed25519 -C "you@example.com"

# 2. Start the SSH agent
eval "$(ssh-agent -s)"

# 3. Add your key to the agent
ssh-add ~/.ssh/id_ed25519

# 4. Copy your PUBLIC key to the clipboard
cat ~/.ssh/id_ed25519.pub
# Highlight all the output and copy it
```

Now add it to GitHub:
1. github.com → profile photo → **Settings**
2. Left sidebar → **SSH and GPG keys**
3. Click **New SSH key**
4. Title: `fedora-laptop`
5. Paste the key into the Key field
6. Click **Add SSH key**

Test it:
```bash
ssh -T git@github.com
```
Expected:
```
Hi YOUR_USERNAME! You've successfully authenticated...
```

---

## PART 5 — Create the Repository on GitHub

1. Go to https://github.com/new
2. **Repository name:** `cicd-audit-framework`
3. **Description:** `Automated security and efficiency auditor for GitHub Actions and GitLab CI pipelines`
4. Set visibility to **Public** (so clients can see it as a portfolio piece)
5. **Do NOT check** "Add a README" — you already have one
6. **Do NOT check** "Add .gitignore" — you already have one
7. Click **Create repository**

GitHub shows you a page with setup instructions. You can ignore it —
your commands below do the same thing.

---

## PART 6 — Connect Your Local Project to GitHub and Push

Open your terminal. Make sure you are in the project folder with the venv active:

```bash
cd ~/projects/cicd-audit-framework
source .venv/bin/activate
```

### If using PAT (HTTPS):

```bash
# 1. Initialise git in the project folder
git init

# 2. Stage all files for the first commit
git add .

# 3. Make the first commit
git commit -m "Initial commit: CI/CD audit framework with 6 checks and HTML reporting"

# 4. Rename the default branch to 'main'
git branch -M main

# 5. Connect to your GitHub repo (replace YOUR_USERNAME)
git remote add origin https://github.com/YOUR_USERNAME/cicd-audit-framework.git

# 6. Push your code to GitHub
git push -u origin main
```

When prompted:
- Username: your GitHub username
- Password: paste your PAT token (not your GitHub password)

### If using SSH:

```bash
git init
git add .
git commit -m "Initial commit: CI/CD audit framework with 6 checks and HTML reporting"
git branch -M main
git remote add origin git@github.com:YOUR_USERNAME/cicd-audit-framework.git
git push -u origin main
```

No username/password prompt — SSH handles it automatically.

---

## PART 7 — Verify It Worked

1. Go to `https://github.com/YOUR_USERNAME/cicd-audit-framework`
2. You should see all your files including `cicd_auditor/`, `samples/`, `README.md`
3. GitHub will render your `README.md` beautifully on the front page —
   this is what clients see

---

## PART 8 — Watch the Self-Audit GitHub Action Run

The project includes `.github/workflows/audit.yml` which runs the
audit tool on every push. GitHub will have already triggered it.

1. On your repo page, click the **Actions** tab
2. You'll see a workflow run called "CI/CD Audit + Tests"
3. Click it to watch it run live
4. When it finishes (green checkmark = pass), click on the `audit` job
5. You'll see the score printed in the logs
6. Click **Summary** → **Artifacts** → download `audit-report-<sha>` to get the HTML report

---

## PART 9 — Future Pushes (Day-to-Day)

After the first push, updating GitHub is just three commands:

```bash
# Stage your changes
git add .

# Describe what you changed
git commit -m "Add check for missing CODEOWNERS file"

# Push to GitHub
git push
```

That's it. GitHub Actions will automatically re-run the audit on every push.

---

## PART 10 — Share Your Profile With Clients

Your portfolio URL is:
```
https://github.com/YOUR_USERNAME
```

Your specific project URL is:
```
https://github.com/YOUR_USERNAME/cicd-audit-framework
```

Put both in your:
- Email signature
- LinkedIn profile (under Featured or Experience)
- Any proposal or quote you send to clients
- Your personal website if you have one

---

## Quick Reference — Git Commands You'll Use Every Day

| Command | What it does |
|---------|-------------|
| `git status` | Shows what files have changed since the last commit |
| `git add .` | Stages ALL changed files for the next commit |
| `git add filename` | Stages one specific file |
| `git commit -m "message"` | Saves a snapshot with a description |
| `git push` | Sends your commits to GitHub |
| `git pull` | Gets the latest changes from GitHub |
| `git log --oneline` | Shows your commit history (one line each) |

---

## Glossary

| Term | Meaning |
|------|---------|
| Repository (repo) | A project folder tracked by git |
| Commit | A saved snapshot of your code at a point in time |
| Push | Upload your local commits to GitHub |
| Pull | Download changes from GitHub to your machine |
| Branch | A parallel version of your code (main is the default) |
| PAT | Personal Access Token — a password substitute for git |
| SSH key | A cryptographic key pair for passwordless authentication |
| Public repo | Visible to everyone on the internet |
| Private repo | Only visible to you and invited collaborators |
