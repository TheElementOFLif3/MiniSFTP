
<img width="958" height="910" alt="SCR-20251211-syjc" src="https://github.com/user-attachments/assets/2cdd4960-9dc3-4239-afd4-f8281e0260e9" />

# Mini FTP / SFTP Client (macOS)

Minimalistic FTP / SFTP (SSH) client written in Python with a simple GUI.
This project is intentionally **primitive and lightweight**, designed for quick file transfers without heavy dependencies or complex UI.

## ✨ Features

- FTP support
- SFTP (SSH) support
- Upload files to server
- Download files from server
- Directory listing
- Create folders
- Rename files and folders
- Delete files and folders
- Back / Forward directory navigation
- Upload queue
- Transfer progress indicator
- Connection profiles
- Password storage via system keyring (if available)
- macOS native `.pkg` installer

## ⚠️ Project Status

This is an **early-stage / primitive client**.

- No advanced optimizations
- No resume support yet
- No parallel transfers
- Minimal error handling by design

The goal is **simplicity**, not to compete with FileZilla or WinSCP.

## 🖥 Supported Platforms

- ✅ macOS (Apple Silicon & Intel)
- 🚧 Windows version **planned** (coming later)
- 🚫 Linux version not planned at the moment

## 📦 Installation (macOS)

Download the installer from GitHub Releases:

1. Download `Mini_FTP_Client.pkg`
2. Double-click the installer
3. Follow the standard macOS installation steps

If macOS shows a security warning:
- Right-click the installer
- Choose **Open**
- Confirm installation

## 🔐 Security Notice

- Passwords are stored only if you enable **"Remember password"**
- Storage uses the system keyring when available
- No passwords are logged or transmitted elsewhere

## 🛠 Technology Stack

- Python 3
- Tkinter GUI
- Paramiko (SFTP / SSH)
- ftplib (FTP)
- PyInstaller (macOS app bundling)

## 📌 Why this project exists

I needed:
- A **small**
- **fast**
- **no-nonsense**
FTP/SFTP client for internal use (servers, containers, labs)

So I built one.

## 🧭 Roadmap

- [ ] Windows `.exe` installer
- [ ] Drag & drop improvements
- [ ] Better error reporting
- [ ] UI polish
- [ ] Transfer resume

## 📄 License

This project is provided **as-is**, without warranty.
Use it at your own risk.

---

