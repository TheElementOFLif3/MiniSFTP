#!/usr/bin/env python3
import os
import json
import posixpath
from ftplib import FTP
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk

# Optional: SFTP (paramiko)
try:
    import paramiko
except ImportError:
    paramiko = None

# Optional: secure password storage (keyring)
try:
    import keyring
except ImportError:
    keyring = None

# Optional: drag & drop support (tkinterdnd2)
try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
except ImportError:
    TkinterDnD = None
    DND_FILES = None

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".mini_ftp_client_config.json")
KEYRING_SERVICE = "MiniFTPClient"


class MiniFTPClientApp:
    def __init__(self):
        # Root window (with optional drag & drop support)
        if TkinterDnD is not None:
            self.root = TkinterDnD.Tk()
        else:
            self.root = tk.Tk()

        self.root.title("Mini FTP/SFTP Client")

        # Internal state
        self.proto = "ftp"
        self.ftp_conn = None
        self.ssh_transport = None
        self.sftp_conn = None

        self.upload_queue = []  # list of local file paths
        self.is_uploading = False

        # Directory history: for Back/Forward navigation
        self.history = []
        self.history_index = -1

        # Profiles
        self.profiles = {}
        self.current_profile_name = tk.StringVar()

        self._build_ui()
        self._wire_events()
        self.load_config()

    # ==========================
    # UI
    # ==========================

    def _build_ui(self):
        root = self.root

        # Profiles row
        frame_profiles = tk.Frame(root)
        frame_profiles.grid(row=0, column=0, columnspan=4, sticky="we", padx=5, pady=5)
        tk.Label(frame_profiles, text="Profile:").pack(side=tk.LEFT)

        self.profile_combo = ttk.Combobox(frame_profiles, width=20, state="readonly")
        self.profile_combo.pack(side=tk.LEFT, padx=3)

        self.entry_profile_name = tk.Entry(frame_profiles, width=18)
        self.entry_profile_name.pack(side=tk.LEFT, padx=3)

        self.btn_profile_save = tk.Button(
            frame_profiles, text="Save profile", command=self.save_profile
        )
        self.btn_profile_save.pack(side=tk.LEFT, padx=2)

        self.btn_profile_delete = tk.Button(
            frame_profiles, text="Delete profile", command=self.delete_profile
        )
        self.btn_profile_delete.pack(side=tk.LEFT, padx=2)

        # Protocol
        self.protocol_var = tk.StringVar(value="ftp")
        frame_proto = tk.Frame(root)
        frame_proto.grid(row=1, column=0, columnspan=4, sticky="w", padx=5, pady=5)
        tk.Label(frame_proto, text="Protocol:").pack(side=tk.LEFT)
        tk.Radiobutton(
            frame_proto, text="FTP", variable=self.protocol_var, value="ftp"
        ).pack(side=tk.LEFT)
        tk.Radiobutton(
            frame_proto, text="SFTP (SSH)", variable=self.protocol_var, value="sftp"
        ).pack(side=tk.LEFT)

        # Host / IP
        tk.Label(root, text="Host / IP:").grid(
            row=2, column=0, sticky="e", padx=5, pady=3
        )
        self.entry_host = tk.Entry(root, width=30)
        self.entry_host.grid(row=2, column=1, columnspan=3, padx=5, pady=3, sticky="we")

        # Port
        tk.Label(root, text="Port:").grid(row=3, column=0, sticky="e", padx=5, pady=3)
        self.entry_port = tk.Entry(root, width=10)
        self.entry_port.insert(0, "21")
        self.entry_port.grid(row=3, column=1, sticky="w", padx=5, pady=3)

        # Username
        tk.Label(root, text="Username:").grid(
            row=4, column=0, sticky="e", padx=5, pady=3
        )
        self.entry_user = tk.Entry(root, width=30)
        self.entry_user.grid(row=4, column=1, columnspan=3, padx=5, pady=3, sticky="we")

        # Password
        tk.Label(root, text="Password:").grid(
            row=5, column=0, sticky="e", padx=5, pady=3
        )
        self.entry_pass = tk.Entry(root, width=30, show="*")
        self.entry_pass.grid(row=5, column=1, columnspan=3, padx=5, pady=3, sticky="we")

        self.remember_var = tk.BooleanVar(value=True)
        self.chk_remember = tk.Checkbutton(
            root,
            text="Remember password (keyring if available)",
            variable=self.remember_var,
        )
        self.chk_remember.grid(row=6, column=1, columnspan=3, sticky="w", padx=5)

        # Remote folder
        tk.Label(root, text="Remote folder:").grid(
            row=7, column=0, sticky="e", padx=5, pady=3
        )
        self.entry_remote = tk.Entry(root, width=30)
        self.entry_remote.grid(
            row=7, column=1, columnspan=3, padx=5, pady=3, sticky="we"
        )

        # Local files
        tk.Label(root, text="Local file(s):").grid(
            row=8, column=0, sticky="e", padx=5, pady=3
        )
        self.entry_file = tk.Entry(root, width=30)
        self.entry_file.grid(row=8, column=1, padx=5, pady=3, sticky="we")
        self.btn_browse = tk.Button(root, text="Browse...", command=self.choose_files)
        self.btn_browse.grid(row=8, column=2, padx=5, pady=3, sticky="w")

        if TkinterDnD is not None:
            msg = "(You can also drag & drop files onto this window)"
        else:
            msg = "(Drag & drop available if 'tkinterdnd2' is installed)"
        self.label_dnd = tk.Label(root, text=msg, fg="#888")
        self.label_dnd.grid(row=9, column=1, columnspan=3, sticky="w", padx=5)

        # Main action buttons
        self.btn_connect = tk.Button(root, text="Connect", command=self.connect)
        self.btn_connect.grid(row=10, column=0, pady=8, padx=5, sticky="we")

        self.btn_upload = tk.Button(
            root, text="Upload queue", command=self.start_upload_queue
        )
        self.btn_upload.grid(row=10, column=1, pady=8, padx=5, sticky="we")

        self.btn_download = tk.Button(
            root, text="Download", command=self.download_selected
        )
        self.btn_download.grid(row=10, column=2, pady=8, padx=5, sticky="we")

        self.btn_refresh = tk.Button(
            root,
            text="Refresh list",
            command=lambda: self.refresh_list(update_history=True),
        )
        self.btn_refresh.grid(row=10, column=3, pady=8, padx=5, sticky="we")

        # Progress
        tk.Label(root, text="Transfer progress:").grid(
            row=11, column=0, columnspan=2, sticky="w", padx=5
        )
        self.progress = ttk.Progressbar(
            root, orient="horizontal", mode="determinate", maximum=100
        )
        self.progress.grid(row=12, column=0, columnspan=4, padx=5, pady=3, sticky="we")
        self.progress_label = tk.Label(root, text="0%")
        self.progress_label.grid(row=11, column=2, sticky="e", padx=5)

        # Navigation row: Back / Forward / Up, all same width
        frame_nav = tk.Frame(root)
        frame_nav.grid(row=13, column=0, columnspan=4, padx=5, pady=(2, 8), sticky="we")

        self.btn_back = tk.Button(frame_nav, text="← Back", command=self.go_back)
        self.btn_back.pack(side=tk.LEFT, expand=True, fill="x", padx=(0, 4))

        self.btn_forward = tk.Button(frame_nav, text="→ Forward", command=self.go_forward)
        self.btn_forward.pack(side=tk.LEFT, expand=True, fill="x", padx=4)

        self.btn_up = tk.Button(frame_nav, text="Up (..)", command=self.go_up_directory)
        self.btn_up.pack(side=tk.LEFT, expand=True, fill="x", padx=(4, 0))

        # Files list
        tk.Label(root, text="Files on server:").grid(
            row=14, column=0, columnspan=4, sticky="w", padx=5
        )
        self.files_list = tk.Listbox(
            root, width=80, height=14, selectmode=tk.EXTENDED
        )
        self.files_list.grid(
            row=15, column=0, columnspan=4, padx=5, pady=3, sticky="nsew"
        )

        # File operations
        frame_ops = tk.Frame(root)
        frame_ops.grid(row=16, column=0, columnspan=4, padx=5, pady=5, sticky="we")

        self.btn_delete = tk.Button(
            frame_ops, text="Delete selected", command=self.delete_selected
        )
        self.btn_delete.pack(side=tk.LEFT, padx=2)

        tk.Label(frame_ops, text="Rename to:").pack(side=tk.LEFT, padx=(10, 2))
        self.entry_rename = tk.Entry(frame_ops, width=18)
        self.entry_rename.pack(side=tk.LEFT, padx=2)
        self.btn_rename = tk.Button(
            frame_ops, text="Rename", command=self.rename_selected
        )
        self.btn_rename.pack(side=tk.LEFT, padx=2)

        tk.Label(frame_ops, text="New folder:").pack(side=tk.LEFT, padx=(10, 2))
        self.entry_new_folder = tk.Entry(frame_ops, width=18)
        self.entry_new_folder.pack(side=tk.LEFT, padx=2)
        self.btn_mkdir = tk.Button(
            frame_ops, text="Create", command=self.create_folder
        )
        self.btn_mkdir.pack(side=tk.LEFT, padx=2)

        # Log
        tk.Label(root, text="Log:").grid(
            row=17, column=0, columnspan=4, sticky="w", padx=5
        )
        self.text_log = tk.Text(root, width=80, height=8, state="disabled")
        self.text_log.grid(
            row=18, column=0, columnspan=4, padx=5, pady=3, sticky="nsew"
        )

        # Grid weights (for resizing)
        root.grid_rowconfigure(15, weight=1)
        root.grid_rowconfigure(18, weight=1)
        root.grid_columnconfigure(1, weight=1)
        root.grid_columnconfigure(2, weight=1)
        root.grid_columnconfigure(3, weight=1)

    def _wire_events(self):
        self.protocol_var.trace_add("write", self.on_protocol_change)
        self.files_list.bind("<Double-1>", self.on_item_double_click)

        # drag & drop
        if TkinterDnD is not None and DND_FILES is not None:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind("<<Drop>>", self.on_drop_files)

        self.profile_combo.bind("<<ComboboxSelected>>", self.on_profile_selected)

    # ==========================
    # Logging & progress
    # ==========================

    def log(self, msg: str):
        self.text_log.config(state="normal")
        self.text_log.insert(tk.END, msg + "\n")
        self.text_log.see(tk.END)
        self.text_log.config(state="disabled")

    def update_progress(self, percent: int, text: str = ""):
        self.progress["value"] = percent
        if text:
            self.progress_label.config(text=f"{percent}%  {text}")
        else:
            self.progress_label.config(text=f"{percent}%")
        self.root.update_idletasks()

    # ==========================
    # Config & profiles
    # ==========================

    def load_config(self):
        if not os.path.isfile(CONFIG_PATH):
            self.profiles = {}
            self._refresh_profile_combo()
            return

        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            self.log(f"[CONFIG] Error loading config: {e}")
            self.profiles = {}
            self._refresh_profile_combo()
            return

        self.profiles = data.get("profiles", {})
        current = data.get("current_profile")
        self._refresh_profile_combo()

        if current and current in self.profiles:
            self.profile_combo.set(current)
            self.apply_profile(current)

            # load password from keyring if possible
            if keyring is not None:
                prof = self.profiles[current]
                try:
                    key = self._keyring_key(
                        prof.get("protocol", "ftp"),
                        prof.get("host", ""),
                        prof.get("user", ""),
                    )
                    pwd = keyring.get_password(KEYRING_SERVICE, key)
                    if pwd:
                        self.entry_pass.insert(0, pwd)
                except Exception as e:
                    self.log(f"[KEYRING] Error reading password: {e}")

    def save_config(self, current_profile=None):
        if current_profile is None:
            current_profile = self.profile_combo.get().strip() or None

        data = {
            "profiles": self.profiles,
            "current_profile": current_profile,
        }
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.log(f"[CONFIG] Error writing config: {e}")

        # Save password to keyring
        if (
            keyring is not None
            and current_profile is not None
            and current_profile in self.profiles
        ):
            prof = self.profiles[current_profile]
            try:
                key = self._keyring_key(
                    prof.get("protocol", "ftp"),
                    prof.get("host", ""),
                    prof.get("user", ""),
                )
                if self.remember_var.get():
                    pwd = self.entry_pass.get()
                    if pwd:
                        keyring.set_password(KEYRING_SERVICE, key, pwd)
                else:
                    try:
                        keyring.delete_password(KEYRING_SERVICE, key)
                    except keyring.errors.PasswordDeleteError:
                        pass
            except Exception as e:
                self.log(f"[KEYRING] Error writing password: {e}")

    def _keyring_key(self, proto, host, user):
        return f"{proto}:{host}:{user}"

    def _refresh_profile_combo(self):
        names = sorted(self.profiles.keys())
        self.profile_combo["values"] = names
        if names and not self.profile_combo.get():
            self.profile_combo.set(names[0])

    def apply_profile(self, name: str):
        prof = self.profiles.get(name)
        if not prof:
            return
        self.protocol_var.set(prof.get("protocol", "ftp"))
        self.entry_host.delete(0, tk.END)
        self.entry_host.insert(0, prof.get("host", ""))

        self.entry_port.delete(0, tk.END)
        port = prof.get("port")
        if port:
            self.entry_port.insert(0, str(port))

        self.entry_user.delete(0, tk.END)
        self.entry_user.insert(0, prof.get("user", ""))

        self.entry_remote.delete(0, tk.END)
        self.entry_remote.insert(0, prof.get("remote_dir", ""))

    def on_profile_selected(self, event=None):
        name = self.profile_combo.get().strip()
        if name:
            self.apply_profile(name)
            self.save_config(name)

    def save_profile(self):
        name = self.entry_profile_name.get().strip() or self.profile_combo.get().strip()
        if not name:
            messagebox.showerror("Profile", "Please enter profile name.")
            return

        try:
            port_text = self.entry_port.get().strip()
            port = int(port_text) if port_text else None
        except ValueError:
            port = None

        self.profiles[name] = {
            "host": self.entry_host.get().strip(),
            "port": port,
            "user": self.entry_user.get().strip(),
            "remote_dir": self.entry_remote.get().strip(),
            "protocol": self.protocol_var.get(),
        }
        self._refresh_profile_combo()
        self.profile_combo.set(name)
        self.entry_profile_name.delete(0, tk.END)
        self.save_config(name)
        self.log(f"[PROFILE] Saved profile '{name}'.")

    def delete_profile(self):
        name = self.profile_combo.get().strip()
        if not name:
            messagebox.showinfo("Profile", "No profile selected.")
            return
        if not messagebox.askyesno("Delete profile", f"Delete profile '{name}'?"):
            return
        self.profiles.pop(name, None)
        self.profile_combo.set("")
        self._refresh_profile_combo()
        self.save_config(None)
        self.log(f"[PROFILE] Deleted profile '{name}'.")

    # ==========================
    # Protocol & connection
    # ==========================

    def on_protocol_change(self, *args):
        proto = self.protocol_var.get()
        self.proto = proto
        port_text = self.entry_port.get().strip()
        if proto == "ftp":
            if port_text in ("", "22"):
                self.entry_port.delete(0, tk.END)
                self.entry_port.insert(0, "21")
        else:
            if port_text in ("", "21"):
                self.entry_port.delete(0, tk.END)
                self.entry_port.insert(0, "22")

    def choose_files(self):
        paths = filedialog.askopenfilenames()
        if not paths:
            return
        self.upload_queue = list(paths)
        self.entry_file.delete(0, tk.END)
        if len(paths) == 1:
            self.entry_file.insert(0, paths[0])
        else:
            self.entry_file.insert(0, f"{paths[0]} (+{len(paths)-1} more)")
        self.log(f"[QUEUE] {len(paths)} file(s) added to upload queue.")

    def on_drop_files(self, event):
        raw = event.data
        if not raw:
            return
        paths = []
        for part in raw.split():
            part = part.strip()
            if part.startswith("{") and part.endswith("}"):
                part = part[1:-1]
            if os.path.isfile(part):
                paths.append(part)
        if not paths:
            return
        if not self.upload_queue:
            self.upload_queue = paths
        else:
            self.upload_queue.extend(paths)
        self.entry_file.delete(0, tk.END)
        if len(self.upload_queue) == 1:
            self.entry_file.insert(0, self.upload_queue[0])
        else:
            self.entry_file.insert(
                0, f"{self.upload_queue[0]} (+{len(self.upload_queue)-1} more)"
            )
        self.log(f"[QUEUE] {len(paths)} file(s) added via drag & drop.")

    def get_common_fields(self):
        host = self.entry_host.get().strip()
        port_text = self.entry_port.get().strip()
        user = self.entry_user.get().strip()
        pwd = self.entry_pass.get()
        remote_dir = self.entry_remote.get().strip()

        if not host or not user or not pwd:
            messagebox.showerror("Error", "Host, username and password are required.")
            return None

        try:
            port = int(port_text) if port_text else (21 if self.proto == "ftp" else 22)
        except ValueError:
            messagebox.showerror("Error", "Port must be a number.")
            return None

        return host, port, user, pwd, remote_dir

    def _close_connections(self):
        if self.ftp_conn is not None:
            try:
                self.ftp_conn.quit()
            except Exception:
                pass
        self.ftp_conn = None

        if self.sftp_conn is not None:
            try:
                self.sftp_conn.close()
            except Exception:
                pass
        self.sftp_conn = None

        if self.ssh_transport is not None:
            try:
                self.ssh_transport.close()
            except Exception:
                pass
        self.ssh_transport = None

    def connect(self):
        """User pressed Connect."""
        self._close_connections()
        self.proto = self.protocol_var.get()
        if self.proto == "ftp":
            self._connect_ftp(show_message=True)
        else:
            self._connect_sftp(show_message=True)

        # Save current profile
        current_profile = self.profile_combo.get().strip() or None
        self.save_config(current_profile)

    def ensure_connection(self):
        """Auto reconnect if needed."""
        self.proto = self.protocol_var.get()
        if self.proto == "ftp":
            if self.ftp_conn is None:
                self._connect_ftp(show_message=False)
        else:
            if self.sftp_conn is None:
                self._connect_sftp(show_message=False)

    def _connect_ftp(self, show_message: bool):
        fields = self.get_common_fields()
        if not fields:
            return
        host, port, user, pwd, remote_dir = fields
        try:
            ftp = FTP()
            ftp.connect(host, port, timeout=10)
            ftp.login(user, pwd)
            if remote_dir:
                ftp.cwd(remote_dir)
            path = ftp.pwd()
            self.entry_remote.delete(0, tk.END)
            self.entry_remote.insert(0, path)
            self.record_history(path)

            self.ftp_conn = ftp
            self.log(f"[FTP] Connected to {host}:{port} as {user}")
            if show_message:
                messagebox.showinfo("Connection", "FTP connection successful.")
        except Exception as e:
            self.log(f"[FTP] Connection error: {e}")
            if show_message:
                messagebox.showerror("FTP connection error", str(e))

    def _connect_sftp(self, show_message: bool):
        if paramiko is None:
            messagebox.showerror(
                "SFTP not available",
                "Paramiko is not installed.\nInstall with:\n\npip install paramiko",
            )
            return
        fields = self.get_common_fields()
        if not fields:
            return
        host, port, user, pwd, remote_dir = fields
        try:
            transport = paramiko.Transport((host, port))
            transport.connect(username=user, password=pwd)
            sftp = paramiko.SFTPClient.from_transport(transport)
            if remote_dir:
                sftp.chdir(remote_dir)
            path = sftp.getcwd() or "."
            self.entry_remote.delete(0, tk.END)
            self.entry_remote.insert(0, path)
            self.record_history(path)

            self.ssh_transport = transport
            self.sftp_conn = sftp
            self.log(f"[SFTP] Connected to {host}:{port} as {user}")
            if show_message:
                messagebox.showinfo("Connection", "SFTP connection successful.")
        except Exception as e:
            self.log(f"[SFTP] Connection error: {e}")
            if show_message:
                messagebox.showerror("SFTP connection error", str(e))

    # ==========================
    # Directory history
    # ==========================

    def record_history(self, path: str):
        """Add a path to navigation history."""
        if not path:
            return
        # If we are not at the end, drop any "forward" entries
        if self.history_index < len(self.history) - 1:
            self.history = self.history[: self.history_index + 1]
        self.history.append(path)
        self.history_index = len(self.history) - 1

    def go_back(self):
        if self.history_index > 0:
            self.history_index -= 1
            path = self.history[self.history_index]
            self.entry_remote.delete(0, tk.END)
            self.entry_remote.insert(0, path)
            self.refresh_list(update_history=False)

    def go_forward(self):
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            path = self.history[self.history_index]
            self.entry_remote.delete(0, tk.END)
            self.entry_remote.insert(0, path)
            self.refresh_list(update_history=False)

    # ==========================
    # Upload queue
    # ==========================

    def start_upload_queue(self):
        if not self.upload_queue:
            messagebox.showinfo("Upload", "Upload queue is empty. Add files first.")
            return
        if self.is_uploading:
            messagebox.showinfo("Upload", "Upload is already in progress.")
            return
        self.is_uploading = True
        self.log(f"[QUEUE] Starting upload of {len(self.upload_queue)} file(s).")
        self.process_next_upload()

    def process_next_upload(self):
        if not self.upload_queue:
            self.is_uploading = False
            self.update_progress(0, "")
            self.log("[QUEUE] Upload queue finished.")
            self.refresh_list(update_history=False)
            return

        local_path = self.upload_queue.pop(0)
        filename = os.path.basename(local_path)
        self.entry_file.delete(0, tk.END)
        self.entry_file.insert(0, filename)

        self.ensure_connection()
        if self.proto == "ftp" and self.ftp_conn is None:
            self.is_uploading = False
            return
        if self.proto == "sftp" and self.sftp_conn is None:
            self.is_uploading = False
            return

        self.update_progress(0, filename)

        try:
            size = os.path.getsize(local_path) or 1

            if self.proto == "ftp":
                sent = 0

                def callback(data):
                    nonlocal sent
                    sent += len(data)
                    percent = int(sent * 100 / size)
                    self.update_progress(percent, filename)

                with open(local_path, "rb") as f:
                    self.ftp_conn.storbinary(f"STOR " + filename, f, 8192, callback)
                self.log(f"[FTP] Upload OK: {filename}")
            else:

                def cb(transferred, total):
                    percent = int(transferred * 100 / size)
                    self.update_progress(percent, filename)

                self.sftp_conn.put(local_path, filename, callback=cb)
                self.log(f"[SFTP] Upload OK: {filename}")

        except Exception as e:
            self.log(f"[UPLOAD] Error for {filename}: {e}")
            messagebox.showerror("Upload error", f"{filename}: {e}")
        finally:
            self.update_progress(0, "")
            self.root.after(100, self.process_next_upload)

    # ==========================
    # Listing & navigation
    # ==========================

    def refresh_list(self, update_history: bool = False):
        self.ensure_connection()
        self.files_list.delete(0, tk.END)

        if self.proto == "ftp":
            if self.ftp_conn is None:
                return
            try:
                path = self.entry_remote.get().strip()
                if path:
                    self.ftp_conn.cwd(path)
                path = self.ftp_conn.pwd()
                self.entry_remote.delete(0, tk.END)
                self.entry_remote.insert(0, path)
                if update_history:
                    self.record_history(path)

                entries = []
                try:
                    for name, facts in self.ftp_conn.mlsd():
                        ftype = facts.get("type", "file")
                        entries.append((name, ftype))
                except Exception:
                    names = self.ftp_conn.nlst()
                    entries = [(name, "file") for name in names]

                if path not in ("/", ""):
                    self.files_list.insert(tk.END, "..")

                if not entries:
                    self.files_list.insert(tk.END, "[Empty folder]")
                else:
                    for name, ftype in entries:
                        prefix = "[D] " if ftype == "dir" else "    "
                        self.files_list.insert(tk.END, f"{prefix}{name}")

                self.log("[FTP] File list refreshed.")
            except Exception as e:
                self.log(f"[FTP] Listing error: {e}")
                messagebox.showerror("Listing error", str(e))

        else:
            if self.sftp_conn is None:
                return
            try:
                path = self.entry_remote.get().strip()
                if path:
                    self.sftp_conn.chdir(path)
                path = self.sftp_conn.getcwd() or "."
                self.entry_remote.delete(0, tk.END)
                self.entry_remote.insert(0, path)
                if update_history:
                    self.record_history(path)

                entries = self.sftp_conn.listdir_attr(path)
                if path not in ("/", ""):
                    self.files_list.insert(tk.END, "..")

                if not entries:
                    self.files_list.insert(tk.END, "[Empty folder]")
                else:
                    import stat

                    for e in entries:
                        is_dir = stat.S_ISDIR(e.st_mode)
                        prefix = "[D] " if is_dir else "    "
                        self.files_list.insert(tk.END, f"{prefix}{e.filename}")

                self.log("[SFTP] File list refreshed.")
            except Exception as e:
                self.log(f"[SFTP] Listing error: {e}")
                messagebox.showerror("Listing error", str(e))

    def _selected_items(self):
        sels = self.files_list.curselection()
        result = []
        for idx in sels:
            text = self.files_list.get(idx)
            if text in ("..", "[Empty folder]"):
                continue
            is_dir = text.startswith("[D]")
            name = text[4:].strip() if is_dir else text.strip()
            result.append((name, is_dir))
        return result

    def go_up_directory(self):
        self.ensure_connection()
        path = self.entry_remote.get().strip()
        if not path or path == "/":
            return
        parent = posixpath.dirname(path.rstrip("/")) or "/"
        self.entry_remote.delete(0, tk.END)
        self.entry_remote.insert(0, parent)
        self.record_history(parent)
        self.refresh_list(update_history=False)

    def on_item_double_click(self, event):
        sels = self.files_list.curselection()
        if not sels:
            return
        idx = sels[0]
        text = self.files_list.get(idx)
        if text == "..":
            self.go_up_directory()
            return
        if text == "[Empty folder]":
            return
        is_dir = text.startswith("[D]")
        if not is_dir:
            return

        name = text[4:].strip()
        self.ensure_connection()
        try:
            if self.proto == "ftp":
                self.ftp_conn.cwd(name)
                path = self.ftp_conn.pwd()
            else:
                current = self.sftp_conn.getcwd() or "."
                new_path = posixpath.join(current, name)
                self.sftp_conn.chdir(new_path)
                path = self.sftp_conn.getcwd() or new_path
            self.entry_remote.delete(0, tk.END)
            self.entry_remote.insert(0, path)
            self.record_history(path)
            self.refresh_list(update_history=False)
        except Exception as e:
            self.log(f"[CD] Error changing directory: {e}")
            messagebox.showerror("Change directory error", str(e))

    # ==========================
    # Download / delete / rename / mkdir
    # ==========================

    def download_selected(self):
        self.ensure_connection()
        items = self._selected_items()
        if not items:
            messagebox.showinfo("Download", "Please select file(s) to download.")
            return

        dest_dir = filedialog.askdirectory()
        if not dest_dir:
            return

        for name, is_dir in items:
            if is_dir:
                self.log(f"[DOWNLOAD] Skipping directory: {name}")
                continue
            remote_path = name
            filename = os.path.basename(name)
            local_path = os.path.join(dest_dir, filename)
            self.update_progress(0, filename)

            try:
                if self.proto == "ftp":
                    with open(local_path, "wb") as f:
                        total = [0]

                        def callback(data):
                            f.write(data)
                            total[0] += len(data)
                            # simple approximate progress
                            percent = min(100, total[0] // 1024)
                            self.update_progress(percent, filename)

                        self.ftp_conn.retrbinary("RETR " + remote_path, callback)
                    self.log(f"[FTP] Download OK: {filename}")
                else:
                    size = self.sftp_conn.lstat(remote_path).st_size or 1

                    def cb(transferred, total):
                        percent = int(transferred * 100 / size)
                        self.update_progress(percent, filename)

                    self.sftp_conn.get(remote_path, local_path, callback=cb)
                    self.log(f"[SFTP] Download OK: {filename}")
            except Exception as e:
                self.log(f"[DOWNLOAD] Error for {filename}: {e}")
                messagebox.showerror("Download error", f"{filename}: {e}")
            finally:
                self.update_progress(0, "")

        messagebox.showinfo("Download", "Download completed.")

    def delete_selected(self):
        self.ensure_connection()
        items = self._selected_items()
        if not items:
            messagebox.showinfo("Delete", "Please select file(s) or folder(s).")
            return

        names_for_confirm = ", ".join(n for n, _ in items)
        if not messagebox.askyesno(
            "Delete", f"Are you sure you want to delete:\n{names_for_confirm}"
        ):
            return

        for name, is_dir in items:
            try:
                if self.proto == "ftp":
                    if is_dir:
                        self.ftp_conn.rmd(name)
                    else:
                        self.ftp_conn.delete(name)
                else:
                    if is_dir:
                        self.sftp_conn.rmdir(name)
                    else:
                        self.sftp_conn.remove(name)
                self.log(f"[{self.proto.upper()}] Deleted: {name}")
            except Exception as e:
                self.log(f"[DELETE] Error for {name}: {e}")
                messagebox.showerror("Delete error", f"{name}: {e}")

        self.refresh_list(update_history=False)

    def create_folder(self):
        self.ensure_connection()
        new_name = self.entry_new_folder.get().strip()
        if not new_name:
            messagebox.showerror("Error", "Please enter folder name.")
            return

        try:
            if self.proto == "ftp":
                self.ftp_conn.mkd(new_name)
            else:
                current = self.sftp_conn.getcwd() or "."
                new_path = posixpath.join(current, new_name)
                self.sftp_conn.mkdir(new_path)
            self.log(f"[{self.proto.upper()}] Folder created: {new_name}")
            self.entry_new_folder.delete(0, tk.END)
            self.refresh_list(update_history=False)
        except Exception as e:
            self.log(f"[MKDIR] Error: {e}")
            messagebox.showerror("Create folder error", str(e))

    def rename_selected(self):
        self.ensure_connection()
        items = self._selected_items()
        if len(items) != 1:
            messagebox.showinfo("Rename", "Select exactly one file or folder.")
            return
        old_name, _ = items[0]
        new_name = self.entry_rename.get().strip()
        if not new_name:
            messagebox.showerror("Error", "Please enter new name.")
            return

        try:
            if self.proto == "ftp":
                self.ftp_conn.rename(old_name, new_name)
            else:
                current = self.sftp_conn.getcwd() or "."
                old_path = posixpath.join(current, old_name)
                new_path = posixpath.join(current, new_name)
                self.sftp_conn.rename(old_path, new_path)
            self.log(f"[{self.proto.upper()}] Renamed: {old_name} -> {new_name}")
            self.entry_rename.delete(0, tk.END)
            self.refresh_list(update_history=False)
        except Exception as e:
            self.log(f"[RENAME] Error: {e}")
            messagebox.showerror("Rename error", str(e))

    # ==========================
    # Main loop
    # ==========================

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = MiniFTPClientApp()
    app.run()