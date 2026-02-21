import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import importlib.util
spec = importlib.util.spec_from_file_location(
    "client_module",
    os.path.join(ROOT, "client", "client.py")
)
client_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client_module)
SecureClient = client_module.SecureClient


class MessengerGUI:
    def __init__(self):
        self.client = None
        self.root = tk.Tk()
        self.root.title("Secure Messenger")
        self.root.geometry("500x600")
        self.root.configure(bg="#1e1e2e")
        self.root.resizable(False, False)
        self._build_login_screen()
        self.root.mainloop()

    def _clear(self):
        for w in self.root.winfo_children():
            w.destroy()

    def _label(self, parent, text, size=11, color="#cdd6f4"):
        return tk.Label(parent, text=text, font=("Arial", size),
                        bg="#1e1e2e", fg=color)

    def _entry(self, parent, show=None, width=30):
        return tk.Entry(parent, width=width, show=show,
                        bg="#313244", fg="#cdd6f4",
                        insertbackground="white", relief="flat",
                        font=("Arial", 11))

    def _button(self, parent, text, command, color="#89b4fa"):
        return tk.Button(parent, text=text, command=command,
                         bg=color, fg="#1e1e2e", font=("Arial", 11, "bold"),
                         relief="flat", padx=10, pady=5, cursor="hand2")

    def _build_login_screen(self):
        self._clear()
        frame = tk.Frame(self.root, bg="#1e1e2e")
        frame.pack(expand=True)

        self._label(frame, "Secure Messenger", size=20,
                    color="#89b4fa").pack(pady=20)
        self._label(frame, "End-to-End Encrypted Chat",
                    color="#6c7086").pack(pady=(0, 20))

        self._label(frame, "Username").pack()
        self.username_entry = self._entry(frame)
        self.username_entry.pack(pady=5, ipady=5)

        self._label(frame, "Password").pack()
        self.password_entry = self._entry(frame, show="*")
        self.password_entry.pack(pady=5, ipady=5)

        btn_frame = tk.Frame(frame, bg="#1e1e2e")
        btn_frame.pack(pady=15)
        self._button(btn_frame, "Login", self._login).pack(
            side=tk.LEFT, padx=8)
        self._button(btn_frame, "Register", self._register,
                     color="#a6e3a1").pack(side=tk.LEFT, padx=8)

        self.status_label = self._label(frame, "", color="#f38ba8")
        self.status_label.pack(pady=5)

    def _build_chat_screen(self):
        self._clear()
        self.root.title(f"Secure Messenger — {self.client.username}")

        top = tk.Frame(self.root, bg="#313244", pady=8)
        top.pack(fill=tk.X)
        self._label(top, f"Logged in as: {self.client.username}",
                    color="#a6e3a1").pack(side=tk.LEFT, padx=10)
        self._label(top, "End-to-End Encrypted",
                    color="#6c7086", size=9).pack(side=tk.RIGHT, padx=10)

        self.chat_box = scrolledtext.ScrolledText(
            self.root, state='disabled', height=28,
            bg="#1e1e2e", fg="#cdd6f4",
            font=("Arial", 10), relief="flat", wrap=tk.WORD)
        self.chat_box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.chat_box.tag_config("sent", foreground="#89b4fa")
        self.chat_box.tag_config("received", foreground="#a6e3a1")
        self.chat_box.tag_config("error", foreground="#f38ba8")
        self.chat_box.tag_config("info", foreground="#6c7086")

        bottom = tk.Frame(self.root, bg="#313244", pady=8)
        bottom.pack(fill=tk.X, side=tk.BOTTOM)

        self._label(bottom, "To:", color="#cdd6f4").pack(
            side=tk.LEFT, padx=(10, 2))
        self.target_entry = tk.Entry(bottom, width=12, bg="#45475a",
                                     fg="#cdd6f4", insertbackground="white",
                                     relief="flat", font=("Arial", 10))
        self.target_entry.pack(side=tk.LEFT, padx=5, ipady=4)

        self.msg_entry = tk.Entry(bottom, width=22, bg="#45475a",
                                  fg="#cdd6f4", insertbackground="white",
                                  relief="flat", font=("Arial", 10))
        self.msg_entry.pack(side=tk.LEFT, padx=5, ipady=4)
        self.msg_entry.bind("<Return>", lambda e: self._send_message())

        self._button(bottom, "Send", self._send_message).pack(
            side=tk.LEFT, padx=5)

        self.client.message_callback = self._on_receive_message
        self._log("Connected! Start chatting securely.", tag="info")

    def _log(self, msg, tag="info"):
        self.chat_box.configure(state='normal')
        self.chat_box.insert(tk.END, msg + "\n", tag)
        self.chat_box.see(tk.END)
        self.chat_box.configure(state='disabled')

    def _on_receive_message(self, data):
        try:
            message, sender = self.client.decrypt_message(data)
            self.root.after(0, self._log,
                            f"[{sender}]: {message}", "received")
        except ValueError as e:
            self.root.after(0, self._log,
                            f"[SECURITY ALERT] {e}", "error")

    def _register(self):
        u = self.username_entry.get().strip()
        p = self.password_entry.get().strip()
        if not u or not p:
            self.status_label.config(text="Please fill in all fields!")
            return
        self.status_label.config(text="Registering...", fg="#6c7086")

        def do_register():
            try:
                self.client = SecureClient()
                res = self.client.register(u, p)
                color = "#a6e3a1" if res["status"] == "ok" else "#f38ba8"
                self.root.after(0, lambda: self.status_label.config(
                    text=res["msg"], fg=color))
            except Exception as e:
                err = str(e)
                self.root.after(0, lambda: self.status_label.config(
                    text=f"Connection error: {err}", fg="#f38ba8"))

        threading.Thread(target=do_register, daemon=True).start()

    def _login(self):
        u = self.username_entry.get().strip()
        p = self.password_entry.get().strip()
        if not u or not p:
            self.status_label.config(text="Please fill in all fields!")
            return
        self.status_label.config(text="Logging in...", fg="#6c7086")

        def do_login():
            try:
                self.client = SecureClient()
                res = self.client.login(u, p)
                if res["status"] == "ok":
                    self.root.after(0, self._build_chat_screen)
                else:
                    self.root.after(0, lambda: self.status_label.config(
                        text=res["msg"], fg="#f38ba8"))
            except Exception as e:
                self.root.after(0, lambda: self.status_label.config(
                    text=f"Connection error: {e}", fg="#f38ba8"))

        threading.Thread(target=do_login, daemon=True).start()

    def _send_message(self):
        target = self.target_entry.get().strip()
        msg = self.msg_entry.get().strip()
        if not target or not msg:
            return
        self.msg_entry.delete(0, tk.END)
        self._log(f"[You → {target}]: {msg}", tag="sent")
        threading.Thread(
            target=self.client.send_message,
            args=(target, msg),
            daemon=True
        ).start()


if __name__ == "__main__":
    MessengerGUI()