import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
from tkinterdnd2 import DND_FILES, TkinterDnD
import socket
import threading
import os

class CommandSenderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Remote Command & File Manager")
        self.client_socket = None

        self.output_area = scrolledtext.ScrolledText(root, width=80, height=10)
        self.output_area.grid(row=0, column=0, columnspan=3, padx=10, pady=5)

        self.command_entry = tk.Entry(root, width=60)
        self.command_entry.grid(row=1, column=0, padx=10, pady=5)
        tk.Button(root, text="Send Command", command=self.send_command).grid(row=1, column=1)
        tk.Button(root, text="Connect to Client", command=self.connect_to_client).grid(row=1, column=2)

        self.tree = ttk.Treeview(root)
        self.tree.grid(row=2, column=0, columnspan=3, padx=10, pady=5, sticky="nsew")
        self.tree.heading("#0", text="Client File System")
        self.tree.bind("<<TreeviewOpen>>", self.expand_node)
        self.tree.bind("<Double-1>", self.handle_double_click)

        self.root.drop_target_register(DND_FILES)
        self.root.dnd_bind('<<Drop>>', self.upload_dropped_file)

        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

    def log(self, message):
        self.output_area.insert(tk.END, message + "\n")
        self.output_area.see(tk.END)

    def connect_to_client(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(("127.0.0.1", 9999))  # Change IP for remote
            self.log("Connected to remote client.")
            self.tree.delete(*self.tree.get_children())
            self.tree.insert("", "end", "/root.", text="📁 .", open=False)
        except Exception as e:
            self.log(f"Connection error: {e}")

    def send_command(self):
        cmd = self.command_entry.get().strip()
        if not cmd or not self.client_socket:
            return
        try:
            self.client_socket.send(f"CMD:{cmd}".encode())
            response = self.client_socket.recv(4096).decode()
            self.log(f">> {cmd}\n{response}")
        except Exception as e:
            self.log(f"Send error: {e}")

    def expand_node(self, event):
        node = self.tree.focus()
        path = node.replace("/root", "")
        if not path or path == "/":
            path = "."
        self.client_socket.send(f"LISTDIR:{path}".encode())
        response = self.client_socket.recv(8192).decode()
        self.tree.delete(*self.tree.get_children(node))
        for item in response.splitlines():
            clean_item = item.rstrip("/")
            full_path = os.path.join(path, clean_item)
            icon = "📁" if item.endswith("/") else "📄"
            self.tree.insert(node, "end", f"/root{full_path}", text=f"{icon} {item}", open=False)

    def handle_double_click(self, event):
        node = self.tree.focus()
        label = self.tree.item(node)["text"]
        if label.startswith("📁"):
            self.expand_node(None)
        elif label.startswith("📄"):
            self.download_file(node)

    def download_file(self, node):
        path = node.replace("/root", "")
        self.client_socket.send(f"DOWNLOAD:{path}".encode())
        header = self.client_socket.recv(1024).decode()
        if header.startswith("SIZE:"):
            size = int(header.split(":")[1])
            self.client_socket.send("READY".encode())
            data = b""
            while len(data) < size:
                chunk = self.client_socket.recv(4096)
                if not chunk:
                    break
                data += chunk
            with open(os.path.basename(path), "wb") as f:
                f.write(data)
            self.log(f"Downloaded {path}")
        else:
            self.log("File not found on client.")

    def upload_dropped_file(self, event):
        path = event.data.strip("{}")
        if not os.path.isfile(path):
            self.log("Only files can be uploaded.")
            return
        try:
            filename = os.path.basename(path)
            with open(path, "rb") as f:
                data = f.read()
            self.client_socket.send(f"UPLOAD:{filename}:{len(data)}".encode())
            ack = self.client_socket.recv(1024).decode()
            if ack == "READY":
                self.client_socket.send(data)
                self.log(f"Uploaded {filename} to client.")
            else:
                self.log("Client refused upload.")
        except Exception as e:
            self.log(f"Upload error: {e}")

root = TkinterDnD.Tk()
app = CommandSenderGUI(root)
root.mainloop()
