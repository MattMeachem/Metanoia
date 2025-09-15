#!/usr/bin/env python3
import json
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Import DnD wrapper
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:
    raise ImportError("Please install tkinterdnd2: pip install tkinterdnd2")

# -------------------------
# App version
# -------------------------
APP_VERSION = "Alpha v0.1"

# -------------------------
# Conversion functions
# -------------------------
def json_to_ndjson(json_file, ndjson_file):
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    with open(ndjson_file, "w", encoding="utf-8") as f:
        if isinstance(data, list):
            for obj in data:
                f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        else:
            f.write(json.dumps(data, ensure_ascii=False) + "\n")


def ndjson_to_json(ndjson_file, json_file):
    with open(ndjson_file, "r", encoding="utf-8") as f:
        data = [json.loads(line) for line in f if line.strip()]

    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# -------------------------
# Cross-platform icon function
# -------------------------
def set_app_icon(root, icon_path=None):
    """
    Set the window icon in a cross-platform-safe way.
    If icon_path is None or file doesn't exist, does nothing.
    """
    if icon_path is None or not os.path.exists(icon_path):
        return  # skip if missing

    try:
        if sys.platform.startswith("win"):
            # Windows: use .ico file
            root.iconbitmap(icon_path)
        else:
            # Linux/macOS: use .png file
            from tkinter import PhotoImage
            img = PhotoImage(file=icon_path)
            root.iconphoto(True, img)
    except Exception:
        pass  # fallback to default icon

# -------------------------
# GUI class
# -------------------------
class ConverterApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"JSON ↔ NDJSON Converter — {APP_VERSION}")
        self.root.geometry("500x340")  # Fixed window size

        # Mode selector
        self.mode_var = tk.StringVar(value="to-ndjson")
        ttk.Label(root, text="Conversion mode:").pack(pady=5)
        self.mode_combo = ttk.Combobox(root, textvariable=self.mode_var,
                                       values=["to-ndjson", "to-json"],
                                       state="readonly")
        self.mode_combo.pack()
        self.mode_combo.bind("<<ComboboxSelected>>", self.mode_changed)

        # Drag-and-drop input area
        ttk.Label(root, text="Drop input file here or use the button:").pack(pady=5)
        self.drop_area = tk.Label(root, text="Drag file here",
                                  relief="ridge", width=50, height=3, bg="#f0f0f0")
        self.drop_area.pack(pady=5)
        self.drop_area.drop_target_register(DND_FILES)
        self.drop_area.dnd_bind("<<Drop>>", self.handle_drop)

        # Input file button
        ttk.Button(root, text="Select Input File", command=self.select_input).pack(pady=5)
        self.input_label = ttk.Label(root, text="No file selected", wraplength=460)
        self.input_label.pack()

        # Output file
        ttk.Button(root, text="Select Output File", command=self.select_output).pack(pady=5)
        self.output_label = ttk.Label(root, text="No file selected", wraplength=460)
        self.output_label.pack()

        # Convert button
        ttk.Button(root, text="Convert", command=self.convert).pack(pady=10)

        # Version label at bottom
        version_label = ttk.Label(root, text=APP_VERSION, font=("Arial", 8, "italic"))
        version_label.pack(side="bottom", pady=5)

    # -------------------------
    # Helper methods
    # -------------------------
    def suggest_output_file(self, input_file):
        base, ext = os.path.splitext(input_file)
        return base + (".ndjson" if self.mode_var.get() == "to-ndjson" else ".json")

    def handle_drop(self, event):
        file_path = event.data.strip("{}")
        self.set_input_file(file_path)

    def select_input(self):
        filetypes = [("JSON files", "*.json"), ("NDJSON files", "*.ndjson"), ("All files", "*.*")]
        file = filedialog.askopenfilename(title="Select input file", filetypes=filetypes)
        if file:
            self.set_input_file(file)

    def set_input_file(self, file_path):
        self.input_file = file_path
        self.input_label.config(text=file_path)

        suggested = self.suggest_output_file(file_path)
        self.output_file = suggested
        self.output_label.config(text=suggested)

    def select_output(self):
        filetypes = [("JSON files", "*.json"), ("NDJSON files", "*.ndjson"), ("All files", "*.*")]
        file = filedialog.asksaveasfilename(title="Select output file",
                                            filetypes=filetypes,
                                            defaultextension=".json")
        if file:
            self.output_file = file
            self.output_label.config(text=file)

    def mode_changed(self, event=None):
        if hasattr(self, "input_file"):
            suggested = self.suggest_output_file(self.input_file)
            self.output_file = suggested
            self.output_label.config(text=suggested)

    def convert(self):
        try:
            if not hasattr(self, "input_file") or not hasattr(self, "output_file"):
                messagebox.showerror("Error", "Please select both input and output files.")
                return

            if self.mode_var.get() == "to-ndjson":
                json_to_ndjson(self.input_file, self.output_file)
            else:
                ndjson_to_json(self.input_file, self.output_file)

            messagebox.showinfo("Success", f"Conversion completed!\nOutput saved to:\n{self.output_file}")
        except Exception as e:
            messagebox.showerror("Error", str(e))


# -------------------------
# Main
# -------------------------
if __name__ == "__main__":
    root = TkinterDnD.Tk()
    # Cross-platform-safe icon, ignore if missing
    set_app_icon(root, "app_icon.ico")  # You can add .png later for Linux/macOS
    app = ConverterApp(root)
    root.mainloop()
