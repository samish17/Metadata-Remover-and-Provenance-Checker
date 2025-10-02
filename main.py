"""
Metadata Tool: Remover + Provenance Checker + GUI
-------------------------------------------------
Author: Digital Forensics & Cybersecurity Analyst
Description:
    - Removes metadata from images (JPEG/PNG/TIFF), PDFs, DOCX, XLSX.
    - Checks files for AI-related provenance markers using hachoir.
    - Provides a minimal Tkinter GUI for ease of use.
Notes:
    - This tool does NOT remove AI watermarks; it only detects obvious provenance markers.
    - For unsupported types, it performs a raw byte copy fallback (internal metadata may remain).
"""

import os
import sys
import mimetypes
import shutil
import traceback

# Optional imports with feature flags
HAS_PIL = HAS_PYMUPDF = HAS_DOCX = HAS_OPENPYXL = HAS_HACHOIR = True

try:
    from PIL import Image
except Exception:
    HAS_PIL = False

try:
    import fitz  # PyMuPDF
except Exception:
    HAS_PYMUPDF = False

try:
    from docx import Document
except Exception:
    HAS_DOCX = False

try:
    from openpyxl import load_workbook
except Exception:
    HAS_OPENPYXL = False

try:
    from hachoir.parser import createParser
    from hachoir.metadata import extractMetadata
except Exception:
    HAS_HACHOIR = False

# -------------- Utility -------------- #

def log_exception(prefix: str, exc: Exception) -> str:
    return f"{prefix}: {exc.__class__.__name__}: {exc}\n{traceback.format_exc()}"

def guess_mime(input_path: str) -> str:
    mime, _ = mimetypes.guess_type(input_path)
    # Basic extension-based fallback for common types
    if not mime:
        ext = os.path.splitext(input_path)[1].lower()
        if ext in (".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp"):
            return "image/unknown"
        if ext == ".pdf":
            return "application/pdf"
        if ext == ".docx":
            return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        if ext == ".xlsx":
            return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return mime or "application/octet-stream"

# -------------- Metadata Removal -------------- #

def remove_image_metadata(input_path: str, output_path: str) -> str:
    """
    Removes EXIF and ancillary metadata by reconstructing pixel data into a new image.
    Works for JPEG/PNG/TIFF/WebP. Requires Pillow.
    """
    if not HAS_PIL:
        raise RuntimeError("Pillow (PIL) not available")
    with Image.open(input_path) as img:
        # Ensure image is loaded
        img.load()
        # Normalize mode for safer saving (optional conversion for palette images)
        mode = "RGB" if img.mode in ("P", "PA", "RGBA", "LA") else img.mode
        base = img.convert(mode)
        data = list(base.getdata())
        clean_img = Image.new(base.mode, base.size)
        clean_img.putdata(data)
        # Choose format based on input extension to avoid re-encoding surprises
        ext = os.path.splitext(output_path)[1].lower()
        save_kwargs = {}
        if ext in (".jpg", ".jpeg"):
            # Avoid copying EXIF; Pillow won't add EXIF unless provided
            save_kwargs.update({"quality": 95, "optimize": True})
        elif ext == ".png":
            # Avoid text chunks; default save creates minimal PNG
            save_kwargs.update({"optimize": True})
        clean_img.save(output_path, **save_kwargs)
    return "Image metadata removed"

def remove_pdf_metadata(input_path: str, output_path: str) -> str:
    """
    Clears PDF Document Info and XMP metadata. Requires PyMuPDF.
    Also performs garbage collection to remove residual objects.
    """
    if not HAS_PYMUPDF:
        raise RuntimeError("PyMuPDF (fitz) not available")
    doc = fitz.open(input_path)
    try:
        # Clear both info dict and XMP
        doc.set_metadata({})
        # Save with garbage collection and compression
        doc.save(output_path, garbage=4, deflate=True)
    finally:
        doc.close()
    return "PDF metadata removed"

def remove_docx_metadata(input_path: str, output_path: str) -> str:
    """
    Clears core document properties for DOCX. Requires python-docx.
    Note: Custom properties are not covered by python-docx; most cases use core props.
    """
    if not HAS_DOCX:
        raise RuntimeError("python-docx not available")
    doc = Document(input_path)
    core = doc.core_properties
    # Clear common fields
    core.author = None
    core.title = None
    core.subject = None
    core.keywords = None
    core.comments = None
    core.category = None
    core.last_modified_by = None
    core.content_status = None
    core.identifier = None
    core.language = None
    core.version = None
    # Timestamps (set to None may be ignored; python-docx uses datetime)
    try:
        core.created = None
        core.modified = None
    except Exception:
        pass
    doc.save(output_path)
    return "DOCX metadata removed"

def remove_excel_metadata(input_path: str, output_path: str) -> str:
    """
    Clears workbook properties for XLSX. Requires openpyxl.
    """
    if not HAS_OPENPYXL:
        raise RuntimeError("openpyxl not available")
    wb = load_workbook(input_path)
    props = wb.properties
    props.creator = None
    props.lastModifiedBy = None
    props.title = None
    props.subject = None
    props.keywords = None
    props.description = None
    props.category = None
    props.company = None
    props.manager = None
    wb.save(output_path)
    return "XLSX metadata removed"

def safe_byte_copy(input_path: str, output_path: str) -> str:
    """
    Fallback: raw byte copy (does NOT remove internal metadata).
    Avoids filesystem-level metadata preservation by not copying stat info.
    """
    with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    return "File copied (no specific metadata removal applied)"

def remove_metadata_dispatch(input_path: str, output_path: str) -> str:
    mime = guess_mime(input_path)
    if mime.startswith("image"):
        return remove_image_metadata(input_path, output_path)
    if mime == "application/pdf":
        return remove_pdf_metadata(input_path, output_path)
    if mime == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
        return remove_docx_metadata(input_path, output_path)
    if mime == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
        return remove_excel_metadata(input_path, output_path)
    return safe_byte_copy(input_path, output_path)

# -------------- Provenance Checker -------------- #

AI_MARKERS = [
    # General
    "ai", "artificial intelligence", "generated by",
    # Popular models/tools
    "stable diffusion", "sdxl", "midjourney", "dall-e", "openai",
    "runwayml", "adobe firefly", "canva ai", "copilot",
    # Common generator fields
    "generator", "model", "provenance", "c2pa", "content credentials"
]

def check_provenance(file_path: str) -> dict:
    """
    Uses hachoir to extract metadata and scans for AI-related markers.
    Returns dict with keys: ai_related (bool), tags (list), error (optional).
    """
    if not HAS_HACHOIR:
        return {"error": "hachoir not available", "ai_related": False, "tags": []}

    parser = createParser(file_path)
    if not parser:
        return {"error": "Unsupported or unreadable file format", "ai_related": False, "tags": []}

    findings = {"ai_related": False, "tags": []}
    try:
        with parser:
            metadata = extractMetadata(parser)
            if metadata:
                text = "\n".join(metadata.exportPlaintext())
                low = text.lower()
                for marker in AI_MARKERS:
                    if marker in low:
                        findings["ai_related"] = True
                        findings["tags"].append(marker)
    except Exception as e:
        findings["error"] = f"Provenance check failed: {e}"
    return findings

# -------------- GUI -------------- #

import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk

class MetadataRemoverApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("🛡️ Metadata Remover & Provenance Checker")
        self.root.geometry("620x360")
        self.root.resizable(False, False)

        # Style
        style = ttk.Style()
        # Use 'clam' for a cleaner look across platforms
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TButton", font=("Segoe UI", 10), padding=6)
        style.configure("TLabel", font=("Segoe UI", 10))
        style.configure("Status.TLabel", font=("Segoe UI", 9))

        # Vars
        self.input_file = tk.StringVar()
        self.output_file = tk.StringVar()

        # Layout
        container = ttk.Frame(root, padding=12)
        container.pack(fill="both", expand=True)

        # Input
        ttk.Label(container, text="Select file:").grid(row=0, column=0, sticky="w")
        ttk.Entry(container, textvariable=self.input_file, width=60).grid(row=1, column=0, columnspan=2, sticky="we", pady=(2, 8))
        ttk.Button(container, text="Browse", command=self.browse_input).grid(row=1, column=2, sticky="e")

        # Output
        ttk.Label(container, text="Save cleaned file as:").grid(row=2, column=0, sticky="w")
        ttk.Entry(container, textvariable=self.output_file, width=60).grid(row=3, column=0, columnspan=2, sticky="we", pady=(2, 8))
        ttk.Button(container, text="Choose", command=self.browse_output).grid(row=3, column=2, sticky="e")

        # Actions
        btn_frame = ttk.Frame(container)
        btn_frame.grid(row=4, column=0, columnspan=3, pady=10, sticky="we")
        ttk.Button(btn_frame, text="Remove metadata", command=self.process_file).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Check provenance", command=self.run_provenance).grid(row=0, column=1, padx=5)

        # Status
        self.status_label = ttk.Label(container, text="", style="Status.TLabel", foreground="#2e7d32")
        self.status_label.grid(row=5, column=0, columnspan=3, sticky="w", pady=(6, 4))

        # Log
        ttk.Label(container, text="Log:").grid(row=6, column=0, sticky="w")
        self.log = tk.Text(container, height=8, width=74, wrap="word")
        self.log.grid(row=7, column=0, columnspan=3, sticky="nsew")
        self.log.configure(font=("Consolas", 9))
        scroll = ttk.Scrollbar(container, command=self.log.yview)
        self.log["yscrollcommand"] = scroll.set
        scroll.grid(row=7, column=3, sticky="ns")

        # Feature availability banner
        self.report_features()

        # Grid weights
        for c in range(3):
            container.columnconfigure(c, weight=1)
        container.rowconfigure(7, weight=1)

    def report_features(self):
        unavailable = []
        if not HAS_PIL: unavailable.append("Pillow (images)")
        if not HAS_PYMUPDF: unavailable.append("PyMuPDF (PDF)")
        if not HAS_DOCX: unavailable.append("python-docx (DOCX)")
        if not HAS_OPENPYXL: unavailable.append("openpyxl (XLSX)")
        if not HAS_HACHOIR: unavailable.append("hachoir (provenance)")

        if unavailable:
            msg = "Unavailable features:\n - " + "\n - ".join(unavailable)
            self.append_log(msg)
            self.status_label.config(
                text=f"⚠️ Missing: {', '.join(unavailable)}",
                foreground="#b71c1c"
            )
        else:
            self.status_label.config(
                text="✅ All features ready.",
                foreground="#2e7d32"
            )
            self.append_log("All features available.")

  
    def browse_input(self):
        file_path = filedialog.askopenfilename(title="Select file")
        if file_path:
            self.input_file.set(file_path)
            # Suggest output name
            base, ext = os.path.splitext(file_path)
            self.output_file.set(base + "_clean" + ext)

    def browse_output(self):
        file_path = filedialog.asksaveasfilename(title="Save cleaned file as", initialfile=os.path.basename(self.output_file.get() or "cleaned_file"))
        if file_path:
            self.output_file.set(file_path)

    def process_file(self):
        input_path = self.input_file.get().strip()
        output_path = self.output_file.get().strip()

        if not input_path or not os.path.isfile(input_path):
            messagebox.showerror("Error", "Please select a valid input file.")
            return
        if not output_path:
            messagebox.showerror("Error", "Please choose an output path.")
            return

        try:
            result = remove_metadata_dispatch(input_path, output_path)
            self.status_label.config(text=f"✅ {result}. Saved as: {os.path.basename(output_path)}", foreground="#2e7d32")
            self.append_log(f"[CLEAN] {input_path} -> {output_path}\nResult: {result}")
        except Exception as e:
            self.status_label.config(text="❌ Failed to remove metadata.", foreground="#b71c1c")
            self.append_log(log_exception("Metadata removal failed", e))
            messagebox.showerror("Error", f"Failed to process file:\n{e}")

    def run_provenance(self):
        input_path = self.input_file.get().strip()
        if not input_path or not os.path.isfile(input_path):
            messagebox.showerror("Error", "Please select a valid input file.")
            return
        results = check_provenance(input_path)
        if "error" in results and results["error"]:
            self.status_label.config(text="⚠️ Provenance check error.", foreground="#b71c1c")
            self.append_log(f"[PROVENANCE ERROR] {results['error']}")
            messagebox.showerror("Error", results["error"])
            return
        if results["ai_related"]:
            tags = ", ".join(sorted(set(results["tags"])))
            self.status_label.config(text="⚠️ AI provenance markers detected.", foreground="#e65100")
            self.append_log(f"[PROVENANCE] AI markers found: {tags}")
            messagebox.showwarning("Provenance alert", f"AI provenance markers found:\n{tags}")
        else:
            self.status_label.config(text="✅ No AI provenance markers detected.", foreground="#2e7d32")
            self.append_log("[PROVENANCE] No AI markers detected.")

    def append_log(self, text: str):
        self.log.insert("end", text + "\n")
        self.log.see("end")

# -------------- Entry Point -------------- #

def main():
    # Windows .py association sometimes uses pythonw that hides console; ensure GUI runs
    root = tk.Tk()
    app = MetadataRemoverApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()