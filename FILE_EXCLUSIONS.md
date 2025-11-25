# File Exclusions for SAST Scanning

This document lists all files and directories that are automatically excluded from download and scanning.

## Why Exclude These Files?

SAST (Static Application Security Testing) tools like Semgrep are designed to analyze **source code**, not binary files, images, or documents. Excluding these files:

- ✅ **Speeds up scanning** - No time wasted downloading/scanning non-code files
- ✅ **Reduces noise** - Eliminates parsing errors and warnings from non-code files
- ✅ **Saves bandwidth** - Images and binaries can be large
- ✅ **Focuses on security** - Only analyzes files that can contain vulnerabilities

---

## Excluded File Types

### 🖼️ Binary Assets & Images

```
*.png, *.jpg, *.jpeg, *.gif, *.bmp, *.ico, *.webp, *.tiff, *.svg
```

**Why:** Binary image files cannot be analyzed by code scanners. SVG is excluded by default but could be scanned if needed (sometimes contains JavaScript).

---

### 🎵 Media Files

```
*.mp4, *.mp3, *.wav, *.mov, *.avi, *.wmv, *.flv, *.mkv
```

**Why:** Audio and video files are binary media that cannot contain code vulnerabilities.

---

### 📄 Documents

```
*.pdf, *.doc, *.docx, *.xls, *.xlsx, *.ppt, *.pptx
```

**Why:** Office documents and PDFs are not source code files and cannot be analyzed by SAST tools.

---

### 📦 Compressed/Archives

```
*.zip, *.rar, *.7z, *.tar, *.gz, *.bz2, *.xz, *.tgz
```

**Why:** Archive files need to be extracted first. If you need to scan archived code, extract it to the repository first.

---

### ⚙️ Build Outputs & Compiled Code

```
*.class     (Java bytecode)
*.jar       (Java archives)
*.war       (Web archives)
*.ear       (Enterprise archives)
*.exe       (Windows executables)
*.dll       (Windows libraries)
*.so        (Linux shared objects)
*.dylib     (macOS libraries)
*.o         (Object files)
*.a         (Static libraries)
*.lib       (Library files)
*.pyc       (Python bytecode)
*.pyo       (Optimized Python bytecode)
*.pyd       (Python DLL)
```

**Why:** These are compiled/binary outputs generated from source code. We want to scan the **source**, not the compiled output.

---

### 🗜️ Minified & Generated Code

```
*.min.js    (Minified JavaScript)
*.min.css   (Minified CSS)
*.map       (Source maps)
```

**Why:** Minified code is hard to analyze and shouldn't be modified directly. Scan the original source instead.

---

### 🔤 Fonts

```
*.ttf, *.woff, *.woff2, *.eot, *.otf
```

**Why:** Font files are binary assets, not source code.

---

### 💾 Databases & Binary Data

```
*.db, *.sqlite, *.sqlite3, *.dat, *.bin
```

**Why:** Database files and binary data files cannot contain code vulnerabilities.

---

## Excluded Directories

### 📦 Dependencies & Packages

```
node_modules/       (Node.js dependencies)
vendor/             (PHP/Ruby dependencies)
packages/           (Various package managers)
bower_components/   (Bower dependencies)
```

**Why:** Third-party dependencies should be scanned separately (using tools like `npm audit` or `snyk`). Scanning them creates massive noise and slows down analysis.

---

### 🏗️ Build & Output Directories

```
dist/               (Distribution builds)
build/              (Build outputs)
out/                (Output directories)
target/             (Maven/Java builds)
bin/                (Binary outputs)
obj/                (Object files)
.next/              (Next.js builds)
.nuxt/              (Nuxt.js builds)
```

**Why:** These contain generated/compiled code, not source. Scan the source directory instead.

---

### 🧪 Test & Cache Directories

```
.pytest_cache/      (Pytest cache)
.cache/             (Various caches)
coverage/           (Code coverage reports)
__pycache__/        (Python cache)
```

**Why:** Cache and test output directories contain generated files, not source code.

---

### 🔧 Version Control & Environment

```
.git/               (Git repository data)
venv/               (Python virtual environment)
env/                (Environment directories)
.venv/              (Virtual environment)
```

**Why:** Version control metadata and virtual environments don't contain code to scan.

---

### 📋 System & Metadata Files

```
.DS_Store           (macOS metadata)
Thumbs.db           (Windows thumbnails)
desktop.ini         (Windows folder settings)
.gitkeep            (Git placeholder)
.gitattributes      (Git configuration)
```

**Why:** System-generated metadata files, not source code.

---

## What WILL Be Downloaded & Scanned?

✅ **Source code files:**
- Python: `.py`
- JavaScript/TypeScript: `.js`, `.ts`, `.jsx`, `.tsx`
- Java: `.java`
- C/C++: `.c`, `.cpp`, `.h`, `.hpp`
- Go: `.go`
- Ruby: `.rb`
- PHP: `.php`
- C#: `.cs`
- Shell: `.sh`, `.bash`
- And more...

✅ **Configuration files:**
- `.json`, `.yaml`, `.yml`, `.xml`, `.toml`, `.ini`
- `Dockerfile`, `.env.example`

✅ **Web files:**
- `.html`, `.css` (non-minified)
- `.vue`, `.svelte`

✅ **Documentation (text-based):**
- `.md`, `.txt`, `.rst`

---

## How to Override

If you need to scan a specific file type that's currently excluded, you can modify `scan.py`:

### Add an Exception

```python
# In the download_files function, before the skip checks:

# Example: Allow SVG files if they might contain JavaScript
if file_name.endswith('.svg'):
    # Don't skip, allow download
    pass
```

### Remove an Exclusion

```python
# In scan.py, edit the skip_extensions set:
skip_extensions = {
    # Remove the line for the extension you want to include
    # '.svg',  ← Commented out to allow SVG files
    '.png', '.jpg', ...
}
```

---

## Statistics

When you run the scanner, you'll see output like:

```
Downloaded 147 code files.
Skipped 523 non-code files (binaries, images, documents, build outputs, etc.)
```

This shows how many files were filtered out, helping you understand what was analyzed.

---

## Notes

- **CSV files** are NOT excluded by default, as they can sometimes contain code or configuration
- **Lock files** (package-lock.json, yarn.lock, Gemfile.lock) ARE included, as they can have security implications
- **Source maps** (.map) are excluded as they're generated files

---

## Best Practices

1. **Keep your repository clean** - Don't commit build outputs or binaries
2. **Use .gitignore** - Prevent build artifacts from being committed
3. **Scan source branches** - Scan development branches, not production builds
4. **Separate dependencies** - Use dedicated tools for dependency scanning

---

**Last Updated:** November 2024

