# Polyglot Codebase Knowledge Graph

> Generated offline by **readmenator**. Supports C, C++, Python, Go, Rust, JS/TS, Java, C#, Shell, PHP, Dart, GDScript, Nim, ASM.
> No LLMs. No tokens. Pure static analysis. See more [here](https://github.com/grisuno/ReadMenator)

**Total Files Parsed:** 3 | **Total Symbols Extracted:** 2 | **Total Imports:** 1

## Structural Knowledge Map
```mermaid
graph TD
    classDef mod fill:#1e1e1e,stroke:#ff6666,stroke-width:2px,color:#fff;
    classDef cls fill:#2d2d2d,stroke:#4ec9b0,stroke-width:2px,color:#fff;
    classDef fn fill:#333,stroke:#dcdcaa,stroke-width:1px,color:#dcdcaa;
    classDef ext fill:#111,stroke:#666,stroke-dasharray:5 5,color:#aaa;
    app_py["app.py (py)"]
    class app_py mod;
    gen_ebird3_sh["gen_ebird3.sh (sh)"]
    class gen_ebird3_sh mod;
    gen_ebird3_sh_usage["usage"]
    class gen_ebird3_sh_usage fn;
    gen_ebird3_sh --> gen_ebird3_sh_usage
    gen_ebird3_sh_xor_string["xor_string"]
    class gen_ebird3_sh_xor_string fn;
    gen_ebird3_sh --> gen_ebird3_sh_xor_string
    install_sh["install.sh (sh)"]
    class install_sh mod;
    ext_os["os"]
    class ext_os ext;
    app_py -.->|imports| ext_os
```

---

## Architecture Reference

### PY (1 files)

#### `app.py`
**Path:** `app.py`

*No symbols extracted*

### SH (2 files)

#### `gen_ebird3.sh`
**Path:** `gen_ebird3.sh`

**Functions:**
- `usage` (line 12)
- `xor_string` (line 57) - *Función para XOR y convertir a array C*

#### `install.sh`
**Path:** `install.sh`

*No symbols extracted*
