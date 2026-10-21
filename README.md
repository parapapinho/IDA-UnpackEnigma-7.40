# Enigma x64 7.40: unpacking workflow in IDA

[Português (Brasil)](README.pt-BR.md)

This project contains an **IDAPython script for IDA 9.4** and two helper modules. It follows an x64 PE executable protected with Enigma Protector 7.40 to its original entry point (OEP), saves a prepared dump, and prints the values needed to continue repairing the imports in Scylla.

The analysis core was checked against two samples protected with version 7.40; the full IDA workflow was tested on one of them. Addresses come from the open executable and the running process. There is no fixed image base, OEP, or IAT taken from a particular sample. Other protector settings may require manual analysis.

The companion article walks through the analysis: [Unpacking Enigma Protector 7.40 Like the Old Days: Bypassing Anti-Debugging, Finding the OEP, and Rebuilding the IAT](https://ntknowledge.com/#/blog/unpacking-enigma-protector-7-40).

## Files

| File | Purpose |
| --- | --- |
| **ida_enigma740_generic.py** | Main script: controls the debugger, handles stops, and creates the dump. |
| **ida_enigma740_api.py** | Resolves APIs in loaded DLLs and handles the two observed anti-debugging calls. |
| **enigma740_generic_core.py** | Parses the PE, searches for the transfer to the OEP, infers the IAT range, and prepares the file for Scylla. |

Keep all three **.py** files **in the same folder**. Run only **ida_enigma740_generic.py** through IDA's menu. It imports the other two modules.

## Requirements

- Windows x64 and IDA 9.4 with IDAPython and the **Local Windows** debugger.
- An x64 PE executable protected with Enigma Protector 7.40 to analyze.
- Scylla x64 to rebuild the imports after capture.

The script uses Python's standard library and IDA's modules. No **pip** packages or PDB symbols are needed to locate the APIs.

## Usage

1. Open the **protected executable** in IDA and select the **Local Windows** debugger.
2. Go to **File > Script file** and select **ida_enigma740_generic.py**. If debugging has not started, the script starts the process. If it has, leave the process paused at the protected entry point before running the script.
3. In the **Output** window, look for **[Enigma 7.40 generic] loading workflow** and follow the messages with that prefix. If an import fails, check that all three **.py** files are together.
4. The script resolves **NtSetInformationThread** and watches for class **0x11** (**ThreadHideFromDebugger**) calls made by the protected module. It also watches **CheckRemoteDebuggerPresent** if the sample calls it. For these specific calls, it simulates a return that lets debugging continue. It uses execution breakpoints and does not modify Windows DLLs on disk.
5. The script searches memory for the final sequence observed in the version studied: **48 8B 45 E0 48 8B 65 F8 FF E0**, ending in **jmp rax**. It confirms that the same thread reached the executable target before identifying it as the OEP.
6. When the OEP is reached, the **Save As** dialog asks where to save the **.exe** dump. Choose a new filename. The process stays paused at the OEP.
7. In **Output**, copy the hexadecimal values from the **SCYLLA** line: **OEP**, the IAT's **VA**, and **Size**. The IAT range is printed only when the inference has high confidence. Otherwise, use Scylla's IAT search.
8. Attach **Scylla x64** to the process while it is still paused, check the IAT, get the imports, use **Autotrace** on entries redirected by Enigma when needed, and apply **Fix Dump** to the **.exe** produced by the script. Validate the resulting executable outside the debugger.

The program does not need to call **CheckRemoteDebuggerPresent** for the OEP to be found. Whether that call occurs depends on the sample and the protector settings.

## Generated files

The name chosen in the **Save As** dialog determines three files in the same folder:

| Output | Contents |
| --- | --- |
| **name.exe** | PE with a prepared layout and an adjusted entry point, still **pre-Scylla**. |
| **name.mem.bin** | Raw image captured from memory, with each file offset equal to its RVA. |
| **name.json** | Report containing the loaded base, OEP, IAT analysis, **.bss**, unreadable pages, and events. |

The script refuses to overwrite any of these files. The JSON records the paths of the analyzed executable and the generated files; review it before publishing.

## IDA Python console controls

After running the script, the **enigma740_generic** object is available in the console:

```python
enigma740_generic.status()       # Current state and last error, if any
enigma740_generic.probe_jump()   # Search for the jump again while paused
enigma740_generic.advance()      # Continue a recognized stop when automatic mode is off
enigma740_generic.save()         # Reopen Save As while the process is still at the OEP
enigma740_generic.abort()        # Remove the breakpoints created by the script
```

To inspect each stop before continuing, set **AUTO_CONTINUE = False** near the top of **ida_enigma740_generic.py** before loading it. In this mode, call **advance()** after your inspection.

### If the final jump is not detected

With the process paused, **probe_jump()** searches the mapped image again. If the variant uses a different pattern, follow the **jmp rax** manually: note the jump address, execute **one instruction** to reach its target, and, with IDA stopped there, run:

```python
enigma740_generic.confirm_manual_oep(jump_address, target_address)
```

The report marks this confirmation as a manual observation. The script validates the source instruction, target, **RIP**, and **RAX** before accepting it.

### If the **.bss** section needs adjustment

The script tries to select an original section with **RawSize = 0** and the uninitialized-data flag automatically, **only when there is a single candidate**. Check the **bss_source** field in the JSON and the headers of the generated PE. This heuristic does not prove that any section without data in the protected file is the original **.bss**.

If you need to specify the section's starting RVA, **cancel the Save As dialog** when the OEP is reached and run, for example:

```python
enigma740_generic.set_bss_rva(0x290000)
enigma740_generic.save()
```

Replace **0x290000** with the section RVA from your sample. The script requires an original section with **RawSize = 0** in the protected file. After **Fix Dump**, check the headers again: Scylla may rewrite them.

## Scope and limitations

- The final-transfer signature and a loader-relative hint were observed in two samples. With different settings, the script may not stop at the OEP automatically. The hint alone never confirms the OEP.
- The script does not formally identify Enigma's initial stub. It validates the x64 PE and the transfer observed during debugging.
- Anti-debugging handling covers the observed calls from the protected module to **NtSetInformationThread** with class **0x11**, and to **CheckRemoteDebuggerPresent** with the current-process pseudohandle. Other techniques require further analysis. If distinct API names resolve to different addresses, only the primary entry is monitored.
- Image capture is limited to **512 MiB**. Unreadable application pages prevent the dump; unreadable loader pages are recorded in the JSON.
- The IAT range is inferred. The script **does not rebuild** descriptors, API names, or Enigma redirections. The resulting **.exe** may not run until the imports are repaired in Scylla and other metadata is corrected.
- After the dump, monitoring of both APIs remains active to observe runtime checks. Use **abort()** to end the workflow and remove the script's breakpoints.

This package is a **script run through File > Script file**, not a plugin installed in IDA's **plugins** directory.
