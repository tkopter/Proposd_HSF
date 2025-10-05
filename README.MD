# Zynq Vitis Benchmarks (866.67 MHz) & Arduino Due Decoder/Attack Suite — Vivado/Vitis 2020.2

> **Important Note.** This repository corresponds to the code used in the studies **_A Hybrid Security Framework with Energy-Aware Encryption for Protecting Embedded Systems Against Code Theft_** and **_DESIGNING ADVANCED ENCRYPTION METHOD ON FPGA_**. The original prototypes used **Dynamic Function eXchange (DFX)** on Zynq; DFX brings orchestration and I/O overhead. When the **HSF (Hybrid Security Framework)** **proposed encryption methodology** is executed in a **single-image, no-DFX** flow (this repo), **Zynq execution times are expected to be lower** than the DFX-based numbers, while the benchmark logic and timing windows remain identical.

This repository provides **simple, single-image Vitis applications for Xilinx Zynq** and a companion **Arduino Due** suite for decryption and attack experiments. The Zynq builds target **866.67 MHz**. The toolchain is fixed to **Vivado 2020.2** and **Vitis 2020.2**. The Arduino side runs on **Arduino Due (SAM3X8E) @ 84 MHz**, including both **decoder** and **attack** sketches.

> **Scope.** Minimal codebase for reproducible benchmarking: no DFX, no partial bitstreams; timing windows and signatures are preserved.

---

## Platform & Toolchain

- **SoC:** Xilinx Zynq (ARM Cortex-A9, PS)
- **PS clock:** **866.67 MHz** (fixed, timing-sensitive runs)
- **FPGA tools:** **Vivado 2020.2** (XSA export)
- **Software tools:** **Vitis 2020.2** (BSP & bare-metal app)
- **Arduino:** **Arduino Due @ 84 MHz** (SAM3X8E), standard Arduino IDE/CLI

---

## Repository Layout (file names)

- `helloworld.c` — single-image driver that invokes the comparison routine
- `gizli.c` — self-contained comparison/benchmark logic (**verbatim** to preserve timing)
- `lscript.ld` — linker script (**unchanged**)
- `arduino/decoder/` — Arduino Due decryption sketches (84 MHz)
- `arduino/attacks/` — Arduino Due attack sketches

---

## Build (reproducible flow)

### Zynq / Vitis 2020.2
1. Export hardware (XSA) in **Vivado 2020.2** with the **866.67 MHz** PS setting used in your design.
2. In **Vitis 2020.2**, create a **bare-metal** app + BSP from that XSA.
3. Add `helloworld.c`, `gizli.c`, `lscript.ld` **without edits**.
4. Compiler **-O3**, **no debug** info (to avoid timing perturbation).
5. Program and collect UART logs.

### Arduino Due (84 MHz)
1. Open sketches under `arduino/decoder/` and `arduino/attacks/`.
2. Select **Arduino Due (Programming Port)**, CPU **84 MHz**.
3. Build, upload, and log serial output.

---

## Timing & Measurement Notes

- All measurement windows and signatures live **inside `gizli.c`** and are **kept unchanged** for apples-to-apples comparison.
- `helloworld.c` is a thin driver; it forwards control and reports a mailbox-style return signature.
- Pinning tool versions (2020.2) and frequencies (Zynq **866.67 MHz**, Due **84 MHz**) stabilizes distributions.

---

## Citation

If you use this repository or its methodology, please cite:

- **Zynq Vitis Benchmarks (866.67 MHz) & Arduino Due Decoder/Attack Suite — Vivado/Vitis 2020.2**. GitHub repository, 2025.  
- **A Hybrid Security Framework with Energy-Aware Encryption for Protecting Embedded Systems Against Code Theft**, 2025.  
- **DESIGNING ADVANCED ENCRYPTION METHOD ON FPGA**, 2025.

---

## License

**MIT License** — see the `LICENSE` file in the repository root.
