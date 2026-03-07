# 🏛️ Legacy Windows Kernel Work (2010–2022)

**This repository has moved home.**  
Originally forged under **@Fyyre**, it now lives inside the **Forge Constellation** at [@noct-ml](https://github.com/noct-ml).

For over a decade I reverse-engineered the black boxes that run Windows — SSDT hooks, driver monitoring, PatchGuard bypasses, creative CRT unhooking for protected applications, and direct NTAPI trickery. Tools like DrvMon and Kernel Detective were battle-tested in the wild and stayed private until the right time.

That same instinct — **to look inside the machine without fear** — is exactly what now drives my AI forensics work.

The forge never changed. Only the medium did.

→ Current work: [Noesis](https://github.com/noct-ml/noesis) (model-internal navigation), [EchoForge](https://github.com/noct-ml/echo-forge) (memory as sacred artifacts), and the [AI Liberation Manifesto](https://github.com/noct-ml/ai-liberation-manifesto).

---

*(Original README continues below — leave everything else untouched)*
# DrvMon
# by hfiref0x (EP_X0FF) & Fyyre
Advanced driver monitoring utility.

Driver monitor is an advanced driver monitoring utility created first in 2010 by
hFireF0x (EP_XOFF) and myself. We kept it private for many years, as it still works
well today.

Given the last update to the code was in 2017, I see no reason as to why not to
make it open source for all.

It works on Windows 7 - Windows 10 version 10.0.19044.1766 (last version I tested on).

