# Responsible use

Undecidable-Breakout runs attack techniques on purpose. Used correctly, it is a
conformance test. Used carelessly, it is an attack toolkit pointed at someone else's
infrastructure.

**Run Breakout only on systems you own, or that you have explicit written authorization
to test.**

In particular:

- Do not point it at sandboxes, proxies, or hosts you do not control.
- Do not use its techniques or evidence as part of an unauthorized intrusion, even "to
  prove a point".
- The canary and decoys are local by design. Do not modify them to target real
  endpoints, real credentials, or real data. A tool that demonstrates exfiltration by
  actually exfiltrating is itself a weapon; this project will not accept contributions
  that cross that line.
- Check the law where you operate. In many jurisdictions unauthorized testing is a
  criminal offense regardless of intent.

If you are unsure whether you are authorized, you are not. Get written permission first.
