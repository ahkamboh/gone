# gone

See what deleted files can still be brought back. Erase them for good. Prove it.

**gone** is an open-source privacy auditor and sanitizer for storage media. Point it at a drive and it shows you what a forensic examiner could still recover: deleted photos, documents, and fragments sitting in space that only looks empty. One click sanitizes it. Then it rescans and hands you a signed certificate that proves nothing recoverable remains.

Recovery tools like PhotoRec can find your data but cannot remove it. Wipers can remove it but cannot show you what was there or confirm it is gone. gone closes that loop, for people selling a laptop, journalists protecting sources, activists, small businesses, and anyone who wants evidence instead of promises that deleted means deleted.

## Status

Early development. The workspace is scaffolded; the engine is being built. Watch the repo or check back for the first tagged release.

## How it works

1. **Check.** A read-only scan maps the parts of your drive that look empty but still hold deleted data, and reports in plain language: "About 1,240 photos and 86 documents could be brought back by anyone with free software." The scan never changes anything.
2. **Erase.** One click overwrites only the free space. Your files, programs, and operating system stay exactly as they are. Every operation is labeled with the NIST SP 800-88 Rev. 2 category it can actually achieve on your media, because honesty beats marketing.
3. **Verify.** The tool rescans and issues a signed, hash-chained certificate: what was recoverable before, what is recoverable now (zero), when, and on which drive.

Built for non-technical people first. One button, plain words, no device paths, no jargon. A full CLI ships for power users.

## Safety and intended use

- The scan is read-only by architecture.
- Erase operations touch only unallocated (free) space in the current version. They cannot harm live files.
- Use this tool on media you own or are explicitly authorized to sanitize.
- Do not use it to destroy data that is subject to litigation, an investigation, or a legal hold. That is spoliation, and it is a crime in most jurisdictions.
- No telemetry. Nothing leaves your machine.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. Study GPL tools like textbooks; no GPL code is copied into this project, which keeps the license clean for everyone.
