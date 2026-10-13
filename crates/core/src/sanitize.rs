//! Secure deletion and free-space sanitization.
//!
//! Single-pass CSPRNG fill (NIST SP 800-88 Rev.2: multi-pass is dead),
//! cluster-safe allocation, post-fill TRIM/discard, safe-cancel with honest
//! partial-state reporting. Every operation is labeled with the NIST
//! category it can actually achieve on the target media.
