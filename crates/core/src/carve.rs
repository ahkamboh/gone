//! Deleted-file carving and validation.
//!
//! PhotoRec-style signature matching with per-format validators. A decodable
//! file is proof of recoverability; failed decodes are discarded as false
//! positives. Signature database is data-driven (YAML) and user-extensible.
