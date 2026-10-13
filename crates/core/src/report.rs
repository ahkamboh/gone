//! Findings, recoverability scores, and certificate models.
//!
//! Plain-language first: every summary carries both the technical counts
//! and a human sentence suitable for the GUI verdict banner.

use std::collections::BTreeMap;
use std::fmt;

use crate::carve::Hit;

/// Coarse, human-meaningful groupings for recoverable items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Category {
    Photos,
    Documents,
    Archives,
    Databases,
    Other,
}

impl Category {
    /// Lowercase label for plain-language sentences, singular or plural
    /// depending on `count`.
    pub fn label(&self, count: u64) -> &'static str {
        let singular = count == 1;
        match (self, singular) {
            (Category::Photos, true) => "photo",
            (Category::Photos, false) => "photos",
            (Category::Documents, true) => "document",
            (Category::Documents, false) => "documents",
            (Category::Archives, true) => "archive",
            (Category::Archives, false) => "archives",
            (Category::Databases, true) => "database",
            (Category::Databases, false) => "databases",
            (Category::Other, true) => "other item",
            (Category::Other, false) => "other items",
        }
    }
}

/// Result of scanning one evidence source.
#[derive(Debug)]
pub struct ScanSummary {
    pub source: String,
    pub bytes_scanned: u64,
    pub blocks_empty: u64,
    pub blocks_fill: u64,
    pub blocks_random: u64,
    pub blocks_structured: u64,
    hits: Vec<Hit>,
}

impl ScanSummary {
    pub fn new(source: &str) -> Self {
        Self {
            source: source.to_string(),
            bytes_scanned: 0,
            blocks_empty: 0,
            blocks_fill: 0,
            blocks_random: 0,
            blocks_structured: 0,
            hits: Vec::new(),
        }
    }

    pub fn record_hit(&mut self, hit: Hit) {
        self.hits.push(hit);
    }

    pub fn hit_count(&self) -> usize {
        self.hits.len()
    }

    pub fn hits(&self) -> &[Hit] {
        &self.hits
    }

    /// Hit counts grouped by human category.
    pub fn hits_by_category(&self) -> BTreeMap<Category, u64> {
        let mut map = BTreeMap::new();
        for hit in &self.hits {
            *map.entry(hit.category).or_insert(0) += 1;
        }
        map
    }

    /// The one-sentence verdict shown to non-technical users.
    pub fn verdict(&self) -> String {
        let counts = self.hits_by_category();
        if counts.is_empty() {
            return "Good news: nothing recoverable was found in the scanned space.".to_string();
        }
        let total: u64 = counts.values().sum();
        let parts: Vec<String> = counts
            .iter()
            .map(|(category, n)| format!("{n} {}", category.label(*n)))
            .collect();
        let noun = if total == 1 { "item" } else { "items" };
        format!(
            "{total} potentially recoverable {noun} found: {}.",
            parts.join(", ")
        )
    }
}

impl fmt::Display for ScanSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mib = self.bytes_scanned as f64 / (1024.0 * 1024.0);
        writeln!(f, "Scanned {} ({mib:.1} MiB, read-only)", self.source)?;
        writeln!(
            f,
            "Blocks: {} empty, {} fill-pattern, {} random-or-encrypted, {} structured",
            self.blocks_empty, self.blocks_fill, self.blocks_random, self.blocks_structured
        )?;
        write!(f, "{}", self.verdict())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(category: Category) -> Hit {
        Hit {
            signature_name: "test",
            extension: "bin",
            category,
            offset: 0,
        }
    }

    #[test]
    fn verdict_when_clean() {
        let summary = ScanSummary::new("disk.img");
        assert_eq!(
            summary.verdict(),
            "Good news: nothing recoverable was found in the scanned space."
        );
    }

    #[test]
    fn verdict_counts_by_category() {
        let mut summary = ScanSummary::new("disk.img");
        summary.record_hit(hit(Category::Photos));
        summary.record_hit(hit(Category::Photos));
        summary.record_hit(hit(Category::Documents));
        let verdict = summary.verdict();
        assert!(verdict.starts_with("3 potentially recoverable items found:"));
        assert!(verdict.contains("2 photos"));
        assert!(verdict.contains("1 document"));
    }
}
