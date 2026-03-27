//! Winnower-style log reduction via syscall n-gram analysis.
//!
//! Inspired by Winnower (Hassan et al., NDSS 2018), this module identifies
//! and collapses repetitive syscall patterns in binary logs. The key insight
//! is that most container workloads generate highly repetitive syscall
//! sequences (e.g., read-write loops, repeated open-read-close patterns),
//! and compressing these to a single representative + count dramatically
//! reduces log size without losing semantic information.
//!
//! Algorithm:
//! 1. Extract per-process syscall sequences from the log.
//! 2. Compute n-gram frequencies (n=2,3,4) for each process.
//! 3. Identify the most common n-grams (covering >80% of events).
//! 4. Report reduction statistics and the dominant patterns.

use std::collections::HashMap;
use std::path::Path;

use crate::binlog::{LogEntry, LogReader};
use crate::error::SysconError;
use crate::syscalls;

/// Result of analyzing a binary log for reduction.
#[derive(Debug)]
pub struct ReductionReport {
    /// Total syscall events in the log.
    pub total_events: u64,
    /// Events after deduplication of repeated n-gram patterns.
    pub unique_events: u64,
    /// Reduction ratio (1.0 - unique/total). Higher = more reduction.
    pub reduction_ratio: f64,
    /// Per-container statistics.
    pub containers: Vec<ContainerReduction>,
}

/// Reduction statistics for a single container.
#[derive(Debug)]
pub struct ContainerReduction {
    pub container_id: String,
    pub total_events: u64,
    pub unique_patterns: usize,
    /// Top n-gram patterns with their counts.
    pub top_patterns: Vec<PatternInfo>,
}

/// A frequently occurring syscall pattern.
#[derive(Debug, Clone)]
pub struct PatternInfo {
    /// The syscall sequence (as human-readable names).
    pub syscalls: Vec<&'static str>,
    /// How many times this pattern appeared.
    pub count: u64,
    /// What fraction of all events this pattern covers.
    pub coverage: f64,
}

/// Analyze a binary log file and produce reduction statistics.
pub fn analyze(path: &Path) -> Result<ReductionReport, SysconError> {
    let reader = LogReader::open(path)?;

    // Collect syscall sequences per (container, pid)
    let mut sequences: HashMap<(String, u32), Vec<u32>> = HashMap::new();
    let mut total_events: u64 = 0;

    for result in reader {
        let entry = result.map_err(|e| SysconError::io(e, "reading log entry"))?;
        if let LogEntry::Syscall(rec) = entry {
            total_events += 1;
            let cid = rec.container_id.clone().unwrap_or_default();
            sequences
                .entry((cid, rec.pid))
                .or_default()
                .push(rec.syscall_nr);
        }
    }

    // Analyze per-container
    let mut by_container: HashMap<String, Vec<(u32, Vec<u32>)>> = HashMap::new();
    for ((cid, pid), seq) in sequences {
        by_container.entry(cid).or_default().push((pid, seq));
    }

    let mut containers = Vec::new();
    let mut total_unique: u64 = 0;

    for (cid, process_seqs) in &by_container {
        let mut container_events: u64 = 0;
        let mut all_ngrams: HashMap<Vec<u32>, u64> = HashMap::new();

        for (_pid, seq) in process_seqs {
            container_events += seq.len() as u64;

            // Extract n-grams for n=2,3,4
            for n in 2..=4 {
                if seq.len() < n {
                    continue;
                }
                for window in seq.windows(n) {
                    *all_ngrams.entry(window.to_vec()).or_insert(0) += 1;
                }
            }
        }

        // Find patterns that appear more than once
        let mut patterns: Vec<(Vec<u32>, u64)> = all_ngrams
            .into_iter()
            .filter(|(_, count)| *count > 1)
            .collect();
        patterns.sort_by(|a, b| b.1.cmp(&a.1));

        // Greedy coverage: select patterns that cover the most events
        // without double-counting (simplified: just take top patterns)
        let mut top_patterns = Vec::new();
        for (ngram, count) in patterns.iter().take(20) {
            let pattern_events = count * ngram.len() as u64;
            let coverage = pattern_events as f64 / container_events.max(1) as f64;

            top_patterns.push(PatternInfo {
                syscalls: ngram.iter().map(|nr| syscalls::name(*nr)).collect(),
                count: *count,
                coverage,
            });
        }

        // Estimate unique events: total - events covered by repeated patterns
        // (each pattern counted once instead of N times)
        let unique_from_patterns: u64 = patterns
            .iter()
            .map(|(ngram, count)| (count - 1) * ngram.len() as u64)
            .sum();
        let unique = container_events.saturating_sub(unique_from_patterns);
        total_unique += unique;

        containers.push(ContainerReduction {
            container_id: cid.clone(),
            total_events: container_events,
            unique_patterns: patterns.len(),
            top_patterns,
        });
    }

    let reduction_ratio = if total_events > 0 {
        1.0 - (total_unique as f64 / total_events as f64)
    } else {
        0.0
    };

    Ok(ReductionReport {
        total_events,
        unique_events: total_unique,
        reduction_ratio,
        containers,
    })
}

/// Format the reduction report for display.
pub fn format_report(report: &ReductionReport) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "=== Log Reduction Analysis ===\n\
         Total events: {}\n\
         Unique events (after n-gram dedup): {}\n\
         Reduction: {:.1}% ({:.1}x compression)\n\n",
        report.total_events,
        report.unique_events,
        report.reduction_ratio * 100.0,
        if report.unique_events > 0 {
            report.total_events as f64 / report.unique_events as f64
        } else {
            0.0
        },
    ));

    for container in &report.containers {
        out.push_str(&format!(
            "Container: {}\n\
             Events: {} | Unique patterns: {}\n",
            container.container_id, container.total_events, container.unique_patterns,
        ));

        if !container.top_patterns.is_empty() {
            out.push_str("Top patterns:\n");
            for (i, pattern) in container.top_patterns.iter().take(10).enumerate() {
                out.push_str(&format!(
                    "  {}. [{}] x{} ({:.1}% coverage)\n",
                    i + 1,
                    pattern.syscalls.join(" → "),
                    pattern.count,
                    pattern.coverage * 100.0,
                ));
            }
        }
        out.push('\n');
    }

    out
}

/// Write a reduced version of the log: only unique events and pattern summaries.
/// Returns the reduced log entries.
pub fn reduce_log(path: &Path) -> Result<(Vec<LogEntry>, ReductionReport), SysconError> {
    let reader = LogReader::open(path)?;
    let header = reader.header().clone();

    // First pass: collect sequences and find patterns
    let mut all_entries: Vec<LogEntry> = vec![LogEntry::Header(header)];
    let mut sequences: HashMap<(String, u32), Vec<(usize, u32)>> = HashMap::new(); // (index, syscall_nr)

    for (entry_index, result) in reader.enumerate() {
        let entry = result.map_err(|e| SysconError::io(e, "reading log entry"))?;
        if let LogEntry::Syscall(rec) = &entry {
            let cid = rec.container_id.clone().unwrap_or_default();
            sequences
                .entry((cid, rec.pid))
                .or_default()
                .push((entry_index, rec.syscall_nr));
        }
        all_entries.push(entry);
    }

    // Find frequent bigrams per process
    let mut keep_indices: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut total_events: u64 = 0;
    let mut total_kept: u64 = 0;

    // Keep all non-syscall entries
    for (i, entry) in all_entries.iter().enumerate() {
        match entry {
            LogEntry::Header(_) | LogEntry::ActionStart { .. } | LogEntry::ActionEnd { .. } => {
                keep_indices.insert(i);
            }
            _ => {}
        }
    }

    for ((_cid, _pid), seq) in &sequences {
        total_events += seq.len() as u64;

        if seq.len() < 4 {
            // Too short to have patterns — keep everything
            for (idx, _) in seq {
                keep_indices.insert(*idx + 1); // +1 because header is at index 0
            }
            total_kept += seq.len() as u64;
            continue;
        }

        // Find repeated bigrams
        let mut bigram_counts: HashMap<(u32, u32), u64> = HashMap::new();
        for window in seq.windows(2) {
            let bigram = (window[0].1, window[1].1);
            *bigram_counts.entry(bigram).or_insert(0) += 1;
        }

        // Mark events to keep: first occurrence of each repeated pattern,
        // plus all events that aren't part of a repeated pattern
        let mut in_repeated = false;
        let mut prev_syscall: Option<u32> = None;

        for (idx, nr) in seq {
            let is_repeated = if let Some(prev) = prev_syscall {
                bigram_counts.get(&(prev, *nr)).copied().unwrap_or(0) > 2
            } else {
                false
            };

            if !is_repeated || !in_repeated {
                keep_indices.insert(*idx + 1);
                total_kept += 1;
            }

            in_repeated = is_repeated;
            prev_syscall = Some(*nr);
        }
    }

    // Build reduced log
    let reduced: Vec<LogEntry> = all_entries
        .into_iter()
        .enumerate()
        .filter(|(i, _)| keep_indices.contains(i))
        .map(|(_, entry)| entry)
        .collect();

    let reduction_ratio = if total_events > 0 {
        1.0 - (total_kept as f64 / total_events as f64)
    } else {
        0.0
    };

    let report = ReductionReport {
        total_events,
        unique_events: total_kept,
        reduction_ratio,
        containers: Vec::new(), // Simplified for reduce mode
    };

    Ok((reduced, report))
}
