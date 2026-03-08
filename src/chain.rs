use std::cell::RefCell;
use std::rc::Rc;

/// Iterator that concatenates named segments and tracks which line number
/// each segment starts at. Pair with [`SegmentTracker`] to look up which
/// segment a given line belongs to.
pub struct TrackedChain {
    segments: Vec<Box<dyn Iterator<Item = String>>>,
    current: usize,
    lines_emitted: u64,
    starts: Rc<RefCell<Vec<u64>>>,
}

/// Handle for looking up which segment a line number belongs to.
///
/// Created alongside a [`TrackedChain`] — keep this while the chain is
/// consumed by [`LogStream`](crate::LogStream).
pub struct SegmentTracker {
    filenames: Vec<String>,
    starts: Rc<RefCell<Vec<u64>>>,
}

impl TrackedChain {
    /// Build a tracked chain from named segments.
    ///
    /// Returns the iterator (feed to `LogStream::new()`) and a tracker handle
    /// (use to look up segment boundaries after entries are yielded).
    pub fn new(
        segments: Vec<(String, Box<dyn Iterator<Item = String>>)>,
    ) -> (Self, SegmentTracker) {
        let (filenames, iters): (Vec<_>, Vec<_>) = segments.into_iter().unzip();
        let starts = Rc::new(RefCell::new(if iters.is_empty() {
            Vec::new()
        } else {
            vec![1u64]
        }));
        let tracker = SegmentTracker {
            filenames: filenames.clone(),
            starts: starts.clone(),
        };
        let chain = TrackedChain {
            segments: iters,
            current: 0,
            lines_emitted: 0,
            starts,
        };
        (chain, tracker)
    }
}

impl Iterator for TrackedChain {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        loop {
            if self.current >= self.segments.len() {
                return None;
            }
            if let Some(line) = self.segments[self.current].next() {
                self.lines_emitted += 1;
                return Some(line);
            }
            self.current += 1;
            if self.current < self.segments.len() {
                self.starts.borrow_mut().push(self.lines_emitted + 1);
            }
        }
    }
}

impl SegmentTracker {
    /// Look up which segment a line number belongs to.
    ///
    /// Returns `(segment_index, filename)` or `None` for line number 0.
    pub fn segment_for_line(&self, line_number: u64) -> Option<(usize, &str)> {
        if line_number == 0 {
            return None;
        }
        let starts = self.starts.borrow();
        let idx = starts.partition_point(|&s| s <= line_number);
        if idx == 0 {
            return None;
        }
        let seg = idx - 1;
        Some((seg, &self.filenames[seg]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(name: &str, lines: Vec<&str>) -> (String, Box<dyn Iterator<Item = String>>) {
        let owned: Vec<String> = lines.into_iter().map(String::from).collect();
        (name.to_string(), Box::new(owned.into_iter()))
    }

    #[test]
    fn single_segment() {
        let (chain, tracker) = TrackedChain::new(vec![seg("a.log", vec!["x", "y", "z"])]);
        let lines: Vec<_> = chain.collect();
        assert_eq!(lines, ["x", "y", "z"]);
        assert_eq!(tracker.segment_for_line(1), Some((0, "a.log")));
        assert_eq!(tracker.segment_for_line(3), Some((0, "a.log")));
    }

    #[test]
    fn two_segments() {
        let (chain, tracker) = TrackedChain::new(vec![
            seg("a.log", vec!["a1", "a2"]),
            seg("b.log", vec!["b1"]),
        ]);
        let lines: Vec<_> = chain.collect();
        assert_eq!(lines, ["a1", "a2", "b1"]);
        assert_eq!(tracker.segment_for_line(1), Some((0, "a.log")));
        assert_eq!(tracker.segment_for_line(2), Some((0, "a.log")));
        assert_eq!(tracker.segment_for_line(3), Some((1, "b.log")));
    }

    #[test]
    fn empty_segment_skipped() {
        let (chain, tracker) = TrackedChain::new(vec![
            seg("a.log", vec!["a1"]),
            seg("empty.log", vec![]),
            seg("c.log", vec!["c1"]),
        ]);
        let lines: Vec<_> = chain.collect();
        assert_eq!(lines, ["a1", "c1"]);
        assert_eq!(tracker.segment_for_line(1), Some((0, "a.log")));
        assert_eq!(tracker.segment_for_line(2), Some((2, "c.log")));
    }

    #[test]
    fn line_zero_returns_none() {
        let (_chain, tracker) = TrackedChain::new(vec![seg("a.log", vec!["x"])]);
        assert_eq!(tracker.segment_for_line(0), None);
    }

    #[test]
    fn empty_chain() {
        let (chain, tracker) = TrackedChain::new(vec![]);
        let lines: Vec<String> = chain.collect();
        assert!(lines.is_empty());
        assert_eq!(tracker.segment_for_line(1), None);
    }
}
