//! Puts the datagrams that a path reordered back in the order they were sent in.
//!
//! A path with jitter (a wireless hop, two routes) delivers packets out of order, and QUIC takes
//! that for loss: it keeps the holes of a burst in an acknowledgement of 64 ranges and drops the
//! oldest ones beyond that, so what arrived is reported as lost and sent again. At the rate of a
//! bulk transfer (10 000 packets per second) and 3 ms of jitter this ceilings the throughput at
//! about 12 MB/s however large the windows are. The datagrams of a relay carry a counter, which
//! tells the receiver what is missing, and a packet that comes behind a hole waits for the hole to
//! fill (for as long as holes have taken to fill so far, and never for long) before QUIC sees it.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// How long a hole is waited for at least, and at most.
const MIN_WAIT: Duration = Duration::from_millis(2);
const MAX_WAIT: Duration = Duration::from_millis(40);
/// Datagrams held at most; more than this and everything held goes on, since a hole that wide is
/// a loss.
const MAX_HELD: usize = 512;

#[derive(Debug)]
pub struct Resequencer {
    /// The counter that comes next, or 0 before the first datagram.
    next: u64,
    held: BTreeMap<u64, Vec<u8>>,
    /// When the oldest datagram that is held was held.
    since: Option<Instant>,
    /// The longest that a hole took to fill lately.
    longest: Duration,
}

impl Default for Resequencer {
    fn default() -> Self {
        Self::new()
    }
}

impl Resequencer {
    pub fn new() -> Self {
        Self {
            next: 0,
            held: BTreeMap::new(),
            since: None,
            longest: Duration::ZERO,
        }
    }

    /// How long a hole is waited for now.
    fn wait(&self) -> Duration {
        (self.longest * 2).clamp(MIN_WAIT, MAX_WAIT)
    }

    /// A datagram with `counter` arrived. Whatever is due goes to `out`, in order.
    pub fn push(&mut self, counter: u64, payload: &[u8], now: Instant, out: &mut Vec<Vec<u8>>) {
        if self.next == 0 || counter == self.next {
            if counter == self.next
                && let Some(since) = self.since
            {
                // the hole that was waited for is filled
                self.longest = self
                    .longest
                    .max(now.saturating_duration_since(since))
                    .min(MAX_WAIT);
            }
            out.push(payload.to_vec());
            self.next = counter + 1;
            self.release(now, out);
        } else if counter < self.next {
            // it came after the others had gone on: nothing to wait for, and nothing to put in
            // order any more. Holes take longer than thought.
            self.longest = (self.longest + self.longest / 4).clamp(MIN_WAIT, MAX_WAIT);
            out.push(payload.to_vec());
        } else {
            self.since.get_or_insert(now);
            self.held.insert(counter, payload.to_vec());
            if self.held.len() > MAX_HELD {
                self.flush(out);
            }
        }
        // the slow decay lets the wait shrink again after a bad moment
        self.longest = self.longest.mul_f64(0.99999);
    }

    /// Sends on what is held in order up to the next hole.
    fn release(&mut self, now: Instant, out: &mut Vec<Vec<u8>>) {
        while let Some(payload) = self.held.remove(&self.next) {
            out.push(payload);
            self.next += 1;
        }
        self.since = (!self.held.is_empty()).then_some(now);
    }

    /// Gives up the holes and sends on everything that is held.
    fn flush(&mut self, out: &mut Vec<Vec<u8>>) {
        if let Some((&last, _)) = self.held.last_key_value() {
            out.extend(std::mem::take(&mut self.held).into_values());
            self.next = last + 1;
        }
        self.since = None;
    }

    /// When the datagrams that are held must go on, if any are.
    pub fn deadline(&self) -> Option<Instant> {
        self.since.map(|since| since + self.wait())
    }

    /// Time has come to `now`: holes that were waited for long enough are given up.
    pub fn expire(&mut self, now: Instant, out: &mut Vec<Vec<u8>>) {
        if self.deadline().is_some_and(|deadline| now >= deadline) {
            self.flush(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(r: &mut Resequencer, counters: &[u64], now: Instant) -> Vec<u64> {
        let mut out = Vec::new();
        for &c in counters {
            r.push(c, &c.to_be_bytes(), now, &mut out);
        }
        out.iter()
            .map(|d| u64::from_be_bytes(d[..8].try_into().unwrap()))
            .collect()
    }

    #[test]
    fn datagrams_in_order_pass_at_once() {
        let mut r = Resequencer::new();
        assert_eq!(feed(&mut r, &[5, 6, 7], Instant::now()), [5, 6, 7]);
        assert!(r.deadline().is_none());
    }

    #[test]
    fn a_datagram_behind_a_hole_waits_until_it_fills() {
        let mut r = Resequencer::new();
        let now = Instant::now();
        assert_eq!(feed(&mut r, &[1, 2], now), [1, 2]);
        assert!(feed(&mut r, &[4, 5], now).is_empty());
        assert!(r.deadline().is_some());
        assert_eq!(feed(&mut r, &[3], now), [3, 4, 5]);
        assert!(r.deadline().is_none());
    }

    #[test]
    fn a_hole_that_does_not_fill_is_given_up_after_the_wait() {
        let mut r = Resequencer::new();
        let now = Instant::now();
        assert_eq!(feed(&mut r, &[1], now), [1]);
        assert!(feed(&mut r, &[3, 4], now).is_empty());
        let mut out = Vec::new();
        r.expire(now + MIN_WAIT / 2, &mut out);
        assert!(out.is_empty());
        r.expire(now + MAX_WAIT, &mut out);
        assert_eq!(out.len(), 2);
        // what comes after goes through again
        assert_eq!(feed(&mut r, &[5], now + MAX_WAIT), [5]);
    }

    #[test]
    fn a_datagram_that_comes_after_the_hole_was_given_up_still_passes() {
        let mut r = Resequencer::new();
        let now = Instant::now();
        feed(&mut r, &[1, 3], now);
        let mut out = Vec::new();
        r.expire(now + MAX_WAIT, &mut out);
        assert_eq!(feed(&mut r, &[2], now + MAX_WAIT), [2]);
    }

    #[test]
    fn the_wait_follows_how_long_holes_take_to_fill() {
        let mut r = Resequencer::new();
        let now = Instant::now();
        feed(&mut r, &[1, 3], now);
        feed(&mut r, &[2], now + Duration::from_millis(6));
        assert!(r.wait() >= Duration::from_millis(11));
        assert!(r.wait() <= MAX_WAIT);
    }

    #[test]
    fn a_hole_too_wide_is_given_up_at_once() {
        let mut r = Resequencer::new();
        let now = Instant::now();
        feed(&mut r, &[1], now);
        let counters: Vec<u64> = (3..3 + MAX_HELD as u64 + 1).collect();
        let out = feed(&mut r, &counters, now);
        assert_eq!(out.len(), counters.len());
    }
}
