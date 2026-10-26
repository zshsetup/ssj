//! A congestion controller that starts with CUBIC and moves to BBR on a path that loses packets
//! without a queue in front of the loss.
//!
//! CUBIC is the better one on a clean link, wired or loopback: it fills the link and BBR paces
//! below it (30 to 80 percent less bulk throughput there). BBR is the better one when packets are
//! lost for other reasons than a full queue, such as Wi-Fi, mobile, or a long path with random
//! loss, where CUBIC halves its window at every loss and crawls (0.3 MB/s against 7 MB/s at 80 ms
//! and 1 percent loss).
//!
//! A loss with a round-trip time that has not grown is not congestion. A few of them in a short
//! time move the connection to BBR, and a long time without any loss moves it back. Both
//! controllers see every event, so the one that takes over knows the path already.

use std::any::Any;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use quinn::congestion::{BbrConfig, Controller, ControllerFactory, CubicConfig};
use quinn_proto::RttEstimator;

/// A loss counts as random when the round-trip time is at most this much above its minimum
/// (as a fraction), plus [`QUEUE_SLACK`].
const QUEUE_FRACTION: f64 = 0.15;
const QUEUE_SLACK: Duration = Duration::from_millis(2);
/// Random losses within [`LOSS_WINDOW`] that move the connection to BBR.
const SWITCH_AT: usize = 4;
const LOSS_WINDOW: Duration = Duration::from_secs(10);
/// A quiet time without any loss after which CUBIC takes over again.
const CLEAN_FOR: Duration = Duration::from_secs(30);

static TO_BBR: AtomicUsize = AtomicUsize::new(0);
static TO_CUBIC: AtomicUsize = AtomicUsize::new(0);

/// How often connections of this process moved to BBR and back, for the debug output and tests.
pub fn switches() -> (usize, usize) {
    (
        TO_BBR.load(Ordering::Relaxed),
        TO_CUBIC.load(Ordering::Relaxed),
    )
}

/// The decision, apart from the controllers and their types, so that it can be tested.
#[derive(Clone, Debug)]
pub struct Policy {
    bbr: bool,
    since: Instant,
    random_losses: VecDeque<Instant>,
    last_loss: Option<Instant>,
}

impl Policy {
    pub fn new(now: Instant) -> Self {
        Self {
            bbr: false,
            since: now,
            random_losses: VecDeque::new(),
            last_loss: None,
        }
    }

    /// Whether BBR sends now.
    pub fn bbr(&self) -> bool {
        self.bbr
    }

    /// Whether a loss at this round-trip time, against the smallest one seen, is random. `spread`
    /// is how far the round-trip time wanders (four times its deviation): on a path with jitter
    /// the smallest time is an extreme, and the usual one lies far above it with no queue at all.
    pub fn is_random(smoothed: Duration, min: Duration, spread: Duration) -> bool {
        smoothed <= min.mul_f64(1.0 + QUEUE_FRACTION) + QUEUE_SLACK + spread
    }

    /// Bytes were lost. Returns true if this moved the connection to BBR.
    pub fn on_loss(
        &mut self,
        now: Instant,
        smoothed: Duration,
        min: Duration,
        spread: Duration,
    ) -> bool {
        self.last_loss = Some(now);
        if !Self::is_random(smoothed, min, spread) {
            return false;
        }
        self.random_losses.push_back(now);
        while self
            .random_losses
            .front()
            .is_some_and(|t| now.duration_since(*t) > LOSS_WINDOW)
        {
            self.random_losses.pop_front();
        }
        if !self.bbr && self.random_losses.len() >= SWITCH_AT {
            self.bbr = true;
            self.since = now;
            return true;
        }
        false
    }

    /// Time has passed. Returns true if this moved the connection back to CUBIC.
    pub fn on_time(&mut self, now: Instant) -> bool {
        if !self.bbr {
            return false;
        }
        let quiet_since = self.last_loss.unwrap_or(self.since).max(self.since);
        if now.duration_since(quiet_since) >= CLEAN_FOR {
            self.bbr = false;
            self.since = now;
            self.random_losses.clear();
            return true;
        }
        false
    }
}

/// The lowest smoothed round-trip time of the last [`FLOOR_WINDOW`]. The lowest time that ever
/// was measured is the better floor on a steady path, but with jitter it is one lucky sample far
/// below the usual time, and every loss then looks like the work of a queue.
#[derive(Clone, Debug, Default)]
struct Floor {
    /// The lowest time of each second that had a measurement.
    seconds: VecDeque<(Instant, Duration)>,
}

const FLOOR_WINDOW: Duration = Duration::from_secs(30);

impl Floor {
    fn observe(&mut self, now: Instant, smoothed: Duration) {
        match self.seconds.back_mut() {
            Some((start, lowest)) if now.duration_since(*start) < Duration::from_secs(1) => {
                *lowest = (*lowest).min(smoothed);
            }
            _ => self.seconds.push_back((now, smoothed)),
        }
        while self
            .seconds
            .front()
            .is_some_and(|(start, _)| now.duration_since(*start) > FLOOR_WINDOW)
        {
            self.seconds.pop_front();
        }
    }

    fn get(&self) -> Option<Duration> {
        self.seconds.iter().map(|(_, lowest)| *lowest).min()
    }
}

/// Builds [`Adaptive`] controllers.
pub struct AdaptiveConfig {
    pub initial_window: u64,
}

impl ControllerFactory for AdaptiveConfig {
    fn build(self: Arc<Self>, now: Instant, mtu: u16) -> Box<dyn Controller> {
        let mut cubic = CubicConfig::default();
        cubic.initial_window(self.initial_window);
        let mut bbr = BbrConfig::default();
        bbr.initial_window(self.initial_window);
        Box::new(Adaptive {
            cubic: Arc::new(cubic).build(now, mtu),
            bbr: Arc::new(bbr).build(now, mtu),
            policy: Policy::new(now),
            rtt: None,
            floor: Floor::default(),
            initial_window: self.initial_window,
        })
    }
}

struct Adaptive {
    cubic: Box<dyn Controller>,
    bbr: Box<dyn Controller>,
    policy: Policy,
    /// The smoothed and the smallest round-trip time of the last acknowledgement, and how far the
    /// round-trip time wanders.
    rtt: Option<(Duration, Duration, Duration)>,
    floor: Floor,
    initial_window: u64,
}

impl Adaptive {
    fn active(&self) -> &dyn Controller {
        if self.policy.bbr() {
            self.bbr.as_ref()
        } else {
            self.cubic.as_ref()
        }
    }

    fn tick(&mut self, now: Instant) {
        if self.policy.on_time(now) {
            TO_CUBIC.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Controller for Adaptive {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.cubic.on_sent(now, bytes, last_packet_number);
        self.bbr.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.cubic.on_ack(now, sent, bytes, app_limited, rtt);
        self.bbr.on_ack(now, sent, bytes, app_limited, rtt);
        // the estimator keeps the deviation to itself; the conservative time is the smoothed one
        // plus four times the deviation
        let spread = rtt.conservative().saturating_sub(rtt.get());
        self.floor.observe(now, rtt.get());
        let floor = self.floor.get().unwrap_or_else(|| rtt.min());
        self.rtt = Some((rtt.get(), floor, spread));
        self.tick(now);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.cubic
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
        self.bbr
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        // a loss with no queue in front of it says nothing about the capacity. CUBIC that cut its
        // window for it would need seconds to grow back (a single stray loss in the first round
        // trips left a bulk transfer at a tenth of the link for ten seconds), and BBR that went
        // into recovery for a loss that the jitter of the path made up fell to its smallest window.
        let random = lost_bytes > 0
            && !is_persistent_congestion
            && self
                .rtt
                .is_some_and(|(smoothed, min, spread)| Policy::is_random(smoothed, min, spread));
        if !random {
            self.cubic
                .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
            self.bbr
                .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
        }
        // lost_bytes is 0 for a mark of congestion by the network (ECN), which is a queue.
        if lost_bytes > 0
            && let Some((smoothed, min, spread)) = self.rtt
            && self.policy.on_loss(now, smoothed, min, spread)
        {
            TO_BBR.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.cubic.on_mtu_update(new_mtu);
        self.bbr.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        self.active().window()
    }

    fn metrics(&self) -> quinn::congestion::ControllerMetrics {
        self.active().metrics()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            cubic: self.cubic.clone_box(),
            bbr: self.bbr.clone_box(),
            policy: self.policy.clone(),
            rtt: self.rtt,
            floor: self.floor.clone(),
            initial_window: self.initial_window,
        })
    }

    fn initial_window(&self) -> u64 {
        self.initial_window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_floor_is_the_lowest_time_of_the_window_and_forgets_older_ones() {
        let start = Instant::now();
        let mut floor = Floor::default();
        floor.observe(start, Duration::from_millis(40));
        floor.observe(start + Duration::from_secs(2), Duration::from_millis(120));
        floor.observe(start + Duration::from_secs(3), Duration::from_millis(130));
        assert_eq!(floor.get(), Some(Duration::from_millis(40)));
        // the low time lies outside the window now
        floor.observe(
            start + FLOOR_WINDOW + Duration::from_secs(5),
            Duration::from_millis(125),
        );
        assert_eq!(floor.get(), Some(Duration::from_millis(125)));
    }
}
