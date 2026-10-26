use std::time::{Duration, Instant};

use ssj_net::adaptive::Policy;

const MIN: Duration = Duration::from_millis(40);

fn at(base: Instant, ms: u64) -> Instant {
    base + Duration::from_millis(ms)
}

#[test]
fn a_loss_without_a_queue_is_random_and_a_loss_with_one_is_not() {
    // the round trip time is near its minimum: nothing has queued.
    assert!(Policy::is_random(
        Duration::from_millis(41),
        MIN,
        Duration::ZERO
    ));
    assert!(Policy::is_random(
        Duration::from_millis(48),
        MIN,
        Duration::ZERO
    ));
    // 15 percent and 2 ms above the minimum is the limit.
    assert!(!Policy::is_random(
        Duration::from_millis(49),
        MIN,
        Duration::ZERO
    ));
    assert!(!Policy::is_random(
        Duration::from_millis(120),
        MIN,
        Duration::ZERO
    ));
    // a LAN: 2 ms of slack still counts, 5 ms does not.
    assert!(Policy::is_random(
        Duration::from_micros(1500),
        Duration::from_micros(400),
        Duration::ZERO
    ));
    assert!(!Policy::is_random(
        Duration::from_millis(5),
        Duration::from_micros(400),
        Duration::ZERO
    ));
}

#[test]
fn a_path_with_jitter_is_not_taken_for_a_queue() {
    // the smallest round trip is an extreme on a jittery path: the usual one is far above it, and
    // that is no queue as long as the round trip time wanders as much
    assert!(!Policy::is_random(
        Duration::from_millis(130),
        Duration::from_millis(90),
        Duration::ZERO
    ));
    assert!(Policy::is_random(
        Duration::from_millis(130),
        Duration::from_millis(90),
        Duration::from_millis(60)
    ));
    // a queue that fills steadily has a small spread, and stays one
    assert!(!Policy::is_random(
        Duration::from_millis(250),
        Duration::from_millis(90),
        Duration::from_millis(8)
    ));
}

#[test]
fn it_starts_with_cubic_and_stays_there_on_a_clean_path() {
    let base = Instant::now();
    let mut policy = Policy::new(base);
    assert!(!policy.bbr());
    // time alone changes nothing.
    assert!(!policy.on_time(at(base, 3_600_000)));
    assert!(!policy.bbr());
}

#[test]
fn losses_with_a_queue_never_move_it_to_bbr() {
    let base = Instant::now();
    let mut policy = Policy::new(base);
    for i in 0..50 {
        let moved = policy.on_loss(
            at(base, i * 100),
            Duration::from_millis(90),
            MIN,
            Duration::ZERO,
        );
        assert!(!moved);
    }
    assert!(!policy.bbr());
}

#[test]
fn four_random_losses_within_ten_seconds_move_it_to_bbr() {
    let base = Instant::now();
    let mut policy = Policy::new(base);
    let smoothed = Duration::from_millis(42);
    for i in 0..3 {
        assert!(!policy.on_loss(at(base, i * 1000), smoothed, MIN, Duration::ZERO));
    }
    assert!(!policy.bbr());
    assert!(policy.on_loss(at(base, 3000), smoothed, MIN, Duration::ZERO));
    assert!(policy.bbr());
    // already there: more losses do not report another move.
    assert!(!policy.on_loss(at(base, 3500), smoothed, MIN, Duration::ZERO));
    assert!(policy.bbr());
}

#[test]
fn losses_spread_over_a_long_time_do_not_add_up() {
    let base = Instant::now();
    let mut policy = Policy::new(base);
    let smoothed = Duration::from_millis(42);
    // one loss every 4 seconds: never four within ten.
    for i in 0..30 {
        assert!(!policy.on_loss(at(base, i * 4000), smoothed, MIN, Duration::ZERO));
    }
    assert!(!policy.bbr());
}

#[test]
fn thirty_quiet_seconds_move_it_back_and_a_loss_postpones_that() {
    let base = Instant::now();
    let mut policy = Policy::new(base);
    let smoothed = Duration::from_millis(42);
    for i in 0..4 {
        policy.on_loss(at(base, i * 100), smoothed, MIN, Duration::ZERO);
    }
    assert!(policy.bbr());
    assert!(!policy.on_time(at(base, 20_000)));
    // a loss at 25 s starts the quiet time again.
    assert!(!policy.on_loss(at(base, 25_000), smoothed, MIN, Duration::ZERO));
    assert!(!policy.on_time(at(base, 50_000)));
    assert!(policy.bbr());
    assert!(policy.on_time(at(base, 55_001)));
    assert!(!policy.bbr());
    // back on cubic it takes four fresh losses again.
    assert!(!policy.on_loss(at(base, 56_000), smoothed, MIN, Duration::ZERO));
    assert!(!policy.bbr());
}
