use super::*;

#[test]
fn hourly_boundary_and_clock_rollback() {
    assert!(due(None, 100));
    assert!(!due(Some(100), 100));
    assert!(!due(Some(100), 99));
    assert!(!due(Some(100), 100 + INTERVAL - 1));
    assert!(due(Some(100), 100 + INTERVAL));
    assert!(due(Some(100), 100 + 2 * INTERVAL));
}
