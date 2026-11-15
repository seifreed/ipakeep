//! Global logging installation, isolated in its own test process.

use ipakeep::infrastructure::observability::init_logging;

#[test]
fn installs_the_global_subscriber_exactly_once() {
    assert_eq!(init_logging(false), Ok(()));
    assert_eq!(
        init_logging(true),
        Err("could not install the global logging subscriber".to_string())
    );
}
