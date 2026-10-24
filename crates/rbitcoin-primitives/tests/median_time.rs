use rbitcoin_primitives::median_time::*;

#[test]
fn unsorted_three() {
    let window = MedianWindow::new(&[3, 1, 2]).unwrap();
    assert_eq!(median_time_past_times(window), 2);
}

#[test]
fn even_count_takes_the_lower_middle() {
    let window = MedianWindow::new(&[1, 2, 3, 4]).unwrap();
    assert_eq!(median_time_past_times(window), 3);
}
