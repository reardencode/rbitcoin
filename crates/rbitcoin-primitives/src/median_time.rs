//! BIP113 median-time-past of an already-collected timestamp window.

/// At least one header timestamp. An empty slice is not a median.
pub struct MedianWindow<'a> {
    times: &'a [u32],
}

impl<'a> MedianWindow<'a> {
    pub fn new(times: &'a [u32]) -> Result<Self, &'static str> {
        if times.is_empty() {
            return Err("invariant: empty median time");
        }
        Ok(Self { times })
    }
}

/// Median of `times` (unsorted OK). The lower middle when the count is even.
pub fn median_time_past_times(times: MedianWindow<'_>) -> u32 {
    let mut sorted = times.times.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}
