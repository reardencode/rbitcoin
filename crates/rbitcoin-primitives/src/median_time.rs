//! BIP113 median-time-past of an already-collected timestamp window.

/// Median of `times` (unsorted OK). An empty window is an error.
pub fn median_time_past_times(times: &[u32]) -> Result<u32, &'static str> {
    if times.is_empty() {
        return Err("invariant: empty median time");
    }
    let mut sorted = times.to_vec();
    sorted.sort_unstable();
    Ok(sorted[sorted.len() / 2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsorted_three() {
        assert_eq!(median_time_past_times(&[3, 1, 2]).unwrap(), 2);
    }

    #[test]
    fn empty_median_time_is_an_error() {
        let err = median_time_past_times(&[]).unwrap_err();
        assert!(err.contains("median"), "{err}");
    }
}
