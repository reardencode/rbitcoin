Security

- A fuse8 segment length that is not a power of two is rejected as corrupt.
- A var-table or create.loc read past the published end is corrupt.
- Dropping an undrained io_uring session fails closed instead of freeing
  buffers a completion may still own. The drain hard cap is unchanged.
- A sorted-run manifest or txstat blob longer than the file is corrupt
  and is not allocated.
- The datadir `.lock` is created mode 0600 and is not followed if it is
  a symlink.
- Pool write jobs read the caller buffer through a shared slice.
- Findings write-ups: 067, 068, 069, 070, 071, 072.
