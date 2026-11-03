Fixed

- **Initial download connects archived blocks that spend an output created in the same archived batch.** A retry found no range for a parent created in that batch, or in an earlier chunk of the same wave. It logged `lookup stage miss` and stopped below blocks that were valid. The retry follows an invalid block in a batch, or a restart after a crash between writing the block and advancing the tip.
