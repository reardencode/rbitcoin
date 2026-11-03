Fixed

- **After a crash, initial download puts archived bodies above the tip back on the download queue.** A crash between writing the block and advancing the tip leaves those bodies. Restart used to mark them archived and skip them, and only a quarter-full queue raced that hole, so download could sit at the old tip.
