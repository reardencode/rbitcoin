Fixed

- **A failed read at open no longer rolls the tip back.** Tip-window revalidation treated an OS read error the same as a corrupt block, so one transient error on a recent record dropped the tip below that block and cleared its body association, again on every start. Open now stops with the read error and leaves the chain as it was, as Core does. A corrupt or missing record, or a stored length past the body read cap, still shrinks the tip.
