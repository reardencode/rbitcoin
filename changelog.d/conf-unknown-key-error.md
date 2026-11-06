Changed

- **Unknown conf keys are now a hard error.** A misspelled or unknown key in
  the conf file previously warned and was ignored, so a typo in a privacy or
  security key failed open. The node now refuses to start, matching the CLI
  and Bitcoin Core, and the error names the file, line, and key.