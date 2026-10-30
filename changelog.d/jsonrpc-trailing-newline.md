Fixed

- HTTP JSON-RPC bodies end with a newline, and object keys follow Bitcoin
  Core (`result`, `error`, `id`, with `jsonrpc` first on 2.0). A line
  reader such as ckpool can finish the response.
