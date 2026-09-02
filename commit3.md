Implement per-port striping and fix MuxCon regression

This patch refactors the `wsmux` multiplexing dispatcher to support per-flow
decisions on whether to use striping or plain single-leg connections.

Key features:
1. **Per-flow framing**: For `MuxVersion >= 2`, every flow is prefixed with a
   1-byte indicator (`utils.FlowPlain` or `utils.FlowStriped`). These prefixes
   have been combined into a single write buffer with their respective headers,
   preventing tiny fragmented frames over the network.
2. **MuxCon Regression Fix**: The `MuxCon` concurrency limit regression has been
   addressed for plain flows by introducing `acquirePlainSlot()` and enforcing
   the global session pool budget dynamically via CAS.
3. **Design A (Port-Based Routing)**: The server now uses `shouldStripe` to
   dynamically route connections to `dispatchPlain` or `dispatchStriped` based
   on the `StripePorts` configuration.

(Note: Design B / Mid-stream promotion was deliberately omitted due to the
inherent data-loss risks of hot-swapping a `smux.Stream` without `CloseWrite`
support on a bidirectional connection. The user acknowledged these risks and
confirmed that Design A is clearer and lower risk).
