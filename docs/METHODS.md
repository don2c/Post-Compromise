# Methods implemented by the artifact

## Trace and rings

The code loads the synthetic access trace and staff graph, assigns each event
to a workflow, and builds epoch-rotating rings with target size 64. Graph
neighbours are used before active-user fill.

## Cost model

Runtime tables are generated from stated operation-count formulas. The model
reports key-update cost, Show cost, Verify cost, recovery latency, transcript
size, and public-parameter size.

## Linking evaluation

The artifact reports prior-epoch linking advantage as an empirical score under
the declared exposure class. Reported privacy values are tied to the synthetic
trace, random seed, exposure model, and implemented table-generation code.

## Recovery evaluation

Recovery regenerates credential binding state, refreshes revocation state, and
records stale-state rejection. The verifier interface remains unchanged.
