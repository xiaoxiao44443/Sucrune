# Manager active execution index

The Go manager counts ordinary and resident executions separately for each environment. A Linux request with `resident: true` can run alongside the project's single ordinary execution. Both counts retain the environment until terminal publication.
The existing `Service.mu` covers index queries, storage commits and index updates.
Only one live Service may own a data directory; the shared bridge cache retains
that Service. This is not a cross-process lock or protection from same-UID writers.

Previously, each active check reread every historical execution record, including
when importing one file. Environment state, delete, import and execution-create
guards now use the index. A normal lookup is O(1), and environment listing adds
one lookup per listed environment; historical record count does not affect those
lookups. The index retains active environment IDs only, not terminal output or
other historical metadata.

`Open` still reads and validates the complete history and durably marks previous
running records `lost`, as before. `exec.get` and `exec.list` retain their existing
on-disk parsing, consistency checks and historical results, including records for
deleted environments. Active-state queries are no longer implicit audits of
completed history: external edits to old records during a manager lifetime are
detected by explicit history reads or the next `Open`, not every `env.get/list`.
The same manager-owned active index is used by delete/import/create guards.

Successful execution creation increments the count only after directory
publication and sync succeed. Successful terminal publication decrements it.
Rename can succeed before directory sync reports an error, so an error cannot
always mean that no record changed. An uncertain publication invalidates the
index. The next active query performs one full validated scan of visible records
and replaces the index; it does not mark live executions lost. A failed scan
leaves the index invalid and blocks dependent operations until storage can be
read consistently. Normal successful operations do not perform this scan.

If failed creation left a complete visible running record, the conservative
existing behavior is retained: it occupies its environment until the manager
records `lost` through `exec.finish`, or restart recovery does so. `exec.list`
can identify that record. No worker is started by Go, and this optimization does
not invent evidence that a worker stopped. A failed terminal commit that is
already visible as a complete terminal record is recognized on reconciliation;
it does not leave a stale active entry indefinitely.

Tests inject errors before/after creation publication and terminal publication,
check independent environments and import guards, reject corrupt records while
reconciling, retain history validation, and recover multiple environments after
restart. The reproducible benchmark is:

```powershell
go test ./internal/runtimecore -run '^$' -bench '^BenchmarkEnvironmentGetWithHistory$' -benchtime=200x -count=1
```

On the checked Windows x64 Go 1.26.10 host, `env.get` took about 0.32 ms with no
history and 0.40 ms with 1000 terminal records, with 45 allocations per call in
both cases. These are one host run, not an Android performance guarantee. The
benchmark excludes startup validation and fixture creation, which intentionally
continue to scale with history size.
