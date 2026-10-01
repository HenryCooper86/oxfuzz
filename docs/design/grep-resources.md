# Grep receive and result resources

Owner: hf-tools; configuration assembly: hf-service and hf-agent.
Scope: existing read-only Grep tool, not a new execution subsystem.

## Configuration

The service loads [grep] from oxfuzz.toml before a chat turn can reach a
provider. Shared typed configuration and its immutable resolved values live
in hf-core. The service passes this snapshot to the Agent, its inspection
registry and existing delegated children. Direct tool/agent construction
resolves the same documented defaults. Invalid or unknown settings fail load.

| Setting | Default | Maximum |
| --- | --- | --- |
| output_bytes | 10000 | 1048576 |
| heap_bytes | 16777216 | 268435456 |
| timeout_secs | 30 | 300 |

Every value must be positive. output_bytes covers retained result text and
file names, including separators; JSON escaping and result metadata are
additional finite allocations. heap_bytes limits grep-searcher's reader
line/multiline buffers with memory mapping disabled. The fixed decoding buffer
is additional. It is not a file-size or process RSS
promise. Regex, decoding, walker and allocator overhead remain additional.
A multiline search needs room to verify EOF as required by grep-searcher;
a file exactly as large as its buffer allowance can therefore fail explicitly.

## Pagination and totals

Skip offset entries while scanning without copying them. Retain the requested
page under both head_limit and output_bytes, and stop the file/walk when an
extra entry establishes continuation. head_limit=0 removes the entry limit
only. Matching text is formatted into available space, never into an unlimited
intermediate string. A content entry can return a UTF-8-safe prefix and consume
that entry; nextOffset advances past it. Use FileRead or a narrower query for
the omitted text. File-name and count entries are atomic; an entry that cannot
fit alone fails with a bounded explanation to raise the allowance or narrow
the query, rather than returning an invalid path or a repeating continuation.

Returned content includes truncated, hasMore, totalsComplete, numReturned,
nextOffset and limitingReason. Totals count matches/files observed during this
scan, including the extra continuation witness. Early stop sets totalsComplete
false; these fields do not claim a whole-tree inventory. numFiles in content
mode continues to count files represented in the returned page, using actual
file identity rather than splitting formatted paths. Count mode completes each
visited file's count before adding its entry. numLines counts matching sink
records; with multiline patterns one record can contain several physical lines.

Context options already configure the searcher but the old UTF8 sink discarded
context events. This repair preserves matching-record output and documents
those options as reserved/ignored, rather than adding a second pagination
meaning. Reader context retention remains subject to heap_bytes.

## Cancellation and errors

A cancellation-aware regular-file reader checks cancellation/deadline before
reads; match sinks and count iteration check too. Timeout and caller drop signal
that same worker, including single-file searches. An in-flight blocking OS read
or regex operation cannot be forcibly interrupted; no hard worker-latency or
CPU preemption guarantee is claimed. Reader/sink checks stop at the next
cooperative point. Search and walk errors propagate instead of returning
misleading successful partial output. Source scope and link policies remain
those of the existing inspection tools. NUL bytes do not reclassify a file or
renumber its matching records; otherwise a later page could lose ordinary
files that earlier continuation offsets had counted after that file. Matching
non-UTF-8 text fails explicitly. Read failures return errors.


## Verification

Small inert regular-file fixtures exercise real registered dispatch: offset,
all modes, exact/over output allowance, oversized line, UTF-8, partial totals,
continuation, long-line/multiline reader admission, config forwarding and
cancellation. No generated harness, target, fuzzer or private provider is run.
