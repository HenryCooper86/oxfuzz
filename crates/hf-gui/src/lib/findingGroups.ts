interface GroupableFinding {
  crash: { id: string; run_id: string; stack_signature: string };
  target_id: string;
  /** Service identity of the bug; equal for findings of one bug. */
  bug_key?: string;
}

export interface FindingGroup<T extends GroupableFinding> {
  key: string;
  /** The first member in queue order, which is attention order. */
  representative: T;
  members: T[];
  runCount: number;
}

/**
 * Group findings that are the same crash, across runs: by the service's bug
 * key (which also matches an unsymbolized replay to its symbolized report),
 * else by target and stack signature. Findings with neither stay on their own.
 */
export function groupFindings<T extends GroupableFinding>(items: readonly T[]): FindingGroup<T>[] {
  const groups = new Map<string, FindingGroup<T>>();
  for (const item of items) {
    const signature = item.crash.stack_signature.trim();
    const key = item.bug_key
      ? `bug\u0000${item.bug_key}`
      : signature ? `${item.target_id}\u0000${signature}` : `crash\u0000${item.crash.id}`;
    const group = groups.get(key);
    if (group) group.members.push(item);
    else groups.set(key, { key, representative: item, members: [item], runCount: 0 });
  }
  return [...groups.values()].map((group) => ({
    ...group,
    runCount: new Set(group.members.map((member) => member.crash.run_id)).size,
  }));
}
