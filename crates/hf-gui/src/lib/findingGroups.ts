interface GroupableFinding {
  crash: { id: string; run_id: string; stack_signature: string };
  target_id: string;
  /** Service identity of the bug; equal for findings of one bug. */
  bug_key?: string;
  /** Whether report, reproduction and export actions work on this finding
   *  (it belongs to its target's latest run). */
  latest_scoped_actions_allowed?: boolean;
}

export interface FindingGroup<T extends GroupableFinding> {
  key: string;
  /** The member from the target's latest run, where report actions work;
   *  else the first in queue order, which is attention order. Always
   *  `members[0]`. */
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
  return [...groups.values()].map((group) => {
    // A bug reproduced run after run would otherwise be led by its oldest
    // occurrence, on which Compose Report and the other latest-run actions
    // are disabled.
    const lead = group.members.findIndex((member) => member.latest_scoped_actions_allowed === true);
    const members = lead > 0
      ? [group.members[lead], ...group.members.slice(0, lead), ...group.members.slice(lead + 1)]
      : group.members;
    return {
      ...group,
      representative: members[0],
      members,
      runCount: new Set(members.map((member) => member.crash.run_id)).size,
    };
  });
}
