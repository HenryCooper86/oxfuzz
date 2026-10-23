CREATE TABLE model_budget_scopes (
    scope_id TEXT PRIMARY KEY NOT NULL,
    policy_json TEXT NOT NULL,
    calls INTEGER NOT NULL DEFAULT 0 CHECK(calls >= 0),
    tokens INTEGER NOT NULL DEFAULT 0 CHECK(tokens >= 0),
    cost_microusd INTEGER NOT NULL DEFAULT 0 CHECK(cost_microusd >= 0),
    terminal_reason TEXT,
    blocked INTEGER NOT NULL DEFAULT 0 CHECK(blocked IN (0, 1))
);
CREATE TABLE model_budget_attempts (
    id TEXT PRIMARY KEY NOT NULL,
    scope_id TEXT NOT NULL REFERENCES model_budget_scopes(scope_id),
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    reserved_input INTEGER NOT NULL CHECK(reserved_input >= 0),
    reserved_output INTEGER NOT NULL CHECK(reserved_output >= 0),
    reserved_cost_microusd INTEGER NOT NULL CHECK(reserved_cost_microusd >= 0),
    observed_input INTEGER,
    observed_output INTEGER,
    observed_cost_microusd INTEGER,
    state TEXT NOT NULL CHECK(state IN ('reserved', 'settled', 'overrun')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX model_budget_attempts_scope ON model_budget_attempts(scope_id);
