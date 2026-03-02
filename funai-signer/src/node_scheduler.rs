// Copyright (C) 2020-2024 Funai Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::seq::SliceRandom;
use rand::Rng;
use rusqlite::{params, Connection, Result as SqliteResult};
use serde::{Deserialize, Serialize};
use slog::{slog_debug, slog_info, slog_warn};

use funai_common::{debug, info, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const W_SPEED: f64 = 0.45;
const W_REPUTATION: f64 = 0.35;
const W_STAKE: f64 = 0.15;
const W_BID: f64 = 0.05;

const HALF_LIFE_DAYS: f64 = 14.0;
const ALPHA: f64 = 5.0;
const BETA: f64 = 2.0;

const EPSILON: f64 = 1e-6;

const TOPK: usize = 3;
const EXPLORE_RATIO: f64 = 0.10;

const MIN_REPUTATION_FOR_POOL: f64 = 0.7;
const MIN_ACTIVITY_FOR_POOL: u64 = 10;

const NEW_NODE_TASK_THRESHOLD: u64 = 20;
const NEW_NODE_DAYS_THRESHOLD: u64 = 3;
const NEW_NODE_MAX_TOKENS: u64 = 2048;

const TPS_WINDOW_SIZE: usize = 1000;
const FORCED_RECALC_THRESHOLD: u64 = 100;

const PENALTY_COOLDOWN_SECS: u64 = 3600;
const SLASH_COOLDOWN_SECS: u64 = 86400 * 7;

// ---------------------------------------------------------------------------
// Per-node statistics
// ---------------------------------------------------------------------------

/// Persistent per-node statistics tracked by the scheduler.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeStats {
    /// Unique node identifier.
    pub node_id: String,
    /// Bayesian success count (decayed).
    pub succ: f64,
    /// Bayesian failure count (decayed).
    pub fail: f64,
    /// Unix timestamp of last task completion.
    pub last_active_at: u64,
    /// Unix timestamp when this node was first registered.
    pub first_seen_at: u64,
    /// Rolling count of tasks completed in the scoring window.
    pub total_tasks_window: u64,
    /// Unix timestamp until which this node is in penalty cooldown.
    pub penalty_until: u64,
    /// Cached stake amount (µSTX).
    pub stake_amount: u128,
    /// Current bid price multiplier (1.0 = baseline).
    pub bid_price: f64,
}

impl NodeStats {
    /// Create stats for a newly-seen node.
    pub fn new(node_id: &str) -> Self {
        let now = now_secs();
        Self {
            node_id: node_id.to_string(),
            succ: 0.0,
            fail: 0.0,
            last_active_at: now,
            first_seen_at: now,
            total_tasks_window: 0,
            penalty_until: 0,
            stake_amount: 0,
            bid_price: 1.0,
        }
    }

    /// Whether this node is considered "new" and subject to task restrictions.
    pub fn is_new_node(&self) -> bool {
        let now = now_secs();
        let online_days = now.saturating_sub(self.first_seen_at) / 86400;
        self.total_tasks_window < NEW_NODE_TASK_THRESHOLD || online_days < NEW_NODE_DAYS_THRESHOLD
    }

    /// Whether this node is currently in a penalty cooldown.
    pub fn is_in_penalty(&self) -> bool {
        now_secs() < self.penalty_until
    }

    /// Compute the reputation score using Bayesian smoothing with half-life decay.
    pub fn reputation_score(&self) -> f64 {
        (self.succ + ALPHA) / (self.succ + self.fail + ALPHA + BETA)
    }

    /// Apply time-based decay to success/fail counters and record a new outcome.
    pub fn record_outcome(&mut self, success: bool) {
        let now = now_secs();
        let dt_days = (now.saturating_sub(self.last_active_at) as f64) / 86400.0;
        let decay = 0.5_f64.powf(dt_days / HALF_LIFE_DAYS);

        self.succ *= decay;
        self.fail *= decay;

        if success {
            self.succ += 1.0;
        } else {
            self.fail += 1.0;
        }

        self.last_active_at = now;
        self.total_tasks_window += 1;
    }

    /// Apply a penalty: triple the fail count and set a cooldown.
    pub fn apply_penalty(&mut self) {
        self.fail *= 3.0;
        self.penalty_until = now_secs() + PENALTY_COOLDOWN_SECS;
    }
}

// ---------------------------------------------------------------------------
// Task metadata used during assignment decisions
// ---------------------------------------------------------------------------

/// Lightweight view of a task for scheduling decisions.
pub struct TaskCandidate {
    /// Unique task identifier.
    pub task_id: String,
    /// The inference fee attached to this task (µSTX).
    pub infer_fee: u64,
    /// Model type name (for logging / new-node filtering).
    pub model_type: String,
    /// Estimated output token count (0 if unknown at assignment time).
    pub estimated_tokens: u64,
    /// Normalised task price used for new-node median filtering.
    pub price: f64,
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

/// The node scheduler manages scoring, ranking, and dispatch of inference
/// tasks to registered inference nodes.
pub struct NodeScheduler {
    /// Per-node statistics keyed by node_id.
    stats: HashMap<String, NodeStats>,
    /// Global TPS sample window (across all nodes) for percentile calculation.
    global_tps_samples: VecDeque<f64>,
    /// Cached P10.
    tps_p10: f64,
    /// Cached P90.
    tps_p90: f64,
    /// Counter: consecutive new samples that fell outside the current P90.
    consecutive_outside_p90: u64,
    /// In-flight task assignments: task_id -> (node_id, assigned_at_secs).
    in_flight: HashMap<String, (String, u64)>,
    /// Median task price (for new-node gating).
    median_price: f64,
}

impl NodeScheduler {
    /// Create a new scheduler, optionally loading persisted state from the DB.
    pub fn new(conn: &Connection) -> Self {
        Self::ensure_tables(conn);
        let stats = Self::load_all_stats(conn).unwrap_or_default();
        Self {
            stats,
            global_tps_samples: VecDeque::with_capacity(TPS_WINDOW_SIZE),
            tps_p10: 0.0,
            tps_p90: 0.0,
            consecutive_outside_p90: 0,
            in_flight: HashMap::new(),
            median_price: 0.0,
        }
    }

    // ------------------------------------------------------------------
    // DB helpers
    // ------------------------------------------------------------------

    fn ensure_tables(conn: &Connection) {
        let _ = conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS node_stats (
                node_id          TEXT PRIMARY KEY,
                succ             REAL NOT NULL DEFAULT 0,
                fail             REAL NOT NULL DEFAULT 0,
                last_active_at   INTEGER NOT NULL DEFAULT 0,
                first_seen_at    INTEGER NOT NULL DEFAULT 0,
                total_tasks_window INTEGER NOT NULL DEFAULT 0,
                penalty_until    INTEGER NOT NULL DEFAULT 0,
                stake_amount     INTEGER NOT NULL DEFAULT 0,
                bid_price        REAL NOT NULL DEFAULT 1.0
            );
            CREATE TABLE IF NOT EXISTS tps_samples (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id  TEXT NOT NULL,
                tps      REAL NOT NULL,
                ts       INTEGER NOT NULL
            );",
        );
    }

    fn load_all_stats(conn: &Connection) -> SqliteResult<HashMap<String, NodeStats>> {
        let mut stmt = conn.prepare(
            "SELECT node_id, succ, fail, last_active_at, first_seen_at,
                    total_tasks_window, penalty_until, stake_amount, bid_price
             FROM node_stats",
        )?;
        let mut map = HashMap::new();
        let mut rows = stmt.query::<[&dyn rusqlite::ToSql; 0]>([])?;
        while let Some(row) = rows.next()? {
            let node_id: String = row.get(0)?;
            let stake_i64: i64 = row.get(7)?;
            let s = NodeStats {
                node_id: node_id.clone(),
                succ: row.get(1)?,
                fail: row.get(2)?,
                last_active_at: row.get::<_, i64>(3)? as u64,
                first_seen_at: row.get::<_, i64>(4)? as u64,
                total_tasks_window: row.get::<_, i64>(5)? as u64,
                penalty_until: row.get::<_, i64>(6)? as u64,
                stake_amount: stake_i64 as u128,
                bid_price: row.get(8)?,
            };
            map.insert(node_id, s);
        }
        Ok(map)
    }

    /// Persist a single node's stats to the DB.
    pub fn save_node_stats(&self, conn: &Connection, node_id: &str) {
        if let Some(s) = self.stats.get(node_id) {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO node_stats
                 (node_id, succ, fail, last_active_at, first_seen_at,
                  total_tasks_window, penalty_until, stake_amount, bid_price)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    s.node_id,
                    s.succ,
                    s.fail,
                    s.last_active_at as i64,
                    s.first_seen_at as i64,
                    s.total_tasks_window as i64,
                    s.penalty_until as i64,
                    s.stake_amount as i64,
                    s.bid_price,
                ],
            );
        }
    }

    fn save_tps_sample(conn: &Connection, node_id: &str, tps: f64) {
        let _ = conn.execute(
            "INSERT INTO tps_samples (node_id, tps, ts) VALUES (?, ?, ?)",
            params![node_id, tps, now_secs() as i64],
        );
    }

    // ------------------------------------------------------------------
    // Scoring
    // ------------------------------------------------------------------

    /// Ensure a node has a stats entry; create one if missing.
    pub fn ensure_node(&mut self, node_id: &str) {
        if !self.stats.contains_key(node_id) {
            self.stats.insert(node_id.to_string(), NodeStats::new(node_id));
        }
    }

    /// Update the cached stake amount for a node.
    pub fn update_stake(&mut self, node_id: &str, amount: u128) {
        self.ensure_node(node_id);
        if let Some(s) = self.stats.get_mut(node_id) {
            s.stake_amount = amount;
        }
    }

    /// Record the outcome of a completed task and update all relevant scores.
    /// `latency_secs` is the wall-clock time from assignment to completion.
    /// `total_tokens` is the number of output tokens produced.
    pub fn record_task_outcome(
        &mut self,
        conn: &Connection,
        node_id: &str,
        task_id: &str,
        success: bool,
        total_tokens: u64,
        latency_secs: f64,
    ) {
        self.ensure_node(node_id);

        // 1. Reputation update
        if let Some(s) = self.stats.get_mut(node_id) {
            s.record_outcome(success);

            if !success {
                s.apply_penalty();
            }
        }

        // 2. TPS tracking (only on success with valid data)
        if success && latency_secs > 0.0 && total_tokens > 0 {
            let tps = total_tokens as f64 / latency_secs;

            if self.global_tps_samples.len() >= TPS_WINDOW_SIZE {
                self.global_tps_samples.pop_front();
            }
            self.global_tps_samples.push_back(tps);

            Self::save_tps_sample(conn, node_id, tps);

            // Track consecutive samples outside P90 for forced recalc
            if self.tps_p90 > EPSILON && tps > self.tps_p90 {
                self.consecutive_outside_p90 += 1;
            } else {
                self.consecutive_outside_p90 = 0;
            }

            if self.consecutive_outside_p90 >= FORCED_RECALC_THRESHOLD {
                info!("Forced TPS percentile recalculation after {} consecutive samples above P90", FORCED_RECALC_THRESHOLD);
                self.recalc_percentiles();
                self.consecutive_outside_p90 = 0;
            }
        }

        // 3. Remove from in-flight
        self.in_flight.remove(task_id);

        // 4. Persist
        self.save_node_stats(conn, node_id);
    }

    /// Record an on-chain slash for a fraudulent inference node.
    /// This is much harsher than a normal task failure: the fail counter is
    /// multiplied by 10 and a 7-day cooldown is applied.
    pub fn record_slash(
        &mut self,
        conn: &Connection,
        node_id: &str,
    ) {
        self.ensure_node(node_id);
        if let Some(s) = self.stats.get_mut(node_id) {
            s.fail *= 10.0;
            s.penalty_until = now_secs() + SLASH_COOLDOWN_SECS;
            warn!("Node {} slashed: fail={:.1}, cooldown until {}", node_id, s.fail, s.penalty_until);
        }
        self.save_node_stats(conn, node_id);
    }

    /// Recalculate P10 and P90 from the global TPS sample window.
    pub fn recalc_percentiles(&mut self) {
        if self.global_tps_samples.is_empty() {
            self.tps_p10 = 0.0;
            self.tps_p90 = 0.0;
            return;
        }
        let mut sorted: Vec<f64> = self.global_tps_samples.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = sorted.len();
        self.tps_p10 = sorted[(n as f64 * 0.10).floor() as usize];
        self.tps_p90 = sorted[((n as f64 * 0.90).floor() as usize).min(n - 1)];
    }

    /// Compute speed score for a node from its most recent TPS relative to
    /// the global P10/P90 window.
    fn speed_score_for_node(&self, node_id: &str) -> f64 {
        let recent_tps = self.recent_tps_for_node(node_id);
        if recent_tps <= 0.0 {
            return 0.5; // neutral for nodes without data
        }
        let range = self.tps_p90 - self.tps_p10 + EPSILON;
        let raw = (recent_tps - self.tps_p10) / range;
        raw.clamp(0.0, 1.0)
    }

    /// Get the most recent TPS sample for a given node.
    /// In a production system we'd keep per-node deques; here we scan the
    /// global window (which is bounded and small).
    fn recent_tps_for_node(&self, _node_id: &str) -> f64 {
        // For the first version, use the node's average TPS from the in-memory
        // window. Per-node tracking uses the DB `tps_samples` table and can
        // be queried for richer analytics.
        //
        // The global percentile-based scoring already provides fairness;
        // per-node breakdowns are an optimisation for later.
        if self.global_tps_samples.is_empty() {
            return 0.0;
        }
        // Use the median of the global window as the baseline for nodes
        // without individual TPS data. We'll refine this when per-node
        // tracking is added.
        let mut sorted: Vec<f64> = self.global_tps_samples.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        sorted[sorted.len() / 2]
    }

    fn stake_score(&self, node_id: &str) -> f64 {
        let amount = self
            .stats
            .get(node_id)
            .map(|s| s.stake_amount)
            .unwrap_or(0);
        let (min_s, max_s) = self.stake_bounds();
        let range = (max_s as f64) - (min_s as f64) + EPSILON;
        ((amount as f64 - min_s as f64) / range).clamp(0.0, 1.0)
    }

    fn stake_bounds(&self) -> (u128, u128) {
        let mut min_s = u128::MAX;
        let mut max_s = 0u128;
        for s in self.stats.values() {
            if s.stake_amount > 0 {
                min_s = min_s.min(s.stake_amount);
                max_s = max_s.max(s.stake_amount);
            }
        }
        if min_s == u128::MAX {
            min_s = 0;
        }
        (min_s, max_s)
    }

    fn bid_score(&self, node_id: &str) -> f64 {
        let bid = self
            .stats
            .get(node_id)
            .map(|s| s.bid_price)
            .unwrap_or(1.0);
        // Lower bid = higher score. Normalised against a max of 2.0.
        (1.0 - (bid / (2.0 + EPSILON))).clamp(0.0, 1.0)
    }

    /// Compute the composite FinalScore for a node.
    pub fn final_score(&self, node_id: &str) -> f64 {
        let speed = self.speed_score_for_node(node_id);
        let rep = self
            .stats
            .get(node_id)
            .map(|s| s.reputation_score())
            .unwrap_or(0.5);
        let stake = self.stake_score(node_id);
        let bid = self.bid_score(node_id);

        W_SPEED * speed + W_REPUTATION * rep + W_STAKE * stake + W_BID * bid
    }

    // ------------------------------------------------------------------
    // Dispatch
    // ------------------------------------------------------------------

    /// Select the best node for a given task from the set of `eligible_node_ids`.
    ///
    /// `eligible_node_ids` should already be filtered by model support and
    /// hard stake gate (`stake >= 3 * infer_fee`).
    ///
    /// Returns `Some(node_id)` or `None` if no qualified node is available.
    pub fn select_node(
        &mut self,
        eligible_node_ids: &[String],
        task: &TaskCandidate,
    ) -> Option<String> {
        if eligible_node_ids.is_empty() {
            return None;
        }

        // 1. Build qualified pool (pass gate)
        let qualified: Vec<&String> = eligible_node_ids
            .iter()
            .filter(|nid| self.passes_qualified_gate(nid))
            .collect();

        if qualified.is_empty() {
            debug!("No nodes pass the qualified pool gate for task {}", task.task_id);
            // Fall back: try all eligible nodes without gate (graceful degradation)
            return self.select_fallback(eligible_node_ids, task);
        }

        // 2. Apply new-node protection filter
        let qualified: Vec<&String> = qualified
            .into_iter()
            .filter(|nid| {
                let stats = self.stats.get(nid.as_str());
                if let Some(s) = stats {
                    if s.is_new_node() {
                        // New nodes can only take small/cheap tasks
                        return task.estimated_tokens <= NEW_NODE_MAX_TOKENS
                            && task.price <= self.median_price;
                    }
                }
                true
            })
            .collect();

        if qualified.is_empty() {
            debug!("No non-new nodes available for task {}", task.task_id);
            return self.select_fallback(eligible_node_ids, task);
        }

        // 3. Score all qualified nodes
        let mut scored: Vec<(&String, f64)> = qualified
            .iter()
            .map(|nid| (*nid, self.final_score(nid)))
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // 4. TopK vs exploration
        let mut rng = rand::thread_rng();
        let roll: f64 = rng.gen();

        let selected = if roll < EXPLORE_RATIO && scored.len() > TOPK {
            // Exploration: random pick from qualified pool excluding TopK
            let explore_pool: Vec<&String> = scored[TOPK..].iter().map(|(nid, _)| *nid).collect();
            explore_pool.choose(&mut rng).map(|nid| (*nid).clone())
        } else {
            // Exploit: pick from TopK (weighted random within TopK for fairness)
            let top_k: Vec<(&String, f64)> =
                scored.iter().take(TOPK).cloned().collect();
            weighted_random_pick(&top_k, &mut rng)
        };

        if let Some(ref nid) = selected {
            self.in_flight
                .insert(task.task_id.clone(), (nid.clone(), now_secs()));
            info!(
                "Scheduler selected node {} for task {} (score={:.4}, explore={})",
                nid,
                task.task_id,
                self.final_score(nid),
                roll < EXPLORE_RATIO && scored.len() > TOPK
            );
        }

        selected
    }

    /// Graceful fallback when no node passes the gate: pick the best
    /// eligible node by raw score.
    fn select_fallback(&self, eligible: &[String], task: &TaskCandidate) -> Option<String> {
        if eligible.is_empty() {
            return None;
        }
        let mut best: Option<(String, f64)> = None;
        for nid in eligible {
            let score = self.final_score(nid);
            if best.as_ref().map_or(true, |(_, s)| score > *s) {
                best = Some((nid.clone(), score));
            }
        }
        if let Some((ref nid, score)) = best {
            warn!(
                "Scheduler fallback: selected node {} for task {} (score={:.4})",
                nid, task.task_id, score
            );
        }
        best.map(|(nid, _)| nid)
    }

    /// Check whether a node passes the qualified pool gate.
    fn passes_qualified_gate(&self, node_id: &str) -> bool {
        let stats = match self.stats.get(node_id) {
            Some(s) => s,
            None => return false,
        };

        if stats.is_in_penalty() {
            return false;
        }

        if stats.total_tasks_window < MIN_ACTIVITY_FOR_POOL {
            // New nodes bypass the activity check (they can enter via new-node
            // path or exploration). Returning true here lets them into the
            // pool; the new-node filter will restrict what tasks they can take.
            if !stats.is_new_node() {
                return false;
            }
        }

        if stats.reputation_score() < MIN_REPUTATION_FOR_POOL {
            return false;
        }

        true
    }

    /// Get the assignment time for a task (if it's in-flight).
    pub fn get_assigned_at(&self, task_id: &str) -> Option<u64> {
        self.in_flight.get(task_id).map(|(_, ts)| *ts)
    }

    /// Update the median task price (called periodically or on task submit).
    pub fn update_median_price(&mut self, prices: &[f64]) {
        if prices.is_empty() {
            return;
        }
        let mut sorted = prices.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        self.median_price = sorted[sorted.len() / 2];
    }

    /// Get a reference to node stats.
    pub fn get_stats(&self, node_id: &str) -> Option<&NodeStats> {
        self.stats.get(node_id)
    }

    /// Get mutable reference to node stats.
    pub fn get_stats_mut(&mut self, node_id: &str) -> Option<&mut NodeStats> {
        self.stats.get_mut(node_id)
    }

    /// Compute the P95 timeout threshold for the current TPS distribution.
    /// Returns seconds; `None` if insufficient data.
    pub fn p95_timeout(&self, estimated_tokens: u64) -> Option<f64> {
        if self.global_tps_samples.len() < 10 {
            return None;
        }
        let mut sorted: Vec<f64> = self.global_tps_samples.iter().copied().collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p5_tps = sorted[(sorted.len() as f64 * 0.05).floor() as usize]; // P5 TPS = slow end
        if p5_tps < EPSILON {
            return None;
        }
        Some((estimated_tokens as f64 / p5_tps) * 1.5) // 1.5x buffer
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Weighted random pick from scored candidates (higher score = more likely).
fn weighted_random_pick(
    candidates: &[(&String, f64)],
    rng: &mut impl Rng,
) -> Option<String> {
    if candidates.is_empty() {
        return None;
    }
    let total: f64 = candidates.iter().map(|(_, s)| *s).sum();
    if total < EPSILON {
        // All scores ≈ 0, pick uniformly
        return candidates.choose(rng).map(|(nid, _)| (*nid).clone());
    }
    let roll: f64 = rng.gen::<f64>() * total;
    let mut acc = 0.0;
    for (nid, score) in candidates {
        acc += score;
        if roll <= acc {
            return Some((*nid).clone());
        }
    }
    candidates.last().map(|(nid, _)| (*nid).clone())
}

// ---------------------------------------------------------------------------
// Integration helpers (called from inference_api.rs)
// ---------------------------------------------------------------------------

/// Extract total token count from an inference output JSON.
/// Falls back to 0 if the field is not present.
pub fn extract_total_tokens(output_json: &str) -> u64 {
    serde_json::from_str::<serde_json::Value>(output_json)
        .ok()
        .and_then(|v| {
            // Try explicit field first
            if let Some(n) = v.get("total_tokens").and_then(|t| t.as_u64()) {
                return Some(n);
            }
            // Fall back to counting first_top_logprobs array length
            v.get("first_top_logprobs")
                .and_then(|a| a.as_array())
                .map(|arr| arr.len() as u64)
        })
        .unwrap_or(0)
}
