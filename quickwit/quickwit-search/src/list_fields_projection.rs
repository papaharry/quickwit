// Copyright 2021-Present Datadog, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Pushdown projection for list-fields requests.
//!
//! Builds a `tantivy_fst::Automaton` that accepts any SSTable key starting
//! with at least one of a set of field-name prefixes. Used by
//! `SplitFieldsReader::read_filtered_async` to fetch only the SSTable blocks
//! whose key range can intersect the union of prefixes — wildcard suffixes
//! and exact-length checks for `FieldPattern::Match` are still applied by the
//! existing in-memory post-filter in `merge_leaf_list_fields`.

use std::sync::Arc;

use tantivy_fst::Automaton;

/// Sentinel marking a prefix that can no longer match (a byte mismatched).
const DISQUALIFIED: u32 = u32::MAX;

/// Automaton that accepts keys starting with at least one of `prefixes`.
///
/// Built from the prefix part of `FieldPattern`s in a list-fields request and
/// handed to `SplitFieldsReader::read_filtered_async`. Cloning is cheap
/// (`Arc<[..]>`), so it can be reused across splits.
#[derive(Clone, Debug)]
pub(crate) struct MultiPrefixAutomaton {
    prefixes: Arc<[Vec<u8>]>,
}

impl MultiPrefixAutomaton {
    /// Builds a pushdown automaton from a set of mandatory prefixes.
    ///
    /// Returns `None` when no useful pushdown is possible — either because the
    /// set is empty, or because at least one prefix is empty (which would force
    /// the automaton to match everything anyway, so the caller should issue a
    /// full SSTable scan instead of paying for the automaton machinery).
    pub(crate) fn try_new(prefixes: Vec<Vec<u8>>) -> Option<Self> {
        if prefixes.is_empty() || prefixes.iter().any(|p| p.is_empty()) {
            return None;
        }
        Some(MultiPrefixAutomaton {
            prefixes: prefixes.into(),
        })
    }
}

/// Per-streamer state for `MultiPrefixAutomaton`.
///
/// `Done` is sticky: once any prefix is fully matched the automaton accepts
/// the key and every descendant key, so streaming can fast-path the rest of
/// the block.
#[derive(Clone, Debug)]
pub(crate) enum MultiPrefixState {
    Done,
    /// Per-prefix byte-match counter; `DISQUALIFIED` for prefixes that
    /// mismatched at an earlier position.
    Running(Vec<u32>),
}

impl Automaton for MultiPrefixAutomaton {
    type State = MultiPrefixState;

    fn start(&self) -> Self::State {
        MultiPrefixState::Running(vec![0; self.prefixes.len()])
    }

    fn is_match(&self, state: &Self::State) -> bool {
        matches!(state, MultiPrefixState::Done)
    }

    fn can_match(&self, state: &Self::State) -> bool {
        match state {
            MultiPrefixState::Done => true,
            MultiPrefixState::Running(counts) => counts.iter().any(|&c| c != DISQUALIFIED),
        }
    }

    fn will_always_match(&self, state: &Self::State) -> bool {
        matches!(state, MultiPrefixState::Done)
    }

    fn accept(&self, state: &Self::State, byte: u8) -> Self::State {
        let MultiPrefixState::Running(counts) = state else {
            return MultiPrefixState::Done;
        };
        let mut next = counts.clone();
        for (i, count) in next.iter_mut().enumerate() {
            if *count == DISQUALIFIED {
                continue;
            }
            let prefix = &self.prefixes[i];
            let pos = *count as usize;
            // Invariant: a prefix that's already fully matched would have
            // collapsed the state to `Done` on the prior `accept`, so pos < prefix.len() here.
            debug_assert!(pos < prefix.len());
            if prefix[pos] == byte {
                *count += 1;
                if (*count as usize) == prefix.len() {
                    return MultiPrefixState::Done;
                }
            } else {
                *count = DISQUALIFIED;
            }
        }
        MultiPrefixState::Running(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(automaton: &MultiPrefixAutomaton, input: &[u8]) -> bool {
        let mut state = automaton.start();
        for &byte in input {
            if !automaton.can_match(&state) {
                return false;
            }
            state = automaton.accept(&state, byte);
        }
        automaton.is_match(&state)
    }

    #[test]
    fn rejects_empty_prefix_set() {
        assert!(MultiPrefixAutomaton::try_new(vec![]).is_none());
    }

    #[test]
    fn rejects_empty_prefix_member() {
        assert!(
            MultiPrefixAutomaton::try_new(vec![b"foo".to_vec(), Vec::new()]).is_none(),
            "an empty prefix forces a full-scan; the caller should detect this and skip the \
             automaton"
        );
    }

    #[test]
    fn single_prefix_matches_keys_starting_with_it() {
        let automaton = MultiPrefixAutomaton::try_new(vec![b"attributes.http.".to_vec()]).unwrap();
        assert!(run(&automaton, b"attributes.http.method\x00"));
        assert!(run(&automaton, b"attributes.http."));
        assert!(!run(&automaton, b"attributes.db.system\x00"));
        assert!(!run(&automaton, b"attribute"));
    }

    #[test]
    fn union_of_disjoint_prefixes() {
        let automaton = MultiPrefixAutomaton::try_new(vec![
            b"attributes.http.".to_vec(),
            b"resource.".to_vec(),
        ])
        .unwrap();
        assert!(run(&automaton, b"attributes.http.method\x00"));
        assert!(run(&automaton, b"resource.service.name\x00"));
        assert!(!run(&automaton, b"body\x00"));
    }

    #[test]
    fn shared_byte_prefixes() {
        // Both "foo" and "foobar" share the prefix "foo".
        let automaton =
            MultiPrefixAutomaton::try_new(vec![b"foo".to_vec(), b"foobar".to_vec()]).unwrap();
        // "foo" alone is matched by the "foo" prefix.
        assert!(run(&automaton, b"foo"));
        // "foobar" is matched by both.
        assert!(run(&automaton, b"foobar"));
        // "foobaz" is matched by "foo" (shorter prefix satisfied first).
        assert!(run(&automaton, b"foobaz"));
        // "bar" is matched by neither.
        assert!(!run(&automaton, b"bar"));
    }

    #[test]
    fn done_state_short_circuits_remaining_bytes() {
        let automaton = MultiPrefixAutomaton::try_new(vec![b"ab".to_vec()]).unwrap();
        let mut state = automaton.start();
        state = automaton.accept(&state, b'a');
        state = automaton.accept(&state, b'b');
        assert!(matches!(state, MultiPrefixState::Done));
        // Any further byte keeps us in Done.
        state = automaton.accept(&state, b'z');
        assert!(matches!(state, MultiPrefixState::Done));
        assert!(automaton.is_match(&state));
        assert!(automaton.will_always_match(&state));
    }

    #[test]
    fn disqualified_state_stays_disqualified() {
        let automaton = MultiPrefixAutomaton::try_new(vec![b"abc".to_vec()]).unwrap();
        let mut state = automaton.start();
        state = automaton.accept(&state, b'a');
        state = automaton.accept(&state, b'x'); // mismatch — prefix disqualified
        assert!(!automaton.can_match(&state));
    }

    /// End-to-end pushdown: serializes a v3 split-fields file, opens it via
    /// `SplitFieldsReader`, and verifies that filtering with a
    /// `MultiPrefixAutomaton` returns only the keys whose field name starts
    /// with one of the requested prefixes.
    #[tokio::test]
    async fn pushdown_through_split_fields_reader() {
        use std::sync::Arc;

        use quickwit_proto::search::{
            ListFieldType, ListFields, ListFieldsEntryResponse, SplitFieldsReader,
            serialize_split_fields,
        };
        use quickwit_storage::OwnedBytes;
        use tantivy::directory::FileHandle;

        fn entry(name: &str, ty: ListFieldType) -> ListFieldsEntryResponse {
            ListFieldsEntryResponse {
                field_name: name.to_string(),
                field_type: ty as i32,
                searchable: true,
                aggregatable: false,
                index_ids: Vec::new(),
                non_searchable_index_ids: Vec::new(),
                non_aggregatable_index_ids: Vec::new(),
            }
        }

        // 4 fields, only 2 share the "attributes.http." prefix.
        let original = ListFields {
            fields: vec![
                entry("attributes.db.system", ListFieldType::Str),
                entry("attributes.http.method", ListFieldType::Str),
                entry("attributes.http.status", ListFieldType::U64),
                entry("body", ListFieldType::Str),
            ],
        };
        let bytes = serialize_split_fields(original);
        let total_len = bytes.len();
        let handle: Arc<dyn FileHandle> = Arc::new(OwnedBytes::new(bytes));

        let reader = SplitFieldsReader::open(handle, total_len).await.unwrap();

        let automaton = MultiPrefixAutomaton::try_new(vec![b"attributes.http.".to_vec()]).unwrap();
        let filtered = reader.read_filtered_async(automaton, 0).await.unwrap();
        let names: Vec<_> = filtered.iter().map(|e| e.field_name.as_str()).collect();
        assert_eq!(
            names,
            vec!["attributes.http.method", "attributes.http.status"]
        );
    }
}
