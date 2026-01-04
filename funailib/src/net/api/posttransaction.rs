// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Funai Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::io::{Read, Write};

use clarity::vm::costs::ExecutionCost;
use regex::{Captures, Regex};
use funai_common::codec::{Error as CodecError, FunaiMessageCodec, MAX_PAYLOAD_LEN};
use funai_common::types::chainstate::{
    BlockHeaderHash, ConsensusHash, FunaiBlockId, FunaiPublicKey,
};
use funai_common::types::net::PeerHost;
use funai_common::types::FunaiPublicKeyBuffer;
use funai_common::util::hash::{hex_bytes, to_hex, Hash160, Sha256Sum};
use funai_common::util::retry::BoundReader;

use crate::burnchains::affirmation::AffirmationMap;
use crate::burnchains::Txid;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::funai::db::blocks::MINIMUM_TX_FEE_RATE_PER_BYTE;
use crate::chainstate::funai::db::FunaiChainState;
use crate::chainstate::funai::{FunaiTransaction, TransactionPayload};
use crate::core::mempool::MemPoolDB;
use crate::cost_estimates::FeeRateEstimate;
use crate::net::http::{
    parse_json, Error, HttpBadRequest, HttpContentType, HttpNotFound, HttpRequest,
    HttpRequestContents, HttpRequestPreamble, HttpResponse, HttpResponseContents,
    HttpResponsePayload, HttpResponsePreamble, HttpServerError, HttpVersion,
};
use crate::net::httpcore::{
    HttpPreambleExtensions, RPCRequestHandler, FunaiHttpRequest, FunaiHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::relay::Relayer;
use crate::net::{Attachment, Error as NetError, FunaiMessageType, FunaiNodeState};

#[derive(Serialize, Deserialize)]
pub struct PostTransactionRequestBody {
    pub tx: String,
    pub attachment: Option<String>,
}

#[derive(Clone)]
pub struct RPCPostTransactionRequestHandler {
    pub tx: Option<FunaiTransaction>,
    pub attachment: Option<Attachment>,
}
impl RPCPostTransactionRequestHandler {
    pub fn new() -> Self {
        Self {
            tx: None,
            attachment: None,
        }
    }

    /// Decode a bare transaction from the body
    fn parse_posttransaction_octets(mut body: &[u8]) -> Result<FunaiTransaction, Error> {
        let tx = FunaiTransaction::consensus_deserialize(&mut body).map_err(|e| {
            if let CodecError::DeserializeError(msg) = e {
                Error::DecodeError(format!("Failed to deserialize posted transaction: {}", msg))
            } else {
                e.into()
            }
        })?;
        Ok(tx)
    }

    /// Decode a JSON-encoded transaction and Atlas attachment pair
    fn parse_posttransaction_json(
        body: &[u8],
    ) -> Result<(FunaiTransaction, Option<Attachment>), Error> {
        let body: PostTransactionRequestBody = serde_json::from_slice(body)
            .map_err(|_e| Error::DecodeError("Failed to parse body".into()))?;

        let tx = {
            let tx_bytes = hex_bytes(&body.tx)
                .map_err(|_e| Error::DecodeError("Failed to parse tx".into()))?;
            FunaiTransaction::consensus_deserialize(&mut &tx_bytes[..]).map_err(|e| {
                if let CodecError::DeserializeError(msg) = e {
                    Error::DecodeError(format!("Failed to deserialize posted transaction: {}", msg))
                } else {
                    e.into()
                }
            })
        }?;

        let attachment = match body.attachment {
            None => None,
            Some(ref attachment_content) => {
                let content = hex_bytes(attachment_content)
                    .map_err(|_e| Error::DecodeError("Failed to parse attachment".into()))?;
                Some(Attachment::new(content))
            }
        };

        Ok((tx, attachment))
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCPostTransactionRequestHandler {
    fn verb(&self) -> &'static str {
        "POST"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v2/transactions$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/transactions"
    }

    /// Try to decode this request.
    /// There's nothing to load here, so just make sure the request is well-formed.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        _captures: &Captures,
        query: Option<&str>,
        body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        if preamble.get_content_length() == 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected non-zero-length body for PostTransaction"
                    .to_string(),
            ));
        }

        if preamble.get_content_length() > MAX_PAYLOAD_LEN {
            return Err(Error::DecodeError(
                "Invalid Http request: PostTransaction body is too big".to_string(),
            ));
        }

        match preamble.content_type {
            None => {
                return Err(Error::DecodeError(
                    "Missing Content-Type for transaction".to_string(),
                ));
            }
            Some(HttpContentType::Bytes) => {
                // expect a bare transaction
                let tx = Self::parse_posttransaction_octets(body)?;
                self.tx = Some(tx);
                self.attachment = None;
            }
            Some(HttpContentType::JSON) => {
                // expect a transaction and an attachment
                let (tx, attachment_opt) = Self::parse_posttransaction_json(body)?;
                self.tx = Some(tx);
                self.attachment = attachment_opt;
            }
            _ => {
                return Err(Error::DecodeError(
                    "Wrong Content-Type for transaction; expected application/json or application/octet-stream".to_string(),
                ));
            }
        }

        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCPostTransactionRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.tx = None;
        self.attachment = None;
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut FunaiNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let tx = self
            .tx
            .take()
            .ok_or(NetError::SendError("`tx` not set".into()))?;
        let attachment_opt = self.attachment.take();

        let txid = tx.txid();

        let data_resp = node.with_node_state(|network, sortdb, chainstate, mempool, rpc_args| {
            if mempool.has_tx(&txid) {
                // will not accept
                debug!("Mempool already has POSTed transaction {}", &txid);
                return Ok(false);
            }

            let event_observer = rpc_args.event_observer.as_deref();
            let burn_tip = self.get_canonical_burn_chain_tip(&preamble, sortdb)?;
            let funai_epoch = self.get_funai_epoch(&preamble, sortdb, burn_tip.block_height)?;

            // check for defects which can be determined statically
            if Relayer::do_static_problematic_checks()
                && !Relayer::static_check_problematic_relayed_tx(
                    chainstate.mainnet,
                    funai_epoch.epoch_id,
                    &tx,
                    network.ast_rules,
                )
                .is_ok()
            {
                // we statically check the tx for known problems, and it had some.  Reject.
                debug!(
                    "Transaction {} is problematic in rules {:?}; will not store or relay",
                    &tx.txid(),
                    network.ast_rules
                );
                return Ok(false);
            }

            let funai_tip = self.get_funai_chain_tip(&preamble, sortdb, chainstate)?;

            // accept to mempool
            if let Err(e) = mempool.submit(
                chainstate,
                sortdb,
                &funai_tip.consensus_hash,
                &funai_tip.anchored_header.block_hash(),
                &tx,
                event_observer,
                &funai_epoch.block_limit,
                &funai_epoch.epoch_id,
            ) {
                return Err(FunaiHttpResponse::new_error(
                    &preamble,
                    &HttpBadRequest::new_json(e.into_json(&txid)),
                ));
            };

            match tx.payload {
                TransactionPayload::Infer(_, _, ref userInput, ref context, ref nodePrincipal, _) => {
                    let txid_str = txid.to_hex();
                    let user_input = userInput.to_string();

                    // Check if an attachment (inference result) was provided
                    let result_saved = if let Some(ref attachment) = attachment_opt {
                        if let Ok(output) = String::from_utf8(attachment.content.clone()) {
                            let node_id = nodePrincipal.to_string();
                            match libllm::save_infer_result(txid_str.clone(), &user_input, &output, &node_id) {
                                Ok(_) => {
                                    info!("Saved inference result from attachment for tx: {}", txid_str);
                                    true
                                }
                                Err(e) => {
                                    warn!("Failed to save inference result from attachment: {}", e);
                                    false
                                }
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    // If no result was saved from attachment, fallback to creating a pending task
                    if !result_saved {
                        let context_str = context.to_string();
                        let chat_completion_message = serde_json::from_str(context_str.as_str()).unwrap_or(vec![]);
                        let context_messages = if chat_completion_message.is_empty() {
                            None
                        } else {
                            Some(chat_completion_message)
                        };
                        let submit_infer_res = libllm::infer_chain(txid_str.clone(), user_input.as_str(), context_messages);
                        match submit_infer_res {
                            Ok(infer_res) => {
                                debug!("Submitted pending infer task: {:?}", infer_res);
                            }
                            Err(e) => {
                                let err_msg = format!("tx:{:?} infer task submission failed: {:?}", txid_str, e.to_string());
                                error!("{}", err_msg);
                                return Err(FunaiHttpResponse::new_error(
                                    &preamble,
                                    &HttpBadRequest::new(err_msg),
                                ));
                            }
                        }
                    }
                }
                TransactionPayload::RegisterModel(ref model_name, ref model_params) => {
                    // Persist model definition if not exists; otherwise reject
                    let name = model_name.to_string();
                    let params = model_params.to_string();
                    match libllm::register_model_if_absent(name.as_str(), params.as_str()) {
                        Ok(true) => {}, // stored
                        Ok(false) => {
                            let err_msg = format!("model already exists: {}", name);
                            return Err(FunaiHttpResponse::new_error(
                                &preamble,
                                &HttpBadRequest::new(err_msg),
                            ));
                        }
                        Err(e) => {
                            let err_msg = format!("failed to register model: {}", e);
                            return Err(FunaiHttpResponse::new_error(
                                &preamble,
                                &HttpServerError::new(err_msg),
                            ));
                        }
                    }
                }
                _ => {} // otherwise ignore
            }

            // store attachment as well, if it's part of a contract-call
            if let Some(ref attachment) = attachment_opt {
                if let TransactionPayload::ContractCall(ref contract_call) = tx.payload {
                    if network
                        .get_atlasdb()
                        .should_keep_attachment(&contract_call.to_clarity_contract_id(), attachment)
                    {
                        network
                            .get_atlasdb_mut()
                            .insert_uninstantiated_attachment(attachment)
                            .map_err(|e| {
                                FunaiHttpResponse::new_error(
                                    &preamble,
                                    &HttpServerError::new(format!(
                                        "Failed to store contract-call attachment: {:?}",
                                        &e
                                    )),
                                )
                            })?;
                    }
                }
            }

            Ok(true)
        });

        let (accepted, txid) = match data_resp {
            Ok(accepted) => (accepted, txid),
            Err(response) => {
                return response.try_into_contents().map_err(NetError::from);
            }
        };

        // don't forget to forward this to the p2p network!
        if accepted {
            node.set_relay_message(FunaiMessageType::Transaction(tx));
        }

        let mut preamble = HttpResponsePreamble::ok_json(&preamble);
        preamble.set_canonical_funai_tip_height(Some(node.canonical_funai_tip_height()));
        let body = HttpResponseContents::try_from_json(&txid)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCPostTransactionRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let txid: Txid = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(txid)?)
    }
}

impl FunaiHttpRequest {
    /// Make a new post-transaction request
    pub fn new_post_transaction(host: PeerHost, tx: FunaiTransaction) -> FunaiHttpRequest {
        FunaiHttpRequest::new_for_peer(
            host,
            "POST".into(),
            "/v2/transactions".to_string(),
            HttpRequestContents::new().payload_funai(&tx),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }

    /// Make a new post-transaction request with an attachment
    pub fn new_post_transaction_with_attachment(
        host: PeerHost,
        tx: FunaiTransaction,
        attachment: Option<Vec<u8>>,
    ) -> FunaiHttpRequest {
        FunaiHttpRequest::new_for_peer(
            host,
            "POST".into(),
            "/v2/transactions".to_string(),
            HttpRequestContents::new().payload_json(
                serde_json::to_value(PostTransactionRequestBody {
                    tx: to_hex(&tx.serialize_to_vec()),
                    attachment: attachment.map(|bytes| to_hex(&bytes)),
                })
                .expect("FATAL: failed to construct request from infallible data"),
            ),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl FunaiHttpResponse {
    #[cfg(test)]
    pub fn new_posttransaction(txid: Txid, with_content_length: bool) -> FunaiHttpResponse {
        let value = serde_json::to_value(txid).expect("FATAL: failed to serialize infallible data");
        let length = serde_json::to_string(&value)
            .expect("FATAL: failed to serialize infallible data")
            .len();
        let preamble = HttpResponsePreamble::new(
            HttpVersion::Http11,
            200,
            "OK".to_string(),
            if with_content_length {
                Some(length as u32)
            } else {
                None
            },
            HttpContentType::JSON,
            true,
        );
        let body = HttpResponsePayload::JSON(value);
        FunaiHttpResponse::new(preamble, body)
    }

    pub fn decode_txid(self) -> Result<Txid, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let txid: Txid = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(txid)
    }
}
