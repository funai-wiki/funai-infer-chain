use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use crate::net::api::getinferresult;
use crate::net::api::tests::{test_rpc, TestRPC};
use crate::net::connection::ConnectionOptions;
use crate::net::httpcore::{RPCRequestHandler, FunaiHttp, FunaiHttpRequest};
use crate::net::ProtocolFamily;

#[test]
fn test_try_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let mut http = FunaiHttp::new(addr.clone(), &ConnectionOptions::default());

    let request = FunaiHttpRequest::new_getinferresult(
        addr.into(),
        "123456".to_string(),
    );
    let bytes = request.try_serialize().unwrap();

    debug!("Request:\n{}\n", std::str::from_utf8(&bytes).unwrap());

    let (parsed_preamble, offset) = http.read_preamble(&bytes).unwrap();
    let mut handler = getinferresult::RPCInferResultRequestHandler::new();
    let mut parsed_request = http
        .handle_try_parse_request(
            &mut handler,
            &parsed_preamble.expect_request(),
            &bytes[offset..],
        )
        .unwrap();

    // parsed request consumes headers that would not be in a constructed request
    parsed_request.clear_headers();
    let (preamble, contents) = parsed_request.destruct();

    // consumed path args
    assert_eq!(handler.tx_id, Some("123456".to_string()));

    assert_eq!(&preamble, request.preamble());

    handler.restart();
    assert!(handler.tx_id.is_none());
}

#[test]
fn test_try_make_response() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);

    let rpc_test = TestRPC::setup(function_name!());
    let mut requests = vec![];

    // query existing infer result
    let request = FunaiHttpRequest::new_getinferresult(addr.into(), "123456".to_string());
    requests.push(request);

    // query non-exist infer result
    let request = FunaiHttpRequest::new_getinferresult(addr.into(), "654321".to_string());
    requests.push(request);

    let mut responses = rpc_test.run(requests);

    // got the infer result
    let response = responses.remove(0);
    let resp = response.decode_rpc_get_infer_result().unwrap();

    assert_eq!(resp.txid, "123456".to_string());

    assert_eq!(resp.status, libllm::InferStatus::NotFound);
}