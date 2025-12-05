;; A FunaiDB for a specific message type for signer set 0.
;; The contract name indicates which -- it has the form `signers-0-{:message_id}`.

(define-read-only (funaidb-get-signer-slots)
    (contract-call? .signers funaidb-get-signer-slots-page u0))

(define-read-only (funaidb-get-config)
    (contract-call? .signers funaidb-get-config))
