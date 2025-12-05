;; The .infer-stake contract – lightweight staking for inference nodes

;; --------------------------------------------------------------------
;;  This contract allows an "inference node" (a Funai principal that
;;  performs off-chain ML inference in the Funai signer service) to
;;  lock STX for a fixed number of burn-chain blocks as collateral.
;;  The design purposefully mirrors the developer-experience of PoX-4
;;  (stack/extend/increase/unlock) but is *completely independent* of
;;  the existing PoX contracts so that no existing behavior is changed.
;; --------------------------------------------------------------------

;; ------------------------------
;; Constants & error codes
;; ------------------------------
(define-constant ERR_ALREADY_STAKED 100)
(define-constant ERR_NOT_STAKED 101)
(define-constant ERR_LOCK_NOT_EXPIRED 102)
(define-constant ERR_INVALID_LOCK_PERIOD 103)
(define-constant ERR_INSUFFICIENT_STAKE 104)
(define-constant ERR_STX_TRANSFER_FAILED 105)

;; Minimum amount (in uSTX) required to participate – default 100 STX
(define-constant MIN_STAKE_USTX u10000000) ;; 100 * 10^6

;; Min/max lock period (in burnchain blocks).  For simplicity we
;; re-use PoX-4 defaults (2100 blocks ≈ ~2 weeks) but allow multiples.
(define-constant MIN_LOCK_PERIOD u2100)    ;; one PoX reward cycle
(define-constant MAX_LOCK_PERIOD (* u12 MIN_LOCK_PERIOD))

;; ------------------------------
;; Data-vars and maps
;; ------------------------------
;; Total amount currently locked by all inference nodes
(define-data-var total-ustx-staked uint u0)

;; Per-node staking information
(define-map node-stake
    { node: principal }
    {
        node-id: (buff 32),      ;; off-chain identifier supplied by node
        amount-ustx: uint,       ;; amount locked (micro-STX)
        lock-start: uint,        ;; burn block height when lock was made
        lock-period: uint,       ;; period (in burn blocks)
        unlock-height: uint      ;; burn block height when funds can unlock
    })

;; ------------------------------
;; Read-only helpers
;; ------------------------------
(define-read-only (get-stake-info (node principal))
    (map-get? node-stake { node: node }))

(define-read-only (get-total-staked)
    (var-get total-ustx-staked))

;; ------------------------------
;; Public functions
;; ------------------------------

;; Register & lock STX for the first time.
;;   node-id: arbitrary 32-byte identifier chosen by the node.
;;   amount-ustx: how many micro-STX to lock (≥ MIN_STAKE_USTX).
;;   lock-period: number of burn blocks to lock (MIN_LOCK_PERIOD ≤ x ≤ MAX_LOCK_PERIOD).
(define-public (stake-stx (node-id (buff 32)) (amount-ustx uint) (lock-period uint))
    (let (
        (current-height burn-block-height)
        (already-staked? (is-some (map-get? node-stake { node: tx-sender })))
    )
        (asserts! (not already-staked?) (err ERR_ALREADY_STAKED))
        (asserts! (>= amount-ustx MIN_STAKE_USTX) (err ERR_INSUFFICIENT_STAKE))
        (asserts! (>= lock-period MIN_LOCK_PERIOD) (err ERR_INVALID_LOCK_PERIOD))
        (asserts! (<= lock-period MAX_LOCK_PERIOD) (err ERR_INVALID_LOCK_PERIOD))
        (let ((unlock-height (+ current-height lock-period)))
            (match (stx-transfer? amount-ustx tx-sender contract-principal)
                transfer-result
                    (ok ())
                _ (err ERR_STX_TRANSFER_FAILED))
            ;; persist
            (map-set node-stake
                { node: tx-sender }
                {
                    node-id: node-id,
                    amount-ustx: amount-ustx,
                    lock-start: current-height,
                    lock-period: lock-period,
                    unlock-height: unlock-height
                })
            (var-set total-ustx-staked (+ (var-get total-ustx-staked) amount-ustx))
            (ok true)))
)

;; Increase stake amount without changing unlock height.
(define-public (increase-stake (additional-ustx uint))
    (let ((info (unwrap! (map-get? node-stake { node: tx-sender }) (err ERR_NOT_STAKED))))
        (asserts! (> additional-ustx u0) (err ERR_INSUFFICIENT_STAKE))
        (match (stx-transfer? additional-ustx tx-sender contract-principal)
            transfer-result (ok ())
            _ (err ERR_STX_TRANSFER_FAILED))
        (let ((new-amount (+ (get amount-ustx info) additional-ustx)))
            (map-set node-stake { node: tx-sender }
                (merge info { amount-ustx: new-amount }))
            (var-set total-ustx-staked (+ (var-get total-ustx-staked) additional-ustx))
            (ok true)))
)

;; Extend lock period (cannot shorten).
(define-public (extend-lock (additional-lock uint))
    (let (
        (info (unwrap! (map-get? node-stake { node: tx-sender }) (err ERR_NOT_STAKED)))
        (new-period (+ (get lock-period info) additional-lock))
    )
        (asserts! (>= new-period MIN_LOCK_PERIOD) (err ERR_INVALID_LOCK_PERIOD))
        (asserts! (<= new-period MAX_LOCK_PERIOD) (err ERR_INVALID_LOCK_PERIOD))
        (let ((new-unlock (+ (get unlock-height info) additional-lock)))
            (map-set node-stake { node: tx-sender }
                (merge info {
                    lock-period: new-period,
                    unlock-height: new-unlock
                }))
            (ok true)))
)

;; Unlock and withdraw stake once lock expired.
(define-public (unlock-stx)
    (let ((info (unwrap! (map-get? node-stake { node: tx-sender }) (err ERR_NOT_STAKED))))
        (asserts! (>= burn-block-height (get unlock-height info)) (err ERR_LOCK_NOT_EXPIRED))
        (match (stx-transfer? (get amount-ustx info) contract-principal tx-sender)
            transfer-result (ok ())
            _ (err ERR_STX_TRANSFER_FAILED))
        (map-delete node-stake { node: tx-sender })
        (var-set total-ustx-staked (- (var-get total-ustx-staked) (get amount-ustx info)))
        (ok true))) 