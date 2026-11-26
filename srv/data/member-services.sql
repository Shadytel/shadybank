-- Apply once to an existing database before enabling the member API.
-- Execute with autocommit (do not wrap the enum addition and subsequent use in a single transaction).
ALTER TYPE trans_type ADD VALUE IF NOT EXISTS 'member_transfer';

CREATE TABLE IF NOT EXISTS member_transfers (
    sender_account integer NOT NULL REFERENCES accounts(id),
    request_id uuid NOT NULL,
    recipient_account integer NOT NULL REFERENCES accounts(id),
    amount numeric(8,2) NOT NULL CHECK (amount > 0),
    transaction_id integer NOT NULL UNIQUE REFERENCES transactions(id),
    created_at timestamp NOT NULL DEFAULT NOW(),
    PRIMARY KEY(sender_account, request_id),
    CHECK (sender_account <> recipient_account)
);
