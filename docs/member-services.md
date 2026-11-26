# Member services API

The member interface supports a telephone client or other trusted service without conferring merchant, partner or administrative capabilities. It is distinct from the existing merchant endpoints, and disabled unless `SHADYBANK_MEMBER_SERVICE_KEY` contains an operator-supplied service credential of at least 32 characters. Deploy behind an authenticated, TLS-protected service connection; never expose the service credential to a caller. Ordinary members authenticate using their own activated, unexpired numeric ShadyBucks card and assigned member PIN, not a payment-network card or PIN.

## Provisioning

For a fresh database, the existing initialization SQL includes the member transfer ledger. For an already initialized database, apply `srv/data/member-services.sql` with an operator-authorized PostgreSQL connection before enabling the member service. The migration is additive and does not alter merchant records. Set `SHADYBANK_MEMBER_SERVICE_KEY` in the API container environment. Do not commit the value.

The database operator runs `python src/provision_member_pin.py` in the API container with its authorized database connection and a terminal capable of hidden input. Assign the member's 4 to 8 digit numeric PIN; it is stored as an Argon2 hash in the existing `pin` secret type, separately from web passwords and OTP secrets. Existing member PINs must be provisioned or rotated into this hashed format, not copied as plaintext. Rotating the PIN deauthorizes old member sessions.

## HTTP contract

All routes require `X-Shadybank-Member-Key`. After login they additionally require `Authorization: Bearer <member token>`. POST payloads are URL-encoded forms. Responses are JSON except the empty logout response. Member tokens expire after five minutes and only authorize the member API, not existing merchant or administrative routes. No card number, PIN or full recipient identifier is returned in JSON.

| Method and path | Inputs | Response |
| --- | --- | --- |
| POST `/api/member/login` | `pan`, `pin` | 201 `token`, `expires_in` |
| POST `/api/member/logout` | Member token | 204 |
| GET `/api/member/balance` | Member token | `balance`, `available` as decimal strings |
| GET `/api/member/transactions` | Member token | Up to 10 posted transactions with `timestamp`, `amount`, `direction`, `type`, `counterparty`, `description` |
| GET `/api/member/authorizations` | Member token | Up to 10 pending, unexpired holds with `timestamp`, `expires`, `amount`, `direction`, `counterparty` |
| POST `/api/member/transfer` | `recipient_pan`, `amount` (positive fixed two decimals), `request_id` (UUID) | 201 `status: posted`, `transaction_id`, `amount`; exact repeat returns 200 with the same receipt |

Authentication failure responses are generic and account/card attempts have a bounded fixed-window rate limit, in addition to a service-wide limit. Transfers only debit the authenticated ordinary member, require both eligible cards and sufficient posted and available balances, reject self-transfer and privileged accounts, and lock both accounts in deterministic order. Debit, credit, journal entry and idempotency receipt commit in one database transaction. Reusing a request ID with different transfer details is rejected. If an HTTP mutation response is lost, a client must not invent a success or automatically generate a new request; it may inspect activity or retry the identical request identifier where appropriate.

## Testing

`python -m unittest discover -s tests -v` exercises the member API using synthetic data. Set `SHADYBANK_TEST_DSN` to a dedicated disposable PostgreSQL test database to run the optional real-database concurrency tests. They create and remove a uniquely named test schema, verify identical concurrent requests post once and verify separate concurrent requests cannot overspend. No actual member or production balance is required for these tests.
