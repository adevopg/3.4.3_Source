Prototype chat bridge

1) Install dependencies:
   cd tools/chat_bridge
   npm install

2) Run Redis locally

3) Start bridge:
   node index.js

4) Use REST /login and /chars, and connect with socket.io client passing JWT in handshake auth { token }.

Note: This is a prototype. For production use SRP6 login, secure passwords, HTTPS/WSS, JWT secret management, and validation.

SRP prototype
---------------
This prototype exposes minimal SRP endpoints:
 - POST /srp/start { username } -> returns salt (if account exists)
 - POST /srp/finish { username, clientProof } -> returns JWT (prototype simplified)

Client example
--------------
Open tools/chat_bridge/client_example.html (served by your static file host) to see a minimal WebSocket client demo that logs in using /login and connects via socket.io.

Node.js SRP client
------------------
You can use the provided script tools/chat_bridge/srp_client.js to register and authenticate a user (prototype). Example:

  node srp_client.js user pass

The bridge stores salt and verifier in a table srp_accounts; fields are encoded as hex in this prototype.

Security & notes
----------------
- Messages are escaped and limited in size (1024 bytes) before publishing.
- The C++ ChatBridge supports optional hiredis async publisher (define USE_HIREDIS) which runs a worker thread with reconnection attempts.
- For production: use HTTPS/WSS, secure JWT secret storage, validate message origin, and add rate-limiting.

Legacy login fallback
---------------------
If your auth DB no longer has sha_pass_hash (SRP6 or external auth), the /login endpoint will attempt a safe fallback lookup by username or email and issue a JWT without password verification (development convenience). To require password checks in fallback mode set environment variable DEV_REQUIRE_PASSWORD_CHECK=true and implement a suitable password check.
