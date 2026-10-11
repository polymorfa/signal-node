# signal-node

Self-hosted Signal service for Polymorfa zero-knowledge sessions. It holds a
linked WhatsApp device's Signal keys, sessions and message plaintext, and
delivers messages to your application. Polymorfa keeps the WhatsApp
connection and never sees message content.

The runner contract is `proto/polymorfa/signal/v1/signal_service.proto`.
