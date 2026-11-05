# key-policy module

Builds the common part of a KMS key policy for a key that a stack's deploy role creates
([encryption](../../../docs/security/encryption-and-keys.md) 4.4): the deploy role administers it, the plan role
reads it, the key-admin role may only read and put the policy, BreakGlass recovers, and AWS Config reads its state.
No `kms:*` for the account root. The caller adds the statements for the services and roles that use the key. Creates
nothing. Written by [#105](https://github.com/codewithmuh/secure-file-transfer/issues/105) for the registry, DNSSEC
and logs keys of the shared stack.
