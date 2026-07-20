# Deterministic hierarchical secret derivation (DHSD)

The method presented herein enables deterministic hierarchical secret
derivation: a master secret and a path deterministically generate a new secret,
giving rise to a tree structure. Compromising a secret only compromises the
respective subtree, not any other secrets.

While the use case similar to and the design is heavily inspired by
[BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), DHSD
is simpler, more general and adapted to our needs. In particular, we focus on
general secret derivation; derivation of private and public keys for specific
private/public key algorithms is out of scope. (Note that the latter can be
achieved indirectly.)

## Out of scope

(Direct) Derivation of private and public keys.

## Business impact and use cases

Deterministic hierarchical secret derivation allows an operator to scale the
infrascture and adopt new features while only maintain a _single_ secret.

## Solution

The DHSD-function `DHSD: S ⨯ P → S` maps a value of the cross product `S ⨯ P` to
`S`, where `S = {0,1}^256` is the set of all 256-bit wide bit strings and `P` is
the set of hierarchical paths. In this context, a path is a finite sequence of
elements of `S` which are called _node labels_:
`P = { [n_0, n_1, ..., n_{i-1}] | i ∈ ℕ ∧ n_i ∈ S }`.

The function definition for DHSD is inductive:

```text
DHSD(s, [n]) = HMAC-SHA256(s, n)

DHSD(s, [n_0, n_1, ... n_{i-1}]) = DHSD(DHSD(s, n_0), [n_1, ..., n_{i-1}])
```

The HMAC-SHA256 key derivation function is defined in
[rfc2104](https://datatracker.ietf.org/doc/html/rfc2104) and instantiated with
SHA256 as the hash function.

### Path coercion

`DHSD` can be applied to any tree structure where the child nodes are uniquely
named by simply applying `SHA256` to the node name to form a node label.
