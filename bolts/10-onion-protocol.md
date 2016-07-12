# Onion Routing Protocol for Lightning

## Overview

This document describes the construction of an onion routed packet
that is used to route a message from a _sender_ to a _recipient_, over
a number of intermediate nodes, called _hops_.

The routing schema is based on the
[Sphinx](http://www.cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf)
construction, and is extended with a per-hop payload.

Intermediate nodes forwarding the message can verify the integrity of
the packet, and can learn about which node they should forward the
packet to. They cannot learn about which other nodes, besides their
predecessor or successor, are part of this route, nor can they learn
the length of the route and their position within it. The packet is
obfuscated at each hop, so that a network level attacker cannot
associate packets belonging to the same route, i.e., packets belonging
to a route do not share any identifying information. Notice that this
does not preclude the possibility to associate packets by performing a
traffic analysis.

The route is constructed by the sender, which knows a public key of
each intermediate node. Knowing the intermediate node's public key
allows the sender to create a shared secret using ECDH for each
intermediate node, including the recipient. The shared secret is then
used to generate a _pseudo-random stream_ of bytes to obfuscate the
packet, and a number of _keys_ used to encrypt the payload and compute
HMACs ensuring integrity at each hop.

This specification describes version 0 of the packet format and
routing mechanism. Should a node receive a higher version packet that
it does not implement it MUST report a route failure to the sending
node and discard the packet.

## Conventions

There are a number of conventions we will adhere throughout the document:

 - The maximum route length is limited to 20 hops.
 - Nodes are addressed using 20 byte identifiers. These are computed
   from the node's public key, in accordance to the Bitcoin address
   creation, as `RIPEMD160(SHA256(pubkey))` where `pubkey` is the
   serialized compressed public key of the node. Refer to
   [`OP_HASH160`](https://en.bitcoin.it/wiki/Script#Crypto) for
   details.
 - HMAC: the integrity verification of the packet is based on Keyed-Hash Message Authentication Code as defined by the [FIPS 198 Standard](http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf), using `SHA256` as hashing algorithm.
   The resulting HMAC is then truncated at 20 bytes in order to reduce the overhead.
 - Elliptic Curve: for all computations involving elliptic curves, the
   Bitcoin curve, [`secp256k1`](http://www.secg.org/sec2-v2.pdf), is used.
 - Pseudo-Random Stream: [`ChaCha20`](https://tools.ietf.org/html/rfc7539) is used to generate a pseudo-random byte stream.
   For the generation we use a fixed null-nonce (`0x0000000000000000`), a key derived from a shared secret and a `0x00`-byte stream of the desired output size as message.
 - We use the terms _hop_ and _node_ interchangeably.

## Packet Structure

The packet consists of 3 parts:
 
 - The fixed size _header_ containing meta information about the
   packet and the routing information necessary to forward the
   message.
 - A fixed size _per-hop payload_ containing information for each hop
   as they forward the message.
 - A fixed size _end-to-end payload_ containing information for the
   receiving node.

The overall structure of the packet is depicted below. The network format of the packet consists of the individual parts being serialized into one continguous byte-stream and then transferred to the recipient of the packet. Due to the fixed size of the packet it does not need to be prefixed by its length when transferred over a connection.

~~~~
+--------+-----------------+--------------------+
| header | per-hop payload | end-to-end payload |
+--------+-----------------+--------------------+
~~~~

The header is a fixed 854 byte array containing the necessary information for each hop to identify the next hop, and verify the integrity of the packet.
It consists of a version byte, a 33 byte compressed `secp256k1` public key, used during the shared secret generation, a 20 byte HMAC used to verify the packet's integrity and a 800 byte routing information field.
For this specification the version byte has a constant value of `0x00`.

~~~~
+------------------+-----------------------+-----------------+------------...-----------+
| Version (1 byte) | Public Key (33 bytes) | HMAC (20 bytes) | Routing Info (800 bytes) |
+------------------+-----------------------+-----------------+------------...-----------+
~~~~

The routing info field is a structure that holds obfuscated versions of the next hop's address and the associated HMAC.
It is 800 bytes long, i.e., 20 byte MAC and 20 byte address times 20 hops, and has the following structure:

~~~~
+-------------+----------+-------------+----------+-----+--------+
| n_1 address | n_1 HMAC | n_2 address | n_2 HMAC | ... | filler |
+-------------+----------+-------------+----------+-----+--------+
~~~~

Where the `filler` consists of obfuscated deterministically generated
padding. For details about how the `filler` is generated please see
below. In addition every _(address, HMAC)_-pair is incrementally
obfuscated at each hop.

The per-hop payloads has a similar structure:

~~~~
+-------------+-------------+-------------+-----+------------+
| n_1 payload | n_2 payload | n_3 payload | ... | hop filler |
+-------------+-------------+-------------+-----+------------+
~~~~

With the `hopfiller` being constructed in the same way as the routing
info `filler` and each payload being incrementally obfuscated at each
hop.

Finally, the end-to-end payload consists of a message, padded to 1024
bytes and repeatedly encrypted at each hop using a key derived from the hop's shared secret.

## Packet Construction

The sender computes a route `{n_1, ..., n_{r-1}, n_r}`, where `n_1` is a peer of the sender and `n_r` is the recipient. The sender gathers the public keys for `n_1` to `n_r` and generates a random 32 byte `sessionkey`.

For each node the sender computes an _ephemeral public key_, a _shared secret_ and a _blinding factor_.
The blinding factor is used at each hop to blind the ephemeral public key for the next hop.
The node receiving the header will perform ECDH with the ephemeral public key and its private key to derive the same shared secret.
However, when generating the packet we do not have access to the node's private key.
Hence, we use the commutative property of multiplication and blind the node's public key with all previous blinding factors and perform ECDH using the node's blinded public key and the `sessionkey`.

The transformations at hop `k` are given by the following:

 - The shared secret `ss_k` is computed by first blinding the node's public key `nodepk_k` with all previous blinding factors `{b_1, ..., b_{k-1}}`, if any, and then executing ECDH with the blinded public key and the `sessionkey`.
 - The blinding factor is the `SHA256` hash of the concatenation between the node's public key `nodepk_k` and the hop's shared secret `ss_k`.
   Before concatenation the node's public key is serialized in the compressed format.
 - The ephemeral public key `epk_k` is computed  by blinding the previous hop's ephemeral public key `epk_{k-1}` with the previous hop's blinding factor `b_{k-1}`.

This recursive algorithm is initialized by setting the first hop's (`k=1`) ephemeral public key to the public key corresponding with the `sessionkey`, i.e., `secp256k1` is used to derive a public key for the randomly selected `sessionkey`.

The sender then iteratively computes the ephemeral public keys, shared secrets and blinding factors for nodes `{n_2, ..., n_r}`.

Once the sender has all the required information it can construct the packet.
Constructing a packet routed over `r` hops requires `r` 32 byte ephemeral public keys, `r` 32 byte shared secrets, `r` 32 byte blinding factors, `r` 20 byte per-hop payloads and a 1024 byte end-to-end payload.
The construction returns one 2258 byte packet and the first hop's address.

The packet construction is performed in reverse order of the route, i.e., the last hop's operations are applied first.

The end-to-end payload field is initialized by the actual payload, padding it with one `0x7F` byte followed by `0xFF` bytes for a total length to 1024 bytes.
The per-hop payload is initialized with 400 `0x00` bytes. 
The routing info is initialized with 800 `0x00` bytes.
The next address and the HMAC are initialized to 20 `0x00` bytes each.

Two fillers are generated with the shared secrets: a routing info filler with 40 byte hopsize and a per-hop payload filler with 20 byte hopsize.
See below for details on filler generation.

For each hop in the route in reverse order the sender applies the
following operations:

 - It generates a _rho_-key, _mu_-key, a _gamma_-key and a _pi_-key using the hop's shared secret.
 - The _pi_-key is used to encrypt the end-to-end payload field using `ChaCha20` as detailed below.
 - The routing info field is right-shifted by 40 bytes, discarding the last 40 bytes that exceed the 800 bytes.
   The address is copied into the first 20 bytes of the routing info and the HMAC is copied into
   the following 20 bytes.
   The _rho_-key is used to generate 800 bytes of pseudo random byte stream and applied with `XOR` to the routing info field.
   Should this be the last hop, i.e., the first iteration, then the tail of the routing info field is overwritten with the routing info `filler`.
 - The per-hop payload field is right-shifted by 20 bytes, and the last 20 bytes discarded, resulting in 400 bytes of per-hop payload.
   The current hop's per-hop payload is copied into the first 20 bytes.
   The _gamma_-key is used to generate 400 bytes of pseudo random byte stream which are then applied using `XOR` to the per-hop payloads field.
   Should this be the last hop then the tail of the per-hop payloads field is overwritten with the per-hop payload filler.
 - The next HMAC is computed over the concatenated routing info, per-hop payload and end-to-end payloads fields, with the _mu_-key as HMAC-key.
 - The next address is computed from the current node's public key using the Bitcoin address hash derivation.

The final value for the HMAC is the HMAC as it should be sent to the first hop.

The packet generation returns the serialized packet, consisting of the version byte, the ephemeral pubkey for the first hop, the HMAC for the first hop, the obfuscated routing info, the obfuscated per-hop payload and the encrypted end-to-end payload.

## Packet Forwarding

Upon receiving a packet a node compares the version byte of the packet with its supported versions and aborts otherwise.
This specification is limited to version `0` packets and the structure of future version may change.
The receiving node then splits the packet into its fields.

The node MUST check that the ephemeral public key is on the `secp256k1` curve.
Should this not be the case the node MUST abort processing the packet and report a route failure to the sender.

The node then computes the shared secret as described below, using the private key corresponding to its public key and the ephemeral key from the packet.
The node MUST keep a log of previously used shared secrets.
Should the shared secret already be in the log it MUST abort processing the packet and report a route failure, since this is likely a replay attack, otherwise the shared secret is added to the log.

The shared secret is used to compute a _mu_-key.  The node then computes the HMAC of the packet, starting from byte 54, which corresponds to the routing info, per-hop payloads and end-to-end
payload, using the _mu_-key.
The resulting HMAC is compared with the HMAC from the packet.
Should the computed HMAC and the HMAC from the packet differ then the node MUST abort processing and report a route failure.

At this point the node can generate a _rho_-key, a _pi_-key and a _gamma_-key.

The routing info is deobfuscated and the information about the next hop is extracted.
In order to do so the node copies the routing info field, appends 40 `0x00` bytes and generates 840 pseudo random bytes using the _rho_-key and applies it using `XOR` to the copy of the routing information.
The first 20 bytes of the resulting routing info are the address of the next hop, followed by the 20 byte HMAC.
The routing info for the outgoing packet, destined for the next hop, consists of the 800 bytes starting at byte 40.

The per-hop payload is deobfuscated in a similar way.
The node creates a copy of the per-hop payloads field and appends 20 `0x00` bytes of padding.
It generates 420 bytes of pseudo random bytes using the _gamma_-key and applies it using `XOR` to the padded copy of the per-hop payloads.
The first 20 bytes of the padded copy are the node's per-hop payload, while the remaining 400 bytes are the per-hop payload destined for the next hop.

A special HMAC value of 20 `0x00` bytes indicates that the currently processing hop is the intended recipient and that the packet should not be forwarded.
At this point the end-to-end payload is fully decrypted and the route has terminated.

Should the HMAC not indicate route termination and the next hop be a peer of the current node, then the new packet is assembled by blinding the ephemeral key with the current node's public key and shared secret, and serializing the routing info, per-hop payload and end-to-end payload fields.
The resulting packet is then forwarded to the addressed peer.

## Shared secret

The sender performs ECDH with each hop of the route in order to establish a secret.
For each message a new _sessionkey_ is generated.
The sessionkey is a 32 byte EC private key.
The shared secret creation receives a public key and a 32 byte secret as input and returns a 32 byte secret as output.

In the packet generation phase the secret is the `sessionkey` and the public key is the node's public key, blinded with all previous blinding factors.
In the pocessing phase the secret is the node's private key and the public key is the ephemeral public key from the packet, which has been incrementally blinded by the predecessors.

The public key is multiplied by the secret, using to the `secp256k1` curve.
The `X` coordinate of the multiplication result is serialized and hashed using `SHA256`.
The resulting hash is returned as the shared secret.
Notice that this is not the ECDH variant implemented in `libsecp256k1` which also includes the `Y` coordinate in the hash.

## Key Generation

A number of encryption and verification keys is derived from the shared secret:

 - _rho_: used as key when generating the pseudo random byte stream
   used to obfuscate the routing information.
 - _gamma_: used as key when generating the pseudo random byte stream used to obfuscate the per-hop payloads.
 - _mu_: used during the HMAC generation.
 - _pi_: used as key for the payload encryption/decryption.

The key generation takes a key-type (_rho_, _gamma_, _mu_ or _pi_) and a 32
byte secret as inputs and returns a 20 byte key.

Keys are generated by computing an HMAC, with `SHA256` as hashing algorithm, using the key-type, i.e., _rho_, _mu_, _pi_ or _gamma_, as HMAC-key and the 32 byte shared secret as the message.
The resulting HMAC is further truncated to 20 bytes, which results in the actual key.

Notice that the key-type does not include a C-style `0x00` termination-byte, e.g., the length of the _gamma_ key-type is 5 bytes, not 6.

## Pseudo Random Byte Stream

The pseudo random byte stream is used to obfuscate the packet at each hop of the path, so that each hop may only recover the address of the next hop as well as the HMAC for the next hop.
The pseudo random byte stream is generated by encrypting a `0x00`-byte stream of the required length with `ChaCha20`, initialized with a key derived from the shared secret and a zero-nonce (`0x00000000000000`).
The use of a fixed nonce is safe since the keys are never reused.

## Filler Generation

Upon receiving a packet each node extracts the information destined for that node from the route info and the per-hop payload.
The extraction is done by deobfuscating and left-shifting the field.
This would make the field shorter at each hop, allowing an attacker to deduce the route length.
For this reason the field is padded before forwarding.
Since the padding is part of the HMAC the sender will have to generate an identical padding in order to compute the HMACs correctly for each hop.
The filler is also used to pad the field-length in case the selected route is shorter than the maximum allowed route length.

We call the number of bytes extracted from the field _hopsize_.
In case of the route info the hopsize is 40 bytes (20 bytes address and 20 bytes HMAC), while in the case of the per-hop payload it is 20 bytes.

Before deobfuscating the field the node pads the field with hopsize `0x00` bytes, such that the total length of the field is `(20 + 1) * hopsize`.
It then generates the pseudo random byte stream of matching length and applies it with `XOR` to the field.
This deobfuscates the information destined for it, and simultaneously obfuscates the added
`0x00`-bytes at the end.

In order to compute the correct HMAC, the sender has to generate the field's state at the hop.
This also includes the incrementally obfuscated padding added by each hop.
The incrementally obfuscated padding is called the _filler_.

The following code shows how the filler is generated:

```Go
func generate_filler(key string, numHops int, hopSize int, sharedSecrets [][sharedSecretSize]byte) []byte {
	fillerSize := uint((numMaxHops + 1) * hopSize)
	filler := make([]byte, fillerSize)

	// The last hop does not obfuscate, it's not forwarding the message anymore.
	for i := 0; i < numHops-1; i++ {

		// Left-shift the field
		copy(filler[:], filler[hopSize:])

		// Zero-fill the last hop
		copy(filler[len(filler)-hopSize:], bytes.Repeat([]byte{0x00}, hopSize))

		// Generate pseudo random byte stream
		streamKey := generateKey(key, sharedSecrets[i])
		streamBytes := generateCipherStream(streamKey, fillerSize)

		// Obfuscate
		xor(filler, filler, streamBytes)
	}

	// Cut filler down to the correct length (numHops+1)*hopSize
	// bytes will be prepended by the packet generation.
	return filler[(numMaxHops-numHops+2)*hopSize:]
}
```

Notice that this implementation is for demonstration purposes only, the filler can be generated much more efficiently.
The last hop does not obfuscate the filler since it will not forward the packet and will not extract an HMAC for any followup hops.

## Payload Encryption

The end-to-end payload is decrypted incrementally at each hop using `ChaCha20` using that hop's _pi_-key and a null-nonce (`0x0000000000000000`).
This is safe since this key is only ever going to be used once.

Since the integrity of the payload is ensured by the HMAC verified at each hop we do not require any additional integrity ensuring measures, such as using `ChaCha20-Poly1305` instead of the simple `ChaCha20`.

## Blinding EC Points

In order to vary the ephemeral public key (the EC point) between hops, it is blinded at each hop. 
The inputs for the blinding process are the EC point to be blinded, the node's public key and a 32 byte shared secret, while the output is a single EC point, representing the blinded element.

Blinding is done by computing a blinding factor from the node's public key and the shared secret for that hop.
The blinding factor is the result of serializing the node's public key into its compressed format, appending the shared secret and computing the `SHA256` hash.
The blinded EC point then is the result of the scalar multiplication between the EC point and the blinding factor.
