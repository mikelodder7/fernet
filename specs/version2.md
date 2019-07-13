# Fernet Spec

This document describes version 0x40.

Conceptually, fernet takes a user-provided *message* (an arbitrary
sequence of bytes), a *key* (128 bits), and the current
time, and produces a *token*, which contains the message in a form
that can't be read or altered without the key.

To facilitate convenient interoperability, this spec defines the
external format of both tokens and keys.

All encryption in this version is done with AES 128 in GCM mode.

However, unlike version 0x80, this version does not mandate
an encoding and leaves this up implementors and how they prefer to use it

## Notation
|| denotes a byte concatenation e.g. 0100, b = 1001, a || b = 01001001 

## Key Format

A fernet *key* is 16 bytes/128 bits big-endian format.

## Token Format

A fernet *token* is the byte sequence
concatenation of the following fields:

    Version ‖ Timestamp ‖ Nonce ‖ Ciphertext ‖ Tag

- *Version*, 8 bits
- *Timestamp*, 64 bits
- *Nonce*, 96 bits
- *Ciphertext*, variable length, multiple of 128 bits
- *Tag*, 128 bits

Fernet tokens are not self-delimiting. It is assumed that the
transport will provide a means of finding the length of each
complete fernet token.

## Token Fields

### Version

This field denotes which version of the format is being used by
the token. Currently there is only one version defined, with the
value 64 (0x40).

### Timestamp

This field is a 64-bit unsigned big-endian integer. It records the
number of seconds elapsed between January 1, 1970 UTC and the time
the token was created.

### Nonce

The 96-bit Nonce used in AES encryption and
decryption of the Ciphertext.

When generating new fernet tokens, the nonce must be chosen uniquely
for every token and nonce's must not be reused. With a high-quality source of entropy, random
selection will do this with high probability. 
Accidentally reusing a nonce leaks both the authentication key and the XOR of both plaintexts, both of which can potentially be leveraged for full plaintext recovery attacks.

### Ciphertext

This field has variable size, but is always a multiple of 128
bits, the AES block size. It contains the original input message,
padded and encrypted.

### TAG

This field is the 128-bit tag output of the ciphertext and the additional authentication data (AAD).
The additional authentication data is

    Version ‖ Timestamp ‖ Nonce

Note that the AAD input is the entire rest of the token not included in the ciphertext.

## Generating

Given a key and message, generate a fernet token with the
following steps, in order:

1. Record the current time for the timestamp field.
2. Choose a unique Nonce.
3. Construct the ciphertext:
   1. Set the AAD header = Version || Timestamp || Nonce 
   2. Encrypt the message using AES 128 in GCM mode with
   the chosen Nonce, user-supplied encryption-key, and AAD header.
user-supplied signing-key.
4. Concatenate all fields together in the format above.

    Version || Timestamp || Nonce || Ciphertext || Tag
    
5. Encode and store the token according to your application's needs. base64url, base58, or hex are commonly practiced.

## Verifying

Given a key and token, to verify that the token is valid and
recover the original message, perform the following steps, in
order:

1. Decode the token.
2. Ensure the first byte of the token is 0x40.
3. If the user has specified a maximum age (or "time-to-live") for
the token, ensure the recorded timestamp is not too far in the
past..
4. Decrypt the ciphertext field using AES 128 in GCM mode with the
recorded nonce, user-supplied encryption-key, and AAD header.
