
# Signing Transaction Inputs

You need to modify the transaction before actually signing it. That is, you have to compute the `z` in a very particular way. The procedure is as follows.

#### Step 1: Empty all the scriptSigs

The first step is to empty all the scriptSigs when checking the signature. The same procedure is used for creating the signature, except the scriptSig is usually already empty.

#### Step 2: Replace the scriptSig of the input being signed with the previous scriptPubKey

Each input points to a previous transaction output, which itself has a scriptPubKey. We take this scriptPubKey and put that in place of the empty scriptSig. You would think that this would require a lookup on the blockchain, and this may be the case. In practice, you already know the scriptPubKey as the input was chosen as one where you have the private key to unlock it. Therefore, you know the address it was sent to and thus, the scriptPubKey.

#### Step 3: Append the hash type

Lastly, we add a 4-byte hash type to the end. This is to specify what the signature is authorizing. The signature can authorize that this input has to go with all the other inputs and outputs (SIGHASH_ALL), go with a specific output (SIGHASH_SINGLE) or go with none of the outputs (SIGHASH_NONE). The latter two have some theoretical use cases, but in practice, almost every transaction is signed with SIGHASH_ALL. That is, the entire transaction has to go through, or the input signature is invalid.


```python
# Transaction Construction Example

from ecc import PrivateKey
from helper import decode_base58, p2pkh_script, SIGHASH_ALL
from script import Script
from tx import TxIn, TxOut, Tx

# Step 1
tx_ins = []
prev_tx = bytes.fromhex('0025bc3c0fa8b7eb55b9437fdbd016870d18e0df0ace7bc9864efc38414147c8')
tx_ins.append(TxIn(
            prev_tx=prev_tx,
            prev_index=0,
            script_sig=b'',
            sequence=0xffffffff,
        ))

# Step 2
tx_outs = []
h160 = decode_base58('mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2')
tx_outs.append(TxOut(
    amount=int(0.99*100000000),
    script_pubkey=p2pkh_script(h160),
))
h160 = decode_base58('mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf')
tx_outs.append(TxOut(
    amount=int(0.1*100000000),
    script_pubkey=p2pkh_script(h160),
))
tx_obj = Tx(version=1, tx_ins=tx_ins, tx_outs=tx_outs, locktime=0, testnet=True)

# Step 3
hash_type = SIGHASH_ALL
z = tx_obj.sig_hash(0, hash_type)
pk = PrivateKey(secret=8675309)
der = pk.sign(z).der()
sig = der + bytes([hash_type])
sec = pk.point.sec()
script_sig = bytes([len(sig)]) + sig + bytes([len(sec)]) + sec
script_sig = bytes([len(script_sig)]) + script_sig
tx_obj.tx_ins[0].script_sig = Script.parse(script_sig)
print(tx_obj.serialize().hex())
```
