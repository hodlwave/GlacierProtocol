#! /bin/sh

# Constants
PROOF_WALLET_TAG=v0.2-alpha
PYTHON_MNEMONIC_HASH=ad06157e21fc2c2145c726efbfdcf69df1350061

# Clone Proof Wallet and initalize submodule
git clone https://github.com/hodlwave/proof-wallet.git
pushd proof-wallet
git checkout $PROOF_WALLET_TAG
git submodule update --init

# Checkout specific commit hash 
pushd python-mnemonic
git checkout $PYTHON_MNEMONIC_HASH
popd

# Archive proof-wallet and echo sha256sum
popd
tar -cf proof-wallet.tar proof-wallet \
    --sort=name \
    --mtime='1970-01-01 00:00Z' \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime
zip -r proof-wallet.zip proof-wallet

TARBALL_HASH=$(sha256sum proof-wallet.tar)
ZIP_HASH=$(sha256sum proof-wallet.zip)
echo "proof-wallet.tar (sha256): $TARBALL_HASH"
echo "proof-wallet.zip (sha256): $ZIP_HASH"

