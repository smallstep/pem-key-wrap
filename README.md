# 🔐 pem-key-wrap

Wrap keys from a PEM file using RSAES-OAEP with SHA-256 + AES-KWP, the same as
the PKCS #11 key wrapping algorithm CKM_RSA_AES_KEY_WRAP.

This tool can be used for example for importing to Google's KMS or Microsoft
Azure's Key Vault.

## Install

```console
go install github.com/smallstep/pem-key-wrap@latest
```

## Usage

```console
pem-key-wrap --out wrapped.key priv.pem wrapping.pub
```
