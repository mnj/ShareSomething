`oidc_test_key.pem` is a throwaway RSA key generated for this repository's tests. The in-process
mock OpenID provider in `src/tests.rs` signs ID tokens with it. It protects nothing and isn't a
secret.
