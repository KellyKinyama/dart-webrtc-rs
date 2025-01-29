A sample command-line application with an entrypoint in `bin/`, library code
in `lib/`, and example unit test in `test/`.

openssl ecparam -genkey -name prime256v1 -out key.pem

openssl ecparam -genkey -name secp256k1 -out key.pem

openssl req -new -x509 -key key.pem -out server.pem -days 365


openssl ecparam -in key.pem -text -noout
openssl x509 -in server.pem -text -noout