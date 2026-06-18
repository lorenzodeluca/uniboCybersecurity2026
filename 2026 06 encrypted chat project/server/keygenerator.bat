REM Lorenzo De Luca - AI disclaimer: this file has been written with the help of an LLM (openai codex 5.1, date 2026/06/18)

@echo off
REM password to use both for the keystore and the private key
set PASS=VerySafePassword654321

REM keytool -genkeypair  -> generates a key pair (private/public) and a self-signed certificate
REM -alias       -> logical name used to identify the key/certificate inside the keystore
REM -keyalg      -> algorithm of the generated key (here RSA)
REM -keysize     -> RSA key size in bits (suggested >= 2048)
REM -keystore 	 -> path/name of the keystore file in which to store the material
REM -storetype   -> keystore format; PKCS#12 is the modern standard (compatible with many libraries)
REM -storepass   -> password to protect the entire keystore
REM -keypass     -> password specific to the private key (can differ from storepass)
REM -dname 	 -> Distinguished Name inserted into the certificate

keytool -genkeypair -alias server -keyalg RSA -keysize 4096  -keystore keystore.p12 -storetype PKCS12 -storepass %PASS% -keypass %PASS% -dname "CN=Server, OU=Lab, O=Uni, L=Bologna, ST=BO, C=IT"