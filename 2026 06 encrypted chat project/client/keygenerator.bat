@echo off
REM password to use both for the keystore and the private key
set PASS=VerySafePassword123456

REM keytool -genkeypair  -> generates a key pair (private/public) and a self-signed certificate
REM -alias       -> logical name used to identify the key/certificate inside the keystore
REM -keyalg      -> algorithm of the generated key (here RSA)
REM -keysize     -> RSA key size in bits (suggested >= 2048)
REM -keystore 	 -> path/name of the keystore file in which to store the material
REM -storetype   -> keystore format; PKCS#12 is the modern standard (compatible with many libraries)
REM -storepass   -> password to protect the entire keystore
REM -keypass     -> password specific to the private key (can differ from storepass)
REM -dname 	 -> Distinguished Name inserted into the certificate

keytool -genkeypair -alias client -keyalg RSA -keysize 4096  -keystore keystore.p12 -storetype PKCS12 -storepass %PASS% -keypass %PASS% -dname "CN=Client, OU=Lab, O=Uni, L=Bologna, ST=BO, C=IT"