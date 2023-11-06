# PyQuCryptor
PyQuCryptor is an encryption software written in Python. That is designed to be resistant to post-quantum cryptoanalysis.

TL;DR
The encryptor is suppose to be very easy to use and remain relatively secure. AES-256-CTR is the cipher used to encrypt the files. The encryption keys are encrypted with AES-256-CTR again but this time with a key derived from the user generated password. This is a project for the Congressional App Challenge, but unlike **most** people with their apps for the challenge, I actually plan to support this for as long as possible.

Encryption:
I chose CTR because I don't have to worry about padding, plus it has authentication, which makes life a bit easier. Technically CTR, GCM, CFB, CBC, and XTS are all quantum resistant to about the same degree but CTR was the easiest to implement and has generally the same security of the other modes except unlike GCM, can encrypt a way bigger file. 

Possible modes of operations/ciphers and why I didn't chose them:
  AES :
    XTS - PyCryptoDome doesn't support it
    CBC - Padding is painful
    CFB - Too lazy (Most valid reason **ever**)
    GCM - Can only encrypt about 64 GiBs worth of files (We wanted a higher limit)
    CCM - No idea how it works
    EAX - No idea how it works
    ECB - Bruh its not secure
  Other ciphers :
    CHACHA20 - AES is faster with acceleration (AES-NI) plus most CPUs support them
    3DES/TDES - This is barely secure for today, let alone 20+ years into the future
    All public-private key systems - None of them are secure against quantum attacks
    Actual post-quantum algos - This is Python, implememnting them would be painful, plus I have zero idea how most of them even work ¯\_(ツ)_/¯

    
