# PyQuCryptor
PyQuCryptor is an encryption software written in Python that is designed to be resistant to post-quantum cryptoanalysis.

# TL;DR
PyQuCryptor is supposed to be very easy to use and remain relatively secure. AES-256-CTR is the cipher used to encrypt the files. The encryption keys are encrypted with AES-256-CTR again but this time with a key derived from the user generated password. This is a project for the Congressional App Challenge, but unlike **most** people with their apps for the challenge, I actually plan to support this for as long as possible. (This is obviously for my colledge resume.)

# Encryption:
I chose CTR because I don't have to worry about padding, plus it has authentication, which makes life a bit easier. Technically CTR, GCM, CFB, CBC, and XTS are all quantum resistant to about the same degree but CTR was the easiest to implement and has generally the same security of the other modes except unlike GCM, can encrypt a way bigger file. 

# Possible modes of operations/ciphers and why I didn't chose them:

  AES :
  
  - XTS - PyCryptoDome doesn't support it
  - CBC - Padding is painful
  - CFB - Too lazy (Most valid reason **ever**)
  - GCM - Can only encrypt about 64 GiBs worth of files (We wanted a higher limit)
  - CCM - No idea how it works, it's seucre
  - EAX - No idea how it works, it's secure
  - ECB - Bruh its not secure
    
  Other ciphers :
  
  - CHACHA20 - AES is faster with acceleration (AES-NI) plus most CPUs support them
  - 3DES/TDES - This is barely secure for today, let alone 20+ years into the future
  - All public-private key systems - None of them are secure against quantum attacks
  - Actual post-quantum algos - This is Python, implememnting them would be painful, plus I have zero idea how most of them even work ¯\\_(ツ)_/¯
    
# Plausible deniability
The data inside of the encrypted file is indistinguishable from random, thus providing plausible deniability that the data is infact just random noise. However there are a few caveats to be aware of; 

  - The size of the original file should not be known by the advisory.
  - The file name should be scrambled with the randomize filename option.
  - The password of the file should not be known by the advisory (Obviously).

PyQuCryptor provides plausible deniability by having "random" data in the entirety of the file. The first 12 bytes is a random salt for the password. Then a 64-byte SHA3-512 hash is encoded in bytes, which makes it also random, and then everything else in the file has been encrypted using AES-256-CTR, which as of currently, cannot be distinguished from randomness. And thus the user can claim that the file is a collection of random bytes, with no actual data inside of it. 

## Virus flags
Since the bootloader that ships default with PyInstaller absolutely sucks at not being flagged by every AV in existence, I have compiled my own (OMG, I can blame the compiler now!!! Next time I will blame the Kernel). This helps in reducing the total amount of flags that gets generated from a script kiddy trying to test out their cool idea. But still, Microsoft Defender and some other AI-based AVs detect my app as malicious, its best to just ignore the positives (Just my app, please listen to other warnings/positives) or to submit them for reanalysis to an actual human. I will upload PyQuCryptor to get analysised by MS with every release, so the majority of the time, PyQuCryptor won't be flagged. 
