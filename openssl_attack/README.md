
This proof-of-concept attacks a reference impementation of a program 
which uses OpenSSL to encrypt data. The `openssl/` folder contains a
recent version of OpenSSL (v1.1.1b). 

The compilation procedure involves building `libcrypto.a`. The attack
and victim both link against this library with minor modifications
as described in `src/inject_gadget.py`. The changes are as follows:
- The SMoTher gadget is injected into the victim. The attacker's
  timing sequence is injected into the same address in its binary.
  Note: injecting the SMoTher gadget in the victim binary only allows
  us to statically know its address. In a more realistic scenario, 
  the gadget would be dynamically loaded.
- The attacker binary is also modified to train the predictor.

To run this attack, you will need a setup similar to that in 
`SMoTherSpectre/poc/README.md`. Please set up the cores in the
Makefile. In addition, you will require the `pwntools` 
library (https://github.com/Gallopsled/pwntools).

The folder structure is:
- Makefile: For all binaries in this attack
- plot_secret.m: Plot the PDF for the attack time based on 
                 victim secret
- openssl: OpenSSL source code
- src/inject_gadget.py: Modify binaries to setup attacker and
                        vicitm binary.
- src/skeleton.c: Example of program using OpenSSL
- src/*: Other necessary files

Note that the attacker and victim only synchronize *before* the 
encryption function call. You might need to introduce delays
before the attacker timing sequence to get a signal. 
This, unfortunately, will depend on the specific processor you 
are running on. Modify the injected code in `src/inject_gadget.py`
accordingly. 

Once built, run `sudo ./orchestrator`. 

