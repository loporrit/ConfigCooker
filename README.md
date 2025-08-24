# ConfigCooker

This program takes an input file (`input.json` in the currently directory), and transforms it using a private key (`signing.key` in the current directory), to produce a signed and wrapped copy of the file (`config.json` in the current directory).

If signing.key does not exist, a new one will be generated, along with a public key (`public.key` in the current directory).

