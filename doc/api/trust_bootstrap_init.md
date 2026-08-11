[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# trust_bootstrap_init
Generate a one-time ML-KEM keypair to bootstrap trust with another IPA deployment. Save the returned private key; it must be passed back to trust-bootstrap-retrieve once the other side has prepared a bootstrap package for it. The public key is meant to be handed, out of band, to an administrator of the other IPA deployment.

### Arguments
No arguments.

### Options
* kem_parameter_set : :ref:`StrEnum<StrEnum>`
 * Default: ML-KEM-768
 * Values: ('ML-KEM-768', 'ML-KEM-1024')
* version : :ref:`Str<Str>`

### Output
|Name|Type
|-|-
|result|Output

[//]: # (ADD YOUR NOTES BELOW. THESE WILL BE PICKED EVERY TIME THE DOCS ARE REGENERATED. //end)
### Semantics

### Notes

### Version differences