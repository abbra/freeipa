[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# trust_bootstrap_retrieve
Fetch a sealed trust bootstrap package prepared by another IPA deployment via trust-bootstrap-prepare, and configure this side's half of the trust.

### Arguments
No arguments.

### Options
* server : :ref:`Str<Str>` **(Required)**
* token : :ref:`Str<Str>` **(Required)**
* kem_private_key : :ref:`Bytes<Bytes>` **(Required)**
* kem_parameter_set : :ref:`StrEnum<StrEnum>`
 * Default: ML-KEM-768
 * Values: ('ML-KEM-768', 'ML-KEM-1024')
* bidirectional : :ref:`Bool<Bool>`
 * Default: False
* base_id : :ref:`Int<Int>`
* range_size : :ref:`Int<Int>`
* range_type : :ref:`StrEnum<StrEnum>`
 * Values: ('ipa-ad-trust-posix',)
* version : :ref:`Str<Str>`

### Output
|Name|Type
|-|-
|result|Output
|summary|Output

[//]: # (ADD YOUR NOTES BELOW. THESE WILL BE PICKED EVERY TIME THE DOCS ARE REGENERATED. //end)
### Semantics

### Notes

### Version differences