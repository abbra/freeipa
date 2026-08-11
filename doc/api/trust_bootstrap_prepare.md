[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# trust_bootstrap_prepare
Prepare a sealed trust bootstrap package for another IPA deployment and configure this side's half of the trust. Run this after receiving an ML-KEM public key (from trust-bootstrap-init on the other side) out of band. Relay the returned token, and this server's hostname, back to the other side out of band so it can run trust-bootstrap-retrieve.

### Arguments
|Name|Type|Required
|-|-|-
|remote_domain|:ref:`Str<Str>`|True

### Options
* remote_kem_public_key : :ref:`Bytes<Bytes>` **(Required)**
* kem_parameter_set : :ref:`StrEnum<StrEnum>`
 * Default: ML-KEM-768
 * Values: ('ML-KEM-768', 'ML-KEM-1024')
* signature_algorithm : :ref:`StrEnum<StrEnum>`
 * Default: EC
 * Values: ('RSA', 'EC', 'ML-DSA')
* ttl : :ref:`Int<Int>`
 * Default: 3600
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

[//]: # (ADD YOUR NOTES BELOW. THESE WILL BE PICKED EVERY TIME THE DOCS ARE REGENERATED. //end)
### Semantics

### Notes

### Version differences