[//]: # (THE CONTENT BELOW IS GENERATED. DO NOT EDIT.)
# trust_mod

Modify a trust.

Allows modification of trust attributes including SID to authentication
indicator mappings. Use --indicator-map to configure mappings between
Active Directory group SIDs (or names) and Kerberos authentication
indicators, enabling policy enforcement for trusted domain users.


### Arguments
|Name|Type|Required
|-|-|-
|cn|:ref:`Str<Str>`|True

### Options
* rights : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* all : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* raw : :ref:`Flag<Flag>` **(Required)**
 * Default: False
* ipantsidblacklistincoming : :ref:`Str<Str>`
* ipantsidblacklistoutgoing : :ref:`Str<Str>`
* ipantadditionalsuffixes : :ref:`Str<Str>`
* ipasidindicatormap : :ref:`Str<Str>`
* setattr : :ref:`Str<Str>`
* addattr : :ref:`Str<Str>`
* delattr : :ref:`Str<Str>`
* version : :ref:`Str<Str>`

### Output
|Name|Type
|-|-
|result|Entry
|summary|Output
|value|PrimaryKey

[//]: # (ADD YOUR NOTES BELOW. THESE WILL BE PICKED EVERY TIME THE DOCS ARE REGENERATED. //end)
### Semantics

### Notes

### Version differences