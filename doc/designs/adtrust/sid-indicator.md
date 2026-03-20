# SID to Authentication Indicator Mapping

## Overview

When FreeIPA establishes trust with Active Directory forests, users from trusted
domains can authenticate to FreeIPA-enrolled systems. During this authentication
process, the KDC issues tickets that include PAC (Privilege Attribute Certificate)
data containing the user's group memberships as Security Identifiers (SIDs).

Authentication indicators are a Kerberos feature that allows tickets to carry
metadata about how the user authenticated (e.g., "pkinit" for smartcard-based
authentication). This information can be used by services to make authorization
decisions based on the authentication method.

This feature allows FreeIPA administrators to configure mappings between Active
Directory group SIDs and authentication indicators. When a trusted user's ticket
is processed by the KDC, if the user is a member of a mapped group (indicated by
the presence of that group's SID in their PAC), the corresponding authentication
indicator will be added to their ticket.

This enables policy enforcement scenarios such as:
- Requiring smartcard authentication for members of privileged AD groups
- Enforcing different authentication requirements based on AD group membership
- Implementing MS-PKCA (Microsoft Public Key Cryptography for Initial Authentication
  in Kerberos) compliance for cross-realm authentication
- Integrating with Active Directory Authentication Mechanism Assurance (AMA) to
  map certificate-based temporary group memberships to authentication indicators

### Integration with Active Directory Authentication Mechanism Assurance

Active Directory's Authentication Mechanism Assurance (AMA) feature allows AD
domain controllers to assign temporary group memberships based on the authentication
method and certificate properties used during authentication. When a user
authenticates with a smartcard, the domain controller examines specific Object
Identifiers (OIDs) in the certificate's Issuance Policy extension. Based on these
OIDs and the AD's configured certificate trust settings, the DC dynamically adds
special group SIDs to the user's PAC for that authentication session only.

These temporary group memberships:
- Only exist within the Kerberos ticket (PAC); they are not permanent AD group
  memberships
- Are automatically added by the AD domain controller during authentication
- Depend on the certificate's Issuance Policy OIDs matching configured AMA policies
- Persist only for the lifetime of the Kerberos ticket

When FreeIPA processes cross-realm tickets from AD users, the PAC contains both
permanent group memberships and these AMA-based temporary group memberships. The
SID to indicator mapping feature treats both types of group SIDs identically,
allowing FreeIPA administrators to map AMA groups to authentication indicators.

This integration enables certificate-based authentication assurance across the
trust boundary: possession of a qualified certificate (as defined by AD's AMA
policy) automatically grants temporary group membership in AD, and FreeIPA can
detect this membership and translate it into authentication indicators that
FreeIPA services can enforce.

**Federal PKI and DoD CAC Support:**

This feature is particularly valuable for US government and DoD environments that
use Federal PKI certificates (such as Common Access Cards - CAC, or Personal
Identity Verification - PIV cards). Federal PKI defines a standardized set of
certificate policy OIDs (2.16.840.1.101.3.2.1.3.x) that indicate the assurance
level of the authentication. When Active Directory is configured with AMA using
these Federal PKI OIDs, FreeIPA can automatically enforce authentication assurance
requirements based on the certificate's policy OIDs, enabling seamless integration
between DoD/Federal authentication infrastructure and FreeIPA-managed Linux systems.

Reference: https://pagure.io/freeipa/issue/TBD

## Use Cases

### Smartcard requirement for privileged AD groups

As a FreeIPA administrator managing a trust with Active Directory, I want to
ensure that members of certain privileged AD groups (such as "Domain Admins" or
"Enterprise Admins") can only access FreeIPA services if they authenticated using
a smartcard, even though they are authenticating from the AD side.

By mapping these AD group SIDs to the "pkinit" authentication indicator with the
smartcard requirement flag, I can enforce that their tickets will include the
pkinit indicator, which services can then check before granting access.

### MS-PKCA compliance for cross-realm authentication

As a security-conscious FreeIPA administrator, I want to implement Microsoft's
PKCA protocol requirements (MS-PKCA section 3.1.5.2) for certain trusted domain
users. This protocol requires that authentication indicators properly reflect
smartcard authentication based on group membership in the trusted domain.

By configuring SID to indicator mappings with PKCA compliance flags, I ensure
that the KDC enforces these requirements when processing tickets for trusted users.

### Differentiated access based on AD organizational structure

As a FreeIPA administrator, I want to apply different authentication policies
based on which department or organizational unit users belong to in Active Directory.
For example, finance department members might require stronger authentication than
general users.

By mapping SIDs of AD security groups representing different departments to custom
authentication indicators, I enable fine-grained access control policies on FreeIPA
services.

### Leveraging Active Directory AMA for certificate assurance

As a FreeIPA administrator in an environment where Active Directory has configured
Authentication Mechanism Assurance (AMA) policies, I want to enforce that users
accessing sensitive FreeIPA resources must have authenticated with qualified
certificates.

In Active Directory, AMA has been configured to assign users who authenticate with
certificates containing specific Issuance Policy OIDs (e.g., id-kp-smartcardLogon)
to a temporary group such as "Certificate-Based Authentication" or "High Assurance
Users". This group membership is only injected into the PAC during smartcard
authentication and only exists for that ticket's lifetime.

By mapping the SID of this AMA group to an authentication indicator like "pkinit"
or "qualified-cert", I can:
- Detect on the FreeIPA side which users authenticated with qualified certificates
- Enforce access policies that require this indicator for sensitive services
- Implement defense-in-depth by leveraging AD's certificate validation while
  enforcing FreeIPA's own authorization policies
- Bridge AD's certificate trust policies with FreeIPA's authentication requirements

This enables seamless integration between AD's certificate-based authentication
policies and FreeIPA's service access controls without requiring duplicate policy
configuration.

## How to Use

### Prerequisites

**General Requirements:**
- FreeIPA deployment with Active Directory trust established
- Trust administrator privileges (member of "trust admins" group)
- Knowledge of the SID or name of the target AD group

**For Federal PKI / DoD CAC Integration:**
- Active Directory with Federal PKI certification authorities trusted
- Federal Bridge CA or DoD Root CAs published to AD NTAuth and Root stores
- AMA configured in Active Directory with Federal PKI OID mappings
- Smartcard readers available for CAC/PIV authentication
- Certificates containing Federal PKI policy OIDs (2.16.840.1.101.3.2.1.3.x)

**Active Directory CA Trust Configuration (Federal PKI):**
```powershell
# On AD Domain Controller as Enterprise Admin

# Import Federal Bridge CA certificate
certutil -dspublish -f FederalBridgeCA.cer NTAuthCA
certutil -dspublish -f FederalBridgeCA.cer RootCA

# Or import DoD Root CAs for DoD CAC
certutil -dspublish -f DoD_Root_CA_3.cer NTAuthCA
certutil -dspublish -f DoD_Root_CA_3.cer RootCA

# Verify CA publication
certutil -viewstore -enterprise NTAuth
certutil -viewstore -enterprise Root

# Enable certificate chain validation
# Group Policy: Computer Configuration > Windows Settings > Security Settings >
# Public Key Policies > Certificate Path Validation Settings
# Enable: "Define these policy settings"
# Enable: "Allow user trusted root CAs to be used to validate certificates"
```

### Configuring SID to indicator mappings

SID to indicator mappings are configured on a per-trust basis using the `ipa trust-mod`
command:

```bash
# Map by group name (recommended)
ipa trust-mod ad.example.com \
  --indicator-map="Domain Admins:pkinit:true"

# Map by explicit SID
ipa trust-mod ad.example.com \
  --indicator-map="S-1-5-21-123456789-987654321-111111111-512:pkinit:true"

# Add multiple mappings
ipa trust-mod ad.example.com \
  --indicator-map="Domain Admins:pkinit:true" \
  --indicator-map="Enterprise Admins:pkinit:true" \
  --indicator-map="Finance Users:custom-strong-auth"
```

The indicator map format is: `<group-name-or-sid>:<indicator>[:<smartcard-flag>]`

Where:
- `group-name-or-sid`: Either the AD group name or explicit SID
- `indicator`: The authentication indicator to add (e.g., "pkinit", or a custom value)
- `smartcard-flag`: Optional boolean (`true` or `false`, defaults to `false`). When
  set to `true`, indicates MS-PKCA smartcard requirement compliance.

### Configuring mappings for AMA groups

When Active Directory is configured with Authentication Mechanism Assurance (AMA),
users who authenticate with qualified certificates receive temporary group
memberships that appear in their PAC. These AMA groups can be mapped to indicators
just like regular AD groups.

**Important**: AMA groups are often universal or domain local groups that may not
be visible through standard LDAP queries. You may need to use the explicit SID
format when configuring mappings for AMA groups.

#### Finding AMA group SIDs

To find the SID of an AMA group in Active Directory:

```powershell
# On an AD domain controller
Get-ADGroup "Authentication Policy Silo - High Assurance" | Select-Object Name,SID

# Or for certificate-based authentication groups
Get-ADGroup "Certificate-Based Authentication" | Select-Object Name,SID
```

Alternatively, examine a user's ticket after smartcard authentication:

```bash
# On a Windows system or AD-joined host
klist tickets

# Use Microsoft's PAC parsing tools to examine group SIDs
```

#### Example AMA mapping configurations

##### Using Federal PKI Assurance Levels

For organizations using Federal PKI (common in US government and DoD environments):

```bash
# Step 1: Identify AMA group SIDs in Active Directory
# On AD DC as Domain Admin:
# Get-ADGroup "id-fpki-common-High" | Select-Object Name,SID
# Get-ADGroup "id-fpki-common-authentication" | Select-Object Name,SID
# Get-ADGroup "id-fpki-common-hardware" | Select-Object Name,SID
# Get-ADGroup "id-fpki-common-pivAuth-derived-hardware" | Select-Object Name,SID

# Step 2: Configure FreeIPA SID mappings using the discovered SIDs

# Map Federal PKI High Assurance to pkinit with smartcard flag
ipa trust-mod ad.example.com \
  --indicator-map="id-fpki-common-High:pkinit:true"

# Or using explicit SID (recommended for AMA groups)
ipa trust-mod ad.example.com \
  --indicator-map="S-1-5-21-123456789-987654321-111111111-5001:fpki-high:true"

# Map multiple Federal PKI assurance levels
ipa trust-mod ad.example.com \
  --indicator-map="S-1-5-21-...-5001:fpki-high:true" \
  --indicator-map="S-1-5-21-...-5002:fpki-hardware:true" \
  --indicator-map="S-1-5-21-...-5003:fpki-auth" \
  --indicator-map="S-1-5-21-...-5004:fpki-piv-derived:true"

# Complete Federal PKI configuration example
ipa trust-mod dod.example.mil \
  --indicator-map="id-fpki-common-High:fpki-high:true" \
  --indicator-map="id-fpki-common-hardware:fpki-hardware:true" \
  --indicator-map="id-fpki-common-authentication:fpki-auth" \
  --indicator-map="id-fpki-common-pivAuth-derived-hardware:fpki-piv-hw:true"
```

##### Using Microsoft Generic Assurance Levels

For organizations using Microsoft's generic AMA implementation:

```bash
# Map Microsoft assurance levels
ipa trust-mod ad.example.com \
  --indicator-map="High Assurance Users:pkinit:true" \
  --indicator-map="Medium Assurance Users:enhanced-auth" \
  --indicator-map="Low Assurance Users:basic-auth"
```

##### Combining Permanent and AMA Group Mappings

```bash
# Mix permanent AD groups with Federal PKI AMA groups
ipa trust-mod ad.example.com \
  --indicator-map="Domain Admins:admin-access:true" \
  --indicator-map="Enterprise Admins:admin-access:true" \
  --indicator-map="id-fpki-common-High:fpki-high:true" \
  --indicator-map="id-fpki-common-hardware:fpki-hardware:true"
```

##### DoD/Federal Use Case Example

Complete configuration for a DoD environment with CAC (Common Access Card) authentication:

```bash
# DoD environment typically uses Federal PKI OIDs
# CAC certificates contain policy OIDs like:
# - 2.16.840.1.101.3.2.1.3.13 (authentication)
# - 2.16.840.1.101.3.2.1.3.16 (high assurance)
# - 2.16.840.1.101.3.2.1.3.18 (PIV-I hardware)

# Configure mappings for DoD trust
ipa trust-mod dod.example.mil \
  --indicator-map="id-fpki-common-High:cac-high:true" \
  --indicator-map="id-fpki-certpcy-pivi-hardware:cac-pivi:true" \
  --indicator-map="id-fpki-common-authentication:cac-auth:true"

# Verify configuration
ipa trust-show dod.example.mil --all | grep -A10 "SID to Indicator"
```

**Note**: Users must authenticate from AD using smartcard/certificate for AMA
group memberships to be included in their PAC. Regular password-based
authentication will not trigger AMA group assignment, even for users who
possess qualifying certificates.

### Viewing configured mappings

```bash
ipa trust-show ad.example.com --all
```

The output will include the `ipaSIDIndicatorMap` attribute showing all configured
mappings.

### Verifying indicator mapping

After configuration, when a user from the trusted domain authenticates and is a
member of a mapped group, their ticket will include the corresponding authentication
indicator. This can be verified by examining the KDC logs or using PAC inspection tools:

```bash
# On the IPA KDC, check logs for indicator mapping
tail -f /var/log/krb5kdc.log | grep -i "indicator"

# Or examine the PAC from the ticket
/usr/libexec/ipa/ipa-print-pac ticket username@AD.EXAMPLE.COM
```

## Design

### LDAP Schema Extensions

New LDAP schema elements are introduced to support SID indicator mappings:

**Attributes:**
- `ipaPartnerTrustType` (OID: 2.16.840.1.113730.3.8.27.1): Integer attribute
  indicating the trust type configuration
- `ipaSIDIndicatorMap` (OID: 2.16.840.1.113730.3.8.27.2): Multi-valued string
  attribute storing SID to indicator mappings in the format
  `<SID>:<indicator>:<smartcard-flag>`

**Object Class:**
- `ipaTrustObject` (OID: 2.16.840.1.113730.3.8.28.1): Auxiliary object class
  that extends trust entries with `ipaPartnerTrustType` (required) and
  `ipaSIDIndicatorMap` (optional) attributes

These schema elements are defined in `install/share/60basev5.ldif`.

### LDAP ACIs

Two new Access Control Instructions (ACIs) are added to `cn=trusts,$SUFFIX`:

1. Trust admins ACI: Allows members of the "trust admins" group to read, write,
   add, and delete the new attributes
2. AD trust agents ACI: Allows the adtrust system account to read, write, add,
   and delete the new attributes for system operations

These ACIs ensure proper authorization for managing SID indicator mappings.

### IPA Framework (trust plugin)

The `trust` plugin in `ipaserver/plugins/trust.py` is extended with:

**New parameter:**
- `ipaSIDIndicatorMap`: Multi-valued string parameter with custom normalization
  and validation logic

**Normalization function (`normalize_sidindicatormap`):**
1. Parses the input string format: `<name-or-sid>:<indicator>:<smartcard-flag>`
2. Validates the group name or SID by resolving it to an actual SID in the
   trusted domain using the domain validator
3. Validates the authentication indicator is present
4. Parses and validates the optional smartcard flag (must be true/false)
5. Enforces that if smartcard flag is true, the indicator must be "pkinit"
6. Returns normalized format: `<SID>:<indicator>:<smartcard-flag>`

This normalization ensures that:
- Invalid group names/SIDs are rejected at input time
- SID format is consistent in the database (always uses canonical SID, not names)
- MS-PKCA compliance rules are validated

### KDB Backend (ipa-kdb)

The KDB backend processes SID indicator mappings during PAC verification and
ticket issuance for trusted users.

**Data structures:**

```c
struct ipadb_sid_indicator_map {
    char *sid;              /* Group SID to match */
    char *indicator;        /* Indicator to add */
    bool req_pkca;          /* MS-PKCA compliance flag */
};

struct ipadb_adtrusts {
    /* ... existing fields ... */
    struct ipadb_sid_indicator_map *indicator_map;
};
```

**Processing flow:**

1. **Loading mappings** (`ipadb_mspac_get_trusted_domains`):
   - Modified to query the `ipaSIDIndicatorMap` attribute from trust entries
   - Uses updated filter: `(|(objectclass=ipaNTTrustedDomain)(objectclass=ipaTrustObject))`
   - Parses mapping entries using `ipadb_adtrusts_fill_sid_indicator_map()`
   - Stores mappings in the per-domain trust structure

2. **Applying mappings** (`map_sids_to_indicators`):
   - Called during PAC verification for cross-realm tickets
   - Extracts all group SIDs from the user's PAC LOGON_INFO structure
   - Compares each group SID against the domain's indicator map
   - For matching SIDs, adds the corresponding indicator to the ticket's
     authentication indicators list
   - Avoids adding duplicate indicators

3. **MS-PKCA compliance** (`req_pkca` field):
   - The `req_pkca` flag is stored as informational metadata in the
     `ipadb_sid_indicator_map` structure; the KDB applies the mapped indicator
     unconditionally whenever the SID matches, regardless of this flag's value
   - Runtime enforcement relies on AD's AMA mechanism: AMA group SIDs only
     appear in the PAC when the user authenticated with a qualifying certificate,
     so the indicator is implicitly correct without additional KDB enforcement
   - During configuration, setting `req_pkca=true` requires the indicator to
     be `"pkinit"` (enforced by the IPA framework validator in `trust.py`)

**Integration points:**

The SID mapping is integrated into the PAC verification flow in
`ipadb_check_logon_info()`, which is called when:
- Processing cross-realm TGTs from trusted domains
- Verifying S4U (Service for User) requests
- Issuing tickets for trusted domain users

### Active Directory Authentication Mechanism Assurance (AMA)

#### AMA Overview

Authentication Mechanism Assurance is an Active Directory feature introduced to
enable dynamic group membership based on authentication method and certificate
properties. AMA allows organizations to enforce authentication strength requirements
by granting access to resources based on how users authenticated, not just who
they are.

#### AMA Configuration in Active Directory

AMA is configured in Active Directory through the following steps. The configuration
must be performed on a domain controller with appropriate administrative privileges.

##### Step 1: Create Universal Security Groups

Create universal security groups for each assurance level. Universal scope is
required because AMA groups need to be accessible across the forest for cross-realm
authentication.

```powershell
# Example: Create AMA groups for Federal PKI assurance levels
New-ADGroup -Name "id-fpki-common-authentication" `
            -GroupScope Universal `
            -GroupCategory Security `
            -Path "OU=AMA Groups,DC=example,DC=com" `
            -Description "Authentication Mechanism Assurance - FPKI Common Authentication"

New-ADGroup -Name "id-fpki-common-High" `
            -GroupScope Universal `
            -GroupCategory Security `
            -Path "OU=AMA Groups,DC=example,DC=com" `
            -Description "Authentication Mechanism Assurance - FPKI High Assurance"

New-ADGroup -Name "id-fpki-common-hardware" `
            -GroupScope Universal `
            -GroupCategory Security `
            -Path "OU=AMA Groups,DC=example,DC=com" `
            -Description "Authentication Mechanism Assurance - FPKI Hardware"

New-ADGroup -Name "id-fpki-common-pivAuth-derived-hardware" `
            -GroupScope Universal `
            -GroupCategory Security `
            -Path "OU=AMA Groups,DC=example,DC=com" `
            -Description "Authentication Mechanism Assurance - PIV-Derived Hardware"
```

##### Step 2: Register OIDs in Active Directory Configuration

Use `certutil` to create OID objects in the Active Directory Configuration naming
context. This makes the OIDs available for mapping.

```powershell
# Register FPKI OIDs in AD Configuration
# Format: certutil -dsaddtemplate <OID> <DisplayName>

certutil -dsaddtemplate "2.16.840.1.101.3.2.1.3.13" "id-fpki-common-authentication"
certutil -dsaddtemplate "2.16.840.1.101.3.2.1.3.16" "id-fpki-common-High"
certutil -dsaddtemplate "2.16.840.1.101.3.2.1.3.7" "id-fpki-common-hardware"
certutil -dsaddtemplate "2.16.840.1.101.3.2.1.3.41" "id-fpki-common-pivAuth-derived-hardware"
```

**Note**: The `certutil -dsaddtemplate` command creates an object in the
`CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=...` container.

##### Step 3: Link OIDs to Security Groups

Establish the mapping between OIDs and security groups using the `msDS-OIDToGroupLink`
attribute. This is the core of AMA configuration.

```powershell
# PowerShell function to link OID to group
function Set-AMAOIDMapping {
    param(
        [string]$OID,
        [string]$GroupDN
    )

    # Get the configuration naming context
    $configNC = (Get-ADRootDSE).configurationNamingContext

    # Construct the OID container DN
    $oidDN = "CN=$OID,CN=OID,CN=Public Key Services,CN=Services,$configNC"

    # Set the link attribute
    Set-ADObject -Identity $oidDN -Add @{'msDS-OIDToGroupLink'=$GroupDN}
}

# Apply mappings for FPKI OIDs
$groupsOU = "OU=AMA Groups,DC=example,DC=com"

Set-AMAOIDMapping -OID "2.16.840.1.101.3.2.1.3.13" `
                  -GroupDN "CN=id-fpki-common-authentication,$groupsOU"

Set-AMAOIDMapping -OID "2.16.840.1.101.3.2.1.3.16" `
                  -GroupDN "CN=id-fpki-common-High,$groupsOU"

Set-AMAOIDMapping -OID "2.16.840.1.101.3.2.1.3.7" `
                  -GroupDN "CN=id-fpki-common-hardware,$groupsOU"

Set-AMAOIDMapping -OID "2.16.840.1.101.3.2.1.3.41" `
                  -GroupDN "CN=id-fpki-common-pivAuth-derived-hardware,$groupsOU"
```

##### Step 4: Verify OID to Group Mappings

Verify that the mappings are correctly configured:

```powershell
# List all configured OID mappings
$configNC = (Get-ADRootDSE).configurationNamingContext
$oidContainer = "CN=OID,CN=Public Key Services,CN=Services,$configNC"

Get-ADObject -SearchBase $oidContainer -Filter * -Properties msDS-OIDToGroupLink |
    Where-Object {$_.msDS-OIDToGroupLink} |
    Select-Object Name, msDS-OIDToGroupLink

# Expected output shows OIDs with their linked group DNs
```

##### Step 5: Configure Trusted Certification Authorities

Ensure that the CAs issuing the certificates with these OIDs are trusted in Active
Directory:

```powershell
# Import CA certificate to NTAuth store (required for smart card logon)
certutil -dspublish -f ca_certificate.cer NTAuthCA

# Import CA certificate to Root CA store
certutil -dspublish -f ca_certificate.cer RootCA

# Verify CA is trusted
certutil -viewstore -enterprise NTAuth
```

##### Complete Configuration Script

Here's a complete PowerShell script for Federal PKI AMA configuration, based on
the GSA FICAM reference implementation:

```powershell
# Configure AMA for Federal PKI Assurance Levels
# Based on: https://github.com/GSA/ficam-scripts-public

param(
    [Parameter(Mandatory=$true)]
    [string]$GroupOU  # e.g., "OU=AMA Groups,DC=example,DC=com"
)

function Set-ADUG-CertIssOID {
    param(
        [string]$IssuancePolicyOID,
        [string]$IssuancePolicyName,
        [string]$GroupDN
    )

    Write-Host "Configuring AMA for OID: $IssuancePolicyOID"

    # Create universal security group if it doesn't exist
    if (-not (Get-ADGroup -Filter "DistinguishedName -eq '$GroupDN'" -ErrorAction SilentlyContinue)) {
        $ouPath = $GroupDN -replace '^CN=[^,]+,', ''
        New-ADGroup -Name $IssuancePolicyName `
                    -GroupScope Universal `
                    -GroupCategory Security `
                    -Path $ouPath `
                    -Description "AMA Group for $IssuancePolicyName"
        Write-Host "  Created group: $GroupDN"
    } else {
        Write-Host "  Group already exists: $GroupDN"
    }

    # Register OID in AD configuration
    $result = certutil -dsaddtemplate $IssuancePolicyOID $IssuancePolicyName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Registered OID in AD"
    } else {
        Write-Host "  OID already registered or error occurred"
    }

    # Link OID to group
    $configNC = (Get-ADRootDSE).configurationNamingContext
    $oidDN = "CN=$IssuancePolicyOID,CN=OID,CN=Public Key Services,CN=Services,$configNC"

    try {
        Set-ADObject -Identity $oidDN -Add @{'msDS-OIDToGroupLink'=$GroupDN} -ErrorAction Stop
        Write-Host "  Linked OID to group"
    } catch {
        if ($_.Exception.Message -like "*already exists*") {
            Write-Host "  Link already exists"
        } else {
            Write-Host "  Error linking: $($_.Exception.Message)"
        }
    }

    Write-Host "  Configuration complete for $IssuancePolicyName"
    Write-Host ""
}

# Configure FPKI assurance levels
$mappings = @(
    @{OID="2.16.840.1.101.3.2.1.3.13"; Name="id-fpki-common-authentication"},
    @{OID="2.16.840.1.101.3.2.1.3.16"; Name="id-fpki-common-High"},
    @{OID="2.16.840.1.101.3.2.1.3.7";  Name="id-fpki-common-hardware"},
    @{OID="2.16.840.1.101.3.2.1.3.41"; Name="id-fpki-common-pivAuth-derived-hardware"}
)

foreach ($mapping in $mappings) {
    $groupDN = "CN=$($mapping.Name),$GroupOU"
    Set-ADUG-CertIssOID -IssuancePolicyOID $mapping.OID `
                        -IssuancePolicyName $mapping.Name `
                        -GroupDN $groupDN
}

Write-Host "AMA configuration complete!"
Write-Host "Next steps:"
Write-Host "1. Ensure issuing CAs are published to NTAuth and Root stores"
Write-Host "2. Verify certificates contain the configured policy OIDs"
Write-Host "3. Test smart card authentication"
```

##### Usage Example

```powershell
# Run the configuration script
.\Configure-FPKI-AMA.ps1 -GroupOU "OU=AMA Groups,DC=corp,DC=example,DC=com"

# Verify configuration
$configNC = (Get-ADRootDSE).configurationNamingContext
Get-ADObject -SearchBase "CN=OID,CN=Public Key Services,CN=Services,$configNC" `
             -Filter * -Properties msDS-OIDToGroupLink |
    Where-Object {$_.msDS-OIDToGroupLink} |
    Format-Table Name, msDS-OIDToGroupLink -AutoSize
```

Common Issuance Policy OIDs include:

**Microsoft's generic assurance OIDs:**
- `1.3.6.1.4.1.311.21.8` - Microsoft low assurance
- `1.3.6.1.4.1.311.21.9` - Microsoft medium assurance
- `1.3.6.1.4.1.311.21.10` - Microsoft high assurance

**Federal PKI (FPKI) Assurance Level OIDs:**
- `2.16.840.1.101.3.2.1.3.13` - id-fpki-common-authentication
- `2.16.840.1.101.3.2.1.3.16` - id-fpki-common-High
- `2.16.840.1.101.3.2.1.3.7` - id-fpki-common-hardware
- `2.16.840.1.101.3.2.1.3.12` - id-fpki-certpcy-mediumHardware
- `2.16.840.1.101.3.2.1.3.4` - id-fpki-certpcy-highAssurance
- `2.16.840.1.101.3.2.1.3.18` - id-fpki-certpcy-pivi-hardware
- `2.16.840.1.101.3.2.1.3.36` - id-fpki-common-devicesHardware
- `2.16.840.1.101.3.2.1.3.40` - id-fpki-common-derived-pivAuth
- `2.16.840.1.101.3.2.1.3.41` - id-fpki-common-pivAuth-derived-hardware

Organizations using Federal PKI or DoD PKI certificates will have these OIDs in
their certificates' Certificate Policies extension, enabling interoperability with
government systems and compliance with Federal authentication standards.

#### AMA Authentication Flow

When a user authenticates to Active Directory with a smartcard:

1. **Certificate Presentation**: The user's smartcard presents the certificate to
   the domain controller during PKINIT authentication.

2. **Certificate Validation**: The DC validates the certificate chain against
   trusted CAs configured in AD.

3. **OID Extraction**: The DC extracts Issuance Policy OIDs from the certificate's
   Enhanced Key Usage or Certificate Policies extension.

4. **Group Assignment**: Based on configured mappings, the DC identifies which AMA
   groups the user should temporarily belong to.

5. **PAC Injection**: The DC adds the SIDs of the matched AMA groups to the
   Resource Groups (extra SIDs) section of the PAC LOGON_INFO structure.

6. **Ticket Issuance**: The TGT is issued with the PAC containing both:
   - User's permanent group memberships (from AD groups)
   - Temporary AMA group memberships (based on certificate OIDs)

#### FreeIPA Integration with AMA

When FreeIPA processes tickets from AD users who authenticated via AMA:

1. **PAC Reception**: FreeIPA receives cross-realm tickets containing PAC with
   both permanent and AMA-assigned group SIDs.

2. **SID Extraction**: The `map_sids_to_indicators()` function in the KDB backend
   extracts all group SIDs from the PAC LOGON_INFO structure, including:
   - `info->info->info3.base.groups` - Primary user groups
   - `info->info->info3.base.rid` - User's primary group RID
   - `info->info->info3.sids` - Extra SIDs (where AMA groups appear)

3. **Mapping Application**: For each SID (whether from permanent or AMA groups),
   the function checks the configured SID to indicator mappings and adds matching
   indicators to the ticket.

4. **Indicator Propagation**: The authentication indicators are included in
   subsequent tickets issued by the FreeIPA KDC, allowing services to make
   authorization decisions.

**Key Implementation Details**:

The FreeIPA KDB backend does not distinguish between permanent AD group memberships
and temporary AMA group memberships - both are simply SIDs in the PAC. This design
choice is intentional and provides several benefits:

- **Simplicity**: No special handling required for AMA vs. regular groups
- **Flexibility**: Any group SID can be mapped, regardless of its source
- **Transparency**: The mapping configuration is consistent across all group types
- **Security**: Trust in AD's authentication decisions while enforcing FreeIPA's
  authorization policies

**AMA Temporary Nature**:

It's important to understand that AMA group memberships are scoped to the ticket:

- They do not appear in AD's directory as persistent group memberships
- They are not visible via LDAP queries of the user object
- They only exist within the PAC of tickets issued during certificate authentication
- Password-based authentication of the same user will NOT include these SIDs
- Different certificate authentication sessions may yield different AMA groups
  (if the user authenticates with different certificates)

This temporary nature makes AMA groups ideal candidates for authentication
indicators, as both concepts represent authentication-time assertions rather than
persistent identity attributes.

#### MS-PKCA Compliance and AMA

The MS-PKCA (Microsoft Public Key Cryptography for Initial Authentication in
Kerberos) protocol specification (section 3.1.5.2) defines requirements for
propagating authentication strength indicators when certificates are used for
authentication. The `req_pkca` flag in the SID indicator mapping allows FreeIPA
to enforce these requirements.

When a mapping has `req_pkca=true`:
- The indicator must be "pkinit" (enforced during configuration by `trust.py`)
- This signals that the mapping is intended for PKCA compliance
- The KDB adds the pkinit indicator whenever the mapped group SID is present
  in the PAC; the actual guarantee that the SID is only present during
  certificate-based authentication is provided by AD's AMA mechanism

This division of responsibility ensures that services relying on PKCA can
trust that the "pkinit" indicator accurately reflects certificate-based
authentication: AD's AMA enforces the certificate requirement, and FreeIPA
maps the resulting AMA group SID to the authentication indicator.

## Implementation

### Schema and ACIs

- **File**: `install/share/60basev5.ldif`
  - Defines new LDAP attributes and object class
  - Automatically loaded during fresh installation
  - Applied during upgrade via LDAP update mechanism

- **File**: `install/updates/60-trusts.update`
  - Adds ACIs for trust admins and adtrust agents
  - Applied during upgrade

### IPA Framework

- **File**: `ipaserver/plugins/trust.py`
  - Adds `ipaSIDIndicatorMap` parameter to the `trust` object
  - Implements `normalize_sidindicatormap()` validation function
  - Updates `possible_objectclasses` to include `ipaTrustObject`
  - Updates `default_attributes` to include `ipaPartnerTrustType` and
    `ipaSIDIndicatorMap`

### KDB Backend

- **Files**:
  - `daemons/ipa-kdb/ipa_kdb_mspac_private.h`: Data structure definitions and
    declarations for all non-static helper functions (the header comment notes
    it is intended for use in both the implementation and unit tests)
  - `daemons/ipa-kdb/ipa_kdb_mspac.c`: Implementation of parsing and mapping logic

- **Key functions** (all non-static, declared in `ipa_kdb_mspac_private.h` to
  allow direct invocation from the unit test binary):
  - `ipadb_adtrusts_fill_sid_indicator_map()`: Parses the `ipaSIDIndicatorMap`
    LDAP attribute values into in-memory `ipadb_sid_indicator_map` structures.
    Returns `ENOENT` if the attribute is absent (treated as non-fatal: no
    mappings configured); propagates other errors to abort domain loading.
  - `map_sids_to_indicators()`: Applies SID to indicator mappings during PAC
    verification; extracts all group SIDs from the PAC LOGON_INFO and adds
    matching indicators to the ticket's authentication indicator list
  - `_ipadb_authind_add()`: Appends an indicator to the `krb5_data **` list,
    allocating or growing the array as needed
  - `_ipadb_authind_contains()`: Checks whether an indicator is already present
    in the list, used to suppress duplicates

- **Error handling** in `ipadb_mspac_get_trusted_domains()`:
  The return value of `ipadb_adtrusts_fill_sid_indicator_map()` is checked
  after freeing the raw LDAP string array. `ENOENT` (attribute absent or empty)
  is treated as non-fatal and cleared; any other error causes the function to
  jump to the error path via `goto done`, consistent with the adjacent
  `ipadb_adtrusts_fill_sid_blacklists()` call.

## Feature Management

### UI

The Web UI can be enhanced to manage SID indicator mappings through the Trust
configuration interface:

- **Location**: `IPA Server / Trusts / <trust-name>`
- **New section**: "SID to Indicator Mappings"
  - Display existing mappings in a table format
  - Add button to create new mappings with fields:
    - Group Name/SID (text input with validation)
    - Authentication Indicator (text input or dropdown)
    - Smartcard Required (checkbox)
  - Delete button for each mapping

### CLI

| Command | Options |
| --- | ----- |
| ipa trust-mod | `--indicator-map=GROUP:INDICATOR[:SMARTCARD]` |
| ipa trust-show | `--all` (to display indicator maps) |

#### Examples:

```bash
# Add mapping by group name
ipa trust-mod ad.example.com --indicator-map="Domain Admins:pkinit:true"

# Add mapping by SID
ipa trust-mod ad.example.com --indicator-map="S-1-5-21-...-512:pkinit:true"

# Multiple mappings in one command
ipa trust-mod ad.example.com \
  --indicator-map="Domain Admins:pkinit:true" \
  --indicator-map="Finance Group:strong-auth"

# View all mappings
ipa trust-show ad.example.com --all
```

### Configuration

SID indicator mappings are stored in LDAP under the trust entry:
`cn=<domain>,cn=ad,cn=trusts,$SUFFIX`

The mappings are automatically loaded by the KDB backend when processing tickets
and are cached with other trust information. The cache is refreshed periodically
based on the trust information update interval.

## Upgrade

During upgrade from versions without this feature:

1. LDAP schema is automatically updated with new attributes and object class
   from `60basev5.ldif`
2. New ACIs are added to the trusts container via `60-trusts.update`
3. Existing trust entries are not automatically modified (no mappings are added)
4. Administrators can add mappings to existing trusts using `ipa trust-mod` after
   upgrade

No manual intervention is required. The feature is available immediately after
upgrade, with no mappings configured by default.

## Security Considerations

### Input validation

The normalization function performs strict validation:
- Group names/SIDs must resolve to valid trusted domain objects
- Invalid or non-existent groups are rejected
- Smartcard flag must be valid boolean if provided
- Indicator must be present and non-empty

This prevents:
- Mapping to invalid/arbitrary SIDs
- Injection of malformed data
- Bypassing MS-PKCA compliance rules

### Authorization

Only members of the "trust admins" group can configure SID indicator mappings.
This is enforced through:
- LDAP ACIs on the trust entries
- Framework-level permission checks in the trust plugin

### MS-PKCA compliance

When the smartcard flag is set to true:
- The indicator must be "pkinit" (enforced during normalization)
- This ensures compliance with Microsoft's PKCA protocol requirements
- Attempting to use a different indicator with smartcard=true will result in
  validation error

### Performance impact

- Mappings are loaded once during trust information refresh (periodic)
- SID matching is performed only for cross-realm tickets from trusted domains
- Impact is limited to the number of group SIDs in the PAC and the number of
  configured mappings
- No impact on local IPA user authentication

### AMA security considerations

When integrating with Active Directory's Authentication Mechanism Assurance:

**Trust in AD's AMA implementation:**
- FreeIPA trusts that the AD domain controller correctly validated the certificate
  and assigned appropriate AMA group memberships
- The security of the feature depends on proper AD certificate trust configuration
- Ensure that AD's trusted CAs and OID-to-group mappings are correctly configured
- Review AD's certificate validation policies regularly

**Certificate revocation:**
- AMA group assignment happens at authentication time in AD
- If a certificate is revoked after authentication, the Kerberos ticket (and its
  AMA group memberships) remains valid until expiration
- Services should consider implementing additional certificate status checks for
  high-security operations
- Ticket lifetime policies should be configured appropriately to limit exposure
  window

**OID spoofing prevention:**
- AD validates certificates against configured trusted CAs before considering OIDs
- Only certificates from trusted CAs can trigger AMA group assignment
- Ensure AD's certificate trust configuration includes proper CA validation
- Review certificate chain validation settings in AD

**Temporary nature of AMA memberships:**
- AMA group memberships are scoped to the ticket lifetime
- They do not persist beyond ticket expiration
- Services should not cache authorization decisions based on AMA indicators beyond
  ticket lifetime
- Renewing tickets with password authentication will lose AMA group memberships

**Cross-realm implications:**
- FreeIPA services should enforce their own authorization policies in addition to
  relying on authentication indicators
- The presence of an indicator asserts how the user authenticated, not what they
  are authorized to do
- Implement defense-in-depth by combining indicator checks with other authorization
  mechanisms (group membership, HBAC, sudo rules, etc.)

## Test Plan

### Unit tests

Unit tests for the KDB backend are implemented using the cmocka framework in
`daemons/ipa-kdb/tests/ipa_kdb_tests.c` and are run via `make check`.

Three test groups cover the new SID indicator mapping code:

**`test_fill_sid_indicator_map`** — tests `ipadb_adtrusts_fill_sid_indicator_map()`:
- NULL input returns `ENOENT`
- Single entry `"<SID>:<indicator>:true"` → `req_pkca=true`
- Single entry with no flag → `req_pkca=false`
- Single entry with `":false"` flag → `req_pkca=false`
- Two-entry array with sentinel NULL is parsed correctly

**`test_authind_add_contains`** — tests `_ipadb_authind_add()` and
`_ipadb_authind_contains()`:
- `_ipadb_authind_contains()` on NULL list returns false
- Adding to a NULL list allocates a new list with the indicator
- Adding the same indicator again is suppressed (duplicate check)
- Adding a second distinct indicator grows the list to two entries

**`test_map_sids_to_indicators`** — tests `map_sids_to_indicators()` with a
synthetic PAC and trust context:
- Returns without error when `indicators` pointer is NULL
- Returns without error when the domain has no `indicator_map`
- No indicator is added when no PAC SID matches the map
- A matching SID in `info->info->info3.sids[]` (the extra SIDs array, where
  AMA groups appear) causes the corresponding indicator to be added
- Calling with an already-matching SID and an existing indicator list does not
  add a duplicate

### Integration tests

Test scenarios should cover:

1. **Basic mapping configuration**
   - Add SID indicator mapping using group name
   - Add SID indicator mapping using explicit SID
   - Verify mapping is stored correctly in LDAP
   - View mapping with `ipa trust-show --all`

2. **Indicator application**
   - Configure mapping for AD group
   - Authenticate as trusted user who is member of the mapped group
   - Verify authentication indicator appears in the ticket
   - Authenticate as trusted user NOT in the mapped group
   - Verify indicator is NOT added to their ticket

3. **Multiple mappings**
   - Configure multiple SID indicator mappings for same trust
   - Authenticate as user member of multiple mapped groups
   - Verify all corresponding indicators are added to ticket

4. **Smartcard flag handling**
   - Configure mapping with smartcard=true and indicator=pkinit
   - Verify configuration succeeds
   - Attempt to configure smartcard=true with non-pkinit indicator
   - Verify validation error

5. **Invalid inputs**
   - Attempt to add mapping with non-existent group name
   - Verify error message
   - Attempt to add mapping with invalid SID format
   - Verify error message

6. **Upgrade scenario**
   - Test upgrade from version without this feature
   - Verify schema updates applied
   - Verify ACIs are present
   - Add mapping to existing trust
   - Verify functionality

7. **Authorization**
   - As non-admin user, attempt to add mapping
   - Verify permission denied
   - As trust admin, add mapping
   - Verify success

8. **AMA integration (requires AD with AMA configured)**
   - Configure AMA in AD with certificate trust and OID-to-group mappings
   - Create AMA group in AD (e.g., "High Assurance Users")
   - In FreeIPA, configure SID mapping for the AMA group SID
   - Authenticate AD user with smartcard containing qualifying OID
   - Verify user's ticket includes the mapped authentication indicator
   - Authenticate same AD user with password (no smartcard)
   - Verify user's ticket does NOT include the AMA-related indicator
   - Verify permanent group mappings still work for password authentication

9. **AMA with multiple assurance levels**
   - Configure multiple AMA groups in AD for different assurance levels
   - Configure different SID mappings for each assurance level
   - Authenticate with certificates containing different OIDs
   - Verify correct indicators are added based on certificate assurance level

### Manual testing

On a test deployment with AD trust:

```bash
# Configure mapping for Domain Admins
ipa trust-mod ad.example.com --indicator-map="Domain Admins:pkinit:true"

# From IPA client, authenticate as AD user in Domain Admins
kinit domainadmin@AD.EXAMPLE.COM

# Request a service ticket to trigger cross-realm processing
kvno host/ipaclient.ipa.example.com@IPA.EXAMPLE.COM

# On the IPA KDC, check the logs for indicator application
# tail -f /var/log/krb5kdc.log | grep -i "indicator"

# Or examine the PAC
# /usr/libexec/ipa/ipa-print-pac ticket domainadmin@AD.EXAMPLE.COM
```

### Manual testing with AMA

On a test deployment with AD trust and AMA configured:

#### Generic AMA Testing

```bash
# Step 1: Identify AMA group SID in Active Directory
# (Run on AD DC as Domain Admin)
Get-ADGroup "High Assurance Users" | Select-Object Name,SID

# Step 2: Configure SID mapping in FreeIPA
# Use the SID from step 1
ipa trust-mod ad.example.com \
  --indicator-map="S-1-5-21-123456789-987654321-111111111-1234:qualified-cert:true"

# Step 3: Authenticate from Windows with smartcard
# On Windows client with smartcard reader
kinit testuser@AD.EXAMPLE.COM
# (This will prompt for smartcard PIN)

# Step 4: Request service ticket and verify on IPA KDC
# On IPA client, get service ticket to trigger cross-realm processing
kvno host/ipaclient.ipa.example.com@IPA.EXAMPLE.COM

# On IPA KDC, examine the PAC and indicators
/usr/libexec/ipa/ipa-print-pac ticket testuser@AD.EXAMPLE.COM

# Or check KDC logs for indicator mapping
# tail -f /var/log/krb5kdc.log | grep -i "indicator"

# Step 5: Verify with password authentication (negative test)
kdestroy -A
kinit testuser@AD.EXAMPLE.COM
# (This will prompt for password, not smartcard)

# Get service ticket
kvno host/ipaclient.ipa.example.com@IPA.EXAMPLE.COM

# Verify AMA indicator is NOT present by examining PAC
/usr/libexec/ipa/ipa-print-pac ticket testuser@AD.EXAMPLE.COM
# qualified-cert indicator should NOT appear in the PAC

# Step 6: View the PAC to confirm SID presence/absence
# On IPA KDC as root
/usr/libexec/ipa/ipa-print-pac ticket testuser@AD.EXAMPLE.COM

# In the PAC output, check for the AMA group SID:
# - With smartcard auth: SID should appear in extra_sids or resource_groups
# - With password auth: SID should NOT appear
```

#### Federal PKI / DoD CAC Testing

For environments using Federal PKI or DoD CAC cards:

```bash
# === STEP 1: Configure AMA in Active Directory ===
# (Run on AD DC as Domain Admin)

# Configure Federal PKI AMA groups and OID mappings
.\Configure-FPKI-AMA.ps1 -GroupOU "OU=AMA Groups,DC=agency,DC=gov"

# Verify AMA configuration
Get-ADGroup "id-fpki-common-High" | Select-Object Name,SID
Get-ADGroup "id-fpki-common-authentication" | Select-Object Name,SID

# Check OID mappings
$configNC = (Get-ADRootDSE).configurationNamingContext
Get-ADObject -SearchBase "CN=OID,CN=Public Key Services,CN=Services,$configNC" `
             -Filter {Name -eq "2.16.840.1.101.3.2.1.3.16"} `
             -Properties msDS-OIDToGroupLink |
    Select-Object Name, msDS-OIDToGroupLink

# === STEP 2: Configure FreeIPA SID Mappings ===
# (Run on IPA server as admin)

# Establish trust if not already done
ipa trust-add agency.gov --type=ad --admin Administrator

# Configure mappings for Federal PKI assurance levels
ipa trust-mod agency.gov \
  --indicator-map="id-fpki-common-High:fpki-high:true" \
  --indicator-map="id-fpki-common-authentication:fpki-auth:true"

# Verify configuration
ipa trust-show agency.gov --all | grep -A10 "SID to Indicator"

# === STEP 3: Test with CAC/PIV Card ===
# (On Windows client with CAC reader)

# Examine certificate OIDs (before authentication)
# Insert CAC into reader, export cert, then:
certutil -dump auth_cert.cer | findstr "2.16.840.1.101.3.2"

# Expected output shows Federal PKI OIDs like:
#   2.16.840.1.101.3.2.1.3.13 (authentication)
#   2.16.840.1.101.3.2.1.3.16 (high assurance)

# Authenticate with CAC
kinit testuser@AGENCY.GOV
# (This will prompt for CAC PIN)

# Get service ticket from IPA to trigger cross-realm
kvno host/ipaclient.agency.gov@IPA.AGENCY.GOV

# === STEP 4: Verify Indicators on IPA KDC ===
# (On IPA KDC as root)

# Examine the PAC to verify indicators
/usr/libexec/ipa/ipa-print-pac ticket testuser@AGENCY.GOV

# Check KDC logs for indicator mapping
tail -f /var/log/krb5kdc.log | grep -i "indicator\|fpki-high"

# === STEP 5: Examine PAC Contents ===
# (On IPA KDC as root)

# Extract and display PAC
/usr/libexec/ipa/ipa-print-pac ticket testuser@AGENCY.GOV > /tmp/pac_output.txt

# Search for Federal PKI AMA group SID
grep -i "S-1-5-21" /tmp/pac_output.txt | grep -A2 -B2 "id-fpki"

# Check extra_sids section (where AMA groups appear)
grep -A50 "extra_sids" /tmp/pac_output.txt

# === STEP 6: Negative Test - Password Authentication ===
# (On Windows client)

kdestroy -A
kinit testuser@AGENCY.GOV
# (Enter password, not CAC PIN)

# Get service ticket
kvno host/ipaclient.agency.gov@IPA.AGENCY.GOV

# Verify on IPA KDC (should NOT have fpki-high indicator)
/usr/libexec/ipa/ipa-print-pac ticket testuser@AGENCY.GOV | grep extra_sids
# Should NOT contain Federal PKI AMA group SID

# === STEP 7: Test HBAC Enforcement ===
# (On IPA server)

# Create test HBAC rule requiring high assurance
ipa hbacrule-add test_fpki_high
ipa hbacrule-add-host test_fpki_high --hosts=testhost.ipa.agency.gov
ipa hbacrule-add-service test_fpki_high --hbacsvcs=sshd
ipa hbacrule-add-user test_fpki_high --users=testuser@agency.gov
ipa hbacrule-mod test_fpki_high --authindicator=fpki-high

# Test SSH access with CAC authentication (should succeed)
# (On IPA client after CAC kinit and obtaining service ticket)
ssh testuser@agency.gov@testhost.ipa.agency.gov
# Expected: Access granted (HBAC allows due to fpki-high indicator presence)

# Test SSH access with password authentication (should fail)
# (On IPA client after password kinit and obtaining service ticket)
ssh testuser@agency.gov@testhost.ipa.agency.gov
# Expected: Access denied (HBAC blocks due to missing fpki-high indicator)

# Check logs for HBAC decision
# On IPA client:
journalctl -u sssd -n 50 | grep -i "indicator\|hbac"
```

#### Verification Checklist

Use this checklist to verify Federal PKI AMA integration:

- [ ] Active Directory AMA groups created (universal security groups)
- [ ] Federal PKI OIDs registered in AD Configuration
- [ ] OID-to-group mappings configured via msDS-OIDToGroupLink
- [ ] FreeIPA trust established with AD
- [ ] SID to indicator mappings configured in FreeIPA
- [ ] CAC/PIV certificate contains expected Federal PKI policy OIDs
- [ ] CAC authentication adds AMA group SID to PAC
- [ ] FreeIPA KDC maps SID to authentication indicator
- [ ] Authentication indicator verified via PAC inspection on KDC
- [ ] Password authentication does NOT include AMA indicator
- [ ] HBAC rules enforce indicator requirements correctly
- [ ] SSH access granted/denied based on authentication method

### Debugging AMA integration

To verify AMA is working correctly in the full authentication flow:

```bash
# 1. Authenticate from AD with smartcard
# (on Windows or AD-joined system)
kinit testuser@AD.EXAMPLE.COM

# 2. Request service ticket from IPA KDC
# (forces cross-realm ticket processing)
kvno host/ipaclient.ipa.example.com@IPA.EXAMPLE.COM

# 3. Check KDC logs for PAC processing and indicator mapping
# On IPA KDC
tail -f /var/log/krb5kdc.log | grep -i "indicator\|pac\|sid"

# Look for messages about:
# - PAC verification
# - SID extraction from LOGON_INFO
# - Indicator mapping application
# - Final authentication indicators in issued ticket
```

## Troubleshooting and Debugging

### Verify mappings are configured

```bash
ipa trust-show ad.example.com --all | grep -A5 "SID to Indicator map"
```

### Check LDAP directly

```bash
ldapsearch -Y GSSAPI -b "cn=ad.example.com,cn=ad,cn=trusts,dc=ipa,dc=test" \
  ipaSIDIndicatorMap
```

Expected format: `S-1-5-21-...:indicator:true|false`

### Common issues

**Mapping not applied to tickets:**
- Verify user is actually member of the mapped AD group
- Check that the SID in LDAP matches the group SID in the user's PAC
- Ensure KDC has reloaded trust information (may take up to trust refresh interval)

**Cannot add mapping:**
- Verify you are member of "trust admins" group
- Check that the group name can be resolved to a SID
- Verify network connectivity to AD domain controllers

**Validation error when adding mapping:**
- Ensure group name is spelled correctly and exists in AD
- If using explicit SID, verify SID format is correct
- Check that smartcard flag is either "true" or "false" if provided
- Verify that smartcard=true is only used with indicator "pkinit"

**AMA-specific issues:**

**Indicator not added for smartcard authentication:**
- Verify AMA is properly configured in Active Directory
  - Check certificate trust settings: `certutil -TCAInfo` on AD DC
  - Verify OID-to-group mappings in AD Certificate Trust configuration
  - Confirm the certificate contains the expected Issuance Policy OIDs
- Use Windows Event Viewer on AD DC to check authentication events
  - Look for Event ID 4768 (TGT Request) with certificate information
  - Verify AMA group SIDs are being added to the PAC
- Examine the certificate's Enhanced Key Usage extension:
  ```bash
  openssl x509 -in certificate.pem -text -noout | grep -A5 "Extended Key Usage"
  ```
- Verify the Certificate Policy OIDs in the certificate:
  ```bash
  openssl x509 -in certificate.pem -text -noout | grep -A10 "Certificate Policies"
  ```

  For Federal PKI / DoD CAC certificates, look for OIDs starting with `2.16.840.1.101.3.2.1.3`:
  ```bash
  # Extract CAC certificate from smartcard
  pkcs15-tool --read-certificate 01 > cac_cert.pem

  # Or on Windows
  certutil -scinfo
  certutil -dump -v cert.cer | findstr "2.16.840.1.101.3.2"

  # Examine certificate policies
  openssl x509 -in cac_cert.pem -text -noout | grep -A20 "Certificate Policies"

  # Expected output for DoD CAC:
  #   Policy: 2.16.840.1.101.3.2.1.3.13
  #   Policy: 2.16.840.1.101.3.2.1.3.16  (for high-assurance CACs)
  ```
- Confirm the AMA group SID is correct in the FreeIPA mapping:
  ```bash
  ipa trust-show ad.example.com --all | grep ipaSIDIndicatorMap
  ```

**AMA group SID appears with password authentication:**
- This should NOT happen - AMA groups are only for certificate authentication
- Check if the group is actually a permanent AD group, not an AMA-only group
- Verify the group's settings in AD (should be configured for AMA, not regular membership)
- Review AD's Certificate Trust configuration to ensure proper OID mappings

**Unable to find AMA group SID:**
- AMA groups may not be enumerable via standard LDAP queries
- Use PowerShell on AD DC to find the SID:
  ```powershell
  Get-ADGroup -Filter {Name -like "*Assurance*"} | Select-Object Name,SID
  Get-ADGroup -Filter {Name -like "*Certificate*"} | Select-Object Name,SID
  ```
- Capture and decode a PAC from a successful smartcard authentication:
  ```bash
  # On IPA KDC
  /usr/libexec/ipa/ipa-print-pac ticket testuser@AD.EXAMPLE.COM | grep -A100 "extra_sids"
  ```
- Use Microsoft's PAC analysis tools on Windows:
  ```cmd
  klist tickets
  klist query_bind
  ```

**Different indicators for same user with different certificates:**
- This is expected behavior when using AMA with multiple assurance levels
- Different certificates may contain different Issuance Policy OIDs
- AD will assign different AMA groups based on the certificate used
- Ensure you have mappings configured for all relevant AMA groups if you want
  consistent indicators across certificates

**Federal PKI / DoD CAC specific issues:**

**CAC not triggering AMA group assignment:**
- Verify Federal Bridge CA is trusted in AD:
  ```powershell
  certutil -viewstore -enterprise NTAuth
  certutil -viewstore -enterprise Root
  ```
- Check if DoD root CAs are published:
  ```powershell
  # DoD Root CA 3, DoD Root CA 4, DoD Root CA 5 should be present
  certutil -viewstore -enterprise Root | findstr "DoD Root"
  ```
- Verify Federal PKI OID registration:
  ```powershell
  $configNC = (Get-ADRootDSE).configurationNamingContext
  Get-ADObject -SearchBase "CN=OID,CN=Public Key Services,CN=Services,$configNC" `
               -Filter {Name -like "2.16.840.1.101.3.2*"}
  ```

**CAC certificate doesn't contain expected OIDs:**
- Different CAC types have different policy OIDs
- Check certificate issuance date - older CACs may use different OID sets
- PIV-I cards use different OIDs than standard DoD CACs
- Derived credentials have their own OID set (2.16.840.1.101.3.2.1.3.40, .41)

**Federal PKI OID Quick Reference:**

| Certificate Type | Common OIDs | AMA Group Suggestion |
|------------------|-------------|----------------------|
| DoD CAC (Standard) | 2.16.840.1.101.3.2.1.3.13, .16 | id-fpki-common-High |
| DoD CAC (PIV-I) | 2.16.840.1.101.3.2.1.3.18 | id-fpki-certpcy-pivi-hardware |
| Derived PIV | 2.16.840.1.101.3.2.1.3.40, .41 | id-fpki-common-pivAuth-derived-hardware |
| Federal Agency PIV | 2.16.840.1.101.3.2.1.3.7, .13, .16 | id-fpki-common-hardware |

**Testing Federal PKI integration:**
```bash
# Quick test script for Federal PKI AMA
#!/bin/bash

echo "Federal PKI AMA Integration Test"
echo "================================="

# Check if certificate contains Federal PKI OIDs
echo -n "Checking certificate for FPKI OIDs... "
if openssl x509 -in cert.pem -text -noout | grep -q "2.16.840.1.101.3.2.1.3"; then
    echo "FOUND"
    openssl x509 -in cert.pem -text -noout | grep "2.16.840.1.101.3.2.1.3"
else
    echo "NOT FOUND - certificate may not be FPKI-compliant"
fi

# Check FreeIPA configuration
echo -n "Checking FreeIPA FPKI indicator mappings... "
ipa trust-show agency.gov --all 2>/dev/null | grep -q "2.16.840.1.101.3.2.1.3"
if [ $? -eq 0 ]; then
    echo "CONFIGURED"
else
    echo "NOT CONFIGURED - run ipa trust-mod to add FPKI mappings"
fi

# Test authentication
echo "Testing CAC authentication..."
kdestroy -A
echo "Insert CAC and enter PIN when prompted"
kinit testuser@AGENCY.GOV

if [ $? -eq 0 ]; then
    echo "Authentication successful"
    echo "Request service ticket to trigger cross-realm processing:"
    kvno host/ipaclient.ipa.agency.gov@IPA.AGENCY.GOV
    echo
    echo "To verify FPKI indicators, run on IPA KDC:"
    echo "/usr/libexec/ipa/ipa-print-pac ticket testuser@AGENCY.GOV"
else
    echo "Authentication failed"
fi
```

### Verification script

```bash
#!/bin/bash
# Verify SID indicator mapping configuration

TRUST_DOMAIN="ad.example.com"
TEST_USER="domainadmin@AD.EXAMPLE.COM"

echo "=== Checking trust configuration ==="
ipa trust-show "$TRUST_DOMAIN" --all | grep -A10 "SID to Indicator"

echo "=== Testing authentication ==="
kdestroy -A
kinit "$TEST_USER"

# Request service ticket to trigger cross-realm processing
kvno host/ipaclient.ipa.example.com@IPA.EXAMPLE.COM

echo "=== Checking indicators on KDC ==="
echo "Run on IPA KDC:"
echo "/usr/libexec/ipa/ipa-print-pac ticket $TEST_USER"

echo "=== Done ==="
```

### AMA verification script

#### Generic AMA Verification

```bash
#!/bin/bash
# Verify AMA integration with SID indicator mapping

TRUST_DOMAIN="ad.example.com"
TEST_USER="testuser@AD.EXAMPLE.COM"
AMA_GROUP_SID="S-1-5-21-123456789-987654321-111111111-1234"
EXPECTED_INDICATOR="qualified-cert"

echo "=== AMA SID to Indicator Mapping Verification ==="
echo

echo "Step 1: Checking FreeIPA configuration"
echo "---------------------------------------"
ipa trust-show "$TRUST_DOMAIN" --all | grep -A20 "SID to Indicator" | grep "$AMA_GROUP_SID"
if [ $? -eq 0 ]; then
    echo "✓ AMA group SID mapping found in configuration"
else
    echo "✗ AMA group SID mapping NOT found"
    echo "  Run: ipa trust-mod $TRUST_DOMAIN --indicator-map=\"$AMA_GROUP_SID:$EXPECTED_INDICATOR:true\""
    exit 1
fi
echo

echo "Step 2: Testing smartcard authentication"
echo "-----------------------------------------"
echo "Authenticating with smartcard (you will be prompted for PIN)..."
kdestroy -A
kinit "$TEST_USER"

if [ $? -ne 0 ]; then
    echo "✗ Authentication failed"
    exit 1
fi
echo "✓ Authentication successful"
echo

echo "Step 3: Requesting service ticket"
echo "-----------------------------------"
echo "Requesting service ticket to trigger cross-realm processing..."
kvno host/ipaclient.ipa.example.com@IPA.EXAMPLE.COM
if [ $? -eq 0 ]; then
    echo "✓ Service ticket obtained"
else
    echo "✗ Failed to obtain service ticket"
    echo "  Check network connectivity and service principal"
fi
echo

echo "Step 4: Examining PAC contents"
echo "-------------------------------"
echo "Extracting PAC from ticket..."
/usr/libexec/ipa/ipa-print-pac ticket "$TEST_USER" > /tmp/pac_output.txt 2>&1
if grep -q "$AMA_GROUP_SID" /tmp/pac_output.txt; then
    echo "✓ AMA group SID found in PAC"
    grep -A2 -B2 "$AMA_GROUP_SID" /tmp/pac_output.txt
else
    echo "✗ AMA group SID NOT found in PAC"
    echo "  This indicates AMA group was not assigned by AD during authentication"
    echo "  Check AD's Certificate Trust configuration and certificate OIDs"
fi
echo

echo "Step 5: Negative test - password authentication"
echo "------------------------------------------------"
echo "Authenticating with password (should NOT include AMA indicator)..."
kdestroy -A
echo "Enter password when prompted:"
kinit "$TEST_USER"

if [ $? -ne 0 ]; then
    echo "✗ Password authentication failed"
else
    echo "✓ Password authentication successful"
    echo
    echo "Requesting service ticket..."
    kvno host/ipaclient.ipa.example.com@IPA.EXAMPLE.COM
    echo
    echo "Checking PAC on IPA KDC (should NOT include AMA group SID)..."
    echo "Run on IPA KDC:"
    echo "/usr/libexec/ipa/ipa-print-pac ticket $TEST_USER | grep $AMA_GROUP_SID"
    echo
    echo "If the SID appears, the group may be a permanent membership, not AMA-only"
fi
echo

echo "=== Verification Complete ==="
echo "Summary:"
echo "- Configuration: Check Step 1 result"
echo "- Smartcard auth with indicator: Check Step 3 result"
echo "- PAC contains AMA SID: Check Step 4 result"
echo "- Password auth without indicator: Check Step 5 result"
```

#### Federal PKI / CAC Verification Script

```bash
#!/bin/bash
# Verify Federal PKI AMA integration with FreeIPA
# For use with DoD CAC or Federal Agency PIV cards

TRUST_DOMAIN="agency.gov"
TEST_USER="testuser@AGENCY.GOV"
IPA_REALM="IPA.AGENCY.GOV"

# Federal PKI OIDs to check
FPKI_HIGH_OID="2.16.840.1.101.3.2.1.3.16"
FPKI_AUTH_OID="2.16.840.1.101.3.2.1.3.13"
FPKI_HARDWARE_OID="2.16.840.1.101.3.2.1.3.7"

# Expected indicators
EXPECTED_INDICATORS=("fpki-high" "fpki-auth" "fpki-hardware")

echo "========================================"
echo "Federal PKI AMA Verification Script"
echo "========================================"
echo

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
echo "Step 0: Checking prerequisites"
echo "-------------------------------"
MISSING_TOOLS=()
for tool in ipa klist kinit pkcs15-tool openssl; do
    if ! command_exists "$tool"; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    echo "✗ Missing required tools: ${MISSING_TOOLS[*]}"
    echo "  Install required packages and try again"
    exit 1
fi
echo "✓ All required tools present"
echo

# Step 1: Check CAC certificate for Federal PKI OIDs
echo "Step 1: Examining CAC certificate"
echo "----------------------------------"
echo "Insert your CAC card and press Enter..."
read

# Try to extract certificate from CAC
if pkcs15-tool --list-certificates >/dev/null 2>&1; then
    echo "Reading certificate from CAC..."
    pkcs15-tool --read-certificate 01 > /tmp/cac_cert.pem 2>/dev/null

    if [ -f /tmp/cac_cert.pem ]; then
        echo "✓ Certificate extracted from CAC"
        echo
        echo "Checking for Federal PKI policy OIDs:"

        FOUND_OIDS=()
        for oid in $FPKI_HIGH_OID $FPKI_AUTH_OID $FPKI_HARDWARE_OID; do
            if openssl x509 -in /tmp/cac_cert.pem -text -noout | grep -q "$oid"; then
                echo "  ✓ Found OID: $oid"
                FOUND_OIDS+=("$oid")
            fi
        done

        if [ ${#FOUND_OIDS[@]} -eq 0 ]; then
            echo "  ✗ No Federal PKI OIDs found in certificate"
            echo "    This may not be a Federal PKI-compliant certificate"
        fi

        rm -f /tmp/cac_cert.pem
    fi
else
    echo "⚠ Could not read CAC certificate automatically"
    echo "  You may need to check certificate OIDs manually"
fi
echo

# Step 2: Check FreeIPA configuration
echo "Step 2: Verifying FreeIPA configuration"
echo "----------------------------------------"

# Check if trust exists
if ! ipa trust-show "$TRUST_DOMAIN" >/dev/null 2>&1; then
    echo "✗ Trust with $TRUST_DOMAIN not found"
    echo "  Run: ipa trust-add $TRUST_DOMAIN --type=ad"
    exit 1
fi
echo "✓ Trust with $TRUST_DOMAIN exists"

# Check for Federal PKI indicator mappings
echo "Checking for Federal PKI indicator mappings:"
MAPPINGS=$(ipa trust-show "$TRUST_DOMAIN" --all 2>/dev/null | grep "SID to Indicator map")

if echo "$MAPPINGS" | grep -q "fpki"; then
    echo "✓ Federal PKI indicator mappings found:"
    echo "$MAPPINGS" | grep fpki
else
    echo "✗ No Federal PKI indicator mappings found"
    echo "  Configure with: ipa trust-mod $TRUST_DOMAIN --indicator-map=..."
    exit 1
fi
echo

# Step 3: Test CAC authentication
echo "Step 3: Testing CAC authentication"
echo "-----------------------------------"
kdestroy -A 2>/dev/null

echo "Authenticating with CAC (you will be prompted for PIN)..."
if kinit "$TEST_USER"; then
    echo "✓ CAC authentication successful"
else
    echo "✗ CAC authentication failed"
    echo "  Check CAC reader, certificate, and AD connectivity"
    exit 1
fi
echo

# Get service ticket to trigger cross-realm
echo "Requesting service ticket (triggers cross-realm processing)..."
TEST_HOST="host/ipaclient.$IPA_REALM"
if kvno "$TEST_HOST" >/dev/null 2>&1; then
    echo "✓ Service ticket obtained"
else
    echo "⚠ Could not obtain service ticket"
    echo "  Some tests may not work correctly"
fi
echo

# Step 4: Verify authentication indicators via PAC
echo "Step 4: Examining PAC for indicators"
echo "-------------------------------------"
echo "Authentication indicators must be checked on the IPA KDC."
echo
echo "Run this command on the IPA KDC as root:"
echo "  /usr/libexec/ipa/ipa-print-pac ticket $TEST_USER"
echo
echo "Look for:"
for indicator in "${EXPECTED_INDICATORS[@]}"; do
    echo "  - Indicator: $indicator"
done
echo
echo "Press Enter after checking on KDC..."
read
echo

# Step 5: Examine PAC for Federal PKI AMA group SIDs
echo "Step 5: Examining PAC contents"
echo "-------------------------------"
echo "Extracting PAC (requires root access on KDC)..."
echo "Run this on the IPA KDC:"
echo "  /usr/libexec/ipa/ipa-print-pac ticket $TEST_USER"
echo
echo "Look for AMA group SIDs in the 'extra_sids' or 'resource_groups' sections"
echo "Federal PKI AMA group SIDs should be visible if OID mapping worked"
echo

# Step 6: Negative test - password authentication
echo "Step 6: Negative test - password authentication"
echo "------------------------------------------------"
read -p "Test password authentication (will clear CAC ticket)? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    kdestroy -A 2>/dev/null
    echo "Authenticating with password (NOT CAC)..."
    echo "Enter password when prompted:"

    if kinit "$TEST_USER"; then
        echo "✓ Password authentication successful"

        # Get service ticket
        if kvno "$TEST_HOST" >/dev/null 2>&1; then
            echo "✓ Service ticket obtained"
        fi
        echo

        # Check PAC on KDC
        echo "Verify on IPA KDC that Federal PKI indicators are NOT present:"
        echo "  /usr/libexec/ipa/ipa-print-pac ticket $TEST_USER"
        echo
        echo "Expected result:"
        for indicator in "${EXPECTED_INDICATORS[@]}"; do
            echo "  - Indicator '$indicator' should NOT be present"
        done
        echo
        echo "If any Federal PKI indicators appear, the groups may be permanent"
        echo "memberships rather than AMA-only groups."
    else
        echo "✗ Password authentication failed"
    fi
else
    echo "Skipping negative test"
fi
echo

# Summary
echo "========================================"
echo "Verification Summary"
echo "========================================"
echo
echo "✓ = Test passed"
echo "✗ = Test failed"
echo "⚠ = Warning or manual check required"
echo
echo "For complete verification:"
echo "1. Ensure all ✓ checks passed"
echo "2. Review PAC contents on KDC"
echo "3. Test HBAC rule enforcement with Federal PKI indicators"
echo "4. Verify CAC authentication includes indicators, password auth does not"
echo
echo "Federal PKI AMA Resources:"
echo "- DoD PKI: https://public.cyber.mil/pki-pke/"
echo "- FPKI: https://www.idmanagement.gov/fpki/"
echo "- GSA FICAM: https://github.com/GSA/ficam-scripts-public"
```

These scripts provide quick ways to verify the end-to-end functionality of SID
to indicator mapping, including full AMA integration testing with both generic
and Federal PKI-specific configurations.

## References and Related Documentation

### Active Directory Authentication Mechanism Assurance

**Microsoft Documentation:**
- [Authentication Mechanism Assurance for AD DS in Windows Server 2008 R2 Step-by-Step Guide](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd378897(v=ws.10))
- [Configuring Authentication Policies and Authentication Policy Silos](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos)
- [How to configure Security for PKI Health Certificates](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/configure-security-pki-health-certificates)

**Technical Details:**
- AMA was introduced in Windows Server 2008 R2
- Enhanced with Authentication Policies in Windows Server 2012 R2
- Certificate Policies extension (OID 2.5.29.32) is examined for Issuance Policy OIDs
- Group memberships are added to the PAC's ExtraSids or ResourceGroups section
- AMA groups can be Universal, Global, or Domain Local security groups

**Configuration Steps in AD:**
1. Open "Certificate Authority" management console (certsrv.msc)
2. Navigate to "Certificate Templates"
3. Configure Issuance Policies in certificate templates
4. In Active Directory Users and Computers, create security groups for each assurance level
5. Use Enterprise PKI (pkiview.msc) to configure OID-to-group mappings
6. Enable certificate trust for the appropriate CAs

### Kerberos Authentication Indicators

**RFC References:**
- [RFC 8129: Authentication Indicator in Kerberos Tickets](https://www.rfc-editor.org/rfc/rfc8129.html)
- Defines the standard for including authentication method indicators in Kerberos tickets
- Specifies common indicator values like "pkinit" for certificate-based authentication

**MIT Kerberos Documentation:**
- [Authentication Indicators](https://web.mit.edu/kerberos/krb5-latest/doc/admin/auth_indicators.html)
- Documentation on how to configure and use authentication indicators
- Examples of service-side enforcement

### MS-PKCA Protocol

**Microsoft Technical Documentation:**
- [MS-PKCA: Public Key Cryptography for Initial Authentication (PKCA) in Kerberos Protocol Extension](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pkca/)
- Section 3.1.5.2: Specifies requirements for authentication indicator propagation
- Defines how smartcard authentication should be reflected in indicators

### FreeIPA Trust Documentation

**Related FreeIPA Features:**
- [Trusts Design](https://freeipa.readthedocs.io/en/latest/designs/trusts.html)
- [SID Configuration](sidconfig.md) - Prerequisite for PAC generation
- [One-way Trust with Shared Secret](oneway-trust-with-shared-secret.md)
- [HBAC with authentication indicators](https://freeipa.readthedocs.io/en/latest/designs/hbac-with-auth-indicators.html)

### Certificate and PKI Resources

**OID Information:**
- [OID Repository](http://www.oid-info.com/)
- Microsoft's OID namespace: 1.3.6.1.4.1.311
- Common Microsoft assurance OIDs:
  - 1.3.6.1.4.1.311.21.8 (Low Assurance)
  - 1.3.6.1.4.1.311.21.9 (Medium Assurance)
  - 1.3.6.1.4.1.311.21.10 (High Assurance)

**Certificate Policy Extension:**
- [RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280.html)
- Section 4.2.1.4: Certificate Policies extension
- Defines structure for Issuance Policy OIDs in certificates

### Federal PKI and DoD PKI Resources

**Federal PKI (FPKI) Documentation:**
- [Federal PKI (FPKI) Homepage](https://www.idmanagement.gov/fpki/)
- [FPKI Certificate Policy Framework](https://www.idmanagement.gov/ficam/)
- Federal PKI OID namespace: 2.16.840.1.101.3.2.1.3.x

**DoD PKI Resources:**
- [DoD PKI Interoperability Assurance Levels](https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/txt/unclass-pki_interop_assurance_levels.txt)
- [DoD Cyber Exchange PKI/PKE](https://public.cyber.mil/pki-pke/)
- DoD certificate policies and profiles

**GSA FICAM AMA Configuration:**
- [GSA FICAM Scripts Repository](https://github.com/GSA/ficam-scripts-public)
- [AMA Configuration Script](https://github.com/GSA/ficam-scripts-public/blob/master/_ama/CertificateIssuanceOIDs.ps1.txt)
- Reference implementation for Federal PKI AMA configuration in Active Directory

**Federal PKI Assurance Level OIDs:**

| OID | Policy Name | Description |
|-----|-------------|-------------|
| 2.16.840.1.101.3.2.1.3.4 | id-fpki-certpcy-highAssurance | High assurance certificate policy |
| 2.16.840.1.101.3.2.1.3.7 | id-fpki-common-hardware | Hardware-protected key material |
| 2.16.840.1.101.3.2.1.3.12 | id-fpki-certpcy-mediumHardware | Medium assurance with hardware |
| 2.16.840.1.101.3.2.1.3.13 | id-fpki-common-authentication | Common authentication policy |
| 2.16.840.1.101.3.2.1.3.16 | id-fpki-common-High | High assurance common policy |
| 2.16.840.1.101.3.2.1.3.18 | id-fpki-certpcy-pivi-hardware | PIV-Interoperable hardware |
| 2.16.840.1.101.3.2.1.3.36 | id-fpki-common-devicesHardware | Device hardware authentication |
| 2.16.840.1.101.3.2.1.3.40 | id-fpki-common-derived-pivAuth | PIV authentication derived |
| 2.16.840.1.101.3.2.1.3.41 | id-fpki-common-pivAuth-derived-hardware | PIV-derived hardware |

**Common Access Card (CAC) Certificates:**
- DoD CAC certificates typically contain Federal PKI OIDs
- CAC authentication certificates commonly include:
  - 2.16.840.1.101.3.2.1.3.13 (id-fpki-common-authentication)
  - 2.16.840.1.101.3.2.1.3.16 (id-fpki-common-High) for high-assurance CACs
  - 2.16.840.1.101.3.2.1.3.18 (id-fpki-certpcy-pivi-hardware) for PIV-I cards
- These OIDs enable AMA-based access control in DoD and Federal environments

### Example AMA Deployment Scenario

#### Scenario 1: Federal Government Agency Deployment

A federal agency using Federal PKI and deploying FreeIPA for Linux infrastructure:

**Active Directory Configuration:**

1. **CA Configuration**: Federal Bridge CA or agency-specific CA issues certificates
   with Federal PKI policy OIDs:
   - Authentication: `2.16.840.1.101.3.2.1.3.13` (id-fpki-common-authentication)
   - Hardware: `2.16.840.1.101.3.2.1.3.7` (id-fpki-common-hardware)
   - High Assurance: `2.16.840.1.101.3.2.1.3.16` (id-fpki-common-High)
   - PIV-Derived: `2.16.840.1.101.3.2.1.3.41` (id-fpki-common-pivAuth-derived-hardware)

2. **AMA Group Setup** (executed on AD DC):
   ```powershell
   # Create AMA groups
   New-ADGroup -Name "id-fpki-common-authentication" -GroupScope Universal -GroupCategory Security
   New-ADGroup -Name "id-fpki-common-hardware" -GroupScope Universal -GroupCategory Security
   New-ADGroup -Name "id-fpki-common-High" -GroupScope Universal -GroupCategory Security
   New-ADGroup -Name "id-fpki-common-pivAuth-derived-hardware" -GroupScope Universal -GroupCategory Security

   # Configure OID mappings
   certutil -dsaddtemplate "2.16.840.1.101.3.2.1.3.13" "id-fpki-common-authentication"
   certutil -dsaddtemplate "2.16.840.1.101.3.2.1.3.7" "id-fpki-common-hardware"
   certutil -dsaddtemplate "2.16.840.1.101.3.2.1.3.16" "id-fpki-common-High"
   certutil -dsaddtemplate "2.16.840.1.101.3.2.1.3.41" "id-fpki-common-pivAuth-derived-hardware"

   # Link OIDs to groups (see full script in AMA Configuration section)
   ```

3. **Certificate Issuance**: Users receive PIV cards or smartcards with certificates
   containing appropriate policy OIDs

4. **Authentication Flow**: When users authenticate with smartcards, AD DCs
   automatically assign AMA group memberships based on certificate policy OIDs

**FreeIPA Configuration:**

1. **Trust Establishment**:
   ```bash
   ipa trust-add agency.gov --type=ad --admin Administrator
   ```

2. **Discover AMA Group SIDs** (on AD DC):
   ```powershell
   Get-ADGroup "id-fpki-common-authentication" | Select-Object Name,SID
   Get-ADGroup "id-fpki-common-hardware" | Select-Object Name,SID
   Get-ADGroup "id-fpki-common-High" | Select-Object Name,SID
   Get-ADGroup "id-fpki-common-pivAuth-derived-hardware" | Select-Object Name,SID
   ```

3. **Configure SID to Indicator Mappings**:
   ```bash
   # Map Federal PKI assurance levels to indicators
   ipa trust-mod agency.gov \
     --indicator-map="id-fpki-common-authentication:fpki-auth" \
     --indicator-map="id-fpki-common-hardware:fpki-hardware:true" \
     --indicator-map="id-fpki-common-High:fpki-high:true" \
     --indicator-map="id-fpki-common-pivAuth-derived-hardware:fpki-piv-derived:true"
   ```

4. **Enforce Access Policies**:
   ```bash
   # HBAC rule for standard systems - accepts basic authentication
   ipa hbacrule-add standard_systems
   ipa hbacrule-add-host standard_systems --hosts=webserver.agency.gov
   ipa hbacrule-add-service standard_systems --hbacsvcs=sshd
   # No indicator requirement - all authenticated users allowed

   # HBAC rule for sensitive systems - requires hardware-backed authentication
   ipa hbacrule-add sensitive_systems
   ipa hbacrule-add-host sensitive_systems --hosts=database.agency.gov
   ipa hbacrule-add-service sensitive_systems --hbacsvcs=sshd
   ipa hbacrule-mod sensitive_systems --authindicator=fpki-hardware
   ipa hbacrule-mod sensitive_systems --authindicator=fpki-high

   # HBAC rule for classified systems - requires high assurance only
   ipa hbacrule-add classified_systems
   ipa hbacrule-add-host classified_systems --hosts=scif-system.agency.gov
   ipa hbacrule-add-service classified_systems --hbacsvcs=sshd
   ipa hbacrule-mod classified_systems --authindicator=fpki-high
   ```

**Access Control Enforcement:**

- **Standard systems**: Users with any Federal PKI certificate can access
- **Sensitive systems**: Only users who authenticated with hardware-backed certificates
  (fpki-hardware or fpki-high indicators) can access
- **Classified systems**: Only users with high-assurance certificates (fpki-high indicator)
  can access

**User Experience:**

1. User authenticates to AD with PIV card containing high-assurance certificate
2. AD DC validates certificate, extracts OID `2.16.840.1.101.3.2.1.3.16`
3. AD DC adds SID of "id-fpki-common-High" group to PAC
4. User requests access to FreeIPA-enrolled Linux system
5. FreeIPA KDC processes cross-realm ticket, extracts SID, maps to "fpki-high" indicator
6. HBAC evaluation checks indicator requirement matches "fpki-high"
7. Access granted or denied based on indicator presence

#### Scenario 2: DoD Environment with CAC Authentication

Department of Defense deployment using Common Access Cards:

**Active Directory (DoD Domain):**
- CAC certificates contain OIDs: 2.16.840.1.101.3.2.1.3.13, 2.16.840.1.101.3.2.1.3.16
- AMA groups configured for CAC assurance levels
- Users authenticate with CAC readers

**FreeIPA (Mission System Network):**
```bash
# Establish trust with DoD AD
ipa trust-add dod.example.mil --type=ad --admin Administrator

# Configure CAC authentication indicator mappings
ipa trust-mod dod.example.mil \
  --indicator-map="id-fpki-common-High:cac-high:true" \
  --indicator-map="id-fpki-common-authentication:cac-auth:true"

# Create HBAC rules based on CAC assurance
ipa hbacrule-add mission_critical_systems
ipa hbacrule-add-host mission_critical_systems --hostgroup=mission_critical
ipa hbacrule-add-service mission_critical_systems --hbacsvcs=sshd
ipa hbacrule-mod mission_critical_systems --authindicator=cac-high
```

**Result**: Only DoD users who authenticate with high-assurance CACs can access
mission-critical systems, with authentication strength automatically determined
by certificate policy OIDs and enforced through FreeIPA HBAC rules.

This creates a seamless authentication assurance framework spanning both AD and
FreeIPA environments, with Federal PKI certificate-based authentication strength
governing access policies across the entire infrastructure, meeting federal compliance
requirements for authentication assurance.
