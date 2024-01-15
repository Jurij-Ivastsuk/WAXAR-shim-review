This repo is for review of requests for signing shim.  To create a request for review:

- clone this repo
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push that to github
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your tag
- approval is ready when the "accepted" label is added to your issue

Note that we really only have experience with using GRUB2 on Linux, so asking
us to endorse anything else for signing is going to require some convincing on
your part.

Check the docs directory in this repo for guidance on submission and
getting your shim signed.

Here's the template:

*******************************************************************************
### What organization or people are asking to have this signed?
*******************************************************************************
WAXAR Data Saving Systems GmbH & Co.KG

*******************************************************************************
### What product or service is this for?
*******************************************************************************
WAXAR backup solutions which utilise Linux-based operating systems. The special feature here is that the backup solutions, including the operating system, are located on a separate medium and must be started from this medium in the separate Linux environment.

*******************************************************************************
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
*******************************************************************************
Customers using WAXAR backup solutions running on third-party laptops, PCs and servers are not authorized and often cannot change the UEFI DB and add our keys. The Microsoft signed SHIM allows these products to run securely on all of these hardware platforms.

*******************************************************************************
### Why are you unable to reuse shim from another distro that is already signed?
*******************************************************************************
We change the kernel configurations to meet our hardware requirements. For example, to address as many storage devices as possible. The changes to the kernel configuration are also important to meet our security requirements. This requires signing the kernel modules with our own key.

*******************************************************************************
### Who is the primary contact for security updates, etc.?
The security contacts need to be verified before the shim can be accepted. For subsequent requests, contact verification is only necessary if the security contacts or their PGP keys have changed since the last successful verification.

An authorized reviewer will initiate contact verification by sending each security contact a PGP-encrypted email containing random words.
You will be asked to post the contents of these mails in your `shim-review` issue to prove ownership of the email addresses and PGP keys.
*******************************************************************************
- Name: Dr. Jurij Ivastsuk-Kienbaum
- Position: Chief Executive Officer
- Email address: jurij.ivastsuk@waxar.eu
- PGP key fingerprint: E334 26BD C7D6 03FE CCEC  1225 3275 C0E6 362F 0212

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

*******************************************************************************
### Who is the secondary contact for security updates, etc.?
*******************************************************************************
- Name: Lukas Lienbaum
- Position: Management assistant
- Email address: lukas.kienbaum@waxar.eu
- PGP key fingerprint: 5227 4A57 5CD3 E793 EE5A  E719 62E1 1617 ED36 701B

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

*******************************************************************************
### Were these binaries created from the 15.7 shim release tar?
Please create your shim binaries starting with the 15.7 shim release tar file: https://github.com/rhboot/shim/releases/download/15.7/shim-15.7.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.7 and contains the appropriate gnu-efi source.

*******************************************************************************
Yes, we created the shim binaries from the 15.7 shim release at https://github.com/rhboot/shim/releases/tag/15.7

*******************************************************************************
### URL for a repo that contains the exact code which was built to get this binary:
*******************************************************************************
https://github.com/Jurij-Ivastsuk/WAXAR-shim-review/tree/waxar-shim-x86_64-aarch64-20240115

*******************************************************************************
### What patches are being applied and why:
*******************************************************************************
530.patch (Enable-the-NX-compatibility-flag-by-default)
531.patch (Add-validation-function-for-Microsoft-signing)
535.patch (Make-sbat_var.S-parse-right-with-buggy-gcc-binutils)
626.patch (Improving the robustness of value retention for the variable second_stage)
According to our analysis of the error-situation and our own improvement, 
patch 626 protects against unprintable ascii characters in the variable second_stage. 
Please see our PR (https://github.com/rhboot/shim/pull/626).

*******************************************************************************
### If shim is loading GRUB2 bootloader what exact implementation of Secureboot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
*******************************************************************************
Using downstream implementations from Canonical

*******************************************************************************
### If shim is loading GRUB2 bootloader and your previously released shim booted a version of GRUB2 affected by any of the CVEs in the July 2020, the March 2021, the June 7th 2022, the November 15th 2022, or 3rd of October 2023 GRUB2 CVE list, have fixes for all these CVEs been applied?

* 2020 July - BootHole
  * Details: https://lists.gnu.org/archive/html/grub-devel/2020-07/msg00034.html
  * CVE-2020-10713
  * CVE-2020-14308
  * CVE-2020-14309
  * CVE-2020-14310
  * CVE-2020-14311
  * CVE-2020-15705
  * CVE-2020-15706
  * CVE-2020-15707
* March 2021
  * Details: https://lists.gnu.org/archive/html/grub-devel/2021-03/msg00007.html
  * CVE-2020-14372
  * CVE-2020-25632
  * CVE-2020-25647
  * CVE-2020-27749
  * CVE-2020-27779
  * CVE-2021-3418 (if you are shipping the shim_lock module)
  * CVE-2021-20225
  * CVE-2021-20233
* June 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-06/msg00035.html, SBAT increase to 2
  * CVE-2021-3695
  * CVE-2021-3696
  * CVE-2021-3697
  * CVE-2022-28733
  * CVE-2022-28734
  * CVE-2022-28735
  * CVE-2022-28736
  * CVE-2022-28737
* November 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-11/msg00059.html, SBAT increase to 3
  * CVE-2022-2601
  * CVE-2022-3775
* October 2023 - NTFS vulnerabilities
  * Details: https://lists.gnu.org/archive/html/grub-devel/2023-10/msg00028.html, SBAT increase to 4
  * CVE-2023-4693
  * CVE-2023-4692
*******************************************************************************
These CVEs are addreessed in the parent distros. We do not modify the source of the grub.

*******************************************************************************
### If these fixes have been applied, is the upstream global SBAT generation in your GRUB2 binary set to 4?
The entry should look similar to: `grub,4,Free Software Foundation,grub,GRUB_UPSTREAM_VERSION,https://www.gnu.org/software/grub/`
*******************************************************************************
Yes: grub,4,Free Software Foundation,grub,2.12~rc1,https://www.gnu.org/software/grub/

*******************************************************************************
### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
*******************************************************************************
No

*******************************************************************************
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?
*******************************************************************************
Yes

*******************************************************************************
### Do you build your signed kernel with additional local patches? What do they do?
*******************************************************************************
No

*******************************************************************************
### Do you use an ephemeral key for signing kernel modules?
### If not, please describe how you ensure that one kernel build does not load modules built for another kernel.
*******************************************************************************
We do not use an ephemeral key. We use a WAXAR HSM backed key for signing kernel modules.

*******************************************************************************
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
*******************************************************************************
We do not use vendor_db

*******************************************************************************
### If you are re-using a previously used (CA) certificate, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs to vendor_dbx in shim in order to prevent GRUB2 from being able to chainload those older GRUB2 binaries. If you are changing to a new (CA) certificate, this does not apply.
### Please describe your strategy.
*******************************************************************************
N/A

*******************************************************************************
### What OS and toolchain must we use to reproduce this build?  Include where to find it, etc.  We're going to try to reproduce your build as closely as possible to verify that it's really a build of the source tree you tell us it is, so these need to be fairly thorough. At the very least include the specific versions of gcc, binutils, and gnu-efi which were used, and where to find those binaries.
### If the shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case and what the differences would be.
*******************************************************************************
Please, first use the Dockerfile: 
docker build -t shim-15-7 . 2>&1 | tee build.log
If the build cannot be reproduced please do the following steps:
We use the Linux-OS: debian:bookworm
apt-get -y -q update
apt-get -y -q install gcc make gcc-aarch64-linux-gnu git
git clone --recursive -b 15.7 https://github.com/rhboot/shim.git shim-15.7
apply all patches from the Patches-dir
modify the sbat.csv file:
cat waxar_sbat.csv >> /shim-15.7/data/sbat.csv
cd shim-15.7
make VENDOR_CERT_FILE=../waxar.cer LIBDIR=/usr/lib
*******************************************************************************
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.
*******************************************************************************
build.log

*******************************************************************************
### What changes were made since your SHIM was last signed?
*******************************************************************************
N/A

*******************************************************************************
### What is the SHA256 hash of your final SHIM binary?
*******************************************************************************
SHA256 (shimx64.efi): 0f307475a1a1cc5d0cd2e41cfe591851521d182fa6098a4d0669e431072dd89e
SHA256 (shimaa64.efi): d8783372a31ff3557b631327ad41c48e94ec78fbccf5071cc96c6d6ba5fe5742

*******************************************************************************
### How do you manage and protect the keys used in your SHIM?
*******************************************************************************
Our keys are in a WAXAR HSM, accessible only by authorized members.

*******************************************************************************
### Do you use EV certificates as embedded certificates in the SHIM?
*******************************************************************************
No, we do not use EV certificates.

*******************************************************************************
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( GRUB2, fwupd, fwupdate, shim + all child shim binaries )?
### Please provide exact SBAT entries for all SBAT binaries you are booting or planning to boot directly through shim.
### Where your code is only slightly modified from an upstream vendor's, please also preserve their SBAT entries to simplify revocation.
If you are using a downstream implementation of GRUB2 (e.g. from Fedora or Debian), please
preserve the SBAT entry from those distributions and only append your own.
More information on how SBAT works can be found [here](https://github.com/rhboot/shim/blob/main/SBAT.md).
*******************************************************************************
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,3,UEFI shim,shim,1,https://github.com/rhboot/shim
shim.waxar,1,Waxar GmbH & Co.KG,shim,15.7,https://www.waxar.eu

We use upstreams distro from Canonical for grub since we are not rebuilding it.

*******************************************************************************
### Which modules are built into your signed GRUB2 image?
*******************************************************************************
N/A

*******************************************************************************
### What is the origin and full version number of your bootloader (GRUB2 or other)?
*******************************************************************************
Ubuntu: grub2 - Version 2.12~rc1-10ubuntu4

*******************************************************************************
### If your SHIM launches any other components, please provide further details on what is launched.
*******************************************************************************
N/A

*******************************************************************************
### If your GRUB2 launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
*******************************************************************************
N/A

*******************************************************************************
### How do the launched components prevent execution of unauthenticated code?
*******************************************************************************
N/A

*******************************************************************************
### Does your SHIM load any loaders that support loading unsigned kernels (e.g. GRUB2)?
*******************************************************************************
No
*******************************************************************************
### What kernel are you using? Which patches does it includes to enforce Secure Boot?
*******************************************************************************
Kernel version of Debian 5.15.1

*******************************************************************************
### Add any additional information you think we may need to validate this shim.
*******************************************************************************
We use this SHIM to boot multiple bootloaders from distro vendor Canonical. This is because we modify kernel configs to apply additional device drivers and security controls which require rebuilding and re-signing.
