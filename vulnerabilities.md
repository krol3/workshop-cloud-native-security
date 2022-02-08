# Detecting Vulnerabilities

## Table of Contents
- [Prerequisites](#prerequisites)
- [Vulnerability Database](#vulnerability-database)
- [Scanning Container Images](#container-images)
  - [**Risk knowledge**](#risk-knowledge)
  - [Tar Images](#tar-images)
  - [**Unfixed vulnerabilities**](#unfixed-vulnerabilities)
- [Filter Log4j-CVE using OPA](#filter-log4j-cve-using-opa)
- [Scanning Filesystems](#scanning-filesystems)
  - [Rootfs](#rootfs)
- [Scanning Git Repositories](#scanning-git-repositories)
- [Binaries created by Golang](#binaries-created-by-golang)
- [CI Integration](#ci-integration)

## Prerequisites

Before you begin, you need the following software:

- A Linux, stand-alone virtual machine (VM)
- [Trivy](https://www.aquasec.com/products/trivy/) command-line tool. [Installation steps here](https://aquasecurity.github.io/trivy/v0.20.0/getting-started/installation/)

### Vulnerability Database

[![cve-db](https://www.researchgate.net/publication/348403318/figure/fig1/AS:978993503289355@1610421648894/A-typical-container-scanning-approach-for-package-vulnerability-detection.png)](https://arxiv.org/pdf/2101.03844.pdf)

> Trivy is stateless and requires no maintenance or preparation.

## Container Images

### **Risk knowledge**

`trivy image --severity HIGH,CRITICAL tomcat:8.0.15-jre7`
<details>
<summary>Show results</summary>

```
2021-10-29T16:25:26.249-0300    ESC[34mINFOESC[0m       Detected OS: debian
2021-10-29T16:25:26.249-0300    ESC[34mINFOESC[0m       Detecting Debian vulnerabilities...
2021-10-29T16:25:26.270-0300    ESC[34mINFOESC[0m       Number of language-specific files: 1
2021-10-29T16:25:26.270-0300    ESC[34mINFOESC[0m       Detecting jar vulnerabilities...
2021-10-29T16:25:26.270-0300    ESC[33mWARNESC[0m       This OS version is no longer supported by the distribution: debian 8.0
2021-10-29T16:25:26.270-0300    ESC[33mWARNESC[0m       The vulnerability detection may be insufficient because security updates are not provided

tomcat:8.0.15-jre7 (debian 8.0)
===============================
Total: 751 (HIGH: 553, CRITICAL: 198)

+--------------------------+------------------+----------+---------------------------+----------------------------------+--------------------------------------------------------------+
|         LIBRARY          | VULNERABILITY ID | SEVERITY |     INSTALLED VERSION     |          FIXED VERSION           |                            TITLE                             |
+--------------------------+------------------+----------+---------------------------+----------------------------------+--------------------------------------------------------------+
| apt                      | CVE-2019-3462    | HIGH     | 1.0.9.5                   | 1.0.9.8.5                        | Incorrect sanitation of                                      |
|                          |                  |          |                           |                                  | the 302 redirect field in                                    |
|                          |                  |          |                           |                                  | HTTP transport method of...                                  |
|                          |                  |          |                           |                                  | -->avd.aquasec.com/nvd/cve-2019-3462                         |
+--------------------------+------------------+          +---------------------------+----------------------------------+--------------------------------------------------------------+
| bash                     | CVE-2016-7543    |          | 4.3-11                    | 4.3-11+deb8u1                    | bash: Specially crafted                                      |
|                          |                  |          |                           |                                  | SHELLOPTS+PS4 variables                                      |
|                          |                  |          |                           |                                  | allows command substitution                                  |
|                          |                  |          |                           |                                  | -->avd.aquasec.com/nvd/cve-2016-7543                         |
+                          +------------------+          +                           +----------------------------------+--------------------------------------------------------------+
|                          | CVE-2019-9924    |          |                           | 4.3-11+deb8u2                    | bash: BASH_CMD is writable                                   |
|                          |                  |          |                           |                                  | in restricted bash shells                                    |
|                          |                  |          |                           |                                  | -->avd.aquasec.com/nvd/cve-2019-9924                         |
+--------------------------+------------------+          +---------------------------+----------------------------------+--------------------------------------------------------------+
| bsdutils                 | CVE-2016-2779    |          | 2.25.2-4                  |                                  | util-linux: runuser tty                                      |
|                          |                  |          |                           |                                  | hijack via TIOCSTI ioctl                                     |
|                          |                  |          |                           |                                  | -->avd.aquasec.com/nvd/cve-2016-2779                         |
+--------------------------+------------------+----------+---------------------------+----------------------------------+--------------------------------------------------------------+
....
```
</details></br>

`trivy image --severity HIGH,CRITICAL --vuln-type os postgres:10.6`

<details>
<summary>Show results</summary>

```
2021-10-29T18:21:09.389-0300    ESC[34mINFOESC[0m       Detected OS: debian
2021-10-29T18:21:09.389-0300    ESC[34mINFOESC[0m       Detecting Debian vulnerabilities...

postgres:10.6 (debian 9.7)
==========================
Total: 331 (HIGH: 228, CRITICAL: 103)

+----------------------+------------------+----------+----------------------------+-----------------------------------+-----------------------------------------+
|       LIBRARY        | VULNERABILITY ID | SEVERITY |     INSTALLED VERSION      |           FIXED VERSION           |                  TITLE                  |
+----------------------+------------------+----------+----------------------------+-----------------------------------+-----------------------------------------+
| bsdutils             | CVE-2016-2779    | HIGH     | 2.29.2-1+deb9u1            |                                   | util-linux: runuser tty                 |
|                      |                  |          |                            |                                   | hijack via TIOCSTI ioctl                |
|                      |                  |          |                            |                                   | -->avd.aquasec.com/nvd/cve-2016-2779    |
+----------------------+------------------+----------+----------------------------+-----------------------------------+-----------------------------------------+
| bzip2                | CVE-2019-12900   | CRITICAL | 1.0.6-8.1                  |                                   | bzip2: out-of-bounds write              |
|                      |                  |          |                            |                                   | in function BZ2_decompress              |
|                      |                  |          |                            |                                   | -->avd.aquasec.com/nvd/cve-2019-12900   |
+----------------------+------------------+----------+----------------------------+-----------------------------------+-----------------------------------------+
| dirmngr              | CVE-2018-1000858 | HIGH     | 2.1.18-8~deb9u3            |                                   | gnupg2: Cross site request              |
|                      |                  |          |                            |                                   | forgery in dirmngr resulting            |
|                      |                  |          |                            |                                   | in an information disclosure...         |
|                      |                  |          |                            |                                   | -->avd.aquasec.com/nvd/cve-2018-1000858 |
+----------------------+------------------+----------+----------------------------+-----------------------------------+-----------------------------------------+
| exim4                | CVE-2019-10149   | CRITICAL | 4.89-2+deb9u3              | 4.89-2+deb9u4                     | exim: Remote command                    |
|                      |                  |          |                            |                                   | execution in deliver_message()          |
|                      |                  |          |                            |                                   | function in /src/deliver.c              |
|                      |                  |          |                            |                                   | -->avd.aquasec.com/nvd/cve-2019-10149   |
+                      +------------------+          +                            +-----------------------------------+-----------------------------------------+
|                      | CVE-2019-13917   |          |                            | 4.89-2+deb9u5                     | exim: ${sort} in configuration          |
|                      |                  |          |                            |                                   | leads to privilege escalation           |
|                      |                  |          |                            |                                   | -->avd.aquasec.com/n:
```
</details></br>

`trivy image --severity HIGH,CRITICAL --vuln-type library node:10.6`

<details>
<summary>Show results</summary>

```
2021-10-29T18:28:53.941-0300    ESC[34mINFOESC[0m       Number of language-specific files: 1
2021-10-29T18:28:53.941-0300    ESC[34mINFOESC[0m       Detecting node-pkg vulnerabilities...

Node.js (node-pkg)
==================
Total: 28 (HIGH: 25, CRITICAL: 3)

+-------------------+------------------+----------+-------------------+-----------------------------+-----------------------------------------+
|      LIBRARY      | VULNERABILITY ID | SEVERITY | INSTALLED VERSION |        FIXED VERSION        |                  TITLE                  |
+-------------------+------------------+----------+-------------------+-----------------------------+-----------------------------------------+
| ansi-regex        | CVE-2021-3807    | HIGH     | 3.0.0             | 5.0.1, 6.0.1                | nodejs-ansi-regex: Regular              |
|                   |                  |          |                   |                             | expression denial of service            |
|                   |                  |          |                   |                             | (ReDoS) matching ANSI escape codes      |
|                   |                  |          |                   |                             | -->avd.aquasec.com/nvd/cve-2021-3807    |
+-------------------+------------------+----------+-------------------+-----------------------------+-----------------------------------------+
| cryptiles         | CVE-2018-1000620 | CRITICAL | 3.1.2             | 4.1.2                       | nodejs-cryptiles: Insecure randomness   |
|                   |                  |          |                   |                             | causes the randomDigits() function      |
|                   |                  |          |                   |                             | returns a pseudo-random data string...  |
|                   |                  |          |                   |                             | -->avd.aquasec.com/nvd/cve-2018-1000620 |
+-------------------+------------------+----------+-------------------+-----------------------------+-----------------------------------------+
| dot-prop          | CVE-2020-8116    | HIGH     | 4.2.0             | 5.1.1, 4.2.1                | nodejs-dot-prop: prototype pollution    |
|                   |                  |          |                   |                             | -->avd.aquasec.com/nvd/cve-2020-8116    |
+-------------------+------------------+----------+-------------------+-----------------------------+-----------------------------------------+
| extend            | CVE-2018-16492   | CRITICAL | 3.0.1             | 2.0.2, 3.0.2                | nodejs-extend: Prototype                |
|                   |                  |          |                   |                             | pollution can allow attackers           |
|                   |                  |          |                   |                             | to modify object properties             |
|                   |                  |          |                   |                             | -->avd.aquasec.com/nvd/cve-2018-16492   |
+-------------------+------------------+----------+-------------------+-----------------------------+-----------------------------------------+
| fstream           | CVE-2019-13173   | HIGH     | 1.0.11            | 1.0.12                      | nodejs-fstream: File overwrite          |
|                   |                  |          |                   |                             | in fstream.DirWriter() function         |
|                   |                  |          |                   |                             | -->avd.aquasec.com/nvd/cve-2019-13173 :
```
</details></br>

Other images samples:
```
trivy image --severity HIGH,CRITICAL jboss/wildfly:10.0.0.Final

trivy image --severity HIGH,CRITICAL tensorflow/tensorflow
```
> [Vulnerable Container List by JGamblin of Kenna Security](https://vulnerablecontainers.org/)

### Tar Images
- Image in tar format (Moby, Buildah, Podman, img, Kaniko) .

`trivy image --input ruby-2.3.0.tar`

- Image build following the OCI Image Specification: Buildah, Skopeo. [Trivy OCI Image support](https://aquasecurity.github.io/trivy/dev/advanced/container/oci/)

### **Unfixed vulnerabilities**

Traditional scanners ignore unfixed by default.

`trivy image ubuntu:20.04`

<details>
<summary>Show results</summary>

```
trivy image ubuntu:20.04 | more
2021-10-29T19:08:47.197-0300    ESC[34mINFOESC[0m       Detected OS: ubuntu
2021-10-29T19:08:47.197-0300    ESC[34mINFOESC[0m       Detecting Ubuntu vulnerabilities...
2021-10-29T19:08:47.201-0300    ESC[34mINFOESC[0m       Number of language-specific files: 0

ubuntu:20.04 (ubuntu 20.04)
===========================
Total: 22 (UNKNOWN: 0, LOW: 22, MEDIUM: 0, HIGH: 0, CRITICAL: 0)

+------------+------------------+----------+--------------------------+---------------+-----------------------------------------+
|  LIBRARY   | VULNERABILITY ID | SEVERITY |    INSTALLED VERSION     | FIXED VERSION |                  TITLE                  |
+------------+------------------+----------+--------------------------+---------------+-----------------------------------------+
| bash       | CVE-2019-18276   | LOW      | 5.0-6ubuntu1.1           |               | bash: when effective UID is not         |
|            |                  |          |                          |               | equal to its real UID the...            |
|            |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2019-18276   |
+------------+------------------+          +--------------------------+---------------+-----------------------------------------+
| coreutils  | CVE-2016-2781    |          | 8.30-3ubuntu2            |               | coreutils: Non-privileged               |
|            |                  |          |                          |               | session can escape to the               |
|            |                  |          |                          |               | parent session in chroot                |
|            |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2016-2781    |
+------------+------------------+          +--------------------------+---------------+-----------------------------------------+
| libc-bin   | CVE-2016-10228   |          | 2.31-0ubuntu9.2          |               | glibc: iconv program can hang           |
|            |                  |          |                          |               | when invoked with the -c option         |
|            |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2016-10228   |
+            +------------------+          +                          +---------------+-----------------------------------------+
|            | CVE-2019-25013   |          |                          |               | glibc: buffer over-read in              |
|            |                  |          |                          |               | iconv when processing invalid           |
|            |                  |          |                          |               | multi-byte input sequences in...        |
|            |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2019-25013   |
+            +------------------+          +                          +---------------+-----------------------------------------+
|            | CVE-2020-27618   |          |                          |               | glibc: iconv when processing            |
|            |                  |          |                          |               | invalid multi-byte input                |
|            |                  |          |                          |               | sequences fails to advance the...       |
|            |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2020-27618   |
+            +------------------+          +                          +---------------+-----------------------------------------+
|            | CVE-2020-29562   |          |                          |               | glibc: assertion failure in iconv       |
|            |                  |          |                          |               | when converting invalid UCS4            |
|            |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2020-29562   |
+            +------------------+          +                          +---------------+-----------------------------------------+
|            | CVE-2020-6096    |          |                          |               | glibc: signed comparison                |
|            |                  |          |                          |               | vulnerability in the                    |
|            |                  |          |                          |               | ARMv7 memcpy function                   |
|            |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2020-6096    |
+            +------------------+          +                          +---------------+-----------------------------------------+
|            | CVE-2021-27645   |          |                          |               | glibc: Use-after-free in                |
|            |                  |          |                          |               | addgetnetgrentX function                |
|            |                  |          |                          |               | in netgroupcache.c                      |
|            |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2021-27645   |
+            +------------------+          +                          +---------------+-----------------------------------------+
|            | CVE-2021-3326    |          |                          |               | glibc: Assertion failure in             |
|            |                  |          |                          |               | ISO-2022-JP-3 gconv module              |
```
</details></br>

`trivy image --ignore-unfixed ubuntu:20.04`

<details>
<summary>Show results</summary>

```
 trivy image --ignore-unfixed ubuntu:20.04
2021-10-29T19:14:43.504-0300	INFO	Detected OS: ubuntu
2021-10-29T19:14:43.504-0300	INFO	Detecting Ubuntu vulnerabilities...
2021-10-29T19:14:43.511-0300	INFO	Number of language-specific files: 0

ubuntu:20.04 (ubuntu 20.04)
===========================
Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)
```
</details></br>

> Some Linux distributions (e.g. Debian or Ubuntu) will release information about CVEs for which there is no released patched package, and so you get the question of “should a vulnerability scanner report those?”.
>  [Unfixed vulnerabilities in traditional scanners](https://raesene.github.io/blog/2020/11/22/When_Is_A_Vulnerability_Not_A_Vulnerability/)


## Filter Log4j-CVE using OPA

We wil filter the results that only contains the log4j CVE: CVE-2021-44228, CVE-2021-44832, CVE-2021-45046.

Here the normal results using Trivy

```
trivy image jerbi/log4j
```
<details>
<summary>Show results</summary>

```
trivy image jerbi/log4j
2022-01-27T23:17:57.322-0300	INFO	Need to update DB
2022-01-27T23:17:57.322-0300	INFO	Downloading DB...
25.78 MiB / 25.78 MiB [---------------------------------------------------------------------------------------------------------------------------------] 100.00% 14.15 MiB p/s 2s
2022-01-27T23:18:01.576-0300	INFO	Detected OS: alpine
2022-01-27T23:18:01.576-0300	INFO	Detecting Alpine vulnerabilities...
2022-01-27T23:18:01.582-0300	INFO	Number of language-specific files: 1
2022-01-27T23:18:01.582-0300	INFO	Detecting jar vulnerabilities...
2022-01-27T23:18:01.586-0300	WARN	This OS version is no longer supported by the distribution: alpine 3.8.2
2022-01-27T23:18:01.586-0300	WARN	The vulnerability detection may be insufficient because security updates are not provided

jerbi/log4j (alpine 3.8.2)
==========================
Total: 310 (UNKNOWN: 0, LOW: 152, MEDIUM: 109, HIGH: 41, CRITICAL: 8)

+-------------------+------------------+----------+-------------------+---------------+------------------------------------------+
|      LIBRARY      | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |                  TITLE                   |
+-------------------+------------------+----------+-------------------+---------------+------------------------------------------+
| krb5-libs         | CVE-2018-20217   | MEDIUM   | 1.15.3-r0         | 1.15.4-r0     | krb5: Reachable assertion in             |
|                   |                  |          |                   |               | the KDC using S4U2Self requests          |
|                   |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2018-20217    |
+-------------------+------------------+----------+-------------------+---------------+------------------------------------------+
| libbz2            | CVE-2019-12900   | CRITICAL | 1.0.6-r6          | 1.0.6-r7      | bzip2: out-of-bounds write               |
|                   |                  |          |                   |               | in function BZ2_decompress               |
|                   |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-12900    |
+-------------------+------------------+----------+-------------------+---------------+------------------------------------------+
| libcom_err        | CVE-2019-5094    | MEDIUM   | 1.44.2-r0         | 1.44.2-r1     | e2fsprogs: Crafted ext4 partition        |
|                   |                  |          |                   |               | leads to out-of-bounds write             |
|                   |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-5094     |
+                   +------------------+          +                   +---------------+------------------------------------------+
|                   | CVE-2019-5188    |          |                   | 1.44.2-r2     | e2fsprogs: Out-of-bounds                 |
|                   |                  |          |                   |               | write in e2fsck/rehash.c                 |
|                   |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-5188     |
+-------------------+------------------+----------+-------------------+---------------+------------------------------------------+
| libjpeg-turbo     | CVE-2019-2201    | HIGH     | 1.5.3-r3          | 1.5.3-r6      | libjpeg-turbo: several integer           |
|                   |                  |          |                   |               | overflows and subsequent                 |
|                   |                  |          |                   |               | segfaults when attempting to             |
|                   |                  |          |                   |               | compress/decompress gigapixel...         |
|                   |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-2201     |
+                   +------------------+----------+                   +---------------+------------------------------------------+
|                   | CVE-2018-14498   | MEDIUM   |                   | 1.5.3-r5      | libjpeg-turbo: heap-based buffer         |
|                   |                  |          |                   |               | over-read via crafted 8-bit BMP          |
|                   |                  |          |                   |               | in get_8bit_row in rdbmp.c...            |
|                   |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2018-14498    |
+-------------------+------------------+----------+-------------------+---------------+------------------------------------------+
| libpng            | CVE-2018-14550   | HIGH     | 1.6.34-r1         | 1.6.37-r0     | libpng: Stack-based buffer overflow in   |
|                   |                  |          |                   |               | contrib/pngminus/pnm2png.c:get_token()   |
|                   |                  |          |                   |               | potentially leading to                   |
|                   |                  |          |                   |               | arbitrary code execution...              |
|                   |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2018-14550    |
+                   +------------------+----------+                   +               +------------------------------------------+
|                   | CVE-2018-14048   | MEDIUM   |                   |               | libpng: Segmentation fault in            |
|                   |                  |          |                   |               | png.c:png_free_data function             |
|                   |                  |          |                   |               | causing denial of service                |
|                   |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2018-14048    |
+                   +------------------+          +                   +               +------------------------------------------+
|                   | CVE-2019-7317    |          |                   |               | libpng: use-after-free in                |
|                   |                  |          |                   |               | png_image_free in png.c                  |
|                   |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-7317     |
+-------------------+------------------+          +-------------------+---------------+------------------------------------------+
| libtasn1          | CVE-2018-1000654 |          | 4.13-r0           | 4.14-r0       | libtasn1: Infinite loop in               |
|                   |                  |          |                   |               | _asn1_expand_object_id(ptree)            |
|                   |                  |          |                   |               | leads to memory exhaustion               |
|                   |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2018-1000654  |

....
```
</details></br>

We will define a rule using Rego, to show only the events that containts the log4j CVEs.

```
trivy image --ignore-policy log4j-cve.rego jerbi/log4j
```

Here the content of [log4j-cve.rego](./log4j-cve.rego) file.

<details>
<summary>Show results</summary>

```
trivy image --ignore-policy log4j-cve.rego jerbi/log4j

2022-01-27T23:45:52.880-0300	INFO	Detected OS: alpine
2022-01-27T23:45:52.880-0300	INFO	Detecting Alpine vulnerabilities...
2022-01-27T23:45:52.886-0300	INFO	Number of language-specific files: 1
2022-01-27T23:45:52.887-0300	INFO	Detecting jar vulnerabilities...
2022-01-27T23:45:52.894-0300	WARN	This OS version is no longer supported by the distribution: alpine 3.8.2
2022-01-27T23:45:52.894-0300	WARN	The vulnerability detection may be insufficient because security updates are not provided

jerbi/log4j (alpine 3.8.2)
==========================
Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)


Java (jar)
==========
Total: 6 (UNKNOWN: 0, LOW: 0, MEDIUM: 2, HIGH: 0, CRITICAL: 4)

+-------------------------------------+------------------+----------+-------------------+-----------------------+---------------------------------------+
|               LIBRARY               | VULNERABILITY ID | SEVERITY | INSTALLED VERSION |     FIXED VERSION     |                 TITLE                 |
+-------------------------------------+------------------+----------+-------------------+-----------------------+---------------------------------------+
| org.apache.logging.log4j:log4j-api  | CVE-2021-44228   | CRITICAL | 2.14.1            | 2.15.0                | log4j-core: Remote code execution     |
|                                     |                  |          |                   |                       | in Log4j 2.x when logs contain        |
|                                     |                  |          |                   |                       | an attacker-controlled...             |
|                                     |                  |          |                   |                       | -->avd.aquasec.com/nvd/cve-2021-44228 |
+                                     +------------------+          +                   +-----------------------+---------------------------------------+
|                                     | CVE-2021-45046   |          |                   | 2.16.0                | log4j-core: DoS in log4j 2.x          |
|                                     |                  |          |                   |                       | with thread context message           |
|                                     |                  |          |                   |                       | pattern and context...                |
|                                     |                  |          |                   |                       | -->avd.aquasec.com/nvd/cve-2021-45046 |
+                                     +------------------+----------+                   +-----------------------+---------------------------------------+
|                                     | CVE-2021-44832   | MEDIUM   |                   | 2.17.1, 2.12.4, 2.3.2 | log4j-core: remote code               |
|                                     |                  |          |                   |                       | execution via JDBC Appender           |
|                                     |                  |          |                   |                       | -->avd.aquasec.com/nvd/cve-2021-44832 |
+-------------------------------------+------------------+----------+                   +-----------------------+---------------------------------------+
| org.apache.logging.log4j:log4j-core | CVE-2021-44228   | CRITICAL |                   | 2.15.0                | log4j-core: Remote code execution     |
|                                     |                  |          |                   |                       | in Log4j 2.x when logs contain        |
|                                     |                  |          |                   |                       | an attacker-controlled...             |
|                                     |                  |          |                   |                       | -->avd.aquasec.com/nvd/cve-2021-44228 |
+                                     +------------------+          +                   +-----------------------+---------------------------------------+
|                                     | CVE-2021-45046   |          |                   | 2.16.0                | log4j-core: DoS in log4j 2.x          |
|                                     |                  |          |                   |                       | with thread context message           |
|                                     |                  |          |                   |                       | pattern and context...                |
|                                     |                  |          |                   |                       | -->avd.aquasec.com/nvd/cve-2021-45046 |
+                                     +------------------+----------+                   +-----------------------+---------------------------------------+
|                                     | CVE-2021-44832   | MEDIUM   |                   | 2.17.1, 2.12.4, 2.3.2 | log4j-core: remote code               |
|                                     |                  |          |                   |                       | execution via JDBC Appender           |
|                                     |                  |          |                   |                       | -->avd.aquasec.com/nvd/cve-2021-44832 |
+-------------------------------------+------------------+----------+-------------------+-----------------------+---------------------------------------+
```
</details></br>

> More details about Filtering vulnerabilities [here](https://aquasecurity.github.io/trivy/dev/vulnerability/examples/filter/) and [samples using OPA with Trivy vulnerability results](https://github.com/aquasecurity/trivy/tree/main/contrib/example_policy).

Find the package path of these CVE:

```
trivy image -f json jerbi/log4j | grep "\"VulnerabilityID\": \"CVE-2021-44228\"" -A2
```

<details>
<summary>Show results</summary>

```
trivy image -f json jerbi/log4j | grep "\"VulnerabilityID\": \"CVE-2021-44228\"" -A2

          "VulnerabilityID": "CVE-2021-44228",
          "PkgName": "org.apache.logging.log4j:log4j-api",
          "PkgPath": "app/spring-boot-application.jar",
--
          "VulnerabilityID": "CVE-2021-44228",
          "PkgName": "org.apache.logging.log4j:log4j-core",
          "PkgPath": "app/spring-boot-application.jar",
```
</details></br>

Download the content of the image in the filesystem:

```
docker export $(docker create jerbi/log4j) | tar -C /tmp/my-rootfs -xvf -
cd /tmp/my-rootfs
```

Explore the files of the app "spring-boot-application.jar"
`unzip ./app/spring-boot-application.jar`

Find the libraries with the name log4j.

<details>
<summary>Show results</summary>

```
find . -name "log*"

./usr/bin/logger
./usr/lib/jvm/java-1.8-openjdk/jre/lib/logging.properties
./app/BOOT-INF/classes/fr/christophetd/log4shell
./app/BOOT-INF/lib/log4j-core-2.14.1.jar
./app/BOOT-INF/lib/log4j-slf4j-impl-2.14.1.jar
./app/BOOT-INF/lib/log4j-jul-2.14.1.jar
./app/BOOT-INF/lib/log4j-api-2.14.1.jar
./bin/login
./log4j.yaml
./sbin/logread
./etc/logrotate.d
./var/log
./BOOT-INF/classes/fr/christophetd/log4shell
./BOOT-INF/lib/log4j-core-2.14.1.jar
./BOOT-INF/lib/log4j-slf4j-impl-2.14.1.jar
./BOOT-INF/lib/log4j-jul-2.14.1.jar
./BOOT-INF/lib/log4j-api-2.14.1.jar
./log4j.rego
```
</details></br>

## Scanning Filesystems

```
git clone https://github.com/goreleaser/goreleaser.git
cd goreleaser && trivy fs .
```

<details>
<summary>Show results</summary>

```
cd goreleaser && trivy fs .
2021-11-01T08:49:28.257-0300	INFO	Number of language-specific files: 1
2021-11-01T08:49:28.257-0300	INFO	Detecting gomod vulnerabilities...

go.sum (gomod)
==============
Total: 3 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 0)

+------------------------------------+------------------+----------+-----------------------------------+---------------------------------------+-----------------------------------------+
|              LIBRARY               | VULNERABILITY ID | SEVERITY |         INSTALLED VERSION         |             FIXED VERSION             |                  TITLE                  |
+------------------------------------+------------------+----------+-----------------------------------+---------------------------------------+-----------------------------------------+
| github.com/dgrijalva/jwt-go        | CVE-2020-26160   | HIGH     | 3.2.0+incompatible                |                                       | jwt-go: access restriction              |
|                                    |                  |          |                                   |                                       | bypass vulnerability                    |
|                                    |                  |          |                                   |                                       | -->avd.aquasec.com/nvd/cve-2020-26160   |
+------------------------------------+------------------+----------+-----------------------------------+---------------------------------------+-----------------------------------------+
| github.com/miekg/dns               | CVE-2019-19794   | MEDIUM   | 1.0.14                            | v1.1.25-0.20191211073109-8ebf2e419df7 | golang-github-miekg-dns: predictable    |
|                                    |                  |          |                                   |                                       | TXID can lead to response forgeries     |
|                                    |                  |          |                                   |                                       | -->avd.aquasec.com/nvd/cve-2019-19794   |
+------------------------------------+------------------+----------+-----------------------------------+---------------------------------------+-----------------------------------------+
| github.com/sassoftware/go-rpmutils | CVE-2020-7667    | HIGH     | 0.0.0-20190420191620-a8f1baeba37b | v0.1.0                                | In package                              |
|                                    |                  |          |                                   |                                       | github.com/sassoftware/go-rpmutils/cpio |
|                                    |                  |          |                                   |                                       | before version 0.1.0, the               |
|                                    |                  |          |                                   |                                       | CPIO extraction functionality           |
|                                    |                  |          |                                   |                                       | doesn't sanitize...                     |
|                                    |                  |          |                                   |                                       | -->avd.aquasec.com/nvd/cve-2020-7667    |
+------------------------------------+------------------+----------+-----------------------------------+---------------------------------------+-----------------------------------------+
```
</details></br>

### Rootfs

Scan a root filesystem (such as a host machine, a virtual machine image, or an unpacked container image filesystem).

Scanning a sample Ubuntu VM rootfs:
`sudo trivy rootfs --severity HIGH,CRITICAL --ignore-unfixed  /`


<details>
<summary>Show results</summary>

![](https://i.imgur.com/lCxtmWj.png)
</details></br>

Scanning container image filesystem. Here a sample creating a sample rootfs from Alpine:
```
docker export $(docker create alpine:3.11) | tar -C /tmp/my-rootfs -xvf -

trivy rootfs /tmp/my-rootfs
```

<details>
<summary>Show results</summary>

![](https://i.imgur.com/ope1cQr.png)
</details></br>

## Scanning Git repositories

`trivy repo https://github.com/goreleaser/goreleaser.git`

<details>
<summary>Show results</summary>

```
2021-11-01T08:46:01.631-0300	INFO	Need to update DB
2021-11-01T08:46:01.631-0300	INFO	Downloading DB...
24.51 MiB / 24.51 MiB [---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------] 100.00% 31.01 MiB p/s 1s
Enumerating objects: 10085, done.
Counting objects: 100% (10085/10085), done.
Compressing objects: 100% (5391/5391), done.
Total 10085 (delta 6407), reused 7665 (delta 4391), pack-reused 0
2021-11-01T08:46:20.794-0300	INFO	Number of language-specific files: 1
2021-11-01T08:46:20.794-0300	INFO	Detecting gomod vulnerabilities...

go.sum (gomod)
==============
Total: 3 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 0)

+------------------------------------+------------------+----------+-----------------------------------+---------------------------------------+-----------------------------------------+
|              LIBRARY               | VULNERABILITY ID | SEVERITY |         INSTALLED VERSION         |             FIXED VERSION             |                  TITLE                  |
+------------------------------------+------------------+----------+-----------------------------------+---------------------------------------+-----------------------------------------+
| github.com/dgrijalva/jwt-go        | CVE-2020-26160   | HIGH     | 3.2.0+incompatible                |                                       | jwt-go: access restriction              |
|                                    |                  |          |                                   |                                       | bypass vulnerability                    |
|                                    |                  |          |                                   |                                       | -->avd.aquasec.com/nvd/cve-2020-26160   |
+------------------------------------+------------------+----------+-----------------------------------+---------------------------------------+-----------------------------------------+
| github.com/miekg/dns               | CVE-2019-19794   | MEDIUM   | 1.0.14                            | v1.1.25-0.20191211073109-8ebf2e419df7 | golang-github-miekg-dns: predictable    |
|                                    |                  |          |                                   |                                       | TXID can lead to response forgeries     |
|                                    |                  |          |                                   |                                       | -->avd.aquasec.com/nvd/cve-2019-19794   |
+------------------------------------+------------------+----------+-----------------------------------+---------------------------------------+-----------------------------------------+
| github.com/sassoftware/go-rpmutils | CVE-2020-7667    | HIGH     | 0.0.0-20190420191620-a8f1baeba37b | v0.1.0                                | In package                              |
|                                    |                  |          |                                   |                                       | github.com/sassoftware/go-rpmutils/cpio |
|                                    |                  |          |                                   |                                       | before version 0.1.0, the               |
|                                    |                  |          |                                   |                                       | CPIO extraction functionality           |
|                                    |                  |          |                                   |                                       | doesn't sanitize...                     |
|                                    |                  |          |                                   |                                       | -->avd.aquasec.com/nvd/cve-2020-7667    |
+------------------------------------+------------------+----------+-----------------------------------+---------------------------------------+-----------------------------------------+
```
</details></br>

## Binaries created by golang

Download a sample binary golang
```
mkdir mytest && cd mytest
curl -LO "https://github.com/goreleaser/goreleaser/releases/download/v0.183.0/goreleaser_Linux_arm64.tar.gz"
tar -xvf goreleaser_Linux_arm64.tar.gz
```

Scanning the folder
`trivy rootfs .`

<details>
<summary>Show results</summary>

```
 trivy rootfs .
2021-11-01T08:59:45.409-0300	INFO	Number of language-specific files: 1
2021-11-01T08:59:45.409-0300	INFO	Detecting gobinary vulnerabilities...

goreleaser (gobinary)
=====================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

+------------------------------------+------------------+----------+------------------------------------+---------------+-----------------------------------------+
|              LIBRARY               | VULNERABILITY ID | SEVERITY |         INSTALLED VERSION          | FIXED VERSION |                  TITLE                  |
+------------------------------------+------------------+----------+------------------------------------+---------------+-----------------------------------------+
| github.com/sassoftware/go-rpmutils | CVE-2020-7667    | HIGH     | v0.0.0-20190420191620-a8f1baeba37b | v0.1.0        | In package                              |
|                                    |                  |          |                                    |               | github.com/sassoftware/go-rpmutils/cpio |
|                                    |                  |          |                                    |               | before version 0.1.0, the               |
|                                    |                  |          |                                    |               | CPIO extraction functionality           |
|                                    |                  |          |                                    |               | doesn't sanitize...                     |
|                                    |                  |          |                                    |               | -->avd.aquasec.com/nvd/cve-2020-7667    |
+------------------------------------+------------------+----------+------------------------------------+---------------+-----------------------------------------+
```
</details></br>

> See more details about [Language-specific Packages](https://aquasecurity.github.io/trivy/dev/vulnerability/detection/language/)

## CI Integration

Using [trivy-action](https://github.com/aquasecurity/trivy-action) you can run Trivy in your Workflow.

```
  - name: Trivy - vulnerability Scanner
    uses: aquasecurity/trivy-action@master
    with:
      image-ref: 'docker.io/${{ env.ORG }}/${{ env.IMAGE_NAME }}:${{ github.sha }}'
      format: 'table'
      exit-code: '0'
      ignore-unfixed: true
      vuln-type: 'os,library'
      severity: 'HIGH,CRITICAL'
```

![Trivy image scanning](./images/gh-action-trivy-image.png)
> Sample github workflow [here](https://github.com/krol3/demo-trivy/blob/main/.github/workflows/scan-image.yaml)

Trivy can generate a SARIF (Static Analysis Results Interchange Format) file.

`trivy image --format sarif --output demo-image.sarif alpine:latest`

For example you can upload the Trivy result using the SARIF file to [Github Code Scanning](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning).

![Trivy image scanning sarif](./images/gh-action-trivy-demo.png)