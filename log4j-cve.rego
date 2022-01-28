package trivy

import data.lib.trivy

default ignore = false

ignore {
  input.VulnerabilityID != "CVE-2021-44228"
  input.VulnerabilityID != "CVE-2021-44832"
  input.VulnerabilityID != "CVE-2021-45046"
}

