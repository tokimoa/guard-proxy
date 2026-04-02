# Third-Party Notices

Guard Proxy uses the following third-party libraries, data sources, and academic works.
This file provides proper attribution as required by their respective licenses.

---

## Python Dependencies

All Python dependencies are listed in `pyproject.toml`. Key licenses:

| Package | License | Copyright |
|---|---|---|
| FastAPI | MIT | © Sebastián Ramírez |
| httpx | BSD-3-Clause | © Encode OSS Ltd. |
| SQLAlchemy | MIT | © Michael Bayer |
| Pydantic | MIT | © Samuel Colvin |
| Typer | MIT | © Sebastián Ramírez |
| loguru | MIT | © Delgan |
| anthropic | MIT | © Anthropic |
| openai | Apache-2.0 | © OpenAI |
| plyara | Apache-2.0 | © plyara contributors |
| pyjsparser | MIT | © Piotr Dabkowski |
| greenlet | MIT | © Alexey Borzenkov |
| packaging | Apache-2.0 / BSD-2-Clause | © Donald Stufft |
| certifi | MPL-2.0 | © Kenneth Reitz |

Full license texts are available in each package's distribution.

---

## Data Sources

### DataDog Malicious Software Packages Dataset
- **Source**: https://github.com/DataDog/malicious-software-packages-dataset
- **License**: Apache-2.0
- **Copyright**: © Datadog, Inc.
- **Usage**: IOC database sync (`guard-proxy sync-ioc`)

### DataDog GuardDog
- **Source**: https://github.com/DataDog/guarddog
- **License**: Apache-2.0
- **Copyright**: © Datadog, Inc.
- **Usage**: YARA rule compatibility, detection rule benchmarks

### OSV.dev (Open Source Vulnerabilities)
- **Source**: https://osv.dev/
- **License**: Apache-2.0
- **Copyright**: © Google LLC
- **Usage**: Vulnerability advisory data sync

### OSSF Malicious Packages
- **Source**: https://github.com/ossf/malicious-packages
- **License**: Apache-2.0
- **Copyright**: © Open Source Security Foundation
- **Usage**: Malicious package reports reference

### Google deps.dev API
- **Source**: https://docs.deps.dev/api/v3/
- **License**: CC-BY 4.0 (generated data)
- **Terms**: Google APIs Terms of Service (https://developers.google.com/terms)
- **Copyright**: © Google LLC
- **Usage**: Dependency graph analysis

### Top PyPI Packages
- **Source**: https://github.com/hugovk/top-pypi-packages
- **Author**: Hugo van Kemenade
- **Usage**: Popular packages list for typosquatting detection

---

## Academic References

### Backstabber's Knife Collection (BKC)

Guard Proxy's detection categories are benchmarked against the BKC taxonomy.

> Ohm, M., Plate, H., Sykosch, A., & Meier, M. (2020).
> **Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks.**
> In *Detection of Intrusions and Malware, and Vulnerability Assessment* (DIMVA 2020), pp. 23-43.
> Springer. https://arxiv.org/abs/2005.09535

---

## Frameworks and Standards

### MITRE ATT&CK®
- **Source**: https://attack.mitre.org/
- **Usage**: Detection categories aligned to T1195 (Supply Chain Compromise)
- **Note**: MITRE ATT&CK® is a registered trademark of The MITRE Corporation.

### CycloneDX
- **Source**: https://cyclonedx.org/
- **Usage**: SBOM output format (CycloneDX 1.6 JSON)
- **Note**: CycloneDX is an OWASP project.

---

## License Compatibility

Guard Proxy is licensed under MIT. All dependencies and data sources use licenses
compatible with MIT:
- MIT, BSD-2/3-Clause, ISC: Fully compatible
- Apache-2.0: Compatible (attribution required, included above)
- MPL-2.0 (certifi): Compatible for use as dependency
- CC-BY 4.0 (deps.dev data): Attribution provided above
