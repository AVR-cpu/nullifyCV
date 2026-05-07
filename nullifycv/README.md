# NullifyCV

**Privacy-first CV de-identification for blind hiring and GDPR compliance.**

> Your CV. Your browser. Nobody else's business.

[![Live site](https://img.shields.io/badge/live-nullifycv.com-1e4d35?style=flat-square)](https://nullifycv.com)
[![License: MIT](https://img.shields.io/badge/license-MIT-7aaa8a?style=flat-square)](LICENSE)
[![Processing: Client-side only](https://img.shields.io/badge/processing-client--side%20only-a8c5b0?style=flat-square)](#privacy-architecture)

---

## Overview

NullifyCV automatically removes personally identifiable information (PII) and bias signals from CVs and resumes — so hiring teams can evaluate candidates on skills and experience alone.

**What makes it different:** everything runs in the browser. Files never travel to any server, never get uploaded, never get stored. Zero bytes of document data are ever transmitted. This isn't a privacy policy claim — it's an architectural fact you can verify with DevTools.

**Who it's for:**
- **Recruiters and HR teams** — prepare blind candidate packs, document GDPR data minimisation workflows, export DPO-ready audit logs
- **Job seekers** — remove personal details before sharing CVs with agencies or clients
- **Compliance teams** — implement structured blind review consistent with EEOC, GDPR, CCPA, and ADEA requirements

---

## Why local processing matters

Most CV redaction tools upload your files to a server. That means:

- Your candidate's personal data leaves your network
- A third party processes sensitive information on your behalf (triggering GDPR data processor requirements)
- You need a Data Processing Agreement
- You're trusting the vendor's security posture with data you're responsible for

NullifyCV is architecturally different. There is no server-side code that can receive your documents. Processing happens using [pdf.js](https://mozilla.github.io/pdf.js/) and [pdf-lib](https://pdf-lib.js.org/) running directly in the browser.

**The result:** NullifyCV does not act as a data processor under GDPR Article 4(8). No Data Processing Agreement is required.

---

## Features

### Redaction modes

| Mode | What it removes |
|---|---|
| **Standard PII** | Name, email, phone, address, postcode, graduation year |
| **Bias Strip** | Everything above + school names, gender pronouns, LinkedIn URLs |
| **Client Submission** | Name, contact details, URLs, file metadata |
| **EEOC Blind Review** | All targets — full demographic signal removal |

### PII patterns detected

| Type | Examples | Regulation |
|---|---|---|
| `NAME` | Full name (first line detection) | GDPR 5(1)(c) |
| `EMAIL` | any@email.com | GDPR 5(1)(c) |
| `PHONE` | +31 6 12345678 · +1 (415) 555-0192 | GDPR 5(1)(c) |
| `ADDRESS` | 123 Main St · Dorpsstraat 12 | GDPR 5(1)(c) |
| `POSTCODE` | 94117 · 1234 AB | CCPA §1798.121 |
| `CITY` | Amsterdam · San Francisco, CA | GDPR 5(1)(c) |
| `GRAD_YR` | Class of 2009 · Graduated May 2011 | ADEA / EEOC |
| `YEAR` | 2008 (age proxy in work history) | ADEA / EEOC |
| `SCHOOL` | Stanford University · Universiteit van Amsterdam | EEOC blind review |
| `LINKEDIN` | linkedin.com/in/username | GDPR 5(1)(b) |
| `URL` | Personal websites, portfolio links | GDPR 5(1)(b) |
| `PRONOUN` | He/Him · She/Her · zij/haar | Title VII / EEOC |
| `DOB` | Date of birth fields (NL: geboortedatum) | GDPR Art. 9 |
| `BSN` | Dutch national ID number | GDPR Art. 9 |
| `PHOTO` | Embedded profile photos | IL BIPA / GDPR Art. 9 |

### Dutch CV support

- 06-number phone format
- Dutch postcode format (1234 AB)
- 30+ Dutch city names
- Dutch field labels (geboortedatum, nationaliteit)
- Dutch month names in date fields
- BSN detection

### PDF output

For PDFs with a text layer, NullifyCV draws solid black redaction bars directly over detected PII on the **original file** — preserving layout, fonts, and formatting.

### Batch processing (Pro)

Pro and Team users can drop up to 200 files at once. All files are processed in the browser and a ZIP is generated containing all redacted files plus a combined JSON audit log.

---

## Privacy architecture

| Component | Technology | Privacy implication |
|---|---|---|
| PDF text extraction | pdf.js 3.11.174 | Reads text and coordinates in browser memory only |
| PDF redaction | pdf-lib 1.17.1 | Draws black bars on original bytes, never transmitted |
| DOCX extraction | mammoth 1.6.0 | Pure JS, text extracted into JS heap only |
| Hosting | Vercel CDN (static files only) | No server-side code path exists for file data |
| Output | Blob URL, revoked after download | Download is a local file transfer |
| Audit log | JSON Blob, downloaded locally | Log never transmitted |

**0 bytes of document data are ever transmitted to any server.**

### How to verify

1. Open DevTools (F12) → Network tab
2. Drop a file onto NullifyCV and process it
3. Filter by Fetch/XHR — observe zero outbound requests containing document data

---

## Compliance coverage

| Standard | Provision | How NullifyCV supports it |
|---|---|---|
| GDPR | Art. 5(1)(c) — Data minimisation | Removes non-essential PII before internal distribution |
| GDPR | Art. 5(1)(b) — Purpose limitation | Redacted copy limits data to assessment purpose only |
| GDPR | Art. 17 — Right to erasure | Panel holds no personal data; single deletion point |
| GDPR | Art. 4(8) — Data processor | NullifyCV is not a data processor; no DPA required |
| CCPA / CPRA | §1798.121 | Removes zip codes and precise location signals |
| IL BIPA | §15 — Biometric data | Profile photos removed in EEOC mode |
| EEOC / Title VII | Blind review | Removes name, location, and demographic signals |
| ADEA | Age discrimination | Removes graduation years and age proxy signals |
| NYC Local Law 144 | Bias audit documentation | Audit log supports documented blind review process |

---

## Use cases

**Blind panel review pack** — Process 50 CVs through Bias Strip mode before a shortlisting panel. Download the batch ZIP and distribute anonymised files. Attach the audit log to your hiring documentation.

**Client CV submission** — Before sending candidate CVs to a client, use Client Submission mode to remove contact details. Protects candidate data and prevents direct contact that bypasses your agency.

**GDPR data minimisation workflow** — Process incoming CVs before distributing internally. Retain the original with the recruiter; share only anonymised copies with hiring managers.

**DPO documentation** — Export the GDPR-annotated audit log and attach it to your Records of Processing Activities as evidence of a systematic data minimisation workflow.

**Agency submissions (job seekers)** — Remove personal contact details before sending your CV to a staffing agency. Share full contact details separately once engaged.

---

## Getting started

Static site — no build step required.

```bash
git clone https://github.com/NullifyCV/nullifyCV.git
cd nullifyCV/nullifycv

# Python
python -m http.server 8080

# Node
npx serve .
```

Open `http://localhost:8080` in your browser.

---

## Project structure

```
nullifycv/
├── index.html          # Main tool
├── app.js              # Processing engine — pdf.js + pdf-lib + mammoth
├── style.css           # Brand stylesheet
├── posts.js            # Blog post registry
├── about.html          # How it works
├── pro.html            # Pricing — Stripe payment links
├── success.html        # Post-payment licence activation
├── glossary.html       # HR privacy & blind hiring terminology
├── nl.html             # Dutch SEO landing page
├── us.html             # US market SEO landing page
├── sitemap.xml
├── robots.txt
├── icons/
│   └── favicon.svg
└── blog/
    ├── index.html      # Blog listing
    ├── blog.css        # Blog post styles
    ├── template.html   # Template for new posts
    └── *.html          # Individual posts
```

---

## Deploying

**Vercel (recommended):** connect repo, set Root Directory to `nullifycv`. No build command.

**Netlify:** drag `nullifycv/` folder to [app.netlify.com/drop](https://app.netlify.com/drop).

**Cloudflare Pages:** connect repo, no build command, output directory `nullifycv`.

---

## Roadmap

### Completed ✓
- [x] pdf.js — real PDF text extraction with coordinate mapping
- [x] pdf-lib — black bar redaction on original PDF preserving layout
- [x] Batch processing — up to 200 files, ZIP with combined audit log
- [x] Dutch CV support — 06 numbers, postcodes, cities, BSN
- [x] Paywall — free tier + job seeker passes + Pro/Team subscriptions
- [x] Licence system — localStorage-based auto-activation
- [x] Blog infrastructure — posts.js registry, prev/next, related posts
- [x] Glossary — 30 terms with structured data schema

### Planned
- [ ] Supabase backend for cross-device licence verification
- [ ] Saved redaction profiles (Pro)
- [ ] DPO compliance report PDF export (Pro)
- [ ] Team dashboard with shared profiles (Team)
- [ ] Browser extension
- [ ] DOCX output preserving original formatting
- [ ] Scanned PDF support via OCR

---

## Contributing

Pull requests welcome. Please open an issue first for significant changes.

---

## Legal

NullifyCV documents a data minimisation workflow consistent with GDPR Article 5 principles. It does not determine legal compliance — consult your DPO or legal counsel for a formal assessment.

MIT License — see [LICENSE](LICENSE).
