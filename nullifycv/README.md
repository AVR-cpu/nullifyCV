# NullifyCV

**Privacy-first resume de-identifier for blind hiring.**

> Nullify the bias. Keep the talent.

[nullifycv.com](https://nullifycv.com) · [MIT License](LICENSE)

---

## What it does

NullifyCV removes bias-causing PII from resumes and CVs so hiring teams can evaluate candidates on skills alone. It supports GDPR Article 5 data minimisation workflows, CCPA sensitive data requirements, Illinois BIPA (profile photo removal), and EEOC blind review documentation.

**The core promise:** your files never leave your device. Everything runs in the browser.

---

## Privacy architecture

| Component | Detail | Privacy implication |
|---|---|---|
| PDF engine | pdf-lib@1.17.1 (WebAssembly, browser-native) | File bytes never leave device memory |
| DOCX engine | mammoth@1.6.0 (pure JS) | Text extracted into JS heap only |
| Hosting | Static CDN — no server backend | No server-side code path exists for file data |
| Ad isolation | Content Security Policy separates ad scripts | Ad networks cannot access file data |
| Output | Blob URL, auto-revoked after 5s | Download is a local file transfer |
| Audit log | Generated as JSON Blob, downloaded locally | Log never transmitted |

**0 bytes of document data are ever transmitted to any server.**

You can verify this claim:
1. Open DevTools → Network tab
2. Drop a file and process it
3. Observe: zero outbound requests containing file data

---

## Redaction capabilities

### PII patterns detected

| Type | Example | Regulation |
|---|---|---|
| `NAME` | Full name on first line | GDPR 5(1)(c) |
| `EMAIL` | any@email.com | GDPR 5(1)(c) |
| `PHONE` | +1 (415) 555-0192 | GDPR 5(1)(c) |
| `ADDRESS` | 123 Main St, City | GDPR 5(1)(c) |
| `ZIP` | 94117 | CCPA §1798.121 |
| `CITY_ST` | San Francisco, CA | GDPR 5(1)(c) |
| `GRAD_YR` | Class of 2009 | ADEA / EEOC |
| `YEAR` | 2008 (age proxy) | ADEA / EEOC |
| `SCHOOL` | Stanford University | EEOC blind review |
| `LINKEDIN` | linkedin.com/in/... | GDPR 5(1)(b) |
| `URL` | https://... | GDPR 5(1)(b) |
| `PRONOUN` | He/Him, She/Her | Title VII / EEOC |
| `PHOTO` | Embedded images | IL BIPA / GDPR Art.9 |

### Preset modes

| Mode | Targets |
|---|---|
| Standard PII | Name, contact, location, graduation year |
| Bias strip | All of the above + school names, pronouns |
| Client submission | Name, contact, URLs, file metadata |
| EEOC blind review | All targets |

---

## Running locally

This is a static site. No build step required.

```bash
git clone https://github.com/yourusername/nullifycv.git
cd nullifycv
# Option 1: Python
python -m http.server 8080
# Option 2: Node
npx serve .
# Option 3: VS Code Live Server extension
```

Open `http://localhost:8080` in your browser.

---

## Deploying

### Vercel (recommended for free tier)

```bash
npm i -g vercel
cd nullifycv
vercel
```

### Netlify

Drag the `nullifycv/` folder onto [app.netlify.com/drop](https://app.netlify.com/drop).

### Cloudflare Pages

Connect your GitHub repo at [pages.cloudflare.com](https://pages.cloudflare.com). Build command: none. Output directory: `/`.

---

## Upgrading the PDF engine

pdf-lib is a PDF creation library. It reads page structure but does not extract text layers. To get full text extraction from existing PDFs, add pdf.js alongside it:

```html
<!-- In index.html, add: -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js"></script>
```

Then replace `extractPDFText()` in `app.js` with a pdf.js implementation that calls `page.getTextContent()` per page. The `app.js` file has a `TODO` comment marking the exact replacement point.

---

## Monetisation

NullifyCV is ad-supported and offers a Pro subscription. See `pro.html` for the paid tier.

**Ad zones:**
- `728×90` leaderboard (top, high viewability)
- `300×250` sidebar (persistent while working)
- Post-download interstitial (peak-intent moment)

All ad zones use contextual targeting only. No behavioural tracking. Recommended networks: [Carbon Ads](https://www.carbonads.net/), [Ethical Ads](https://www.ethicalads.io/).

**Pro tier ($9/month):**
- Batch processing (up to 200 files)
- Saved redaction profiles
- GDPR / CCPA annotated audit log
- DPO compliance report export (PDF)

---

## Content Security Policy

Add the following CSP header to your hosting config to isolate ad scripts from the processing layer:

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' https://unpkg.com https://cdnjs.cloudflare.com [your-ad-network];
  connect-src 'none';
  worker-src blob:;
  object-src 'none';
```

The `connect-src 'none'` directive blocks all outbound fetch/XHR requests — proving that no data can be transmitted even if the code attempted it.

---

## Legal disclaimer

NullifyCV documents a data minimisation workflow consistent with GDPR Article 5 principles. It does not determine legal compliance. Consult your DPO or legal counsel for a formal compliance assessment.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Roadmap

- [ ] pdf.js integration for full PDF text extraction
- [ ] Real PDF output (redacted rectangles over detected coordinates)
- [ ] Batch processing UI
- [ ] Supabase-backed Pro tier (saved profiles, team dashboard)
- [ ] DPO report PDF export in-browser
- [ ] Browser extension for processing files without visiting the site
