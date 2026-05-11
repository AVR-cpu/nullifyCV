import sys
sys.path.insert(0, '/home/claude/nullifycv/working')
from page_template import TEMPLATE, faq_item, redact_item, trust_chip, CANONICAL_FOOTER, english_nav, localized_nav
from pathlib import Path

pages = {}

# ══════════════════════════════════════════════════════════════
# NL — Dutch (rewrite)
# ══════════════════════════════════════════════════════════════
pages['nl'] = dict(
    lang="nl", slug="nl",
    meta_title="CV Anonimiseren — Gratis Tool | NullifyCV",
    meta_desc="Verwijder persoonsgegevens uit je cv in drie seconden. Gratis, GDPR-consistent, bestanden verlaten nooit je browser. Voor recruiters en sollicitanten.",
    nav=localized_nav([
        ("/about.html","Hoe het werkt"),
        ("/blog/","Blog"),
        ("/glossary.html","Woordenlijst"),
    ], cta_label="Pro →"),
    nav_privacy_pill="Lokale verwerking — geen uploads",
    hero_tag="CV Anonimiseren · Nederland",
    hero_title="CV anonimiseren\nin drie seconden.",
    hero_sub="NullifyCV verwijdert persoonsgegevens uit cv's direct in je browser — naam, foto, adres, geboortedatum en meer. Geen uploads, geen opslag, geen account vereist.",
    cta_primary="Gratis proberen →",
    cta_secondary="Bekijk plannen",
    how_tag="Werkwijze",
    how_title="Zo werkt het",
    how_lead="Verwerk een cv in minder dan 30 seconden. Alles gebeurt lokaal — er verlaat geen byte jouw apparaat.",
    step1_title="Upload je cv", step1_body="Sleep een PDF of DOCX op het gereedschap. Het bestand wordt ingelezen in het browsergeheugen — het gaat nergens naartoe.",
    step2_title="Kies je redactieprofiel", step2_body="Standaard PII, Bias Strip, Klantinzending of EEOC Blind Review. Elk profiel verwijdert een andere laag van identificerende informatie.",
    step3_title="Verwerking in je browser", step3_body="pdf.js en pdf-lib tekenen zwarte balken over de PII-posities in het originele bestand. De opmaak, lettertypen en indeling blijven intact.",
    step4_title="Download het geanonimiseerde bestand", step4_body="Het geredigeerde bestand wordt direct naar je apparaat gedownload. De Blob URL wordt daarna ingetrokken — er blijft niets achter.",
    removed_tag="Wat wordt verwijderd",
    removed_title="Alle identificerende informatie wordt verwijderd",
    removed_lead="NullifyCV detecteert en verwijdert een breed scala aan persoonsgegevens, inclusief Nederlandse specificiteiten zoals BSN, postcodes en stadsnamen.",
    redact_items='\n    '.join(redact_item(l) for l in [
        "Volledige naam","E-mailadres","Telefoonnummer","Thuisadres & postcode",
        "Geboortedatum","Nationaliteit","Voornaamwoorden","Afstudeerjaar",
        "Profielfoto","LinkedIn-URL","School- en universiteitsnamen","BSN-nummer",
    ]),
    who_tag="Voor wie",
    who_title="Voor recruiters, HR-teams en sollicitanten",
    aud1_title="Recruiters", aud1_body="Bescherm kandidaatdata wanneer je cv's doorstuurt naar hiring managers of klanten. Voorkom ongewenste identificatie en voldoe aan GDPR-dataminimalisatie.",
    aud2_title="HR-teams", aud2_body="Voer gestructureerde blind hiring uit. Verwijder persoonsgegevens voordat cv's de beoordelingspanels bereiken — inclusief audit logs voor de FG.",
    aud3_title="Uitzend- en wervingsbureaus", aud3_body="Stuur kandidaatprofielen door naar opdrachtgevers zonder privécontactgegevens vrij te geven. Bescherm kandidaten tegen direct headhunten.",
    aud4_title="Sollicitanten", aud4_body="Verwijder je persoonsgegevens voordat je je cv uploadt naar vacaturesites of verzendt naar onbekende werkgevers. Bescherm je eigen privacy.",
    trust_tag="Beveiliging & privacy",
    trust_title="Privacy by design — verifieerbaar",
    trust_lead="NullifyCV is ontworpen zodat het technisch onmogelijk is om jouw bestanden te ontvangen. Je hoeft het niet op ons woord te geloven — je kunt het zelf controleren.",
    trust_chips='\n    '.join(trust_chip(t) for t in [
        "0 bytes geüpload","Geen server","Geen account vereist","Geen advertenties",
        "Open source op GitHub","A-rating Security Headers (Snyk)","GDPR-consistent",
    ]),
    faq_tag="Veelgestelde vragen",
    faq_title="Veelgestelde vragen",
    faq_items='\n'.join([
        faq_item("Worden mijn bestanden opgeslagen of verzonden?",
            "Nee. NullifyCV verwerkt bestanden volledig lokaal via pdf.js en mammoth.js. Er bestaat geen server die jouw bestand kan ontvangen. Je kunt dit zelf verifiëren via DevTools → Netwerk terwijl je een bestand verwerkt: je ziet geen uitgaande verzoeken met bestandsdata."),
        faq_item("Is NullifyCV gratis?",
            "Ja — de basistool is volledig gratis zonder account. Betaalde plannen beginnen bij $1,99 (eenmalig) voor sollicitanten en lopen op tot $49/maand voor recruiters met batchverwerking, opgeslagen profielen en GDPR-auditlogs."),
        faq_item("Welke bestandsformaten worden ondersteund?",
            "PDF en DOCX worden volledig ondersteund. Voor PDF's met een tekstlaag worden zwarte redactiebalkjes direct op het originele bestand getekend, waarbij de opmaak behouden blijft. Gescande PDF's (alleen afbeeldingen) dienen eerst als DOCX geëxporteerd te worden."),
        faq_item("Werkt het ook voor Nederlandse cv's?",
            "Ja — NullifyCV heeft specifieke ondersteuning voor Nederlandse cv's, waaronder Nederlandse telefoonnummers, stadsnamen, postcodes (1234 AB formaat), maandnamen in afstudeerdatums, veldlabels zoals 'geboortedatum' en 'nationaliteit', en BSN-detectie."),
        faq_item("Is NullifyCV GDPR-proof?",
            "NullifyCV ondersteunt de GDPR-dataminimalisatieprincipes onder Artikel 5(1)(c) — bestanden lokaal verwerken betekent dat er geen persoonsgegevens worden verzonden of opgeslagen. Of jouw volledige wervingsproces GDPR-compliant is, hangt af van meerdere factoren. Raadpleeg je Functionaris Gegevensbescherming voor een formele beoordeling."),
    ]),
    cta_box_title="Klaar om te beginnen?",
    cta_box_sub="Verwerk je eerste cv gratis — geen account, geen uploads, geen gedoe.",
    cta_box_btn="Gratis proberen →",
    footer=CANONICAL_FOOTER.replace("How it works","Hoe het werkt").replace(
        "Glossary","Woordenlijst").replace(
        "Case study","Case study").replace(
        "No uploads · No storage · No tracking · GDPR-consistent · Not legal advice",
        "Geen uploads · Geen opslag · Geen tracking · AVG-consistent · Geen juridisch advies"),
)

# ══════════════════════════════════════════════════════════════
# US — American English (rewrite, recruiter/EEOC focus)
# ══════════════════════════════════════════════════════════════
pages['us'] = dict(
    lang="en", slug="us",
    meta_title="Blind Hiring Resume Redaction — EEOC Compliant | NullifyCV",
    meta_desc="Remove personally identifying information from resumes for blind hiring and EEOC compliance. Free, browser-based, zero uploads. Built for US recruiters and HR teams.",
    nav=english_nav(),
    nav_privacy_pill="Processing locally — no uploads",
    hero_tag="Blind Hiring · EEOC Compliance · United States",
    hero_title="Resume redaction for\nblind hiring teams.",
    hero_sub="NullifyCV removes names, addresses, graduation years, and other bias signals from resumes — entirely in your browser. Built for US recruiters and HR teams running structured, EEOC-compliant hiring workflows.",
    cta_primary="Try it free →",
    cta_secondary="See pricing",
    how_tag="How it works",
    how_title="Redact a resume in under 30 seconds",
    how_lead="Upload a PDF or DOCX. Choose your redaction mode. Download the anonymized file. Zero bytes leave your device at any point.",
    step1_title="Upload the resume", step1_body="Drag a PDF or DOCX onto the tool. The file is read into browser memory only — it doesn't leave your device.",
    step2_title="Choose a redaction mode", step2_body="Standard PII, Bias Strip, Client Submission, or EEOC Blind Review. The EEOC mode removes school names, photos, and all location signals in addition to standard identifiers.",
    step3_title="Processed in your browser", step3_body="pdf.js and pdf-lib draw black redaction bars over PII positions directly in the original file — preserving fonts, layout, and formatting.",
    step4_title="Download the redacted resume", step4_body="The redacted file downloads directly to your device. The Blob URL is immediately revoked — nothing is retained or cached.",
    removed_tag="What gets removed",
    removed_title="Every bias signal, every identifier",
    removed_lead="NullifyCV detects a broad range of PII and bias signals relevant to US hiring law — including EEOC-protected characteristics that could expose your organization to discrimination claims.",
    redact_items='\n    '.join(redact_item(l) for l in [
        "Full name","Email address","Phone number","Home address & ZIP code",
        "Date of birth","Graduation year (age proxy)","Gender pronouns","Nationality",
        "Profile photo","LinkedIn & personal URLs","School / university names (EEOC mode)","File author metadata",
    ]),
    who_tag="Who it's for",
    who_title="Built for US HR teams and recruiters",
    aud1_title="In-house HR teams", aud1_body="Run structured blind hiring at scale. Remove PII before resumes reach the scoring panel — with an audit log documenting every redaction for your legal team.",
    aud2_title="Recruiting firms", aud2_body="Submit candidate profiles to clients without exposing personal contact details. Protect candidates from direct poaching while staying EEOC-consistent.",
    aud3_title="Compliance and legal teams", aud3_body="Document a defensible, bias-reducing hiring workflow. The EEOC Blind Review mode removes school names and location signals that have been cited in disparate impact claims.",
    aud4_title="DEI and talent acquisition leaders", aud4_body="Implement structured blind review without replacing your ATS. NullifyCV works on any PDF or DOCX — no integration required.",
    trust_tag="Security & privacy",
    trust_title="Verifiable privacy — not just a claim",
    trust_lead="NullifyCV is architecturally incapable of receiving your files. Open DevTools → Network tab while processing a resume and watch for outbound requests — you'll see none containing file data.",
    trust_chips='\n    '.join(trust_chip(t) for t in [
        "0 bytes uploaded","No server","No account required","No ads",
        "Open source on GitHub","A-rated security headers (Snyk)","EEOC Blind Review mode",
    ]),
    faq_tag="FAQ",
    faq_title="Frequently asked questions",
    faq_items='\n'.join([
        faq_item("Does NullifyCV support EEOC blind hiring requirements?",
            "NullifyCV's EEOC Blind Review mode removes names, addresses, graduation years (age proxies), gender pronouns, school and university names, profile photos, and all location signals — the categories most commonly cited in disparate impact litigation. It doesn't constitute legal compliance advice; consult your employment counsel for a formal assessment."),
        faq_item("Do my files ever get uploaded to a server?",
            "No. Processing happens entirely in your browser using pdf.js and mammoth.js. There is no server that can receive your resume — not even ours. You can verify this by opening DevTools → Network tab while processing a file: you'll see zero outbound requests containing file data."),
        faq_item("Is there a free version?",
            "Yes — single-file processing is completely free with no account required. Paid plans start at $4.99 (Week Pass — unlimited for 7 days) and go up to $49/month (Pro) for HR teams needing batch processing of up to 200 resumes, saved redaction profiles, and GDPR/EEOC-annotated audit logs."),
        faq_item("What file formats are supported?",
            "PDF and DOCX (Word) files are fully supported. For PDFs with a text layer, black redaction bars are drawn directly onto the original file preserving layout. Scanned PDFs (image-only) should be exported as DOCX first."),
        faq_item("Can I process multiple resumes at once?",
            "Batch processing of up to 200 files at once is available on the Pro plan at $49/month. The Pro plan also includes saved redaction profiles and EEOC/GDPR-annotated audit logs suitable for your legal or compliance team."),
    ]),
    cta_box_title="Start blind hiring today.",
    cta_box_sub="Free to use, no account required. Process your first resume in under 30 seconds.",
    cta_box_btn="Try it free →",
    footer=CANONICAL_FOOTER,
)

# ══════════════════════════════════════════════════════════════
# DE — German
# ══════════════════════════════════════════════════════════════
pages['de'] = dict(
    lang="de", slug="de",
    meta_title="Bewerbungsunterlagen anonymisieren — Kostenloses Tool | NullifyCV",
    meta_desc="Personenbezogene Daten aus Lebensläufen entfernen — kostenlos, DSGVO-konform, Dateien verlassen nie Ihren Browser. Für Recruiter und Bewerber in Deutschland.",
    nav=localized_nav([
        ("/about.html","So funktioniert es"),
        ("/blog/","Blog"),
        ("/glossary.html","Glossar"),
    ], cta_label="Pro →"),
    nav_privacy_pill="Lokale Verarbeitung — keine Uploads",
    hero_tag="Lebenslauf Anonymisierung · Deutschland",
    hero_title="Lebensläufe anonymisieren\nin drei Sekunden.",
    hero_sub="NullifyCV entfernt personenbezogene Daten aus Lebensläufen direkt in Ihrem Browser — Name, Foto, Adresse, Geburtsdatum und mehr. Keine Uploads, keine Speicherung, kein Konto erforderlich.",
    cta_primary="Kostenlos testen →",
    cta_secondary="Preise ansehen",
    how_tag="Funktionsweise",
    how_title="So einfach geht's",
    how_lead="Verarbeiten Sie einen Lebenslauf in weniger als 30 Sekunden. Alles geschieht lokal — kein einziges Byte verlässt Ihr Gerät.",
    step1_title="Lebenslauf hochladen", step1_body="Ziehen Sie eine PDF- oder DOCX-Datei auf das Tool. Die Datei wird nur in den Browserspeicher eingelesen — sie verlässt Ihr Gerät nicht.",
    step2_title="Schwärzungsprofil wählen", step2_body="Standard-PII, Bias-Entfernung, Mandanteneinreichung oder EEOC-Blindprüfung. Jedes Profil entfernt eine andere Schicht identifizierender Informationen.",
    step3_title="Verarbeitung im Browser", step3_body="pdf.js und pdf-lib zeichnen schwarze Schwärzungsbalken über die PII-Positionen direkt in die Originaldatei — Layout, Schriftarten und Formatierung bleiben erhalten.",
    step4_title="Anonymisierten Lebenslauf herunterladen", step4_body="Die geschwärzte Datei wird direkt auf Ihr Gerät heruntergeladen. Die Blob-URL wird anschließend widerrufen — es bleibt nichts zurück.",
    removed_tag="Was entfernt wird",
    removed_title="Alle identifizierenden Informationen werden entfernt",
    removed_lead="NullifyCV erkennt und entfernt eine breite Palette personenbezogener Daten, die nach DSGVO Art. 5(1)(c) bei der Weitergabe von Lebensläufen nicht erforderlich sind.",
    redact_items='\n    '.join(redact_item(l) for l in [
        "Vollständiger Name","E-Mail-Adresse","Telefonnummer","Wohnadresse & PLZ",
        "Geburtsdatum","Nationalität","Pronomen","Abschlussjahr",
        "Profilfoto","LinkedIn-URL","Schul- und Hochschulnamen","Datei-Metadaten",
    ]),
    who_tag="Für wen",
    who_title="Für Recruiter, HR-Teams und Bewerber",
    aud1_title="Recruiter", aud1_body="Schützen Sie Kandidatendaten bei der Weiterleitung von Lebensläufen an Hiring Manager oder Kunden. Unterstützen Sie DSGVO-Datensparsamkeit nach Art. 5(1)(c).",
    aud2_title="HR-Abteilungen", aud2_body="Führen Sie strukturiertes Blind Hiring durch. Entfernen Sie personenbezogene Daten, bevor Lebensläufe die Bewertungsgremien erreichen — inklusive Audit-Logs für den DSB.",
    aud3_title="Personalvermittlungsagenturen", aud3_body="Übermitteln Sie Kandidatenprofile an Auftraggeber ohne private Kontaktdaten preiszugeben. Schützen Sie Kandidaten vor direktem Headhunting.",
    aud4_title="Bewerber", aud4_body="Entfernen Sie Ihre persönlichen Daten, bevor Sie Ihren Lebenslauf auf Jobportale hochladen oder an unbekannte Arbeitgeber senden.",
    trust_tag="Sicherheit & Datenschutz",
    trust_title="Datenschutz by Design — nachprüfbar",
    trust_lead="NullifyCV ist technisch so konzipiert, dass es unmöglich ist, Ihre Dateien zu empfangen. Sie müssen uns nicht auf Wort glauben — Sie können es selbst überprüfen.",
    trust_chips='\n    '.join(trust_chip(t) for t in [
        "0 Bytes hochgeladen","Kein Server","Kein Konto erforderlich","Keine Werbung",
        "Open Source auf GitHub","A-Bewertung Security Headers (Snyk)","DSGVO-konform",
    ]),
    faq_tag="Häufige Fragen",
    faq_title="Häufig gestellte Fragen",
    faq_items='\n'.join([
        faq_item("Werden meine Dateien gespeichert oder übertragen?",
            "Nein. NullifyCV verarbeitet Dateien vollständig lokal über pdf.js und mammoth.js. Es gibt keinen Server, der Ihre Datei empfangen könnte. Sie können dies selbst über DevTools → Netzwerk überprüfen: Sie sehen keine ausgehenden Anfragen mit Dateidaten."),
        faq_item("Ist NullifyCV kostenlos?",
            "Ja — das Basis-Tool ist komplett kostenlos ohne Konto. Bezahlte Pläne beginnen bei 1,99 $ (einmalig) für Bewerber und gehen bis zu 49 $/Monat für Recruiter mit Stapelverarbeitung, gespeicherten Profilen und DSGVO-Audit-Logs."),
        faq_item("Welche Dateiformate werden unterstützt?",
            "PDF und DOCX werden vollständig unterstützt. Bei PDFs mit Textebene werden schwarze Schwärzungsbalken direkt in die Originaldatei gezeichnet, wobei das Layout erhalten bleibt. Gescannte PDFs sollten zunächst als DOCX exportiert werden."),
        faq_item("Ist NullifyCV DSGVO-konform?",
            "NullifyCV unterstützt die DSGVO-Datensparsamkeitsprinzipien nach Art. 5(1)(c) — lokale Verarbeitung bedeutet, dass keine personenbezogenen Daten übertragen oder gespeichert werden. Ob Ihr gesamter Einstellungsprozess DSGVO-konform ist, hängt von weiteren Faktoren ab. Konsultieren Sie Ihren Datenschutzbeauftragten für eine formelle Beurteilung."),
        faq_item("Kann ich mehrere Lebensläufe gleichzeitig verarbeiten?",
            "Die Stapelverarbeitung von bis zu 200 Dateien gleichzeitig ist im Pro-Plan für 49 $/Monat verfügbar. Der Pro-Plan umfasst auch gespeicherte Schwärzungsprofile und DSGVO-kommentierte Audit-Logs für Ihren Datenschutzbeauftragten."),
    ]),
    cta_box_title="Jetzt loslegen?",
    cta_box_sub="Kostenlos nutzen, kein Konto erforderlich. Verarbeiten Sie Ihren ersten Lebenslauf in weniger als 30 Sekunden.",
    cta_box_btn="Kostenlos testen →",
    footer=CANONICAL_FOOTER.replace("How it works","So funktioniert es").replace(
        "Glossary","Glossar").replace(
        "No uploads · No storage · No tracking · GDPR-consistent · Not legal advice",
        "Keine Uploads · Keine Speicherung · Kein Tracking · DSGVO-konform · Kein Rechtsrat"),
)

# ══════════════════════════════════════════════════════════════
# FR — French
# ══════════════════════════════════════════════════════════════
pages['fr'] = dict(
    lang="fr", slug="fr",
    meta_title="Anonymiser un CV — Outil Gratuit | NullifyCV",
    meta_desc="Supprimez les données personnelles de vos CV en quelques secondes. Gratuit, conforme RGPD, les fichiers ne quittent jamais votre navigateur.",
    nav=localized_nav([
        ("/about.html","Comment ça marche"),
        ("/blog/","Blog"),
        ("/glossary.html","Glossaire"),
    ], cta_label="Pro →"),
    nav_privacy_pill="Traitement local — aucun envoi",
    hero_tag="Anonymisation de CV · France",
    hero_title="Anonymisez un CV\nen trois secondes.",
    hero_sub="NullifyCV supprime les données personnelles des CV directement dans votre navigateur — nom, photo, adresse, date de naissance et plus encore. Sans envoi, sans stockage, sans compte requis.",
    cta_primary="Essayer gratuitement →",
    cta_secondary="Voir les tarifs",
    how_tag="Fonctionnement",
    how_title="Comment ça marche",
    how_lead="Traitez un CV en moins de 30 secondes. Tout se passe localement — aucun octet ne quitte votre appareil.",
    step1_title="Importez le CV", step1_body="Déposez un fichier PDF ou DOCX sur l'outil. Le fichier est chargé uniquement en mémoire du navigateur — il ne quitte pas votre appareil.",
    step2_title="Choisissez un profil de suppression", step2_body="PII standard, suppression des biais, soumission client ou examen à l'aveugle EEOC. Chaque profil supprime une couche différente d'informations identifiantes.",
    step3_title="Traitement dans le navigateur", step3_body="pdf.js et pdf-lib dessinent des barres de caviardage noires directement sur le fichier original — la mise en page, les polices et la mise en forme sont préservées.",
    step4_title="Téléchargez le CV anonymisé", step4_body="Le fichier caviardé est téléchargé directement sur votre appareil. L'URL Blob est immédiatement révoquée — rien n'est conservé.",
    removed_tag="Ce qui est supprimé",
    removed_title="Toutes les informations identifiantes supprimées",
    removed_lead="NullifyCV détecte et supprime un large éventail de données personnelles conformément aux principes de minimisation des données du RGPD.",
    redact_items='\n    '.join(redact_item(l) for l in [
        "Nom complet","Adresse e-mail","Numéro de téléphone","Adresse & code postal",
        "Date de naissance","Nationalité","Pronoms","Année d'obtention du diplôme",
        "Photo de profil","URL LinkedIn","Noms d'établissements scolaires","Métadonnées du fichier",
    ]),
    who_tag="Pour qui",
    who_title="Pour les recruteurs, RH et candidats",
    aud1_title="Recruteurs", aud1_body="Protégez les données des candidats lors du partage de CV avec les responsables du recrutement ou les clients. Respectez la minimisation des données du RGPD.",
    aud2_title="Équipes RH", aud2_body="Mettez en place un recrutement à l'aveugle structuré. Supprimez les données personnelles avant que les CV n'atteignent les jurys d'évaluation.",
    aud3_title="Cabinets de recrutement", aud3_body="Transmettez des profils de candidats à vos clients sans divulguer leurs coordonnées personnelles. Protégez les candidats du démarchage direct.",
    aud4_title="Candidats", aud4_body="Supprimez vos données personnelles avant de déposer votre CV sur des sites d'emploi ou de l'envoyer à des employeurs inconnus.",
    trust_tag="Sécurité & confidentialité",
    trust_title="Confidentialité by design — vérifiable",
    trust_lead="NullifyCV est architecturalement incapable de recevoir vos fichiers. Ouvrez DevTools → Réseau lors du traitement d'un CV et observez : aucune requête sortante ne contient vos données.",
    trust_chips='\n    '.join(trust_chip(t) for t in [
        "0 octet envoyé","Aucun serveur","Aucun compte requis","Sans publicité",
        "Open source sur GitHub","Note A Security Headers (Snyk)","Conforme RGPD",
    ]),
    faq_tag="FAQ",
    faq_title="Questions fréquentes",
    faq_items='\n'.join([
        faq_item("Mes fichiers sont-ils envoyés ou stockés ?",
            "Non. NullifyCV traite les fichiers entièrement dans votre navigateur via pdf.js et mammoth.js. Il n'existe aucun serveur pouvant recevoir votre fichier. Vous pouvez vérifier cela via DevTools → Réseau pendant le traitement : aucune requête sortante ne contient vos données."),
        faq_item("NullifyCV est-il gratuit ?",
            "Oui — l'outil de base est entièrement gratuit sans compte. Les plans payants commencent à 1,99 $ (usage unique) pour les candidats et vont jusqu'à 49 $/mois pour les recruteurs avec traitement par lots, profils enregistrés et journaux d'audit RGPD."),
        faq_item("Quels formats de fichiers sont pris en charge ?",
            "PDF et DOCX sont entièrement pris en charge. Pour les PDF avec une couche de texte, des barres de caviardage noires sont dessinées directement sur le fichier original en préservant la mise en page. Les PDF numérisés doivent d'abord être exportés en DOCX."),
        faq_item("NullifyCV est-il conforme au RGPD ?",
            "NullifyCV soutient les principes de minimisation des données du RGPD selon l'article 5(1)(c). Le traitement local signifie qu'aucune donnée personnelle n'est transmise ou stockée. Consultez votre DPO pour une évaluation formelle de conformité."),
        faq_item("Puis-je traiter plusieurs CV à la fois ?",
            "Le traitement par lots jusqu'à 200 fichiers simultanément est disponible avec le plan Pro à 49 $/mois, incluant des profils enregistrés et des journaux d'audit annotés RGPD."),
    ]),
    cta_box_title="Prêt à commencer ?",
    cta_box_sub="Gratuit, sans compte. Traitez votre premier CV en moins de 30 secondes.",
    cta_box_btn="Essayer gratuitement →",
    footer=CANONICAL_FOOTER.replace("How it works","Comment ça marche").replace(
        "Glossary","Glossaire").replace(
        "No uploads · No storage · No tracking · GDPR-consistent · Not legal advice",
        "Aucun envoi · Aucun stockage · Aucun suivi · Conforme RGPD · Pas de conseil juridique"),
)

# ══════════════════════════════════════════════════════════════
# ES — Spanish
# ══════════════════════════════════════════════════════════════
pages['es'] = dict(
    lang="es", slug="es",
    meta_title="Anonimizar Currículum — Herramienta Gratuita | NullifyCV",
    meta_desc="Elimine datos personales de currículums en segundos. Gratuito, compatible con RGPD, los archivos nunca salen de su navegador.",
    nav=localized_nav([
        ("/about.html","Cómo funciona"),
        ("/blog/","Blog"),
        ("/glossary.html","Glosario"),
    ], cta_label="Pro →"),
    nav_privacy_pill="Procesamiento local — sin envíos",
    hero_tag="Anonimización de CV · España",
    hero_title="Anonimice un currículum\nen tres segundos.",
    hero_sub="NullifyCV elimina los datos personales de los currículums directamente en su navegador — nombre, foto, dirección, fecha de nacimiento y más. Sin envíos, sin almacenamiento, sin cuenta requerida.",
    cta_primary="Probar gratis →",
    cta_secondary="Ver precios",
    how_tag="Cómo funciona",
    how_title="Así de sencillo",
    how_lead="Procese un currículum en menos de 30 segundos. Todo ocurre localmente — ningún byte sale de su dispositivo.",
    step1_title="Suba el currículum", step1_body="Arrastre un PDF o DOCX sobre la herramienta. El archivo se lee solo en la memoria del navegador — no sale de su dispositivo.",
    step2_title="Elija un perfil de redacción", step2_body="PII estándar, eliminación de sesgos, envío a clientes o revisión ciega EEOC. Cada perfil elimina una capa diferente de información identificativa.",
    step3_title="Procesamiento en el navegador", step3_body="pdf.js y pdf-lib dibujan barras de redacción negras sobre las posiciones de PII directamente en el archivo original — preservando el diseño, las fuentes y el formato.",
    step4_title="Descargue el CV anonimizado", step4_body="El archivo redactado se descarga directamente en su dispositivo. La URL Blob se revoca inmediatamente — no queda nada almacenado.",
    removed_tag="Qué se elimina",
    removed_title="Toda la información identificativa eliminada",
    removed_lead="NullifyCV detecta y elimina una amplia gama de datos personales conforme a los principios de minimización de datos del RGPD.",
    redact_items='\n    '.join(redact_item(l) for l in [
        "Nombre completo","Dirección de correo","Número de teléfono","Dirección & código postal",
        "Fecha de nacimiento","Nacionalidad","Pronombres","Año de graduación",
        "Foto de perfil","URL de LinkedIn","Nombres de centros educativos","Metadatos del archivo",
    ]),
    who_tag="Para quién",
    who_title="Para reclutadores, RRHH y candidatos",
    aud1_title="Reclutadores", aud1_body="Proteja los datos de los candidatos al compartir currículums con responsables de contratación o clientes. Cumpla con la minimización de datos del RGPD.",
    aud2_title="Equipos de RRHH", aud2_body="Implemente una selección ciega estructurada. Elimine datos personales antes de que los currículums lleguen a los paneles de evaluación.",
    aud3_title="Agencias de selección", aud3_body="Envíe perfiles de candidatos a clientes sin revelar datos de contacto privados. Proteja a los candidatos del headhunting directo.",
    aud4_title="Candidatos", aud4_body="Elimine sus datos personales antes de subir su CV a portales de empleo o enviarlo a empleadores desconocidos.",
    trust_tag="Seguridad y privacidad",
    trust_title="Privacidad by design — verificable",
    trust_lead="NullifyCV es arquitectónicamente incapaz de recibir sus archivos. Abra DevTools → Red durante el procesamiento de un CV y observe: ninguna solicitud saliente contiene sus datos.",
    trust_chips='\n    '.join(trust_chip(t) for t in [
        "0 bytes enviados","Sin servidor","Sin cuenta requerida","Sin publicidad",
        "Código abierto en GitHub","Calificación A Security Headers (Snyk)","Compatible con RGPD",
    ]),
    faq_tag="FAQ",
    faq_title="Preguntas frecuentes",
    faq_items='\n'.join([
        faq_item("¿Se envían o almacenan mis archivos?",
            "No. NullifyCV procesa los archivos completamente en su navegador mediante pdf.js y mammoth.js. No existe ningún servidor que pueda recibir su archivo. Puede verificarlo en DevTools → Red durante el procesamiento: no verá ninguna solicitud saliente con datos del archivo."),
        faq_item("¿Es gratuito NullifyCV?",
            "Sí — la herramienta básica es completamente gratuita sin cuenta. Los planes de pago comienzan en 1,99 $ (uso único) para candidatos y llegan hasta 49 $/mes para reclutadores con procesamiento por lotes, perfiles guardados y registros de auditoría RGPD."),
        faq_item("¿Qué formatos de archivo se admiten?",
            "Se admiten completamente PDF y DOCX. Para PDF con capa de texto, las barras de redacción negras se dibujan directamente en el archivo original preservando el diseño. Los PDF escaneados deben exportarse primero como DOCX."),
        faq_item("¿Es NullifyCV compatible con el RGPD?",
            "NullifyCV apoya los principios de minimización de datos del RGPD según el artículo 5(1)(c). El procesamiento local significa que no se transmiten ni almacenan datos personales. Consulte a su DPO para una evaluación formal de cumplimiento."),
        faq_item("¿Puedo procesar varios currículums a la vez?",
            "El procesamiento por lotes de hasta 200 archivos simultáneamente está disponible en el plan Pro a 49 $/mes, incluyendo perfiles guardados y registros de auditoría anotados con RGPD."),
    ]),
    cta_box_title="¿Listo para empezar?",
    cta_box_sub="Gratis, sin cuenta. Procese su primer currículum en menos de 30 segundos.",
    cta_box_btn="Probar gratis →",
    footer=CANONICAL_FOOTER.replace("How it works","Cómo funciona").replace(
        "Glossary","Glosario").replace(
        "No uploads · No storage · No tracking · GDPR-consistent · Not legal advice",
        "Sin envíos · Sin almacenamiento · Sin seguimiento · Compatible con RGPD · No es asesoramiento jurídico"),
)

# ══════════════════════════════════════════════════════════════
# Render and write all pages
# ══════════════════════════════════════════════════════════════
out_dir = Path('/home/claude/nullifycv/working')
for slug, data in pages.items():
    html = TEMPLATE.format(**data)
    path = out_dir / f'{slug}.html'
    path.write_text(html)
    size = len(html)
    print(f"✓ {slug}.html  ({size:,} bytes)")

print(f"\nAll {len(pages)} pages written.")

# ══════════════════════════════════════════════════════════════
# UK — British English
# ══════════════════════════════════════════════════════════════
pages['uk'] = dict(
    lang="en-GB", slug="uk",
    meta_title="CV Redaction for Blind Hiring — UK GDPR Compliant | NullifyCV",
    meta_desc="Remove personal data from CVs for blind hiring and UK GDPR compliance. Free, browser-based, zero uploads. Built for UK recruiters and HR teams.",
    nav=english_nav(),
    nav_privacy_pill="Processing locally — no uploads",
    hero_tag="Blind Hiring · UK GDPR · United Kingdom",
    hero_title="CV redaction for\nfair hiring teams.",
    hero_sub="NullifyCV removes names, addresses, graduation years, and other bias signals from CVs — entirely in your browser. Built for UK recruiters and HR teams running structured, Equality Act-compliant hiring workflows.",
    cta_primary="Try it free →",
    cta_secondary="See pricing",
    how_tag="How it works",
    how_title="Redact a CV in under 30 seconds",
    how_lead="Upload a PDF or DOCX. Choose your redaction mode. Download the anonymised file. Zero bytes leave your device at any point.",
    step1_title="Upload the CV", step1_body="Drag a PDF or DOCX onto the tool. The file is read into browser memory only — it never leaves your device.",
    step2_title="Choose a redaction mode", step2_body="Standard PII, Bias Strip, Client Submission, or EEOC Blind Review. Each mode removes a different layer of identifying information from the CV.",
    step3_title="Processed in your browser", step3_body="pdf.js and pdf-lib draw black redaction bars over PII positions directly in the original file — preserving layout, fonts, and formatting.",
    step4_title="Download the redacted CV", step4_body="The redacted file downloads directly to your device. The Blob URL is immediately revoked — nothing is retained or cached.",
    removed_tag="What gets removed",
    removed_title="Every identifier, every bias signal",
    removed_lead="NullifyCV detects a broad range of personal data relevant to UK hiring law — including characteristics protected under the Equality Act 2010 that could expose your organisation to discrimination claims.",
    redact_items='\n    '.join(redact_item(l) for l in [
        "Full name","Email address","Phone number","Home address & postcode",
        "Date of birth","Graduation year (age proxy)","Gender pronouns","Nationality",
        "Profile photo","LinkedIn & personal URLs","School / university names","File author metadata",
    ]),
    who_tag="Who it's for",
    who_title="Built for UK HR teams and recruiters",
    aud1_title="In-house HR teams", aud1_body="Run structured blind hiring at scale. Remove personal data before CVs reach the scoring panel — with an audit log documenting every redaction for your Data Protection Officer.",
    aud2_title="Recruitment agencies", aud2_body="Submit candidate profiles to clients without exposing personal contact details. Protect candidates from direct poaching while staying UK GDPR-consistent.",
    aud3_title="Compliance and legal teams", aud3_body="Document a defensible, bias-reducing hiring workflow. The ICO expects organisations to demonstrate active steps toward fair processing — anonymised CV handling supports that position.",
    aud4_title="DEI and talent acquisition leads", aud4_body="Implement structured blind review without replacing your ATS. NullifyCV works on any PDF or DOCX — no integration, no procurement process required.",
    trust_tag="Security & privacy",
    trust_title="Verifiable privacy — not just a claim",
    trust_lead="NullifyCV is architecturally incapable of receiving your files. Open DevTools → Network tab while processing a CV and watch for outbound requests — you'll see none containing file data.",
    trust_chips='\n    '.join(trust_chip(t) for t in [
        "0 bytes uploaded","No server","No account required","No ads",
        "Open source on GitHub","A-rated security headers (Snyk)","UK GDPR-consistent",
    ]),
    faq_tag="FAQ",
    faq_title="Frequently asked questions",
    faq_items='\n'.join([
        faq_item("Is NullifyCV compliant with UK GDPR?",
            "NullifyCV supports UK GDPR data minimisation principles under Article 5(1)(c) — processing files locally means no personal data is transmitted or stored by the tool. Whether your overall hiring process is fully UK GDPR compliant depends on many other factors. Consult your Data Protection Officer or legal counsel for a formal assessment."),
        faq_item("Do my files ever get uploaded to a server?",
            "No. Processing happens entirely in your browser using pdf.js and mammoth.js. There is no server that can receive your CV — not even ours. You can verify this by opening DevTools → Network tab while processing a file: you'll see zero outbound requests containing file data."),
        faq_item("Is there a free version?",
            "Yes — single-file processing is completely free with no account required. Paid plans start at $4.99 (Week Pass — unlimited for 7 days) and go up to $49/month (Pro) for HR teams needing batch processing of up to 200 CVs, saved redaction profiles, and audit logs."),
        faq_item("What file formats are supported?",
            "PDF and DOCX (Word) files are fully supported. For PDFs with a text layer, black redaction bars are drawn directly onto the original file preserving layout. Scanned PDFs should be exported as DOCX first."),
        faq_item("Can I process multiple CVs at once?",
            "Batch processing of up to 200 files at once is available on the Pro plan at $49/month. The Pro plan also includes saved redaction profiles and audit logs suitable for your Data Protection Officer."),
    ]),
    cta_box_title="Start fair hiring today.",
    cta_box_sub="Free to use, no account required. Process your first CV in under 30 seconds.",
    cta_box_btn="Try it free →",
    footer=CANONICAL_FOOTER,
)

# ══════════════════════════════════════════════════════════════
# CA — Canadian English
# ══════════════════════════════════════════════════════════════
pages['ca'] = dict(
    lang="en-CA", slug="ca",
    meta_title="Resume Redaction for Blind Hiring — PIPEDA Compliant | NullifyCV",
    meta_desc="Remove personal information from resumes for blind hiring and PIPEDA compliance. Free, browser-based, zero uploads. Built for Canadian HR teams and recruiters.",
    nav=english_nav(),
    nav_privacy_pill="Processing locally — no uploads",
    hero_tag="Blind Hiring · PIPEDA · Canada",
    hero_title="Resume redaction for\nequitable hiring teams.",
    hero_sub="NullifyCV removes names, addresses, graduation years, and other bias signals from resumes — entirely in your browser. Built for Canadian HR teams running structured, Employment Equity Act-consistent hiring workflows.",
    cta_primary="Try it free →",
    cta_secondary="See pricing",
    how_tag="How it works",
    how_title="Redact a resume in under 30 seconds",
    how_lead="Upload a PDF or DOCX. Choose your redaction mode. Download the anonymized file. Zero bytes leave your device at any point.",
    step1_title="Upload the resume", step1_body="Drag a PDF or DOCX onto the tool. The file is read into browser memory only — it never leaves your device.",
    step2_title="Choose a redaction mode", step2_body="Standard PII, Bias Strip, Client Submission, or Blind Review. Each mode removes a different layer of identifying information.",
    step3_title="Processed in your browser", step3_body="pdf.js and pdf-lib draw black redaction bars over PII positions directly in the original file — preserving layout, fonts, and formatting.",
    step4_title="Download the redacted resume", step4_body="The redacted file downloads directly to your device. The Blob URL is immediately revoked — nothing is retained or cached.",
    removed_tag="What gets removed",
    removed_title="Every identifier, every bias signal",
    removed_lead="NullifyCV detects a broad range of personal information relevant to Canadian employment law — including characteristics protected under the Canadian Human Rights Act.",
    redact_items='\n    '.join(redact_item(l) for l in [
        "Full name","Email address","Phone number","Home address & postal code",
        "Date of birth","Graduation year (age proxy)","Gender pronouns","Nationality",
        "Profile photo","LinkedIn & personal URLs","School / university names","File author metadata",
    ]),
    who_tag="Who it's for",
    who_title="Built for Canadian HR teams and recruiters",
    aud1_title="In-house HR teams", aud1_body="Run structured blind hiring at scale. Remove personal information before resumes reach the scoring panel — with an audit log documenting every redaction for your privacy officer.",
    aud2_title="Staffing and recruitment firms", aud2_body="Submit candidate profiles to clients without exposing personal contact details. Protect candidates from direct poaching while staying PIPEDA-consistent.",
    aud3_title="Compliance and legal teams", aud3_body="Document a defensible, bias-reducing hiring workflow. Federally regulated employers under the Employment Equity Act can use anonymised resume handling as part of their documented equity programme.",
    aud4_title="DEI and talent acquisition leads", aud4_body="Implement structured blind review without replacing your ATS. NullifyCV works on any PDF or DOCX — no integration, no procurement process required.",
    trust_tag="Security & privacy",
    trust_title="Verifiable privacy — not just a claim",
    trust_lead="NullifyCV is architecturally incapable of receiving your files. Open DevTools → Network tab while processing a resume and watch for outbound requests — you'll see none containing file data.",
    trust_chips='\n    '.join(trust_chip(t) for t in [
        "0 bytes uploaded","No server","No account required","No ads",
        "Open source on GitHub","A-rated security headers (Snyk)","PIPEDA-consistent",
    ]),
    faq_tag="FAQ",
    faq_title="Frequently asked questions",
    faq_items='\n'.join([
        faq_item("Is NullifyCV compliant with PIPEDA?",
            "NullifyCV supports PIPEDA's data minimisation principles — processing files locally means no personal information is transmitted or stored by the tool. Whether your overall hiring process is fully PIPEDA compliant depends on many other factors. Consult your Privacy Officer or legal counsel for a formal assessment."),
        faq_item("Do my files ever get uploaded to a server?",
            "No. Processing happens entirely in your browser using pdf.js and mammoth.js. There is no server that can receive your resume — not even ours. You can verify this by opening DevTools → Network tab while processing a file: you'll see zero outbound requests containing file data."),
        faq_item("Is there a free version?",
            "Yes — single-file processing is completely free with no account required. Paid plans start at $4.99 (Week Pass — unlimited for 7 days) and go up to $49/month (Pro) for HR teams needing batch processing of up to 200 resumes, saved redaction profiles, and audit logs."),
        faq_item("What file formats are supported?",
            "PDF and DOCX (Word) files are fully supported. For PDFs with a text layer, black redaction bars are drawn directly onto the original file preserving layout. Scanned PDFs should be exported as DOCX first."),
        faq_item("Can I process multiple resumes at once?",
            "Batch processing of up to 200 files at once is available on the Pro plan at $49/month, including saved redaction profiles and audit logs suitable for your privacy officer or legal team."),
    ]),
    cta_box_title="Start equitable hiring today.",
    cta_box_sub="Free to use, no account required. Process your first resume in under 30 seconds.",
    cta_box_btn="Try it free →",
    footer=CANONICAL_FOOTER,
)

# ══════════════════════════════════════════════════════════════
# KR — Korean
# ══════════════════════════════════════════════════════════════
pages['kr'] = dict(
    lang="ko", slug="kr",
    meta_title="이력서 익명화 도구 — 무료 | NullifyCV",
    meta_desc="이력서에서 개인정보를 제거하세요. 무료, 개인정보보호법(PIPA) 준수, 파일이 브라우저를 벗어나지 않습니다.",
    nav=localized_nav([
        ("/about.html","이용 방법"),
        ("/blog/","블로그"),
        ("/glossary.html","용어집"),
    ], cta_label="Pro →"),
    nav_privacy_pill="로컬 처리 — 업로드 없음",
    hero_tag="이력서 익명화 · 대한민국",
    hero_title="이력서 개인정보를\n3초 만에 제거하세요.",
    hero_sub="NullifyCV는 이름, 사진, 주소, 생년월일 등 개인정보를 브라우저 내에서 직접 제거합니다. 업로드 없음, 저장 없음, 계정 불필요.",
    cta_primary="무료로 시작하기 →",
    cta_secondary="요금제 보기",
    how_tag="사용 방법",
    how_title="이렇게 사용하세요",
    how_lead="30초 안에 이력서를 처리할 수 있습니다. 모든 과정이 로컬에서 이루어지며, 어떤 데이터도 기기를 벗어나지 않습니다.",
    step1_title="이력서 업로드", step1_body="PDF 또는 DOCX 파일을 도구에 드래그하세요. 파일은 브라우저 메모리에만 읽히며 기기를 벗어나지 않습니다.",
    step2_title="삭제 프로필 선택", step2_body="표준 개인정보, 편견 제거, 고객 제출용, 또는 완전 블라인드 검토 중 선택하세요. 각 프로필은 다른 수준의 개인정보를 제거합니다.",
    step3_title="브라우저 내 처리", step3_body="pdf.js와 pdf-lib가 원본 파일의 개인정보 위치에 검은 막대를 그립니다. 레이아웃, 폰트, 서식은 그대로 유지됩니다.",
    step4_title="익명화된 이력서 다운로드", step4_body="처리된 파일이 바로 기기로 다운로드됩니다. Blob URL은 즉시 취소되며 아무것도 남지 않습니다.",
    removed_tag="제거되는 항목",
    removed_title="모든 개인 식별 정보 제거",
    removed_lead="NullifyCV는 한국 채용 문화에서 일반적으로 포함되는 개인정보를 감지하고 제거합니다 — 사진, 생년월일, 주소 등 채용 결정에 영향을 줄 수 있는 모든 정보.",
    redact_items='\n    '.join(redact_item(l) for l in [
        "성명","이메일 주소","전화번호","주소 및 우편번호",
        "생년월일","졸업연도","성별","국적",
        "증명사진","LinkedIn URL","학교·대학교명","파일 메타데이터",
    ]),
    who_tag="대상",
    who_title="채용담당자, HR팀, 구직자를 위한 도구",
    aud1_title="채용담당자", aud1_body="이력서를 채용 관리자나 고객에게 전달하기 전에 개인정보를 보호하세요. 개인정보보호법(PIPA) 데이터 최소화 원칙을 지원합니다.",
    aud2_title="HR팀", aud2_body="구조화된 블라인드 채용을 시행하세요. 평가 패널에 이력서가 전달되기 전에 개인정보를 제거하고, 감사 로그를 유지합니다.",
    aud3_title="헤드헌팅·채용 에이전시", aud3_body="개인 연락처를 노출하지 않고 고객에게 후보자 프로필을 제출하세요. 직접 스카우트로부터 후보자를 보호합니다.",
    aud4_title="구직자", aud4_body="채용 사이트에 이력서를 올리거나 모르는 회사에 이력서를 보내기 전에 개인정보를 제거하세요.",
    trust_tag="보안 및 개인정보",
    trust_title="검증 가능한 개인정보 보호",
    trust_lead="NullifyCV는 구조적으로 파일을 수신할 수 없습니다. 이력서를 처리하는 동안 DevTools → 네트워크 탭을 열어 확인해 보세요 — 파일 데이터를 포함한 아웃바운드 요청은 없습니다.",
    trust_chips='\n    '.join(trust_chip(t) for t in [
        "0바이트 업로드","서버 없음","계정 불필요","광고 없음",
        "GitHub 오픈소스","A등급 보안 헤더 (Snyk)","PIPA 준수",
    ]),
    faq_tag="자주 묻는 질문",
    faq_title="자주 묻는 질문",
    faq_items='\n'.join([
        faq_item("파일이 서버에 저장되거나 전송되나요?",
            "아니요. NullifyCV는 pdf.js와 mammoth.js를 사용해 브라우저에서 완전히 처리합니다. 파일을 수신할 수 있는 서버가 없습니다. DevTools → 네트워크 탭에서 직접 확인하실 수 있습니다."),
        faq_item("NullifyCV는 무료인가요?",
            "네 — 기본 도구는 계정 없이 완전 무료입니다. 유료 플랜은 $4.99 (Week Pass — 7일 무제한 사용)부터 시작하며, 대량 처리가 필요한 HR팀을 위한 Pro 플랜은 월 $49입니다."),
        faq_item("어떤 파일 형식을 지원하나요?",
            "PDF와 DOCX를 완전히 지원합니다. 텍스트 레이어가 있는 PDF의 경우 원본 파일에 직접 검은 막대가 그려져 레이아웃이 보존됩니다. 스캔된 PDF는 먼저 DOCX로 내보내야 합니다."),
        faq_item("개인정보보호법(PIPA)을 준수하나요?",
            "NullifyCV는 로컬 처리를 통해 개인정보가 전송되거나 저장되지 않도록 하여 PIPA의 데이터 최소화 원칙을 지원합니다. 전체 채용 프로세스의 PIPA 준수 여부는 법률 전문가와 상담하세요."),
        faq_item("여러 이력서를 한 번에 처리할 수 있나요?",
            "최대 200개 파일을 동시에 처리하는 배치 기능은 월 $49의 Pro 플랜에서 이용 가능합니다. 저장된 삭제 프로필과 감사 로그도 포함됩니다."),
    ]),
    cta_box_title="지금 시작하세요.",
    cta_box_sub="무료, 계정 불필요. 첫 번째 이력서를 30초 안에 처리하세요.",
    cta_box_btn="무료로 시작하기 →",
    footer=CANONICAL_FOOTER.replace("How it works","이용 방법").replace(
        "Glossary","용어집").replace(
        "No uploads · No storage · No tracking · GDPR-consistent · Not legal advice",
        "업로드 없음 · 저장 없음 · 추적 없음 · PIPA 준수 · 법적 조언 아님"),
)

# ══════════════════════════════════════════════════════════════
# SE — Swedish
# ══════════════════════════════════════════════════════════════
pages['se'] = dict(
    lang="sv", slug="se",
    meta_title="Anonymisera CV — Gratis verktyg | NullifyCV",
    meta_desc="Ta bort personuppgifter från CV:n på tre sekunder. Gratis, GDPR-anpassat, filer lämnar aldrig din webbläsare. För rekryterare och HR-team i Sverige.",
    nav=localized_nav([
        ("/about.html","Så fungerar det"),
        ("/blog/","Blogg"),
        ("/glossary.html","Ordlista"),
    ], cta_label="Pro →"),
    nav_privacy_pill="Lokal bearbetning — inga uppladdningar",
    hero_tag="CV-anonymisering · Sverige",
    hero_title="Anonymisera ett CV\npå tre sekunder.",
    hero_sub="NullifyCV tar bort personuppgifter från CV:n direkt i din webbläsare — namn, foto, adress, födelsedatum och mer. Inga uppladdningar, ingen lagring, inget konto krävs.",
    cta_primary="Testa gratis →",
    cta_secondary="Se priser",
    how_tag="Så fungerar det",
    how_title="Enkelt och snabbt",
    how_lead="Bearbeta ett CV på under 30 sekunder. Allt sker lokalt — ingen byte lämnar din enhet.",
    step1_title="Ladda upp CV:t", step1_body="Dra en PDF eller DOCX till verktyget. Filen läses endast in i webbläsarens minne — den lämnar inte din enhet.",
    step2_title="Välj redigeringsprofil", step2_body="Standard PII, borttagning av bias, klientinlämning eller EEOC blind granskning. Varje profil tar bort ett annat lager av identifierande information.",
    step3_title="Bearbetning i webbläsaren", step3_body="pdf.js och pdf-lib ritar svarta redigeringsfält över PII-positioner direkt i originalfilen — layout, teckensnitt och formatering bevaras.",
    step4_title="Ladda ned det anonymiserade CV:t", step4_body="Den redigerade filen laddas ned direkt till din enhet. Blob-URL:en återkallas omedelbart — inget sparas.",
    removed_tag="Vad som tas bort",
    removed_title="All identifierande information tas bort",
    removed_lead="NullifyCV identifierar och tar bort en bred uppsättning personuppgifter i linje med GDPR och Diskrimineringslagens krav på strukturerad rekrytering.",
    redact_items='\n    '.join(redact_item(l) for l in [
        "Fullständigt namn","E-postadress","Telefonnummer","Hemadress & postnummer",
        "Födelsedatum","Examinationsår","Pronomen","Nationalitet",
        "Profilfoto","LinkedIn-URL","Skol- och universitetsnamn","Filmetadata",
    ]),
    who_tag="För vem",
    who_title="För rekryterare, HR-team och kandidater",
    aud1_title="Rekryterare", aud1_body="Skydda kandidatdata när du vidarebefordrar CV:n till anställningschefer eller kunder. Stöd GDPR:s dataminimeringsprinciper enligt Art. 5(1)(c).",
    aud2_title="HR-avdelningar", aud2_body="Genomför strukturerad blind rekrytering. Ta bort personuppgifter innan CV:n når bedömningspanelerna — inklusive granskningsloggar för dataskyddsombud.",
    aud3_title="Rekryteringsbyråer", aud3_body="Skicka kandidatprofiler till kunder utan att avslöja privata kontaktuppgifter. Skydda kandidater från direktkontakt.",
    aud4_title="Kandidater", aud4_body="Ta bort dina personuppgifter innan du laddar upp ditt CV på jobbportaler eller skickar det till okända arbetsgivare.",
    trust_tag="Säkerhet och integritet",
    trust_title="Integritetsskydd by design — verifierbart",
    trust_lead="NullifyCV är arkitektoniskt oförmöget att ta emot dina filer. Öppna DevTools → Nätverk medan du bearbetar ett CV och observera: inga utgående förfrågningar innehåller dina data.",
    trust_chips='\n    '.join(trust_chip(t) for t in [
        "0 byte uppladdade","Ingen server","Inget konto krävs","Ingen reklam",
        "Öppen källkod på GitHub","A-betyg Security Headers (Snyk)","GDPR-anpassat",
    ]),
    faq_tag="Vanliga frågor",
    faq_title="Vanliga frågor",
    faq_items='\n'.join([
        faq_item("Lagras eller skickas mina filer?",
            "Nej. NullifyCV bearbetar filer helt lokalt via pdf.js och mammoth.js. Det finns ingen server som kan ta emot din fil. Du kan verifiera detta via DevTools → Nätverk under bearbetning: du ser inga utgående förfrågningar med fildata."),
        faq_item("Är NullifyCV gratis?",
            "Ja — grundverktyget är helt gratis utan konto. Betalplaner börjar på 1,99 $ (engångsköp) för kandidater och går upp till 49 $/månad för rekryterare med batchbearbetning, sparade profiler och GDPR-granskningsloggar."),
        faq_item("Vilka filformat stöds?",
            "PDF och DOCX stöds fullt ut. För PDF:er med ett textlager ritas svarta redigeringsfält direkt på originalfilen med bibehållen layout. Skannade PDF:er bör först exporteras som DOCX."),
        faq_item("Är NullifyCV GDPR-anpassat?",
            "NullifyCV stöder GDPR:s dataminimeringsprinciper enligt Art. 5(1)(c). Lokal bearbetning innebär att inga personuppgifter överförs eller lagras. Kontakta ditt dataskyddsombud för en formell bedömning."),
        faq_item("Kan jag bearbeta flera CV:n samtidigt?",
            "Batchbearbetning av upp till 200 filer åt gången finns tillgänglig i Pro-planen för 49 $/månad, inklusive sparade redigeringsprofiler och GDPR-annoterade granskningsloggar."),
    ]),
    cta_box_title="Redo att börja?",
    cta_box_sub="Gratis, inget konto krävs. Bearbeta ditt första CV på under 30 sekunder.",
    cta_box_btn="Testa gratis →",
    footer=CANONICAL_FOOTER.replace("How it works","Så fungerar det").replace(
        "Glossary","Ordlista").replace(
        "No uploads · No storage · No tracking · GDPR-consistent · Not legal advice",
        "Inga uppladdningar · Ingen lagring · Ingen spårning · GDPR-anpassat · Inte juridisk rådgivning"),
)

# ══════════════════════════════════════════════════════════════
# FI — Finnish
# ══════════════════════════════════════════════════════════════
pages['fi'] = dict(
    lang="fi", slug="fi",
    meta_title="Ansioluettelon anonymisointi — Ilmainen työkalu | NullifyCV",
    meta_desc="Poista henkilötiedot ansioluetteloista kolmessa sekunnissa. Ilmainen, GDPR-yhteensopiva, tiedostot eivät koskaan poistu selaimestasi.",
    nav=localized_nav([
        ("/about.html","Miten se toimii"),
        ("/blog/","Blogi"),
        ("/glossary.html","Sanasto"),
    ], cta_label="Pro →"),
    nav_privacy_pill="Paikallinen käsittely — ei latauksia",
    hero_tag="Ansioluettelon anonymisointi · Suomi",
    hero_title="Anonymisoi ansioluettelo\nkolmessa sekunnissa.",
    hero_sub="NullifyCV poistaa henkilötiedot ansioluetteloista suoraan selaimessasi — nimi, kuva, osoite, syntymäaika ja paljon muuta. Ei latauksia, ei tallennusta, ei vaadita tiliä.",
    cta_primary="Kokeile ilmaiseksi →",
    cta_secondary="Katso hinnat",
    how_tag="Näin se toimii",
    how_title="Yksinkertaista ja nopeaa",
    how_lead="Käsittele ansioluettelo alle 30 sekunnissa. Kaikki tapahtuu paikallisesti — yksikään tavu ei poistu laitteestasi.",
    step1_title="Lataa ansioluettelo", step1_body="Vedä PDF- tai DOCX-tiedosto työkaluun. Tiedosto luetaan vain selaimen muistiin — se ei poistu laitteestasi.",
    step2_title="Valitse poistoprofiili", step2_body="Vakio-PII, puolueellisuuden poisto, asiakaslähetys tai täysi sokea arviointi. Kukin profiili poistaa eri tason tunnistetietoja.",
    step3_title="Käsittely selaimessa", step3_body="pdf.js ja pdf-lib piirtävät mustat peitepalkit PII-kohtien päälle suoraan alkuperäiseen tiedostoon — asettelu, fontit ja muotoilu säilyvät.",
    step4_title="Lataa anonymisoitu ansioluettelo", step4_body="Muokattu tiedosto latautuu suoraan laitteellesi. Blob URL peruutetaan välittömästi — mitään ei jää tallennettuna.",
    removed_tag="Mitä poistetaan",
    removed_title="Kaikki tunnistetiedot poistetaan",
    removed_lead="NullifyCV tunnistaa ja poistaa laajan valikoiman henkilötietoja GDPR:n ja yhdenvertaisuuslain (Yhdenvertaisuuslaki 1325/2014) tietojen minimointiperiaatteiden mukaisesti.",
    redact_items='\n    '.join(redact_item(l) for l in [
        "Koko nimi","Sähköpostiosoite","Puhelinnumero","Kotiosoite ja postinumero",
        "Syntymäaika","Valmistumisvuosi","Pronominit","Kansalaisuus",
        "Profiilikuva","LinkedIn-URL","Koulu- ja yliopistonimet","Tiedoston metatiedot",
    ]),
    who_tag="Kenelle",
    who_title="Rekrytoijille, HR-tiimeille ja työnhakijoille",
    aud1_title="Rekrytoijat", aud1_body="Suojaa hakijatiedot lähettäessäsi ansioluetteloita rekrytointipäättäjille tai asiakkaille. Tue GDPR:n tietojen minimointiperiaatteita Art. 5(1)(c) mukaisesti.",
    aud2_title="HR-tiimit", aud2_body="Toteuta rakenteellinen sokea rekrytointi. Poista henkilötiedot ennen kuin ansioluettelot saapuvat arviointipaneeleille — tallenna muutosloki tietosuojavastaavalle.",
    aud3_title="Rekrytointitoimistot", aud3_body="Lähetä hakijaprofiileja asiakkaille paljastamatta yksityisiä yhteystietoja. Suojaa hakijoita suorahaulta.",
    aud4_title="Työnhakijat", aud4_body="Poista henkilötietosi ennen kuin lataat ansioluettelosi työnhakuportaaleihin tai lähetät sen tuntemattomille työnantajille.",
    trust_tag="Tietoturva ja yksityisyys",
    trust_title="Yksityisyydensuoja by design — todennettavissa",
    trust_lead="NullifyCV on arkkitehtuuriltaan kyvytön vastaanottamaan tiedostojasi. Avaa DevTools → Verkko käsitellessäsi ansioluetteloa ja tarkkaile: yksikään lähtevä pyyntö ei sisällä tiedostodataa.",
    trust_chips='\n    '.join(trust_chip(t) for t in [
        "0 tavua ladattu","Ei palvelinta","Ei vaadita tiliä","Ei mainoksia",
        "Avoin lähdekoodi GitHubissa","A-luokitus Security Headers (Snyk)","GDPR-yhteensopiva",
    ]),
    faq_tag="UKK",
    faq_title="Usein kysytyt kysymykset",
    faq_items='\n'.join([
        faq_item("Tallennetaanko tai lähetetäänkö tiedostoni?",
            "Ei. NullifyCV käsittelee tiedostot kokonaan paikallisesti pdf.js:n ja mammoth.js:n avulla. Palvelinta, joka voisi vastaanottaa tiedostosi, ei ole olemassa. Voit tarkistaa tämän DevToolsin Verkko-välilehdeltä käsittelyn aikana."),
        faq_item("Onko NullifyCV ilmainen?",
            "Kyllä — peruskäyttö on täysin ilmainen ilman tiliä. Maksulliset suunnitelmat alkavat 1,99 dollarista (kertamaksu) työnhakijoille ja nousevat 49 dollariin kuukaudessa HR-tiimeille, joilla on eräkäsittely, tallennetut profiilit ja GDPR-tarkistuslokit."),
        faq_item("Mitä tiedostomuotoja tuetaan?",
            "PDF ja DOCX ovat täysin tuettuja. Tekstikerroksella varustetuissa PDF-tiedostoissa mustat peitepalkit piirretään suoraan alkuperäiseen tiedostoon säilyttäen asettelu. Skannatut PDF-tiedostot tulee ensin viedä DOCX-muodossa."),
        faq_item("Onko NullifyCV GDPR-yhteensopiva?",
            "NullifyCV tukee GDPR:n tietojen minimointiperiaatteita Art. 5(1)(c) mukaisesti. Paikallinen käsittely tarkoittaa, että henkilötietoja ei siirretä tai tallenneta. Ota yhteyttä tietosuojavastaavaasi virallista arviointia varten."),
        faq_item("Voiko useita ansioluetteloita käsitellä kerralla?",
            "Eräkäsittely jopa 200 tiedostolle samanaikaisesti on saatavilla Pro-suunnitelmassa 49 dollaria kuukaudessa, mukaan lukien tallennetut poistoprofiilit ja GDPR-annotoidut tarkistuslokit."),
    ]),
    cta_box_title="Valmis aloittamaan?",
    cta_box_sub="Ilmainen, ei vaadita tiliä. Käsittele ensimmäinen ansioluettelosi alle 30 sekunnissa.",
    cta_box_btn="Kokeile ilmaiseksi →",
    footer=CANONICAL_FOOTER.replace("How it works","Miten se toimii").replace(
        "Glossary","Sanasto").replace(
        "No uploads · No storage · No tracking · GDPR-consistent · Not legal advice",
        "Ei latauksia · Ei tallennusta · Ei seurantaa · GDPR-yhteensopiva · Ei oikeudellista neuvontaa"),
)

# Render new pages
for slug in ['uk','ca','kr','se','fi']:
    data = pages[slug]
    html = TEMPLATE.format(**data)
    path = out_dir / f'{slug}.html'
    path.write_text(html)
    print(f"✓ {slug}.html  ({len(html):,} bytes)")

print(f"\nAll pages written successfully.")
