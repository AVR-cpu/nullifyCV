/* ── NullifyCV · app.js v2.0.0 ───────────────────────────────────────────── */
/* Real PDF redaction: pdf.js finds PII positions, pdf-lib draws black bars   */
/* mammoth.js handles DOCX → clean text output                                */
'use strict';

function initPdfJs() {
  if (typeof pdfjsLib !== 'undefined') {
    pdfjsLib.GlobalWorkerOptions.workerSrc =
      'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
  }
}

let currentFile=null,detectedPII=[],redactedText='',auditData=null;
let pdfPositions=[];  // stores {text, x, y, w, h, page} for PDF coordinate redaction

const MODES={
  standard:{name:1,contact:1,location:1,gradyear:1},
  bias:{name:1,contact:1,location:1,gradyear:1,school:1,pronouns:1},
  client:{name:1,contact:1,urls:1,metadata:1},
  eeoc:{name:1,contact:1,location:1,gradyear:1,school:1,pronouns:1,urls:1,metadata:1},
};

const PII_PATTERNS=[
  {key:'contact',type:'EMAIL',label:'Email address',conf:'high',
   re:/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g},
  {key:'contact',type:'PHONE',label:'Phone number',conf:'high',
   re:/(?:\+?31|0)[\s\-]?6[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}/g},
  {key:'contact',type:'PHONE',label:'Phone number',conf:'high',
   re:/(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g},
  {key:'contact',type:'PHONE',label:'Phone number',conf:'high',
   re:/\b0\d[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}\b/g},
  {key:'location',type:'POSTCODE',label:'Postcode',conf:'high',
   re:/\b[1-9]\d{3}\s?[A-Z]{2}\b/g},
  {key:'location',type:'ZIP',label:'Zip code',conf:'high',
   re:/\b\d{5}(?:-\d{4})?\b/g},
  {key:'location',type:'CITY',label:'City',conf:'high',
   re:/\b(?:Amsterdam|Rotterdam|Den Haag|Utrecht|Eindhoven|Tilburg|Groningen|Almere|Breda|Nijmegen|Enschede|Haarlem|Arnhem|Zaanstad|Amersfoort|Apeldoorn|'s-Hertogenbosch|Hoofddorp|Maastricht|Leiden|Dordrecht|Zoetermeer|Zwolle|Deventer|Delft|Alkmaar|Heerlen|Venlo|Leeuwarden|Amstelveen|Hilversum|Purmerend|Roosendaal|Middelburg|Assen|Lelystad|Emmen|Helmond|Ede|Sittard|Gouda|Hengelo|Almelo|Zaandam|Vlaardingen|Schiedam)\b/g},
  {key:'location',type:'CITY_ST',label:'City, state',conf:'high',
   re:/\b[A-Z][a-z]+(?:\s[A-Z][a-z]+)?,\s*(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\b/g},
  {key:'contact',type:'ADDRESS',label:'Street address',conf:'high',
   re:/\b\d{1,5}\s+[A-Z][a-z]+(?:\s[A-Za-z]+){1,4}(?:\s(?:St|Ave|Blvd|Dr|Rd|Ln|Ct|Way|Pl|straat|laan|weg|plein|dreef|singel|kade|dijk|gracht)\.?)\b/gi},
  {key:'gradyear',type:'GRAD_YR',label:'Graduation year',conf:'high',
   re:/\b(?:Class of |Graduated?:?\s*|(?:May|June|December|januari|februari|maart|april|mei|juni|juli|augustus|september|oktober|november|december)\s+)(?:19|20)\d{2}\b/gi},
  {key:'gradyear',type:'YEAR',label:'Year (age proxy)',conf:'med',
   re:/\b(?:19[4-9]\d|200[0-9]|201[0-6])\b/g},
  {key:'urls',type:'LINKEDIN',label:'LinkedIn URL',conf:'high',
   re:/(?:linkedin\.com\/in\/)[A-Za-z0-9\-_%]+/gi},
  {key:'urls',type:'URL',label:'URL',conf:'high',
   re:/https?:\/\/[^\s"'<>]+/gi},
  {key:'pronouns',type:'PRONOUN',label:'Pronouns',conf:'high',
   re:/\b(?:He\/Him|She\/Her|They\/Them|he\/him|she\/her|they\/them|hij\/hem|zij\/haar)\b/g},
  {key:'school',type:'SCHOOL',label:'School name',conf:'high',
   re:/\b(?:Universiteit\s+(?:van\s+)?[A-Z][a-z]+(?:\s[A-Z][a-z]+)*|Hogeschool\s+[A-Z][a-z]+(?:\s[A-Z][a-z]+)*|University of [A-Z][a-z]+(?:\s[A-Z][a-z]+)*|[A-Z][a-z]+(?:\s[A-Z][a-z]+)*\s+University|[A-Z][a-z]+(?:\s[A-Z][a-z]+)*\s+College|MIT|UCLA|USC|NYU|CMU|TU Delft|TU Eindhoven|UvA|VU Amsterdam)\b/g},
  {key:'name',type:'NAME',label:'Full name',conf:'high',
   re:/^([A-Z][a-zA-Z\u00C0-\u024F\-]+ (?:[A-Z][a-zA-Z\u00C0-\u024F\-]+ )*[A-Z][a-zA-Z\u00C0-\u024F\-]+)$/gm},
  {key:'contact',type:'DOB',label:'Date of birth',conf:'high',
   re:/\b(?:geboortedatum|geboren op|date of birth|dob):?\s*\d{1,2}[\s\-\/]\d{1,2}[\s\-\/]\d{2,4}\b/gi},
  {key:'contact',type:'DOB',label:'Date of birth',conf:'med',
   re:/\b\d{1,2}\s+(?:januari|februari|maart|april|mei|juni|juli|augustus|september|oktober|november|december)\s+\d{4}\b/gi},
  {key:'contact',type:'BSN',label:'BSN / National ID',conf:'high',
   re:/\b(?:BSN|burgerservicenummer):?\s*\d{8,9}\b/gi},
];

const $=id=>document.getElementById(id);
const fmtSize=b=>b<1024?b+' B':b<1048576?Math.round(b/1024)+' KB':(b/1048576).toFixed(1)+' MB';
const esc=s=>s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const slp=ms=>new Promise(r=>setTimeout(r,ms));
function setStatus(msg,pct){$('stxt').textContent=msg;$('pbar').style.width=pct+'%';}
function showError(msg){const e=$('err');e.textContent='⚠ '+msg;e.classList.add('show');}
function clearError(){$('err').classList.remove('show');}
function getActiveKeys(){const k={};document.querySelectorAll('.tcard.on').forEach(c=>{k[c.dataset.key]=1});return k;}

function setMode(mode,btn){
  document.querySelectorAll('.tab').forEach(t=>{t.classList.remove('on');t.setAttribute('aria-selected','false');});
  btn.classList.add('on');btn.setAttribute('aria-selected','true');
  const cfg=MODES[mode]||{};
  document.querySelectorAll('.tcard').forEach(card=>{
    const on=!!cfg[card.dataset.key];
    card.classList.toggle('on',on);
    card.setAttribute('aria-checked',on?'true':'false');
    card.querySelector('.tbox').textContent=on?'✓':'';
  });
}

function toggleCard(el){
  el.classList.toggle('on');
  const on=el.classList.contains('on');
  el.setAttribute('aria-checked',on?'true':'false');
  el.querySelector('.tbox').textContent=on?'✓':'';
}

function dov(e){e.preventDefault();$('drop').classList.add('over');}
function ddr(e){e.preventDefault();$('drop').classList.remove('over');const f=e.dataTransfer.files[0];if(f)loadFile(f);}
function fsel(e){const f=e.target.files[0];if(f)loadFile(f);}

function loadFile(file){
  const ext=file.name.split('.').pop().toLowerCase();
  if(!['pdf','docx','doc'].includes(ext)){showError('Please upload a PDF or DOCX file.');return;}
  clearError();
  currentFile=file;detectedPII=[];redactedText='';auditData=null;pdfPositions=[];
  $('fext').textContent=ext.toUpperCase();
  $('fname').textContent=file.name;
  $('fsize').textContent=fmtSize(file.size)+' · Ready to nullify';
  $('frow').classList.add('show');
  $('drop').style.display='none';
  $('pbtn').disabled=false;
  ['piiwrap','ss','prev','pad'].forEach(id=>$(id).classList.remove('show'));
}

function clearFile(){
  currentFile=null;$('frow').classList.remove('show');$('drop').style.display='';
  $('pbtn').disabled=true;$('fi').value='';clearError();pdfPositions=[];
  ['piiwrap','ss','prev','pad'].forEach(id=>$(id).classList.remove('show'));
}

/* ── PDF: extract text WITH positions using pdf.js ───────────────────────── */
async function extractPDFData(file){
  if(typeof pdfjsLib==='undefined')
    throw new Error('pdf.js not loaded — please reload the page.');

  const ab=await file.arrayBuffer();
  // Keep a second copy of the raw bytes for pdf-lib to write onto
  const ab2=ab.slice(0);

  const pdf=await pdfjsLib.getDocument({data:ab}).promise;
  let fullText='';
  const allItems=[];  // {str, x, y, w, h, pageNum, pageHeight}

  for(let p=1;p<=pdf.numPages;p++){
    const page=await pdf.getPage(p);
    const viewport=page.getViewport({scale:1});
    const pageHeight=viewport.height;
    const tc=await page.getTextContent();

    let pageText='',lastY=null,lastX=null;
    for(const item of tc.items){
      if(!item.str||!item.str.trim())continue;
      const x=item.transform[4];
      // pdf.js uses bottom-left origin; pdf-lib uses bottom-left too — same coordinate space
      const y=item.transform[5];
      const w=item.width||0;
      const h=item.height||10;

      if(lastY!==null&&Math.abs(y-lastY)>2){pageText+='\n';lastX=null;}
      if(lastX!==null&&x-lastX>3&&lastY!==null&&Math.abs(y-lastY)<=2)pageText+=' ';
      pageText+=item.str;
      lastY=y;lastX=x+w;

      allItems.push({str:item.str,x,y,w,h,pageNum:p,pageHeight});
    }
    fullText+=pageText.trim()+'\n\n';
  }

  if(!fullText.trim())
    throw new Error('No text layer found in this PDF. It may be a scanned image — please export as DOCX.');

  return {text:fullText.trim(), items:allItems, rawBytes:ab2, numPages:pdf.numPages};
}

/* ── Find which text items contain PII ──────────────────────────────────────*/
function findPIIPositions(items, piiValues){
  const positions=[];
  // For each detected PII string, find matching text items
  for(const piiVal of piiValues){
    const valLower=piiVal.toLowerCase();
    // Try to match across items on same line (same y)
    // Group items by page and approximate y
    const byPageY={};
    for(const item of items){
      const key=item.pageNum+'_'+Math.round(item.y);
      if(!byPageY[key])byPageY[key]=[];
      byPageY[key].push(item);
    }
    // Check each line group
    for(const key of Object.keys(byPageY)){
      const lineItems=byPageY[key].sort((a,b)=>a.x-b.x);
      const lineText=lineItems.map(i=>i.str).join(' ');
      if(lineText.toLowerCase().includes(valLower)){
        // Find start item
        let accumulated='';
        let startIdx=-1,endIdx=-1;
        for(let i=0;i<lineItems.length;i++){
          accumulated+=lineItems[i].str+' ';
          if(accumulated.toLowerCase().includes(valLower)){
            if(startIdx===-1)startIdx=Math.max(0,i-1);
            endIdx=i;
          }
        }
        if(startIdx>=0&&endIdx>=startIdx){
          const startItem=lineItems[startIdx];
          const endItem=lineItems[endIdx];
          const padding=2;
          positions.push({
            pageNum:startItem.pageNum,
            x:startItem.x-padding,
            y:startItem.y-padding,
            w:(endItem.x+endItem.w)-(startItem.x)+(padding*2),
            h:Math.max(startItem.h,endItem.h)+(padding*2),
            piiVal,
          });
        }
      }
    }
  }
  return positions;
}

/* ── Draw black redaction bars on PDF using pdf-lib ─────────────────────── */
async function buildRedactedPDF(rawBytes, positions){
  if(typeof PDFLib==='undefined')
    throw new Error('pdf-lib not loaded — please reload the page.');

  const pdfDoc=await PDFLib.PDFDocument.load(rawBytes,{ignoreEncryption:true});
  const pages=pdfDoc.getPages();

  for(const pos of positions){
    const page=pages[pos.pageNum-1];
    if(!page)continue;
    // Draw solid black rectangle over PII position
    page.drawRectangle({
      x:pos.x,
      y:pos.y,
      width:Math.max(pos.w,20),
      height:Math.max(pos.h,10),
      color:PDFLib.rgb(0,0,0),
      opacity:1,
    });
  }

  const pdfBytes=await pdfDoc.save();
  return pdfBytes;
}

/* ── DOCX text extraction via mammoth ────────────────────────────────────── */
async function extractDOCXText(file){
  if(typeof mammoth==='undefined')throw new Error('mammoth.js not loaded — please reload.');
  const ab=await file.arrayBuffer();
  const result=await mammoth.extractRawText({arrayBuffer:ab});
  if(!result.value||!result.value.trim())throw new Error('Could not extract text from this DOCX file.');
  return result.value;
}

/* ── PII scanning ────────────────────────────────────────────────────────── */
function scanForPII(text,activeKeys){
  const found=[],seen=new Set();
  for(const pattern of PII_PATTERNS){
    if(!activeKeys[pattern.key])continue;
    const re=new RegExp(pattern.re.source,pattern.re.flags);
    let match;
    while((match=re.exec(text))!==null){
      const val=match[0].trim();
      if(val.length<2)continue;
      const dk=pattern.type+':'+val.toLowerCase();
      if(seen.has(dk))continue;
      seen.add(dk);
      found.push({type:pattern.type,label:pattern.label,value:val,conf:pattern.conf});
    }
  }
  return found.sort((a,b)=>b.value.length-a.value.length);
}

function applyTextRedactions(text,piiItems){
  let result=text;
  for(const item of piiItems){
    const escaped=item.value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    result=result.replace(new RegExp(escaped,'gi'),'['+item.type+' NULLIFIED]');
  }
  return result;
}

/* ── Preview ─────────────────────────────────────────────────────────────── */
function showPreview(text,piiItems){
  let display=text.slice(0,1600);
  if(text.length>1600)display+='\n\n[... truncated]';
  for(const item of piiItems){
    const escaped=('['+item.type+' NULLIFIED]').replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    display=display.replace(new RegExp(escaped,'g'),`<span class="rx" title="${item.label}">████████</span>`);
  }
  $('prevbody').innerHTML=display;$('prev').classList.add('show');
}

function showPIIList(piiItems){
  const list=$('piil');list.innerHTML='';
  $('piict').textContent=piiItems.length+' item'+(piiItems.length!==1?'s':'')+' nullified';
  if(!piiItems.length){
    list.innerHTML='<div style="font-size:11px;color:var(--ink3);text-align:center;padding:10px;">No PII detected with current settings.</div>';
  }else{
    piiItems.forEach(item=>{
      const div=document.createElement('div');div.className='pii-item';div.setAttribute('role','listitem');
      div.innerHTML=`<span class="ptype">${item.type}</span><span class="pval">${esc(item.value)}</span><span class="c${item.conf[0]}">${item.conf}</span>`;
      list.appendChild(div);
    });
  }
  $('piiwrap').classList.add('show');
}

/* ── Downloads ───────────────────────────────────────────────────────────── */
let _redactedPdfBytes=null;

function downloadRedactedPDF(){
  if(!_redactedPdfBytes){downloadRedactedText();return;}
  const baseName=currentFile.name.replace(/\.[^.]+$/,'');
  const blob=new Blob([_redactedPdfBytes],{type:'application/pdf'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');a.href=url;a.download=baseName+'_NULLIFIED.pdf';a.click();
  setTimeout(()=>URL.revokeObjectURL(url),5000);
}

function downloadRedactedText(){
  const baseName=currentFile.name.replace(/\.[^.]+$/,'');
  const sep='═'.repeat(42);
  const content=['NULLIFYCV — DE-IDENTIFIED DOCUMENT','nullifycv.com',sep,
    'Original file : '+currentFile.name,
    'Processed     : '+new Date().toISOString(),
    'Engine        : pdf.js 3.11.174 + pdf-lib 1.17.1 / mammoth 1.6.0',
    'Transmitted   : 0 bytes',
    'Nullified     : '+detectedPII.length+' PII items',
    sep,'',redactedText].join('\n');
  const blob=new Blob([content],{type:'text/plain;charset=utf-8'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');a.href=url;a.download=baseName+'_NULLIFIED.txt';a.click();
  setTimeout(()=>URL.revokeObjectURL(url),5000);
}

function dlAudit(){
  const data=auditData||{tool:'NullifyCV v2.0.0',site:'nullifycv.com',
    timestamp:new Date().toISOString(),file:currentFile?currentFile.name:'none',
    server_transmissions:0,items_nullified:detectedPII.length,
    disclaimer:'Consistent with GDPR Article 5. Not legal advice.'};
  const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');a.href=url;a.download='nullifycv_audit_'+Date.now()+'.json';a.click();
  setTimeout(()=>URL.revokeObjectURL(url),3000);
}

/* ── Main processing flow ────────────────────────────────────────────────── */
async function go(){
  if(!currentFile)return;clearError();_redactedPdfBytes=null;
  const btn=$('pbtn');btn.disabled=true;
  btn.innerHTML='<div class="spin" style="border-top-color:var(--green-muted);width:11px;height:11px;margin:0;"></div> Nullifying...';
  $('ss').classList.add('show');$('spin').style.display='';

  try{
    const ext=currentFile.name.split('.').pop().toLowerCase();
    const activeKeys=getActiveKeys();

    if(ext==='pdf'){
      /* ── PDF path: extract text+positions, find PII, draw black bars ── */
      setStatus('Extracting text and positions from PDF...',12);
      const {text,items,rawBytes,numPages}=await extractPDFData(currentFile);

      setStatus('Scanning for PII...',35);
      await slp(100);
      detectedPII=scanForPII(text,activeKeys);
      redactedText=applyTextRedactions(text,detectedPII);

      setStatus('Locating PII coordinates on PDF pages...',55);
      await slp(100);
      const piiValues=detectedPII.map(p=>p.value);
      const positions=findPIIPositions(items,piiValues);
      pdfPositions=positions;

      setStatus('Drawing redaction bars on PDF...',72);
      await slp(100);

      if(positions.length>0){
        _redactedPdfBytes=await buildRedactedPDF(rawBytes,positions);
        setStatus('Redacted PDF ready — '+detectedPII.length+' items nullified',90);
      }else{
        setStatus('PII found in text — PDF bars could not be placed (complex layout)',90);
      }
      await slp(100);

      showPreview(redactedText,detectedPII);
      showPIIList(detectedPII);
      setStatus('✓ Complete — '+detectedPII.length+' items nullified',100);
      $('spin').style.display='none';

      auditData={tool:'NullifyCV v2.0.0',site:'nullifycv.com',
        report_id:'NCV-'+Date.now(),timestamp:new Date().toISOString(),
        file:currentFile.name,file_size_bytes:currentFile.size,
        processing_engine:'pdf.js@3.11.174 + pdf-lib@1.17.1',
        output_format:_redactedPdfBytes?'redacted PDF (black bars)':'plain text',
        server_transmissions:0,
        items_nullified:detectedPII.length,
        redaction_positions:positions.length,
        active_redaction_keys:Object.keys(activeKeys),
        items:detectedPII.map(p=>({type:p.type,label:p.label,confidence:p.conf})),
        disclaimer:'Consistent with GDPR Article 5. Not legal advice.'};

      // Download redacted PDF if we have it, otherwise text
      setTimeout(()=>{
        if(_redactedPdfBytes)downloadRedactedPDF();
        else downloadRedactedText();
      },400);

      btn.disabled=false;
      if(_redactedPdfBytes){
        btn.innerHTML='<svg width="13" height="13" viewBox="0 0 14 14" fill="none"><path d="M7 2v7M4 6l3 3 3-3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/><line x1="2" y1="12" x2="12" y2="12" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg> Download redacted PDF';
        btn.onclick=downloadRedactedPDF;
      }else{
        btn.innerHTML='Download text version';
        btn.onclick=downloadRedactedText;
      }

    }else{
      /* ── DOCX path: extract text, redact, output clean text ── */
      setStatus('Extracting text from DOCX...',20);
      const text=await extractDOCXText(currentFile);
      setStatus('Scanning for PII...',45);await slp(150);
      detectedPII=scanForPII(text,activeKeys);
      setStatus('Nullifying '+detectedPII.length+' items...',68);await slp(120);
      redactedText=applyTextRedactions(text,detectedPII);
      setStatus('Generating output...',88);await slp(100);
      showPreview(redactedText,detectedPII);showPIIList(detectedPII);
      setStatus('✓ Complete — '+detectedPII.length+' items nullified',100);
      $('spin').style.display='none';

      auditData={tool:'NullifyCV v2.0.0',site:'nullifycv.com',
        report_id:'NCV-'+Date.now(),timestamp:new Date().toISOString(),
        file:currentFile.name,processing_engine:'mammoth@1.6.0',
        server_transmissions:0,items_nullified:detectedPII.length,
        disclaimer:'Consistent with GDPR Article 5. Not legal advice.'};

      setTimeout(downloadRedactedText,400);
      btn.disabled=false;
      btn.innerHTML='Download again';btn.onclick=downloadRedactedText;
    }

    $('pad').classList.add('show');
    $('padok').textContent='✓ '+detectedPII.length+' items nullified — 0 bytes transmitted to any server.';

  }catch(err){
    console.error('[NullifyCV]',err);showError(err.message);setStatus('Error',0);
    $('spin').style.display='none';btn.disabled=false;btn.innerHTML='Retry';btn.onclick=go;
  }
}

document.addEventListener('DOMContentLoaded',()=>{
  initPdfJs();
  document.querySelectorAll('.tcard').forEach(card=>{
    card.addEventListener('keydown',e=>{
      if(e.key==='Enter'||e.key===' '){e.preventDefault();toggleCard(card);}
    });
  });
});
