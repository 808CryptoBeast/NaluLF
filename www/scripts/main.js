import{a as Nr,b as bo,c as Tn,d as It,e as x,f as Be,g as y,h as Xe,i as _,j as W,k as Q,l as Z,m as vt,n as ve,o as ae,p as ge,q as Wt,r as B,s as ma,v as Me,w as Rr}from"./chunk-R7KFE7J7.js";function Cn(e){Tn.includes(e)||(e="gold"),B.currentTheme=e,Tn.forEach(t=>document.body.classList.remove(`theme-${t}`)),document.body.classList.add(`theme-${e}`),Z(bo,e)}function yo(){let e=Tn.indexOf(B.currentTheme);Cn(Tn[(e+1)%Tn.length])}function _r(){let e=Q(bo);Cn(Tn.includes(e)?e:"gold")}var Dr={landing:"landing-page",dashboard:"dashboard",inspector:"inspector",profile:"dashboard"};function wo(e){document.body.classList.remove("modal-open"),Object.values(Dr).forEach(i=>document.body.classList.remove(i)),document.body.classList.add(Dr[e]||"dashboard");let t=x("landing"),n=x("dashboard"),s=x("profile-page");t&&(t.style.display=e==="landing"?"":"none"),n&&(n.style.display=e==="dashboard"?"":"none"),s&&(s.style.display=e==="profile"?"":"none");let a=e==="landing",o={landingActions:x("navbar-landing-actions"),dashActions:x("navbar-dash-actions"),navConn:x("navbar-conn"),cmdkHint:x("cmdk-hint"),helpBtn:x("help-trigger")};o.landingActions&&(o.landingActions.style.display=a?"":"none"),o.dashActions&&(o.dashActions.style.display=a?"none":""),o.navConn&&(o.navConn.style.display=a?"none":""),o.cmdkHint&&(o.cmdkHint.style.display=a?"none":""),o.helpBtn&&(o.helpBtn.style.display=a?"none":""),B.currentPage=e,window.scrollTo({top:0,behavior:"smooth"}),window.dispatchEvent(new CustomEvent("naluxrp:pagechange",{detail:{pageId:e}}))}function Pn(){wo("landing")}function Ln(){wo("dashboard")}function xo(){wo("profile")}function Mn(e,t){Be(".dash-tab").forEach(n=>{n.classList.toggle("active",n===e),n.setAttribute("aria-selected",String(n===e))}),["stream","inspector","network"].forEach(n=>{let s=x(`tab-${n}`);s&&(s.style.display=n===t?"":"none")}),t==="inspector"?(document.body.classList.remove("dashboard"),document.body.classList.add("inspector")):(document.body.classList.remove("inspector"),document.body.classList.add("dashboard")),B.currentTab=t,window.dispatchEvent(new CustomEvent("naluxrp:tabchange",{detail:{tabId:t}}))}var Fr="naluxrp_tour_seen",an=[{title:"Welcome to NaluLF \u{1F30A}",body:"A 20-second tour of the three things people miss most. Skip anytime."},{selector:"#cmdk-hint",title:"Jump anywhere, instantly",body:"Press <kbd>Ctrl</kbd>+<kbd>K</kbd> (or <kbd>/</kbd>) from any page. Paste an address in and it offers to inspect it directly \u2014 no need to navigate first."},{selector:"#dash-tab-inspector",title:"Inspect any wallet",body:"Full forensic suite \u2014 trust lines, fund flow, convergence signals, AI-assisted explanations \u2014 for any XRPL address, not just your own."},{selector:".user-chip",title:"Your Profile has more than wallets",body:"Portfolio analytics, activity history, and Project Intelligence \u2014 liquidity depth, holder concentration, and issuer-risk scoring for any token \u2014 all live there."}],nt=0,$o=!1,Cs=null,Ft=null;function Or(){Q(Fr)||setTimeout(So,700)}function So(){$o||($o=!0,nt=0,ym(),To())}function ym(){if(x("tourOverlay"))return;let e=document.createElement("div");e.id="tourOverlay",e.className="tour-overlay",e.innerHTML='<div class="tour-card" id="tour-card"></div>',document.body.appendChild(e),e.addEventListener("click",t=>{t.target===e&&fa()})}function ko(e){if(!e)return null;let t=document.querySelector(e);if(!t)return null;let n=t.getBoundingClientRect();return n.width>0||n.height>0?t:null}function Br(){Cs==null||Cs.classList.remove("tour-highlight"),Cs=null}function To(){for(;nt<an.length&&an[nt].selector&&!ko(an[nt].selector);)nt++;if(nt>=an.length)return Co();let e=an[nt],t=x("tourOverlay"),n=x("tour-card");t.classList.add("show"),Br();let s=ko(e.selector);s&&(s.scrollIntoView({block:"center",behavior:"smooth"}),s.classList.add("tour-highlight"),Cs=s),n.innerHTML=`
    <div class="tour-step-count">${nt+1} / ${an.length}</div>
    <div class="tour-title">${e.title}</div>
    <div class="tour-body">${e.body}</div>
    <div class="tour-actions">
      <button class="tour-btn tour-btn--ghost" onclick="tourSkip()">Skip tour</button>
      <div class="tour-actions-right">
        ${nt>0?'<button class="tour-btn tour-btn--ghost" onclick="tourPrev()">Back</button>':""}
        <button class="tour-btn tour-btn--primary" onclick="tourNext()">${nt===an.length-1?"Done":"Next"}</button>
      </div>
    </div>`,Ir(s,n),Ft&&(window.removeEventListener("resize",Ft),window.removeEventListener("scroll",Ft,!0)),Ft=()=>Ir(ko(e.selector),n),window.addEventListener("resize",Ft),window.addEventListener("scroll",Ft,!0)}function Ir(e,t){if(!e){t.classList.add("tour-card--centered");return}t.classList.remove("tour-card--centered"),t.style.visibility="hidden",requestAnimationFrame(()=>{let n=e.getBoundingClientRect(),s=t.offsetWidth||320,a=t.offsetHeight||160,i=window.innerHeight-n.bottom>a+28?n.bottom+16:Math.max(16,n.top-a-16),r=n.left+n.width/2-s/2;r=Math.min(Math.max(16,r),window.innerWidth-s-16),t.style.top=`${i}px`,t.style.left=`${r}px`,t.style.visibility="visible"})}function Xr(){nt++,nt>=an.length?Co():To()}function Hr(){nt=Math.max(0,nt-1),To()}function fa(){Co()}function Co(){var e;$o=!1,Z(Fr,"1"),Br(),(e=x("tourOverlay"))==null||e.classList.remove("show"),Ft&&(window.removeEventListener("resize",Ft),window.removeEventListener("scroll",Ft,!0),Ft=null)}var Ot="naluxrp_vault_meta",Ut="naluxrp_vault_data",Jn="naluxrp_session",Lo="nalulf_used_names",Mo="nalulf_used_emails",Ao="nalulf_used_domains",Po=15e4,ha="naluxrp_v2",Ke={_key:null,_vault:null,_lockTimer:null,AUTO_LOCK_MS:30*60*1e3,get isUnlocked(){return this._key!==null&&this._vault!==null},get vault(){return this._vault},hasVault(){return!!Q(Ot)&&!!Q(Ut)},async create(e,t,n,s){let a=crypto.getRandomValues(new Uint8Array(32));this._key=await this._deriveKey(e,a);let o=(s||t).toLowerCase().replace(/[^a-z0-9_]/g,"");return this._vault={checksum:ha,identity:{name:t,email:n,domain:o,createdAt:new Date().toISOString()},profile:{},wallets:[],social:{}},Z(Ot,JSON.stringify({salt:Array.from(a),iterations:Po,version:ha})),await this._persist(),this._startLockTimer(),this._vault},async unlock(e){let t=ve(Q(Ot));if(!t)throw new Error("No account found. Create one first.");this._key=await this._deriveKey(e,new Uint8Array(t.salt));let n;try{let s=ve(Q(Ut));if(!s)throw new Error("missing");n=await this._decrypt(s)}catch{throw this._key=null,new Error("Incorrect password. Please try again.")}if((n==null?void 0:n.checksum)!==ha)throw this._key=null,new Error("Account data corrupted. Restore from backup.");return this._vault=n,this._startLockTimer(),this._vault},async update(e){if(!this.isUnlocked)throw new Error("Sign in to continue.");e(this._vault),await this._persist()},lock(){this._key=null,this._vault=null,clearTimeout(this._lockTimer),this._lockTimer=null},resetTimer(){this.isUnlocked&&this._startLockTimer()},async changePassword(e){if(!this.isUnlocked)throw new Error("Sign in first.");let t=crypto.getRandomValues(new Uint8Array(32));this._key=await this._deriveKey(e,t),Z(Ot,JSON.stringify({salt:Array.from(t),iterations:Po,version:ha})),await this._persist()},async exportBlob(){if(!this.isUnlocked)throw new Error("Sign in before exporting.");let e={vault:ve(Q(Ut)),meta:ve(Q(Ot)),exportedAt:new Date().toISOString()},t=URL.createObjectURL(new Blob([JSON.stringify(e,null,2)],{type:"application/json"}));Object.assign(document.createElement("a"),{href:t,download:`naluxrp-backup-${Date.now()}.json`}).click(),URL.revokeObjectURL(t)},async _deriveKey(e,t){let n=new TextEncoder,s=await crypto.subtle.importKey("raw",n.encode(e),"PBKDF2",!1,["deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt:t,iterations:Po,hash:"SHA-256"},s,{name:"AES-GCM",length:256},!1,["encrypt","decrypt"])},async _encrypt(e){let t=crypto.getRandomValues(new Uint8Array(12)),n=new TextEncoder,s=await crypto.subtle.encrypt({name:"AES-GCM",iv:t},this._key,n.encode(JSON.stringify(e)));return{iv:Array.from(t),cipher:Array.from(new Uint8Array(s))}},async _decrypt(e){let t=new TextDecoder,n=await crypto.subtle.decrypt({name:"AES-GCM",iv:new Uint8Array(e.iv)},this._key,new Uint8Array(e.cipher).buffer);return JSON.parse(t.decode(n))},async _persist(){!this._key||!this._vault||Z(Ut,JSON.stringify(await this._encrypt(this._vault)))},_startLockTimer(){clearTimeout(this._lockTimer),this._lockTimer=setTimeout(()=>{this.lock(),window.dispatchEvent(new CustomEvent("naluxrp:vault-locked"))},this.AUTO_LOCK_MS)}},lt=1;function No(e){var t;Ke.hasVault()?on(e||"login"):on("welcome"),(t=x("auth-overlay"))==null||t.classList.add("show")}function rn(){var e;(e=x("auth-overlay"))==null||e.classList.remove("show"),ln(),lt=1,An(1)}function on(e){var s,a,o,i,r;ya(".auth-view").forEach(l=>l.classList.remove("active")),(s=x(`auth-view-${e}`))==null||s.classList.add("active"),(a=x("auth-overlay"))==null||a.setAttribute("data-view",e);let t=["welcome","forgot","sync","celebrate","syncaware"].includes(e),n=x("auth-tab-row");n&&(n.style.display=t?"none":""),(o=x("tab-login-btn"))==null||o.classList.toggle("active",e==="login"),(i=x("tab-signup-btn"))==null||i.classList.toggle("active",e==="signup"),(r=x("tab-sync-btn"))==null||r.classList.toggle("active",e==="sync"),e==="signup"&&(lt=1,An(1),Gn()),ln()}function An(e){[1,2,3].forEach(s=>{let a=x(`signup-step-${s}`);a&&(a.style.display=s===e?"":"none");let o=x(`signup-dot-${s}`);o&&(o.classList.toggle("active",s===e),o.classList.toggle("done",s<e))});let t=["","Step 1 of 3 \u2014 Identity","Step 2 of 3 \u2014 Security","Step 3 of 3 \u2014 Sync setup"],n=x("signup-step-label");n&&(n.textContent=t[e]||"")}function Ro(){var e,t,n,s,a,o;if(ln(),lt===1){let i=((e=x("inp-signup-name"))==null?void 0:e.value.trim())||"",r=((t=x("inp-signup-email"))==null?void 0:t.value.trim())||"",l=((n=x("inp-signup-domain"))==null?void 0:n.value.trim())||"";if(!i||i.length<3)return Ae("Display name must be at least 3 characters.");if(qr(i))return Ae(`"${i}" is already in use on this device.`);if(!r||!r.includes("@"))return Ae("Enter a valid email address.");if(Vr(r))return Ae("That email is already registered on this device.");if(l&&Gr(l))return Ae(`@${l} is already taken on this device.`);if(l&&!/^[a-z0-9_]{2,30}$/.test(l))return Ae("Handle: 2-30 lowercase letters, numbers, underscores only.");lt=2,An(2),Gn(),setTimeout(()=>{var c;return(c=x("inp-signup-pass"))==null?void 0:c.focus()},80)}else if(lt===2){let i=((s=x("inp-signup-pass"))==null?void 0:s.value)||"",r=((a=x("inp-signup-confirm"))==null?void 0:a.value)||"";if(!i||i.length<8)return Ae("Password must be at least 8 characters.");if(!ol(i))return Ae("Add uppercase, lowercase, and a number.");if(i!==r)return Ae("Passwords do not match.");if(!jr())return Gn(),Ae("Type the word from the image exactly.");lt=3,An(3);let l=x("syncaware-name"),c=((o=x("inp-signup-name"))==null?void 0:o.value.trim())||"there";l&&(l.textContent=c.split(" ")[0])}}function Wr(){lt>1&&(lt--,An(lt),ln(),lt===1&&setTimeout(()=>{var e;return(e=x("inp-signup-name"))==null?void 0:e.focus()},80))}var zr=["XRPL","LEDGER","VAULT","CRYPTO","BLOCK","TOKEN","CHAIN","WAVE","ATLAS","FORGE","NEXUS","ORBIT","PRISM","DELTA","NOVA","SONIC","PIXEL","GHOST","FLARE","SPARK","TITAN","LUNAR","STORM","PROXY","CIPHER","RELAY","PULSE","SCOUT"],Eo="";function Gn(){Eo=zr[Math.floor(Math.random()*zr.length)];let e=document.getElementById("captcha-canvas"),t=x("inp-captcha");if(t&&(t.value=""),!e)return;let n=e.getContext("2d"),s=e.width,a=e.height;n.clearRect(0,0,s,a),n.fillStyle="#080f1e",n.fillRect(0,0,s,a),n.strokeStyle="rgba(0,255,240,.05)",n.lineWidth=1;for(let r=0;r<s;r+=18)n.beginPath(),n.moveTo(r,0),n.lineTo(r,a),n.stroke();for(let r=0;r<a;r+=18)n.beginPath(),n.moveTo(0,r),n.lineTo(s,r),n.stroke();for(let r=0;r<55;r++)n.fillStyle=`rgba(${Math.random()>.5?"0,255,240":"160,180,255"},${(Math.random()*.22+.05).toFixed(2)})`,n.beginPath(),n.arc(Math.random()*s,Math.random()*a,Math.random()*2+.5,0,Math.PI*2),n.fill();for(let r=0;r<4;r++)n.strokeStyle=`rgba(0,255,240,${(Math.random()*.1+.03).toFixed(2)})`,n.lineWidth=1,n.beginPath(),n.moveTo(0,Math.random()*a),n.bezierCurveTo(s*.3,Math.random()*a,s*.7,Math.random()*a,s,Math.random()*a),n.stroke();let o=Eo.split(""),i=(s-o.length*26)/2+8;o.forEach((r,l)=>{let c=i+l*26+(Math.random()*8-4),d=a/2+8+(Math.random()*10-5);n.save(),n.translate(c,d),n.rotate(Math.random()*.35-.175),n.shadowColor="rgba(0,255,240,.5)",n.shadowBlur=8,n.fillStyle=`rgb(${Math.random()>.4?"180,255,240":"140,200,255"})`,n.font=`bold ${24+Math.random()*4}px 'JetBrains Mono','Courier New',monospace`,n.fillText(r,0,0),n.restore()})}function Ur(){Gn()}function jr(){var e;return(((e=x("inp-captcha"))==null?void 0:e.value)||"").trim().toUpperCase()===Eo}function qr(e){return(ve(Q(Lo))||[]).some(t=>t.toLowerCase()===e.toLowerCase())}function Vr(e){return(ve(Q(Mo))||[]).some(t=>t.toLowerCase()===e.toLowerCase())}function Gr(e){return(ve(Q(Ao))||[]).some(t=>t.toLowerCase()===e.toLowerCase())}function wm(e,t,n){let s=ve(Q(Lo))||[],a=ve(Q(Mo))||[],o=ve(Q(Ao))||[];s.includes(e.toLowerCase())||s.push(e.toLowerCase()),a.includes(t.toLowerCase())||a.push(t.toLowerCase()),n&&!o.includes(n.toLowerCase())&&o.push(n.toLowerCase()),Z(Lo,JSON.stringify(s)),Z(Mo,JSON.stringify(a)),Z(Ao,JSON.stringify(o))}async function _o(){var s,a,o;if(jt)return;let e=((s=x("inp-login-email"))==null?void 0:s.value.trim())||"",t=((a=x("inp-login-pass"))==null?void 0:a.value)||"";if(ln(),!e)return Ae("Enter your email address.");if(!t)return Ae("Enter your password.");let n=x("signin-btn");jt=!0,Kn(n,!0,"Signing in\u2026");try{let i=await Ke.unlock(t);B.session={name:i.identity.name,email:i.identity.email,domain:i.identity.domain||""},Z(Jn,JSON.stringify(B.session)),rn(),ba(B.session),Ln(),ma(),window.dispatchEvent(new CustomEvent("naluxrp:vault-ready",{detail:Ke.vault})),$m()}catch(i){Ae(i.message),(o=x("auth-modal-inner"))==null||o.classList.add("shake"),setTimeout(()=>{var r;return(r=x("auth-modal-inner"))==null?void 0:r.classList.remove("shake")},500)}finally{jt=!1,Kn(n,!1,"Sign In \u2192")}}async function Do(){var i,r,l,c,d;if(jt)return;let e=((i=x("inp-signup-name"))==null?void 0:i.value.trim())||"",t=((r=x("inp-signup-email"))==null?void 0:r.value.trim())||"",n=((l=x("inp-signup-domain"))==null?void 0:l.value.trim())||e.toLowerCase().replace(/[^a-z0-9_]/g,"_"),s=((c=x("inp-signup-pass"))==null?void 0:c.value)||"",a=((d=x("inp-signup-confirm"))==null?void 0:d.value)||"";if(ln(),!s||s.length<8)return Ae("Password must be at least 8 characters.");if(!ol(s))return Ae("Add uppercase, lowercase, and a number.");if(s!==a)return Ae("Passwords do not match.");if(!jr())return Gn(),lt=2,An(2),Ae("Type the word from the image exactly.");let o=x("signup-btn");jt=!0,Kn(o,!0,"Creating vault\u2026");try{await Ke.create(s,e,t,n),wm(e,t,n),B.session={name:e,email:t,domain:n},Z(Jn,JSON.stringify(B.session)),ba(B.session),xm(e,()=>{rn(),Ln(),ma(),window.dispatchEvent(new CustomEvent("naluxrp:vault-ready",{detail:Ke.vault})),Or(),setTimeout(Sm,3500)})}catch(u){Ae(u.message),Gn(),lt=2,An(2)}finally{jt=!1,Kn(o,!1,"Create Account \u2192")}}function xm(e,t){on("celebrate");let n=x("celebrate-name");n&&(n.textContent=e.split(" ")[0]);let s=setTimeout(t,2800),a=x("celebrate-continue-btn");a&&(a.onclick=()=>{clearTimeout(s),t()})}function Kr(){on("forgot"),ya(".forgot-step").forEach(t=>t.style.display="none");let e=x("forgot-step-options");e&&(e.style.display="")}function Jr(){let e=document.createElement("input");e.type="file",e.accept=".json,application/json",e.onchange=async t=>{let n=t.target.files[0];if(n)try{let s=await n.text(),a=JSON.parse(s);if(!(a!=null&&a.vault)||!(a!=null&&a.meta))throw new Error("Invalid backup file.");Z(Ut,JSON.stringify(a.vault)),Z(Ot,JSON.stringify(a.meta)),ae("Backup restored \u2014 sign in with your original password."),on("login")}catch(s){Wt("Could not read backup: "+s.message)}},e.click()}function Yr(){ya(".forgot-step").forEach(n=>n.style.display="none");let e=x("forgot-step-wipe");e&&(e.style.display="");let t=x("inp-wipe-confirm");t&&(t.value="")}function Qr(){var t;if((((t=x("inp-wipe-confirm"))==null?void 0:t.value.trim())||"")!=="DELETE")return Ae("Type DELETE exactly.");vt(Ot),vt(Ut),vt(Jn),Ke.lock(),B.session=null,ae("Account cleared. Create a new one."),rn(),on("signup"),window.dispatchEvent(new Event("naluxrp:logout"))}function Zr(){ya(".forgot-step").forEach(t=>t.style.display="none");let e=x("forgot-step-options");e&&(e.style.display=""),ln()}function el(){let e=Q(Ut),t=Q(Ot);if(!e||!t){Wt("No vault to export.");return}let n=btoa(JSON.stringify({vault:JSON.parse(e),meta:JSON.parse(t)})),s=document.createElement("div");s.id="sync-code-overlay",s.style.cssText="position:fixed;inset:0;background:rgba(0,0,0,.92);backdrop-filter:blur(14px);z-index:99999;display:flex;align-items:center;justify-content:center;padding:20px;",s.innerHTML=`<div style="background:#0d1829;border:1.5px solid rgba(0,255,240,.22);border-radius:22px;padding:28px;max-width:500px;width:100%;box-shadow:0 28px 70px rgba(0,0,0,.95);"><div style="font-size:1rem;font-weight:900;margin-bottom:6px;color:#00fff0;">\u{1F4F1} Vault Sync Code</div><p style="font-size:.82rem;color:rgba(255,255,255,.55);margin-bottom:16px;line-height:1.6;">On your new device open NaluLF \u2192 <strong style="color:rgba(255,255,255,.8)">\u{1F4F1} New Device</strong> tab, paste this code and enter your password.</p><textarea readonly id="sync-code-output" style="width:100%;height:110px;background:#060e1a;border:1px solid rgba(255,255,255,.12);border-radius:10px;color:rgba(0,255,240,.85);font-family:monospace;font-size:.7rem;padding:10px;resize:none;box-sizing:border-box;" spellcheck="false">${n}</textarea><div style="display:flex;gap:10px;margin-top:14px;justify-content:flex-end;"><button onclick="document.getElementById('sync-code-overlay').remove()" style="padding:9px 16px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);border-radius:9px;color:rgba(255,255,255,.65);font-size:.85rem;font-weight:700;cursor:pointer;font-family:inherit;">Close</button><button onclick="navigator.clipboard.writeText(document.getElementById('sync-code-output').value).then(()=>{this.textContent='\u2713 Copied!';setTimeout(()=>this.textContent='Copy Code',2000)})" style="padding:9px 18px;background:linear-gradient(135deg,#00d4ff,#00fff0);border:none;border-radius:9px;color:#000;font-size:.85rem;font-weight:900;cursor:pointer;font-family:inherit;">Copy Code</button></div></div>`,document.body.appendChild(s),s.addEventListener("click",a=>{a.target===s&&s.remove()})}async function Io(){var s,a;if(jt)return;let e=((s=x("inp-sync-code"))==null?void 0:s.value.trim())||"",t=((a=x("inp-sync-pass"))==null?void 0:a.value)||"";if(ln(),!e)return Ae("Paste your vault sync code or load a backup file first.");if(!t)return Ae("Enter the password from your original device.");let n=document.querySelector("#auth-view-sync .auth-submit-btn");jt=!0,Kn(n,!0,"Importing\u2026");try{let o;try{o=JSON.parse(atob(e))}catch{try{o=JSON.parse(e)}catch{throw new Error("Invalid sync code. Paste the full code from your other device.")}}if(!(o!=null&&o.vault)||!(o!=null&&o.meta))throw new Error("Invalid sync code format \u2014 make sure you copied the entire code.");Z(Ut,JSON.stringify(o.vault)),Z(Ot,JSON.stringify(o.meta));let i=await Ke.unlock(t);B.session={name:i.identity.name,email:i.identity.email,domain:i.identity.domain||""},Z(Jn,JSON.stringify(B.session)),rn(),ba(B.session),Ln(),ma(),window.dispatchEvent(new CustomEvent("naluxrp:vault-ready",{detail:Ke.vault})),ae("\u2705 Account imported to this device!")}catch(o){let i=o.message.includes("decrypt")||o.message.includes("Incorrect");Ae(i?"Wrong password \u2014 use the password from your original device.":"Could not import: "+o.message),vt(Ut),vt(Ot)}finally{jt=!1,Kn(n,!1,"Import & Sign In \u2192")}}function tl(){let e=document.createElement("input");e.type="file",e.accept=".json,application/json",e.onchange=async t=>{var s;let n=t.target.files[0];if(n)try{let a=await n.text(),o=JSON.parse(a);if(!(o!=null&&o.vault)||!(o!=null&&o.meta))throw new Error("Invalid backup file format.");let i=x("inp-sync-code");i&&(i.value=btoa(JSON.stringify({vault:o.vault,meta:o.meta})));let r=x("sync-file-feedback");r&&(r.textContent=`\u2713 File loaded: ${n.name}`,r.style.color="#50fa7b"),(s=x("inp-sync-pass"))==null||s.focus()}catch(a){Wt("Could not read backup: "+a.message)}},e.click()}function nl(){Ke.lock(),B.session=null,vt(Jn),Pn(),window.dispatchEvent(new Event("naluxrp:logout"))}function sl(){let e=ve(Q(Jn));return e!=null&&e.email&&Ke.hasVault()?(B.session=e,ba(e),!0):!1}function km(){if(x("vault-lock-banner"))return;let e=document.createElement("div");e.id="vault-lock-banner",e.className="vault-lock-banner",e.innerHTML=`<span class="vlb-icon">\u{1F512}</span><span class="vlb-text">Vault locked for security after 30 min of inactivity.</span><button class="vlb-btn" onclick="openAuth('login')">Unlock \u2192</button><button class="vlb-close" onclick="this.closest('.vault-lock-banner').remove()" title="Dismiss">\u2715</button>`,document.body.prepend(e),requestAnimationFrame(()=>e.classList.add("show"))}function $m(){let e=x("vault-lock-banner");e&&(e.classList.remove("show"),setTimeout(()=>e.remove(),300))}function Sm(){if(x("backup-reminder-banner")||!Ke.hasVault())return;let e=document.createElement("div");e.id="backup-reminder-banner",e.className="backup-reminder-banner",e.innerHTML=`<span class="brb-icon">\u26A0\uFE0F</span><div class="brb-body"><strong>Back up your vault</strong> \u2014 you'll lose access if browser storage is cleared. <button class="brb-btn" onclick="window.exportVaultBackup?.()">Export Backup</button></div><button class="brb-close" onclick="this.closest('.backup-reminder-banner').remove()">\u2715</button>`;let t=document.getElementById("profile-page");t?t.prepend(e):document.body.prepend(e),requestAnimationFrame(()=>e.classList.add("show"))}function al(e){var n;let t=((n=x("auth-overlay"))==null?void 0:n.getAttribute("data-view"))||"login";if(e.key==="Enter"&&(t==="login"&&_o(),t==="signup"&&(lt<3?Ro():Do()),t==="sync"&&Io()),e.key==="Tab"){let s=x("auth-modal-inner");if(!s)return;let a=Array.from(s.querySelectorAll("button:not([disabled]),input,textarea,select")).filter(r=>r.offsetParent!==null);if(!a.length)return;let o=a[0],i=a[a.length-1];e.shiftKey&&document.activeElement===o&&(e.preventDefault(),i.focus()),!e.shiftKey&&document.activeElement===i&&(e.preventDefault(),o.focus())}}function ga(e){let t=x(e);t==null||t.classList.add("valid"),t==null||t.classList.remove("invalid")}function En(e){let t=x(e);t==null||t.classList.add("invalid"),t==null||t.classList.remove("valid")}function va(e){let t=x(e);t==null||t.classList.remove("valid","invalid")}window.validateSignupName=()=>{var s;let e=((s=x("inp-signup-name"))==null?void 0:s.value.trim())||"",t=x("hint-signup-name");if(!e){va("inp-signup-name"),t&&(t.textContent="");return}if(e.length<3){En("inp-signup-name"),t&&(t.textContent="At least 3 characters");return}if(qr(e)){En("inp-signup-name"),t&&(t.textContent="Already in use on this device");return}ga("inp-signup-name"),t&&(t.textContent="\u2713 Looks good!");let n=x("inp-signup-domain");n&&!n.dataset.manuallyEdited&&(n.value=e.toLowerCase().replace(/[^a-z0-9]/g,"_").replace(/_+/g,"_").replace(/^_|_$/g,""),window.validateSignupDomain())};window.validateSignupEmail=()=>{var n;let e=((n=x("inp-signup-email"))==null?void 0:n.value.trim())||"",t=x("hint-signup-email");if(!e){va("inp-signup-email"),t&&(t.textContent="");return}if(!e.includes("@")||!e.includes(".")){En("inp-signup-email"),t&&(t.textContent="Enter a valid email");return}if(Vr(e)){En("inp-signup-email"),t&&(t.textContent="Already registered on this device");return}ga("inp-signup-email"),t&&(t.textContent="\u2713 Available")};window.validateSignupDomain=()=>{var s;let e=((s=x("inp-signup-domain"))==null?void 0:s.value.trim())||"",t=x("hint-signup-domain"),n=x("inp-signup-domain");if(!e){va("inp-signup-domain"),t&&(t.textContent="");return}if(!/^[a-z0-9_]{2,30}$/.test(e)){En("inp-signup-domain"),t&&(t.textContent="2-30 chars: a-z, 0-9, underscore only");return}if(Gr(e)){En("inp-signup-domain"),t&&(t.textContent="Already taken on this device");return}ga("inp-signup-domain"),t&&(t.textContent=`\u2713 @${e}`),n&&(n.dataset.manuallyEdited="1")};window.validateLoginEmail=()=>{var t;let e=((t=x("inp-login-email"))==null?void 0:t.value.trim())||"";if(!e)return va("inp-login-email");e.includes("@")?ga("inp-login-email"):En("inp-login-email")};window.switchSyncMethod=function(e){var i,r;let t=e==="code";(i=document.getElementById("sync-method-code"))==null||i.classList.toggle("sync-method-card--active",t),(r=document.getElementById("sync-method-file"))==null||r.classList.toggle("sync-method-card--active",!t);let n=document.getElementById("sync-code-section"),s=document.getElementById("sync-file-section"),a=document.getElementById("sync-method-code-steps"),o=document.getElementById("sync-method-file-steps");n&&(n.style.display=t?"":"none"),s&&(s.style.display=t?"none":""),a&&(a.style.display=t?"":"none"),o&&(o.style.display=t?"none":"")};window.togglePwVisibility=function(e,t){let n=x(e);if(!n)return;let s=n.type==="password";n.type=s?"text":"password",t.textContent=s?"\u{1F648}":"\u{1F441}"};window.updatePwStrength=function(e){let t=x("pw-strength-fill"),n=x("pw-strength-label");if(!t||!n)return;let s=0;e.length>=8&&s++,/[A-Z]/.test(e)&&s++,/[a-z]/.test(e)&&s++,/[0-9]/.test(e)&&s++,/[^A-Za-z0-9]/.test(e)&&s++;let a=[{w:"0%",bg:"transparent",txt:""},{w:"20%",bg:"#ff5555",txt:"Very weak"},{w:"40%",bg:"#ff8c42",txt:"Weak"},{w:"60%",bg:"#ffb86c",txt:"Fair"},{w:"80%",bg:"#00d4ff",txt:"Good"},{w:"100%",bg:"#50fa7b",txt:"Strong \u2713"}],o=a[s]||a[0];t.style.width=o.w,t.style.background=o.bg,n.textContent=o.txt,n.style.color=o.bg};function ol(e){return/[A-Z]/.test(e)&&/[a-z]/.test(e)&&/[0-9]/.test(e)}function ba(e){let t=x("user-avatar"),n=x("user-name");t&&(t.textContent=e.name.charAt(0).toUpperCase()),n&&(n.textContent=e.name)}function Ae(e){let t=x("auth-error");t&&(t.textContent=e,t.style.display="")}function ln(){let e=x("auth-error");e&&(e.textContent="")}function Kn(e,t,n){e&&(e.disabled=t,e.textContent=n)}var jt=!1;function ya(e){return Array.from(document.querySelectorAll(e))}["click","keydown","mousemove","touchstart"].forEach(e=>document.addEventListener(e,()=>Ke.resetTimer(),{passive:!0}));window.addEventListener("naluxrp:vault-locked",()=>{B.vaultLocked=!0,km()});var Tm="https://xrplcluster.com/",Cm="https://s2.ripple.com:51234/";async function wa(e,t){var a;try{if(((a=B.wsConn)==null?void 0:a.readyState)===1){let o=await Me({command:e,...t});if((o==null?void 0:o.status)==="error")throw new Error(o.error_message||o.error||"XRPL RPC error");return(o==null?void 0:o.result)||null}}catch{}let n=JSON.stringify({method:e,params:[t]}),s=async o=>{let i=await fetch(o,{method:"POST",headers:{"Content-Type":"application/json"},body:n,mode:"cors"});if(!i.ok)throw new Error(`HTTP ${i.status}`);return(await i.json()).result};try{return await s(Tm)}catch{return await s(Cm)}}function Qn(e){return typeof e=="string"?{value:Number(e)/1e6,isXrp:!0,currency:"XRP"}:e&&typeof e=="object"?{value:Number(e.value||0),isXrp:!1,currency:e.currency,issuer:e.issuer}:{value:0,isXrp:!0,currency:"XRP"}}function Pm(e){let t=String(e||"").trim().toUpperCase();if(t==="XRP"||/^[A-Z0-9?!@#$%^&*(){}[\]|]{3}$/i.test(t)||/^[0-9A-F]{40}$/.test(t))return t;let n=new TextEncoder().encode(t).slice(0,20),s=new Uint8Array(20);return s.set(n),Array.from(s).map(a=>a.toString(16).padStart(2,"0")).join("").toUpperCase()}var cn={lsfRequireAuth:262144,lsfDisableMaster:1048576,lsfNoFreeze:2097152,lsfGlobalFreeze:4194304,lsfDefaultRipple:8388608,lsfAllowTrustLineClawback:2147483648};async function Lm(e,t){var n;try{let s=await wa("amm_info",{asset:{currency:"XRP"},asset2:{currency:e,issuer:t}}),a=s==null?void 0:s.amm;if(!a)return{exists:!1};let o=Qn(a.amount).value,i=Qn(a.amount2).value,r=Qn(a.lp_token||a.lp_token_balance).value,l=((n=a.lp_token||a.lp_token_balance)==null?void 0:n.currency)||null;return{exists:!0,account:a.account,xrpReserve:o,tokenReserve:i,lpSupply:r,lpCurrency:l,tradingFeePct:Number(a.trading_fee||0)/1e3,auctionSlot:a.auction_slot?{account:a.auction_slot.account,discountedFeePct:Number(a.auction_slot.discounted_fee||0)/1e3,priceXrp:Qn(a.auction_slot.price).value,expiration:a.auction_slot.expiration||null}:null,voteSlots:Array.isArray(a.vote_slots)?a.vote_slots.map(c=>({account:c.account,tradingFeePct:Number(c.trading_fee||0)/1e3,voteWeight:Number(c.vote_weight||0)/1e3})):[]}}catch{return{exists:!1,error:!0}}}async function Mm(e){try{let t=await wa("account_info",{account:e,ledger_index:"validated"}),n=t==null?void 0:t.account_data;if(!n)return{exists:!1};let s=Number(n.Flags||0),a=o=>(s&o)===o;return{exists:!0,requireAuth:a(cn.lsfRequireAuth),globalFreeze:a(cn.lsfGlobalFreeze),noFreeze:a(cn.lsfNoFreeze),freezeCapable:!a(cn.lsfNoFreeze),defaultRipple:a(cn.lsfDefaultRipple),clawbackEnabled:a(cn.lsfAllowTrustLineClawback),blackholed:a(cn.lsfDisableMaster)&&!n.RegularKey,masterDisabled:a(cn.lsfDisableMaster),hasRegularKey:!!n.RegularKey}}catch{return{exists:!1,error:!0}}}async function ll(e,t,n=8){let s=[],a;for(let o=0;o<n;o++){let i=await wa("account_lines",{account:e,ledger_index:"validated",limit:400,...a?{marker:a}:{}});for(let r of(i==null?void 0:i.lines)||[]){if(r.currency!==t)continue;let l=-Number(r.balance||0);l>0&&s.push({address:r.account,balance:l})}if(a=i==null?void 0:i.marker,!a)break}return s}function cl(e){let t=[...e].sort((a,o)=>o.balance-a.balance),n=t.reduce((a,o)=>a+o.balance,0),s=a=>n>0?t.slice(0,a).reduce((o,i)=>o+i.balance,0)/n*100:0;return{holderCount:t.length,totalSampled:n,top1Pct:s(1),top5Pct:s(5),top10Pct:s(10),topHolders:t.slice(0,10)}}async function Am(e,t){try{let n=await ll(e,t);return n.length?{exists:!0,...cl(n),sampleOnly:!0}:{exists:!1}}catch{return{exists:!1,error:!0}}}async function Em(e,t){if(!e||!t)return{exists:!1};try{let n=await ll(e,t);return n.length?{exists:!0,...cl(n)}:{exists:!1}}catch{return{exists:!1,error:!0}}}var Nm=[1,2,5,10,25];async function il(e,t,n){let o=await wa("book_offers",{taker_gets:n==="buy"?{currency:e,issuer:t}:{currency:"XRP"},taker_pays:n==="buy"?{currency:"XRP"}:{currency:e,issuer:t},limit:200,ledger_index:"validated"});return((o==null?void 0:o.offers)||[]).map(r=>{let l=Qn(r.taker_gets_funded??r.TakerGets).value,c=Qn(r.taker_pays_funded??r.TakerPays).value;return l<=0||c<=0?null:{gets:l,pays:c,quality:c/l}}).filter(Boolean).sort((r,l)=>r.quality-l.quality)}function rl(e){if(!e.length)return{bestPrice:null,levels:[]};let t=e[0].quality,n=Nm.map(s=>{let a=t*(1+s/100),o=0,i=0,r=!0;for(let l of e){if(l.quality>a){r=!1;break}o+=l.pays,i+=l.gets}return{pct:s,xrpAtOffer:o,tokenAtOffer:i,bookExhausted:r}});return{bestPrice:t,levels:n}}async function Rm(e,t){try{let[n,s]=await Promise.all([il(e,t,"buy"),il(e,t,"sell")]);if(!n.length&&!s.length)return{exists:!1};let a=rl(s.map(l=>({...l,gets:l.pays,pays:l.gets}))),o=rl(n),i=a.bestPrice?1/a.bestPrice:null,r=o.bestPrice&&i?(o.bestPrice-i)/i*100:null;return{exists:!0,buySideOfferCount:n.length,sellSideOfferCount:s.length,buyPriceXrp:o.bestPrice,sellPriceXrp:i,spreadPct:r,buyDepth:o.levels,sellDepth:a.levels}}catch{return{exists:!1,error:!0}}}var Fo={liquidity:31.25,distribution:18.75,marketQuality:18.75,lpStability:18.75,issuerRisk:12.5};function dl(e){return Math.max(0,Math.min(100,e))}function Yn(e,t,n){return n===t?0:dl((e-t)/(n-t)*100)}function _m({amm:e,orderBook:t,holders:n,lp:s,issuer:a}){var p;let o={},i=e!=null&&e.exists?e.xrpReserve*2:0,r=t!=null&&t.exists&&((p=t.buyDepth.find(m=>m.pct===2))==null?void 0:p.xrpAtOffer)||0;o.liquidity={score:Math.round((Yn(i,0,1e5)+Yn(r,0,2e4))/2),inputs:{ammTvlXrp:i,depthTo2PctXrp:r,ammExists:!!(e!=null&&e.exists),orderBookExists:!!(t!=null&&t.exists)}},o.distribution={score:n!=null&&n.exists?Math.round(Yn(n.top10Pct,90,20)):0,inputs:{top1Pct:(n==null?void 0:n.top1Pct)??null,top5Pct:(n==null?void 0:n.top5Pct)??null,top10Pct:(n==null?void 0:n.top10Pct)??null,holderCount:(n==null?void 0:n.holderCount)??0,sampleOnly:(n==null?void 0:n.sampleOnly)??!0}};let l=t!=null&&t.exists?Math.abs(t.spreadPct??100):100;o.marketQuality={score:t!=null&&t.exists?Math.round(Yn(l,15,0)):0,inputs:{spreadPct:(t==null?void 0:t.spreadPct)??null,buySideOfferCount:(t==null?void 0:t.buySideOfferCount)??0,sellSideOfferCount:(t==null?void 0:t.sellSideOfferCount)??0}},o.lpStability={score:s!=null&&s.exists?Math.round((Yn(s.top1Pct,100,20)+Yn(s.holderCount,1,25))/2):0,inputs:{top1Pct:(s==null?void 0:s.top1Pct)??null,top5Pct:(s==null?void 0:s.top5Pct)??null,holderCount:(s==null?void 0:s.holderCount)??0}};let c=100,d={clawbackEnabled:!1,globalFreeze:!1,freezeCapable:!1,requireAuth:!1,blackholed:!1};a!=null&&a.exists?(d.clawbackEnabled=a.clawbackEnabled,d.globalFreeze=a.globalFreeze,d.freezeCapable=a.freezeCapable,d.requireAuth=a.requireAuth,d.blackholed=a.blackholed,a.clawbackEnabled&&(c-=30),a.globalFreeze&&(c-=25),a.freezeCapable&&(c-=10),a.requireAuth&&(c-=10),a.blackholed&&(c+=15)):c=0,o.issuerRisk={score:dl(Math.round(c)),inputs:d};let u=Object.entries(Fo).reduce((m,[f,g])=>m+o[f].score*g/100,0);return{overall:Math.round(u),subScores:o,weights:Fo,dimensionsLive:Object.keys(Fo),dimensionsDeferred:["networkActivity","treasuryHealth","transparency"]}}async function pl(e){let t=Pm(e.currency||e.symbol),n=e.issuer;if(!n)throw new Error("This token has no issuer address \u2014 Project Intelligence only applies to issued tokens, not XRP itself.");let[s,a,o,i]=await Promise.all([Lm(t,n),Mm(n),Am(n,t),Rm(t,n)]),r=s.exists&&s.account&&s.lpCurrency?await Em(s.account,s.lpCurrency):{exists:!1},l=_m({amm:s,orderBook:i,holders:o,lp:r,issuer:a});return{token:{symbol:e.symbol,name:e.name,issuer:n,currency:t},amm:s,issuerRisk:a,holders:o,lp:r,orderBook:i,strength:l,fetchedAt:Date.now()}}var Ll="nalulf_wallets",Ml="nalulf_profile",Al="nalulf_social",Es="naluxrp_active_wallet",pn="nalulf_avatar_img",Dn="nalulf_banner_img",Uo="nalulf_activity_log",ei="nalulf_balhist_",Dm="nalulf_addr_book",Im="https://xrplcluster.com/",Fm="https://s2.ripple.com:51234/",Om=[e=>`https://corsproxy.io/?${encodeURIComponent(e)}`,e=>`https://api.allorigins.win/raw?url=${encodeURIComponent(e)}`],Bm="https://api.xrpscan.com/api/v1/tokens",Xm="https://api.coingecko.com/api/v3/coins/markets",Hm="https://bithomp.com/api/v2/tokens",zm="https://api.xrpl.to/api/tokens",Wm=!1,Ta=10,Ca=2,Um=["\u{1F30A}","\u{1F40B}","\u{1F409}","\u{1F98B}","\u{1F981}","\u{1F43A}","\u{1F98A}","\u{1F43B}","\u{1F43C}","\u{1F985}","\u{1F42C}","\u{1F988}","\u{1F419}","\u{1F991}","\u{1F9FF}","\u{1F33A}","\u{1F338}","\u{1F340}","\u26A1","\u{1F525}","\u{1F48E}","\u{1F319}","\u2B50","\u{1F3AF}","\u{1F9E0}","\u{1F52E}","\u{1F6F8}","\u{1F5FA}","\u{1F3D4}","\u{1F3AD}","\u{1F3DB}"],jm=["\u{1F48E}","\u{1F3E6}","\u{1F510}","\u{1F511}","\u{1F4B0}","\u{1F30A}","\u26A1","\u{1F680}","\u{1F319}","\u2B50","\u{1F3F4}\u200D\u2620\uFE0F","\u{1F3AF}","\u{1F9E0}","\u{1F52E}"],qm=["#50fa7b","#00d4ff","#ffb86c","#bd93f9","#ff79c6","#f1fa8c","#ff5555","#00fff0","#ff6b6b","#a78bfa"],Ns=["banner-ocean","banner-neon","banner-gold","banner-cosmic","banner-sunset","banner-aurora"],ns=[{id:"discord",label:"Discord",icon:"\u{1F4AC}",prefix:"https://discord.com/users/"},{id:"twitter",label:"X / Twitter",icon:"\u{1D54F}",prefix:"https://x.com/"},{id:"linkedin",label:"LinkedIn",icon:"in",prefix:"https://linkedin.com/in/"},{id:"github",label:"GitHub",icon:"\u2325",prefix:"https://github.com/"},{id:"telegram",label:"Telegram",icon:"\u2708",prefix:"https://t.me/"},{id:"facebook",label:"Facebook",icon:"f",prefix:"https://facebook.com/"},{id:"tiktok",label:"TikTok",icon:"\u266A",prefix:"https://tiktok.com/@"}],Vm={tecNO_DST:"Destination account does not exist \u2014 fund it with 10 XRP first.",tecINSUF_RESERVE_LINE:"Insufficient reserve to add another trustline.",tecINSUF_RESERVE_OFFER:"Insufficient reserve to place a DEX order.",tecUNFUNDED_PAYMENT:"Insufficient balance (including reserve).",tecDST_TAG_NEEDED:"This destination requires a Destination Tag.",tecNO_PERMISSION:"Account has DepositAuth enabled \u2014 destination must preauthorize.",temBAD_AMOUNT:"Invalid amount.",temBAD_CURRENCY:"Invalid currency code.",temBAD_ISSUER:"Invalid issuer address.",tefPAST_SEQ:"Sequence number already used \u2014 please retry.",terQUEUED:"Transaction queued \u2014 will be included in a future ledger."},Gm="https://cdn.jsdelivr.net/npm/xrpl@4.2.5/build/xrpl-latest-min.js",Pa=21e4,xa=null;function Oo(e){return btoa(String.fromCharCode(...e))}function Bo(e){let t=atob(e),n=new Uint8Array(t.length);for(let s=0;s<t.length;s+=1)n[s]=t.charCodeAt(s);return n}async function Aa(){var e,t;return(e=window.xrpl)!=null&&e.Wallet?!0:(xa||(xa=new Promise((n,s)=>{let a=document.querySelector('script[data-xrpl-lib="1"]');if(a){a.addEventListener("load",()=>n(!0),{once:!0}),a.addEventListener("error",()=>s(new Error("Failed to load xrpl.js")),{once:!0});return}let o=document.createElement("script");o.src=Gm,o.async=!0,o.defer=!0,o.dataset.xrplLib="1",o.onload=()=>n(!0),o.onerror=()=>s(new Error("Failed to load xrpl.js")),document.head.appendChild(o)}).finally(()=>{var n;(n=window.xrpl)!=null&&n.Wallet||(xa=null)})),await xa,!!((t=window.xrpl)!=null&&t.Wallet))}async function El(e,t,n=Pa){let s=new TextEncoder,a=await crypto.subtle.importKey("raw",s.encode(e),{name:"PBKDF2"},!1,["deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",hash:"SHA-256",salt:t,iterations:n},a,{name:"AES-GCM",length:256},!1,["encrypt","decrypt"])}async function Nl(e,t){let n=new TextEncoder,s=crypto.getRandomValues(new Uint8Array(16)),a=crypto.getRandomValues(new Uint8Array(12)),o=await El(t,s,Pa),i=await crypto.subtle.encrypt({name:"AES-GCM",iv:a},o,n.encode(e));return{v:1,kdf:"PBKDF2-SHA256",iter:Pa,alg:"AES-GCM-256",salt:Oo(s),iv:Oo(a),ct:Oo(new Uint8Array(i))}}async function Km(e,t){if(!(e!=null&&e.ct)||!(e!=null&&e.salt)||!(e!=null&&e.iv))throw new Error("Wallet seed blob is invalid.");let n=await El(t,Bo(e.salt),e.iter||Pa),s=await crypto.subtle.decrypt({name:"AES-GCM",iv:Bo(e.iv)},n,Bo(e.ct));return new TextDecoder().decode(s)}async function Jm(e,t){let n=(t||"").trim();if(n)return n;if(e!=null&&e.encSeed){let a=prompt("Enter your wallet password to decrypt and sign this transaction:");if(!a)throw new Error("Wallet password is required to sign.");try{return await Km(e.encSeed,a)}catch{throw new Error("Could not decrypt wallet seed. Check your wallet password and try again.")}}let s=prompt("Enter the wallet seed to sign this transaction (used once, not stored):");if(!s)throw new Error("Seed phrase is required to sign transactions.");return s.trim()}var de={displayName:"",handle:"",bio:"",location:"",website:"",avatar:"\u{1F30A}",banner:"banner-ocean",joinedDate:new Date().toISOString(),domain:""},re=[],Ge={},dt=null,Ye={},ti={},ni={},Rl={},si={},Ls={},_l={},Ce={loading:!0,data:null,error:""},bt={loading:!0,items:[],error:""},yt={loading:!0,pools:[],error:""},Lt={loading:!0,pools:[],error:""},_e={loading:!1,pool:null,error:""},P={pair:"BITSTAMP:XRPUSD",interval:"15",chartType:"candles",stats:null,loading:!0,error:"",comparePair:"",indicators:{sma20:!0,ema20:!1,wma20:!1,bb20:!1,vwap:!1,ichimoku:!1,macd:!1,rsi:!1,atr:!1,adx:!1,aroon:!1,cci:!1,williamsr:!1,mfi:!1,obv:!1,adline:!1,cmf:!1,stoch:!1,uo:!1,stdev:!1,donchian:!1,keltner:!1,supertrend:!1,pivots:!1,sar:!1,vortex:!1,elderRay:!1},tokenFocusKey:"",drawingTool:"none",drawings:[],alerts:[],indicatorMenuOpen:!1,moreMenuOpen:!1,indicatorQuery:"",indicatorSettings:{},settingsOpenFor:null,threeEnabled:!0,selectedIndicator:"sma20",selectedEducationTab:"indicator",educationCollapsed:!1,educationHint:"",chartMeta:{tokenKey:"XRP|",symbol:"XRP",source:"Coinbase + XRPL live",last:null,high:null,low:null,mode:"pair"}},U={loading:!0,tokens:[],filtered:[],trending:[],error:"",query:"",total:0,lastSyncAt:0,filters:{type:"all",minCap:0,minVol:0,hasDex:!1},selectedTokenKey:"",listLimit:240},Pt={loading:!0,items:[],error:""},Je={loading:!1,error:"",data:null,tokenKey:"",expandedSubScore:""},ul=new Map,ka=null,$a=null,ml=!1,fl=0,Dl=0,Ms=null,hl={xrplto:0},ee={chart:null,volumeSeries:null,activeSeries:null,compareSeries:null,indicatorSeries:[],indicatorPriceLines:[],priceLines:[],resizeObserver:null,chartType:"",configKey:"",legendEl:null,renderLegend:null,ichimokuData:null,indicatorLegendItems:[],alertPriceLines:[]},Ve={renderer:null,scene:null,camera:null,points:null,raf:0,host:null,resizeHandler:null},As=new Map,Nn=0,Xo="",Ym="naluxrp_hist_v1_",Il=60,Fl=25,Qm=200,Zm=e=>new Promise(t=>setTimeout(t,e)),jo="naluxrp_seed_backed_up",Ol="naluxrp_token_watchlist",qo="naluxrp_chart_layout",Bl="naluxrp_selected_token",ai="naluxrp_chart_3d",Xl="naluxrp_price_alerts";function La(){return B.currentPage==="profile"&&!document.hidden}var ef=[{symbol:"XRP",name:"XRP Ledger Native",marketCap:"$124.3B",source:"CoinGecko"},{symbol:"RLUSD",name:"Ripple USD",marketCap:"$312.0M",source:"Static sample"},{symbol:"SOLOGENIC",name:"Sologenic",marketCap:"$96.4M",source:"Static sample"}],In=[{id:"BITSTAMP:XRPUSD",label:"XRP / USD (Coinbase + XRPL)",source:"coinbase",ticker:"xrpusd",symbol:"XRP",coingeckoId:"ripple"},{id:"BINANCE:XRPUSDT",label:"XRP / USD (Coinbase mirror)",source:"coinbase",ticker:"XRPUSDT",symbol:"XRP",coingeckoId:"ripple"},{id:"BINANCE:ETHUSDT",label:"ETH / USD (Coinbase)",source:"coinbase",ticker:"ETHUSDT",symbol:"ETH",coingeckoId:"ethereum"},{id:"BINANCE:BTCUSDT",label:"BTC / USD (Coinbase)",source:"coinbase",ticker:"BTCUSDT",symbol:"BTC",coingeckoId:"bitcoin"},{id:"BINANCE:SOLUSDT",label:"SOL / USD (Coinbase)",source:"coinbase",ticker:"SOLUSDT",symbol:"SOL",coingeckoId:"solana"}],Hl=[{value:"1",label:"1m"},{value:"3",label:"3m"},{value:"5",label:"5m"},{value:"15",label:"15m"},{value:"30",label:"30m"},{value:"60",label:"1h"},{value:"120",label:"2h"},{value:"240",label:"4h"},{value:"D",label:"1D"},{value:"W",label:"1W"},{value:"M",label:"1M"}];var zl=[{key:"none",label:"Cursor"},{key:"hline",label:"Horizontal Line"}],tf={trend:["sma20","ema20","wma20","ichimoku","adx","aroon","sar","supertrend","vortex","elderRay","macd"],momentum:["rsi","stoch","cci","williamsr","mfi","uo"],volume:["obv","adline","cmf","vwap"],volatility:["bb20","keltner","atr","donchian","stdev"],advanced:["pivots"]},qt={sma20:{name:"SMA 20",what:"Simple average of closing prices over 20 periods.",purpose:"Baseline trend smoothing.",apply:"Use slope and price relation for trend confirmation.",mistake:"Assuming one crossover equals full trend reversal.",bias:"Check higher timeframe trend first."},ema20:{name:"EMA 20",what:"Weighted moving average that reacts faster.",purpose:"Track momentum shifts early.",apply:"Use with structure breaks for continuation entries.",mistake:"Overtrading every touch.",bias:"Wait for confirmation candle close."},wma20:{name:"WMA 20",what:"Linear weighted average favoring recent closes.",purpose:"Balance noise and reactivity.",apply:"Useful for dynamic pullback zones.",mistake:"Treating it as support in chop.",bias:"Confirm with volatility context."},ichimoku:{name:"Ichimoku Cloud",what:"Multi-line trend, momentum, and support/resistance framework.",purpose:"One-glance regime detection.",apply:"Favor trades aligned with cloud direction and conversion/base line confluence.",mistake:"Ignoring lagging span context.",bias:"Only take signals in clear trend phases."},macd:{name:"MACD",what:"Difference between fast and slow EMAs with signal line.",purpose:"Momentum and trend acceleration.",apply:"Use histogram contraction/expansion and line cross with structure.",mistake:"Late entries from isolated crosses.",bias:"Match cross direction with market structure."},rsi:{name:"RSI",what:"Relative strength oscillator from 0-100.",purpose:"Momentum strength and exhaustion.",apply:"40-80 bull range, 20-60 bear range is often more useful than 30/70 alone.",mistake:"Shorting every overbought reading in uptrends.",bias:"Use RSI with trend filters and divergence context."},stoch:{name:"Stochastic",what:"Close location relative to recent range.",purpose:"Short-term momentum turns.",apply:"Best in ranges or pullbacks within trend.",mistake:"Treating every cross as signal.",bias:"Require structure or support/resistance confluence."},cci:{name:"CCI",what:"Deviation from statistical mean.",purpose:"Identify cyclical overextensions.",apply:"Look for trend-aligned re-entry after reset.",mistake:"Using fixed thresholds in all regimes.",bias:"Adapt thresholds to volatility."},williamsr:{name:"Williams %R",what:"Inverse stochastic oscillator.",purpose:"Range extremes and momentum snapbacks.",apply:"Use with market regime filter.",mistake:"Fading trends blindly.",bias:"Avoid countertrend trades without invalidation levels."},mfi:{name:"MFI",what:"Volume-weighted RSI style oscillator.",purpose:"Money flow pressure.",apply:"Combine with volume spikes for conviction.",mistake:"Ignoring thin liquidity distortions.",bias:"Cross-check on multiple venues when possible."},uo:{name:"Ultimate Oscillator",what:"Weighted momentum across multiple windows.",purpose:"Reduce single-window false signals.",apply:"Divergences can be strong with structure breaks.",mistake:"Using without trend filter.",bias:"Require two independent confirmations."},obv:{name:"On Balance Volume",what:"Cumulative signed volume.",purpose:"Volume pressure trend.",apply:"Look for OBV breaks before price breaks.",mistake:"Trusting OBV in sparse data periods.",bias:"Check liquidity quality first."},adline:{name:"Accumulation/Distribution",what:"Volume flow using close location in candle.",purpose:"Detect stealth accumulation/distribution.",apply:"Use for divergence against price trend.",mistake:"Ignoring wick distortions.",bias:"Validate with average volume regime."},cmf:{name:"Chaikin Money Flow",what:"Normalized accumulation/distribution over window.",purpose:"Money flow bias.",apply:"Sustained above/below zero is more meaningful than single crosses.",mistake:"Reacting to one-bar flips.",bias:"Use persistence thresholds."},vwap:{name:"VWAP",what:"Volume weighted average price.",purpose:"Institutional execution benchmark.",apply:"Use as intraday mean reversion or trend continuation anchor.",mistake:"Ignoring session resets.",bias:"Define session context explicitly."},bb20:{name:"Bollinger Bands",what:"Moving average with standard deviation envelopes.",purpose:"Volatility expansion/contraction.",apply:"Squeezes can precede breakouts; walks indicate trend.",mistake:"Assuming every upper-band touch is sell.",bias:"Pair with trend and volume confirmation."},keltner:{name:"Keltner Channel",what:"EMA center with ATR-based envelopes.",purpose:"Trend-aware volatility channel.",apply:"Break/hold beyond band can mark trend strength.",mistake:"Using fixed ATR multiplier everywhere.",bias:"Tune per asset volatility."},atr:{name:"ATR",what:"Average true range.",purpose:"Position sizing and stop calibration.",apply:"Use ATR multiples for stops/targets.",mistake:"Using fixed pip stops in all regimes.",bias:"Normalize risk by volatility."},donchian:{name:"Donchian Channels",what:"Highest high / lowest low bands.",purpose:"Breakout systems.",apply:"Use channel breaks with trend filter.",mistake:"Ignoring false breakout environment.",bias:"Wait for close confirmation."},stdev:{name:"Standard Deviation",what:"Dispersion of price from mean.",purpose:"Volatility regime shifts.",apply:"Expand risk controls during high dispersion.",mistake:"Mistaking volatility for direction.",bias:"Separate volatility from trend."},adx:{name:"ADX",what:"Trend strength metric independent of direction.",purpose:"Regime filter.",apply:"Use +DI/-DI with ADX slope.",mistake:"Trading direction off ADX alone.",bias:"Combine with directional structure."},aroon:{name:"Aroon",what:"Time since highs/lows.",purpose:"Trend emergence detection.",apply:"Aroon up/down crosses near extremes can flag regime shifts.",mistake:"Using in high-noise micro ranges.",bias:"Require multi-candle confirmation."},pivots:{name:"Pivot Points",what:"Session-based support/resistance levels.",purpose:"Map likely reaction zones.",apply:"Use confluence with order flow and trend.",mistake:"Treating pivots as guaranteed reversal levels.",bias:"Plan invalidation before entry."},sar:{name:"Parabolic SAR",what:"Trailing stop indicator with acceleration factor.",purpose:"Trend trailing and stop logic.",apply:"Works best in persistent trends.",mistake:"Using in sideways chop.",bias:"Filter with ADX or structure."},supertrend:{name:"Supertrend",what:"ATR-based trend-following overlay.",purpose:"Trend direction and trailing stop.",apply:"Follow flips when volatility supports continuation.",mistake:"Chasing every flip in range.",bias:"Use higher timeframe confirmation."},vortex:{name:"Vortex",what:"Positive/negative trend movement lines.",purpose:"Trend turning points.",apply:"Crosses with expansion can mark trend shifts.",mistake:"Ignoring low-liquidity noise.",bias:"Confirm with volume and structure."},elderRay:{name:"Elder Ray",what:"Bull/Bear power versus EMA baseline.",purpose:"Pressure around trend mean.",apply:"Look for divergence and trend continuation.",mistake:"Using without baseline trend direction.",bias:"Anchor decisions to trend context."}},oi={sma20:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#f1c40f"}],ema20:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#ffb86c"}],wma20:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#bd93f9"}],vwap:[{id:"color",label:"Color",type:"color",default:"#80ffea"}],bb20:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Band Color",type:"color",default:"#ff79c6"}],ichimoku:[{id:"tenkanLen",label:"Tenkan Length",type:"number",default:9},{id:"kijunLen",label:"Kijun Length",type:"number",default:26},{id:"senkouBLen",label:"Senkou B Length",type:"number",default:52},{id:"tenkanColor",label:"Tenkan Color",type:"color",default:"#ffde59"},{id:"kijunColor",label:"Kijun Color",type:"color",default:"#6ecbff"},{id:"bullColor",label:"Cloud Bull Color",type:"color",default:"#46ffa0"},{id:"bearColor",label:"Cloud Bear Color",type:"color",default:"#ff7878"}],donchian:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#9cfb8c"}],keltner:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#7ee7ff"}],supertrend:[{id:"color",label:"Color",type:"color",default:"#8bffde"}],sar:[{id:"color",label:"Color",type:"color",default:"#ffaf7a"}],elderRay:[{id:"bullColor",label:"Bull Color",type:"color",default:"#5fff9d"},{id:"bearColor",label:"Bear Color",type:"color",default:"#ff9d9d"}],rsi:[{id:"length",label:"Length",type:"number",default:14},{id:"color",label:"Color",type:"color",default:"#a6ff4d"}],atr:[{id:"length",label:"Length",type:"number",default:14},{id:"color",label:"Color",type:"color",default:"#ffb86c"}],stdev:[{id:"color",label:"Color",type:"color",default:"#b2a3ff"}],stoch:[{id:"length",label:"Length",type:"number",default:14},{id:"kColor",label:"%K Color",type:"color",default:"#9ee8ff"},{id:"dColor",label:"%D Color",type:"color",default:"#ffd86b"}],macd:[{id:"fastLen",label:"Fast Length",type:"number",default:12},{id:"slowLen",label:"Slow Length",type:"number",default:26},{id:"signalLen",label:"Signal Length",type:"number",default:9},{id:"lineColor",label:"MACD Color",type:"color",default:"#8fd9ff"},{id:"signalColor",label:"Signal Color",type:"color",default:"#ffcf8e"}],obv:[{id:"color",label:"Color",type:"color",default:"#8cf9ff"}],adline:[{id:"color",label:"Color",type:"color",default:"#ffb7ff"}],cmf:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#f8ff87"}],williamsr:[{id:"length",label:"Length",type:"number",default:14},{id:"color",label:"Color",type:"color",default:"#ff9adf"}],cci:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#b8ff8e"}],mfi:[{id:"length",label:"Length",type:"number",default:14},{id:"color",label:"Color",type:"color",default:"#7bffd2"}],uo:[{id:"color",label:"Color",type:"color",default:"#ffd36f"}],adx:[{id:"length",label:"Length",type:"number",default:14},{id:"adxColor",label:"ADX Color",type:"color",default:"#9fd8ff"},{id:"plusColor",label:"+DI Color",type:"color",default:"#73ffc0"},{id:"minusColor",label:"-DI Color",type:"color",default:"#ff9797"}],aroon:[{id:"length",label:"Length",type:"number",default:14},{id:"upColor",label:"Up Color",type:"color",default:"#6cffb0"},{id:"downColor",label:"Down Color",type:"color",default:"#ff8f8f"}],vortex:[{id:"length",label:"Length",type:"number",default:14},{id:"plusColor",label:"VI+ Color",type:"color",default:"#d6a8ff"},{id:"minusColor",label:"VI- Color",type:"color",default:"#ffb0f3"}]},nf={sma20:{creator:"Early quantitative analysts (1900s tape reading era)",era:"Formalized in the early 20th century",math:"Arithmetic mean of the last N closes.",context:"Designed to smooth noisy tape data for trend direction visibility.",regime:"Best in directional trends, weaker in mean-reverting chop."},ema20:{creator:"Modern technical analysts adapting exponential smoothing",era:"Popularized in 1960s-1980s",math:"Recursive weighted mean with alpha = 2/(N+1).",context:"Improves responsiveness versus SMA while preserving trend structure.",regime:"Useful for pullback entries in trending environments."},ichimoku:{creator:"Goichi Hosoda",era:"Developed pre-WW2, published 1969",math:"Median-price lines (9/26/52) plus shifted cloud projections.",context:"Built as a full market regime system: trend, momentum, support/resistance in one frame.",regime:"Most reliable when cloud slope and price acceptance align."},macd:{creator:"Gerald Appel",era:"Late 1970s",math:"MACD = EMA(12)-EMA(26), signal=EMA(9) of MACD, histogram=spread.",context:"Tracks trend acceleration/deceleration, not just direction.",regime:"Strong in trend transitions, noisy in low-volatility ranges."},rsi:{creator:"J. Welles Wilder Jr.",era:"1978",math:"RSI = 100 - 100/(1+RS), RS = avg gain / avg loss.",context:"Measures internal momentum pressure rather than price level alone.",regime:"Range shifts (bull/bear RSI zones) matter more than static 30/70."},adx:{creator:"J. Welles Wilder Jr.",era:"1978",math:"Smoothed directional movement (+DI/-DI) transformed into trend-strength index.",context:"Separates trend strength from trend direction.",regime:"Filter trades: momentum systems improve when ADX slope rises."},aroon:{creator:"Tushar Chande",era:"1995",math:"Time since recent high/low scaled to 0-100.",context:"Focuses on trend freshness instead of pure magnitude.",regime:"Good at identifying emergent trend phases and late-trend fatigue."},cci:{creator:"Donald Lambert",era:"1980",math:"Deviation of typical price from moving average normalized by mean deviation.",context:"Originally commodity cycle tool for identifying statistical extremes.",regime:"Works better with volatility-aware thresholds than fixed +/-100."},williamsr:{creator:"Larry Williams",era:"1970s",math:"Position of close within rolling high-low range, scaled negative.",context:"Fast oscillator for short-horizon exhaustion and reversion timing.",regime:"Most effective in bounded ranges; trend filters prevent fade traps."},mfi:{creator:"Gene Quong and Avrum Soudack",era:"1989",math:"RSI-style transform using typical price * volume money flow.",context:"Adds participation/volume dimension to momentum analysis.",regime:"Useful where volume quality is high; weaker on fragmented liquidity."},obv:{creator:"Joseph Granville",era:"1963",math:"Cumulative signed volume based on close direction.",context:"Detects accumulation/distribution before obvious price moves.",regime:"Best when confirmed with structure breaks and volume regime shifts."},vwap:{creator:"Institutional execution desks",era:"1980s electronic execution era",math:"Cumulative price*volume divided by cumulative volume.",context:"Execution benchmark and intraday fair-value reference.",regime:"Most meaningful intraday and around session anchor resets."},bb20:{creator:"John Bollinger",era:"1980s",math:"SMA +/- k * standard deviation.",context:"Captures volatility contraction/expansion around a mean.",regime:"Band walks imply trend persistence; squeezes imply potential expansion."},atr:{creator:"J. Welles Wilder Jr.",era:"1978",math:"Smoothed average of true range components.",context:"Volatility unit for risk sizing and adaptive stops.",regime:"Risk engine input rather than directional signal."},donchian:{creator:"Richard Donchian",era:"1940s-1950s",math:"Rolling highest-high and lowest-low channels.",context:"Classic breakout trend-following framework.",regime:"Performs in sustained directional moves, whipsaws in compression."},supertrend:{creator:"Olivier Seban",era:"2009",math:"ATR envelope with trend-state switching logic.",context:"Simplifies trend-following and stop-trailing into one overlay.",regime:"Good in clean trends; combine with structure/ADX in chop."},vortex:{creator:"Etienne Botes and Douglas Siepman",era:"2010",math:"Normalized positive/negative movement vectors over rolling true range.",context:"Detects trend emergence and directional dominance shifts.",regime:"Improves when paired with volatility and liquidity filters."}},sf={hline:"Horizontal levels represent reaction zones. Respect zone width and liquidity sweeps."},af=[{label:"XRP/USD (Bitstamp)",asset:{currency:"XRP"},asset2:{currency:"USD",issuer:"rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq"}},{label:"XRP/EUR (Bitstamp)",asset:{currency:"XRP"},asset2:{currency:"EUR",issuer:"rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq"}},{label:"XRP/USDC (Gatehub)",asset:{currency:"XRP"},asset2:{currency:"USDC",issuer:"rKveEyR1SrkWbJX214xcfH43ZsoGMb3PEv"}}],Rn=null,dn={},Zn="",wt=1,ye={algo:"ed25519",label:"",emoji:"\u{1F48E}",color:"#50fa7b",seed:"",address:"",passphrase:""},_n=new Set,gl=60,of={wallet_created:"\u{1F48E}",wallet_removed:"\u{1F5D1}",social_connected:"\u{1F517}",social_removed:"\u2715",profile_saved:"\u270F\uFE0F",trustline_added:"\u{1F517}",sent:"\u2B06",received:"\u2B07",vault_created:"\u{1F510}",backup_exported:"\u{1F4C2}",theme_changed:"\u{1F3A8}",wallet_imported:"\u{1F511}",watch_added:"\u{1F441}"};function Wl(){Vo(),Kh(),pf(),P.threeEnabled=Q(ai)!=="0",rf(),Aa().catch(()=>{ge("Could not preload xrpl.js. Wallet generation/signing will require network access when used.")}),j(),Bt(),ng(),cf(),La()&&es({silent:!0}),window.addEventListener("naluxrp:pagechange",e=>{var t;((t=e==null?void 0:e.detail)==null?void 0:t.pageId)==="profile"?es({silent:!0}):Ve.raf&&Fs()}),document.addEventListener("click",e=>{var s;let t=document.querySelector(".xpd-indicator-menu-wrap");t&&!t.contains(e.target)&&P.indicatorMenuOpen&&(P.indicatorMenuOpen=!1,j());let n=document.querySelector(".xpd-more-menu-wrap");if(n&&!n.contains(e.target)&&P.moreMenuOpen&&(P.moreMenuOpen=!1,j()),P.settingsOpenFor){let a=(s=document.querySelector(".xpd-indicator-settings"))==null?void 0:s.closest(".xpd-indicator-chip-wrap");a&&!a.contains(e.target)&&(P.settingsOpenFor=null,j())}}),window.addEventListener("naluxrp:vault-ready",()=>{Vo(),j(),Bt(),Bh(),es({silent:!0,force:!0})}),window.addEventListener("naluxrp:vault-locked",()=>{j(),es({silent:!0,force:!0})}),document.addEventListener("visibilitychange",()=>{if(La()&&!document.hidden&&re.length){let e=re.filter(t=>{let n=Ye[t.address];return!n||Date.now()-n.fetchedAt>3e5});e.length&&Promise.all(e.map(t=>Fn(t.address))).then(()=>{$t(),Bt()})}})}function rf(){let e=new URLSearchParams(window.location.search),t=e.get("pair")||"",n=e.get("tf")||"",s=e.get("token")||Q(Bl)||"",a=e.get("ind")||"";if(t&&In.some(o=>o.id===t)&&(P.pair=t),n&&Hl.some(o=>o.value===n)&&(P.interval=n),a){let o=new Set(a.split(",").map(i=>i.trim()).filter(Boolean));Object.keys(P.indicators).forEach(i=>{P.indicators[i]=o.has(i)})}s&&(P.tokenFocusKey=s,U.selectedTokenKey=s)}function At(){let e=new URLSearchParams(window.location.search);e.set("pair",P.pair||"BITSTAMP:XRPUSD"),e.set("tf",P.interval||"15"),P.tokenFocusKey?e.set("token",P.tokenFocusKey):e.delete("token");let t=Object.entries(P.indicators).filter(([,s])=>!!s).map(([s])=>s).join(",");t?e.set("ind",t):e.delete("ind");let n=`${window.location.pathname}?${e.toString()}${window.location.hash||""}`;window.history.replaceState(null,"",n),P.tokenFocusKey&&Z(Bl,P.tokenFocusKey)}function lf(){let e=document.getElementById("xpd-chart-section");e&&e.scrollIntoView({behavior:"smooth",block:"start"})}function cf(){ml||(ml=!0,window.addEventListener("xrpl-ledger",()=>{let e=Date.now();e-fl<5e3||(fl=e,B.currentPage==="profile"&&document.querySelector("#profile-page .profile-wrap .xrpl-profile-dashboard")&&cc().then(()=>{if(Date.now()-Dl>15e3)return;let n=document.activeElement;n&&/^(INPUT|TEXTAREA|SELECT)$/.test(n.tagName)||P.moreMenuOpen||P.indicatorMenuOpen||(As.clear(),j())}).catch(()=>{}))}))}function ii(e){let t=x(`profile-tab-${e}`);t&&t.scrollIntoView({behavior:"smooth",block:"start"})}function df(e,t,n){e.innerHTML=`<div class="tab-error-card">
    <div class="tab-error-icon">\u26A0\uFE0F</div>
    <div class="tab-error-title">Something went wrong</div>
    <div class="tab-error-sub">${y((n==null?void 0:n.message)||"Unknown error")}</div>
    <button class="tab-error-btn" onclick="switchProfileTab('${t}')">Try Again</button>
  </div>`}function pf(){document.addEventListener("keydown",e=>{if(e.key==="Escape")for(let t of["profile-editor-modal","wallet-creator-overlay","social-modal","send-modal-overlay","receive-modal-overlay","trustline-modal-overlay","import-address-modal","import-seed-modal","token-details-modal","pub-profile-overlay"]){let n=x(t)||document.getElementById(t);if(n!=null&&n.classList.contains("show")||(n==null?void 0:n.style.display)==="flex"){n.classList.remove("show"),n.style.display==="flex"&&(n.style.display="none");return}}e.key==="k"&&(e.ctrlKey||e.metaKey)&&(e.preventDefault(),bi())})}function Vo(){var t,n;let e=ve(Q(Ml));e&&Object.assign(de,e),Ge=ve(Q(Al))||{},re=ve(Q(Ll))||[],_l=ve(Q(Dm))||{},P.alerts=ve(Q(Xl))||[],dt=Q(Es)||((t=re[0])==null?void 0:t.id)||null,!de.displayName&&((n=B.session)!=null&&n.name)&&(de.displayName=B.session.name,de.handle=B.session.name.toLowerCase().replace(/\s+/g,"_"),Ul())}function Ul(){Z(Ml,JSON.stringify(de))}function Rs(){Z(Ll,JSON.stringify(re))}function jl(){Z(Al,JSON.stringify(Ge))}function ri(){Z(Xl,JSON.stringify(P.alerts||[]))}function kt(e,t){let n=ve(Q(Uo))||[];n.unshift({type:e,detail:t,ts:Date.now()}),n.length>gl&&(n.length=gl),Z(Uo,JSON.stringify(n))}function uf(){return ve(Q(Uo))||[]}function ql(e){let t=(Date.now()-e)/1e3;return t<60?"just now":t<3600?`${Math.floor(t/60)}m ago`:t<86400?`${Math.floor(t/3600)}h ago`:`${Math.floor(t/86400)}d ago`}function Et(){return re.find(e=>e.id===dt)||re[0]||null}function Vl(e){re.find(t=>t.id===e)&&(dt=e,Z(Es,e),$t(),Bt(),window.dispatchEvent(new CustomEvent("naluxrp:active-wallet-changed",{detail:Et()})),ae("Active wallet switched"))}window.addEventListener("naluxrp:active-wallet-changed",e=>{let t=e.detail;if(!t)return;let n=x("inspect-addr");n&&!n.value&&(n.value=t.address),B.activeWalletAddress=t.address});function Bt(){var o;let e=x("active-wallet-bar");if(!e)return;let t=Et();if(!t){e.innerHTML='<div class="awb-empty">No wallet \u2014 <button class="awb-link" onclick="openWalletCreator()">create one</button></div>';return}let n=Ye[t.address],s=n?_(n.xrp,2)+" XRP":"\u2014 XRP",a=(o=n==null?void 0:n.tokens)!=null&&o.length?`\xB7 ${n.tokens.length} token${n.tokens.length>1?"s":""}`:"";e.innerHTML=`
    <div class="awb-left">
      <div class="awb-icon" style="background:${t.color}22;border-color:${t.color}55;color:${t.color}">${y(t.emoji)}</div>
      <div class="awb-info">
        <span class="awb-label">${y(t.label)}</span>
        <span class="awb-address mono">${y(t.address)}</span>
      </div>
      <span class="awb-balance">${s} ${a}</span>
    </div>
    <div class="awb-actions">
      <button class="awb-btn awb-btn--send"    onclick="openSendModal('${t.id}')">\u2B06 Send</button>
      <button class="awb-btn awb-btn--receive" onclick="openReceiveModal('${t.id}')">\u2B07 Receive</button>
      <button class="awb-btn awb-btn--trust"   onclick="openTrustlineModal('${t.id}')">\u{1F517} Trustlines</button>
      <button class="awb-btn awb-btn--inspect" onclick="inspectWalletAddr('${y(t.address)}')">\u{1F50D} Inspect</button>
    </div>`}function j(){var h,v;let e=document.querySelector("#profile-page .profile-wrap");if(!e)return;let t=document.getElementById("xpd-tv-widget"),n=!!(t&&ee.chart);t&&t.remove();let s=document.getElementById("xpd-chart-atmosphere"),a=!!(s&&Ve.renderer);s&&s.remove();let o=Et(),i=(o==null?void 0:o.address)||"",r=mf(),l=localStorage.getItem(pn),c=re.some(w=>!w.watchOnly),d=Q(jo)==="1",u=(h=Ye[i])==null?void 0:h.xrp,p=Object.values(Ye).reduce((w,k)=>w+((k==null?void 0:k.xrp)||0),0),m=(v=Ce.data)!=null&&v.priceUsd?p*Ce.data.priceUsd:0,f=In.map(w=>`<option value="${y(w.id)}" ${P.pair===w.id?"selected":""}>${y(w.label)}</option>`).join(""),g=In.map(w=>`<option value="${y(w.id)}" ${P.comparePair===w.id?"selected":""}>${y(w.label)}</option>`).join(""),b=Hl.map(w=>`<option value="${y(w.value)}" ${P.interval===w.value?"selected":""}>${y(w.label)}</option>`).join("");if(e.innerHTML=`
    <div class="xrpl-profile-dashboard">
      <header class="xpd-header xpd-header--stack">
        <div>
          <h1 class="xpd-title">XRPL Portfolio Intelligence Terminal</h1>
          <p class="xpd-subtitle">Profile identity, market intelligence, DEX charting, NFT inventory, and AMM liquidity in one secure workspace.</p>
        </div>
        <div class="xpd-header-badges">
          <a class="xpd-badge" href="https://pikoverse.xyz" target="_blank" rel="noopener">\u{1F310} Part of the Pikoverse ecosystem</a>
          <span class="xpd-badge ${r.kind}">${r.label}</span>
          <span class="xpd-badge security">Local signing only \xB7 private keys stay in-browser</span>
          ${i?`<span class="xpd-badge mono">${i.slice(0,10)}...${i.slice(-8)}</span>`:'<span class="xpd-badge warn">No active wallet selected</span>'}
          <button class="xpd-action xpd-action--primary" onclick="openWalletCreator()"><span class="xai">\uFF0B</span>Add Wallet</button>
          <button class="xpd-action xpd-action--primary" onclick="refreshXrplDashboard()"><span class="xai">\u27F3</span>Refresh all</button>
          <button class="xpd-action" onclick="jumpToProjectIntelLookup()" title="Jump straight to the project-analysis lookup, further down this page"><span class="xai">\u{1F52C}</span>Analyze a Project</button>
        </div>
      </header>

      <div class="xpd-layout-grid">
        <aside class="xpd-profile-card" aria-label="Profile identity">
          <div class="xpd-profile-top">
            <div class="xpd-avatar-shell" title="${y(de.displayName||"Anonymous")}" onclick="openProfileEditor()">
              ${l?`<img src="${l}" alt="Profile avatar" class="xpd-avatar-img" />`:`<span class="xpd-avatar-fallback">${y(de.avatar||(o==null?void 0:o.emoji)||"\u{1F30A}")}</span>`}
            </div>
            <div class="xpd-profile-meta">
              <h2 class="xpd-display-name">${y(de.displayName||"Anonymous")}</h2>
              <p class="xpd-bio">${y(de.bio||"No bio set. Click edit profile to add one.")}</p>
              <button class="xpd-action" onclick="openProfileEditor()">Edit profile</button>
            </div>
          </div>
          <div class="xpd-profile-list">
            <div class="xpd-item-row">
              <span class="xpd-item-label">Wallet</span>
              <div class="xpd-wallet-inline">
                ${i?`<span class="mono xpd-wallet-chip" title="${y(i)}">${i}</span><button class="xpd-mini-btn" onclick="copyToClipboard('${y(i)}')">Copy</button>`:'<span class="xpd-empty">No wallet selected</span>'}
              </div>
            </div>
            <div class="xpd-item-row">
              <span class="xpd-item-label">XRP Balance</span>
              <span class="xpd-item-value">${Number.isFinite(u)?`${_(u,4)} XRP`:"\u2014"}</span>
            </div>
            <div class="xpd-item-row">
              <span class="xpd-item-label">Network</span>
              <span class="xpd-item-value">${r.label}</span>
            </div>
            <div class="xpd-item-row">
              <span class="xpd-item-label">Vault status</span>
              <span class="xpd-item-value">${c?"Vault ready":"Watch-only mode"}</span>
            </div>
            <div class="xpd-item-row xpd-item-row--toggle">
              <span class="xpd-item-label">Seed phrase backed up</span>
              <button class="xpd-toggle ${d?"on":""}" onclick="toggleSeedBackupStatus()" aria-pressed="${d?"true":"false"}">${d?"Yes":"No"}</button>
            </div>
          </div>
          <div class="xpd-sidebar-snapshot">
            <span class="xpd-sidebar-snapshot-label">Portfolio Snapshot</span>
            <div class="xpd-sidebar-snapshot-row">
              <span>Total XRP</span>
              <strong>${_(p,4)}</strong>
            </div>
            <div class="xpd-sidebar-snapshot-row">
              <span>Est. USD</span>
              <strong>${m?`$${_(m,2)}`:"\u2014"}</strong>
            </div>
            <div class="xpd-sidebar-snapshot-row">
              <span>Wallets</span>
              <strong>${re.length}</strong>
            </div>
          </div>
        </aside>

        <div class="xpd-main-stack">
          <section id="xpd-chart-section" class="xpd-section xpd-section--chart" aria-label="DEX chart">
            <div class="xpd-section-head">
              <h2>XRPL DEX Chart</h2>
              <div class="xpd-chart-toolbar">
                <div class="xpd-toolbar-group">
                  <span class="xpd-toolbar-group-label">Data</span>
                  <select class="xpd-input" onchange="setDexPair(this.value)">${f}</select>
                  <select class="xpd-input" onchange="setDexInterval(this.value)">${b}</select>
                  <select class="xpd-input" onchange="setDexChartType(this.value)">
                    <option value="candles" ${P.chartType==="candles"?"selected":""}>Candlestick</option>
                    <option value="line" ${P.chartType==="line"?"selected":""}>Line</option>
                    <option value="area" ${P.chartType==="area"?"selected":""}>Area</option>
                    <option value="bars" ${P.chartType==="bars"?"selected":""}>Bar</option>
                    <option value="heikin_ashi" ${P.chartType==="heikin_ashi"?"selected":""}>Heikin Ashi</option>
                    <option value="hollow_candles" ${P.chartType==="hollow_candles"?"selected":""}>Hollow Candle</option>
                  </select>
                  <select class="xpd-input" onchange="setComparePair(this.value)">
                    <option value="" ${P.comparePair?"":"selected"}>No Compare</option>
                    ${g}
                  </select>
                </div>
                <div class="xpd-toolbar-group">
                  <span class="xpd-toolbar-group-label">View</span>
                  <button class="xpd-action xpd-action--primary" onclick="refreshDexChart()" title="Refresh"><span class="xai">\u27F3</span>Refresh</button>
                  <button class="xpd-action xpd-action--icon" onclick="zoomChartIn()" title="Zoom In" aria-label="Zoom In">\u{1F50D}+</button>
                  <button class="xpd-action xpd-action--icon" onclick="zoomChartOut()" title="Zoom Out" aria-label="Zoom Out">\u{1F50D}\u2212</button>
                  <button class="xpd-action xpd-action--icon" onclick="panChartLeft()" title="Pan Left" aria-label="Pan Left">\u2190</button>
                  <button class="xpd-action xpd-action--icon" onclick="panChartRight()" title="Pan Right" aria-label="Pan Right">\u2192</button>
                  <button class="xpd-action xpd-action--icon" onclick="resetChartView()" title="Reset View" aria-label="Reset View">\u293E</button>
                  <button class="xpd-action xpd-action--icon" onclick="toggleChartFullscreen()" title="Fullscreen" aria-label="Fullscreen">\u26F6</button>
                </div>
                <div class="xpd-toolbar-group">
                  <span class="xpd-toolbar-group-label">Tools</span>
                  <select class="xpd-input" onchange="setDrawingTool(this.value)">
                    ${zl.map(w=>`<option value="${w.key}" ${P.drawingTool===w.key?"selected":""}>Draw: ${w.label}</option>`).join("")}
                  </select>
                  <button class="xpd-action xpd-action--icon" onclick="clearAllDrawings()" title="Clear Lines" aria-label="Clear Lines">\u{1F9F9}</button>
                  <button class="xpd-action xpd-action--icon" onclick="addPriceAlert()" title="Set Price Alert" aria-label="Set Price Alert">\u{1F514}</button>
                  ${ff()}
                  <button class="xpd-action xpd-action--icon" onclick="exportChartPng()" title="Export PNG" aria-label="Export PNG">\u{1F5BC}\uFE0F</button>
                  <button class="xpd-action xpd-action--icon" onclick="copyChartLink()" title="Copy Chart Link" aria-label="Copy Chart Link">\u{1F517}</button>
                </div>
                <div class="xpd-toolbar-group xpd-more-menu-wrap">
                  <button class="xpd-action xpd-action--icon" onclick="event.stopPropagation(); toggleChartMoreMenu()" title="More settings" aria-label="More settings">\u22EF</button>
                  ${P.moreMenuOpen?`
                    <div class="xpd-more-menu" role="menu" aria-label="Chart preferences">
                      <button class="xpd-more-menu-item" onclick="toggleThreeEffects()"><span class="xai">\u{1F9CA}</span>${P.threeEnabled?"3D Background: On":"3D Background: Off"}</button>
                      <button class="xpd-more-menu-item" onclick="toggleTerminalTheme()"><span class="xai">\u{1F313}</span>Toggle Theme</button>
                      <button class="xpd-more-menu-item" onclick="saveChartLayoutPreset()"><span class="xai">\u{1F4BE}</span>Save Layout</button>
                      <button class="xpd-more-menu-item" onclick="loadChartLayoutPreset()"><span class="xai">\u{1F4C2}</span>Load Layout</button>
                    </div>
                  `:""}
                </div>
              </div>
            </div>
            ${hf()}
          </section>

          <section class="xpd-section" aria-label="XRPL market data">
            <div class="xpd-section-head">
              <h2>XRPL Market Data</h2>
              <button class="xpd-action" onclick="refreshMarketData()"><span class="xai">\u27F3</span>Refresh market</button>
            </div>
            ${vf()}
          </section>
        </div>
      </div>

      ${gf()}

      <section class="xpd-section" aria-label="Token discovery and watchlist">
        <div class="xpd-section-head">
          <h2>Token Discovery and Watchlists</h2>
          <button class="xpd-action" onclick="refreshTokenDiscovery()"><span class="xai">\u27F3</span>Refresh tokens</button>
        </div>
        ${kf()}
      </section>

      ${Je.loading||Je.error||Je.data?`
      <section class="xpd-section" aria-label="Project intelligence" id="xpd-project-intel-section">
        ${$f()}
      </section>`:""}

      <div class="xpd-dual-grid">
        <section class="xpd-section" aria-label="NFT gallery">
          <div class="xpd-section-head">
            <h2>NFT Gallery</h2>
            <button class="xpd-action" onclick="refreshNftGallery()"><span class="xai">\u27F3</span>Refresh NFTs</button>
          </div>
          ${bf(i)}
        </section>

        <section class="xpd-section" aria-label="AMM pools and DEX liquidity">
          <div class="xpd-section-head">
            <h2>AMM, DEX, and Liquidity Pools</h2>
            <button class="xpd-action" onclick="refreshAmmPools()"><span class="xai">\u27F3</span>Refresh pools</button>
          </div>
          ${wf(i)}
        </section>
      </div>

      <section class="xpd-section" aria-label="Portfolio and recent transactions">
        <div class="xpd-section-head">
          <h2>Portfolio and Recent Transactions</h2>
          <button class="xpd-action" onclick="refreshRecentTransactions()"><span class="xai">\u27F3</span>Refresh tx</button>
        </div>
        ${Pf(i)}
      </section>

      <section class="xpd-section" aria-label="Activity and analytics">
        <div class="xpd-section-head">
          <h2>Activity &amp; Analytics</h2>
        </div>
        <div id="profile-tab-activity"></div>
        <div id="profile-tab-analytics" style="margin-top:16px"></div>
      </section>

      <section class="xpd-section" aria-label="Social and community links">
        <div class="xpd-section-head">
          <h2>Social &amp; Community Links</h2>
        </div>
        <div id="profile-tab-social"></div>
      </section>

      <section class="xpd-section" aria-label="Preferences and settings">
        <div class="xpd-section-head">
          <h2>Preferences &amp; Settings</h2>
        </div>
        <div id="profile-tab-settings"></div>
      </section>
    </div>`,n){let w=document.getElementById("xpd-tv-widget");w&&w.replaceWith(t)}if(a){let w=document.getElementById("xpd-chart-atmosphere");w&&w.replaceWith(s)}hh(),Nh(),Rh(),fi(),Os()}function mf(){let e=String(B.currentNetwork||"").toLowerCase();return e.includes("testnet")?{label:"XRPL Testnet",kind:"testnet"}:e.includes("mainnet")?{label:"XRPL Mainnet",kind:"mainnet"}:e.includes("xahau")?{label:"Xahau Network",kind:"xahau"}:{label:`Network: ${y(B.currentNetwork||"Unknown")}`,kind:"unknown"}}function ff(){let e=String(P.indicatorQuery||"").trim().toLowerCase(),t=[{key:"trend",label:"Trend",icon:"\u{1F4C8}"},{key:"momentum",label:"Momentum",icon:"\u26A1"},{key:"volume",label:"Volume",icon:"\u{1F4CA}"},{key:"volatility",label:"Volatility",icon:"\u{1F32A}\uFE0F"},{key:"advanced",label:"Custom",icon:"\u{1F9E0}"}];return`
    <div class="xpd-indicator-menu-wrap">
      <button class="xpd-action xpd-action--add" onclick="event.stopPropagation(); toggleIndicatorMenu()">+ Indicator</button>
      ${P.indicatorMenuOpen?`
        <div class="xpd-indicator-menu" role="menu" aria-label="Indicator menu">
          <input class="xpd-input xpd-indicator-search" placeholder="Search indicators..." value="${y(P.indicatorQuery||"")}" oninput="setIndicatorQuery(this.value)" />
          ${t.map(n=>{let s=(tf[n.key]||[]).filter(a=>{var i;return e?(((i=qt[a])==null?void 0:i.name)||a).toLowerCase().includes(e):!0});return s.length?`
              <details class="xpd-indicator-group" open>
                <summary>${n.icon} ${n.label}</summary>
                <div class="xpd-indicator-items">
                  ${s.map(a=>{var o,i;return`<button class="xpd-indicator-item" title="${y(((o=qt[a])==null?void 0:o.what)||"")}" onclick="addIndicatorFromMenu('${a}')">${y(((i=qt[a])==null?void 0:i.name)||a)}</button>`}).join("")}
                </div>
              </details>`:""}).join("")}
        </div>
      `:""}
    </div>`}function hf(){var m;let e=P.stats,t=((m=B.wsConn)==null?void 0:m.readyState)===1,n=P.chartMeta||{},s=Object.entries(P.indicators).filter(([,f])=>!!f).map(([f])=>f),a=String(P.tokenFocusKey||""),o=a.includes("|")?a.split("|")[0]:a,i=U.tokens.find(f=>Ue(f)===a)||U.tokens.find(f=>String(f.symbol||"").toUpperCase()===String(o||"").toUpperCase())||null,r=!!i&&String(i.symbol||"").toUpperCase()!=="XRP"&&Number.isFinite(Number(i.price||0)),l=Number.isFinite(Number(n.last))?Number(n.last):r?Number(i.price||0):e==null?void 0:e.price,c=Number.isFinite(Number(n.high))?Number(n.high):e==null?void 0:e.high,d=Number.isFinite(Number(n.low))?Number(n.low):e==null?void 0:e.low,u=i?`${String(i.symbol||"").toUpperCase()}${i.issuer?` \xB7 ${i.issuer.slice(0,10)}...`:""}`:String(n.symbol||"XRP").toUpperCase(),p=String(n.source||(r?"Coinbase + token proxy":(e==null?void 0:e.source)||"Source pending"));return`
    ${P.error?`<div class="xpd-error">${y(P.error)}</div>`:""}
    <div class="xpd-chart-stats">
      <div class="xpd-pill" title="Current price">${l!=null?`$${_(l,r?6:4)}`:"Price \u2014"}</div>
      <div class="xpd-pill" title="24h change">${(e==null?void 0:e.changePct)!=null?`${e.changePct>=0?"+":""}${_(e.changePct,2)}%`:"24h \u2014"}</div>
      <div class="xpd-pill" title="24h high">${c!=null?`High $${_(c,r?6:4)}`:"High \u2014"}</div>
      <div class="xpd-pill" title="24h low">${d!=null?`Low $${_(d,r?6:4)}`:"Low \u2014"}</div>
      <div class="xpd-pill" title="XRPL orderbook spot">${r?`Token Spot $${_(Number((i==null?void 0:i.price)||0),6)}`:(e==null?void 0:e.xrplSpot)!=null?`XRPL Spot $${_(e.xrplSpot,4)}`:"XRPL Spot \u2014"}</div>
      <div class="xpd-pill" title="Streaming status">${t?"\u25CF Live stream connected":"\u25CF Stream offline"}</div>
      ${i?`<div class="xpd-pill" title="Token focus">Token Focus: ${y(i.symbol)} ${i.price!=null?`($${_(i.price,6)})`:""}</div>`:""}
    </div>
    <div class="xpd-indicator-row">
      ${s.length?s.map(f=>{var g,b;return`<div class="xpd-indicator-chip-wrap"><div class="xpd-indicator-chip" title="${y(((g=qt[f])==null?void 0:g.what)||"")}"><span>${y(((b=qt[f])==null?void 0:b.name)||f)}</span><button class="xpd-mini-btn" onclick="event.stopPropagation(); openIndicatorSettings('${f}')">\u2699</button><button class="xpd-mini-btn" onclick="removeIndicator('${f}')">\u2715</button></div>${gh(f)}</div>`}).join(""):'<span class="xpd-empty">No indicators enabled. Use + Indicator.</span>'}
    </div>
    ${(()=>{let f=Na(),g=(P.alerts||[]).filter(b=>b.tokenKey===f);return g.length?`
      <div class="xpd-indicator-row">
        ${g.map(b=>`
          <div class="xpd-indicator-chip" data-alert-id="${y(b.id)}" title="Notify when price crosses $${_(b.price,6)}">
            <span>\u{1F514} $${_(b.price,6)}</span>
            <button class="xpd-mini-btn" onclick="removePriceAlert('${b.id}')">\u2715</button>
          </div>`).join("")}
      </div>`:""})()}
    ${P.educationHint?`<div class="xpd-note">${y(P.educationHint)}</div>`:""}
    <div class="xpd-chart-wrap">
      <div class="xpd-chart-active-head">
        <div class="xpd-chart-active-left">
          <span class="xpd-chart-active-label">Active Chart Token</span>
          <strong class="xpd-chart-active-token" title="${y(u)}">${y(u)}</strong>
        </div>
        <div class="xpd-chart-active-right">
          <span class="xpd-chart-active-chip">Mode: ${y(n.mode||"pair")}</span>
          <span class="xpd-chart-active-chip" title="${y(p)}">Source: ${y(p)}</span>
        </div>
      </div>
      <div id="xpd-chart-atmosphere" class="xpd-chart-atmosphere" aria-hidden="true"></div>
      <div id="xpd-tv-widget" class="xpd-tv-widget"></div>
    </div>
    <p class="xpd-note">Professional chart controls: wheel zoom, hold-and-drag pan, horizontal price-line marking, and token-focused context ribbons for faster execution decisions.</p>`}function gf(){let e=P.selectedIndicator||"sma20",t=qt[e]||qt.sma20,n=nf[e]||null,s=P.educationCollapsed;return`
    <div class="xpd-edu-panel ${s?"collapsed":""}">
      <div class="xpd-edu-head">
        <h3>Indicator Intelligence and Bias Control</h3>
        <button class="xpd-mini-btn" onclick="toggleEducationPanel()">${s?"Expand":"Collapse"}</button>
      </div>
      ${s?"":`
        <div class="xpd-edu-tabs">
          <button class="xpd-mini-btn ${P.selectedEducationTab==="indicator"?"active":""}" onclick="selectEducationTab('indicator')">Indicator Guide</button>
          <button class="xpd-mini-btn ${P.selectedEducationTab==="psychology"?"active":""}" onclick="selectEducationTab('psychology')">Trading Psychology</button>
          <button class="xpd-mini-btn ${P.selectedEducationTab==="practice"?"active":""}" onclick="selectEducationTab('practice')">Best Practices</button>
        </div>
        ${P.selectedEducationTab==="indicator"?`
          <div class="xpd-edu-content">
            <h4 class="xpd-edu-title">${y(t.name)}</h4>
            ${ct("What it measures",t.what)}
            ${ct("Original purpose",t.purpose)}
            ${ct("How to apply",t.apply)}
            ${ct("Common mistake",t.mistake)}
            ${ct("Bias reduction tip",t.bias)}
            ${n?`
              ${ct("Created by / Era",`${n.creator} \xB7 ${n.era}`)}
              ${ct("Core math",n.math)}
              ${ct("Historical context",n.context)}
              ${ct("Best market regime",n.regime)}
            `:""}
          </div>
        `:""}
        ${P.selectedEducationTab==="psychology"?`
          <div class="xpd-edu-content">
            ${ct("Confirmation Bias","Require at least two independent signals before entering.")}
            ${ct("Anchoring","Do not anchor to entry price; respect invalidation and current structure.")}
            ${ct("Overfitting","More indicators is not better; build a repeatable checklist.")}
            ${ct("Risk Discipline","Position size by volatility and stop distance, not conviction.")}
          </div>
        `:""}
        ${P.selectedEducationTab==="practice"?`
          <ol class="xpd-edu-steps">
            <li>Start with trend context (higher timeframe).</li>
            <li>Add one momentum and one volatility indicator.</li>
            <li>Mark levels with drawings before taking a trade.</li>
            <li>Define entry, invalidation, and target before execution.</li>
            <li>Journal whether setup matched your rules.</li>
          </ol>
        `:""}
      `}
    </div>`}function ct(e,t){return`<div class="xpd-edu-row"><span class="xpd-edu-label">${y(e)}</span><span class="xpd-edu-value">${y(t)}</span></div>`}function vf(){if(Ce.loading)return'<div class="xpd-loading">Loading XRP market snapshot...</div>';if(Ce.error)return`<div class="xpd-error">${y(Ce.error)}</div>`;let e=Ce.data;if(!e)return'<div class="xpd-empty">Market data is not available yet.</div>';let t=e.change24h>=0;return`
    <div class="xpd-market-grid">
      <article class="xpd-stat-card">
        <span class="xpd-stat-label">XRP Price</span>
        <strong class="xpd-stat-value">$${_(e.priceUsd,4)}</strong>
      </article>
      <article class="xpd-stat-card">
        <span class="xpd-stat-label">24h Change</span>
        <strong class="xpd-stat-value ${t?"up":"down"}">${t?"+":""}${_(e.change24h,2)}%</strong>
      </article>
      <article class="xpd-stat-card">
        <span class="xpd-stat-label">24h Volume</span>
        <strong class="xpd-stat-value">$${We(e.volume24h)}</strong>
      </article>
      <article class="xpd-stat-card">
        <span class="xpd-stat-label">Market Cap</span>
        <strong class="xpd-stat-value">$${We(e.marketCap)}</strong>
      </article>
    </div>
    <div class="xpd-token-strip">
      ${ef.map(n=>`<div class="xpd-token-pill" title="${y(`${n.symbol} ${n.name}`)}"><span class="sym xpd-pill-text">${n.symbol}</span><span class="xpd-pill-text">${y(n.name)}</span><span class="cap xpd-pill-text">${n.marketCap}</span></div>`).join("")}
    </div>
    <p class="xpd-note">Top XRPL token cards are static examples when direct DEX market-cap feeds are unavailable.</p>`}function bf(e){return e?bt.loading?'<div class="xpd-loading">Loading account NFTs...</div>':bt.error?`<div class="xpd-error">${y(bt.error)}</div>`:bt.items.length?`<div class="xpd-nft-grid">${bt.items.map(yf).join("")}</div>`:'<div class="xpd-empty">No NFTs found for this wallet.</div>':'<div class="xpd-empty">Select or create a wallet to load NFTs.</div>'}function yf(e){let t=`${e.id.slice(0,12)}...${e.id.slice(-10)}`;return`<article class="xpd-nft-card">
    <div class="xpd-nft-media">
      ${e.image?`<img src="${y(e.image)}" alt="NFT ${y(t)}" loading="lazy" onerror="this.closest('.xpd-nft-media').innerHTML='<div class=&quot;xpd-nft-placeholder&quot;>NFT</div>'"/>`:'<div class="xpd-nft-placeholder">NFT</div>'}
    </div>
    <div class="xpd-nft-body">
      <div class="xpd-nft-id mono" title="${y(e.id)}">${y(t)}</div>
      <button class="xpd-action" onclick="sendNft('${y(e.id)}')">Send NFT</button>
    </div>
  </article>`}function wf(e){let t=Lf(e),n=Mf(),s=Af();return`<div class="xpd-amm-columns">${t}${n}${s}</div>`}function li(){return(ve(Q(Ol))||[]).filter(Boolean)}function Gl(e){let t=[...new Set((e||[]).filter(Boolean))];Z(Ol,JSON.stringify(t))}function xf(e,t){return t.has(e)?t.get(e):U.tokens.find(s=>s.symbol===e)||null}function kf(){let e=U.query||"",t=li(),n=U.filtered,s=Math.max(120,Number(U.listLimit||240)),a=n.slice(0,s),o=U.trending.slice(0,14),i=new Map(U.tokens.map(c=>[Ue(c),c])),r=i.get(U.selectedTokenKey)||null,l=U.filters||{type:"all",minCap:0,minVol:0,hasDex:!1};return`
    <div class="xpd-token-grid">
      <div class="xpd-token-col">
        <div class="xpd-search-row">
          <input class="xpd-input" list="xpd-token-suggest" placeholder="Search symbol, token, issuer" value="${y(e)}" oninput="searchTokens(this.value)" />
          <datalist id="xpd-token-suggest">${U.tokens.slice(0,80).map(c=>`<option value="${y(c.symbol)}">${y(c.name)}</option>`).join("")}</datalist>
          <div class="xpd-note">Loaded ${We(U.total||n.length)} issued tokens \xB7 showing ${We(a.length)} of ${We(n.length)}${U.lastSyncAt?` \xB7 synced ${new Date(U.lastSyncAt).toLocaleTimeString()}`:""}</div>
          <div class="xpd-lookup-row" title="The search box above only finds tokens already in the loaded registry \u2014 use this to chart any XRPL issued currency directly by its currency code and issuer address.">
            <span class="xpd-lookup-label">Look up any issued asset</span>
            <div class="xpd-lookup-fields">
              <input id="xpd-lookup-currency" class="xpd-input" placeholder="Currency (e.g. SOLO)" maxlength="20" />
              <input id="xpd-lookup-issuer" class="xpd-input mono" placeholder="Issuer address (r...)" />
              <button class="xpd-action xpd-action--primary" onclick="lookupIssuedAsset()"><span class="xai">\u{1F50E}</span>Load</button>
              <button class="xpd-action" onclick="lookupAndAnalyzeProject()" title="Loads the token and jumps straight to its Project Strength dashboard"><span class="xai">\u{1F52C}</span>Analyze Project</button>
            </div>
          </div>
          <div class="xpd-token-filters">
            <select class="xpd-input" onchange="setTokenFilter('type', this.value)">
              <option value="all" ${l.type==="all"?"selected":""}>All Types</option>
              <option value="standard" ${l.type==="standard"?"selected":""}>Standard</option>
              <option value="mpt" ${l.type==="mpt"?"selected":""}>MPT</option>
              <option value="stablecoin" ${l.type==="stablecoin"?"selected":""}>Stablecoin</option>
              <option value="meme" ${l.type==="meme"?"selected":""}>Meme</option>
            </select>
            <select class="xpd-input" onchange="setTokenFilter('minCap', Number(this.value))">
              <option value="0" ${Number(l.minCap)===0?"selected":""}>Any Market Cap</option>
              <option value="1000000" ${Number(l.minCap)===1e6?"selected":""}>Cap > $1M</option>
              <option value="10000000" ${Number(l.minCap)===1e7?"selected":""}>Cap > $10M</option>
              <option value="100000000" ${Number(l.minCap)===1e8?"selected":""}>Cap > $100M</option>
            </select>
            <select class="xpd-input" onchange="setTokenFilter('minVol', Number(this.value))">
              <option value="0" ${Number(l.minVol)===0?"selected":""}>Any 24h Volume</option>
              <option value="10000" ${Number(l.minVol)===1e4?"selected":""}>Vol > $10k</option>
              <option value="100000" ${Number(l.minVol)===1e5?"selected":""}>Vol > $100k</option>
              <option value="1000000" ${Number(l.minVol)===1e6?"selected":""}>Vol > $1M</option>
            </select>
            <label><input type="checkbox" ${l.hasDex?"checked":""} onchange="setTokenFilter('hasDex', this.checked)"/> Has active DEX</label>
          </div>
          ${n.length>a.length?'<div class="xpd-row-actions"><button class="xpd-mini-btn" onclick="showMoreIssuedTokens()">Show More</button><button class="xpd-mini-btn" onclick="showAllIssuedTokens()">Show All</button><button class="xpd-mini-btn" onclick="resetIssuedTokenLimit()">Reset</button></div>':""}
        </div>
        ${U.loading?'<div class="xpd-loading">Loading XRPL issued token registry...</div>':""}
        ${U.error?`<div class="xpd-error">${y(U.error)}</div>`:""}
        ${!a.length&&!U.loading?`<div class="xpd-empty">No tokens match${e?` "${y(e)}"`:" the current filters"}. <button class="xpd-mini-btn" onclick="clearTokenFilters()">Clear search & filters</button></div>`:""}
        <div class="xpd-token-list">${a.map(c=>{let d=Ue(c),u=Ps(d),p=String(e||"").trim();return`
          <div class="xpd-token-row xpd-token-row--clickable" title="${y(`${c.symbol} ${c.name}`)}" onclick="openTokenOnChart(decodeURIComponent('${u}'))">
            <div class="xpd-token-main">
              <strong>${wl(c.symbol,p)}</strong>
              <span>${wl(c.name,p)}</span>
              ${c.issuer?`<span class="mono xpd-pill-text">${y(c.issuer)}</span>`:""}
            </div>
            <div class="xpd-token-actions">
              <span>${c.price!=null?`$${_(c.price,6)}`:"\u2014"}</span>
              ${Number.isFinite(c.holders)?`<span title="Holders">${We(c.holders)} holders</span>`:""}
              <button class="xpd-mini-btn" onclick="event.stopPropagation(); addTokenToWatchlist(decodeURIComponent('${u}'))">Watch</button>
              <button class="xpd-mini-btn" onclick="event.stopPropagation(); openTokenOnChart(decodeURIComponent('${u}'))">Chart</button>
              <button class="xpd-mini-btn" onclick="event.stopPropagation(); selectTokenDetails(decodeURIComponent('${u}'))">Details</button>
              ${c.issuer?`<button class="xpd-mini-btn xpd-mini-btn--accent" onclick="event.stopPropagation(); openProjectIntel(decodeURIComponent('${u}'))" title="Project Strength \u2014 liquidity depth, holder/LP concentration, issuer risk">\u{1F52C} Strength</button>`:""}
            </div>
          </div>`}).join("")}</div>
      </div>
      <div class="xpd-token-col">
        ${r?`<div class="xpd-token-detail-card">
          <h3>${y(r.symbol)} \xB7 ${y(r.name)}</h3>
          <div class="pool-meta">Issuer: <span class="mono">${y(r.issuer||"Native XRP")}</span></div>
          <div class="pool-meta">Token ID: <span class="mono">${y(r.tokenId||"\u2014")}</span></div>
          <div class="pool-meta">Price: ${r.price!=null?`$${_(r.price,6)}`:"\u2014"} \xB7 24h Vol: ${r.volume24h!=null?`$${We(r.volume24h)}`:"\u2014"}</div>
          <div class="pool-meta">Market Cap: ${r.marketCap!=null?`$${We(r.marketCap)}`:"\u2014"} \xB7 Holders: ${r.holders!=null?We(r.holders):"\u2014"}</div>
          <div class="xpd-row-actions">
            <button class="xpd-mini-btn" onclick="openTokenOnChart(decodeURIComponent('${Ps(Ue(r))}'))">Switch Main Chart</button>
            ${r.issuer?`<button class="xpd-mini-btn" onclick="window.open('https://xrpscan.com/account/${y(r.issuer)}','_blank')">View Issuer</button>`:""}
            ${r.issuer?`<button class="xpd-mini-btn xpd-mini-btn--accent" onclick="openProjectIntel(decodeURIComponent('${Ps(Ue(r))}'))">\u{1F52C} Project Strength</button>`:""}
          </div>
        </div>`:""}
        <h3>Watchlist</h3>
        <div class="xpd-watchlist">${t.length?t.map(c=>{let d=xf(c,i),u=d?`${d.symbol} \xB7 ${d.name}`:c,p=(d==null?void 0:d.price)!=null?`$${_(d.price,6)}`:"\u2014",m=Ps(c);return`<div class="xpd-token-row xpd-token-row--clickable" onclick="openTokenOnChart(decodeURIComponent('${m}'))"><span>${y(u)}</span><div class="xpd-token-actions"><span>${p}</span><button class="xpd-mini-btn" onclick="event.stopPropagation(); openTokenOnChart(decodeURIComponent('${m}'))">Chart</button><button class="xpd-mini-btn" onclick="event.stopPropagation(); removeTokenFromWatchlist(decodeURIComponent('${m}'))">Remove</button></div></div>`}).join(""):'<div class="xpd-empty">No watchlist tokens yet.</div>'}</div>
        <h3>Trending</h3>
        <div class="xpd-watchlist">${o.length?o.map(c=>`<div class="xpd-token-row xpd-token-row--clickable" onclick="openTokenOnChart(decodeURIComponent('${Ps(Ue(c))}'))"><span>${y(c.symbol)} \xB7 ${y(c.name)}</span><span>${c.volume24h!=null?`$${We(c.volume24h)} vol`:c.marketCap!=null?`$${We(c.marketCap)} mcap`:"\u2014"}</span></div>`).join(""):'<div class="xpd-empty">No trending data.</div>'}</div>
      </div>
    </div>`}function Kl(){let e=document.getElementById("xpd-lookup-currency");if(!e){ge("Token Discovery hasn't loaded yet \u2014 give it a moment and try again.");return}e.scrollIntoView({behavior:"smooth",block:"center"}),setTimeout(()=>e.focus(),350)}async function ci(e){let t=String(e||"").trim();if(!t)return;let n=t.includes("|")?U.tokens.find(s=>Ue(s)===t):U.tokens.find(s=>String(s.symbol||"").toUpperCase()===t.toUpperCase());if(!(n!=null&&n.issuer)){ge("Project Intelligence needs a token with a known issuer.");return}Je={loading:!0,error:"",data:null,tokenKey:Ue(n),expandedSubScore:""},j(),setTimeout(()=>{var s;return(s=document.getElementById("xpd-project-intel-section"))==null?void 0:s.scrollIntoView({behavior:"smooth",block:"start"})},30);try{Je={loading:!1,error:"",data:await pl(n),tokenKey:Ue(n),expandedSubScore:""}}catch(s){Je={loading:!1,error:(s==null?void 0:s.message)||"Could not load project intelligence.",data:null,tokenKey:Ue(n),expandedSubScore:""}}j()}function Jl(e){Je.expandedSubScore=Je.expandedSubScore===e?"":e,j()}function Yl(){Je={loading:!1,error:"",data:null,tokenKey:"",expandedSubScore:""},j()}var Ql={liquidity:{label:"Liquidity",icon:"\u{1F4A7}"},distribution:{label:"Distribution",icon:"\u{1F9EE}"},marketQuality:{label:"Market Quality",icon:"\u{1F4CA}"},lpStability:{label:"LP Stability",icon:"\u{1F3E6}"},issuerRisk:{label:"Issuer Risk",icon:"\u{1F6E1}"}};function Ho(e){return e>=75?"#50fa7b":e>=50?"#f1fa8c":e>=25?"#ffb86c":"#ff5555"}function Zl(e){return e>=75?"STRONG":e>=50?"MODERATE":e>=25?"WEAK":"VERY WEAK"}function $f(){if(Je.loading)return`<div class="xpd-section-head"><h2>\u{1F52C} Project Intelligence</h2></div>
      <div class="xpd-loading">Fetching AMM state, order-book depth, holder and LP concentration, and issuer flags\u2026</div>`;if(Je.error)return`<div class="xpd-section-head"><h2>\u{1F52C} Project Intelligence</h2>
      <button class="xpd-action" onclick="closeProjectIntel()">\u2715 Close</button></div>
      <div class="xpd-error">${y(Je.error)}</div>`;let e=Je.data;if(!e)return"";let t=e.strength,n=Ho(t.overall),s=t.dimensionsLive.map(a=>{let o=Ql[a],i=t.subScores[a],r=Je.expandedSubScore===a;return`
      <div class="pi-subscore ${r?"pi-subscore--open":""}" onclick="toggleProjectIntelSubScore('${a}')">
        <div class="pi-subscore-row">
          <span class="pi-subscore-label">${o.icon} ${o.label}</span>
          <span class="pi-subscore-val" style="color:${Ho(i.score)}">${i.score}</span>
        </div>
        <div class="pi-subscore-bar"><div class="pi-subscore-fill" style="width:${i.score}%;background:${Ho(i.score)}"></div></div>
        ${r?`<div class="pi-subscore-detail">${Object.entries(i.inputs).map(([l,c])=>`
          <div class="pi-kv"><span>${y(di(l))}</span><span class="mono">${y(ec(c))}</span></div>
        `).join("")}</div>`:""}
      </div>`}).join("");return`
    <div class="xpd-section-head">
      <h2>\u{1F52C} Project Intelligence \u2014 ${y(e.token.symbol)}</h2>
      <div class="xpd-section-head-actions">
        <button class="xpd-action" onclick="copyProjectIntelForAi()" title="Copy every metric on this page as plain text, ready to paste into ChatGPT, Claude, or any model you use">\u{1F4CB} Copy for AI</button>
        <button class="xpd-action" onclick="closeProjectIntel()">\u2715 Close</button>
      </div>
    </div>
    <div class="pi-methodology-note">
      Under this app's own methodology, ${y(e.token.symbol)}'s measurable on-ledger structure currently scores as shown below.
      This is not investment advice, and a high score is not a claim that this is a good investment \u2014 it reflects only the
      five dimensions computable from a live snapshot (Liquidity, Distribution, Market Quality, LP Stability, Issuer Risk).
      Network Activity, Treasury Health, and Project Transparency need historical tracking this app doesn't yet do, and are
      not included. Click any dimension below to see exactly what it's computed from.
    </div>
    <div class="pi-header-card">
      <div class="pi-score-big" style="color:${n}">${t.overall}<span class="pi-score-max">/100</span></div>
      <div class="pi-score-word" style="color:${n}">${Zl(t.overall)}</div>
      <div class="pi-issuer-line mono">Issuer: ${y(e.token.issuer)}</div>
    </div>
    <div class="pi-subscore-grid">${s}</div>

    <div class="pi-cards-grid">
      ${Sf(e)}
      ${vl("Holder Concentration",e.holders,"\u{1F465}")}
      ${vl("LP Token Concentration",e.lp,"\u{1F3E6}")}
      ${Tf(e.issuerRisk)}
    </div>`}function di(e){return e.replace(/([A-Z])/g," $1").replace(/^./,t=>t.toUpperCase()).trim()}function ec(e){return e==null?"\u2014":typeof e=="boolean"?e?"Yes":"No":typeof e=="number"?Number.isInteger(e)?String(e):_(e,2):String(e)}function Sf(e){var i;let t=e.amm,n=e.orderBook,s=t!=null&&t.exists?`
    <div class="pi-kv"><span>XRP reserve</span><span class="mono">${_(t.xrpReserve,2)} XRP</span></div>
    <div class="pi-kv"><span>Token reserve</span><span class="mono">${_(t.tokenReserve,2)}</span></div>
    <div class="pi-kv"><span>LP token supply</span><span class="mono">${_(t.lpSupply,2)}</span></div>
    <div class="pi-kv"><span>Trading fee</span><span class="mono">${_(t.tradingFeePct,3)}%</span></div>
    ${t.auctionSlot?`<div class="pi-kv"><span>Auction slot discount</span><span class="mono">${_(t.auctionSlot.discountedFeePct,3)}%</span></div>`:""}
    ${(i=t.voteSlots)!=null&&i.length?`<div class="pi-kv"><span>Fee-vote participants</span><span class="mono">${t.voteSlots.length}</span></div>`:""}
  `:'<div class="inspect-empty-note">No AMM pool found for this pair.</div>',a=(r,l)=>r!=null&&r.length?`
    <div class="pi-depth-title">${l}</div>
    <table class="pi-depth-table"><thead><tr><th>Impact</th><th>XRP</th><th>Tokens</th></tr></thead><tbody>
    ${r.map(c=>`<tr><td>${c.pct}%</td><td class="mono">${_(c.xrpAtOffer,1)}</td><td class="mono">${We(c.tokenAtOffer)}${c.bookExhausted?' <span title="Visible order book fully consumed before reaching this price-impact level \u2014 real depth may be less than shown, book is thin.">\u26A0</span>':""}</td></tr>`).join("")}
    </tbody></table>`:"",o=n!=null&&n.exists?`
    <div class="pi-kv"><span>Buy price</span><span class="mono">${_(n.buyPriceXrp,6)} XRP</span></div>
    <div class="pi-kv"><span>Sell price</span><span class="mono">${_(n.sellPriceXrp,6)} XRP</span></div>
    <div class="pi-kv"><span>Spread</span><span class="mono">${n.spreadPct!=null?_(n.spreadPct,2)+"%":"\u2014"}</span></div>
    ${a(n.buyDepth,"DEX Depth \u2014 buying with XRP")}
    ${a(n.sellDepth,"DEX Depth \u2014 selling for XRP")}
  `:'<div class="inspect-empty-note">No live order book found for this pair.</div>';return`
    <div class="sec-card pi-card">
      <div class="sec-card-hdr"><span class="sec-card-icon">\u{1F4A7}</span><div><div class="sec-card-title">Liquidity Intelligence</div><div class="sec-card-sub">AMM pool + real DEX depth, not just TVL</div></div></div>
      ${s}
      <hr class="pi-hr" />
      ${o}
    </div>`}function vl(e,t,n){if(!(t!=null&&t.exists))return`
    <div class="sec-card pi-card">
      <div class="sec-card-hdr"><span class="sec-card-icon">${n}</span><div><div class="sec-card-title">${y(e)}</div></div></div>
      <div class="inspect-empty-note">No holder data found.</div>
    </div>`;let s=(t.topHolders||[]).slice(0,8).map((a,o)=>`
    <div class="pi-holder-row">
      <span class="pi-holder-rank">${o+1}</span>
      <a href="https://xrpscan.com/account/${y(a.address)}" target="_blank" rel="noopener" class="mono pi-holder-addr">${y(a.address.slice(0,8))}\u2026${y(a.address.slice(-5))}</a>
      <span class="mono">${We(a.balance)}</span>
      <span class="mono pi-holder-pct">${t.totalSampled>0?_(a.balance/t.totalSampled*100,1):"0.0"}%</span>
    </div>`).join("");return`
    <div class="sec-card pi-card">
      <div class="sec-card-hdr"><span class="sec-card-icon">${n}</span><div><div class="sec-card-title">${y(e)}</div><div class="sec-card-sub">${We(t.holderCount)} holders${t.sampleOnly?" (sampled, capped)":""}</div></div></div>
      <div class="pi-kv"><span>Top 1</span><span class="mono">${_(t.top1Pct,1)}%</span></div>
      <div class="pi-kv"><span>Top 5</span><span class="mono">${_(t.top5Pct,1)}%</span></div>
      <div class="pi-kv"><span>Top 10</span><span class="mono">${_(t.top10Pct,1)}%</span></div>
      <hr class="pi-hr" />
      ${s}
    </div>`}var xt={clawbackEnabled:"The issuer has the technical capability to reclaim issued balances under XRPL's clawback mechanism. Consider the project's stated policy and use case.",globalFreeze:"The issuer has currently frozen all trustlines for this currency \u2014 holders cannot move balances until it's lifted.",freezeCapable:"The issuer retains the ability to freeze individual trustlines. Common and not inherently malicious, but a real capability worth knowing about.",requireAuth:"The issuer must approve each trustline before it can hold a balance \u2014 restricts who can hold this token.",blackholed:"The issuer has permanently disabled its master key and holds no regular key \u2014 issuer-side control of the account is no longer possible."};function Tf(e){if(!(e!=null&&e.exists))return`
    <div class="sec-card pi-card">
      <div class="sec-card-hdr"><span class="sec-card-icon">\u{1F6E1}</span><div><div class="sec-card-title">Issuer Risk</div></div></div>
      <div class="inspect-empty-note">Could not load issuer account state.</div>
    </div>`;let t=(n,s,a)=>`
    <div class="finding finding--${s?a?"ok":"warn":"ok"}">
      <span class="finding-sev ${s?a?"sev-ok":"sev-warn":"sev-ok"}">${s?a?"YES":"\u26A0":"NO"}</span>
      <div class="finding-body">
        <div class="finding-label">${di(n)}</div>
        <div class="finding-detail">${y(xt[n]||"")}</div>
      </div>
    </div>`;return`
    <div class="sec-card pi-card">
      <div class="sec-card-hdr"><span class="sec-card-icon">\u{1F6E1}</span><div><div class="sec-card-title">Issuer Risk</div><div class="sec-card-sub">Token controls \u2014 neutral facts, not a verdict</div></div></div>
      ${t("clawbackEnabled",e.clawbackEnabled,!1)}
      ${t("globalFreeze",e.globalFreeze,!1)}
      ${t("freezeCapable",e.freezeCapable,!1)}
      ${t("requireAuth",e.requireAuth,!1)}
      ${t("blackholed",e.blackholed,!0)}
    </div>`}function tc(){let e=Je.data;e&&Ia(Cf(e))}function bl(e,t){if(!(e!=null&&e.length))return"";let n=e.map(s=>`    ${s.pct}% impact: ${_(s.xrpAtOffer,1)} XRP / ${We(s.tokenAtOffer)} tokens${s.bookExhausted?" (book exhausted before this level \u2014 real depth may be less than shown)":""}`).join(`
`);return`  ${t}:
${n}`}function yl(e,t){let n=[`${e}:`];return t!=null&&t.exists?(n.push(`  Holder count: ${t.holderCount}${t.sampleOnly?" (sampled, capped)":""}`),n.push(`  Top 1 holds: ${_(t.top1Pct,1)}%`),n.push(`  Top 5 hold: ${_(t.top5Pct,1)}%`),n.push(`  Top 10 hold: ${_(t.top10Pct,1)}%`),(t.topHolders||[]).slice(0,10).forEach((s,a)=>{let o=t.totalSampled>0?_(s.balance/t.totalSampled*100,2):"0.00";n.push(`    #${a+1} ${s.address}: ${We(s.balance)} (${o}%)`)}),n.join(`
`)):(n.push("  No data found."),n.join(`
`))}function Cf(e){var i;let t=e.strength,n=e.amm,s=e.orderBook,a=e.issuerRisk,o=[];if(o.push(`XRPL TOKEN ANALYSIS \u2014 ${e.token.symbol}${e.token.name?` (${e.token.name})`:""}`),o.push(`Issuer: ${e.token.issuer}`),o.push(`Currency code: ${e.token.currency}`),o.push(`Snapshot taken: ${new Date(e.fetchedAt).toISOString()}`),o.push(""),o.push(`OVERALL STRENGTH SCORE: ${t.overall}/100 (${Zl(t.overall)})`),o.push("Methodology note: this score covers only 5 point-in-time-computable dimensions (Liquidity, Distribution, Market Quality, LP Stability, Issuer Risk). Network Activity, Treasury Health, and Project Transparency are NOT included \u2014 they would require historical tracking this tool does not do."),o.push(""),o.push("SUB-SCORES:"),t.dimensionsLive.forEach(r=>{let l=Ql[r],c=t.subScores[r];o.push(`- ${l.label}: ${c.score}/100`),Object.entries(c.inputs||{}).forEach(([d,u])=>{o.push(`    ${di(d)}: ${ec(u)}`)})}),o.push(""),o.push("LIQUIDITY \u2014 AMM POOL:"),n!=null&&n.exists?(o.push(`  XRP reserve: ${_(n.xrpReserve,2)}`),o.push(`  Token reserve: ${_(n.tokenReserve,2)}`),o.push(`  LP token supply: ${_(n.lpSupply,2)}`),o.push(`  Trading fee: ${_(n.tradingFeePct,3)}%`),n.auctionSlot&&o.push(`  Auction slot discounted fee: ${_(n.auctionSlot.discountedFeePct,3)}%`),(i=n.voteSlots)!=null&&i.length&&o.push(`  Fee-vote participants: ${n.voteSlots.length}`)):o.push("  No AMM pool found for this pair."),o.push(""),o.push("LIQUIDITY \u2014 LIVE ORDER BOOK (DEX):"),s!=null&&s.exists){o.push(`  Buy price: ${_(s.buyPriceXrp,6)} XRP`),o.push(`  Sell price: ${_(s.sellPriceXrp,6)} XRP`),o.push(`  Spread: ${s.spreadPct!=null?_(s.spreadPct,2)+"%":"\u2014"}`);let r=bl(s.buyDepth,"Depth buying with XRP"),l=bl(s.sellDepth,"Depth selling for XRP");r&&o.push(r),l&&o.push(l)}else o.push("  No live order book found for this pair.");return o.push(""),o.push(yl("HOLDER CONCENTRATION",e.holders)),o.push(""),o.push(yl("LP TOKEN CONCENTRATION",e.lp)),o.push(""),o.push("ISSUER RISK FLAGS:"),a!=null&&a.exists?(o.push(`  Clawback enabled: ${a.clawbackEnabled?"YES":"No"} \u2014 ${xt.clawbackEnabled}`),o.push(`  Global freeze active: ${a.globalFreeze?"YES":"No"} \u2014 ${xt.globalFreeze}`),o.push(`  Freeze-capable: ${a.freezeCapable?"YES":"No"} \u2014 ${xt.freezeCapable}`),o.push(`  Requires auth to hold: ${a.requireAuth?"YES":"No"} \u2014 ${xt.requireAuth}`),o.push(`  Issuer blackholed: ${a.blackholed?"YES":"No"} \u2014 ${xt.blackholed}`)):o.push("  Could not load issuer account state."),o.push(""),o.push("---"),o.push("Please analyze this XRPL token's on-chain data above. Explain in plain language what these metrics suggest about the token's liquidity health, holder/LP concentration risk, and issuer-side control risk. Point out anything that looks like a red flag or an unusually strong/weak signal, and note any limits in what this data can and can't tell me (e.g. it's a point-in-time snapshot, not history)."),o.join(`
`)}function wl(e,t){let n=String(e||""),s=String(t||"").trim();if(!s)return y(n);let a=n.toLowerCase().indexOf(s.toLowerCase());if(a<0)return y(n);let o=y(n.slice(0,a)),i=y(n.slice(a,a+s.length)),r=y(n.slice(a+s.length));return`${o}<mark class="xpd-hit">${i}</mark>${r}`}function Pf(e){var a,o;let t=Object.values(Ye).reduce((i,r)=>i+((r==null?void 0:r.xrp)||0),0),n=(a=Ce.data)!=null&&a.priceUsd?t*Ce.data.priceUsd:0,s=Pt.items.slice(0,8);return`
    <div class="xpd-token-grid">
      <div class="xpd-token-col">
        <div class="xpd-market-grid">
          <article class="xpd-stat-card xpd-token-row--clickable" onclick="openTokenOnChart('XRP')"><span class="xpd-stat-label">Portfolio XRP</span><strong class="xpd-stat-value">${_(t,4)}</strong></article>
          <article class="xpd-stat-card"><span class="xpd-stat-label">Portfolio USD</span><strong class="xpd-stat-value">${n?`$${_(n,2)}`:"\u2014"}</strong></article>
          <article class="xpd-stat-card"><span class="xpd-stat-label">Wallets</span><strong class="xpd-stat-value">${re.length}</strong></article>
          <article class="xpd-stat-card"><span class="xpd-stat-label">Network Stream</span><strong class="xpd-stat-value">${((o=B.wsConn)==null?void 0:o.readyState)===1?"Online":"Offline"}</strong></article>
        </div>
      </div>
      <div class="xpd-token-col">
        ${Pt.loading?'<div class="xpd-loading">Loading recent transactions...</div>':""}
        ${Pt.error?`<div class="xpd-error">${y(Pt.error)}</div>`:""}
        <div class="xpd-watchlist">${e?s.length?s.map(i=>`<div class="xpd-token-row"><span class="mono">${y((i.hash||"").slice(0,12))}...</span><span>${y(i.TransactionType||"Unknown")}</span></div>`).join(""):'<div class="xpd-empty">No recent transactions.</div>':'<div class="xpd-empty">Select wallet to view transactions.</div>'}</div>
      </div>
    </div>`}function Lf(e){return e?yt.loading?'<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-loading">Loading account_objects and LP balances...</div></div>':yt.error?`<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-error">${y(yt.error)}</div></div>`:yt.pools.length?`<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-pool-list">${yt.pools.map(t=>`
    <div class="xpd-pool-item">
      <div class="pool-pair xpd-pill-text" title="${y(t.pair)}">${y(t.pair)}</div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">LP Balance</span><span class="xpd-pool-row-value" title="${y(t.lpBalance)}">${y(t.lpBalance)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Est. Value</span><span class="xpd-pool-row-value">${y(t.estimatedValue)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Trading Fee</span><span class="xpd-pool-row-value">${y(t.tradingFee||"\u2014")}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">TVL</span><span class="xpd-pool-row-value">${y(t.tvl||"Unavailable")}</span></div>
    </div>`).join("")}</div></div>`:'<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-empty">No AMM entries or LP-token balances detected for this wallet yet.</div></div>':'<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-empty">No active wallet.</div></div>'}function Mf(){return Lt.loading?'<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-loading">Loading amm_info for known pools...</div></div>':Lt.error?`<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-error">${y(Lt.error)}</div></div>`:Lt.pools.length?`<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-pool-list">${Lt.pools.map(e=>`
    <div class="xpd-pool-item">
      <div class="pool-pair xpd-pill-text" title="${y(e.label)}">${y(e.label)}</div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Reserves</span><span class="xpd-pool-row-value">${y(e.reserveA)} / ${y(e.reserveB)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Trading Fee</span><span class="xpd-pool-row-value">${y(e.tradingFee)} bps</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Total LP</span><span class="xpd-pool-row-value mono" title="${y(e.totalLp)}">${y(e.totalLp)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">TVL</span><span class="xpd-pool-row-value">${y(e.tvl||"Unavailable")}</span></div>
    </div>`).join("")}</div></div>`:'<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-empty">No seeded pools returned on this network.</div></div>'}function Af(){return`<div class="xpd-amm-card">
    <h3>Lookup custom pool</h3>
    <div class="xpd-form-grid">
      <input id="xpd-asset1-currency" class="xpd-input" placeholder="Asset 1 currency (e.g. XRP)" />
      <input id="xpd-asset1-issuer" class="xpd-input" placeholder="Asset 1 issuer (optional for XRP)" />
      <input id="xpd-asset2-currency" class="xpd-input" placeholder="Asset 2 currency (e.g. USD)" />
      <input id="xpd-asset2-issuer" class="xpd-input" placeholder="Asset 2 issuer" />
    </div>
    <div class="xpd-row-actions"><button class="xpd-action" onclick="loadCustomAmmPool()"><span class="xai">\u{1F50E}</span>Load pool</button><button class="xpd-action" onclick="refreshPoolExplorer()"><span class="xai">\u27F3</span>Refresh known pools</button></div>
    ${_e.loading?'<div class="xpd-loading">Loading pool...</div>':""}
    ${_e.error?`<div class="xpd-error">${y(_e.error)}</div>`:""}
    ${_e.pool?`<div class="xpd-pool-item">
      <div class="pool-pair xpd-pill-text" title="${y(_e.pool.label)}">${y(_e.pool.label)}</div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Reserves</span><span class="xpd-pool-row-value">${y(_e.pool.reserveA)} / ${y(_e.pool.reserveB)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Trading Fee</span><span class="xpd-pool-row-value">${y(_e.pool.tradingFee)} bps</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Total LP</span><span class="xpd-pool-row-value mono" title="${y(_e.pool.totalLp)}">${y(_e.pool.totalLp)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">TVL</span><span class="xpd-pool-row-value">${y(_e.pool.tvl||"Unavailable")}</span></div>
    </div>`:""}
  </div>`}function We(e){return Number.isFinite(Number(e))?new Intl.NumberFormat("en-US",{notation:"compact",maximumFractionDigits:2}).format(Number(e)):"\u2014"}function ts(e){return typeof e=="string"?`${_(Number(e)/1e6,4)} XRP`:e&&typeof e=="object"?`${_(Number(e.value||0),4)} ${e.currency||"UNK"}`:"\u2014"}function Ef(e){if(!e||typeof e!="string")return"";try{let t=e.trim();if(!/^[0-9A-Fa-f]+$/.test(t)||t.length%2!==0)return t;let n=new Uint8Array(t.length/2);for(let s=0;s<t.length;s+=2)n[s/2]=parseInt(t.slice(s,s+2),16);return new TextDecoder().decode(n)}catch{return""}}function xl(e){return e?e.startsWith("ipfs://")?`https://ipfs.io/ipfs/${e.slice(7)}`:e.startsWith("ar://")?`https://arweave.net/${e.slice(5)}`:e:""}async function Nf(e){let t=xl(Ef(e.URI||e.uri||""));if(!t)return"";if(/\.(png|jpg|jpeg|gif|webp|svg)$/i.test(t))return t;try{let n=await fetch(t,{method:"GET"});if(!n.ok)return"";let s=await n.json(),a=(s==null?void 0:s.image)||(s==null?void 0:s.image_url)||(s==null?void 0:s.thumbnail);return xl(a||"")}catch{return""}}async function Mt(e,{timeoutMs:t=9e3,allowProxy:n=!0}={}){let s=async a=>{let o=typeof(AbortSignal==null?void 0:AbortSignal.timeout)=="function"?AbortSignal.timeout(t):void 0,i=await fetch(a,{method:"GET",mode:"cors",cache:"no-store",signal:o});if(!i.ok)throw new Error(`HTTP ${i.status}`);return await i.json()};try{return await s(e)}catch(a){if(!n)throw a;for(let o of Om)try{return await s(o(e))}catch{}throw a}}async function nc(){var e;Ce.loading=!0,Ce.error="",j();try{let t=await Mt("https://api.exchange.coinbase.com/products/XRP-USD/ticker"),n=await Mt("https://api.exchange.coinbase.com/products/XRP-USD/candles?granularity=86400"),s=Array.isArray(n)&&n.length?n[0]:null,a=Number((t==null?void 0:t.price)||0),o=s?Number(s[3]||0):a,i=s?Number(s[2]||a):a,r=s?Number(s[1]||a):a,l=s?Number(s[5]||0):0;Ce.data={priceUsd:a,change24h:o?(a-o)/o*100:0,volume24h:l*a,marketCap:Number(((e=Ce.data)==null?void 0:e.marketCap)||0),high24h:i,low24h:r}}catch(t){Ce.error=(t==null?void 0:t.message)||"Could not load market data right now.",Ce.data=null}finally{Ce.loading=!1,j()}}async function sc(e){if(bt.loading=!0,bt.error="",bt.items=[],j(),!e){bt.loading=!1,j();return}try{let t,n=[];do{let a=await st({method:"account_nfts",params:[{account:e,limit:100,...t?{marker:t}:{}}]});n.push(...(a==null?void 0:a.account_nfts)||[]),t=a==null?void 0:a.marker}while(t);let s=await Promise.all(n.slice(0,80).map(async a=>({id:a.NFTokenID||a.nf_token_id||"Unknown",image:await Nf(a)})));bt.items=s}catch(t){bt.error=(t==null?void 0:t.message)||"Could not load NFTs for this wallet."}finally{bt.loading=!1,j()}}async function ac(e){if(yt.loading=!0,yt.error="",yt.pools=[],j(),!e){yt.loading=!1,j();return}try{let t=[],n;do{let o=await st({method:"account_objects",params:[{account:e,type:"amm",limit:200,...n?{marker:n}:{}}]});((o==null?void 0:o.account_objects)||[]).forEach(r=>{let l=ts(r.Asset||r.amount),c=ts(r.Asset2||r.amount2),d=l.split(" ").pop()||"AssetA",u=c.split(" ").pop()||"AssetB";t.push({pair:`${d}/${u}`,lpBalance:r.LPTokenBalance?ts(r.LPTokenBalance):"Not reported",estimatedValue:"Estimate unavailable",tradingFee:r.TradingFee!=null?`${r.TradingFee} bps`:"\u2014",tvl:"Unavailable"})}),n=o==null?void 0:o.marker}while(n);let s=await st({method:"account_lines",params:[{account:e,limit:200}]});((s==null?void 0:s.lines)||[]).filter(o=>typeof o.currency=="string"&&o.currency.length>=16&&Number(o.balance)>0).forEach(o=>{t.push({pair:`LP Token ${o.currency.slice(0,8)}...`,lpBalance:`${_(Number(o.balance),4)} ${o.currency.slice(0,8)}...`,estimatedValue:"Estimate unavailable",tradingFee:"\u2014",tvl:"Unavailable"})}),yt.pools=t}catch(t){yt.error=(t==null?void 0:t.message)||"Could not load account AMM objects."}finally{yt.loading=!1,j()}}async function oc(e){try{let t=await st({method:"amm_info",params:[{asset:e.asset,asset2:e.asset2}]}),n=t==null?void 0:t.amm;return n?{label:e.label,reserveA:ts(n.amount),reserveB:ts(n.amount2),tradingFee:String(n.trading_fee??"\u2014"),totalLp:ts(n.lp_token||n.lp_token_balance),tvl:Rf(n.amount,n.amount2)}:null}catch{return null}}function Rf(e,t){let n=a=>typeof a=="string"?Number(a)/1e6:a&&typeof a=="object"?Number(a.value||0):0,s=n(e)+n(t);return!Number.isFinite(s)||s<=0?"Unavailable":`${_(s,4)} (asset units)`}async function ic(){Lt.loading=!0,Lt.error="",j();try{let e=await Promise.all(af.map(oc));Lt.pools=e.filter(Boolean)}catch(e){Lt.error=(e==null?void 0:e.message)||"Could not load AMM explorer data.",Lt.pools=[]}finally{Lt.loading=!1,j()}}async function rc(){var r,l,c,d;let e=(((r=document.getElementById("xpd-asset1-currency"))==null?void 0:r.value)||"").trim().toUpperCase(),t=(((l=document.getElementById("xpd-asset1-issuer"))==null?void 0:l.value)||"").trim(),n=(((c=document.getElementById("xpd-asset2-currency"))==null?void 0:c.value)||"").trim().toUpperCase(),s=(((d=document.getElementById("xpd-asset2-issuer"))==null?void 0:d.value)||"").trim();if(!e||!n){_e.error="Enter both asset currency codes first.",j();return}let a=e==="XRP"?{currency:"XRP"}:{currency:e,issuer:t},o=n==="XRP"?{currency:"XRP"}:{currency:n,issuer:s};if(e!=="XRP"&&!t||n!=="XRP"&&!s){_e.error="Issuer is required for non-XRP assets.",j();return}_e.loading=!0,_e.error="",_e.pool=null,j();let i=await oc({label:`${e}/${n}`,asset:a,asset2:o});_e.loading=!1,i?_e.pool=i:_e.error="Pool not found or unavailable on this network.",j()}function Ea(){return In.find(e=>e.id===P.pair)||In[0]}function pi(e){if(e==="D")return 1440;if(e==="W")return 10080;if(e==="M")return 43200;let t=Number(e);return Number.isFinite(t)&&t>0?t:60}function _f(e){if(e==="M")return"W";if(e==="D"||e==="W")return e;let t=pi(e);for(let n of[5,15,60,240])if(t<=n)return String(n);return"D"}async function Df(e,t,n,s=200){var d;let a=t?`${e}.${t}`:e,o=_f(n),i=Math.min(2e3,Math.max(20,Number(s)||200)),r=`https://api.onthedex.live/public/v1/ohlc?base=${encodeURIComponent(a)}&quote=XRP&interval=${o}&bars=${i}`,l=await Mt(r,{timeoutMs:1e4});return(Array.isArray((d=l==null?void 0:l.data)==null?void 0:d.ohlc)?l.data.ohlc:[]).map(u=>({time:Number(u.t),open:Number(u.o),high:Number(u.h),low:Number(u.l),close:Number(u.c),volume:Number(u.vb||0)})).filter(u=>Number.isFinite(u.time)&&[u.open,u.high,u.low,u.close].every(Number.isFinite)).sort((u,p)=>u.time-p.time)}function lc(e){return{xrpusd:"XRP-USD",XRPUSDT:"XRP-USD",ETHUSDT:"ETH-USD",BTCUSDT:"BTC-USD",SOLUSDT:"SOL-USD"}[e]||null}function If(e){return{XRP:"XRP-USD",BTC:"BTC-USD",ETH:"ETH-USD",SOL:"SOL-USD",USDC:"USDC-USD"}[String(e||"").toUpperCase()]||null}var zo=new Map;async function Ff(e,t){if(!e)return null;let n=`${Ue(e)}:${t}`,s=zo.get(n);if(s)return s;let a=Of(e,t);zo.set(n,a);try{return await a}finally{zo.delete(n)}}async function Of(e,t){var o,i;let n=String(e.symbol||"").toUpperCase();if(!n||n==="XRP")return null;let s=If(n);if(s)try{let r=pc(t),l=r===86400?Il:Fl,{candles:c,reachedStart:d}=await Yo(s,r,l);if(c.length){let u=d?`${new Date(c[0].time*1e3).getUTCFullYear()}\u2013present`:`last ${c.length} bars`;return{candles:c,source:`Coinbase direct (${s}, ${u})`,mode:"token-direct"}}}catch{}let a=String(e.issuer||"").trim();if(a)try{let r=await Df(n,a,t,2e3);if(r.length){let l=Number(((o=P.stats)==null?void 0:o.xrplSpot)||((i=P.stats)==null?void 0:i.price)||0);return{candles:l>0?r.map(d=>({time:d.time,open:d.open*l,high:d.high*l,low:d.low*l,close:d.close*l,volume:d.volume})):r,source:`OnTheDex XRPL DEX (${n}/XRP)`,mode:"token-direct"}}}catch{}return null}function Bf(e,{mode:t="pair",source:n="Source pending",tokenKey:s=""}={}){let a=Array.isArray(e)?e:[];if(!a.length){P.chartMeta={tokenKey:s||P.tokenFocusKey||"XRP|",symbol:s&&s.split("|")[0]||"XRP",source:n,last:null,high:null,low:null,mode:t};return}let o=a[a.length-1],i=a.map(c=>Number(c.high)).filter(c=>Number.isFinite(c)),r=a.map(c=>Number(c.low)).filter(c=>Number.isFinite(c)),l=s||P.tokenFocusKey||"XRP|";P.chartMeta={tokenKey:l,symbol:l.split("|")[0]||"XRP",source:n,last:Number(o.close),high:i.length?Math.max(...i):Number(o.high),low:r.length?Math.min(...r):Number(o.low),mode:t}}async function Is(){var t;let e=Ea();P.loading=!0,P.error="";try{let n=lc(e.ticker);if(n){let s=await Mt(`https://api.exchange.coinbase.com/products/${n}/ticker`),a=await Mt(`https://api.exchange.coinbase.com/products/${n}/candles?granularity=86400`),o=Array.isArray(a)&&a.length?a[0]:null,i=Number(s.price||0),r=o?Number(o[3]):i;P.stats={price:i,high:o?Number(o[2]):i,low:o?Number(o[1]):i,changePct:r?(i-r)/r*100:0,baseSource:"Coinbase",source:"Coinbase"},await cc(),!Ce.data&&P.stats.price&&(Ce.data={priceUsd:P.stats.price,change24h:P.stats.changePct,volume24h:o?Number(o[5]||0)*P.stats.price:0,marketCap:Number(((t=Ce.data)==null?void 0:t.marketCap)||0)});return}throw new Error("Chart stats unavailable for selected pair.")}catch(n){P.error=(n==null?void 0:n.message)||"DEX chart stats unavailable right now."}finally{P.loading=!1}}async function cc(){var e,t,n;try{let s=await st({method:"book_offers",params:[{taker_gets:{currency:"USD",issuer:"rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq"},taker_pays:{currency:"XRP"},limit:1}]}),a=(e=s==null?void 0:s.offers)==null?void 0:e[0];if(!a)return;let o=Number(((t=a.TakerGets)==null?void 0:t.value)||0),i=typeof a.TakerPays=="string"?Number(a.TakerPays)/1e6:Number(((n=a.TakerPays)==null?void 0:n.value)||0);if(o>0&&i>0){let r=o/i;if(Dl=Date.now(),P.stats||(P.stats={}),P.stats.xrplSpot=r,String(Ea().symbol||"XRP").toUpperCase()==="XRP"){P.stats.price=r;let l=P.stats.baseSource||P.stats.source||"Market feed";P.stats.source=`${l} + XRPL live`,Ce.data&&(Ce.data.priceUsd=r)}}}catch{}}async function Xf(){var e,t;return(e=window.LightweightCharts)!=null&&e.createChart?!0:(ka||(ka=new Promise((n,s)=>{let a=document.querySelector('script[data-lw-chart="1"]');if(a){a.addEventListener("load",()=>n(!0),{once:!0}),a.addEventListener("error",()=>s(new Error("Chart library failed to load.")),{once:!0});return}let o=document.createElement("script");o.src="https://unpkg.com/lightweight-charts@4.2.2/dist/lightweight-charts.standalone.production.js",o.async=!0,o.defer=!0,o.dataset.lwChart="1",o.onload=()=>n(!0),o.onerror=()=>s(new Error("Chart library failed to load.")),document.head.appendChild(o)}).finally(()=>{var n;(n=window.LightweightCharts)!=null&&n.createChart||(ka=null)})),await ka,!!((t=window.LightweightCharts)!=null&&t.createChart))}async function Hf(){var e,t;return(e=window.THREE)!=null&&e.Scene?!0:($a||($a=new Promise((n,s)=>{let a=document.querySelector('script[data-three-chart="1"]');if(a){a.addEventListener("load",()=>n(!0),{once:!0}),a.addEventListener("error",()=>s(new Error("Three.js failed to load.")),{once:!0});return}let o=document.createElement("script");o.src="https://unpkg.com/three@0.166.1/build/three.min.js",o.async=!0,o.defer=!0,o.dataset.threeChart="1",o.onload=()=>n(!0),o.onerror=()=>s(new Error("Three.js failed to load.")),document.head.appendChild(o)}).finally(()=>{var n;(n=window.THREE)!=null&&n.Scene||($a=null)})),await $a,!!((t=window.THREE)!=null&&t.Scene))}function Fs(){var e,t;if(Ve.resizeHandler)try{window.removeEventListener("resize",Ve.resizeHandler)}catch{}if(Ve.raf&&cancelAnimationFrame(Ve.raf),(t=(e=Ve.renderer)==null?void 0:e.domElement)!=null&&t.parentElement)try{Ve.renderer.domElement.parentElement.removeChild(Ve.renderer.domElement)}catch{}if(Ve.renderer)try{Ve.renderer.dispose()}catch{}Ve={renderer:null,scene:null,camera:null,points:null,raf:0,host:null,resizeHandler:null}}async function zf(){var t;let e=document.getElementById("xpd-chart-atmosphere");if(e&&!(Ve.renderer&&e.contains(Ve.renderer.domElement))&&!((navigator.hardwareConcurrency||4)<=3))try{if(await Hf(),!((t=window.THREE)!=null&&t.Scene))return;Fs();let n=window.THREE,s=Math.max(1,e.clientWidth||640),a=Math.max(1,e.clientHeight||460),o=new n.Scene,i=new n.PerspectiveCamera(52,s/a,.1,1e3);i.position.z=46;let r=new n.WebGLRenderer({alpha:!0,antialias:!0});r.setPixelRatio(Math.min(2,window.devicePixelRatio||1)),r.setSize(s,a),e.appendChild(r.domElement);let l=900,c=new Float32Array(l*3);for(let h=0;h<l;h+=1){let v=h*3;c[v]=(Math.random()-.5)*90,c[v+1]=(Math.random()-.5)*40,c[v+2]=(Math.random()-.5)*24}let d=new n.BufferGeometry;d.setAttribute("position",new n.BufferAttribute(c,3));let u=new n.PointsMaterial({color:5101823,size:.25,transparent:!0,opacity:.26,depthWrite:!1}),p=new n.Points(d,u);o.add(p);let m=0,f=0,g=()=>{var $;m+=1;let h=Number((($=P.stats)==null?void 0:$.changePct)||0),v=Math.min(4,Math.max(.35,Math.abs(h)/2.2)),w=h>0?16758874:16739999;u.color.setHex(Math.abs(h)>1.5?w:5101823),p.rotation.y+=9e-4*v,p.rotation.x=Math.sin(m*.0015*v)*.08,p.position.y=Math.sin(m*.003*v)*.7,(!document.hidden||Date.now()-f>350)&&(r.render(o,i),f=Date.now()),Ve.raf=requestAnimationFrame(g)},b=()=>{let h=Math.max(1,e.clientWidth||640),v=Math.max(1,e.clientHeight||460);i.aspect=h/v,i.updateProjectionMatrix(),r.setSize(h,v)};window.addEventListener("resize",b,{passive:!0}),Ve={renderer:r,scene:o,camera:i,points:p,raf:0,host:e,resizeHandler:b},g()}catch{}}function dc(e){return pi(e)*60}function pc(e){let t=pi(e);return t<=1?60:t<=5?300:t<=15?900:t<=60?3600:t<=360?21600:86400}function uc(){let e=String(P.tokenFocusKey||"");if(!e)return null;let t=e.includes("|")?e.split("|")[0]:e;return U.tokens.find(n=>Ue(n)===e)||U.tokens.find(n=>String(n.symbol||"").toUpperCase()===String(t||"").toUpperCase())||null}function mc(){var a,o;let e=uc(),t=Number((e==null?void 0:e.price)||0);if(Number.isFinite(t)&&t>0)return t;let n=Number(((a=P.stats)==null?void 0:a.xrplSpot)||0);if(Number.isFinite(n)&&n>0)return n;let s=Number(((o=P.stats)==null?void 0:o.price)||0);return Number.isFinite(s)&&s>0?s:1}function fc(e,t=1,n=220){let s=Math.max(60,dc(e)),a=Math.floor(Date.now()/1e3),o=Math.floor(a/s)*s-n*s,i=Math.max(1e-6,Number(t)||1),r=[];for(let l=0;l<n;l+=1){let c=o+l*s,d=i,u=Math.sin((l+1)/9)*.004+Math.cos((l+3)/17)*.002;i=Math.max(1e-6,d*(1+u));let p=Math.max(d,i)*(1+Math.abs(u)*.55+.0015),m=Math.min(d,i)*Math.max(1e-6,1-(Math.abs(u)*.55+.0015));r.push({time:c,open:Number(d),high:Number(p),low:Number(m),close:Number(i),volume:Math.max(0,Math.round(Math.abs(u)*12e3+l%13*55))})}return r}function Go(e){if(!e.length)return e;let t=[];for(let n=0;n<e.length;n+=1){let s=e[n],a=(s.open+s.high+s.low+s.close)/4,o=t[n-1],i=o?(o.open+o.close)/2:(s.open+s.close)/2,r=Math.max(s.high,i,a),l=Math.min(s.low,i,a);t.push({...s,open:i,high:r,low:l,close:a})}return t}function Ko(e,t){let n=[],s=0;for(let a=0;a<e.length;a+=1)s+=e[a].close,a>=t&&(s-=e[a-t].close),a>=t-1&&n.push({time:e[a].time,value:s/t});return n}function _s(e,t){let n=[];if(!e.length)return n;let s=2/(t+1),a=e[0].close;for(let o=0;o<e.length;o+=1)a=o===0?e[o].close:e[o].close*s+a*(1-s),o>=t-1&&n.push({time:e[o].time,value:a});return n}function Wf(e,t){let n=[],s=t*(t+1)/2;for(let a=t-1;a<e.length;a+=1){let o=0;for(let i=0;i<t;i+=1)o+=e[a-i].close*(t-i);n.push({time:e[a].time,value:o/s})}return n}function Uf(e,t=20,n=2){let s=Ko(e,t),a=[],o=[];for(let i=t-1;i<e.length;i+=1){let r=e.slice(i-t+1,i+1),l=s[i-(t-1)].value,c=r.reduce((u,p)=>u+Math.pow(p.close-l,2),0)/t,d=Math.sqrt(c);a.push({time:e[i].time,value:l+d*n}),o.push({time:e[i].time,value:l-d*n})}return{upper:a,lower:o}}function jf(e){let t=[],n=0,s=0;for(let a=0;a<e.length;a+=1){let o=(e[a].high+e[a].low+e[a].close)/3;n+=o*(e[a].volume||0),s+=e[a].volume||0,s>0&&t.push({time:e[a].time,value:n/s})}return t}function qf(e,t=14){let n=[];if(e.length<=t)return n;let s=0,a=0;for(let r=1;r<=t;r+=1){let l=e[r].close-e[r-1].close;s+=l>0?l:0,a+=l<0?-l:0}let o=s/t,i=a/t;for(let r=t+1;r<e.length;r+=1){let l=e[r].close-e[r-1].close;o=(o*(t-1)+(l>0?l:0))/t,i=(i*(t-1)+(l<0?-l:0))/t;let c=i>0?o/i:100;n.push({time:e[r].time,value:100-100/(1+c)})}return n}function ui(e,t=14){let n=[];for(let o=0;o<e.length;o+=1){let i=o>0?e[o-1].close:e[o].close;n.push(Math.max(e[o].high-e[o].low,Math.abs(e[o].high-i),Math.abs(e[o].low-i)))}let s=[],a=n.slice(0,t).reduce((o,i)=>o+i,0)/Math.max(1,t);for(let o=t;o<e.length;o+=1)a=(a*(t-1)+n[o])/t,s.push({time:e[o].time,value:a});return s}function Vf(e,t=14,n=3){let s=[];for(let o=t-1;o<e.length;o+=1){let i=e.slice(o-t+1,o+1),r=Math.max(...i.map(d=>d.high)),l=Math.min(...i.map(d=>d.low)),c=r!==l?(e[o].close-l)/(r-l)*100:50;s.push({time:e[o].time,value:c})}let a=[];for(let o=n-1;o<s.length;o+=1){let i=s.slice(o-n+1,o+1).reduce((r,l)=>r+l.value,0)/n;a.push({time:s[o].time,value:i})}return{k:s,d:a}}function Gf(e,t=12,n=26,s=9){let a=_s(e,t),o=_s(e,n),i=new Map(o.map(u=>[u.time,u.value])),r=a.filter(u=>i.has(u.time)).map(u=>({time:u.time,value:u.value-i.get(u.time)})),l=[];if(r.length){let u=2/(s+1),p=r[0].value;for(let m=0;m<r.length;m+=1)p=m===0?r[m].value:r[m].value*u+p*(1-u),m>=s-1&&l.push({time:r[m].time,value:p})}let c=new Map(l.map(u=>[u.time,u.value])),d=r.filter(u=>c.has(u.time)).map(u=>({time:u.time,value:u.value-c.get(u.time)}));return{line:r,signal:l,hist:d}}function hc(e,t=9,n=26,s=52){let a=u=>{let p=[];for(let m=u-1;m<e.length;m+=1){let f=e.slice(m-u+1,m+1);p.push({time:e[m].time,value:(Math.max(...f.map(g=>g.high))+Math.min(...f.map(g=>g.low)))/2})}return p},o=a(t),i=a(n),r=new Map(i.map(u=>[u.time,u.value])),l=o.filter(u=>r.has(u.time)).map(u=>({time:u.time,value:(u.value+r.get(u.time))/2})),c=a(s),d=e.map(u=>({time:u.time,value:u.close}));return{tenkan:o,kijun:i,senkouA:l,senkouB:c,chikou:d}}function Kf(e,t=20){let n=[],s=[],a=[];for(let o=t-1;o<e.length;o+=1){let i=e.slice(o-t+1,o+1),r=Math.max(...i.map(c=>c.high)),l=Math.min(...i.map(c=>c.low));n.push({time:e[o].time,value:r}),s.push({time:e[o].time,value:l}),a.push({time:e[o].time,value:(r+l)/2})}return{upper:n,lower:s,mid:a}}function Jf(e,t=20,n=2){let s=_s(e,t),a=ui(e,t),o=new Map(a.map(l=>[l.time,l.value])),i=[],r=[];return s.forEach(l=>{if(o.has(l.time)){let c=o.get(l.time)*n;i.push({time:l.time,value:l.value+c}),r.push({time:l.time,value:l.value-c})}}),{upper:i,lower:r,mid:s}}function Yf(e){let t=[],n=[],s=0,a=0;for(let o=0;o<e.length;o+=1){if(o>0){let l=e[o-1];e[o].close>l.close&&(s+=e[o].volume||0),e[o].close<l.close&&(s-=e[o].volume||0)}let i=e[o].high-e[o].low||1,r=(e[o].close-e[o].low-(e[o].high-e[o].close))/i;a+=r*(e[o].volume||0),t.push({time:e[o].time,value:s}),n.push({time:e[o].time,value:a})}return{obv:t,adline:n}}function Qf(e,t=14){if(e.length<t+2)return{adx:[],plusDi:[],minusDi:[]};let n=[],s=[],a=[];for(let p=1;p<e.length;p+=1){let m=e[p].high-e[p-1].high,f=e[p-1].low-e[p].low;s.push(m>f&&m>0?m:0),a.push(f>m&&f>0?f:0),n.push(Math.max(e[p].high-e[p].low,Math.abs(e[p].high-e[p-1].close),Math.abs(e[p].low-e[p-1].close)))}let o=n.slice(0,t).reduce((p,m)=>p+m,0),i=s.slice(0,t).reduce((p,m)=>p+m,0),r=a.slice(0,t).reduce((p,m)=>p+m,0),l=[],c=[],d=[];for(let p=t;p<n.length;p+=1){o=o-o/t+n[p],i=i-i/t+s[p],r=r-r/t+a[p];let m=o>0?100*i/o:0,f=o>0?100*r/o:0,g=m+f>0?100*Math.abs(m-f)/(m+f):0,b=e[p+1].time;l.push({time:b,value:m}),c.push({time:b,value:f}),d.push({time:b,value:g})}let u=[];if(d.length>=t){let p=d.slice(0,t).reduce((m,f)=>m+f.value,0)/t;for(let m=t;m<d.length;m+=1)p=(p*(t-1)+d[m].value)/t,u.push({time:d[m].time,value:p})}return{adx:u,plusDi:l,minusDi:c}}function Zf(e,t=14){let n=[],s=[];for(let a=t-1;a<e.length;a+=1){let o=e.slice(a-t+1,a+1),i=0,r=0;for(let d=1;d<o.length;d+=1)o[d].high>=o[i].high&&(i=d),o[d].low<=o[r].low&&(r=d);let l=t-1-i,c=t-1-r;n.push({time:e[a].time,value:(t-l)/t*100}),s.push({time:e[a].time,value:(t-c)/t*100})}return{up:n,down:s}}function eh(e,t=14){let n=[],s=[];if(e.length<t+2)return{plus:n,minus:s};for(let a=t;a<e.length;a+=1){let o=0,i=0,r=0;for(let l=a-t+1;l<=a;l+=1){let c=e[l-1],d=e[l];o+=Math.max(d.high-d.low,Math.abs(d.high-c.close),Math.abs(d.low-c.close)),i+=Math.abs(d.high-c.low),r+=Math.abs(d.low-c.high)}n.push({time:e[a].time,value:o>0?i/o:0}),s.push({time:e[a].time,value:o>0?r/o:0})}return{plus:n,minus:s}}function th(e,t=10,n=3){let s=ui(e,t),a=new Map(s.map(c=>[c.time,c.value])),o=[],i=0,r=0,l=!0;return e.forEach((c,d)=>{if(d===0||!a.has(c.time))return;let u=(c.high+c.low)/2,p=a.get(c.time),m=u+n*p,f=u-n*p;d>1&&(m>i&&e[d-1].close<=i&&(m=i),f<r&&e[d-1].close>=r&&(f=r));let g=c.close>m?!0:c.close<f?!1:l,b=g?f:m;o.push({time:c.time,value:b,trendUp:g?1:0}),i=m,r=f,l=g}),o}function nh(e,t=14){let n=[];if(e.length<=t)return n;let s=e.map((a,o)=>{let i=(a.high+a.low+a.close)/3,r=o>0?(e[o-1].high+e[o-1].low+e[o-1].close)/3:i,l=i*(a.volume||0);return{time:a.time,pos:i>=r?l:0,neg:i<r?l:0}});for(let a=t;a<s.length;a+=1){let o=s.slice(a-t+1,a+1),i=o.reduce((c,d)=>c+d.pos,0),r=o.reduce((c,d)=>c+d.neg,0),l=r>0?i/r:100;n.push({time:s[a].time,value:100-100/(1+l)})}return n}function sh(e,t=14){let n=[];for(let s=t-1;s<e.length;s+=1){let a=e.slice(s-t+1,s+1),o=Math.max(...a.map(l=>l.high)),i=Math.min(...a.map(l=>l.low)),r=o!==i?(o-e[s].close)/(o-i)*-100:-50;n.push({time:e[s].time,value:r})}return n}function ah(e,t=20){let n=[],s=e.map(a=>({time:a.time,value:(a.high+a.low+a.close)/3}));for(let a=t-1;a<s.length;a+=1){let o=s.slice(a-t+1,a+1),i=o.reduce((c,d)=>c+d.value,0)/t,r=o.reduce((c,d)=>c+Math.abs(d.value-i),0)/t,l=r>0?(s[a].value-i)/(.015*r):0;n.push({time:s[a].time,value:l})}return n}function oh(e){if(e.length<30)return[];let t=[],n=[];for(let o=1;o<e.length;o+=1){let i=e[o-1].close,r=Math.min(e[o].low,i),l=Math.max(e[o].high,i);t.push({time:e[o].time,value:e[o].close-r}),n.push({time:e[o].time,value:l-r})}let s=(o,i,r)=>o.slice(i-r+1,i+1).reduce((l,c)=>l+c.value,0),a=[];for(let o=27;o<t.length;o+=1){let i=s(t,o,7)/Math.max(1e-9,s(n,o,7)),r=s(t,o,14)/Math.max(1e-9,s(n,o,14)),l=s(t,o,28)/Math.max(1e-9,s(n,o,28));a.push({time:t[o].time,value:100*(4*i+2*r+l)/7})}return a}function ih(e,t=20){let n=[],s=e.map(a=>{let o=a.high-a.low||1,i=(a.close-a.low-(a.high-a.close))/o;return{time:a.time,value:i*(a.volume||0),volume:a.volume||0}});for(let a=t-1;a<s.length;a+=1){let o=s.slice(a-t+1,a+1),i=o.reduce((l,c)=>l+c.value,0),r=o.reduce((l,c)=>l+c.volume,0);n.push({time:s[a].time,value:r>0?i/r:0})}return n}function rh(e){return(Array.isArray(e)?e:[]).map(t=>({time:Number(t[0]),low:Number(t[1]),high:Number(t[2]),open:Number(t[3]),close:Number(t[4]),volume:Number(t[5])})).filter(t=>Number.isFinite(t.time)&&[t.open,t.high,t.low,t.close].every(Number.isFinite))}function Jo(e,t){let n=new Map;for(let s of e)n.set(s.time,s);for(let s of t)n.set(s.time,s);return Array.from(n.values()).sort((s,a)=>s.time-a.time)}async function Yo(e,t,n){let s=[],a=Math.floor(Date.now()/1e3),o=!1;for(let i=0;i<n;i+=1){let r=a-t*300,l=`https://api.exchange.coinbase.com/products/${e}/candles?granularity=${t}&start=${new Date(r*1e3).toISOString()}&end=${new Date(a*1e3).toISOString()}`,c;try{c=await Mt(l,{timeoutMs:1e4})}catch{break}let d=rh(c);if(!d.length){o=!0;break}s.push(...d),a=r,i<n-1&&await Zm(Qm)}return{candles:Jo(s,[]),reachedStart:o}}async function lh(e,t,n){if(!e||!Number.isFinite(t)||!Number.isFinite(n)||n<=t)return[];try{let s=`https://api.coingecko.com/api/v3/coins/${e}/market_chart/range?vs_currency=usd&from=${t}&to=${n}`,a=await Mt(s,{timeoutMs:15e3});return(Array.isArray(a==null?void 0:a.prices)?a.prices:[]).map(([i,r])=>({time:Math.floor(Number(i)/1e3/86400)*86400,open:Number(r),high:Number(r),low:Number(r),close:Number(r),volume:0})).filter(i=>Number.isFinite(i.time)&&Number.isFinite(i.close)&&i.close>0).sort((i,r)=>i.time-r.time)}catch{return[]}}async function ch(e,t,n){var u;let s=pc(n),a=s===86400,o=`${Ym}${e.id}:${s}`,i=ve(Q(o));if((u=i==null?void 0:i.candles)!=null&&u.length&&i.reachedStart){let p=await Yo(t,s,1),m=Jo(i.candles,p.candles);return Z(o,JSON.stringify({candles:m,reachedStart:!0,source:i.source,cachedAt:Date.now()})),{candles:m,source:i.source}}let l=await Yo(t,s,a?Il:Fl),c=l.candles,d=c.length?`Coinbase (${new Date(c[0].time*1e3).getUTCFullYear()}\u2013present, ${c.length} bars)`:"Coinbase";if(a&&l.reachedStart&&e.coingeckoId&&c.length){let p=c[0].time,m=await lh(e.coingeckoId,0,p);m.length&&(c=Jo(m,c),d=`CoinGecko (${new Date(c[0].time*1e3).getUTCFullYear()}+) + Coinbase (${new Date(p*1e3).getUTCFullYear()}\u2013present)`)}else!a&&!l.reachedStart&&(d=`Coinbase (last ${c.length} bars \u2014 full inception history is daily/weekly/monthly only)`);return c.length&&Z(o,JSON.stringify({candles:c,reachedStart:l.reachedStart,source:d,cachedAt:Date.now()})),{candles:c,source:d}}var Wo=new Map;async function gc(e,t){let n=`${e.id}:${t}`,s=As.get(n);if(s&&Date.now()-s.ts<6e4&&Array.isArray(s.data)&&s.data.length)return s.data;let a=Wo.get(n);if(a)return a;let o=(async()=>{let i=[],r="",l=lc(e.ticker);if(l)try{let c=await ch(e,l,t);i=c.candles,r=c.source}catch{i=[]}if(!Array.isArray(i)||!i.length){let c=fc(t,mc());return As.set(n,{ts:Date.now(),data:c,sourceLabel:""}),c}return As.set(n,{ts:Date.now(),data:i,sourceLabel:r}),i})();Wo.set(n,o);try{return await o}finally{Wo.delete(n)}}async function dh(){var u,p,m,f,g,b,h,v;let e=Ea(),t=await gc(e,P.interval),s=((u=As.get(`${e.id}:${P.interval}`))==null?void 0:u.sourceLabel)||String(((p=P.stats)==null?void 0:p.source)||"Coinbase + XRPL live"),a="pair",o=uc(),i=String((o==null?void 0:o.symbol)||"").toUpperCase(),r=o?Ue(o):`${e.symbol||"XRP"}|`;if(o&&i&&i!=="XRP"){let w=await Ff(o,P.interval);(m=w==null?void 0:w.candles)!=null&&m.length&&(t=w.candles,s=w.source,a=w.mode)}let l=String(e.symbol||"XRP").toUpperCase()==="XRP",c=Number((l?(f=P.stats)==null?void 0:f.xrplSpot:null)??((g=P.stats)==null?void 0:g.price)??0);if(a==="pair"&&Number.isFinite(c)&&c>0&&t.length){let w=Math.max(60,dc(P.interval)),k=Math.floor(Date.now()/1e3),$=Math.floor(k/w)*w,T=t[t.length-1];T.time===$?(T.high=Math.max(T.high,c),T.low=Math.min(T.low,c),T.close=c):T.time<$&&t.push({time:$,open:T.close,high:Math.max(T.close,c),low:Math.min(T.close,c),close:c,volume:0})}let d=Number((o==null?void 0:o.price)||0);if(a==="pair"&&o&&i&&i!=="XRP"&&Number.isFinite(d)&&d>0&&t.length){let w=Number((l?(b=P.stats)==null?void 0:b.xrplSpot:null)??((h=P.stats)==null?void 0:h.price)??((v=t[t.length-1])==null?void 0:v.close)??0);if(Number.isFinite(w)&&w>0){let k=d/w;Number.isFinite(k)&&k>0&&(t=t.map($=>({...$,open:$.open*k,high:$.high*k,low:$.low*k,close:$.close*k})),s="Coinbase pair + token spot proxy",a="token-proxy")}}return t.length||(t=fc(P.interval,mc()),s=o&&i!=="XRP"?"Synthetic fallback (token-focused)":"Synthetic fallback",a="fallback"),o&&i!=="XRP"&&(a==="pair"||a==="fallback")?Xo!==r&&(Xo=r,ge(`No market data found for ${o.symbol} yet \u2014 showing ${e.symbol||"XRP"} for reference.`)):r&&(Xo=""),P.chartType==="heikin_ashi"&&(t=Go(t)),Bf(t,{mode:a,source:s,tokenKey:r||"XRP|"}),t}function kl(e){if(!Array.isArray(e))return[];let t=e.map(s=>({time:Number(s.time),open:Number(s.open),high:Number(s.high),low:Number(s.low),close:Number(s.close),volume:Number(s.volume||0)})).filter(s=>Number.isFinite(s.time)&&Number.isFinite(s.open)&&Number.isFinite(s.high)&&Number.isFinite(s.low)&&Number.isFinite(s.close)&&s.time>0).sort((s,a)=>s.time-a.time),n=[];for(let s=0;s<t.length;s+=1){let a=t[s],o=n[n.length-1];o&&o.time===a.time?n[n.length-1]=a:n.push(a)}return n}function ph(e,t,n){var i;let s=Number(((i=e==null?void 0:e[e.length-1])==null?void 0:i.close)||0);if(!Number.isFinite(s)||s<=0)return 6;let o=Math.max(1e-12,Math.abs(Number(n)-Number(t)))/Math.max(1e-12,Math.abs(s));return s>=1e3?o<.01?4:2:s>=1?o<.01?6:4:s>=.01?o<.03?8:6:8}function uh(){if(ee.resizeObserver)try{ee.resizeObserver.disconnect()}catch{}ee.chart&&(ee.chart.remove(),ee={chart:null,volumeSeries:null,activeSeries:null,compareSeries:null,indicatorSeries:[],indicatorPriceLines:[],priceLines:[],resizeObserver:null,chartType:"",configKey:"",legendEl:null,renderLegend:null,ichimokuData:null,indicatorLegendItems:[],alertPriceLines:[]})}function $l(e,t){var d;let{addOverlay:n,addOsc:s,addOscHist:a,addPriceLevel:o}=t,i=(u,p)=>{var f,g;let m=Number((g=(f=P.indicatorSettings)==null?void 0:f[u])==null?void 0:g.length);return Number.isFinite(m)&&m>1?Math.min(500,Math.max(2,m)):p},r=(u,p,m)=>{var b,h;let f=(h=(b=P.indicatorSettings)==null?void 0:b[u])==null?void 0:h[p];if(f==null||f==="")return m;let g=(oi[u]||[]).find(v=>v.id===p);if((g==null?void 0:g.type)==="number"){let v=Number(f);return Number.isFinite(v)&&v>1?Math.min(500,Math.max(2,v)):m}return f},l=P.indicators;if(l.sma20&&n(Ko(e,i("sma20",20)),r("sma20","color","#f1c40f"),1.2,!1,"SMA"),l.ema20&&n(_s(e,i("ema20",20)),r("ema20","color","#ffb86c"),1.2,!1,"EMA"),l.wma20&&n(Wf(e,i("wma20",20)),r("wma20","color","#bd93f9"),1.2,!1,"WMA"),l.vwap&&n(jf(e),r("vwap","color","#80ffea"),1.2,!1,"VWAP"),l.bb20){let u=r("bb20","color","#ff79c6"),p=Uf(e,i("bb20",20),2);n(p.upper,u,1,!0,"BB Upper"),n(p.lower,u,1,!0,"BB Lower")}if(l.ichimoku){let u=hc(e,r("ichimoku","tenkanLen",9),r("ichimoku","kijunLen",26),r("ichimoku","senkouBLen",52));n(u.tenkan,r("ichimoku","tenkanColor","#ffde59"),1.2,!1,"Tenkan"),n(u.kijun,r("ichimoku","kijunColor","#6ecbff"),1.2,!1,"Kijun"),n(u.senkouA,"rgba(70,255,160,0.8)",1,!0,"Senkou A"),n(u.senkouB,"rgba(255,120,120,0.8)",1,!0,"Senkou B"),n(u.chikou,"rgba(220,220,255,0.6)",.9,!0,"Chikou")}if(l.donchian){let u=r("donchian","color","#9cfb8c"),p=Kf(e,i("donchian",20));n(p.upper,u,1,!0,"Donchian Upper"),n(p.lower,u,1,!0,"Donchian Lower"),n(p.mid,"rgba(156,251,140,0.6)",1.2,!1,"Donchian Mid")}if(l.keltner){let u=r("keltner","color","#7ee7ff"),p=Jf(e,i("keltner",20),2);n(p.upper,u,1,!0,"Keltner Upper"),n(p.lower,u,1,!0,"Keltner Lower"),n(p.mid,"rgba(126,231,255,0.66)",1.2,!1,"Keltner Mid")}if(l.pivots&&e.length>=2){let u=e[e.length-2],p=(u.high+u.low+u.close)/3,m=2*p-u.low,f=2*p-u.high,g=p+(u.high-u.low),b=p-(u.high-u.low);o(p,"#f6f6f6","P"),o(m,"#61ffb0","R1"),o(f,"#ff8f8f","S1"),o(g,"rgba(97,255,176,0.6)","R2"),o(b,"rgba(255,143,143,0.6)","S2")}if(l.supertrend||l.sar||l.elderRay){let u=_s(e,14);if(l.supertrend&&n(th(e,10,3),r("supertrend","color","#8bffde"),1.3,!1,"Supertrend"),l.sar&&n(u.map(p=>({time:p.time,value:p.value*.998})),r("sar","color","#ffaf7a"),1,!0,"SAR"),l.elderRay){let p=new Map(u.map(g=>[g.time,g.value])),m=e.filter(g=>p.has(g.time)).map(g=>({time:g.time,value:g.high-p.get(g.time)})),f=e.filter(g=>p.has(g.time)).map(g=>({time:g.time,value:g.low-p.get(g.time)}));s(m,r("elderRay","bullColor","#5fff9d"),"Elder Bull"),s(f,r("elderRay","bearColor","#ff9d9d"),"Elder Bear")}}if(l.rsi&&s(qf(e,i("rsi",14)),r("rsi","color","#a6ff4d"),"RSI"),l.atr&&s(ui(e,i("atr",14)),r("atr","color","#ffb86c"),"ATR"),l.stdev){let u=Ko(e,20),p=new Map(u.map(f=>[f.time,f.value])),m=e.filter(f=>p.has(f.time)).map(f=>({time:f.time,value:Math.abs(f.close-p.get(f.time))}));s(m,r("stdev","color","#b2a3ff"),"StdDev")}if(l.stoch){let u=Vf(e,i("stoch",14),3);s(u.k,r("stoch","kColor","#9ee8ff"),"%K"),s(u.d,r("stoch","dColor","#ffd86b"),"%D")}if(l.macd){let u=Gf(e,r("macd","fastLen",12),r("macd","slowLen",26),r("macd","signalLen",9));s(u.line,r("macd","lineColor","#8fd9ff"),"MACD"),s(u.signal,r("macd","signalColor","#ffcf8e"),"Signal"),(d=u.hist)!=null&&d.length&&a(u.hist)}let c=Yf(e);if(l.obv&&s(c.obv,r("obv","color","#8cf9ff"),"OBV"),l.adline&&s(c.adline,r("adline","color","#ffb7ff"),"A/D"),l.cmf&&s(ih(e,i("cmf",20)),r("cmf","color","#f8ff87"),"CMF"),l.williamsr&&s(sh(e,i("williamsr",14)),r("williamsr","color","#ff9adf"),"Williams %R"),l.cci&&s(ah(e,i("cci",20)),r("cci","color","#b8ff8e"),"CCI"),l.mfi&&s(nh(e,i("mfi",14)),r("mfi","color","#7bffd2"),"MFI"),l.uo&&s(oh(e),r("uo","color","#ffd36f"),"UO"),l.adx){let u=Qf(e,i("adx",14));s(u.adx,r("adx","adxColor","#9fd8ff"),"ADX"),s(u.plusDi,r("adx","plusColor","#73ffc0"),"+DI"),s(u.minusDi,r("adx","minusColor","#ff9797"),"-DI")}if(l.aroon){let u=Zf(e,i("aroon",14));s(u.up,r("aroon","upColor","#6cffb0"),"Aroon Up"),s(u.down,r("aroon","downColor","#ff8f8f"),"Aroon Down")}if(l.vortex){let u=eh(e,i("vortex",14));s(u.plus.map(p=>({time:p.time,value:p.value*100})),r("vortex","plusColor","#d6a8ff"),"VI+"),s(u.minus.map(p=>({time:p.time,value:p.value*100})),r("vortex","minusColor","#ffb0f3"),"VI-")}}function mh(e){let t=e.querySelector(":scope > svg.xpd-ichimoku-cloud-svg");return t||(t=document.createElementNS("http://www.w3.org/2000/svg","svg"),t.setAttribute("class","xpd-ichimoku-cloud-svg"),e.appendChild(t)),t}function fh(e){var t;(t=e==null?void 0:e.querySelector(":scope > svg.xpd-ichimoku-cloud-svg"))==null||t.remove()}function vc(e,t,n,s,a){var b;if(!e||!t||!n)return;let o=n.clientWidth||0,i=n.clientHeight||0;if(!o||!i||!(s!=null&&s.length)||!(a!=null&&a.length))return;let r=mh(n);r.setAttribute("width",o),r.setAttribute("height",i),r.setAttribute("viewBox",`0 0 ${o} ${i}`);let l=((b=P.indicatorSettings)==null?void 0:b.ichimoku)||{},c=l.bullColor||"#46ffa0",d=l.bearColor||"#ff7878",u=new Map(a.map(h=>[h.time,h.value])),p=e.timeScale(),m=[];for(let h of s){let v=u.get(h.time);if(v==null)continue;let w=p.timeToCoordinate(h.time),k=t.priceToCoordinate(h.value),$=t.priceToCoordinate(v);w==null||k==null||$==null||m.push({x:w,ya:k,yb:$,bullish:h.value>=v})}let f="",g=0;for(let h=1;h<=m.length;h+=1){if(!(h===m.length||m[h].bullish!==m[g].bullish))continue;let w=m.slice(g,h);if(w.length>=2){let k=w.map(S=>`${S.x.toFixed(1)},${S.ya.toFixed(1)}`).join(" "),$=w.slice().reverse().map(S=>`${S.x.toFixed(1)},${S.yb.toFixed(1)}`).join(" "),T=w[0].bullish?c:d;f+=`<polygon points="${k} ${$}" fill="${y(T)}" opacity="0.22" />`}g=h}r.innerHTML=f}function Sl(e,t,n,s){var i;if(!P.indicators.ichimoku){fh(s),ee.ichimokuData=null;return}let a=((i=P.indicatorSettings)==null?void 0:i.ichimoku)||{},o=hc(e,Number(a.tenkanLen)||9,Number(a.kijunLen)||26,Number(a.senkouBLen)||52);ee.ichimokuData={senkouA:o.senkouA,senkouB:o.senkouB},vc(t,n,s,o.senkouA,o.senkouB)}function Qo(){let e=ee.ichimokuData,t=document.getElementById("xpd-tv-widget");e&&ee.chart&&ee.activeSeries&&t&&vc(ee.chart,ee.activeSeries,t,e.senkouA,e.senkouB)}async function hh(){var n,s,a,o;let e=++Nn,t=document.getElementById("xpd-tv-widget");if(t){ee.chart||(t.innerHTML='<div class="xpd-loading">Loading full price history\u2026</div>');try{P.threeEnabled?zf():Fs();let i=await dh(),r=kl(i);if(e!==Nn)return;if(!r.length)throw new Error("No chart bars returned for selected pair/timeframe.");vh(r);let l=JSON.stringify({pair:P.pair,interval:P.interval,chartType:P.chartType,comparePair:P.comparePair,indicators:P.indicators,indicatorSettings:P.indicatorSettings,threeEnabled:P.threeEnabled});if(!P.comparePair&&!(P.drawings||[]).length&&ee.chart&&ee.configKey===l){let X=P.chartType==="heikin_ashi"?Go(r):r;P.chartType==="line"||P.chartType==="area"?ee.activeSeries.setData(X.map(Y=>({time:Y.time,value:Y.close}))):ee.activeSeries.setData(X),ee.volumeSeries.setData(r.map(Y=>({time:Y.time,value:Y.volume||0,color:Y.close>=Y.open?"rgba(38,166,154,0.5)":"rgba(239,83,80,0.5)"})));let q=0,se=0,me=[];$l(r,{addOverlay:(Y,he,tt,it,Ct)=>{let Dt=ee.indicatorSeries[q++];Y!=null&&Y.length&&(Dt==null||Dt.setData(Y),Ct&&Dt&&me.push({label:Ct,color:he,series:Dt,points:Y}))},addOsc:(Y,he,tt)=>{let it=ee.indicatorSeries[q++];Y!=null&&Y.length&&(it==null||it.setData(Y),tt&&it&&me.push({label:tt,color:he,series:it,points:Y}))},addOscHist:Y=>{let he=ee.indicatorSeries[q++];Y!=null&&Y.length&&(he==null||he.setData(Y.map(tt=>({time:tt.time,value:tt.value,color:tt.value>=0?"rgba(99,255,157,0.45)":"rgba(255,126,126,0.45)"}))))},addPriceLevel:Y=>{let he=ee.indicatorPriceLines[se++];Number.isFinite(Y)&&(he==null||he.applyOptions({price:Y}))}}),ee.indicatorLegendItems=me,Sl(r,ee.chart,ee.activeSeries,t),Tl(ee.activeSeries);let Re=r[r.length-1];(n=ee.renderLegend)==null||n.call(ee,Re.open,Re.high,Re.low,Re.close,Re.volume);return}if(!await Xf())throw new Error("Chart library failed to load.");if(e!==Nn)return;let d=document.getElementById("xpd-tv-widget");if(!d||e!==Nn)return;let u=null;try{u=((s=ee.chart)==null?void 0:s.timeScale().getVisibleLogicalRange())||null}catch{}uh(),d.innerHTML="";let p=window.LightweightCharts,m=Math.max(320,d.clientWidth||((a=d.parentElement)==null?void 0:a.clientWidth)||320),f=Math.max(360,d.clientHeight||460),g=r.map(X=>X.low),b=r.map(X=>X.high),h=ph(r,Math.min(...g),Math.max(...b)),v={type:"price",precision:h,minMove:Math.pow(10,-h)},w="#26a69a",k="#ef5350",$=p.createChart(d,{width:m,height:f,layout:{background:{type:p.ColorType.Solid,color:"#131722"},textColor:"#d1d4dc"},grid:{vertLines:{color:"#242832"},horzLines:{color:"#242832"}},rightPriceScale:{borderColor:"rgba(197,203,206,0.3)"},leftPriceScale:{visible:!1,borderColor:"rgba(197,203,206,0.3)"},timeScale:{borderColor:"rgba(197,203,206,0.3)",timeVisible:!0,secondsVisible:!1},crosshair:{mode:p.CrosshairMode.Normal},handleScroll:!0,handleScale:!0}),T=P.chartType==="heikin_ashi"?Go(r):r,S;if(P.chartType==="line")S=$.addLineSeries({color:"#2962ff",lineWidth:2,priceFormat:v}),S.setData(T.map(X=>({time:X.time,value:X.close})));else if(P.chartType==="area")S=$.addAreaSeries({lineColor:"#2962ff",topColor:"rgba(41,98,255,0.36)",bottomColor:"rgba(41,98,255,0.04)",lineWidth:2,priceFormat:v}),S.setData(T.map(X=>({time:X.time,value:X.close})));else if(P.chartType==="bars")S=$.addBarSeries({upColor:w,downColor:k,priceFormat:v}),S.setData(T);else{let X=P.chartType==="hollow_candles";S=$.addCandlestickSeries({upColor:X?"rgba(0,0,0,0)":w,downColor:k,borderUpColor:w,borderDownColor:k,wickUpColor:w,wickDownColor:k,borderVisible:!0,priceFormat:v}),S.setData(T)}let M=$.addHistogramSeries({priceFormat:{type:"volume"},priceScaleId:"vol"});$.priceScale("vol").applyOptions({scaleMargins:{top:.85,bottom:0}}),M.setData(r.map(X=>({time:X.time,value:X.volume||0,color:X.close>=X.open?"rgba(38,166,154,0.5)":"rgba(239,83,80,0.5)"})));let C=document.createElement("div");C.className="xpd-chart-legend",d.appendChild(C);let E=X=>Number.isFinite(X)?X.toFixed(h):"\u2014",R=(X,q,se,me,xe,Te)=>{let qe=me>=X,Fe=(Te||[]).map(Re=>`<span style="color:${y(Re.color)}">${y(Re.label)} <b>${E(Re.value)}</b></span>`).join("");C.innerHTML=`
        <span>O <b>${E(X)}</b></span>
        <span>H <b>${E(q)}</b></span>
        <span>L <b>${E(se)}</b></span>
        <span class="${qe?"xpd-legend-up":"xpd-legend-down"}">C <b>${E(me)}</b></span>
        ${xe!=null?`<span>Vol <b>${We(xe)}</b></span>`:""}
        ${Fe}
      `},O=T[T.length-1],I=(o=r[r.length-1])==null?void 0:o.volume,D=()=>{if(!O)return;let X=O.open??O.value,q=O.high??O.value,se=O.low??O.value,me=O.close??O.value,xe=(ee.indicatorLegendItems||[]).map(Te=>{var qe,Fe;return{label:Te.label,color:Te.color,value:(Fe=(qe=Te.points)==null?void 0:qe[Te.points.length-1])==null?void 0:Fe.value}}).filter(Te=>Number.isFinite(Te.value));R(X,q,se,me,I,xe)};D(),$.subscribeCrosshairMove(X=>{var Re,Y;if(!X.time){D();return}let q=(Re=X.seriesData)==null?void 0:Re.get(S);if(!q){D();return}let se=(Y=X.seriesData)==null?void 0:Y.get(M),me=q.open??q.value,xe=q.high??q.value,Te=q.low??q.value,qe=q.close??q.value,Fe=(ee.indicatorLegendItems||[]).map(he=>{var tt,it;return{label:he.label,color:he.color,value:(it=(tt=X.seriesData)==null?void 0:tt.get(he.series))==null?void 0:it.value}}).filter(he=>Number.isFinite(he.value));R(me,xe,Te,qe,se==null?void 0:se.value,Fe)});let F=!1,H=()=>{F||(F=!0,$.priceScale("osc").applyOptions({scaleMargins:{top:.65,bottom:.18}}))},N=[],z=[],te=[];$l(r,{addOverlay:(X,q,se=1.2,me=!1,xe="")=>{if(!(X!=null&&X.length))return;let Te=$.addLineSeries({color:q,lineWidth:se,lineStyle:me?p.LineStyle.Dashed:p.LineStyle.Solid,priceLineVisible:!1,lastValueVisible:!1});Te.setData(X),N.push(Te),xe&&te.push({label:xe,color:q,series:Te,points:X})},addOsc:(X,q,se="")=>{if(!(X!=null&&X.length))return;H();let me=$.addLineSeries({color:q,lineWidth:1.2,priceScaleId:"osc",title:se,priceLineVisible:!1,lastValueVisible:!1});me.setData(X),N.push(me),se&&te.push({label:se,color:q,series:me,points:X})},addOscHist:X=>{if(!(X!=null&&X.length))return;H();let q=$.addHistogramSeries({priceScaleId:"osc",priceLineVisible:!1,lastValueVisible:!1});q.setData(X.map(se=>({time:se.time,value:se.value,color:se.value>=0?"rgba(99,255,157,0.45)":"rgba(255,126,126,0.45)"}))),N.push(q)},addPriceLevel:(X,q,se="")=>{Number.isFinite(X)&&z.push(S.createPriceLine({price:X,color:q,lineWidth:1,lineStyle:p.LineStyle.Dashed,axisLabelVisible:!0,title:se}))}}),Sl(r,$,S,d),$.timeScale().subscribeVisibleLogicalRangeChange(Qo);let ce=null;if(P.comparePair){let X=In.find(q=>q.id===P.comparePair);if(X){let q=kl(await gc(X,P.interval));if(e===Nn&&q.length){let se=q[0].close||1;ce=$.addLineSeries({color:"#ffd166",lineWidth:1.4,priceScaleId:"left",priceLineVisible:!1,lastValueVisible:!0,priceFormat:{type:"custom",formatter:me=>`${me>=0?"+":""}${me.toFixed(2)}%`,minMove:.01}}),$.priceScale("left").applyOptions({visible:!0,borderColor:"rgba(255,209,102,0.35)"}),ce.setData(q.map(me=>({time:me.time,value:(me.close/se-1)*100})))}}}else $.priceScale("left").applyOptions({visible:!1});if(e!==Nn){try{$.remove()}catch{}return}let G=(P.drawings||[]).filter(X=>Number.isFinite(X==null?void 0:X.price)).map(X=>S.createPriceLine({price:X.price,color:"#78e5ff",lineWidth:2,lineStyle:p.LineStyle.Dashed,axisLabelVisible:!0,title:"Line"}));if($.subscribeClick(X=>{if(P.drawingTool!=="hline"||!X.point)return;let q=S.coordinateToPrice(X.point.y);Number.isFinite(q)&&(P.drawings=[...P.drawings||[],{price:q}].slice(-50),G.push(S.createPriceLine({price:q,color:"#78e5ff",lineWidth:2,lineStyle:p.LineStyle.Dashed,axisLabelVisible:!0,title:"Line"})))}),u&&Number.isFinite(u.from)&&Number.isFinite(u.to))try{$.timeScale().setVisibleLogicalRange(u)}catch{$.timeScale().fitContent()}else $.timeScale().fitContent();let Se=new ResizeObserver(()=>{$.applyOptions({width:Math.max(320,d.clientWidth||320)}),Qo()});Se.observe(d),ee={chart:$,volumeSeries:M,activeSeries:S,compareSeries:ce,indicatorSeries:N,indicatorPriceLines:z,priceLines:G,resizeObserver:Se,chartType:P.chartType,configKey:l,legendEl:C,renderLegend:R,indicatorLegendItems:te,alertPriceLines:[]},Tl(S)}catch(i){if(e!==Nn)return;if(P.error=(i==null?void 0:i.message)||"Could not initialize chart widget.",ee.chart){ge(P.error);return}let r=document.getElementById("xpd-tv-widget");r&&(r.innerHTML=`<div class="xpd-error">${y(P.error)}</div>`)}}}function bc(){let e=Q(jo)==="1"?"0":"1";Z(jo,e),j()}async function yc(e){In.some(t=>t.id===e)&&(P.pair=e,await Is(),At(),j())}async function wc(e){P.interval=e,await Is(),At(),j()}function xc(e){P.chartType=e,At(),j()}async function kc(){await Is(),j()}function $c(e,t){e in P.indicators&&(P.indicators[e]=!!t,t&&(P.selectedIndicator=e,P.selectedEducationTab="indicator"),At(),j())}function Sc(){P.indicatorMenuOpen=!P.indicatorMenuOpen,j()}function Tc(){P.moreMenuOpen=!P.moreMenuOpen,j()}function Cc(e){P.indicatorQuery=String(e||""),P.indicatorMenuOpen||(P.indicatorMenuOpen=!0),j()}function Pc(e){let t=String(e||"").trim();t in P.indicators&&(P.indicators[t]=!0,P.selectedIndicator=t,P.selectedEducationTab="indicator",At(),j())}function Lc(e){let t=String(e||"").trim();t in P.indicators&&(P.indicators[t]=!1,At(),j())}function gh(e){var s,a;if(P.settingsOpenFor!==e)return"";let t=P.indicatorSettings[e]||{},n=oi[e]||[];return`
    <div class="xpd-indicator-settings" role="dialog" aria-label="${y(((s=qt[e])==null?void 0:s.name)||e)} settings">
      <div class="xpd-indicator-settings-title">${y(((a=qt[e])==null?void 0:a.name)||e)} settings</div>
      ${n.map(o=>{let i=t[o.id]??o.default;return o.type==="number"?`
            <label class="xpd-indicator-settings-field">
              <span>${y(o.label)}</span>
              <input id="xpd-ind-${o.id}-${e}" class="xpd-input" type="number" min="2" max="500" value="${i}" />
            </label>`:`
          <label class="xpd-indicator-settings-field">
            <span>${y(o.label)}</span>
            <input id="xpd-ind-${o.id}-${e}" class="xpd-indicator-color-input" type="color" value="${i}" />
          </label>`}).join("")}
      ${n.length?"":'<div class="xpd-note">This indicator has no adjustable settings yet.</div>'}
      <div class="xpd-indicator-settings-actions">
        <button class="xpd-mini-btn" onclick="resetIndicatorSettings('${e}')">Reset</button>
        <button class="xpd-mini-btn" onclick="closeIndicatorSettings()">Cancel</button>
        <button class="xpd-action xpd-action--primary" onclick="applyIndicatorSettings('${e}')">Save</button>
      </div>
    </div>`}function Mc(e){let t=String(e||"").trim();t in P.indicators&&(P.settingsOpenFor=P.settingsOpenFor===t?null:t,j())}function Ac(){P.settingsOpenFor=null,j()}function Ec(e){let t=String(e||"").trim();if(!(t in P.indicators))return;let n=P.indicatorSettings[t]||{},s={...n};for(let a of oi[t]||[]){let o=document.getElementById(`xpd-ind-${a.id}-${t}`);o&&(a.type==="number"?s[a.id]=Math.max(2,Math.min(500,Number(o.value)||n[a.id]||a.default)):s[a.id]=o.value)}P.indicatorSettings[t]=s,P.settingsOpenFor=null,j()}function Nc(e){let t=String(e||"").trim();delete P.indicatorSettings[t],P.settingsOpenFor=null,j()}function Rc(){At(),Hs(window.location.href),ae("Chart link copied.")}function _c(){P.threeEnabled=!P.threeEnabled,Z(ai,P.threeEnabled?"1":"0"),P.threeEnabled||Fs(),j()}function Dc(e){let t=!!e;P.threeEnabled!==t&&(P.threeEnabled=t,Z(ai,P.threeEnabled?"1":"0"),P.threeEnabled||Fs(),j())}function Ic(e){P.comparePair=e||"",At(),j()}function Fc(e){let t=String(e||"").trim();!t||!(t in P.indicators)||(P.indicators[t]=!0,P.selectedIndicator=t,j())}function Oc(e){let t=String(e||"none");zl.some(n=>n.key===t)&&(P.drawingTool=t,P.educationHint=sf[t]||"",j())}function Na(){var e;return((e=P.chartMeta)==null?void 0:e.tokenKey)||P.tokenFocusKey||`${Ea().symbol||"XRP"}|`}function Bc(){var s,a;let e=Number((s=P.chartMeta)==null?void 0:s.last),t=prompt(`Alert me when ${((a=P.chartMeta)==null?void 0:a.symbol)||"price"} crosses:`,Number.isFinite(e)?e.toFixed(6):"");if(t==null)return;let n=Number(t);if(!Number.isFinite(n)||n<=0){ge("Enter a valid price.");return}P.alerts=[...P.alerts||[],{id:`alert_${Date.now()}`,tokenKey:Na(),price:n,createdAt:new Date().toISOString()}],ri(),j(),ae(`Alert set at $${_(n,6)}`)}function Xc(e){P.alerts=(P.alerts||[]).filter(t=>t.id!==e),ri(),j()}function Tl(e){if(!e)return;let t=window.LightweightCharts;for(let s of ee.alertPriceLines||[])try{e.removePriceLine(s)}catch{}let n=(P.alerts||[]).filter(s=>s.tokenKey===Na());ee.alertPriceLines=n.map(s=>{var a;return e.createPriceLine({price:s.price,color:"#ffb703",lineWidth:2,lineStyle:((a=t==null?void 0:t.LineStyle)==null?void 0:a.Dotted)??2,axisLabelVisible:!0,title:"\u{1F514} Alert"})})}function vh(e){var r,l;if(e.length<2)return;let t=Na(),n=(P.alerts||[]).filter(c=>c.tokenKey===t);if(!n.length)return;let s=e[e.length-2].close,a=e[e.length-1].close,o=[],i=!1;for(let c of n){let d=s<c.price&&a>=c.price,u=s>c.price&&a<=c.price;d||u?(ae(`\u{1F514} ${((r=P.chartMeta)==null?void 0:r.symbol)||"Price"} crossed $${_(c.price,6)} (${d?"\u2191":"\u2193"} now $${_(a,6)})`),i=!0,(l=document.querySelector(`.xpd-indicator-chip[data-alert-id="${c.id}"]`))==null||l.remove()):o.push(c)}i&&(P.alerts=[...(P.alerts||[]).filter(c=>c.tokenKey!==t),...o],ri())}function Hc(){let e=ee.activeSeries;if(e)for(let t of ee.priceLines||[])try{e.removePriceLine(t)}catch{}ee.priceLines=[],P.drawings=[]}function Ra(e,t=0){var i;let n=(i=ee.chart)==null?void 0:i.timeScale();if(!n)return;let s=n.getVisibleLogicalRange();if(!s)return;let a=(s.to-s.from)*e,o=(s.to+s.from)/2+(s.to-s.from)*t;n.setVisibleLogicalRange({from:o-a/2,to:o+a/2})}function zc(){Ra(.8)}function Wc(){Ra(1.25)}function Uc(){Ra(1,-.2)}function jc(){Ra(1,.2)}function qc(){P.educationCollapsed=!P.educationCollapsed,j()}function Vc(e){["indicator","psychology","practice"].includes(e)&&(P.selectedEducationTab=e,j())}function Gc(){let e=document.body.classList.contains("theme-gold");Cn(e?"cosmic":"gold"),j()}var Cl=!1;function bh(){let e=document.getElementById("xpd-tv-widget");e&&ee.chart&&(ee.chart.applyOptions({width:Math.max(320,e.clientWidth||320),height:Math.max(320,e.clientHeight||460)}),Qo())}function Kc(){var t;let e=document.querySelector(".xpd-chart-wrap");e&&(Cl||(Cl=!0,document.addEventListener("fullscreenchange",()=>{requestAnimationFrame(()=>requestAnimationFrame(bh))})),document.fullscreenElement?document.exitFullscreen():(t=e.requestFullscreen)==null||t.call(e))}function Jc(){let e=ee.chart;if(!e){ge("Chart image is not ready yet.");return}let t=e.takeScreenshot(),n=document.createElement("a");n.download=`xrpl-chart-${Date.now()}.png`,n.href=t.toDataURL("image/png"),n.click()}function Yc(){return P.tokenFocusKey||P.pair||"default"}function Qc(){var n;let e=ve(Q(qo))||{},t=Yc();e[t]={interval:P.interval,chartType:P.chartType,comparePair:P.comparePair,indicators:P.indicators,indicatorSettings:P.indicatorSettings},Z(qo,JSON.stringify(e)),ae(`Chart layout saved for ${((n=P.chartMeta)==null?void 0:n.symbol)||t}.`)}function Zc(){var s;let e=ve(Q(qo))||{},t=Yc(),n=e[t];if(!n){ge(`No saved layout for ${((s=P.chartMeta)==null?void 0:s.symbol)||t} yet.`);return}P.interval=n.interval||P.interval,P.chartType=n.chartType||P.chartType,P.comparePair=n.comparePair||"",P.indicators={...P.indicators,...n.indicators||{}},P.indicatorSettings={...P.indicatorSettings,...n.indicatorSettings||{}},At(),j()}function _a(e){let t=String(e||"").trim();if(/^[0-9A-F]{40}$/i.test(t)){let n=t.replace(/(00)+$/g,"");if(/^[0-9A-F]+$/i.test(n)&&n.length%2===0)try{let s=new Uint8Array(n.length/2);for(let o=0;o<n.length;o+=2)s[o/2]=parseInt(n.slice(o,o+2),16);let a=new TextDecoder().decode(s).replace(/\0/g,"").trim();if(a)return a.toUpperCase()}catch{}}return t.toUpperCase()}function Ue(e){return`${e.symbol}|${e.issuer||""}`}function Ps(e){return encodeURIComponent(e).replace(/'/g,"%27")}function yh(e){var l,c,d,u,p,m,f,g,b,h;let t=_a(e.code||e.currency||""),n=String(e.issuer||((l=e.IssuingAccount)==null?void 0:l.account)||"").trim(),s=Number(e.price??((c=e.metrics)==null?void 0:c.price)??0),a=Number(e.marketcap??((d=e.metrics)==null?void 0:d.marketcap)??0),o=Number(((u=e.metrics)==null?void 0:u.volume_24h)??0),i=((m=(p=e.meta)==null?void 0:p.token)==null?void 0:m.name)||((f=e.IssuingAccount)==null?void 0:f.name)||t||"Unknown Token",r=Number(e.holders??((g=e.metrics)==null?void 0:g.holders)??((b=e.metrics)==null?void 0:b.trustlines)??0);return{symbol:t,name:i,issuer:n,tokenId:e.id||`${t}.${n}`,price:Number.isFinite(s)&&s>0?s:null,marketCap:Number.isFinite(a)&&a>0?a:null,volume24h:Number.isFinite(o)?o:null,holders:Number.isFinite(r)?r:null,change24h:null,verified:!!((h=e.IssuingAccount)!=null&&h.verified),score:Number(e.score||0)||null}}function wh(e){let t=_a((e==null?void 0:e.symbol)||""),n=String((e==null?void 0:e.name)||t||"Unknown Token"),s=Number((e==null?void 0:e.current_price)||0),a=Number((e==null?void 0:e.market_cap)||0),o=Number((e==null?void 0:e.total_volume)||0),i=Number((e==null?void 0:e.price_change_percentage_24h)||0);return{symbol:t,name:n,issuer:"",tokenId:`cg:${(e==null?void 0:e.id)||t}`,price:Number.isFinite(s)&&s>0?s:null,marketCap:Number.isFinite(a)&&a>0?a:null,volume24h:Number.isFinite(o)&&o>0?o:null,holders:null,change24h:Number.isFinite(i)?i:null,verified:!1,score:null}}function xh(e){var r;let t=_a((e==null?void 0:e.currency)||(e==null?void 0:e.token)||""),n=String((e==null?void 0:e.issuer)||(e==null?void 0:e.account)||"").trim(),s=String((e==null?void 0:e.name)||t||"Unknown Token"),a=Number((e==null?void 0:e.price)||((r=e==null?void 0:e.market)==null?void 0:r.price)||0),o=Number((e==null?void 0:e.marketcap)||(e==null?void 0:e.marketCap)||0),i=Number((e==null?void 0:e.volume24h)||(e==null?void 0:e.volume)||0);return{symbol:t,name:s,issuer:n,tokenId:`bithomp:${t}.${n||"na"}`,price:Number.isFinite(a)&&a>0?a:null,marketCap:Number.isFinite(o)&&o>0?o:null,volume24h:Number.isFinite(i)&&i>0?i:null,holders:Number.isFinite(Number((e==null?void 0:e.holders)||0))?Number((e==null?void 0:e.holders)||0):null,change24h:Number.isFinite(Number((e==null?void 0:e.change24h)||0))?Number((e==null?void 0:e.change24h)||0):null,verified:!!(e!=null&&e.verified),score:null}}function kh(e){let t=_a((e==null?void 0:e.symbol)||(e==null?void 0:e.currency)||""),n=String((e==null?void 0:e.issuer)||(e==null?void 0:e.issuerAddress)||"").trim(),s=String((e==null?void 0:e.name)||t||"Unknown Token"),a=Number((e==null?void 0:e.price)||0),o=Number((e==null?void 0:e.volume24h)||0);return{symbol:t,name:s,issuer:n,tokenId:`xrplto:${t}.${n||"na"}`,price:Number.isFinite(a)&&a>0?a:null,marketCap:Number.isFinite(Number((e==null?void 0:e.marketCap)||0))?Number((e==null?void 0:e.marketCap)||0):null,volume24h:Number.isFinite(o)&&o>0?o:null,holders:Number.isFinite(Number((e==null?void 0:e.holders)||0))?Number((e==null?void 0:e.holders)||0):null,change24h:Number.isFinite(Number((e==null?void 0:e.change24h)||0))?Number((e==null?void 0:e.change24h)||0):null,verified:!!(e!=null&&e.verified),score:null}}async function ed(){var e,t,n,s,a,o;if(La()){U.loading=!0,U.error="";try{let i=Date.now(),r=ul.get("tokens");if(r&&i-r.ts<6e4){U.tokens=r.data,U.total=r.total||r.data.length,U.lastSyncAt=r.ts,U.filtered=ss(U.query,r.data),U.trending=Pl(r.data),U.loading=!1;return}let l=500,c=12,d=[];for(let T=1;T<=c;T+=1){let S=await Mt(`${Bm}?page=${T}&limit=${l}`,{allowProxy:!1,timeoutMs:12e3});if(!Array.isArray(S)||!S.length||(d.push(...S),S.length<l))break}let u=d.map(yh).filter(T=>!!T.symbol&&!!T.issuer),p=[Mt(`${Xm}?vs_currency=usd&order=market_cap_desc&per_page=250&page=1&sparkline=false`,{timeoutMs:12e3}).catch(()=>[]),Date.now()<(hl.xrplto||0)?Promise.resolve([]):Mt(zm,{timeoutMs:12e3,allowProxy:!1}).catch(T=>(String((T==null?void 0:T.message)||"").includes("429")&&(hl.xrplto=Date.now()+5*60*1e3),[]))];Wm&&p.push(Mt(Hm,{timeoutMs:12e3,allowProxy:!1}).catch(()=>[]));let[m,f,g=[]]=await Promise.all(p),b=Array.isArray(m)?m.map(wh).filter(T=>!!T.symbol):[],h=Array.isArray(g)?g.map(xh).filter(T=>!!T.symbol):[],v=Array.isArray(f)?f.map(kh).filter(T=>!!T.symbol):[],w={symbol:"XRP",name:"XRP Ledger Native",issuer:"",tokenId:"XRP",price:((e=Ce.data)==null?void 0:e.priceUsd)||((t=P.stats)==null?void 0:t.price)||null,marketCap:((n=Ce.data)==null?void 0:n.marketCap)||null,volume24h:((s=Ce.data)==null?void 0:s.volume24h)||null,holders:null,change24h:((a=Ce.data)==null?void 0:a.change24h)||((o=P.stats)==null?void 0:o.changePct)||null,verified:!0,score:1},k=new Map;[w,...u,...h,...v,...b].forEach(T=>{let S=Ue(T);k.has(S)||k.set(S,T)});let $=[...k.values()];ul.set("tokens",{ts:i,data:$,total:$.length}),U.tokens=$,U.total=$.length,U.lastSyncAt=i,U.filtered=ss(U.query,$),U.trending=Pl($)}catch(i){U.error=(i==null?void 0:i.message)||"Could not load XRPL token discovery data."}finally{U.loading=!1}}}function ss(e,t){let n=String(e||"").trim().toLowerCase(),s=U.filters||{type:"all",minCap:0,minVol:0,hasDex:!1};return t.filter(a=>{if(n&&!`${a.symbol} ${a.name} ${a.issuer} ${a.tokenId||""}`.toLowerCase().includes(n)||Number(s.minCap||0)>0&&Number(a.marketCap||0)<Number(s.minCap||0)||Number(s.minVol||0)>0&&Number(a.volume24h||0)<Number(s.minVol||0)||s.hasDex&&!(Number(a.volume24h||0)>0||Number(a.holders||0)>100))return!1;if(s.type&&s.type!=="all"){let o=String(a.symbol||"").toLowerCase(),i=String(a.name||"").toLowerCase(),r=/usd|usdc|usdt|rlusd|eur|gbp/.test(o)||/stable/.test(i),l=/meme|dog|cat|frog|shib|pepe/.test(o)||/meme/.test(i),c=/mpt/.test(o)||/multi-purpose/.test(i);if(s.type==="stablecoin"&&!r||s.type==="meme"&&!l||s.type==="mpt"&&!c||s.type==="standard"&&(r||l||c))return!1}return!0})}function Pl(e){return[...e].sort((t,n)=>{let s=Number(t.volume24h||0),a=Number(n.volume24h||0);if(a!==s)return a-s;let o=Number(t.marketCap||0);return Number(n.marketCap||0)-o}).slice(0,24)}async function td(e){if(Pt.loading=!0,Pt.error="",Pt.items=[],!e){Pt.loading=!1;return}try{let t=await vi(e,20);Pt.items=t||[]}catch(t){Pt.error=(t==null?void 0:t.message)||"Could not load recent transactions."}finally{Pt.loading=!1}}function nd(e){U.query=e,Ms&&clearTimeout(Ms),Ms=setTimeout(()=>{U.listLimit=240,U.filtered=ss(U.query,U.tokens),j()},300)}function sd(e,t){U.filters={...U.filters,[e]:t},U.listLimit=240,U.filtered=ss(U.query,U.tokens),j()}function ad(){Ms&&clearTimeout(Ms),U.query="",U.filters={type:"all",minCap:0,minVol:0,hasDex:!1},U.listLimit=240,U.filtered=ss("",U.tokens),j()}function od(){U.listLimit=Math.min(5e3,Number(U.listLimit||240)+240),j()}function id(){let e=U.filtered;U.listLimit=Math.min(5e3,Math.max(240,e.length)),j()}function rd(){U.listLimit=240,j()}function ld(e){U.selectedTokenKey=e||"",j()}function cd(e){let t=String(e||"").trim();if(!t)return;let n=li();n.includes(t)||n.push(t),Gl(n),j()}function dd(e){let t=String(e||"").trim(),n=li().filter(s=>s!==t);Gl(n),j()}async function Da(e){let t=String(e||"").trim();if(!t)return;let n=String(t.includes("|")?t.split("|")[0]:t).toUpperCase(),s=t.includes("|")?U.tokens.find(o=>Ue(o)===t):U.tokens.find(o=>String(o.symbol||"").toUpperCase()===String(n||"").toUpperCase());U.selectedTokenKey=s?Ue(s):t.includes("|")?t:U.selectedTokenKey,P.tokenFocusKey=U.selectedTokenKey||t;let a={BTC:"BINANCE:BTCUSDT",ETH:"BINANCE:ETHUSDT",SOL:"BINANCE:SOLUSDT"};P.pair=a[n]||"BITSTAMP:XRPUSD",At(),j(),setTimeout(()=>lf(),20),await Is(),At(),j()}async function pd(e){return Da(e)}async function ud(){await ed(),j()}async function mi(){let e=document.getElementById("xpd-lookup-currency"),t=document.getElementById("xpd-lookup-issuer"),n=String((e==null?void 0:e.value)||"").trim().toUpperCase(),s=String((t==null?void 0:t.value)||"").trim();if(!n){ge("Enter a currency code first.");return}if(!s||!Xe(s)){ge("Enter a valid XRPL issuer address.");return}let a=`${n}|${s}`,o=U.tokens.find(i=>Ue(i)===a);o||(o={symbol:n,name:n,issuer:s,price:null,marketCap:null,volume24h:null,holders:null,tokenId:""},U.tokens=[...U.tokens,o],U.filtered=ss(U.query,U.tokens)),U.selectedTokenKey=a,e&&(e.value=""),t&&(t.value=""),await Da(a)}async function md(){var s,a;let e=String(((s=document.getElementById("xpd-lookup-currency"))==null?void 0:s.value)||"").trim().toUpperCase(),t=String(((a=document.getElementById("xpd-lookup-issuer"))==null?void 0:a.value)||"").trim();if(!e){ge("Enter a currency code first.");return}if(!t||!Xe(t)){ge("Enter a valid XRPL issuer address.");return}let n=`${e}|${t}`;await mi(),await ci(n)}async function fd(){var t;let e=((t=Et())==null?void 0:t.address)||"";await td(e),j()}async function es({silent:e=!1,force:t=!1}={}){var s;if(!t&&!La())return;let n=((s=Et())==null?void 0:s.address)||"";e||ae("Refreshing XRPL dashboard data..."),await Promise.allSettled([Is(),nc(),ed(),td(n),sc(n),ac(n),ic()]),j()}function hd(){return nc()}function gd(){var e;return sc(((e=Et())==null?void 0:e.address)||"")}function vd(){var e;return ac(((e=Et())==null?void 0:e.address)||"")}function bd(){return ic()}function yd(e){ae(`NFT ${e.slice(0,12)}... selected. Send flow can be wired to NFTokenCreateOffer.`)}function Ds(){let e=x("profile-metrics-row");if(!e)return;let t=!1,n=Object.values(Ye).reduce((u,p)=>u+((p==null?void 0:p.xrp)||0),0),s=wd(),a=Object.values(Ye).flatMap(u=>(u==null?void 0:u.tokens)||[]),o=Et(),i=o?Ls[o.address]:null,r=(i==null?void 0:i.ownerCount)||0,l=Ta+r*Ca,c=o!=null&&o.createdAt?Sh(new Date(o.createdAt)):"\u2014",d=(i==null?void 0:i.sequence)!=null?i.sequence:"\u2014";e.innerHTML=`
    <div class="pmetric"><div class="pmetric-val">${t?"\u2022\u2022\u2022\u2022":_(n,2)}</div><div class="pmetric-label">Total XRP</div></div>
    <div class="pmetric pmetric-divider"></div>
    <div class="pmetric"><div class="pmetric-val ${s&&!t?"pmetric-usd":""}">
      ${t?"\u2022\u2022\u2022\u2022":s?"$"+_(n*s,2):"\u2014"}</div>
      <div class="pmetric-label">Est. Value</div></div>
    <div class="pmetric pmetric-divider"></div>
    <div class="pmetric"><div class="pmetric-val">${d}</div><div class="pmetric-label">Transactions</div></div>
    <div class="pmetric pmetric-divider"></div>
    <div class="pmetric"><div class="pmetric-val">${c}</div><div class="pmetric-label">Wallet Age</div></div>
    <div class="pmetric pmetric-divider"></div>
    <div class="pmetric"><div class="pmetric-val">${a.length}</div><div class="pmetric-label">Tokens</div></div>
    ${i?`<div class="pmetric pmetric-divider"></div>
    <div class="pmetric pmetric-reserve" title="${r} owned objects \xD7 ${Ca} XRP + ${Ta} XRP base">
      <div class="pmetric-val pmetric-reserve-val">${l} XRP</div>
      <div class="pmetric-label">Reserved</div></div>`:""}`,o&&(!Ls[o.address]||Date.now()-Ls[o.address].fetchedAt>6e4)&&$h(o.address).then(()=>Ds())}async function $h(e){try{let t=await st({method:"account_info",params:[{account:e,ledger_index:"validated"}]});t!=null&&t.account_data&&(Ls[e]={sequence:t.account_data.Sequence,ownerCount:t.account_data.OwnerCount||0,fetchedAt:Date.now()})}catch{}}function Sh(e){let t=Math.floor((Date.now()-e.getTime())/864e5);if(t<1)return"Today";if(t<30)return`${t}d`;if(t<365)return`${Math.floor(t/30)}mo`;let n=Math.floor(t/365),s=Math.floor(t%365/30);return s?`${n}y ${s}mo`:`${n}y`}function wd(){var t;if(Array.isArray((t=window.__dashSeries)==null?void 0:t.marketPrice)){let n=window.__dashSeries.marketPrice.at(-1);if(n!=null&&Number.isFinite(n))return n}let e=document.getElementById("mkt-price");if(e){let n=parseFloat(e.textContent.replace("$",""));if(!isNaN(n))return n}return 0}function Th(){let e=re.length>0,t=Object.values(Ge).some(Boolean),n=!!de.bio,s=!!localStorage.getItem("naluxrp_last_backup_ts"),a=[e,t,n,s].filter(Boolean).length;return a===4?"":`
    <div class="onboarding-card">
      <div class="onb-header">
        <div class="onb-title">\u2728 Complete your profile</div>
        <div class="onb-prog-wrap">
          <div class="onb-prog-bar"><div class="onb-prog-fill" style="width:${Math.round(a/4*100)}%"></div></div>
          <span class="onb-prog-label">${a}/4</span>
        </div>
      </div>
      <div class="onb-items">
        ${Sa("\u{1F48E}","Generate your first XRPL wallet","Encrypted with AES-256-GCM, never leaves this device.",e,"openWalletCreator()")}
        ${Sa("\u{1F517}","Connect a social account","Link Discord, X, GitHub, or any platform.",t,"switchProfileTab('social')")}
        ${Sa("\u270F\uFE0F","Add a bio","Tell people who you are.",n,"openProfileEditor()")}
        ${Sa("\u{1F4BE}","Export an encrypted backup","Protect against device loss.",s,"exportVaultBackup()")}
      </div>
    </div>`}function Sa(e,t,n,s,a){return`<div class="onb-item ${s?"onb-item--done":""}" ${s?"":` onclick="${a}"`}>
    <div class="onb-item-check">${s?"\u2713":e}</div>
    <div class="onb-item-body"><div class="onb-item-title">${t}</div><div class="onb-item-sub">${n}</div></div>
    ${s?"":'<span class="onb-item-arrow">\u2192</span>'}
  </div>`}function fi(){let e=x("profile-tab-social");if(!e)return;let t=Object.values(Ge).filter(Boolean).length;e.innerHTML=`
    <div class="social-section-head">
      <div class="social-section-title">Social &amp; Community Links</div>
      <div class="social-section-sub">${t} of ${ns.length} connected \xB7 stored locally only</div>
    </div>
    <div class="social-grid">
      ${ns.map(n=>{let s=Ge[n.id]||"",a=!!s;return`<div class="social-card ${a?"social-card--connected":""}" id="social-item-${n.id}">
          <div class="social-card-left">
            <div class="social-platform-badge social-platform-badge--${n.id}">${n.icon}</div>
            <div class="social-card-info">
              <div class="social-card-name">${y(n.label)}</div>
              <div class="social-card-handle ${a?"":"dim"}">${a?y("@"+s):"Not connected"}</div>
            </div>
          </div>
          <div class="social-card-actions">
            ${a?`<button class="sc-btn sc-btn--open" onclick="viewSocial('${n.id}')">\u2197</button>
                 <button class="sc-btn sc-btn--edit" onclick="openSocialModal('${n.id}')">Edit</button>`:`<button class="sc-btn sc-btn--connect" onclick="openSocialModal('${n.id}')">+ Connect</button>`}
          </div>
        </div>`}).join("")}
    </div>
    ${t?`<div class="social-preview-row">
      <span class="social-preview-hint">${t} platform${t>1?"s":""} connected</span>
      <button class="sc-preview-btn" onclick="openPublicProfilePreview()">\u{1F441} Preview Profile</button>
    </div>`:""}`,Ma("stat-socials-val",t)}function xd(e){let t=ns.find(l=>l.id===e);if(!t)return;let n=x("social-modal");if(!n)return;let s=x("social-modal-icon"),a=x("social-modal-title"),o=x("social-modal-sub"),i=x("social-modal-input"),r=x("social-modal-delete");s&&(s.className=`social-platform-icon-lg social-icon ${t.id}`,s.textContent=t.icon),a&&(a.textContent=`Connect ${t.label}`),o&&(o.textContent=`Enter your ${t.label} ${t.id==="discord"?"user ID or username":"username"}.`),i&&(i.value=Ge[e]||"",i.placeholder=`Your ${t.label} handle`),r&&(r.style.display=Ge[e]?"":"none"),n.dataset.platform=e,n.classList.add("show"),setTimeout(()=>i==null?void 0:i.focus(),80)}function kd(){let e=x("social-modal"),t=e==null?void 0:e.dataset.platform,n=x("social-modal-input");if(!t||!n)return;let s=n.value.trim().replace(/^@/,"");s?Ge[t]=s:delete Ge[t],jl(),fi(),as();let a=ns.find(o=>o.id===t);ag(),kt("social_connected",`${(a==null?void 0:a.label)||t} @${s||"(removed)"}`),ae(`${a==null?void 0:a.label} updated`)}function $d(){var t;let e=(t=x("social-modal"))==null?void 0:t.dataset.platform;e&&(delete Ge[e],jl(),fi(),as(),kt("social_removed",e),ae("Social connection removed"))}function Sd(e){let t=ns.find(n=>n.id===e);t&&Ge[e]&&window.open(`${t.prefix}${Ge[e]}`,"_blank","noopener")}function as(){var e;(e=x("social-modal"))==null||e.classList.remove("show")}function $t(){let e=x("profile-tab-wallets");if(!e)return;if(re.length===0){e.innerHTML=Th()+`
      <div class="wallets-empty">
        <div class="wallets-empty-icon">\u{1F48E}</div>
        <div class="wallets-empty-title">No wallets yet</div>
        <div class="wallets-empty-sub">Generate your first XRPL wallet \u2014 your seed is encrypted with AES-256-GCM and never leaves this device.</div>
        <button class="btn-create-wallet-hero" onclick="openWalletCreator()">\u26A1 Generate XRPL Wallet</button>
      </div>`,Ma("stat-wallets-val",0);return}let t=re.length>3?`
    <div class="wallet-filter-row">
      <input class="wallet-filter-input" id="wallet-filter-input" type="text"
        placeholder="\u{1F50D} Filter wallets\u2026" value="${y(Zn)}"
        oninput="filterWallets(this.value)">
      ${Zn?`<button class="wallet-filter-clear" onclick="filterWallets('')">\u2715</button>`:""}
    </div>`:"",n=re.filter(a=>!Zn||a.label.toLowerCase().includes(Zn.toLowerCase())||a.address.toLowerCase().includes(Zn.toLowerCase())),s=n.map((a,o)=>Ch(a,re.indexOf(a))).join("");e.innerHTML=t+(n.length?s:`<div class="wcard-empty">No wallets match "${y(Zn)}"</div>`)+`
    <div class="wallet-add-row">
      <button class="btn-add-wallet" onclick="openWalletCreator()">
        <span class="baw-plus">\uFF0B</span>
        <div class="baw-text"><span class="baw-title">Generate New XRPL Wallet</span>
          <span class="baw-sub">Keys generated in-browser \xB7 encrypted before storage</span></div>
      </button>
      <button class="btn-import-wallet btn-import-wallet--seed" onclick="openImportSeedModal()">
        <span class="baw-plus">\u{1F511}</span>
        <div class="baw-text"><span class="baw-title">Import from Seed</span>
          <span class="baw-sub">Existing family seed \u2014 full signing access</span></div>
      </button>
      <button class="btn-import-wallet btn-import-wallet--watch" onclick="openImportAddressModal()">
        <span class="baw-plus">\u{1F441}</span>
        <div class="baw-text"><span class="baw-title">Watch Address</span>
          <span class="baw-sub">Track any XRPL address read-only</span></div>
      </button>
    </div>`,Ma("stat-wallets-val",re.length)}function Ch(e,t){let n=e.id===dt,s=!!e.watchOnly,a=Ye[e.address],o=Ls[e.address],r=!0||s,l=(o==null?void 0:o.ownerCount)||0,c=Ta+l*Ca,d=r?a?_(a.xrp,2):"\u2014":"\u2022\u2022\u2022\u2022",u=a&&r?Math.max(0,a.xrp-c):null,p=(a==null?void 0:a.tokens)||[],m=a!=null&&a.fetchedAt?ql(a.fetchedAt):null,f=e.address.slice(0,8)+"\u2026"+e.address.slice(-6),g=gi(e.address);return`
  <div class="wcard ${n?"wcard--active":""} ${s?"wcard--watch":""}" id="wallet-item-${e.id}" style="--i:${t}">
    <div class="wcard-top">
      <div class="wcard-icon" style="background:${e.color}18;border-color:${e.color}44;color:${e.color}">${y(e.emoji||"\u{1F48E}")}</div>
      <div class="wcard-identity">
        <div class="wcard-name-row">
          <span class="wcard-name">${y(e.label||"Unnamed")}</span>
          ${n?'<span class="wcard-badge wcard-badge--active">\u25CF Active</span>':""}
          ${s?'<span class="wcard-badge wcard-badge--watch">\u{1F441} Watch</span>':""}
          ${e.testnet?'<span class="wcard-badge wcard-badge--testnet">Testnet</span>':'<span class="wcard-badge wcard-badge--mainnet">Mainnet</span>'}
        </div>
        <div class="wcard-address mono" title="${y(e.address)}" onclick="copyToClipboard('${y(e.address)}')">${f} <span class="wcard-copy-hint">\u29C9</span></div>
        <div class="wcard-algo-row">
          ${s?'<span class="wcard-enc">\u{1F50D} Read-only</span>':`<span class="wcard-algo">${y((e.algo||"ed25519").toUpperCase())}</span>
               <span class="wcard-enc">\u{1F510} AES-256-GCM</span>`}
        </div>
      </div>
      <div class="wcard-balance-col">
        ${g.length>=2?`<div class="wcard-sparkline">${Ed(g,70,22,e.color||"#00fff0")}</div>`:""}
        <div class="wcard-xrp ${r?"":"wcard-balance-locked"}">${d} <span class="wcard-xrp-label">XRP</span></div>
        ${u!==null&&r?`<div class="wcard-avail" title="${c} XRP reserved">${_(u,2)} avail.</div>`:""}
        ${p.length&&r?`<div class="wcard-tokens">${p.length} token${p.length>1?"s":""}</div>`:""}
      </div>
    </div>

    <div class="wcard-sync-row">
      <div class="wcard-sync-time">
        ${r?m?`<span>Synced ${m}</span>`:'<span style="opacity:.4">Not synced yet</span>':"<span>\u{1F512} Sign in to see balance</span>"}
      </div>
      ${r?`<button class="wcard-refresh-btn" onclick="fetchBalance('${e.address}').then(()=>{renderWalletList();renderProfileMetrics();})">\u21BB</button>`:""}
    </div>

    ${o?`<div class="wcard-reserve-row">
      <span class="wcard-reserve-chip">\u{1F512} ${c} XRP reserved</span>
      <span class="wcard-reserve-sub">${l} object${l!==1?"s":""} \xB7 base ${Ta} + ${l}\xD7${Ca}</span>
    </div>`:""}

    ${p.length&&r?`<div class="wcard-token-row">
      ${p.slice(0,6).map(b=>{let h=b.currency.length>4?ki(b.currency)||b.currency.slice(0,4)+"\u2026":b.currency;return`<div class="wcard-token-chip" onclick="openTokenDetailsModal('${y(b.currency)}','${y(b.issuer)}','${y(e.address)}')" title="${y(b.currency)}">
          <span class="wcard-token-cur">${y(h)}</span>
          <span class="wcard-token-bal">${_(parseFloat(b.balance||0),4)}</span>
        </div>`}).join("")}
      ${p.length>6?`<div class="wcard-token-chip wcard-token-more" onclick="openTokenDetailsModal('${y(p[6].currency)}','${y(p[6].issuer)}','${y(e.address)}')">+${p.length-6}</div>`:""}
    </div>`:""}

    <div class="wcard-actions">
      ${s?"":`<button class="wcard-btn wcard-btn--send" onclick="openSendModal('${e.id}')">\u2B06 Send</button>`}
      <button class="wcard-btn wcard-btn--receive" onclick="openReceiveModal('${e.id}')">\u2B07 Receive</button>
      ${s?"":`<button class="wcard-btn wcard-btn--trust" onclick="openTrustlineModal('${e.id}')">\u{1F517} Trust</button>`}
      <button class="wcard-btn wcard-btn--inspect" onclick="inspectWalletAddr('${y(e.address)}')">\u{1F50D} Inspect</button>
      ${n?"":`<button class="wcard-btn wcard-btn--setactive" onclick="setActiveWallet('${e.id}')">\u2605 Active</button>`}
      <button class="wcard-btn wcard-btn--expand ${Rn===e.id?"wcard-btn--expand-open":""}" onclick="toggleWalletDrawer('${e.id}')">${Rn===e.id?"\u25B2 Hide":"\u25BC Details"}</button>
      <button class="wcard-btn wcard-btn--remove" onclick="deleteWallet(${t})">\u2715</button>
    </div>

    ${Rn===e.id?`
    <div class="wcard-drawer" id="wcard-drawer-${e.id}">
      <div class="wcard-drawer-tabs">
        <button class="wdt-btn ${(dn[e.id]||"txns")==="txns"?"active":""}" onclick="switchWalletDrawerTab('${e.id}','txns')">\u{1F4CB} Transactions</button>
        <button class="wdt-btn ${(dn[e.id]||"txns")==="nfts"?"active":""}" onclick="switchWalletDrawerTab('${e.id}','nfts')">\u{1F3A8} NFTs</button>
        <button class="wdt-btn ${(dn[e.id]||"txns")==="orders"?"active":""}" onclick="switchWalletDrawerTab('${e.id}','orders')">\u{1F4CA} DEX</button>
        <button class="wdt-btn ${(dn[e.id]||"txns")==="amm"?"active":""}" onclick="switchWalletDrawerTab('${e.id}','amm')">\u{1F30A} AMM</button>
      </div>
      <div class="wcard-drawer-body" id="wcard-drawer-body-${e.id}">
        <div class="wdd-loading"><div class="spinner"></div> Loading\u2026</div>
      </div>
    </div>`:""}
  </div>`}function Td(e){var n;let t=re[e];t&&(re.splice(e,1),Rs(),dt===t.id&&(dt=((n=re[0])==null?void 0:n.id)||null,dt&&Z(Es,dt)),$t(),Bt(),kt("wallet_removed",t.label),Ph(`Wallet "${t.label}" removed`,()=>{re.splice(e,0,t),Rs(),dt||(dt=t.id,Z(Es,t.id)),$t(),Bt(),kt("wallet_created",t.label+" (restored)")},()=>{t.address&&vt(ei+t.address)}))}function Ph(e,t,n){let s=document.getElementById("undo-toast");s&&s.remove();let a=document.createElement("div");a.id="undo-toast",a.className="undo-toast",a.innerHTML=`<span class="undo-msg">${y(e)}</span><button class="undo-btn">Undo</button>`,document.body.appendChild(a),requestAnimationFrame(()=>a.classList.add("show"));let o=setTimeout(()=>{a.classList.remove("show"),setTimeout(()=>a.remove(),300),n==null||n()},5e3);a.querySelector(".undo-btn").addEventListener("click",()=>{clearTimeout(o),t(),a.classList.remove("show"),setTimeout(()=>a.remove(),300),ae("Wallet restored")})}function Cd(e){var n,s;let t=x("inspect-addr");t&&(t.value=e),(n=window.switchTab)==null||n.call(window,document.querySelector('[data-tab="inspector"]'),"inspector"),(s=window.showDashboard)==null||s.call(window)}function Pd(e){Rn=Rn===e?null:e,Rn&&!dn[e]&&(dn[e]="txns"),$t(),Rn&&setTimeout(()=>hi(e,dn[e]),60)}function Ld(e,t){dn[e]=t;let n=document.getElementById(`wcard-drawer-${e}`);n&&(n.querySelectorAll(".wdt-btn").forEach(s=>s.classList.toggle("active",s.textContent.toLowerCase().includes(t==="txns"?"trans":t==="nfts"?"nft":t==="orders"?"dex":"amm"))),hi(e,t))}async function hi(e,t){var a,o,i;let n=re.find(r=>r.id===e),s=document.getElementById(`wcard-drawer-body-${e}`);if(!(!n||!s)){s.innerHTML='<div class="wdd-loading"><div class="spinner"></div> Loading\u2026</div>';try{t==="txns"?s.innerHTML=Lh(((a=ni[n.address])==null?void 0:a.txns)||await vi(n.address),n.address):t==="nfts"?s.innerHTML=Mh(((o=Rl[n.address])==null?void 0:o.nfts)||await Hh(n.address),n.address):t==="orders"?s.innerHTML=Ah(((i=si[n.address])==null?void 0:i.offers)||await zh(n.address),n.id,n.address):t==="amm"&&(s.innerHTML=await Eh(n.address))}catch(r){s.innerHTML=`<div class="wdd-error">\u26A0\uFE0F ${y(r.message)}</div>`}}}function Md(e){return{Payment:"\u{1F4B8}",OfferCreate:"\u{1F4CA}",OfferCancel:"\u2715",TrustSet:"\u{1F517}",NFTokenMint:"\u{1F3A8}",NFTokenBurn:"\u{1F525}",NFTokenCreateOffer:"\u{1F3AF}",NFTokenAcceptOffer:"\u2705",AMMCreate:"\u{1F30A}",AMMDeposit:"\u{1F4E5}",AMMWithdraw:"\u{1F4E4}",AMMVote:"\u{1F5F3}",AMMBid:"\u{1F4A1}",EscrowCreate:"\u23F3",EscrowFinish:"\u2705",EscrowCancel:"\u2715",AccountSet:"\u2699",SetRegularKey:"\u{1F511}",SignerListSet:"\u{1F4CB}"}[e]||"\u{1F4C4}"}function Zo(e){return e?typeof e=="string"?`${_(Number(e)/1e6,4)} XRP`:`${_(parseFloat(e.value||0),4)} ${(e.currency||"?").length>4?e.currency.slice(0,4)+"\u2026":e.currency}`:"\u2014"}function Lh(e,t){return e!=null&&e.length?`<div class="wdd-tx-list">
    ${e.slice(0,25).map(n=>{var c,d;let s=n.TransactionType||"?",a=n.Account===t,o=!(((c=n.metaData)==null?void 0:c.TransactionResult)||((d=n.meta)==null?void 0:d.TransactionResult)||"").match(/^tec|^tem|^tef|^tel/),i=n.date?(n.date+946684800)*1e3:0,r=i?new Date(i).toLocaleDateString("en-US",{month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"}):"\u2014",l=n.hash||n.tx_hash||"";return`<div class="wdd-tx-row ${o?"":"wdd-tx-failed"}">
        <div class="wdd-tx-icon">${Md(s)}</div>
        <div class="wdd-tx-body">
          <div class="wdd-tx-type-row">
            <span class="wdd-tx-type">${s}</span>
            <span class="wdd-tx-dir ${a?"out":"in"}">${a?"\u2191 Out":"\u2193 In"}</span>
            ${o?"":'<span class="wdd-tx-fail-badge">Failed</span>'}
          </div>
          <div class="wdd-tx-detail">
            ${n.Amount?`<span class="wdd-tx-amount">${Zo(n.Amount)}</span>`:""}
            ${n.Destination?`<span class="wdd-tx-dest mono">${_l[n.Destination]||n.Destination.slice(0,8)+"\u2026"+n.Destination.slice(-5)}</span>`:""}
          </div>
        </div>
        <div class="wdd-tx-right">
          <div class="wdd-tx-date">${r}</div>
          ${l?`<a class="wdd-tx-hash" href="https://xrpscan.com/tx/${l}" target="_blank" rel="noopener">\u2B21 View</a>`:""}
        </div>
      </div>`}).join("")}
    <a class="wdd-view-more" href="https://xrpscan.com/account/${t}" target="_blank" rel="noopener">View full history on XRPScan \u2192</a>
  </div>`:'<div class="wdd-empty"><div class="wdd-empty-icon">\u{1F4CB}</div><div>No transactions yet.</div><div class="wdd-empty-sub">Fund with 10 XRP to activate.</div></div>'}function Mh(e,t){return e!=null&&e.length?`<div class="wdd-nft-header"><span>${e.length} NFT${e.length>1?"s":""}</span>
    <a class="wdd-view-more-inline" href="https://xrpscan.com/account/${t}#nfts" target="_blank">View on XRPScan \u2192</a></div>
    <div class="wdd-nft-grid">
      ${e.slice(0,24).map(n=>{var i;let s=n.nft_serial??((i=n.NFTokenID)==null?void 0:i.slice(-6))??"?",a=n.URI&&ki(n.URI)||"",o=a.startsWith("ipfs://")?`https://cloudflare-ipfs.com/ipfs/${a.slice(7)}`:"";return`<div class="wdd-nft-card">
          <div class="wdd-nft-art">${o?`<img src="${y(o)}" class="wdd-nft-img" alt="NFT" onerror="this.parentNode.innerHTML='<span class=wdd-nft-placeholder>\u{1F3A8}</span>'" />`:'<span class="wdd-nft-placeholder">\u{1F3A8}</span>'}</div>
          <div class="wdd-nft-info"><div class="wdd-nft-id mono">#${s}</div></div>
        </div>`}).join("")}
    </div>
    ${e.length>24?`<div class="wdd-more-note">${e.length-24} more on XRPScan</div>`:""}`:'<div class="wdd-empty"><div class="wdd-empty-icon">\u{1F3A8}</div><div>No NFTs in this wallet.</div></div>'}function Ah(e,t,n){return e!=null&&e.length?`<div class="wdd-orders-header"><span>${e.length} open order${e.length>1?"s":""}</span></div>
    <div class="wdd-orders-list">
      ${e.map(s=>`<div class="wdd-order-row">
        <div class="wdd-order-dir ${s.flags&524288?"sell":"buy"}">${s.flags&524288?"SELL":"BUY"}</div>
        <div class="wdd-order-pair">
          <span class="wdd-order-gets">${Zo(s.TakerGets)}</span>
          <span class="wdd-order-arrow">\u21C4</span>
          <span class="wdd-order-pays">${Zo(s.TakerPays)}</span>
        </div>
        <div class="wdd-order-seq mono">Seq #${s.seq||"?"}</div>
        <button class="wdd-order-cancel" onclick="cancelOffer('${t}',${s.seq},this)">\u2715 Cancel</button>
      </div>`).join("")}
    </div>`:'<div class="wdd-empty"><div class="wdd-empty-icon">\u{1F4CA}</div><div>No open DEX orders.</div></div>'}async function Eh(e){try{let n=(ti[e]||[]).filter(s=>{var a;return((a=s.currency)==null?void 0:a.length)===40});return n.length?`<div class="wdd-amm-list">
      ${n.map(s=>{let a=s.currency,o=_(parseFloat(s.balance||0),6);return`<div class="wdd-amm-row">
          <div class="wdd-amm-icon">\u{1F30A}</div>
          <div class="wdd-amm-info">
            <div class="wdd-amm-pool mono">${a.slice(0,12)}\u2026</div>
            <div class="wdd-amm-bal">LP Tokens: ${o}</div>
            <div class="wdd-amm-issuer mono" style="opacity:.4;font-size:.7rem">${s.issuer.slice(0,14)}\u2026</div>
          </div>
          <a class="wdd-tx-hash" href="https://xrpscan.com/amm/${s.issuer}" target="_blank" rel="noopener">View AMM</a>
        </div>`}).join("")}
    </div>`:'<div class="wdd-empty"><div class="wdd-empty-icon">\u{1F30A}</div><div>No AMM LP positions.</div><div class="wdd-empty-sub">Deposit into an AMM pool to earn fees.</div></div>'}catch(t){return`<div class="wdd-error">\u26A0\uFE0F ${y(t.message)}</div>`}}async function Ad(e,t,n){let s=prompt("Optional seed to cancel this order (leave blank to use wallet password):");if(s!==null){n&&(n.disabled=!0,n.textContent="\u2026");try{let a=await Gh(e,t,s);if(jh(a)){ae("Order cancelled \u2713");let o=re.find(i=>i.id===e);o&&(delete si[o.address],hi(e,"orders"))}else Wt("Cancel failed: "+qh(a)),n&&(n.disabled=!1,n.textContent="\u2715 Cancel")}catch(a){Wt(a.message),n&&(n.disabled=!1,n.textContent="\u2715 Cancel")}}}function Nh(){let e=x("profile-tab-activity");if(!e)return;let t=uf(),n=Et();e.innerHTML=`
    <div class="act-section-row">
      <div class="act-section">
        <div class="act-section-title">In-App Activity</div>
        <div class="act-section-sub">Your recent actions in NaluXRP</div>
        ${t.length?`<div class="act-timeline">${t.slice(0,20).map(s=>`
            <div class="act-entry">
              <div class="act-entry-icon">${of[s.type]||"\u25CF"}</div>
              <div class="act-entry-body">
                <div class="act-entry-detail">${y(s.detail)}</div>
                <div class="act-entry-time">${ql(s.ts)}</div>
              </div>
            </div>`).join("")}</div>`:'<div class="act-empty-small">No activity yet.</div>'}
      </div>
      <div class="act-section">
        <div class="act-section-title">On-Chain Activity</div>
        <div class="act-section-sub">Full forensic analysis via Inspector</div>
        ${n?`<div class="act-redirect-card">
          <div class="act-rc-icon">\u{1F50D}</div>
          <div class="act-rc-body">
            <div class="act-rc-title">${y(n.label)}</div>
            <div class="act-rc-sub">Transaction history, wash trading signals, fund flow tracing, and a full investigation report.</div>
            <button class="act-inspect-btn-lg" onclick="inspectWalletAddr('${y(n.address)}')">Open Inspector \u2192</button>
          </div>
        </div>`:'<div class="act-empty-small">Create a wallet to inspect on-chain activity.</div>'}
      </div>
    </div>`}function Os(){var o,i;let e=x("profile-tab-settings");if(!e)return;let t=["gold","cosmic","starry","hawaiian"],n=Q("nalulf_pref_currency")||"XRP",s=Q("nalulf_pref_network")||"mainnet",a=Q("nalulf_pref_autolock")||"30";e.innerHTML=`<div class="settings-grid">

    <div class="settings-card">
      <div class="settings-card-hdr"><span class="settings-card-icon">\u{1F3A8}</span>
        <div><div class="settings-card-title">Appearance</div><div class="settings-card-sub">Theme and display preferences</div></div></div>
      <div class="settings-label">Theme</div>
      <div class="settings-theme-row">
        ${t.map(r=>`<button class="theme-pill ${r} ${B.currentTheme===r?"active":""}" onclick="prefSetTheme('${r}')">${r[0].toUpperCase()+r.slice(1)}</button>`).join("")}
      </div>
      <div style="margin-top:16px"><div class="settings-label">Display currency</div>
        <div class="settings-seg">
          <button class="settings-seg-btn ${n==="XRP"?"active":""}" onclick="setPrefCurrency('XRP')">XRP</button>
          <button class="settings-seg-btn ${n==="USD"?"active":""}" onclick="setPrefCurrency('USD')">USD</button>
        </div>
      </div>
      <div style="margin-top:16px"><div class="settings-label">3D immersive background</div>
        <div class="settings-seg">
          <button class="settings-seg-btn ${P.threeEnabled?"active":""}" onclick="setThreeEffects(true)">On</button>
          <button class="settings-seg-btn ${P.threeEnabled?"":"active"}" onclick="setThreeEffects(false)">Off</button>
        </div>
      </div>
    </div>

    <div class="settings-card">
      <div class="settings-card-hdr"><span class="settings-card-icon">\u{1F310}</span>
        <div><div class="settings-card-title">Network</div><div class="settings-card-sub">Default XRPL network for new wallets</div></div></div>
      <div class="settings-label">Default network</div>
      <div class="settings-seg">
        <button class="settings-seg-btn ${s==="mainnet"?"active":""}" onclick="setPrefNetwork('mainnet')">\u{1F7E2} Mainnet</button>
        <button class="settings-seg-btn ${s==="testnet"?"active":""}" onclick="setPrefNetwork('testnet')">\u{1F7E1} Testnet</button>
      </div>
      <div style="margin-top:16px"><div class="settings-label">Auto-lock after</div>
        <div class="settings-seg">
          <button class="settings-seg-btn ${a==="15"?"active":""}" onclick="setPrefAutoLock('15')">15 min</button>
          <button class="settings-seg-btn ${a==="30"?"active":""}" onclick="setPrefAutoLock('30')">30 min</button>
          <button class="settings-seg-btn ${a==="60"?"active":""}" onclick="setPrefAutoLock('60')">1 hr</button>
        </div>
      </div>
    </div>

    <div class="settings-card">
      <div class="settings-card-hdr"><span class="settings-card-icon">\u{1F510}</span>
        <div><div class="settings-card-title">Vault Security</div><div class="settings-card-sub">AES-256-GCM \xB7 PBKDF2 \xB7 SHA-256</div></div></div>
      <div class="settings-kv-list">
        <div class="settings-kv"><span class="settings-k">Encryption</span><span class="settings-v mono">AES-256-GCM</span></div>
        <div class="settings-kv"><span class="settings-k">Key derivation</span><span class="settings-v mono">PBKDF2 \xB7 150k iterations</span></div>
        <div class="settings-kv"><span class="settings-k">Vault created</span><span class="settings-v">${y((i=(o=Ke.vault)==null?void 0:o.identity)!=null&&i.createdAt?new Date(Ke.vault.identity.createdAt).toLocaleDateString():"\u2014")}</span></div>
        <div class="settings-kv"><span class="settings-k">Server storage</span><span class="settings-v settings-v--good">None \xB7 local only</span></div>
        <div class="settings-kv"><span class="settings-k">Wallets</span><span class="settings-v">${re.length} stored</span></div>
      </div>
    </div>

    <div class="settings-card">
      <div class="settings-card-hdr"><span class="settings-card-icon">\u{1F4C2}</span>
        <div><div class="settings-card-title">Backup &amp; Recovery</div><div class="settings-card-sub">Keep a copy of your encrypted vault</div></div></div>
      <p class="settings-card-desc">Your backup is still encrypted \u2014 unreadable without your password. Store on USB or an external drive, <strong>not</strong> in the cloud.</p>
      <div class="settings-actions">
        <button class="settings-btn settings-btn--primary" onclick="exportWalletAddresses()">\u2B07 Export Wallet Addresses</button>
        <button class="settings-btn" onclick="exportVaultSyncCode()">\u{1F4F1} Device Sync Code</button>
      </div>
    </div>

    <div class="settings-card">
      <div class="settings-card-hdr"><span class="settings-card-icon">\u{1F4E1}</span>
        <div><div class="settings-card-title">Privacy Architecture</div></div></div>
      <div class="settings-privacy-list">
        <div class="settings-privacy-item settings-privacy--good"><span class="spi-dot"></span><div><strong>Zero server storage.</strong> Profile, wallets, and seeds never leave your browser.</div></div>
        <div class="settings-privacy-item settings-privacy--good"><span class="spi-dot"></span><div><strong>Direct XRPL connections.</strong> No proxy \u2014 connects directly to public nodes.</div></div>
        <div class="settings-privacy-item settings-privacy--good"><span class="spi-dot"></span><div><strong>No telemetry.</strong> No analytics, no tracking scripts.</div></div>
        <div class="settings-privacy-item settings-privacy--warn"><span class="spi-dot"></span><div><strong>On-chain data is public.</strong> XRPL transactions are permanently visible to anyone.</div></div>
      </div>
    </div>

    <div class="settings-card settings-card--danger">
      <div class="settings-card-hdr"><span class="settings-card-icon">\u26A0\uFE0F</span>
        <div><div class="settings-card-title">Danger Zone</div><div class="settings-card-sub">Irreversible actions</div></div></div>
      <p class="settings-card-desc">Wiping removes all local data. Your wallets still exist on-chain and can be re-added with their seed phrases.</p>
      <button class="settings-btn settings-btn--danger" onclick="openAuth?.('forgot')">\u{1F5D1} Wipe Account Data</button>
    </div>
  </div>`}async function Rh(){var t;let e=x("profile-tab-analytics");if(e){e.innerHTML='<div class="analytics-grid"><div class="skeleton-card analytics-card--wide" style="height:80px"></div><div class="skeleton-card" style="height:160px"></div><div class="skeleton-card" style="height:160px"></div></div>';try{let n=Et(),s=Object.values(Ye).reduce((r,l)=>r+((l==null?void 0:l.xrp)||0),0),a=wd(),o=Object.values(Ye).flatMap(r=>(r==null?void 0:r.tokens)||[]),i=[];if(n)try{i=((t=ni[n.address])==null?void 0:t.txns)||await vi(n.address,100)}catch{}e.innerHTML=`<div class="analytics-grid">
      <div class="analytics-card analytics-card--wide">
        <div class="analytics-card-hdr"><span class="analytics-card-title">\u{1F4BC} Portfolio Summary</span>
          <span class="analytics-badge">${re.length} wallet${re.length!==1?"s":""}</span></div>
        <div class="portfolio-summary-row">
          ${re.length?re.map(r=>{let l=Ye[r.address],c=l?_(l.xrp,2):"\u2014",d=l&&a?`$${_(l.xrp*a,2)}`:"",u=gi(r.address);return`<div class="portfolio-wallet-row">
                <div class="pwr-icon" style="color:${r.color};background:${r.color}18;border-color:${r.color}33">${y(r.emoji||"\u{1F48E}")}</div>
                <div class="pwr-info"><div class="pwr-label">${y(r.label)}</div><div class="pwr-addr mono">${r.address.slice(0,8)}\u2026${r.address.slice(-5)}</div></div>
                <div class="pwr-sparkline">${Ed(u,80,28,r.color||"#00fff0")}</div>
                <div class="pwr-balance"><div class="pwr-xrp">${c} <span class="pwr-xrp-label">XRP</span></div>${d?`<div class="pwr-usd">${d}</div>`:""}</div>
              </div>`}).join(""):'<div class="analytics-empty">No wallets yet.</div>'}
        </div>
        <div class="portfolio-totals">
          <div class="ptotal"><span class="ptotal-label">Total XRP</span><span class="ptotal-val">${_(s,4)}</span></div>
          ${a?`<div class="ptotal"><span class="ptotal-label">Est. USD</span><span class="ptotal-val ptotal-usd">$${_(s*a,2)}</span></div>`:""}
          <div class="ptotal"><span class="ptotal-label">Tokens</span><span class="ptotal-val">${o.length}</span></div>
          <div class="ptotal"><span class="ptotal-label">Wallets</span><span class="ptotal-val">${re.length}</span></div>
        </div>
      </div>

      ${n?`<div class="analytics-card analytics-card--wide">
        <div class="analytics-card-hdr"><span class="analytics-card-title">\u{1F4C8} Balance History</span>
          <span class="analytics-badge">${y(n.label)}</span></div>
        ${_h(n.address)}
      </div>`:""}

      <div class="analytics-card analytics-card--wide">
        <div class="analytics-card-hdr"><span class="analytics-card-title">\u{1F4C5} On-Chain Activity</span>
          <span class="analytics-badge">${n?y(n.label):"No wallet"}</span></div>
        ${n?Dh(i):'<div class="analytics-empty">Activate a wallet to see activity.</div>'}
      </div>

      <div class="analytics-card">
        <div class="analytics-card-hdr"><span class="analytics-card-title">\u{1F4CA} TX Breakdown</span>
          <span class="analytics-badge">${i.length} recent</span></div>
        ${i.length?Ih(i):'<div class="analytics-empty-chart"><div class="aec-icon">\u{1F4CA}</div><div>Transaction breakdown builds up as this wallet transacts.</div></div>'}
      </div>

      <div class="analytics-card">
        <div class="analytics-card-hdr"><span class="analytics-card-title">\u{1F4B0} XRP Flow</span>
          <span class="analytics-badge">Est. net</span></div>
        ${n&&i.length?Oh(i,n.address):`<div class="analytics-empty-chart"><div class="aec-icon">\u{1F4B0}</div><div>${n?"XRP flow needs at least one transaction to estimate.":"Activate a wallet to see XRP flow."}</div></div>`}
      </div>

      <div class="analytics-card">
        <div class="analytics-card-hdr"><span class="analytics-card-title">\u{1FA99} Token Holdings</span>
          <span class="analytics-badge">${o.length} assets</span></div>
        ${o.length?Fh(o):'<div class="analytics-empty-chart"><div class="aec-icon">\u{1FA99}</div><div>No token trustlines held by any wallet yet.</div></div>'}
      </div>
    </div>`}catch(n){df(e,"analytics",n)}}}function Ed(e,t,n,s){if(e.length<2)return`<svg width="${t}" height="${n}"><line x1="0" y1="${n/2}" x2="${t}" y2="${n/2}" stroke="${s}" stroke-opacity=".2" stroke-width="1" stroke-dasharray="3 2"/></svg>`;let a=e.map(u=>u.xrp),o=Math.min(...a),i=Math.max(...a),r=i-o||1,l=a.map((u,p)=>`${3+p/(a.length-1)*(t-6)},${3+(1-(u-o)/r)*(n-6)}`),[c,d]=l[l.length-1].split(",");return`<svg width="${t}" height="${n}" viewBox="0 0 ${t} ${n}">
    <polyline points="${l.join(" ")}" fill="none" stroke="${s}" stroke-width="1.5" stroke-opacity=".8" stroke-linejoin="round" stroke-linecap="round"/>
    <circle cx="${c}" cy="${d}" r="2.5" fill="${s}" opacity=".9"/>
  </svg>`}function _h(e){let t=gi(e);if(t.length<2)return`<div class="analytics-empty-chart"><div class="aec-icon">\u{1F4CA}</div><div>Balance history builds up as you refresh your wallet over time.</div><div class="aec-sub">${t.length} snapshot${t.length!==1?"s":""} recorded.</div></div>`;let n=560,s=130,a=52,o=12,i=14,r=30,l=t.map(R=>R.xrp),c=t.map(R=>R.ts),d=Math.min(...l),u=Math.max(...l),p=u-d||1,m=c[0],f=c[c.length-1],g=f-m||1,b=R=>a+(R-m)/g*(n-a-o),h=R=>i+(1-(R-d)/p)*(s-i-r),v=t.map(R=>`${b(R.ts).toFixed(1)},${h(R.xrp).toFixed(1)}`),w=b(c[0]),k=b(c[c.length-1]),$=l[l.length-1]-l[0],T=$>=0,S=l[0]?Math.abs($/l[0]*100).toFixed(2):"0.00",M=T?"#00d4ff":"#ff5555",C=[d,(d+u)/2,u].map(R=>({v:R,y:h(R),l:_(R,2)})),E=[0,.5,1].map(R=>({x:a+R*(n-a-o),l:new Date(m+R*g).toLocaleDateString("en-US",{month:"short",day:"numeric"})}));return`
    <div class="balance-chart-meta">
      <div class="bcm-current">${_(l[l.length-1],4)} XRP</div>
      <div class="bcm-delta ${T?"bcm-up":"bcm-down"}">${T?"\u25B2":"\u25BC"} ${S}%</div>
      <div class="bcm-range">${t.length} snapshots</div>
    </div>
    <div class="balance-chart-wrap"><svg class="balance-chart-svg" viewBox="0 0 ${n} ${s}" preserveAspectRatio="none">
      <defs><linearGradient id="bg${e.slice(-4)}" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="${M}" stop-opacity=".22"/><stop offset="100%" stop-color="${M}" stop-opacity="0"/></linearGradient></defs>
      ${C.map(R=>`<line x1="${a}" y1="${R.y.toFixed(1)}" x2="${n-o}" y2="${R.y.toFixed(1)}" stroke="rgba(255,255,255,.06)" stroke-width="1"/>`).join("")}
      <path d="M${w.toFixed(1)},${s-r} L${v.join(" L")} L${k.toFixed(1)},${s-r} Z" fill="url(#bg${e.slice(-4)})"/>
      <polyline points="${v.join(" ")}" fill="none" stroke="${M}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      ${t.map(R=>`<circle cx="${b(R.ts).toFixed(1)}" cy="${h(R.xrp).toFixed(1)}" r="2" fill="${M}" opacity=".7"/>`).join("")}
      ${C.map(R=>`<text x="${a-5}" y="${(R.y+4).toFixed(1)}" text-anchor="end" fill="rgba(255,255,255,.38)" font-size="10" font-family="JetBrains Mono,monospace">${R.l}</text>`).join("")}
      ${E.map(R=>`<text x="${R.x.toFixed(1)}" y="${s-6}" text-anchor="middle" fill="rgba(255,255,255,.32)" font-size="10" font-family="JetBrains Mono,monospace">${R.l}</text>`).join("")}
    </svg></div>`}function Dh(e){if(!e.length)return'<div class="analytics-empty-chart"><div class="aec-icon">\u{1F4C5}</div><div>Activity heatmap fills in as this wallet transacts.</div></div>';let t=new Map;e.forEach(f=>{f.date&&t.set(new Date((f.date+946684800)*1e3).toISOString().slice(0,10),(t.get(new Date((f.date+946684800)*1e3).toISOString().slice(0,10))||0)+1)});let n=26,s=12,a=2,o=new Date,i=Array.from({length:n*7},(f,g)=>{let b=new Date(o);return b.setDate(b.getDate()-(n*7-1-g)),b}),r=Array.from({length:n},(f,g)=>i.slice(g*7,g*7+7)),l=Math.max(1,...t.values()),c=n*(s+a)+30,d=7*(s+a)+28,u=f=>f===0?"rgba(255,255,255,.07)":`rgb(0,${Math.round(85+f*170)},${Math.round(119+f*121)})`,p=[],m=-1;return r.forEach((f,g)=>{var h;let b=(h=f[0])==null?void 0:h.getMonth();b!==m&&(m=b,p.push({wi:g,l:f[0].toLocaleDateString("en-US",{month:"short"})}))}),`<div class="heatmap-meta"><span>${e.length} tx \xB7 ${t.size} active days</span>
    <div class="heatmap-legend"><span>Less</span><div class="heatmap-legend-cells">${[0,.25,.5,.75,1].map(f=>`<div class="hm-leg-cell" style="background:${u(f)}"></div>`).join("")}</div><span>More</span></div>
  </div>
  <div class="heatmap-scroll"><svg class="heatmap-svg" viewBox="0 0 ${c} ${d}" width="${c}" height="${d}">
    ${p.map(({wi:f,l:g})=>`<text x="${26+f*(s+a)}" y="10" font-size="9" fill="rgba(255,255,255,.38)" font-family="Outfit,sans-serif">${g}</text>`).join("")}
    ${["","Mon","","Wed","","Fri",""].map((f,g)=>f?`<text x="0" y="${16+g*(s+a)+s/2+3}" font-size="9" fill="rgba(255,255,255,.3)" font-family="Outfit,sans-serif">${f}</text>`:"").join("")}
    ${r.map((f,g)=>f.map((b,h)=>{let v=b.toISOString().slice(0,10),w=t.get(v)||0;return`<rect x="${26+g*(s+a)}" y="${16+h*(s+a)}" width="${s}" height="${s}" rx="2" fill="${u(w/l)}" opacity="${w>0?.9:.25}"><title>${v}: ${w} tx</title></rect>`}).join("")).join("")}
  </svg></div>`}function Ih(e){let t=new Map;e.forEach(a=>t.set(a.TransactionType||"?",(t.get(a.TransactionType||"?")||0)+1));let n=[...t.entries()].sort((a,o)=>o[1]-a[1]),s=e.length;return`<div class="tx-breakdown-list">${n.slice(0,8).map(([a,o])=>`<div class="txb-row"><div class="txb-icon">${Md(a)}</div><div class="txb-type">${a}</div><div class="txb-bar-wrap"><div class="txb-bar" style="width:${(o/s*100).toFixed(0)}%"></div></div><div class="txb-count">${o}</div></div>`).join("")}</div>`}function Fh(e){let t=new Map;e.forEach(o=>{let i=Math.abs(parseFloat(o.balance||0));t.set(o.currency,(t.get(o.currency)||0)+i)});let n=[...t.entries()].sort((o,i)=>i[1]-o[1]).slice(0,8),s=n.reduce((o,[,i])=>o+i,0)||1,a=["#00fff0","#00d4ff","#bd93f9","#50fa7b","#ffb86c","#ff79c6","#f1fa8c","#ff5555"];return`<div class="token-alloc-list">${n.map(([o,i],r)=>{let l=(i/s*100).toFixed(1),c=a[r%a.length],d=o.length>4?o.slice(0,4)+"\u2026":o;return`<div class="ta-row"><div class="ta-swatch" style="background:${c}"></div><div class="ta-cur mono">${d}</div><div class="ta-bar-wrap"><div class="ta-bar" style="width:${l}%;background:${c}20;border-color:${c}55"></div></div><div class="ta-pct">${l}%</div></div>`}).join("")}</div>`}function Oh(e,t){let n=0,s=0;e.forEach(i=>{var c,d;if(i.TransactionType!=="Payment"||!((((c=i.metaData)==null?void 0:c.TransactionResult)||((d=i.meta)==null?void 0:d.TransactionResult))==="tesSUCCESS")||typeof i.Amount!="string")return;let l=Number(i.Amount)/1e6;i.Destination===t&&(n+=l),i.Account===t&&(s+=l)});let a=n-s,o=a>=0;return`<div class="xrp-flow-grid">
    <div class="xrf-item xrf-in"><div class="xrf-label">\u2193 Inflow</div><div class="xrf-val">${_(n,4)} XRP</div></div>
    <div class="xrf-item xrf-out"><div class="xrf-label">\u2191 Outflow</div><div class="xrf-val">${_(s,4)} XRP</div></div>
    <div class="xrf-item ${o?"xrf-pos":"xrf-neg"}"><div class="xrf-label">Net</div><div class="xrf-val">${o?"+":""}${_(a,4)} XRP</div></div>
  </div>
  <div class="xrf-note">Based on ${e.length} fetched Payment TXs. Excludes fees and DEX fills.</div>`}async function st(e){var n,s;try{if(((n=B.wsConn)==null?void 0:n.readyState)===1){let{wsSend:a}=await import("./xrpl-6AERZ5KD.js"),o={command:e==null?void 0:e.method,...((s=e==null?void 0:e.params)==null?void 0:s[0])||{}},i=await a(o);if((i==null?void 0:i.status)==="error")throw new Error(i.error_message||i.error||"XRPL RPC error");return(i==null?void 0:i.result)||null}}catch{}let t=async a=>{let o=await fetch(a,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(e),mode:"cors"});if(!o.ok)throw new Error(`HTTP ${o.status}`);return(await o.json()).result};try{return await t(Im)}catch{return await t(Fm)}}async function Fn(e){var t;try{let n=[],s;do{let l=await st({method:"account_lines",params:[{account:e,ledger_index:"current",limit:400,...s?{marker:s}:{}}]});if(!l||l.error)break;n.push(...l.lines||[]),s=l.marker}while(s);let a=await st({method:"account_info",params:[{account:e,ledger_index:"current"}]});if(a!=null&&a.error)return null;let o=Number(a.account_data.Balance)/1e6,i=n.map(l=>({currency:l.currency,issuer:l.account,balance:l.balance,limit:l.limit}));Ye[e]={xrp:o,tokens:i,fetchedAt:Date.now()},ti[e]=i,Xh(e,o);let r=document.getElementById("awb-balance");return r&&e===((t=Et())==null?void 0:t.address)&&og(r.querySelector(".awb-xrp-num")||r,o,2,600),Ye[e]}catch{return null}}async function Bh(){await Promise.allSettled(re.map(e=>Fn(e.address))),$t(),Bt(),Ds()}function Xh(e,t){let n=ei+e,s=ve(Q(n))||[],a=Date.now();s.length&&a-s[s.length-1].ts<5*6e4?s[s.length-1]={xrp:t,ts:a}:s.push({xrp:t,ts:a}),s.length>90&&s.splice(0,s.length-90),Z(n,JSON.stringify(s))}function gi(e){return ve(Q(ei+e))||[]}async function vi(e,t=25){let n=await st({method:"account_tx",params:[{account:e,limit:t,ledger_index_min:-1,ledger_index_max:-1}]}),s=((n==null?void 0:n.transactions)||[]).map(a=>a.tx||a.transaction||a);return ni[e]={txns:s,fetchedAt:Date.now()},s}async function Hh(e){let t=await st({method:"account_nfts",params:[{account:e,limit:50}]}),n=(t==null?void 0:t.account_nfts)||[];return Rl[e]={nfts:n,fetchedAt:Date.now()},n}async function zh(e){let t=await st({method:"account_offers",params:[{account:e,limit:50}]}),n=(t==null?void 0:t.offers)||[];return si[e]={offers:n,fetchedAt:Date.now()},n}async function Wh(e){let t=await st({method:"account_info",params:[{account:e,ledger_index:"current"}]});return(t==null?void 0:t.account_data)||null}async function Uh(){let e=await st({method:"ledger",params:[{ledger_index:"current"}]});return(e==null?void 0:e.ledger_current_index)||0}function jh(e){let t=(e==null?void 0:e.engine_result)||"";return t==="tesSUCCESS"||t.startsWith("tes")||(e==null?void 0:e.engine_result_code)===0}function qh(e){let t=(e==null?void 0:e.engine_result)||"";return Vm[t]||(e==null?void 0:e.engine_result_message)||t||"Unknown error"}async function Vh(e,t,n){if(await Aa(),!window.xrpl)throw new Error("xrpl.js library not loaded. Cannot sign transactions.");let s=re.find(i=>i.id===e);if(!s)throw new Error("Wallet not found.");if(s.watchOnly)throw new Error("Watch-only wallets cannot sign transactions.");let a=await Jm(s,n),o;try{o=window.xrpl.Wallet.fromSeed(a,{algorithm:s.algo==="secp256k1"?"secp256k1":"ed25519"})}catch(i){throw new Error("Invalid seed phrase: "+i.message)}if(o.classicAddress!==s.address)throw new Error("Seed does not match this wallet address.");try{let[i,r]=await Promise.all([Wh(s.address),Uh()]);if(!i)throw new Error("Account not found on-chain. Fund with at least 10 XRP first (base reserve requirement).");let l={...t,Account:s.address,Fee:"12",Sequence:i.Sequence,LastLedgerSequence:r+20},{tx_blob:c,hash:d}=o.sign(l);return{...await st({method:"submit",params:[{tx_blob:c}]}),tx_hash:d}}finally{}}async function Gh(e,t,n){return Vh(e,{TransactionType:"OfferCancel",OfferSequence:parseInt(t)},n)}function Kh(){if(x("send-modal-overlay"))return;let e=document.createElement("div");e.innerHTML=`
  <!-- Send -->
  <div class="wallet-action-overlay" id="send-modal-overlay">
    <div class="wallet-action-modal">
      <div class="wam-header"><div><div class="wam-title">\u2B06 Send</div><div class="wam-sub" id="send-modal-wallet-name"></div></div><button class="modal-close" onclick="closeSendModal()">\u2715</button></div>
      <div class="wam-body">
        <div class="wam-from-row"><span class="wam-from-label">From</span><span class="wam-from-addr mono" id="send-from-address"></span><span class="wam-balance-pill" id="send-available-balance"></span></div>
        <div class="profile-field"><label class="profile-field-label">Destination Address *</label><input class="profile-input mono" id="send-dest" placeholder="rXXXX\u2026" autocomplete="off"></div>
        <div class="wam-row2">
          <div class="profile-field" style="flex:1"><label class="profile-field-label">Amount *</label><input class="profile-input mono" id="send-amount" type="number" placeholder="0.00" min="0" step="any"></div>
          <div class="profile-field" style="flex:1"><label class="profile-field-label">Currency</label><select class="profile-input" id="send-currency-select"><option value="XRP">XRP</option></select></div>
        </div>
        <div class="profile-field"><label class="profile-field-label">Destination Tag <span style="opacity:.5">(optional)</span></label><input class="profile-input mono" id="send-dest-tag" type="number" placeholder="Required by some exchanges"></div>
        <div class="profile-field"><label class="profile-field-label">Seed Phrase <span style="font-size:.72rem;color:rgba(255,255,255,.3);text-transform:none">(optional if wallet is encrypted)</span></label><input class="profile-input mono" id="send-seed" type="password" placeholder="Leave blank to use wallet password" autocomplete="off"></div>
        <div class="wam-error" id="send-error"></div>
      </div>
      <div class="wam-footer"><button class="btn-wizard-back" onclick="closeSendModal()">Cancel</button><button class="btn-wizard-next" id="send-submit-btn" onclick="executeSend()">Send \u2B06</button></div>
    </div>
  </div>
  <!-- Receive -->
  <div class="wallet-action-overlay" id="receive-modal-overlay">
    <div class="wallet-action-modal">
      <div class="wam-header"><div><div class="wam-title">\u2B07 Receive</div><div class="wam-sub" id="receive-wallet-name"></div></div><button class="modal-close" onclick="closeReceiveModal()">\u2715</button></div>
      <div class="wam-body" style="text-align:center">
        <div class="receive-qr-wrap"><div id="receive-qr-container" class="receive-qr-box"></div></div>
        <div class="receive-address-box"><span class="receive-address-val mono" id="receive-address-display"></span></div>
        <button class="btn-wizard-next" id="receive-copy-btn" onclick="copyReceiveAddress()" style="margin-top:16px;width:100%">\u29C9 Copy Address</button>
        <p class="receive-note">Share this address to receive XRP or tokens. Always verify the full address before sending.</p>
      </div>
    </div>
  </div>
  <!-- Trustline -->
  <div class="wallet-action-overlay" id="trustline-modal-overlay">
    <div class="wallet-action-modal wallet-action-modal--wide">
      <div class="wam-header"><div><div class="wam-title">\u{1F517} Trustlines</div><div class="wam-sub" id="trustline-wallet-name"></div></div><button class="modal-close" onclick="closeTrustlineModal()">\u2715</button></div>
      <div class="wam-body">
        <div class="tl-section-h">Active trustlines</div>
        <div id="trustline-list-container" class="tl-list"></div>
        <div class="tl-divider"></div>
        <div class="tl-section-h">Add new trustline</div>
        <div class="wam-row2">
          <div class="profile-field" style="flex:1"><label class="profile-field-label">Currency Code *</label><input class="profile-input" id="tl-currency" placeholder="USD / BTC / SOLO" maxlength="20"></div>
          <div class="profile-field" style="flex:1"><label class="profile-field-label">Trust Limit</label><input class="profile-input mono" id="tl-limit" type="number" placeholder="1000000000" value="1000000000"></div>
        </div>
        <div class="profile-field"><label class="profile-field-label">Issuer Address *</label><input class="profile-input mono" id="tl-issuer" placeholder="rXXXX\u2026 token issuer"></div>
        <div class="profile-field"><label class="profile-field-label">Seed Phrase <span style="font-size:.72rem;color:rgba(255,255,255,.3);text-transform:none">(optional if wallet is encrypted)</span></label><input class="profile-input mono" id="tl-seed" type="password" placeholder="Leave blank to use wallet password" autocomplete="off"></div>
        <div class="wam-error" id="tl-error"></div>
      </div>
      <div class="wam-footer"><button class="btn-wizard-back" onclick="closeTrustlineModal()">Close</button><button class="btn-wizard-finish" id="tl-add-btn" onclick="addTrustline()">+ Add Trustline</button></div>
    </div>
  </div>
  <!-- Import Address -->
  <div class="generic-modal-overlay" id="import-address-modal">
    <div class="generic-modal">
      <div class="gm-hdr"><div class="gm-title">\u{1F441} Watch Address</div><button class="gm-close" onclick="closeImportAddressModal()">\u2715</button></div>
      <div class="gm-sub">Track any XRPL address read-only \u2014 no seed required. Useful for monitoring another wallet or a known exchange address.</div>
      <div class="gm-warning"><span class="gm-warn-icon">\u26A0</span><span>Watch-only wallets cannot sign transactions.</span></div>
      <div class="profile-field"><label class="profile-field-label">XRPL Address *</label><input class="profile-input mono" id="inp-import-address" placeholder="rXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" autocomplete="off"></div>
      <div class="profile-field"><label class="profile-field-label">Label</label><input class="profile-input" id="inp-import-label" placeholder="e.g. My exchange hot wallet"></div>
      <div class="gm-error" id="import-address-error"></div>
      <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:16px">
        <button class="btn-wizard-back" onclick="closeImportAddressModal()">Cancel</button>
        <button class="btn-wizard-next" onclick="importWatchOnlyWallet()">Add Watch Wallet \u2192</button>
      </div>
    </div>
  </div>
  <!-- Import Seed -->
  <div class="generic-modal-overlay" id="import-seed-modal">
    <div class="generic-modal">
      <div class="gm-hdr"><div class="gm-title">\u{1F511} Import from Seed</div><button class="gm-close" onclick="closeImportSeedModal()">\u2715</button></div>
      <div class="gm-sub">Import an existing XRPL wallet using its family seed (starts with 's') or hex seed. Your seed will be encrypted and stored only on this device.</div>
      <div class="gm-warning"><span class="gm-warn-icon">\u26A0</span><span>Never share your seed with anyone. Only import seeds you trust.</span></div>
      <div class="profile-field"><label class="profile-field-label">Seed Phrase *</label><input class="profile-input mono" id="inp-import-seed" placeholder="sXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" type="password" autocomplete="off"></div>
      <div class="profile-field"><label class="profile-field-label">Wallet Password *</label><input class="profile-input" id="inp-import-seed-pass" type="password" placeholder="At least 10 characters" autocomplete="new-password"></div>
      <div class="profile-field"><label class="profile-field-label">Confirm Password *</label><input class="profile-input" id="inp-import-seed-pass-confirm" type="password" placeholder="Re-enter wallet password" autocomplete="new-password"></div>
      <div class="profile-field"><label class="profile-field-label">Wallet Label</label><input class="profile-input" id="inp-import-seed-label" placeholder="e.g. My Old Wallet"></div>
      <div class="gm-error" id="import-seed-error"></div>
      <div style="display:flex;gap:10px;justify-content:flex-end;margin-top:16px">
        <button class="btn-wizard-back" onclick="closeImportSeedModal()">Cancel</button>
        <button class="btn-wizard-next" id="import-seed-btn" onclick="executeImportFromSeed()">Import Wallet \u2192</button>
      </div>
    </div>
  </div>
  <!-- Token Details -->
  <div class="generic-modal-overlay" id="token-details-modal">
    <div class="generic-modal" style="max-width:420px"></div>
  </div>`,document.body.appendChild(e),["send-modal-overlay","receive-modal-overlay","trustline-modal-overlay","import-address-modal","import-seed-modal","token-details-modal"].forEach(t=>{let n=document.getElementById(t);n==null||n.addEventListener("click",s=>{s.target===n&&(n.classList.remove("show"),n.style.display="")})})}function Nd(){var o;["displayName","handle","bio","location","website"].forEach(i=>{let r=x(`edit-${i}`);r&&(r.value=de[i]||"")});let e=x("editor-avatar-preview");if(e){let i=localStorage.getItem(pn);e.innerHTML=i?`<img src="${i}" class="profile-avatar-img"/>`:de.avatar||"\u{1F30A}"}let t=x("avatar-remove-btn");t&&(t.style.display=localStorage.getItem(pn)?"":"none");let n=x("editor-banner-preview");if(n){let i=localStorage.getItem(Dn);n.style.backgroundImage=i?`url(${i})`:"",n.style.backgroundSize="cover",n.style.backgroundPosition="center",Ns.forEach(r=>n.classList.remove(r)),i||n.classList.add(de.banner||"banner-ocean")}let s=x("avatar-picker-grid");s&&(s.innerHTML=Um.map(i=>`<div class="avatar-option ${de.avatar===i?"active":""}" onclick="selectAvatar('${i}')">${i}</div>`).join(""));let a=x("banner-picker-grid");a&&(a.innerHTML=Ns.map(i=>`<div class="banner-option ${i} ${de.banner===i?"active":""}" onclick="selectBanner('${i}')"></div>`).join("")),(o=x("profile-editor-modal"))==null||o.classList.add("show")}function Bs(){var e;(e=x("profile-editor-modal"))==null||e.classList.remove("show")}function Rd(){var e,t,n,s,a;de.displayName=((e=x("edit-displayName"))==null?void 0:e.value.trim())||de.displayName,de.handle=(((t=x("edit-handle"))==null?void 0:t.value.trim())||de.handle).replace(/^@/,"").replace(/\s+/g,"_").toLowerCase(),de.bio=((n=x("edit-bio"))==null?void 0:n.value.trim())||"",de.location=((s=x("edit-location"))==null?void 0:s.value.trim())||"",de.website=((a=x("edit-website"))==null?void 0:a.value.trim())||"",Ul(),kt("profile_saved","Profile details updated"),j(),Bs(),ae("Profile saved")}function _d(e){localStorage.removeItem(pn),de.avatar=e,Be(".avatar-option").forEach(s=>s.classList.toggle("active",s.textContent===e));let t=x("editor-avatar-preview");t&&(t.innerHTML=e);let n=x("avatar-remove-btn");n&&(n.style.display="none")}function Dd(e){localStorage.removeItem(Dn),de.banner=e,Be(".banner-option").forEach(n=>n.classList.toggle("active",n.classList.contains(e)));let t=x("editor-banner-preview");t&&(t.style.backgroundImage="",Ns.forEach(n=>t.classList.remove(n)),t.classList.add(e)),j()}function Id(e){var s;let t=(s=e==null?void 0:e.files)==null?void 0:s[0];if(!t)return;if(t.size>2*1024*1024){ge("Image too large \u2014 max 2 MB");return}let n=new FileReader;n.onload=a=>{let o=new Image;o.onload=()=>{let i=document.createElement("canvas");i.width=i.height=200;let r=i.getContext("2d"),l=Math.min(o.width,o.height);r.drawImage(o,(o.width-l)/2,(o.height-l)/2,l,l,0,0,200,200);let c=i.toDataURL("image/jpeg",.85);localStorage.setItem(pn,c);let d=x("editor-avatar-preview");d&&(d.innerHTML=`<img src="${c}" class="profile-avatar-img"/>`);let u=x("avatar-remove-btn");u&&(u.style.display=""),j(),ae("Profile photo updated")},o.src=a.target.result},n.readAsDataURL(t),e.value=""}function Fd(){localStorage.removeItem(pn);let e=x("editor-avatar-preview");e&&(e.innerHTML=de.avatar||"\u{1F30A}");let t=x("avatar-remove-btn");t&&(t.style.display="none"),j()}function Od(e){var s;let t=(s=e==null?void 0:e.files)==null?void 0:s[0];if(!t)return;if(t.size>5*1024*1024){ge("Image too large \u2014 max 5 MB");return}let n=new FileReader;n.onload=a=>{let o=new Image;o.onload=()=>{let i=document.createElement("canvas");i.width=900,i.height=180;let r=i.getContext("2d"),l=Math.max(900/o.width,180/o.height);r.drawImage(o,(900-o.width*l)/2,(180-o.height*l)/2,o.width*l,o.height*l);let c=i.toDataURL("image/jpeg",.88);localStorage.setItem(Dn,c);let d=x("editor-banner-preview");d&&(d.style.backgroundImage=`url(${c})`,d.style.backgroundSize="cover",d.style.backgroundPosition="center",Ns.forEach(p=>d.classList.remove(p)));let u=x("banner-remove-btn");u&&(u.style.display=""),j(),ae("Banner updated")},o.src=a.target.result},n.readAsDataURL(t),e.value=""}function Bd(){localStorage.removeItem(Dn);let e=x("editor-banner-preview");e&&(e.style.backgroundImage="",Ns.forEach(n=>e.classList.remove(n)),e.classList.add(de.banner||"banner-ocean"));let t=x("banner-remove-btn");t&&(t.style.display="none"),j()}function Jh(){let e=re.map(({id:n,label:s,address:a,algo:o,emoji:i,color:r,testnet:l,watchOnly:c,createdAt:d})=>({id:n,label:s,address:a,algo:o,emoji:i,color:r,testnet:l,watchOnly:c,createdAt:d})),t=document.createElement("a");t.href="data:application/json;charset=utf-8,"+encodeURIComponent(JSON.stringify(e,null,2)),t.download=`nalulf-wallets-${new Date().toISOString().slice(0,10)}.json`,t.click(),kt("backup_exported","Wallet addresses exported"),ae("Wallet addresses exported")}function Xd(){Jh()}function bi(){var e;wt=1,ye={algo:"ed25519",label:"",emoji:"\u{1F48E}",color:"#50fa7b",seed:"",address:"",passphrase:""},_n.clear(),yi(1),Qh(),Yh(),(e=x("wallet-creator-overlay"))==null||e.classList.add("show"),setTimeout(()=>{var t;return(t=x("wallet-label-input"))==null?void 0:t.focus()},80)}function Xs(){var e;(e=x("wallet-creator-overlay"))==null||e.classList.remove("show"),ye.seed=ye.address=ye.passphrase=""}function Yh(){let e=x("wizard-security-banner");e&&(e.innerHTML=`<div class="wsb-icon">\u{1F510}</div>
    <div class="wsb-content">
      <div class="wsb-title">Your keys are encrypted on your device</div>
      <div class="wsb-body">Your wallet seed is encrypted with your password using AES-256-GCM before being saved to this device. <strong>It never leaves your browser.</strong></div>
      <div class="wsb-pills">
        <span class="wsb-pill wsb-pill--green">\u{1F512} Local only</span>
        <span class="wsb-pill wsb-pill--green">\u{1F6AB} Never sent to servers</span>
        <span class="wsb-pill wsb-pill--blue">\u26A1 AES-256-GCM</span>
      </div>
    </div>`)}async function Hd(){var e,t,n;if(wt===1){let s=(e=x("wallet-label-input"))==null?void 0:e.value.trim(),a=((t=x("wallet-pass-input"))==null?void 0:t.value)||"",o=((n=x("wallet-pass-confirm"))==null?void 0:n.value)||"";if(!s){ge("Enter a wallet name.");return}if(a.length<10){ge("Use a wallet password with at least 10 characters.");return}if(a!==o){ge("Wallet password confirmation does not match.");return}if(ye.label=s,ye.passphrase=a,!Zh())return;wt=2}else if(wt===2){if(_n.size<4){ge("Confirm all 4 security checkpoints first.");return}wt=3}else if(wt===3)try{await tg(),wt=4}catch{return}yi(wt)}function zd(){if(wt<=1){Xs();return}wt--,yi(wt)}function yi(e){var a;[1,2,3,4].forEach(o=>{let i=document.querySelector(`.step-${o}`);i&&(i.classList.toggle("active",o===e),i.classList.toggle("done",o<e))}),Be(".wizard-panel").forEach(o=>o.classList.remove("active")),(a=x(`wizard-panel-${e}`))==null||a.classList.add("active");let t=x("wizard-back-btn"),n=x("wizard-next-btn"),s=x("wizard-finish-btn");t&&(t.style.display=e===4?"none":"",t.textContent=e===1?"Cancel":"\u2190 Back"),n&&(n.style.display=e>=3?"none":""),s&&(s.style.display=e===3?"":"none")}function Qh(){let e=x("wallet-emoji-picker");e&&(e.innerHTML=jm.map(n=>`<div class="wallet-emoji-opt ${ye.emoji===n?"active":""}" onclick="selectWalletEmoji('${n}')">${n}</div>`).join(""));let t=x("wallet-color-picker");t&&(t.innerHTML=qm.map(n=>`<div class="color-swatch ${ye.color===n?"active":""}" style="background:${n}" onclick="selectWalletColor('${n}')"></div>`).join(""))}function Zh(){var n;if(!((n=window.xrpl)!=null&&n.Wallet))return Wt("xrpl.js is not available yet. Please wait a moment and try again."),Aa().catch(()=>{}),!1;try{let s=window.xrpl.Wallet.generate(ye.algo==="ed25519"?"ed25519":"secp256k1");ye.seed=s.seed||"",ye.address=s.classicAddress}catch(s){return Wt("Failed to generate a valid XRPL wallet: "+((s==null?void 0:s.message)||"Unknown error")),!1}let e=x("wizard-seed-value"),t=x("wizard-address-value");return e&&(e.textContent=ye.seed),t&&(t.textContent=ye.address),_n.clear(),Be(".security-check").forEach(s=>s.classList.remove("checked")),Be(".check-box").forEach(s=>s.textContent=""),eg(),Vd(),e&&setTimeout(()=>e.classList.add("blur"),3e4),!0}function eg(){let e=x("security-checklist-dynamic");if(!e)return;let t=[{icon:"\u270D\uFE0F",title:"Write it on paper right now",body:"Copy your seed phrase onto paper and store it in a safe place. This is your ONLY recovery option if you lose access to this device."},{icon:"\u{1F6AB}",title:"Never store it digitally",body:"No notes apps, emails, screenshots, or cloud drives. A device with a digital copy that gets hacked means instant loss of funds."},{icon:"\u{1F92B}",title:"Never share it with anyone",body:"No legitimate app, exchange, or support team will ever ask for your seed. Anyone who asks is attempting to steal your funds."},{icon:"\u{1F510}",title:"Use a strong unique password",body:"Your password protects the encrypted seed on this device. Use one you don't use anywhere else."}];e.innerHTML=t.map((n,s)=>`
    <div class="security-check security-check-${s+1}" onclick="toggleSecurityCheck(${s+1})">
      <span class="check-box" id="check-box-${s+1}"></span>
      <div class="check-text"><strong>${n.icon} ${y(n.title)}</strong>${y(n.body)}</div>
    </div>`).join("")}async function tg(){var n;let e=await Nl(ye.seed,ye.passphrase),t={id:crypto.randomUUID(),label:ye.label,address:ye.address,algo:ye.algo,emoji:ye.emoji,color:ye.color,testnet:((n=x("wallet-testnet-check"))==null?void 0:n.checked)||!1,watchOnly:!1,encSeed:e,createdAt:new Date().toISOString()};re.push(t),Rs(),dt||(dt=t.id,Z(Es,t.id)),$t(),Bt(),Ma("wallet-success-address",ye.address),setTimeout(()=>{ye.seed="",ye.address="",ye.passphrase=""},100),kt("wallet_created",ye.label||"New XRPL Wallet"),ae("Wallet created and encrypted locally"),Fn(t.address).then(()=>$t())}function Wd(e){ye.algo=e,Be(".algo-card").forEach(t=>t.classList.toggle("active",t.dataset.algo===e))}function Ud(e){ye.emoji=e,Be(".wallet-emoji-opt").forEach(t=>t.classList.toggle("active",t.textContent===e))}function jd(e){ye.color=e,Be(".color-swatch").forEach(t=>t.classList.toggle("active",t.style.background===e||t.dataset.color===e))}function qd(e){let t=document.querySelector(`.security-check-${e}`);if(!t)return;let n=t.querySelector(".check-box");_n.has(e)?(_n.delete(e),t.classList.remove("checked"),n&&(n.textContent="")):(_n.add(e),t.classList.add("checked"),n&&(n.textContent="\u2713")),Vd()}function Vd(){let e=x("wizard-next-btn");e&&wt===2&&(e.disabled=_n.size<4)}function Gd(){var t;(t=x("wizard-seed-value"))==null||t.classList.remove("blur");let e=x("seed-reveal-hint");e&&(e.style.display="none"),setTimeout(()=>{var n;return(n=x("wizard-seed-value"))==null?void 0:n.classList.add("blur")},3e4)}function Kd(){let e=x("wizard-seed-value");if(!e)return;Ia(e.textContent,3e4);let t=x("btn-copy-seed");t&&(t.textContent="Copied!",t.classList.add("copied"),setTimeout(()=>{t.textContent="Copy Seed",t.classList.remove("copied")},2e3))}function Jd(){let e=x("wizard-address-value")||x("wallet-success-address");if(!e)return;Ia(e.textContent);let t=x("btn-copy-addr");t&&(t.textContent="Copied!",t.classList.add("copied"),setTimeout(()=>{t.textContent="Copy",t.classList.remove("copied")},2e3))}function Yd(){let e=x("import-address-modal");if(!e)return;e.querySelector("#inp-import-address").value="",e.querySelector("#inp-import-label").value="";let t=e.querySelector("#import-address-error");t&&(t.textContent=""),e.classList.add("show"),setTimeout(()=>{var n;return(n=e.querySelector("#inp-import-address"))==null?void 0:n.focus()},80)}function wi(){var e;(e=x("import-address-modal"))==null||e.classList.remove("show")}function Qd(){var s,a;let e=(((s=x("inp-import-address"))==null?void 0:s.value)||"").trim(),t=(((a=x("inp-import-label"))==null?void 0:a.value)||"").trim()||"Watch Wallet",n=x("import-address-error");if(!Xe(e)){n&&(n.textContent="Enter a valid XRPL address (starts with r\u2026)");return}if(re.find(o=>o.address===e)){n&&(n.textContent="This address is already in your list.");return}re.push({id:"watch_"+Date.now(),label:t,address:e,algo:"\u2014",emoji:"\u{1F441}",color:"#8be9fd",testnet:!1,createdAt:new Date().toISOString(),watchOnly:!0}),Rs(),kt("watch_added",`${t} (${e.slice(0,8)}\u2026)`),wi(),$t(),Bt(),Ds(),Fn(e).then(()=>{$t(),Ds()}),ae(`\u{1F441} Watch-only wallet added: ${t}`)}function Zd(){let e=x("import-seed-modal");if(!e)return;e.querySelector("#inp-import-seed").value="",e.querySelector("#inp-import-seed-pass").value="",e.querySelector("#inp-import-seed-pass-confirm").value="",e.querySelector("#inp-import-seed-label").value="";let t=e.querySelector("#import-seed-error");t&&(t.textContent=""),e.classList.add("show"),setTimeout(()=>{var n;return(n=e.querySelector("#inp-import-seed"))==null?void 0:n.focus()},80)}function xi(){var e;(e=x("import-seed-modal"))==null||e.classList.remove("show")}async function ep(){var r,l,c,d,u;let e=(((r=x("inp-import-seed"))==null?void 0:r.value)||"").trim(),t=(((l=x("inp-import-seed-label"))==null?void 0:l.value)||"").trim()||"Imported Wallet",n=(((c=x("inp-import-seed-pass"))==null?void 0:c.value)||"").trim(),s=(((d=x("inp-import-seed-pass-confirm"))==null?void 0:d.value)||"").trim(),a=x("import-seed-error"),o=x("import-seed-btn"),i=p=>{a&&(a.textContent=p)};if(i(""),!e)return i("Enter your seed phrase.");if(n.length<10)return i("Use a wallet password with at least 10 characters.");if(n!==s)return i("Wallet password confirmation does not match.");if(await Aa(),!window.xrpl)return i("xrpl.js not loaded \u2014 cannot derive address from seed.");o&&(o.disabled=!0,o.textContent="Importing\u2026");try{let p=window.xrpl.Wallet.fromSeed(e),m=p.address,f=(u=p.algorithm)!=null&&u.toLowerCase().includes("ed")?"ed25519":"secp256k1";if(re.find(w=>w.address===m))return i("This address is already in your vault.");let g="imp_"+Date.now(),b="\u{1F511}",h="#bd93f9",v=await Nl(e,n);re.push({id:g,label:t,address:m,algo:f,emoji:b,color:h,testnet:!1,watchOnly:!1,encSeed:v,createdAt:new Date().toISOString()}),Rs(),kt("wallet_imported",`${t} (${m.slice(0,8)}\u2026)`),xi(),$t(),Bt(),Fn(m).then(()=>{$t(),Ds()}),ae(`\u{1F511} Wallet imported: ${t}`)}catch(p){i("Invalid seed: "+(p.message||"Could not derive wallet."))}finally{o&&(o.disabled=!1,o.textContent="Import Wallet \u2192");let p=document.getElementById("inp-import-seed");p&&(p.value="");let m=document.getElementById("inp-import-seed-pass");m&&(m.value="");let f=document.getElementById("inp-import-seed-pass-confirm");f&&(f.value="")}}function tp(e,t,n){var d;let s=x("token-details-modal");if(!s)return;let a=s.querySelector(".generic-modal");if(!a)return;let o=Ye[n],i=(d=o==null?void 0:o.tokens)==null?void 0:d.find(u=>u.currency===e&&u.issuer===t),r=i?_(parseFloat(i.balance||0),6):"\u2014",l=i!=null&&i.limit?_(parseFloat(i.limit),2):"Unlimited",c=e.length>4&&ki(e)||e;a.innerHTML=`
    <div class="tdm-hdr">
      <div class="tdm-title"><span class="tdm-icon">\u{1FA99}</span><span class="tdm-cur">${y(c)}</span>
        ${c!==e?`<span class="tdm-hex mono">${y(e)}</span>`:""}</div>
      <button class="tdm-close" onclick="closeTokenDetailsModal()">\u2715</button>
    </div>
    <div class="tdm-grid">
      <div class="tdm-item"><div class="tdm-item-label">Balance</div><div class="tdm-item-val">${r}</div></div>
      <div class="tdm-item"><div class="tdm-item-label">Trust Limit</div><div class="tdm-item-val">${l}</div></div>
      <div class="tdm-item tdm-item--wide">
        <div class="tdm-item-label">Issuer</div>
        <div class="tdm-item-val tdm-issuer mono">${t.slice(0,14)}\u2026${t.slice(-6)}</div>
        <button class="tdm-copy-btn" onclick="copyToClipboard('${y(t)}')">\u29C9 Copy</button>
      </div>
    </div>
    <div class="tdm-links">
      <a class="tdm-link" href="https://xrpscan.com/account/${y(t)}" target="_blank" rel="noopener">\u{1F50D} View Issuer on XRPScan</a>
      <a class="tdm-link" href="https://xrpscan.com/account/${y(n)}#tokens" target="_blank" rel="noopener">\u{1F4CB} All My Tokens</a>
    </div>`,s.classList.add("show")}function np(){let e=x("token-details-modal");e&&(e.classList.remove("show"),e.style.display="")}function sp(){var s;(s=document.getElementById("pub-profile-overlay"))==null||s.remove();let e=localStorage.getItem(pn),t=ns.filter(a=>Ge[a.id]),n=document.createElement("div");n.id="pub-profile-overlay",n.className="pub-profile-overlay",n.innerHTML=`
    <div class="pub-profile-modal">
      <div class="pub-banner ${de.banner||"banner-ocean"}" ${localStorage.getItem(Dn)?`style="background-image:url(${localStorage.getItem(Dn)});background-size:cover;background-position:center;"`:""}>
      </div>
      <div class="pub-hdr">
        <div class="pub-avatar">${e?`<img src="${e}" alt="avatar"/>`:`<span>${y(de.avatar||"\u{1F30A}")}</span>`}</div>
        <div class="pub-info">
          <div class="pub-name">${y(de.displayName||"Anonymous")}</div>
          <div class="pub-handle">@${y(de.handle||"anonymous")}</div>
          ${de.bio?`<div class="pub-bio">${y(de.bio)}</div>`:""}
          <div class="vault-pill vault-pill--locked" style="font-size:.65rem;padding:3px 9px">\u{1F512} Self-custodied XRPL wallet</div>
        </div>
      </div>
      ${t.length?`<div class="pub-socials">${t.map(a=>`<span class="pub-social-badge"><span>${a.icon}</span><span>@${y(Ge[a.id])}</span></span>`).join("")}</div>`:'<div style="padding:0 20px 16px;font-size:.82rem;color:rgba(255,255,255,.3)">No social accounts connected yet.</div>'}
      <div class="pub-close-row">
        <span style="font-size:.78rem;color:rgba(255,255,255,.32);flex:1">This is how others see your profile</span>
        <button class="pub-close-btn" onclick="document.getElementById('pub-profile-overlay').remove()">Close</button>
      </div>
    </div>`,document.body.appendChild(n),requestAnimationFrame(()=>requestAnimationFrame(()=>n.classList.add("show"))),n.addEventListener("click",a=>{a.target===n&&n.remove()})}function ap(e){Cn(e),Os(),kt("theme_changed",e)}function op(e){Z("nalulf_pref_currency",e),Os(),ae(`Display currency: ${e}`)}function ip(e){Z("nalulf_pref_network",e),Os(),ae(`Default network: ${e}`)}function rp(e){Z("nalulf_pref_autolock",e),Os(),ae(`Auto-lock: ${e} minutes`)}window._profileWipeAllData=()=>{confirm("Clear all profile, wallet list, social, and activity data? Encrypted wallet seeds saved on this device will be deleted.")&&(["nalulf_profile","nalulf_wallets","nalulf_social","nalulf_activity_log","nalulf_avatar_img","nalulf_banner_img","naluxrp_active_wallet"].forEach(e=>localStorage.removeItem(e)),re=[],Ge={},dt=null,Ye={},ti={},Vo(),j(),ii("wallets"),ae("Local data cleared"))};function ng(){var e,t,n;(e=x("profile-editor-modal"))==null||e.addEventListener("click",s=>{s.target===s.currentTarget&&Bs()}),(t=x("wallet-creator-overlay"))==null||t.addEventListener("click",s=>{s.target===s.currentTarget&&Xs()}),(n=x("social-modal"))==null||n.addEventListener("click",s=>{s.target===s.currentTarget&&as()})}function sg(){let e=[{done:!!de.displayName&&de.displayName!=="Anonymous",label:"Display name"},{done:!!de.bio,label:"Bio"},{done:de.avatar!=="\u{1F30A}"||!!localStorage.getItem(pn),label:"Custom avatar"},{done:!!localStorage.getItem(Dn),label:"Custom banner"},{done:re.length>0,label:"Wallet added"},{done:Object.keys(Ge).length>=1,label:"Social connected"},{done:!!de.location,label:"Location set"},{done:!!de.website,label:"Website added"}],t=e.filter(n=>n.done).length;return{pct:Math.round(t/e.length*100),done:t,total:e.length,checks:e}}function ag(){let e=document.getElementById("profile-completeness");if(!e)return;let{pct:t,checks:n}=sg(),s=t===100?"#50fa7b":t>=60?"#00fff0":"#ffb86c",a=2*Math.PI*16,o=t/100*a,i=n.filter(r=>!r.done).map(r=>r.label);e.title=t===100?"Profile complete \u2713":`${t}% \u2014 Missing: ${i.join(", ")}`,e.innerHTML=`
    <div class="pc-wrap">
      <svg class="pc-ring" viewBox="0 0 40 40" width="34" height="34">
        <circle cx="20" cy="20" r="16" fill="none" stroke="rgba(255,255,255,.07)" stroke-width="3.5"/>
        <circle cx="20" cy="20" r="16" fill="none" stroke="${s}" stroke-width="3.5"
          stroke-dasharray="${o.toFixed(1)} ${a.toFixed(1)}"
          stroke-linecap="round" transform="rotate(-90 20 20)"
          style="transition:stroke-dasharray .7s cubic-bezier(.4,0,.2,1)"/>
        <text x="20" y="24" text-anchor="middle" font-size="9" font-weight="900"
          fill="${s}" font-family="JetBrains Mono,monospace">${t}%</text>
      </svg>
    </div>`}function og(e,t,n=2,s=700){if(!e)return;let a=performance.now(),o=parseFloat(e.textContent.replace(/[^0-9.]/g,""))||0;if(Math.abs(t-o)<.001){e.textContent=_(t,n);return}let i=r=>{let l=Math.min((r-a)/s,1),c=l<.5?2*l*l:-1+(4-2*l)*l;e.textContent=_(o+(t-o)*c,n),l<1?requestAnimationFrame(i):e.textContent=_(t,n)};requestAnimationFrame(i)}window._profileSetTokenSearch=e=>{let t=e.toLowerCase();document.querySelectorAll(".wdd-token-row").forEach(n=>{n.style.display=n.textContent.toLowerCase().includes(t)?"":"none"})};function Ma(e,t){let n=x(e);n&&(n.textContent=String(t))}function Hs(e){Ia(e)}function Ia(e,t=0){var a;if(!!((a=navigator.clipboard)!=null&&a.writeText)&&document.hasFocus()){navigator.clipboard.writeText(e).then(()=>{ae("Copied to clipboard"),t&&setTimeout(()=>{var o;document.hasFocus()&&((o=navigator.clipboard)!=null&&o.writeText)&&navigator.clipboard.writeText("").catch(()=>{})},t)}).catch(()=>{let o=document.createElement("textarea");o.value=e,document.body.appendChild(o),o.select(),document.execCommand("copy"),o.remove(),ae("Copied")});return}let s=document.createElement("textarea");s.value=e,document.body.appendChild(s),s.select(),document.execCommand("copy"),s.remove(),ae("Copied")}function ki(e){if(!/^[0-9A-Fa-f]+$/.test(e))return"";try{let t="";for(let n=0;n<e.length;n+=2)t+=String.fromCharCode(parseInt(e.slice(n,n+2),16));return t.replace(/\x00/g,"").trim()}catch{return""}}var ig=[{cat:"App",term:"Live Stream",body:"A real-time feed of the XRP Ledger as it closes \u2014 new ledgers, transaction volume, and network metrics as they happen. No refresh needed."},{cat:"App",term:"Inspector",body:"Full forensic analysis of any XRPL address, yours or anyone else's: trust lines, fund flow tracking, and a multi-engine Forensic Analytics Suite that looks for non-organic behavior patterns."},{cat:"App",term:"Network Health",body:"Live validator and node health \u2014 latency probing across public XRPL endpoints, so you can see which server is actually fastest to connect to right now."},{cat:"App",term:"Project Intelligence",body:"Token-level analysis for any issued asset: liquidity depth (AMM + live order book), holder concentration, LP token concentration, and issuer risk flags, rolled into one inspectable Strength score."},{cat:"App",term:"Portfolio Analytics",body:"Balance history, an activity heatmap, and fund-flow breakdowns for your own wallets \u2014 under Profile."},{cat:"App",term:"Command Palette (Ctrl+K)",body:"Press Ctrl+K (or /) from anywhere to jump to any page instantly. Paste in an XRPL address and it offers to inspect it directly, without navigating first."},{cat:"App",term:"Wallet Vault",body:"Your keys are encrypted client-side with AES-256-GCM (PBKDF2, 150,000 iterations) and never leave your device. There is no server that could be breached to expose them \u2014 which also means there's no password reset if you forget your vault password without a backup."},{cat:"On-Chain",term:"Trustline",body:"A trustline is what lets an account hold a token that isn't XRP. You must explicitly create one to a token's issuer before you can receive that token \u2014 this is an XRPL-specific safeguard against unwanted tokens landing in your wallet."},{cat:"On-Chain",term:"AMM / Liquidity Pool",body:"An Automated Market Maker pool holds reserves of two assets (e.g. XRP and a token) and prices trades algorithmically based on the ratio between them. Deeper reserves generally mean less price impact per trade."},{cat:"On-Chain",term:"Order Book Depth / Slippage",body:"How much of an asset is actually available to buy or sell at each price level on the live DEX order book. Thin depth means a modest-sized trade can move the price a lot \u2014 that price movement is slippage."},{cat:"On-Chain",term:"Holder Concentration",body:"What percentage of a token's total supply sits in the top 1, 5, or 10 wallets. High concentration means a small number of holders could crash the price by selling \u2014 a common signal used to spot rug-pull risk."},{cat:"On-Chain",term:"LP Token Concentration",body:`AMM pools issue their own "LP tokens" representing a share of the pool. If a handful of addresses hold most of the LP tokens, they can pull most of the pool's liquidity out at once, collapsing tradability.`},{cat:"On-Chain",term:"Issuer",body:`The XRPL account that created a token and controls certain settings on it (freeze, clawback, auth requirements). Every issued token has exactly one issuer address \u2014 it's effectively that token's "admin account."`},{cat:"On-Chain",term:"Clawback",body:xt.clawbackEnabled},{cat:"On-Chain",term:"Global Freeze",body:xt.globalFreeze},{cat:"On-Chain",term:"Freeze-Capable",body:xt.freezeCapable},{cat:"On-Chain",term:"Require Auth",body:xt.requireAuth},{cat:"On-Chain",term:"Blackholed / Black Hole Address",body:xt.blackholed},{cat:"On-Chain",term:"Fund Flow",body:"Where XRP actually goes after leaving a wallet \u2014 tracing outbound payments to their destinations, flagging known exchanges, black-hole addresses, and brand-new wallets receiving large transfers (a common drain-attack pattern)."},{cat:"On-Chain",term:"Convergence Signal",body:`The Forensic Analytics Suite runs several independent detection engines. When two or more flag the same address using unrelated methods, that agreement ("convergence") is a stronger signal than any single engine alone \u2014 a single flag can be a false positive, convergence usually isn't.`}],Fa="";function lp(){let e=x("helpOverlay"),t=x("helpInput");!e||!t||(e.classList.add("show"),Fa="",t.value="",dp(),t.focus())}function Oa(){var e;(e=x("helpOverlay"))==null||e.classList.remove("show")}function $i(e){Fa=e,dp()}function cp(){let e=x("helpOverlay"),t=x("helpInput");!e||!t||(t.addEventListener("input",()=>$i(t.value)),e.addEventListener("click",n=>{n.target===e&&Oa()}))}function rg(e,t){return t?`${e.term} ${e.body}`.toLowerCase().includes(t):!0}function dp(){let e=x("helpList");if(!e)return;let t=Fa.toLowerCase().trim(),n=ig.filter(o=>rg(o,t));if(!n.length){e.innerHTML=`<div class="help-empty">No matches for "${y(Fa)}".</div>`;return}let s=["App","On-Chain"],a={App:"App Features","On-Chain":"On-Chain & Forensic Concepts"};e.innerHTML=s.map(o=>{let i=n.filter(r=>r.cat===o);return i.length?`
      <div class="help-cat-label">${y(a[o])}</div>
      ${i.map(r=>`
        <div class="help-entry">
          <div class="help-term">${y(r.term)}</div>
          <div class="help-body">${y(r.body)}</div>
        </div>`).join("")}`:""}).join("")}var lg=180,Yt=12,pp=5,up="naluxrp_compact_mode",cg=1e5,dg=18,Si=16,pg=96,mp=96,ug=96,mg=5*6e4,Ba=72,fp=80,fg=1e4,hg=20,Ks=8,Wp=3,Up=.7,Li=.35,Ua=12,fs=10,hs=2,ls=61e3,mn="NALU-SPAM-PROOF:",jp="naluxrp_spam_verified",qp="naluxrp_spam_allowlist",Vp=new Set(["rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy","rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B","rrpNnNLKrartuEqfJGpqyDwPj1BBN1ih7","rN7n3473SaZBCG4dFL83w7PB9judJ7qdDo","rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh","rBKPS4oLSaV2KVVuHH8EpQqMGgGefGFQs7","rfk5bwaKCoNU84fTzdqWQowqnNaZorDmiV","rGFuMiw48HdbnrUbkRYDTvT5i9imC5fvv9","rwYHCs2EYBMBvRXFmxDrCUSorPsuqCck7t","rLHzPsX6oXkzU2qL12kHCH8G8cnZv1rBJh","ra5nK24KXen9AHvsdFTKHSANinZseWnPcX","rGWrZyax5eXbi5gs49MRZKkE9eKNL9p4B","rHsMUQFzBb7S6GnQFVgNirqvHRcLpAn5dU","rDsbeomae4FXwgQTJp9Rs64Qg9vDiTCdBv","rMQ98K56yXJbDGv49ZSmW51sLn94Xe1mu1","rKiCet8SdvWxPXnAgYarFUXMh1zCPz432Y","r9mhdcT2K7FdCGDEPqfbMJwVXsXCqEr5bP","r4GDFMLGJUKMjNEycBKPGnRSNXyNVLQLHi","rUA1S9qobBkxLqzdfGEzh5wm5KdLfbf8bx","rHtbQzmN4BDaEBnGSXp3AZaZAuZamNVsME","rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq","razqnFn6FqBaYBdNaGnVzmGaNE6XPRQ9bG","rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh","r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59","rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY","rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz"]),fe={dexPressure:[],nftMints:[],nftBurns:[],autoBridge:[],marketPrice:[],marketVol:[]},un=null,Ti=0,Nt={acct:new Map},Us={window:[],totals:new Map,maxLedgers:12},Ee={window:[],smoothCancelPerMin:null,smoothBurst:null},le={byAddr:new Map,selectedAddr:null,selectedProof:null,allowList:new Set,verifiedCache:new Map},hp=!1,gp=!1,vp=!1,Mi=!1,bp=!1,yp=!1,wp=!1,xp=!1,kp=!1,$p=!1,Sp=!1,Tp=!1,Cp=!1,Pp=!1,Lp=!1,Mp=!1,Ap=!1,Ep=!1,On=!1,qs=!1,Ai={};var Ei=new Map;function Xa(e,t,n=2){let s=Ei.get(e)??-999;return Number(t)-s<n?!1:(Ei.set(e,Number(t)),!0)}var Qe={ledgersProcessed:0,startTime:Date.now(),totalTx:0,whaleCount:0,feeSpikes:0,botDetections:0,dexAlerts:0},_t=[],gg=40,Bn={whaleTxXrp:1e5,feeSpikeMultiple:5,botCvThreshold:.2,dexCancelAlert:.75,clusterMinSize:5},Gp=0,Va="naluxrp_widget_order",gs="naluxrp_widget_hidden",os=null,Vt=!1,Np=!1,Kp=!0;function Jt(){return Kp&&B.currentPage==="dashboard"&&B.currentTab==="stream"&&!document.hidden}var cs=[],vg=30,bg=0;function Jp(){Pg(),Mg(),bv(),xv(),_g(),Bg(),cv(),dv(),Dg(),kg(),$g(),Rv(),pv(),fv(),gv(),Fv(),Bv(),Hv(),Jt()&&Ja(),Gv(),Kv(),Uv(),Jv(),Yv(),Qv(),window.addEventListener("xrpl-connection",e=>{var n,s;let t=!!((n=e==null?void 0:e.detail)!=null&&n.connected);if(t&&Wg(),((s=e==null?void 0:e.detail)==null?void 0:s.state)==="connecting"){Ka(!0,"Switching networks\u2026");let a=x("tx-mix");a&&(a.innerHTML='<div class="loading-row"><div class="spinner"></div> Accumulating\u2026</div>')}else t&&Ka(!1)}),window.addEventListener("xrpl-ledger",e=>{if(!Jt())return;let t=e.detail,n=Number(t.ledgerIndex||0);Qe.ledgersProcessed++,Qe.totalTx+=Number(t.txPerLedger||0),["risk-badge","risk-regime","risk-friction","risk-signalcount","landscape-badge","dexp-badge","dexP-badge","ab-badge","nft-badge","whale-badge","ss-badge","health-badge","pattern-badge"].forEach(a=>delete Ai[a]),Ag(t),Ig(),Rg(),Fg(),jg(t.latestLedger),Iv(t.recentTransactions||[],n);let s=Kg(t);for(cs.push({li:n,friction:s.friction,regime:s.regime});cs.length>vg;)cs.shift();cu(),!Vt&&(Xa("breadcrumbs",n,1)&&iv(s.breadcrumbs),Xa("clusters",n,2)&&rv(s.clusters),Xa("narratives",n,2)&&lv(s.narratives),Xa("landscape",n,3)&&uv(s),_v(t.txTypes,s.hhi),hv(s.dexPatterns),vv(s),wv(s),$v(s),zv(),n-Gp>=8&&Wv(s,n))}),document.addEventListener("visibilitychange",()=>{Jt()?Ja():Oi()})}function Yp(e){Kp=!!e,Jt()?Ja():Oi()}function V(e,t){let n=x(e);n&&(n.textContent=String(t))}function ke(e,t,n){return Math.max(t,Math.min(n,e))}function gn(e){return e!=null&&e.length?e.reduce((t,n)=>t+n,0)/e.length:null}function Fi(e){if(!e||e.length<2)return null;let t=gn(e),n=gn(e.map(s=>(s-t)**2));return Math.sqrt(n)}function yg(e,t){return e!=null&&e.length?e.slice(Math.max(0,e.length-t)):[]}function wg(e,t){let n=[];for(let s=0;s<e.length;s++){let a=Math.max(0,s-t+1);n.push(gn(e.slice(a,s+1)))}return n}function vn(e,t=0){return e==null||!Number.isFinite(e)?"\u2014":`${e>=0?"\u2191":"\u2193"}${Math.abs(e).toFixed(t)}%`}function is(e,t=2){return e==null||!Number.isFinite(e)?"\u2014":Number(e).toFixed(t)}function fn(e){if(e==null||!Number.isFinite(e))return"\u2014";let t=Number(e);return t===0?"0 XRP":t>=1e3?`${t.toLocaleString(void 0,{maximumFractionDigits:2})} XRP`:t>=1?`${t.toFixed(4)} XRP`:t>=.01?`${t.toFixed(5)} XRP`:`${t.toFixed(6)} XRP`}function ds(e,t=1){if(!e)return null;let n=ke(Number(t),0,1),s=String(e).trim();if(s.startsWith("rgba("))return s;if(s.startsWith("rgb(")){let a=s.match(/^rgb\(\s*([0-9]+)\s*,\s*([0-9]+)\s*,\s*([0-9]+)\s*\)$/i);if(!a)return null;let o=ke(Number(a[1]),0,255),i=ke(Number(a[2]),0,255),r=ke(Number(a[3]),0,255);return`rgba(${o},${i},${r},${n})`}if(s[0]==="#"){let a=s.slice(1);if(a.length===3&&(a=a.split("").map(l=>l+l).join("")),a.length!==6)return null;let o=parseInt(a.slice(0,2),16),i=parseInt(a.slice(2,4),16),r=parseInt(a.slice(4,6),16);return[o,i,r].every(Number.isFinite)?`rgba(${o},${i},${r},${n})`:null}return null}function Rp(e,t,n=.45){return t==null||!Number.isFinite(t)?e:e==null||!Number.isFinite(e)?t:e*(1-n)+t*n}async function xg(e){if(typeof crypto<"u"&&crypto.subtle){let n=new TextEncoder().encode(e),s=await crypto.subtle.digest("SHA-512",n),a=new Uint8Array(s,0,32);return Array.from(a).map(o=>o.toString(16).padStart(2,"0")).join("")}let t=0x811c9dc5n;for(let n=0;n<e.length;n++)t^=BigInt(e.charCodeAt(n)),t=BigInt.asUintN(32,t*0x01000193n);return"FALLBACK-NON-CRYPTO-"+t.toString(16).padStart(8,"0").repeat(4).slice(0,44)}function kg(){var n,s;if(Tp||(Tp=!0,document.getElementById("acctPeekOverlay")))return;let e=document.createElement("div");e.id="acctPeekOverlay",e.className="acct-peek-overlay",e.style.display="none",e.innerHTML=`
    <div class="acct-peek-box" role="dialog" aria-modal="true" aria-label="Account details">
      <button class="acct-peek-close" id="acctPeekClose" aria-label="Close">\u2715</button>

      <div class="acct-peek-head">
        <div style="min-width:0">
          <div class="acct-peek-title">Account</div>
          <div class="acct-peek-addr mono cut" id="acctPeekAddr">\u2014</div>
        </div>
        <button class="acct-peek-inspect" id="acctPeekInspect">Open in Inspector \u2192</button>
      </div>

      <div class="acct-peek-grid">
        <div class="acct-peek-stat"><span>Balance</span><b id="acctPeekBal">\u2014</b></div>
        <div class="acct-peek-stat"><span>Sequence</span><b id="acctPeekSeq">\u2014</b></div>
        <div class="acct-peek-stat"><span>OwnerCount</span><b id="acctPeekOwner">\u2014</b></div>
        <div class="acct-peek-stat"><span>Flags</span><b id="acctPeekFlags">\u2014</b></div>
      </div>

      <div class="acct-peek-section">
        <div class="acct-peek-h">Plain-English note</div>
        <div class="acct-peek-note" id="acctPeekNote">\u2014</div>
      </div>

      <div class="acct-peek-section">
        <div class="acct-peek-h">Recent context</div>
        <div class="acct-peek-note" id="acctPeekCtx">\u2014</div>
      </div>
    </div>
  `,document.body.appendChild(e);let t=()=>{e.style.display="none",e.removeAttribute("data-addr"),document.body.classList.remove("modal-open"),qs=!1,Rt=!1};e.addEventListener("click",a=>{a.target===e&&t()}),(n=x("acctPeekClose"))==null||n.addEventListener("click",t),(s=x("acctPeekInspect"))==null||s.addEventListener("click",async()=>{let a=e.getAttribute("data-addr");a&&await Cg(a),t()})}function $g(){Sp||(Sp=!0,document.addEventListener("click",e=>{var s,a;let t=(a=(s=e.target).closest)==null?void 0:a.call(s,"[data-addr]");if(!t)return;let n=t.getAttribute("data-addr");n&&(e.preventDefault(),Tg(n))}))}function _p(e){var r,l,c;if(!e||!((r=Ee==null?void 0:Ee.window)!=null&&r.length))return null;let t=0,n=0,s=0;for(let d of Ee.window)s+=Number(d.total||0),t+=Number(((l=d.byActorCreate)==null?void 0:l.get(e))||0),n+=Number(((c=d.byActorCancel)==null?void 0:c.get(e))||0);let a=t+n;if(!a)return null;let o=a?n/a:0,i=s?a/s:null;return{create:t,cancel:n,total:a,cancelRatio:o,share:i}}function Sg(e){var o;let t=(o=Nt==null?void 0:Nt.acct)==null?void 0:o.get(e);if(!t||!t.intervals||t.intervals.length<6)return null;let n=gn(t.intervals),s=Fi(t.intervals);return!n||s==null?null:{cv:s/n,total:t.total||0}}async function Tg(e){var i,r,l;if(!Xe(e))return;let t=document.getElementById("acctPeekOverlay");if(!t)return;t.style.display="flex",t.setAttribute("data-addr",e),document.body.classList.add("modal-open"),qs=!0,Rt=!0,V("acctPeekAddr",e),V("acctPeekBal","\u2026"),V("acctPeekSeq","\u2026"),V("acctPeekOwner","\u2026"),V("acctPeekFlags","\u2026");let n=x("acctPeekNote"),s=x("acctPeekCtx");n&&(n.textContent="Fetching account_info\u2026"),s&&(s.textContent="Building context\u2026");let a=Nt.acct.get(e),o=((i=a==null?void 0:a.ledgers)==null?void 0:i.length)||0;try{if(!B.wsConn||B.wsConn.readyState!==1){n&&(n.textContent="Not connected to XRPL. Connect first.");return}let c=await Me({command:"account_info",account:e,ledger_index:"validated",strict:!0}),d=(r=c==null?void 0:c.result)==null?void 0:r.account_data,u=Number((d==null?void 0:d.Balance)??NaN),p=Number.isFinite(u)?u/1e6:null;if(V("acctPeekBal",p==null?"\u2014":`${p.toLocaleString(void 0,{maximumFractionDigits:6})} XRP`),V("acctPeekSeq",(d==null?void 0:d.Sequence)??"\u2014"),V("acctPeekOwner",(d==null?void 0:d.OwnerCount)??"\u2014"),V("acctPeekFlags",(d==null?void 0:d.Flags)!=null?`0x${Number(d.Flags).toString(16)}`:"\u2014"),n){let m=[];p!=null&&p>=cg&&m.push("Large balance (whale-sized).");let f=Sg(e);f&&f.cv<.35&&f.total>10&&m.push(`Bot-like timing signal (CV ${f.cv.toFixed(2)}).`);let g=_p(e);if(g){let h=Math.round(g.cancelRatio*100),v=g.share!=null?Math.round(g.share*100):null;m.push(`DEX activity: ${g.total} offer tx in window.`),m.push(`Creates ${g.create}, cancels ${g.cancel} (${h}% cancels).`),v!=null&&m.push(`~${v}% of window activity.`)}let b=le.byAddr.get(e);if(b){let h=Vs(b.level);m.push(`Spam-defense: score ${(b.score*100).toFixed(0)}% \xB7 level L${b.level} \xB7 bond ${h.toLocaleString()} XRP.`),b.verifiedLedger!=null&&m.push(`Credential verified at ledger #${Number(b.verifiedLedger).toLocaleString()}.`)}o>=6&&m.push(`Shows up often in recent ledgers (${o} times).`),m.length||m.push("No obvious red flags from this quick read."),n.textContent=m.join(" ")}if(s){let m=(l=a==null?void 0:a.ledgers)==null?void 0:l.at(-1),f=_p(e),g=f?`DEX window: ${f.total} (creates ${f.create}, cancels ${f.cancel})`:null,b=_t.filter(k=>k.from===e||k.to===e).slice(0,3),h=b.length?`${b.length} whale tx in session (${b.map(k=>(k.amtXrp>=1e6?(k.amtXrp/1e6).toFixed(1)+"M":(k.amtXrp/1e3).toFixed(0)+"K")+" XRP").join(", ")})`:null,v=le.byAddr.get(e),w=v?`Spam-defense: L${v.level} \xB7 score ${Math.round(v.score*100)}%`:null;s.textContent=[m?`Last seen around ledger #${Number(m).toLocaleString()}`:"Not in recent window.",g,h,w].filter(Boolean).join(" \xB7 ")}}catch(c){n&&(n.textContent=`Lookup failed: ${String((c==null?void 0:c.message)||c)}`),s&&(s.textContent="\u2014")}}async function Cg(e){if(!Xe(e))return;let t=document.querySelector('.dash-tab[data-tab="inspector"]'),n=document.getElementById("tab-inspector"),s=async()=>n&&n.style.display!=="none"?!0:(typeof window.switchTab=="function"&&t?window.switchTab(t,"inspector"):t==null||t.click(),await new Promise(o=>setTimeout(o,80)),n?n.style.display!=="none":!0);for(let o=0;o<6&&!await s();o++)await new Promise(r=>setTimeout(r,80));let a=document.getElementById("inspect-addr");a&&(a.value=e,a.focus()),await new Promise(o=>setTimeout(o,60)),typeof window.runInspect=="function"?window.runInspect():ge("Inspector not ready yet.")}function Pg(){Be(".net-btn[data-network]").forEach(e=>{e.addEventListener("click",()=>{let t=e.getAttribute("data-network");Be(".net-btn").forEach(s=>{s.classList.toggle("active",s===e),s.setAttribute("aria-pressed",String(s===e))}),Nt.acct.clear(),Us.window=[],Us.totals=new Map,Ee.window=[],Ee.smoothCancelPerMin=null,Ee.smoothBurst=null,Xt.length=0,qa.clear(),je=0,Gt=0,pt=0,Ws=0,Kt=!0,Ga=0,Ri=!1,js=null,Rt=!1,hn=0,ps=0,Ya=!1;let n=x("ledgerStreamTrack");n&&(n.innerHTML="",n.style.transform="translateX(0px)"),nu(null,null),yv(),le.byAddr.clear(),le.selectedAddr=null,le.selectedProof=null,Bi(),ru(),ms(null),Rr(t),Ja({force:!0})})})}var ja=[],Lg=8,Ci=null,Ni=0,zs=null;function Mg(){let e=document.querySelector(".dashboard-metric-grid");if(!e)return;let t=e.closest(".dashboard-metrics")||e.parentElement;t&&t.classList.add("dashboard-sticky-strip"),e.innerHTML=`
    <article class="metric-card mc-ledger">
      <div class="mc-label">Ledger Index</div>
      <div class="mc-value mono" id="d2-ledger-index">\u2014</div>
      <div class="mc-sparkline-row">
        <canvas id="d2-close-sparkline" class="mc-sparkline" width="88" height="22" title="Close time history (last 8 ledgers)"></canvas>
        <span class="mc-sub mc-age-timer" id="d2-ledger-age-timer">\u2014</span>
      </div>
      <div class="mc-sub" id="d2-ledger-age">\u2014</div>
    </article>

    <article class="metric-card mc-tps">
      <div class="mc-label">TX / Second</div>
      <div class="mc-value" id="d2-tps">\u2014</div>
      <div class="mc-sub" id="d2-tps-trend">Waiting\u2026</div>
    </article>

    <article class="metric-card mc-tpl">
      <div class="mc-label">TX / Ledger</div>
      <div class="mc-value" id="d2-tx-per-ledger">\u2014</div>
      <div class="mc-sub" id="d2-tx-spread">Waiting\u2026</div>
    </article>

    <article class="metric-card mc-fee">
      <div class="mc-label">Avg Fee</div>
      <div class="mc-fee-row">
        <span class="mc-value mono" id="d2-fee-value">\u2014</span>
        <span class="mc-fee-delta" id="d2-fee-delta" aria-label="Fee trend"></span>
      </div>
      <div class="mc-sub" id="d2-fee-pressure">Waiting\u2026</div>
    </article>

    <article class="metric-card mc-sr">
      <div class="mc-label">Success Rate</div>
      <div class="mc-value" id="d2-success-rate">\u2014</div>
      <div class="mc-sub" id="d2-success-note">Waiting\u2026</div>
    </article>

    <article class="metric-card mc-load">
      <div class="mc-label">Network Load</div>
      <div class="mc-value" id="d2-network-capacity">\u2014</div>
      <div class="mc-sub" id="d2-capacity-note">Waiting\u2026</div>
    </article>

    <article class="metric-card mc-dom">
      <div class="mc-label">Dominant TX</div>
      <div class="mc-value" id="d2-dominant-type">\u2014</div>
      <div class="mc-sub" id="d2-dominance-score">Waiting\u2026</div>
    </article>
  `}function Ag(e){var g,b,h,v;let t=e.ledgerIndex?Number(e.ledgerIndex):null;V("d2-ledger-index",t?t.toLocaleString():"\u2014");let n=((g=e.latestLedger)==null?void 0:g.closeTimeSec)!=null?Number(e.latestLedger.closeTimeSec):null,s=x("d2-ledger-age");if(s&&(n!=null?(s.textContent=`${n<2?n.toFixed(2):n.toFixed(1)}s close`,s.style.color=n<=3?"#50fa7b":n<=6?"#ffb86c":"#ff6e6e"):(s.textContent="Waiting\u2026",s.style.color="")),n!=null&&(ja.push(n),ja.length>Lg&&ja.shift(),Eg()),Ni=Date.now(),Ng(),e.tps!=null){let w=Number(e.tps),k=x("d2-tps");k&&(k.textContent=w.toFixed(1),k.style.color=w<10?"rgba(255,255,255,.65)":w<40?"#50fa7b":w<80?"#ffb86c":"#ff6e6e");let $=x("d2-tps-trend");if($){let T=B.tpsHistory||[],S=T.length>2?(T.slice(-10).reduce((C,E)=>C+E,0)/Math.min(T.length,10)).toFixed(1):null,M=w<10?"Low":w<40?"Normal":w<80?"High":"Peak";$.textContent=S?`${M} \xB7 avg ${S}`:M,$.style.color=w<10?"rgba(255,255,255,.55)":w<40?"#50fa7b":w<80?"#ffb86c":"#ff6e6e"}}let a=(((b=e.latestLedger)==null?void 0:b.totalTx)??e.txPerLedger)||0,o=x("d2-tx-per-ledger");o&&(o.textContent=a>0?a.toLocaleString():"\u2014",o.style.color=a<10?"rgba(255,255,255,.65)":a<150?"#50fa7b":a<400?"#ffb86c":"#ff6e6e");let i=x("d2-tx-spread");i&&a>0&&(i.textContent=a<10?"Very light":a<50?"Light":a<150?"Normal":a<400?"High volume":"Very high volume",i.style.color=a<150?"":a<400?"#ffb86c":"#ff6e6e");let r=e.avgFee!=null?Number(e.avgFee):((h=e.latestLedger)==null?void 0:h.avgFee)!=null?Number(e.latestLedger.avgFee):null;if(r!=null){let w=Math.round(r*1e6),k=x("d2-fee-value");k&&(k.textContent=fn(r),k.style.color=w<=15?"#50fa7b":w<=50?"rgba(255,255,255,.9)":w<=200?"#ffb86c":"#ff6e6e");let $=x("d2-fee-delta");if($)if(Ci!=null){let S=r/Ci;S>1.05?($.textContent="\u2191",$.style.color="#ff6e6e",$.title=`+${((S-1)*100).toFixed(0)}% vs prev ledger`):S<.95?($.textContent="\u2193",$.style.color="#50fa7b",$.title=`-${((1-S)*100).toFixed(0)}% vs prev ledger`):($.textContent="\u2192",$.style.color="rgba(255,255,255,.35)",$.title="Stable vs prev ledger")}else $.textContent="";Ci=r;let T=x("d2-fee-pressure");if(T){let S=w<=15?"Base fee":w<=50?`${w} drops`:w<=200?`${w} drops \xB7 Elevated`:`${w} drops \xB7 Surge`;T.textContent=S,T.style.color=w<=50?"":w<=200?"#ffb86c":"#ff6e6e"}}let l=e.successRate!=null?Number(e.successRate):((v=e.latestLedger)==null?void 0:v.successRate)!=null?Number(e.latestLedger.successRate):null;if(l!=null){let w=x("d2-success-rate");w&&(w.textContent=`${l.toFixed(1)}%`,w.style.color=l>=90?"#50fa7b":l>=75?"#ffb86c":"#ff6e6e");let k=x("d2-success-note");if(k){let $=(100-l).toFixed(1);k.textContent=l>=90?`${$}% failed \xB7 Normal`:l>=75?`${$}% failed \xB7 Watch`:`${$}% failed \xB7 Alert`,k.style.color=l>=90?"":l>=75?"#ffb86c":"#ff6e6e"}}let c=a>0?Math.min(100,a/500*100):null,d=x("d2-network-capacity"),u=x("d2-capacity-note");c!=null&&(d&&(d.textContent=`${c.toFixed(1)}%`,d.style.color=c<20?"rgba(255,255,255,.65)":c<50?"#50fa7b":c<80?"#ffb86c":"#ff6e6e"),u&&(u.textContent=c<20?"Low usage":c<50?"Moderate":c<80?"Heavy":"Near capacity",u.style.color=c<50?"":c<80?"#ffb86c":"#ff6e6e"));let p=e.txTypes||{},m=Object.entries(p).sort(([,w],[,k])=>k-w);if(m.length){let[w,k]=m[0],$=m.reduce((E,[,R])=>E+R,0)||1,T=(k/$*100).toFixed(0),S=typeof It<"u"?It:{},M=x("d2-dominant-type");M&&(M.textContent=w,M.style.color=S[w]||"rgba(255,255,255,.9)");let C=x("d2-dominance-score");if(C){let E=m[1];C.textContent=E?`${T}% \xB7 2nd: ${E[0]}`:`${T}% of txs`}}let f=x("stream-loading");f&&(f.style.display="none")}function Eg(){let e=x("d2-close-sparkline");if(!e||!e.getContext)return;let t=ja;if(t.length<2)return;let n=e.width,s=e.height,a=e.getContext("2d");a.clearRect(0,0,n,s);let o=Math.max(...t,4),i=Math.floor((n-(t.length-1))/t.length),r=1;t.forEach((l,c)=>{let d=Math.max(3,Math.round(l/o*(s-2))),u=c*(i+r),p=s-d,m=l<=3?"rgba(80,250,123,.80)":l<=6?"rgba(255,184,108,.80)":"rgba(255,110,110,.85)";a.fillStyle=m;let f=Math.min(2,i/2);a.beginPath(),a.moveTo(u+f,p),a.lineTo(u+i-f,p),a.quadraticCurveTo(u+i,p,u+i,p+f),a.lineTo(u+i,s),a.lineTo(u,s),a.lineTo(u,p+f),a.quadraticCurveTo(u,p,u+f,p),a.closePath(),a.fill(),c===t.length-1&&(a.fillStyle="rgba(255,255,255,.18)",a.fillRect(u,p,i,Math.min(3,d)))})}function Ng(){if(zs&&cancelAnimationFrame(zs),!Jt())return;let e=0,t=n=>{if(!Jt()){zs=null;return}if(n-e>=120){e=n;let s=x("d2-ledger-age-timer");if(s&&Ni>0){let a=(Date.now()-Ni)/1e3;s.textContent=`${a.toFixed(1)}s ago`,s.style.color=a<4?"rgba(255,255,255,.55)":a<7?"#ffb86c":"#ff6e6e",s.style.opacity=a>=7?(.6+.4*Math.sin(Date.now()/300)).toFixed(2):"1"}}zs=requestAnimationFrame(t)};zs=requestAnimationFrame(t)}function Rg(){let e=x("tx-mix");if(!e)return;let t=Object.entries(B.txMixAccum||{}).filter(([,s])=>s>0).sort(([,s],[,a])=>a-s).slice(0,10),n=t.reduce((s,[,a])=>s+a,0);n&&(e.innerHTML=t.map(([s,a])=>{let o=(a/n*100).toFixed(1),i=It[s]||"#6b7280";return`
      <div class="tx-mix-row">
        <span class="tx-mix-label">${y(s)}</span>
        <div class="tx-mix-bar">
          <div class="tx-mix-fill" style="width:${o}%;background:${i}"></div>
        </div>
        <span class="tx-mix-pct">${o}%</span>
      </div>`}).join(""))}var St=class{constructor(t,n="#00fff0",s="area"){this.canvasId=t,this.canvas=x(t),this.color=n,this.mode=s}_resolveCanvas(){return this.canvas||(this.canvas=x(this.canvasId)),this.canvas}draw(t){let n=this._resolveCanvas();if(!n||!(t!=null&&t.length))return;let s=n.getContext("2d");if(!s)return;let a=n.width=n.offsetWidth||300,o=n.height=n.offsetHeight||180;if(s.clearRect(0,0,a,o),t.length<2)return;let i=Math.min(...t)*.9,r=Math.max(...t)*1.05||1,l=b=>1-(b-i)/(r-i||1),c={l:10,r:10,t:10,b:12},d=a-c.l-c.r,u=o-c.t-c.b,p=d/(t.length-1),m=t.map((b,h)=>[c.l+h*p,c.t+l(b)*u]),f=gn(t);if(f!=null){let b=c.t+l(f)*u;s.beginPath(),s.moveTo(c.l,b),s.lineTo(c.l+d,b),s.strokeStyle="rgba(255,255,255,0.16)",s.lineWidth=1,s.stroke()}if(t.length>=pp+2){let h=wg(t,pp).map((v,w)=>[c.l+w*p,c.t+l(v)*u]);s.beginPath(),h.forEach(([v,w],k)=>k===0?s.moveTo(v,w):s.lineTo(v,w)),s.strokeStyle="rgba(255,255,255,0.22)",s.lineWidth=1.5,s.stroke()}if(this.mode==="bar"){let b=Math.max(1,p-3);t.forEach((h,v)=>{let w=(1-l(h))*u,k=c.l+v*p-b/2,$=s.createLinearGradient(0,c.t,0,c.t+u);$.addColorStop(0,this.color),$.addColorStop(1,this.color+"33"),s.fillStyle=$,s.fillRect(k,c.t+u-w,b,w)});return}let g=s.createLinearGradient(0,c.t,0,c.t+u);g.addColorStop(0,this.color+"aa"),g.addColorStop(1,this.color+"11"),s.beginPath(),m.forEach(([b,h],v)=>v===0?s.moveTo(b,h):s.lineTo(b,h)),s.lineTo(m.at(-1)[0],c.t+u),s.lineTo(m[0][0],c.t+u),s.closePath(),s.fillStyle=g,s.fill(),s.beginPath(),m.forEach(([b,h],v)=>v===0?s.moveTo(b,h):s.lineTo(b,h)),s.strokeStyle=this.color,s.lineWidth=2,s.lineJoin="round",s.stroke()}},we={};function _g(){we.tps=new St("chart-tps","#50fa7b","area"),we.fee=new St("chart-fee","#ffb86c","area"),we.tps2=new St("chart-tps2","#50fa7b","bar"),we.fee2=new St("chart-fee2","#ffb86c","area"),we.dexPressure=new St("chart-dex-pressure","#00d4ff","bar"),we.nftMints=new St("chart-nft-mints","#bd93f9","bar"),we.nftBurns=new St("chart-nft-burns","#ff5555","bar"),we.autoBridge=new St("chart-autobridge","#f1fa8c","bar"),we.marketPrice=new St("chart-market-price","#50fa7b","area"),we.marketVol=new St("chart-market-vol","#8be9fd","bar")}function Ht(e,t=Yt){let n=yg(e,t).filter(r=>Number.isFinite(r));if(!n.length)return{cur:null,avg:null,deltaPct:null,vol:null};let s=n.at(-1),a=gn(n),o=Fi(n),i=a&&a!==0?(s-a)/a*100:null;return{cur:s,avg:a,deltaPct:i,vol:o}}function Dg(){if(vp)return;vp=!0;let e=(t,n)=>{let s=x(t);if(!s)return;let a=s.closest(".widget-card"),o=a==null?void 0:a.querySelector(".widget-header");if(!o||document.getElementById(n))return;let i=document.createElement("div");i.className="trend-mini",i.id=n,i.innerHTML=`
      <div class="trend-mini-row">
        <div class="trend-mini-cell"><span class="trend-mini-k">Now</span><span class="trend-mini-v" data-k="now">\u2014</span></div>
        <div class="trend-mini-cell"><span class="trend-mini-k">Avg</span><span class="trend-mini-v" data-k="avg">\u2014</span></div>
      </div>
      <div class="trend-mini-row">
        <div class="trend-mini-cell"><span class="trend-mini-k">\u0394</span><span class="trend-mini-v" data-k="delta">\u2014</span></div>
        <div class="trend-mini-cell"><span class="trend-mini-k">\u03C3</span><span class="trend-mini-v" data-k="sigma">\u2014</span></div>
      </div>
    `,o.appendChild(i)};e("chart-tps","tpsTrendMini"),e("chart-fee","feeTrendMini"),e("chart-tps2","tpsTrendMini2"),e("chart-fee2","feeTrendMini2")}function Ha(e,t,n,s){let a=document.getElementById(e);if(!a)return;let o=(i,r)=>{let l=a.querySelector(`[data-k="${i}"]`);l&&(l.textContent=r)};if(t.cur==null){o("now","\u2014"),o("avg","\u2014"),o("delta","\u2014"),o("sigma","\u2014");return}o("now",`${Number(t.cur).toFixed(n)}${s}`),o("avg",t.avg!=null?`${Number(t.avg).toFixed(n)}${s}`:"\u2014"),o("delta",t.deltaPct==null?"\u2014":vn(t.deltaPct,0)),o("sigma",t.vol==null?"\u2014":`${Number(t.vol).toFixed(Math.max(0,n-1))}${s}`)}function Ig(){var n,s,a,o,i,r,l,c,d,u;(n=we.tps)==null||n.draw(B.tpsHistory),(s=we.fee)==null||s.draw(B.feeHistory),(a=we.tps2)==null||a.draw(B.tpsHistory),(o=we.fee2)==null||o.draw(B.feeHistory);let e=Ht(B.tpsHistory,Yt),t=Ht(B.feeHistory,Yt);Ha("tpsTrendMini",e,2,""),Ha("tpsTrendMini2",e,2,""),Ha("feeTrendMini",t,0,"d"),Ha("feeTrendMini2",t,0,"d"),(i=we.dexPressure)==null||i.draw(fe.dexPressure),(r=we.nftMints)==null||r.draw(fe.nftMints),(l=we.nftBurns)==null||l.draw(fe.nftBurns),(c=we.autoBridge)==null||c.draw(fe.autoBridge),(d=we.marketPrice)==null||d.draw(fe.marketPrice),(u=we.marketVol)==null||u.draw(fe.marketVol)}function Fg(){let e=x("ledger-log"),t=x("ledger-log-loading"),n=x("ledger-log-count");if(!e||!(B.ledgerLog||[]).length)return;t&&(t.style.display="none"),n&&(n.textContent=B.ledgerLog.length);let s=x("tab-network");!s||s.style.display==="none"||(e.innerHTML=`<div class="ledger-log-row log-head">
      <span>Ledger</span><span>TXs</span><span>TPS</span><span>Close</span><span>Time</span>
    </div>`+B.ledgerLog.slice(0,60).map(a=>`
      <div class="ledger-log-row">
        <span class="log-index">#${a.ledgerIndex.toLocaleString()}</span>
        <span class="log-tx">${a.txCount}</span>
        <span class="log-tps">${a.tps}</span>
        <span class="log-close">${a.closeTimeSec}s</span>
        <span class="log-time">${a.time}</span>
      </div>`).join(""))}var Xt=[],qa=new Set,je=0,za=null,Ws=0,Gt=0,pt=0,Kt=!0,Wa=0,Rt=!1,Ga=0,Ri=!1,js=null,hn=0,ps=0,Ya=!1,Og=.18;function Bg(){Xg(),Hg()}function Xg(){let e=x("ledgerStreamParticles");if(e){e.innerHTML="";for(let t=0;t<14;t++){let n=document.createElement("div");n.className="ledger-particle",n.style.left=Math.random()*100+"%",n.style.top=20+Math.random()*60+"%",n.style.animationDuration=6+Math.random()*8+"s",n.style.animationDelay=Math.random()*5+"s",e.appendChild(n)}}}function Hg(){if(za)return;let e=x("ledgerStreamShell");e&&(e.addEventListener("mouseenter",()=>{Rt=!0}),e.addEventListener("mouseleave",()=>{qs||(Rt=!1)}));let t=x("ledgerStreamTrack");t&&t.addEventListener("click",s=>{let a=s.target.closest("article.ledger-card");if(!a)return;let o=Number(a.dataset.ledgerIndex);Number.isFinite(o)&&(s.shiftKey?js===o?(js=null,qs||(Rt=!1),Dp()):(js=o,Rt=!0,Dp()):zg(o))});let n=s=>{Ws||(Ws=s);let a=Math.min(.05,(s-Ws)/1e3);Ws=s;let o=Jt()?x("ledgerStreamTrack"):null;if(o&&je>0){if(Kt){let i=o.scrollWidth||0;if(i>100)pt=Math.floor(i/2),Kt=!1,Wa=0,je>0&&(hn=pt/je);else{Wa++,Wa>30&&(Kt=!1,Wa=0),za=requestAnimationFrame(n);return}}if(pt>0&&!Rt&&Ya){let i=Math.min(1,a/Og);Gt+=(ps-Gt)*i,Math.abs(ps-Gt)<.5&&(Gt=ps);let r=Gt%pt;o.style.transform=`translateX(${-r}px)`}if(!Rt&&Math.floor(s/250)!==Math.floor((s-a*1e3)/250)){let i=Date.now(),r=o.querySelectorAll("article.ledger-card[data-arrival-ts]"),l=12e4;r.forEach(c=>{let d=i-Number(c.dataset.arrivalTs||i),u=Math.max(.52,1-d/l*.48);c.style.opacity=u.toFixed(3)})}if(Ga>0){let i=Date.now()-Ga>fg;Ka(i)}}za=requestAnimationFrame(n)};za=requestAnimationFrame(n),window.addEventListener("resize",()=>{Kt=!0})}function Qp(){if(hn<=0||pt<=0||je===0)return Gt;let e=x("ledgerStreamShell"),t=e&&e.offsetWidth||800,n=hn-14,a=(je-1)*hn+n-t+18;a=Math.max(0,a);let i=Math.floor(Gt/pt)*pt+a;return i<Gt-2&&(i+=pt),i}function Ka(e,t){if(e===Ri)return;Ri=e;let n=x("ledgerStreamShell");if(!n)return;let s=n.querySelector(".stream-stall-overlay");e?(s||(s=document.createElement("div"),s.className="stream-stall-overlay",n.appendChild(s)),s.innerHTML=`<span class="stream-stall-dot"></span> ${y(t||"Waiting for ledgers\u2026")}`):s==null||s.remove()}function Dp(){document.querySelectorAll(".ledger-card").forEach(e=>{let t=Number(e.dataset.ledgerIndex);e.classList.toggle("ledger-card--pinned",t===js)})}function zg(e){let t=document.querySelector('.dash-tab[data-tab="inspector"]');typeof window.switchTab=="function"&&t?window.switchTab(t,"inspector"):t==null||t.click();let n=document.getElementById("inspect-addr");n&&(n.placeholder=`Ledger #${e.toLocaleString()} \u2014 paste an address`,n.focus())}function Wg(){var t;let e=x("ledgerStreamShell");e&&(e.classList.remove("stream-reconnect-flash"),e.offsetWidth,e.classList.add("stream-reconnect-flash"),setTimeout(()=>e.classList.remove("stream-reconnect-flash"),1200),bg=((t=cs.at(-1))==null?void 0:t.li)??0,Ug())}function Ug(){let e=document.getElementById("reconnect-banner");if(!e){e=document.createElement("div"),e.id="reconnect-banner",e.className="reconnect-banner";let s=document.querySelector(".dashboard-col-main");s&&s.prepend(e)}e.style.display="",e.innerHTML=`
    <span class="reconnect-dot"></span>
    <span>Reconnected \u2014 rebuilding signal baseline (<span id="reconnect-countdown">3</span> ledgers)</span>
    <button onclick="document.getElementById('reconnect-banner').style.display='none'"
      style="margin-left:auto;background:none;border:none;color:inherit;opacity:.5;cursor:pointer;font-size:.9rem">\u2715</button>`;let t=3,n=setInterval(()=>{let s=document.getElementById("reconnect-countdown");if(s&&(s.textContent=t),t--,t<0){clearInterval(n);let a=document.getElementById("reconnect-banner");a&&(a.style.display="none")}},4e3)}function Ip(){let e=x("ledgerStreamTrack"),t=x("ledgerStreamShell"),n=x("stream-loading");if(!e||!t)return;if(n&&(n.style.display="none"),Xt.length===0){e.innerHTML='<div style="padding:40px;opacity:.6">Waiting for ledgers\u2026</div>',je=0,Kt=!0;return}let s=[...Xt].sort((o,i)=>o.ledgerIndex-i.ledgerIndex),a=s.map((o,i)=>eu(o,{prevIndex:i>0?s[i-1].ledgerIndex:null}));e.innerHTML=a.concat(a).join(""),je=s.length,Kt=!0,requestAnimationFrame(()=>{var i;let o=((i=x("ledgerStreamTrack"))==null?void 0:i.scrollWidth)||0;o>100&&(pt=Math.floor(o/2),hn=je>0?pt/je:0,ps=Qp(),Ya=!0,Kt=!1)})}function jg(e){var f,g;if(!e)return;let t=Number(e.ledgerIndex??NaN);if(!Number.isFinite(t)||qa.has(t))return;qa.add(t),Xt.push(e);let n=0;if(Xt.length>fp){let b=Xt.splice(0,Xt.length-fp);b.forEach(h=>qa.delete(h.ledgerIndex)),n=b.length}Ga=Date.now(),Ka(!1),Vg(e.avgFee!=null?Number(e.avgFee):null);let{auraClass:s,domColor:a}=Gg(e);nu(s,a);let o=x("stream-loading");o&&(o.style.display="none");let i=x("ledgerStreamTrack");if(!i)return;if(je===0){Ip();return}let r=Xt.length>=2?Xt[Xt.length-2].ledgerIndex:0;if(t<r){Ip();return}let l=je,c=eu(e),d=document.createElement("template");d.innerHTML=c;let u=d.content.firstElementChild,p=i.children[l];p?i.insertBefore(u,p):i.appendChild(u);let m=document.createElement("template");if(m.innerHTML=c,i.appendChild(m.content.firstElementChild),je=l+1,n>0){for(let h=0;h<n;h++)(f=i.children[0])==null||f.remove();let b=je-n;for(let h=0;h<n;h++)(g=i.children[b])==null||g.remove();je-=n}Kt=!0,requestAnimationFrame(()=>{hn<=0&&pt>0&&je>0&&(hn=pt/je),ps=Qp(),Ya=!0})}var us=[],qg=20;function Vg(e){e==null||!Number.isFinite(e)||(us.push(e),us.length>qg&&us.shift())}function Zp(){return us.length===0?null:us.reduce((e,t)=>e+t,0)/us.length}function eu(e,t={}){let{ledgerIndex:n,closeTimeSec:s,totalTx:a,txTypes:o,avgFee:i}=e,r=o||{},l=a??0,c=Object.entries(r).sort(([,I],[,D])=>D-I)[0],d=(c==null?void 0:c[0])||"Other",u=tu(d),p=typeof It<"u"?It:{},m=I=>p[I]||"#6b7280",f=m(d),g=ds(f,.45)||f,b=ds(f,.14)||f,h=s==null?"\u2014":s<2?`${Number(s).toFixed(2)}s`:`${Number(s).toFixed(1)}s`,v=l>0&&s>0?(l/s).toFixed(1):null,w=i!=null?Number(i):null,k=w!=null?fn(w):"\u2014",$=Zp(),T=w!=null&&$!=null&&w>$*3,S=t.prevIndex!=null?Number(n)-t.prevIndex-1:0,M=S>0?`<div class="stream-gap-badge" title="${S} ledger(s) missing">\xB7\xB7\xB7&nbsp;${S} gap</div>`:"",C=I=>l>0?`${(I/l*100).toFixed(1)}%`:"0%",E=(I,D,F)=>D?`<div class="ledger-type-row">
      <span class="ledger-type-label cut">${y(I)}</span>
      <div class="ledger-type-bar"><div class="ledger-type-fill" style="width:${C(D)};background:${F}"></div></div>
      <span class="ledger-type-count">${D}</span>
    </div>`:"",R=(r.AMMCreate||0)+(r.AMMDeposit||0)+(r.AMMWithdraw||0)+(r.AMMVote||0),O=Date.now();return`${M}<article class="ledger-card ledger-card--${u} ledger-card--entry${T?" ledger-card--fee-spike":""}"
    data-ledger-index="${Number(n??0)}"
    data-arrival-ts="${O}"
    style="border-color:${g};box-shadow:0 0 22px ${b};flex-shrink:0">
    <div class="ledger-card-inner">
      <div class="ledger-card-header">
        <span class="ledger-id">#${(n||0).toLocaleString()}</span>
        <div class="ledger-meta">
          <span class="ledger-tag cut" style="border-color:${g};color:${f}">${y(d)}</span>
          ${T?'<span class="fee-spike-badge" title="Fee spike: 3\xD7 baseline">\u{1F525}</span>':""}
        </div>
      </div>
      <div class="ledger-main-row">
        <div class="ledger-main-stat"><span class="ledger-stat-label">TXs</span><span class="ledger-stat-value">${l}</span></div>
        <div class="ledger-main-stat"><span class="ledger-stat-label">Close</span><span class="ledger-stat-value">${h}</span></div>
        <div class="ledger-main-stat"><span class="ledger-stat-label">Avg Fee</span><span class="ledger-stat-value${T?" fee-spike-value":""}">${k}</span></div>
        ${v!=null?`<div class="ledger-main-stat"><span class="ledger-stat-label">TPS</span><span class="ledger-stat-value">${v}</span></div>`:""}
      </div>
      <div class="ledger-type-bars">
        ${E("Payment",r.Payment,m("Payment"))}
        ${E("OfferCreate",r.OfferCreate,m("OfferCreate"))}
        ${E("OfferCancel",r.OfferCancel,m("OfferCancel"))}
        ${E("TrustSet",r.TrustSet,m("TrustSet"))}
        ${E("NFT Mint",r.NFTokenMint,m("NFTokenMint"))}
        ${R?E("AMM",R,m("AMMCreate")):""}
        ${E("EscrowCreate",r.EscrowCreate,"#6b7280")}
        ${(r.Other||0)>0?E("Other",r.Other,"#6b7280"):""}
      </div>
    </div>
  </article>`}function tu(e){let t=String(e||"");return t==="Payment"?"payment":t.startsWith("Offer")?"offer":t.startsWith("NFToken")?"nft":t==="TrustSet"?"trust":t.startsWith("AMM")?"amm":"other"}function Gg(e){var o;let n=((o=Object.entries(e.txTypes||{}).sort(([,i],[,r])=>r-i)[0])==null?void 0:o[0])||"Other",s=tu(n),a=It[n]||It.Other||"#6b7280";return{dominantTx:n,auraClass:s,domColor:a}}function nu(e,t){let n=x("ledgerStreamShell");if(!n)return;if(!e||!t){n.style.removeProperty("--streamTintStrong"),n.style.removeProperty("--streamTintSoft"),n.style.removeProperty("--streamTintBorder");return}let s=ds(t,.16)||"rgba(0,255,240,0.14)",a=ds(t,.06)||"rgba(0,255,240,0.06)",o=ds(t,.22)||"rgba(0,255,240,0.22)";n.style.setProperty("--streamTintStrong",s),n.style.setProperty("--streamTintSoft",a),n.style.setProperty("--streamTintBorder",o),n.dataset.tint=e}function Kg(e){var b,h;let t=Array.isArray(e.recentTransactions)?e.recentTransactions.slice(0,lg):[],n=e.txTypes||{},s=Number(e.ledgerIndex||0),a=Object.values(n).reduce((v,w)=>v+w,0)||1,o=0;for(let v of Object.values(n)){let w=v/a;o+=w*w}let i=Jg(t);Yg(Us,i);let r=Qg(Us.totals,i),l=Zg(Us.totals),c=ev(s,t),d=tv(s,(b=e.latestLedger)==null?void 0:b.closeTimeSec,t),u=nv({txs:t,txTypes:n,dexPatterns:d}),p=r.filter(v=>v.count>=2).length,m=sv({hhi:o,repeats:p,dex:d,bots:((h=c.bots)==null?void 0:h.length)||0,advanced:u}),f=av({friction:m,tps:Ht(B.tpsHistory),fee:Ht(B.feeHistory)}),g=ov({s:e,txTypes:n,hhi:o,dexPatterns:d,behavior:c,friction:m,regime:f,breadcrumbs:r,clusters:l,advanced:u});return{s:e,txs:t,txTypes:n,hhi:o,behavior:c,dexPatterns:d,friction:m,regime:f,breadcrumbs:r,clusters:l,narratives:g,advanced:u}}function Jg(e){let t=new Map;for(let n of e){let s=n==null?void 0:n.account,a=n==null?void 0:n.destination;if(!s||!a)continue;let o=`${s}|${a}`;t.set(o,(t.get(o)||0)+1)}return t}function Yg(e,t){e.window.unshift(t);for(let[n,s]of t.entries())e.totals.set(n,(e.totals.get(n)||0)+s);for(;e.window.length>e.maxLedgers;){let n=e.window.pop();for(let[s,a]of n.entries()){let o=(e.totals.get(s)||0)-a;o<=0?e.totals.delete(s):e.totals.set(s,o)}}}function Qg(e,t){let s=[...e.entries()].map(([o,i])=>({k:o,c:i})).sort((o,i)=>i.c-o.c).filter(o=>o.c>=2);return(s.length?s:[...t.entries()].map(([o,i])=>({k:o,c:i}))).slice(0,10).map(({k:o,c:i})=>{let[r,l]=o.split("|");return{from:r,to:l,count:i}})}function Zg(e){let t=[...e.entries()].filter(([,i])=>i>=2),n=t.length?t:[...e.entries()],s=new Map;for(let[i]of n){let[r,l]=i.split("|");!r||!l||(s.has(r)||s.set(r,new Set),s.has(l)||s.set(l,new Set),s.get(r).add(l),s.get(l).add(r))}let a=new Set,o=[];for(let i of s.keys()){if(a.has(i))continue;let r=[i],l=[];for(a.add(i);r.length;){let u=r.pop();l.push(u);for(let p of s.get(u)||[])a.has(p)||(a.add(p),r.push(p))}if(l.length<2)continue;let c=l[0],d=-1;for(let u of l){let p=(s.get(u)||new Set).size;p>d&&(d=p,c=u)}o.push({members:l,size:l.length,hub:c})}return o.sort((i,r)=>r.size-i.size),o.slice(0,6)}function ev(e,t){let n=new Map;for(let a of t){let o=a==null?void 0:a.account;o&&n.set(o,(n.get(o)||0)+1)}for(let[a,o]of n.entries()){Nt.acct.has(a)||Nt.acct.set(a,{ledgers:[],intervals:[],total:0});let i=Nt.acct.get(a),r=i.ledgers.at(-1);i.ledgers.push(e),r!=null&&e>r&&i.intervals.push(e-r),i.ledgers.length>30&&i.ledgers.shift(),i.intervals.length>29&&i.intervals.shift(),i.total+=o}let s=[];for(let[a,o]of Nt.acct.entries()){if(o.intervals.length<6)continue;let i=gn(o.intervals),r=Fi(o.intervals);if(!i||r==null)continue;let l=r/i;l<.35&&o.total>10&&s.push({acct:a,cv:l,total:o.total})}if(s.sort((a,o)=>a.cv-o.cv||o.total-a.total),e%50===0)for(let[a,o]of Nt.acct){let i=o.ledgers.at(-1)??e;e-i>1e3&&Nt.acct.delete(a)}return{bots:s.slice(0,6),uniqueActors:n.size}}function tv(e,t,n){var M;let s=0,a=0,o=new Map,i=new Map,r=new Map;for(let C of n){let E=C==null?void 0:C.type,R=C==null?void 0:C.account;R&&(E==="OfferCreate"?(s+=1,o.set(R,(o.get(R)||0)+1),i.set(R,(i.get(R)||0)+1)):E==="OfferCancel"&&(a+=1,o.set(R,(o.get(R)||0)+1),r.set(R,(r.get(R)||0)+1)))}let l=s+a,c=l?a/l:0,d=t!=null&&Number(t)>0?a/Number(t)*60:null;for(Ee.smoothCancelPerMin=Rp(Ee.smoothCancelPerMin,d,.45),Ee.window.unshift({li:e,closeTimeSec:t??null,create:s,cancel:a,total:l,cancelRatio:c,cancelsPerMin:Ee.smoothCancelPerMin,byActor:o,byActorCreate:i,byActorCancel:r});Ee.window.length>dg;)Ee.window.pop();let u={create:0,cancel:0,total:0},p=new Map,m=new Map,f=new Map;for(let C of Ee.window){u.create+=C.create,u.cancel+=C.cancel,u.total+=C.total;for(let[E,R]of C.byActor.entries())p.set(E,(p.get(E)||0)+R);for(let[E,R]of C.byActorCancel.entries())m.set(E,(m.get(E)||0)+R);for(let[E,R]of C.byActorCreate.entries())f.set(E,(f.get(E)||0)+R)}let g=Pi(p,5),b=Pi(m,5),h=Pi(f,5),v=u.total?(((M=g[0])==null?void 0:M.count)||0)/u.total:0,w=0;if(u.total)for(let C of p.values()){let E=C/u.total;w+=E*E}let k=Ee.window.map(C=>C.total).filter(Number.isFinite),$=gn(k)||0,T=$>0?(l-$)/$*100:null;Ee.smoothBurst=Rp(Ee.smoothBurst,T,.4);let S=[];return u.total>=Si&&c>=.65&&S.push("Lots of cancels (looks like quote-stuffing/spam)"),u.total>=Si&&v>=.35&&S.push("One actor dominates DEX activity"),u.total>=Si&&(Ee.smoothCancelPerMin||0)>=18&&S.push("Fast cancelling (high churn)"),Ee.smoothBurst!=null&&Math.abs(Ee.smoothBurst)>=45&&S.push("Sudden DEX burst"),{now:{li:e,create:s,cancel:a,total:l,cancelRatio:c,cancelsPerMin:Ee.smoothCancelPerMin},window:{...u,cancelRatio:u.total?u.cancel/u.total:0},topShare:v,actorHHI:w,burstPct:Ee.smoothBurst,topActor:g,topCanceller:b,topMaker:h,signals:S}}function Pi(e,t){return[...e.entries()].sort((n,s)=>s[1]-n[1]).slice(0,t).map(([n,s])=>({acct:n,count:s}))}function nv({txs:e,txTypes:t,dexPatterns:n}){var H;let s=Number((t==null?void 0:t.OfferCreate)||0)+Number((t==null?void 0:t.OfferCancel)||0),a=Number((t==null?void 0:t.NFTokenMint)||0),o=Number((t==null?void 0:t.NFTokenBurn)||0),i=0,r=new Map,l=new Map;for(let N of e){if((N==null?void 0:N.type)!=="Payment")continue;let z=(N==null?void 0:N.paths)||(N==null?void 0:N.Paths),te=Array.isArray(z)&&z.length>0,oe=(N==null?void 0:N.sendmax)!=null||(N==null?void 0:N.SendMax)!=null,pe=(N==null?void 0:N.delivermax)!=null||(N==null?void 0:N.DeliverMax)!=null;if(!(te||oe||pe))continue;i+=1;let ne=N==null?void 0:N.account,ce=N==null?void 0:N.destination;if(ne&&r.set(ne,(r.get(ne)||0)+1),ne&&ce){let G=`${ne}|${ce}`;l.set(G,(l.get(G)||0)+1)}}let c=[...r.entries()].sort((N,z)=>z[1]-N[1]).slice(0,5).map(([N,z])=>({acct:N,count:z})),d=[...l.entries()].sort((N,z)=>z[1]-N[1]).slice(0,5).map(([N,z])=>{let[te,oe]=N.split("|");return{from:te,to:oe,count:z}}),u=(H=n==null?void 0:n.now)!=null&&H.total?Math.round((n.now.cancelRatio||0)*100):0,p=(n==null?void 0:n.topShare)!=null?Math.round(n.topShare*100):0,m=e.filter(N=>(N==null?void 0:N.type)==="Payment").map(N=>typeof(N==null?void 0:N.amountXrp)=="number"?N.amountXrp:null).filter(N=>N!=null&&N>0&&Number.isFinite(N)),f=[100,1e3,1e4],g=m.filter(N=>f.some(z=>Math.abs(N%z)<1e-9&&N/z>=1)).length,b=m.length>=5?Math.round(g/m.length*100):null,h=e.filter(N=>(N==null?void 0:N.type)==="Payment"&&(N==null?void 0:N.account)&&(N==null?void 0:N.destination)&&N.account===N.destination).length,v=Number((t==null?void 0:t.AMMCreate)||0),w=Number((t==null?void 0:t.AMMDeposit)||0),k=Number((t==null?void 0:t.AMMWithdraw)||0),$=Number((t==null?void 0:t.AMMVote)||0),T=Number((t==null?void 0:t.AMMBid)||0),S=Number((t==null?void 0:t.AMMDelete)||0),M=v+w+k+$+T+S,C=w-k,E=w+k>0?Math.round(w/(w+k)*100):null,R=new Set;for(let N of e)["AMMCreate","AMMDeposit","AMMWithdraw","AMMVote","AMMBid"].includes(N==null?void 0:N.type)&&(N!=null&&N.account)&&R.add(N.account);let O=R.size,I=0,D=0;for(let N of e)(N==null?void 0:N.type)==="Payment"&&Array.isArray(N==null?void 0:N.paths)&&N.paths.length>0&&(I+=N.paths.length,D++);let F=D>0?(I/D).toFixed(1):null;return{offerTotal:s,dexCancelPct:u,dexTopSharePct:p,mints:a,burns:o,pathPays:i,topPathActors:c,topPathPairs:d,roundnessIdx:b,selfTradeCount:h,ammCreate:v,ammDeposit:w,ammWithdraw:k,ammVote:$,ammBid:T,ammDelete:S,lpTotal:M,lpNetFlow:C,lpRatio:E,lpUniqueActors:O,avgPathDepth:F}}function sv({hhi:e,repeats:t,dex:n,bots:s,advanced:a}){var h,v;let o=ke((e-.22)/.25,0,1)*22,i=ke((t-2)/6,0,1)*12,r=((h=n==null?void 0:n.window)==null?void 0:h.cancelRatio)??0,l=(n==null?void 0:n.topShare)??0,c=((v=n==null?void 0:n.now)==null?void 0:v.cancelsPerMin)??0,d=ke((r-.5)/.5,0,1)*18,u=ke((l-.25)/.5,0,1)*18,p=ke(c/25,0,1)*10,m=ke(s/6,0,1)*10,f=(a==null?void 0:a.roundnessIdx)!=null?ke((a.roundnessIdx-30)/40,0,1)*8:0,g=(a==null?void 0:a.selfTradeCount)>0?Math.min(8,a.selfTradeCount*4):0,b=(a==null?void 0:a.pathPays)!=null?ke(a.pathPays/30,0,1)*6:0;return Math.round(o+i+d+u+p+m+f+g+b)}function av({friction:e,tps:t,fee:n}){let s=(n==null?void 0:n.deltaPct)!=null&&Math.abs(n.deltaPct)>=35,a=(t==null?void 0:t.deltaPct)!=null&&Math.abs(t.deltaPct)>=25;return e>=75?"Manipulated":s||a?"Stressed":((t==null?void 0:t.cur)??0)>=12||((t==null?void 0:t.avg)??0)>=10?"Active":"Quiet"}function ov({s:e,txTypes:t,hhi:n,dexPatterns:s,behavior:a,friction:o,regime:i,breadcrumbs:r,clusters:l,advanced:c}){var h,v,w,k,$;let d=[],u=Ht(B.tpsHistory,Yt),p=Ht(B.feeHistory,Yt),m=((h=Object.entries(t||{}).sort(([,T],[,S])=>S-T)[0])==null?void 0:h[0])||"\u2014",f=Number(e.txPerLedger||0);d.push({sentiment:i==="Manipulated"||i==="Stressed"?"warn":i==="Active"?"up":"ok",title:`Overall: ${i} \xB7 Risk score ${o}/100`,detail:"Heuristic score from concentration, repeats, DEX churn, bot-like timing, and routing indicators. It's a signal, not proof."}),d.push({sentiment:"ok",title:`Ledger snapshot: #${Number(e.ledgerIndex||0).toLocaleString()} \xB7 ${f} tx \xB7 most common: ${m}`,detail:`TPS ${is(u.cur,2)} (avg ${is(u.avg,2)} \xB7 ${vn(u.deltaPct,0)}). Fee ${p.cur!=null?fn(p.cur):"\u2014"} (avg ${p.avg!=null?fn(p.avg):"\u2014"} \xB7 ${vn(p.deltaPct,0)}).`});let g=n>=.35?"high":n>=.25?"medium":"low";if(d.push({sentiment:n>=.35?"warn":"ok",title:`Transaction mix: ${g} concentration (HHI ${n.toFixed(2)})`,detail:n>=.35?"A few tx types dominate. Patterns look \u201Cstronger,\u201D but can be misleading.":"Mix is broad. Strong signals usually come from behavior, not just tx type."}),s.window.total){let T=Math.round(s.window.cancelRatio*100),S=Math.round(s.topShare*100);d.push({sentiment:s.signals.length?"warn":"ok",title:`DEX monitor: ${s.window.total} offer tx (window) \xB7 cancels ${T}% \xB7 top actor ~${S}%`,detail:s.signals.length?`Signals: ${s.signals.join(" \xB7 ")}`:"No strong DEX-pattern signals right now.",addr:((v=s.topActor[0])==null?void 0:v.acct)||null})}let b=r.filter(T=>T.count>=2).length;if(b>=2&&d.push({sentiment:"new",title:`Repeating counterparties: ${b} recurring pair(s)`,detail:"Repeated interactions can be routing loops, bots, or coordinated flows. Click addresses for a quick read."}),l!=null&&l.length&&((w=l[0])==null?void 0:w.size)>=3&&d.push({sentiment:"new",title:`Cluster forming: ${l[0].size} wallets \xB7 hub ${W(l[0].hub)}`,detail:"Clusters are co-activity groups (not identity proof). Use as \u201Clikely related behavior.\u201D",addr:l[0].hub}),(k=a.bots)!=null&&k.length){let T=a.bots[0];d.push({sentiment:"warn",title:`Bot-like timing: ${a.bots.length} candidate(s)`,detail:`Low variance in repeated appearances. Top: ${W(T.acct)} (CV ${T.cv.toFixed(2)}).`,addr:T.acct})}if(c!=null&&c.pathPays){let T=($=c.topPathActors)==null?void 0:$[0];d.push({sentiment:c.pathPays>=18?"warn":"ok",title:`Autobridge-ish routing: ${c.pathPays} path payments (ledger sample)`,detail:T?`Most active routing wallet: ${W(T.acct)} (${T.count}).`:"Paths/SendMax/DeliverMax appear frequently in the sample.",addr:(T==null?void 0:T.acct)||null})}return c!=null&&c.selfTradeCount&&d.push({sentiment:"warn",title:`Self-transfer signal: ${c.selfTradeCount} payment(s) where sender = receiver`,detail:"Self-transfers can be benign (housekeeping) or used to fake activity. Treat as a watch signal."}),((c==null?void 0:c.roundnessIdx)??0)>=45&&d.push({sentiment:"warn",title:`Round-number bias: ${c.roundnessIdx}% of payments are exact multiples of 100/1,000/10,000`,detail:"Round-number bias often shows scripted behavior (bots) rather than human payments."}),d.slice(0,12)}function iv(e){let t=x("d2-breadcrumb-list"),n=x("d2-breadcrumb-meta");if(!t)return;if(!e.length){t.innerHTML='<div class="gateway-item" style="opacity:.6">Watching for repeated interactions\u2026</div>',n&&(n.textContent="\u2014");return}let s=e.filter(a=>a.count>=2).length;n&&(n.textContent=s?`${s} repeats`:"Top interactions"),t.innerHTML=e.slice(0,10).map(a=>`
    <div class="gateway-item gateway-row">
      <div class="gateway-left mono cut">
        <button class="addr-link mono cut gw-from" data-addr="${y(a.from)}">${y(W(a.from))}</button>
        <span class="gw-arrow">\u2192</span>
        <button class="addr-link mono cut gw-to" data-addr="${y(a.to)}">${y(W(a.to))}</button>
      </div>
      <span class="gw-count">${a.count}\xD7</span>
    </div>`).join("")}function rv(e){let t=x("d2-cluster-list"),n=x("d2-cluster-persistence");if(t){if(!e.length){t.innerHTML='<div class="gateway-item" style="opacity:.6">Building clusters\u2026 (needs repeated activity)</div>',n&&(n.textContent="\u2014");return}n&&(n.textContent=`${e.length} group${e.length!==1?"s":""}`),t.innerHTML=e.slice(0,6).map((s,a)=>{let i=`hsl(${(a*67+120)%360},70%,60%)`,r=s.members.slice(0,4);return`
      <div class="gateway-item cluster-item">
        <div class="cluster-head">
          <span class="cluster-title" style="color:${i}">Group ${a+1}</span>
          <span class="cluster-meta">${s.size} wallets</span>
        </div>
        <div class="cluster-preview">
          <span class="cluster-chip-h">Hub:</span>
          <button class="addr-chip mono" data-addr="${y(s.hub)}">${y(W(s.hub))}</button>
        </div>
        <div class="cluster-preview">
          <span class="cluster-chip-h">Members:</span>
          ${r.map(l=>`<button class="addr-chip mono" data-addr="${y(l)}">${y(W(l))}</button>`).join("")}
          ${s.members.length>r.length?`<span class="cluster-more">+${s.members.length-r.length}</span>`:""}
        </div>
      </div>`}).join("")}}function lv(e){let t=x("d2-delta-narratives");if(!t)return;if(!e.length){t.innerHTML='<div class="gateway-item" style="opacity:.6">Building baseline \u2014 narratives appear after 1\u20132 ledgers\u2026</div>';return}let n={up:"#50fa7b",down:"#ff5555",new:"#00d4ff",warn:"#ffb86c",ok:"rgba(255,255,255,.85)"};t.innerHTML=e.map(s=>{let a=n[s.sentiment]||"rgba(255,255,255,.85)",o=s.addr&&Xe(s.addr)?`<button class="addr-link narrative-addr" data-addr="${y(s.addr)}">Peek</button>`:"";return`
      <details class="gateway-item narrative-item">
        <summary style="color:${a}">
          <span class="narrative-title">${y(s.title||s.text||"")}</span>
          ${o}
        </summary>
        <div class="narrative-detail">${y(s.detail||"")}</div>
      </details>`}).join("")}function cv(){if(hp)return;hp=!0;let e=new Map([["Pattern detection","Quick \u201Cat a glance\u201D read. If one thing dominates, patterns are easier to spot (but can be noisy)."],["Live ledger stream","Each card is a validated ledger. Glow color shows what activity dominated that ledger. Click a card to jump to inspector."],["Wallet breadcrumbs","Shows who repeatedly interacts with who. Click an address for an account peek."],["Cluster inference","Groups wallets that move together. Not identity proof. Use it as \u201Clikely related behavior.\u201D"],["Delta narratives","Plain-English summary of what changed: load, fees, DEX churn, repeats, bot-like timing."]]);document.querySelectorAll("section.widget-card[aria-label], div.widget-card[aria-label]").forEach(t=>{let n=t.getAttribute("aria-label")||"",s=e.get(n);if(!s)return;let a=t.querySelector(".widget-header");if(!a||t.querySelector(".widget-help"))return;let o=document.createElement("p");o.className="widget-help",o.textContent=s,a.insertAdjacentElement("afterend",o)})}function dv(){if(gp)return;gp=!0;let e=document.querySelector(".ledger-stream-card");if(!e||e.querySelector(".ledger-legend"))return;let t=e.querySelector(".widget-help"),n=e.querySelector(".widget-header"),s=document.createElement("div");s.className="ledger-legend",s.setAttribute("aria-label","Ledger glow legend"),s.innerHTML=`
    <span class="legend-label">Glow key:</span>
    <span class="legend-chip payment">Payment</span>
    <span class="legend-chip offer">DEX</span>
    <span class="legend-chip nft">NFT</span>
    <span class="legend-chip trust">Trust</span>
    <span class="legend-chip amm">AMM</span>
    <span class="legend-chip other">Other</span>
  `,t?t.insertAdjacentElement("afterend",s):n?n.insertAdjacentElement("afterend",s):e.prepend(s)}function pv(){if(bp)return;bp=!0;let e=document.querySelector(".dashboard-col-main");if(!e)return;let t=document.createElement("section");t.className="widget-card",t.id="landscape-card",t.setAttribute("aria-label","Landscape brief"),t.innerHTML=`
    <div class="widget-header">
      <span class="widget-title">\u{1F9FE} Landscape Report</span>
      <span class="widget-tag mono cut" id="landscape-badge">\u2014</span>
      <button onclick="window.printLandscapeReport()" title="Print or save as PDF"
        style="background:rgba(0,212,255,.07);border:1px solid rgba(0,212,255,.18);
               color:var(--accent,#00d4ff);border-radius:8px;padding:5px 10px;
               font-size:.72rem;cursor:pointer;flex-shrink:0">\u{1F5A8} Print</button>
    </div>
    <p class="widget-help">
      \u201CIn plain English\u201D: what\u2019s happening now, why it matters, and who to watch.
      These are <b>signals</b> (not proof).
    </p>

    <div class="landscape-brief" id="landscape-text">Waiting for data\u2026</div>

    <div class="landscape-callout">
      <div class="landscape-callout-h">Why it matters</div>
      <div class="landscape-list" id="landscape-why"></div>
    </div>

    <div class="landscape-callout">
      <div class="landscape-callout-h">Who to watch right now</div>
      <div class="landscape-watchlist" id="landscape-watchlist"></div>
    </div>

    <div class="landscape-grid">
      <div class="landscape-box">
        <div class="landscape-h">What\u2019s happening</div>
        <div class="landscape-list" id="landscape-now"></div>
      </div>
      <div class="landscape-box">
        <div class="landscape-h">What to watch next</div>
        <div class="landscape-list" id="landscape-watch"></div>
      </div>
    </div>
  `,e.prepend(t)}function uv(e){var v,w,k,$,T,S,M,C,E,R,O,I,D,F,H;let t=x("landscape-badge");t&&(t.textContent=`${e.regime} \xB7 Risk ${e.friction}/100`);let n=e.s,s=e.txTypes||{},a=((v=Object.entries(s).sort(([,N],[,z])=>z-N)[0])==null?void 0:v[0])||"\u2014",o=Ht(B.tpsHistory,Yt),i=Ht(B.feeHistory,Yt),r=e.dexPatterns,l=(w=r==null?void 0:r.window)!=null&&w.total?Math.round(r.window.cancelRatio*100):0,c=x("landscape-text");if(c){let N=Number(n.ledgerIndex||0).toLocaleString(),z=Number(n.txPerLedger||0),te=((k=n.latestLedger)==null?void 0:k.closeTimeSec)!=null?Number(n.latestLedger.closeTimeSec).toFixed(2)+"s":"\u2014",oe=o.cur!=null?`${is(o.cur,2)} TPS`:"\u2014",pe=i.cur!=null?`${fn(i.cur)} fee`:"\u2014",ie=n.successRate!=null?`${Number(n.successRate).toFixed(1)}% success`:"\u2014",ne=($=r==null?void 0:r.window)!=null&&$.total?`DEX offers are <b>${r.window.total}</b> (window), with <b>${l}% cancels</b>.`:"DEX offers look quiet right now.";c.innerHTML=`
      <b>Right now:</b> Ledger <b>#${N}</b> closed in <b>${te}</b> with <b>${z}</b> transactions.
      Network is at <b>${oe}</b>, with <b>${pe}</b>, and <b>${ie}</b>.
      Most common activity was <b>${y(a)}</b>. ${ne}
    `}let d=x("landscape-why"),u=x("landscape-watchlist"),p=x("landscape-now"),m=x("landscape-watch"),f=[],g=[],b=[];if(e.regime==="Manipulated"?b.push("Risk score is very high. Patterns like churn, loops, or single-actor dominance often correlate with manipulated activity."):e.regime==="Stressed"?b.push("The network is behaving \u201Cabnormally\u201D (spikes in TPS or fees). This can be organic bursts or bots pushing volume."):e.regime==="Active"?b.push("The network is busy. Patterns are easier to detect because there\u2019s more data per minute."):b.push("The network is quiet. Signals are weaker; a few bots can dominate a small sample."),(T=r==null?void 0:r.signals)!=null&&T.length&&b.push(`DEX churn signals: <b>${y(r.signals.join(" \xB7 "))}</b>. Heavy OfferCreate/Cancel churn can indicate quote-stuffing/spoofing-like behavior.`),((S=e.advanced)==null?void 0:S.selfTradeCount)>0&&b.push(`Detected <b>${e.advanced.selfTradeCount}</b> self-transfer payment(s) in the sample. Can be benign, but can also be used to fake activity.`),(((M=e.advanced)==null?void 0:M.roundnessIdx)??0)>=45&&b.push(`Round-number bias is high (<b>${e.advanced.roundnessIdx}%</b>). That often indicates automation rather than human behavior.`),((C=e.advanced)==null?void 0:C.pathPays)>=18&&b.push(`Path payments are heavy (<b>${e.advanced.pathPays}</b> in sample). Lots of routing can mean arbitrage bots or automated bridge traffic.`),d&&(d.innerHTML=b.map(N=>`<div class="landscape-row">${N}</div>`).join("")),f.push(`Overall mode: <b>${y(e.regime)}</b> (risk score <b>${e.friction}/100</b>).`),f.push(`Traffic: <b>${is(o.cur,2)}</b> TPS (avg ${is(o.avg,2)} \xB7 ${vn(o.deltaPct,0)}).`),f.push(`Fees: <b>${i.cur!=null?fn(i.cur):"\u2014"}</b> (avg ${i.avg!=null?fn(i.avg):"\u2014"} \xB7 ${vn(i.deltaPct,0)}).`),(E=r==null?void 0:r.window)!=null&&E.total){let N=(R=r.topActor)==null?void 0:R[0];f.push(`DEX activity: <b>${r.window.total}</b> offer tx (window) \xB7 cancels <b>${l}%</b> \xB7 churn <b>${is(r.now.cancelsPerMin,1)}</b>/min.`),N&&f.push(`Most active DEX wallet: <button class="addr-link mono" data-addr="${y(N.acct)}">${y(W(N.acct))}</button> (${N.count}).`)}else f.push("DEX activity: <b>quiet</b> (few OfferCreate/OfferCancel).");let h=e.breadcrumbs.filter(N=>N.count>=2).length;if(h&&g.push(`Repeating interactions: <b>${h}</b> pair(s) keep showing up.`),(I=(O=e.behavior)==null?void 0:O.bots)!=null&&I.length){let N=e.behavior.bots[0];g.push(`Bot-like timing: top candidate <button class="addr-link mono" data-addr="${y(N.acct)}">${y(W(N.acct))}</button> (CV ${N.cv.toFixed(2)}).`)}if((D=r==null?void 0:r.signals)!=null&&D.length&&g.push(`DEX signals: <b>${y(r.signals.join(" \xB7 "))}</b>`),(F=e.clusters)!=null&&F.length&&g.push(`Largest cluster: <b>${e.clusters[0].size}</b> wallets \xB7 hub <button class="addr-link mono" data-addr="${y(e.clusters[0].hub)}">${y(W(e.clusters[0].hub))}</button>.`),(H=e.advanced)!=null&&H.pathPays&&g.push(`Autobridge/path flow: <b>${e.advanced.pathPays}</b> path payments detected in sample.`),g.length||g.push("Nothing urgent stands out in the current window."),p&&(p.innerHTML=f.map(N=>`<div class="landscape-row">${N}</div>`).join("")),m&&(m.innerHTML=g.map(N=>`<div class="landscape-row">${N}</div>`).join("")),u){let N=mv(e);u.innerHTML=N.length?N.map(z=>`
        <div class="landscape-watchitem">
          <button class="addr-link mono cut" data-addr="${y(z.addr)}">${y(W(z.addr))}</button>
          <div class="landscape-watchwhy">${z.why}</div>
        </div>
      `).join(""):'<div style="opacity:.75">No clear \u201Ctop suspect\u201D yet \u2014 need a few more ledgers to build a baseline.</div>'}}function mv(e){var i,r,l,c,d,u,p,m;let t=[],n=(f,g)=>{!f||!Xe(f)||t.some(b=>b.addr===f)||t.push({addr:f,why:g})};if((r=(i=e.behavior)==null?void 0:i.bots)!=null&&r.length){let f=e.behavior.bots[0];n(f.acct,`Bot-like timing (CV <span class="mono">${f.cv.toFixed(2)}</span>). High regularity is common in spam & automation.`)}let s=e.dexPatterns;if((l=s==null?void 0:s.topActor)!=null&&l.length){let f=s.topActor[0],g=s.topShare!=null?Math.round(s.topShare*100):null,b=((c=s.now)==null?void 0:c.cancelsPerMin)!=null?s.now.cancelsPerMin.toFixed(1):"\u2014";g!=null&&g>=25&&n(f.acct,`Dominates DEX activity (~<span class="mono">${g}%</span> share). Cancels/min <span class="mono">${b}</span> \u2014 watch for quote-stuffing/spoofing.`)}if((d=s==null?void 0:s.topCanceller)!=null&&d.length){let f=s.topCanceller[0];f.count>=6&&n(f.acct,`Top canceller (<span class="mono">${f.count}</span>). Heavy cancels can be a manipulation signal.`)}let a=e.breadcrumbs||[],o=a[0];if(o!=null&&o.from&&(o!=null&&o.to)){let f=a.find(g=>g.from===o.to&&g.to===o.from);f&&f.count>=3&&o.count>=3?(n(o.from,`Ping\u2011pong loop with ${W(o.to)} (<span class="mono">${o.count}\xD7</span> / <span class="mono">${f.count}\xD7</span>). Can be wash-like routing.`),n(o.to,`Ping\u2011pong loop with ${W(o.from)} (<span class="mono">${f.count}\xD7</span> / <span class="mono">${o.count}\xD7</span>).`)):o.count>=10&&n(o.from,`Repeated counterparty flow to ${W(o.to)} (<span class="mono">${o.count}\xD7</span>). Persistent repetition often indicates automation.`)}if((u=e.clusters)!=null&&u.length&&e.clusters[0].size>=3&&n(e.clusters[0].hub,`Cluster hub of <span class="mono">${e.clusters[0].size}</span> wallets. Coordination is a common feature of wash/loop tactics.`),(m=(p=e.advanced)==null?void 0:p.topPathActors)!=null&&m.length){let f=e.advanced.topPathActors[0];f.count>=6&&n(f.acct,`Heavy path\u2011payment routing (<span class="mono">${f.count}</span>). Often correlates with arbitrage bots.`)}return t.slice(0,6)}function fv(){if(yp)return;yp=!0;let e=document.querySelector(".dashboard-col-side");if(!e)return;let t=document.createElement("section");t.className="widget-card",t.id="dex-pattern-card",t.setAttribute("aria-label","DEX pattern monitor"),t.innerHTML=`
    <div class="widget-header">
      <span class="widget-title">\u{1F9E0} DEX Pattern Monitor</span>
      <span class="widget-tag mono cut" id="dexp-badge">Waiting\u2026</span>
    </div>
    <p class="widget-help">
      Tracks OfferCreate/OfferCancel patterns from the live ledger stream. No order-book polling.
      These are signals (not proof of manipulation).
    </p>

    <div class="dex-metrics">
      <div class="dex-row">
        <span class="dex-k">Cancel ratio</span>
        <div class="dex-bar"><div class="dex-bar-fill" id="dexp-cancel-bar" style="width:0%"></div></div>
        <span class="dex-v mono" id="dexp-cancel-val">\u2014</span>
      </div>
      <div class="dex-row">
        <span class="dex-k">Top actor share</span>
        <div class="dex-bar"><div class="dex-bar-fill" id="dexp-topshare-bar" style="width:0%"></div></div>
        <span class="dex-v mono" id="dexp-topshare-val">\u2014</span>
      </div>
      <div class="dex-row">
        <span class="dex-k">Burst vs avg</span>
        <div class="dex-bar"><div class="dex-bar-fill" id="dexp-burst-bar" style="width:0%"></div></div>
        <span class="dex-v mono" id="dexp-burst-val">\u2014</span>
      </div>
    </div>

    <div class="dex-mini">
      <div><span>Cancels/min</span><b class="mono" id="dexp-cpm">\u2014</b></div>
      <div><span>Actor HHI</span><b class="mono" id="dexp-hhi">\u2014</b></div>
      <div><span>Offer tx (win)</span><b class="mono" id="dexp-totalwin">\u2014</b></div>
    </div>

    <div class="dex-signals" id="dexp-signals"></div>

    <div class="dex-subgrid">
      <div class="dex-subbox">
        <div class="dex-subh">Top cancellers</div>
        <div class="dex-list" id="dexp-cancellers">\u2014</div>
      </div>
      <div class="dex-subbox">
        <div class="dex-subh">Top makers</div>
        <div class="dex-list" id="dexp-makers">\u2014</div>
      </div>
    </div>
  `,e.prepend(t)}function hv(e){var p,m;if(!document.getElementById("dex-pattern-card"))return;let t=e.window.total||0,n=t?Math.round(e.window.cancelRatio*100):0,s=t?Math.round(e.topShare*100):0;V("dexp-badge",t?`${t} offer tx \xB7 ${n}% cancels`:"Quiet");let a=x("dexp-cancel-bar");a&&(a.style.width=`${ke(n,0,100)}%`),V("dexp-cancel-val",t?`${n}%`:"\u2014");let o=x("dexp-topshare-bar");o&&(o.style.width=`${ke(s,0,100)}%`),V("dexp-topshare-val",t?`${s}%`:"\u2014");let i=e.burstPct,r=i==null?0:Math.min(100,Math.abs(i)),l=x("dexp-burst-bar");l&&(l.style.width=`${r}%`),V("dexp-burst-val",i==null?"\u2014":vn(i,0)),V("dexp-cpm",e.now.cancelsPerMin==null?"\u2014":e.now.cancelsPerMin.toFixed(1)),V("dexp-hhi",t?e.actorHHI.toFixed(2):"\u2014"),V("dexp-totalwin",t?`${t}`:"\u2014");let c=x("dexp-signals");c&&(c.innerHTML=e.signals.length?e.signals.map(f=>`<span class="sig-pill warn">${y(f)}</span>`).join(""):'<span class="sig-pill ok">No strong DEX signals</span>');let d=x("dexp-cancellers");d&&(d.innerHTML=(p=e.topCanceller)!=null&&p.length?e.topCanceller.slice(0,5).map(f=>`
        <div class="dex-rowline">
          <button class="addr-link mono cut" data-addr="${y(f.acct)}">${y(W(f.acct))}</button>
          <span class="mono">${f.count}</span>
        </div>`).join(""):'<div style="opacity:.7">\u2014</div>');let u=x("dexp-makers");u&&(u.innerHTML=(m=e.topMaker)!=null&&m.length?e.topMaker.slice(0,5).map(f=>`
        <div class="dex-rowline">
          <button class="addr-link mono cut" data-addr="${y(f.acct)}">${y(W(f.acct))}</button>
          <span class="mono">${f.count}</span>
        </div>`).join(""):'<div style="opacity:.7">\u2014</div>')}function gv(){if(wp)return;wp=!0;let e=document.querySelector(".dashboard-col-main");if(!e)return;let t=document.createElement("section");t.className="widget-card",t.id="risk-card",t.setAttribute("aria-label","Risk panel"),t.innerHTML=`
    <div class="widget-header">
      <span class="widget-title">\u26A0\uFE0F Risk &amp; Deep Ledger Analytics</span>
      <span class="widget-tag mono cut" id="risk-badge">\u2014</span>
    </div>
    <p class="widget-help">
      Transparent heuristics: concentration + repeats + DEX churn + bot-like timing + routing indicators. Signals only.
    </p>

    <div class="risk-top">
      <div class="risk-stat"><span>Regime</span><b id="risk-regime">\u2014</b></div>
      <div class="risk-stat"><span>Risk score</span><b id="risk-friction">\u2014</b></div>
      <div class="risk-stat"><span>Signals</span><b id="risk-signalcount">\u2014</b></div>
    </div>

    <div class="risk-pills" id="risk-pills"></div>

    <div class="risk-grid">
      <div class="risk-box risk-collapsible">
        <button class="risk-box-toggle" data-target="risk-bots" aria-expanded="true">
          <span class="risk-box-h">\u{1F916} Bot-like timing</span><span class="risk-box-chevron">\u25BE</span>
        </button>
        <div id="risk-bots" class="risk-list risk-collapsible-body"></div>
      </div>
      <div class="risk-box risk-collapsible">
        <button class="risk-box-toggle" data-target="risk-amm" aria-expanded="true">
          <span class="risk-box-h">\u{1F4A7} AMM / LP activity</span><span class="risk-box-chevron">\u25BE</span>
        </button>
        <div id="risk-amm" class="risk-list risk-collapsible-body"></div>
      </div>
      <div class="risk-box risk-collapsible">
        <button class="risk-box-toggle" data-target="risk-path" aria-expanded="true">
          <span class="risk-box-h">\u{1F9ED} Routing / path flow</span><span class="risk-box-chevron">\u25BE</span>
        </button>
        <div id="risk-path" class="risk-list risk-collapsible-body"></div>
      </div>
      <div class="risk-box risk-collapsible">
        <button class="risk-box-toggle" data-target="risk-notes" aria-expanded="true">
          <span class="risk-box-h">\u{1F4CC} Notes</span><span class="risk-box-chevron">\u25BE</span>
        </button>
        <div class="risk-list risk-collapsible-body" id="risk-notes"></div>
      </div>
    </div>
  `,t.querySelectorAll(".risk-box-toggle").forEach(n=>{var a;n.addEventListener("click",()=>{let o=n.getAttribute("data-target"),i=document.getElementById(o);if(!i)return;let r=n.getAttribute("aria-expanded")!=="false";n.setAttribute("aria-expanded",r?"false":"true"),i.classList.toggle("risk-collapsed",r),n.querySelector(".risk-box-chevron").textContent=r?"\u25B8":"\u25BE";try{localStorage.setItem("risk_collapsed_"+o,r?"1":"0")}catch{}});let s=n.getAttribute("data-target");try{localStorage.getItem("risk_collapsed_"+s)==="1"&&(n.setAttribute("aria-expanded","false"),(a=document.getElementById(s))==null||a.classList.add("risk-collapsed"),n.querySelector(".risk-box-chevron").textContent="\u25B8")}catch{}}),e.appendChild(t)}function vv(e){var r,l,c,d,u,p,m,f,g,b;if(!document.getElementById("risk-card"))return;V("risk-badge",`Risk ${e.friction}/100`),V("risk-regime",e.regime),V("risk-friction",`${e.friction}/100`);let t=[];e.hhi>=.35&&t.push({cls:"warn",t:"High concentration"}),e.breadcrumbs.filter(h=>h.count>=2).length>=3&&t.push({cls:"new",t:"Repeating counterparties"}),(l=(r=e.behavior)==null?void 0:r.bots)!=null&&l.length&&t.push({cls:"warn",t:"Bot-like timing"}),(d=(c=e.dexPatterns)==null?void 0:c.signals)!=null&&d.length&&t.push({cls:"warn",t:"DEX churn signals"}),((u=e.advanced)==null?void 0:u.selfTradeCount)>0&&t.push({cls:"warn",t:`Self-transfer: ${e.advanced.selfTradeCount}`}),(((p=e.advanced)==null?void 0:p.roundnessIdx)??0)>=45&&t.push({cls:"warn",t:`Round-number bias ${e.advanced.roundnessIdx}%`}),((m=e.advanced)==null?void 0:m.pathPays)>0&&t.push({cls:"warn",t:`Path flow: ${e.advanced.pathPays}`}),V("risk-signalcount",`${t.length}`);let n=x("risk-pills");n&&(n.innerHTML=t.length?t.map(h=>`<span class="sig-pill ${h.cls}">${y(h.t)}</span>`).join(""):'<span class="sig-pill ok">No elevated signals</span>');let s=x("risk-bots");if(s){let h=((f=e.behavior)==null?void 0:f.bots)||[];if(h.length){let v={};for(let k of h){let $=k.botType||"Periodic";v[$]||(v[$]=[]),v[$].push(k)}let w=["Market Maker","Arbitrage","Flood / Spam","Periodic"];s.innerHTML=w.filter(k=>v[k]).map(k=>{let $=v[k];return`<div class="bot-type-group">
          <div class="bot-type-label" style="color:${$[0].botTypeColor||"rgba(255,255,255,.8)"}">${k}</div>
          ${$.map(S=>`
            <div class="risk-row bot-row">
              <button class="addr-link mono cut" data-addr="${y(S.acct)}" title="${y(S.acct)}">${y(W(S.acct))}</button>
              <div class="bot-row-meta">
                <span class="mono bot-cv" style="color:${S.cv<.1?"#ff5555":S.cv<.2?"#ffb86c":"rgba(255,255,255,.65)"}">CV ${S.cv.toFixed(2)}</span>
                <span class="bot-total mono">${S.total}tx</span>
              </div>
            </div>
            ${S.botDesc?`<div class="bot-desc">${y(S.botDesc)}</div>`:""}
          `).join("")}
        </div>`}).join("")}else s.innerHTML='<div style="opacity:.7;font-size:.84rem">No periodic bots detected yet</div>'}let a=x("risk-amm");if(a){let h=e.advanced||{},{ammCreate:v=0,ammDeposit:w=0,ammWithdraw:k=0,ammVote:$=0,ammBid:T=0,lpTotal:S=0,lpNetFlow:M=0,lpRatio:C,lpUniqueActors:E=0}=h;if(S===0)a.innerHTML='<div style="opacity:.6;font-size:.84rem">No AMM activity in this ledger</div>';else{let R=M>0?"#50fa7b":M<0?"#ff5555":"rgba(255,255,255,.5)";a.innerHTML=`
        <div class="amm-chips">
          ${v?`<span class="amm-chip amm-create">\u{1F195} Create \xD7${v}</span>`:""}
          ${w?`<span class="amm-chip amm-dep">\u2193 Deposit \xD7${w}</span>`:""}
          ${k?`<span class="amm-chip amm-wd">\u2191 Withdraw \xD7${k}</span>`:""}
          ${$?`<span class="amm-chip amm-vote">\u{1F5F3} Vote \xD7${$}</span>`:""}
          ${T?`<span class="amm-chip amm-bid">\u{1F4E3} Bid \xD7${T}</span>`:""}
        </div>
        <div class="risk-row" style="margin-top:8px"><span>Net LP flow</span>
          <span class="mono" style="color:${R}">${M>0?"+"+M+" (adding LP)":M<0?M+" (removing LP)":"0 (balanced)"}</span></div>
        ${C!=null?`<div class="risk-row"><span>Deposit ratio</span><span class="mono">${C}% depositing</span></div>`:""}
        <div class="risk-row"><span>Unique LP actors</span><span class="mono">${E||"\u2014"}</span></div>
        <div class="risk-row"><span>Total LP ops</span><span class="mono">${S}</span></div>`}}let o=x("risk-path");if(o){let h=e.advanced||{},v=(g=h.topPathActors)==null?void 0:g[0],w=(b=h.topPathActors)==null?void 0:b[1],k=h.selfTradeCount>0?"#ff5555":"rgba(255,255,255,.5)",$=(h.roundnessIdx??0)>=45?"#ff5555":(h.roundnessIdx??0)>=25?"#ffb86c":"rgba(255,255,255,.5)";o.innerHTML=`
      <div class="risk-row"><span>Path payments</span><span class="mono">${h.pathPays??"\u2014"}</span></div>
      ${h.avgPathDepth!=null?`<div class="risk-row"><span>Avg path depth</span><span class="mono">${h.avgPathDepth} hops</span></div>`:""}
      ${v?`<div class="risk-row"><span>Top router</span>
        <button class="addr-link mono cut" data-addr="${y(v.acct)}">${y(W(v.acct))}</button></div>
        <div class="risk-row" style="opacity:.75"><span style="padding-left:8px">\u21B3 count</span><span class="mono">${v.count}</span></div>`:""}
      ${w?`<div class="risk-row" style="opacity:.7"><span>2nd router</span>
        <button class="addr-link mono cut" data-addr="${y(w.acct)}">${y(W(w.acct))}</button></div>`:""}
      <div class="risk-row" style="margin-top:4px;border-top:1px solid rgba(255,255,255,.05);padding-top:8px">
        <span>Round-number %</span><span class="mono" style="color:${$}">${h.roundnessIdx!=null?h.roundnessIdx+"%":"\u2014"}</span></div>
      <div class="risk-row"><span>Self-transfers</span><span class="mono" style="color:${k}">${h.selfTradeCount??0}</span></div>`}let i=x("risk-notes");i&&(i.innerHTML=`
    <div style="opacity:.85">Signals are not proof. Use them to choose what to inspect.</div>
    <div style="opacity:.85">DEX monitor uses OfferCreate/OfferCancel only \u2014 no orderbook polling.</div>
    <div style="opacity:.85">Click any address to peek, then "Open in Inspector".</div>`)}function bv(){if(Cp)return;Cp=!0;let e=document.querySelector(".dashboard-col-side");if(e){if(!document.getElementById("dex-pressure-card")){let t=document.createElement("section");t.className="widget-card",t.id="dex-pressure-card",t.setAttribute("aria-label","DEX pressure"),t.innerHTML=`
      <div class="widget-header">
        <span class="widget-title">\u{1F4C9} DEX Pressure</span>
        <span class="widget-tag mono cut" id="dexP-badge">Waiting\u2026</span>
      </div>
      <p class="widget-help">
        OfferCreate + OfferCancel per ledger (pressure proxy). Cancel ratio and top-actor share come from the DEX Pattern window.
      </p>
      <div style="height:130px;"><canvas id="chart-dex-pressure" class="mini-chart"></canvas></div>
      <div class="dex-mini">
        <div><span>Offer tx</span><b class="mono" id="dexP-now">\u2014</b></div>
        <div><span>Cancel%</span><b class="mono" id="dexP-cancel">\u2014</b></div>
        <div><span>Top share</span><b class="mono" id="dexP-share">\u2014</b></div>
      </div>
    `,e.prepend(t)}if(!document.getElementById("autobridge-card")){let t=document.createElement("section");t.className="widget-card",t.id="autobridge-card",t.setAttribute("aria-label","Autobridge"),t.innerHTML=`
      <div class="widget-header">
        <span class="widget-title">\u{1F9ED} Autobridge / Path Payments</span>
        <span class="widget-tag mono cut" id="ab-badge">Waiting\u2026</span>
      </div>
      <p class="widget-help">
        Heuristic: payments that include Paths (or SendMax/DeliverMax). Proxy for routing/autobridge flows.
      </p>
      <div style="height:130px;"><canvas id="chart-autobridge" class="mini-chart"></canvas></div>
      <div class="dex-mini">
        <div><span>Path pays</span><b class="mono" id="ab-now">\u2014</b></div>
        <div><span>Top actor</span><b class="mono cut" id="ab-top-actor">\u2014</b></div>
        <div><span>Pairs</span><b class="mono" id="ab-pairs">\u2014</b></div>
      </div>
      <div class="dex-subbox" style="margin-top:10px;">
        <div class="dex-subh">Top path pairs</div>
        <div class="dex-list" id="ab-top-pairs">\u2014</div>
      </div>
    `,e.prepend(t)}if(!document.getElementById("nft-mint-card")){let t=document.createElement("section");t.className="widget-card",t.id="nft-mint-card",t.setAttribute("aria-label","NFT minting"),t.innerHTML=`
      <div class="widget-header">
        <span class="widget-title">\u{1F3A8} NFT Minting</span>
        <span class="widget-tag mono cut" id="nft-badge">Waiting\u2026</span>
      </div>
      <p class="widget-help">
        NFTokenMint and NFTokenBurn per ledger (live stream). Shows both mints and burns so you can spot churn/spam.
      </p>
      <div style="height:110px;margin-bottom:10px;"><canvas id="chart-nft-mints" class="mini-chart"></canvas></div>
      <div style="height:90px;"><canvas id="chart-nft-burns" class="mini-chart"></canvas></div>
      <div class="dex-mini" style="margin-top:10px;">
        <div><span>Mints</span><b class="mono" id="nft-mints-now">\u2014</b></div>
        <div><span>Burns</span><b class="mono" id="nft-burns-now">\u2014</b></div>
        <div><span>Net</span><b class="mono" id="nft-net-now">\u2014</b></div>
      </div>
    `,e.prepend(t)}if(!document.getElementById("market-card")){let t=document.createElement("section");t.className="widget-card",t.id="market-card",t.setAttribute("aria-label","Market history"),t.innerHTML=`
      <div class="widget-header">
        <span class="widget-title">\u{1F4B9} Market History</span>
        <span class="widget-tag mono cut" id="mkt-badge">Loading\u2026</span>
      </div>
      <p class="widget-help">
        Client-only hourly history (public APIs). Updates every 5 minutes. If history is unavailable, falls back to current tick.
      </p>
      <div style="height:130px;"><canvas id="chart-market-price" class="mini-chart"></canvas></div>
      <div style="height:90px;margin-top:10px;"><canvas id="chart-market-vol" class="mini-chart"></canvas></div>
      <div class="dex-mini" style="margin-top:10px;">
        <div><span>Price</span><b class="mono" id="mkt-price">\u2014</b></div>
        <div><span>~24h</span><b class="mono" id="mkt-chg">\u2014</b></div>
        <div><span>Updated</span><b class="mono" id="mkt-upd">\u2014</b></div>
      </div>
    `,e.prepend(t)}}}function yv(){fe.dexPressure=[],fe.nftMints=[],fe.nftBurns=[],fe.autoBridge=[],Ei.clear(),Object.keys(Ai).forEach(e=>delete Ai[e]),su({offerTotal:null,dexCancelPct:null,dexTopSharePct:null,mints:null,burns:null,pathPays:null,topPathActors:[],topPathPairs:[]})}function rs(e,t,n){for(e.push(Number(t||0));e.length>n;)e.shift()}function wv(e){var n,s,a,o;let t=e==null?void 0:e.advanced;t&&(rs(fe.dexPressure,t.offerTotal,pg),rs(fe.nftMints,t.mints,mp),rs(fe.nftBurns,t.burns,mp),rs(fe.autoBridge,t.pathPays,ug),su(t),(n=we.dexPressure)==null||n.draw(fe.dexPressure),(s=we.nftMints)==null||s.draw(fe.nftMints),(a=we.nftBurns)==null||a.draw(fe.nftBurns),(o=we.autoBridge)==null||o.draw(fe.autoBridge))}function su(e){var t,n,s;if(document.getElementById("dex-pressure-card")&&(V("dexP-badge",e.offerTotal==null?"Waiting\u2026":`${e.offerTotal} offer tx`),V("dexP-now",e.offerTotal==null?"\u2014":e.offerTotal),V("dexP-cancel",e.dexCancelPct==null?"\u2014":`${e.dexCancelPct}%`),V("dexP-share",e.dexTopSharePct==null?"\u2014":`${e.dexTopSharePct}%`)),document.getElementById("autobridge-card")){V("ab-badge",e.pathPays==null?"Waiting\u2026":`${e.pathPays} path pays`),V("ab-now",e.pathPays==null?"\u2014":e.pathPays);let a=(t=e.topPathActors)==null?void 0:t[0];V("ab-top-actor",a?W(a.acct):"\u2014"),V("ab-pairs",(n=e.topPathPairs)!=null&&n.length?e.topPathPairs.length:"\u2014");let o=x("ab-top-pairs");o&&(o.innerHTML=(s=e.topPathPairs)!=null&&s.length?e.topPathPairs.map(i=>`
          <div class="dex-rowline">
            <span class="mono cut">${y(W(i.from))}</span>
            <span style="opacity:.7">\u2192</span>
            <span class="mono cut">${y(W(i.to))}</span>
            <span class="mono">${i.count}</span>
          </div>`).join(""):'<div style="opacity:.7">\u2014</div>')}if(document.getElementById("nft-mint-card")){let a=Number(e.mints||0)-Number(e.burns||0);V("nft-badge",e.mints==null&&e.burns==null?"Waiting\u2026":`${e.mints||0} mints \xB7 ${e.burns||0} burns`),V("nft-mints-now",e.mints==null?"\u2014":e.mints),V("nft-burns-now",e.burns==null?"\u2014":e.burns),V("nft-net-now",`${a}`)}}function Ja({force:e=!1}={}){if(!Jt()){Oi();return}un&&!e||(un&&(clearInterval(un),un=null),Fp(),un=setInterval(()=>{Jt()&&Fp()},mg))}function Oi(){un&&(clearInterval(un),un=null)}async function Fp(){var t,n,s,a,o,i,r,l,c,d;let e=++Ti;V("mkt-badge","Loading\u2026");try{let p=await fetch("https://api.exchange.coinbase.com/products/XRP-USD/candles?granularity=3600",{cache:"no-store"});if(!p.ok)throw new Error("market history failed");let m=await p.json();if(!Array.isArray(m)||m.length<10)throw new Error("no history");if(e!==Ti)return;let f=[...m].sort((k,$)=>Number(k[0])-Number($[0])),g=f.map(k=>Number(k[4])).filter(Number.isFinite),b=f.map(k=>Number(k[5])).filter(Number.isFinite);fe.marketPrice=g.slice(-Ba),fe.marketVol=b.slice(-Ba);let h=fe.marketPrice.at(-1),v=fe.marketPrice.length>24?fe.marketPrice.at(-25):fe.marketPrice.at(0),w=v&&h?(h-v)/v*100:null;V("mkt-badge",h?`$${h.toFixed(4)}`:"\u2014"),V("mkt-price",h?`$${h.toFixed(4)}`:"\u2014"),V("mkt-chg",w==null?"\u2014":vn(w,2)),V("mkt-upd",new Date().toLocaleTimeString()),(t=we.marketPrice)==null||t.draw(fe.marketPrice),(n=we.marketVol)==null||n.draw(fe.marketVol);return}catch{}try{let u=await fetch("https://api.coinpaprika.com/v1/tickers/xrp-xrp",{cache:"no-store"});if(!u.ok)throw new Error("tick failed");let p=await u.json();if(e!==Ti)return;let m=Number((a=(s=p==null?void 0:p.quotes)==null?void 0:s.USD)==null?void 0:a.price),f=Number((i=(o=p==null?void 0:p.quotes)==null?void 0:o.USD)==null?void 0:i.volume_24h),g=Number((l=(r=p==null?void 0:p.quotes)==null?void 0:r.USD)==null?void 0:l.percent_change_24h);Number.isFinite(m)&&(rs(fe.marketPrice,m,Ba),Number.isFinite(f)&&rs(fe.marketVol,f,Ba)),V("mkt-badge",Number.isFinite(m)?`$${m.toFixed(4)}`:"\u2014"),V("mkt-price",Number.isFinite(m)?`$${m.toFixed(4)}`:"\u2014"),V("mkt-chg",Number.isFinite(g)?`${g>=0?"\u2191":"\u2193"}${Math.abs(g).toFixed(2)}%`:"\u2014"),V("mkt-upd",new Date().toLocaleTimeString()),(c=we.marketPrice)==null||c.draw(fe.marketPrice),(d=we.marketVol)==null||d.draw(fe.marketVol)}catch{V("mkt-badge","Unavailable")}}function xv(){var n,s,a,o;if(Pp)return;Pp=!0;let e=document.querySelector(".dashboard-fullwidth");if(!e){e=document.createElement("div"),e.className="dashboard-fullwidth";let i=document.querySelector(".dashboard-columns");i?i.insertAdjacentElement("afterend",e):(n=document.querySelector(".dashboard-page"))==null||n.appendChild(e)}if(document.getElementById("spam-defense-card"))return;let t=document.createElement("section");t.className="widget-card",t.id="spam-defense-card",t.setAttribute("aria-label","Spam defense"),Bi(),ru(),t.innerHTML=`
    <div class="widget-header" style="flex-wrap:wrap;gap:8px">
      <span class="widget-title">\u{1F6E1}\uFE0F Spam Defense POC</span>
      <span class="widget-tag mono cut" id="spam-badge">Watching\u2026</span>
      <div style="margin-left:auto;display:flex;gap:6px;flex-wrap:wrap">
        <button class="spam-btn" onclick="exportSpamReputation()" title="Export full reputation list as JSON">\u2B07 Export</button>
        <label class="spam-btn" style="cursor:pointer" title="Import a previously exported reputation file">
          \u2B06 Import<input type="file" accept=".json" style="display:none" onchange="importSpamReputation(this.files[0]);this.value=''">
        </label>
        <button class="spam-btn" id="spam-sim-toggle" onclick="_toggleBondSim()">\u{1F4D0} Bond Sim</button>
      </div>
    </div>
    <p class="widget-help">
      Deterministic <b>ratchet level</b> + <b>XRPL-native SHA-512Half on-ledger credential</b> concept.
      Proof hashes use <b>SHA-512Half</b> \u2014 the same algorithm XRPL uses for transaction and ledger hashes.
      XRPL fees are network-wide and validator-controlled \u2014 this produces <b>provable evidence</b>
      that a gateway/relayer can enforce independently (bond + credential before service).
    </p>

    <div class="spam-summary" id="spam-summary-grid">
      <div><span>Suspects</span><b id="spam-count">\u2014</b></div>
      <div><span>Max level</span><b id="spam-maxlvl">\u2014</b></div>
      <div><span>Verified</span><b id="spam-verified">\u2014</b></div>
      <div><span>Allowlisted</span><b id="spam-allowcount">\u2014</b></div>
      <div><span>Session bonds</span><b id="spam-bondusd">\u2014</b></div>
      <div><span>Hash alg</span><b style="color:#00d4ff">SHA-512Half</b></div>
    </div>

    <!-- Bond curve simulator (hidden by default) -->
    <div id="spam-sim-panel" style="display:none;margin:12px 0;padding:12px;border-radius:14px;border:1px solid rgba(0,212,255,.15);background:rgba(0,212,255,.04)">
      <div style="font-weight:800;margin-bottom:10px;font-size:.85rem">\u{1F4D0} Bond Curve Simulator</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
        <label style="font-size:.78rem;opacity:.7">
          Base XRP (L0)
          <input type="range" id="sim-base" min="1" max="500" step="1" value="${fs}"
            oninput="_renderBondSim()" style="width:100%;margin-top:4px">
          <span id="sim-base-val" class="mono" style="font-size:.72rem">${fs} XRP</span>
        </label>
        <label style="font-size:.78rem;opacity:.7">
          Growth factor
          <input type="range" id="sim-growth" min="1.2" max="4" step="0.1" value="${hs}"
            oninput="_renderBondSim()" style="width:100%;margin-top:4px">
          <span id="sim-growth-val" class="mono" style="font-size:.72rem">${hs}\xD7</span>
        </label>
      </div>
      <div id="sim-table" class="mono" style="font-size:.78rem;display:grid;grid-template-columns:repeat(9,1fr);gap:4px;text-align:center"></div>
    </div>

    <div class="dex-subbox">
      <div class="dex-subh" style="display:flex;justify-content:space-between;align-items:center">
        <span>Suspects \u2014 ratchet levels</span>
        <span style="font-size:.72rem;opacity:.5">Click row to expand \xB7 Proof button for credential</span>
      </div>
      <div id="spam-list"></div>
    </div>

    <div class="spam-proof" id="spam-proof" style="display:none">
      <div style="font-weight:1000;margin-bottom:8px;display:flex;align-items:center;gap:10px">
        Selected proof
        <span style="font-size:.72rem;opacity:.5;font-weight:400">SHA-512Half (XRPL-native)</span>
      </div>
      <div style="margin-bottom:6px;font-size:.82rem">
        Hash: <span class="mono spam-proof-hash-display" id="spam-proof-hash" style="color:#00d4ff;word-break:break-all"></span>
      </div>
      <div style="font-size:.82rem;opacity:.85;margin-bottom:4px">Canonical proof JSON:</div>
      <pre class="mono" id="spam-proof-json" style="max-height:220px;overflow:auto"></pre>
      <div class="spam-proof-actions">
        <button class="spam-btn" id="spam-copy-hash">Copy hash</button>
        <button class="spam-btn" id="spam-copy-json">Copy JSON</button>
        <button class="spam-btn" id="spam-print-proof">\u{1F5A8} Print proof</button>
      </div>
      <div style="margin-top:12px;font-weight:1000;font-size:.9rem">Credential step (on-ledger)</div>
      <div style="margin-top:6px" id="spam-cred-step"></div>
    </div>
  `,e.appendChild(t),(s=x("spam-copy-hash"))==null||s.addEventListener("click",()=>{var i;return Op(((i=x("spam-proof-hash"))==null?void 0:i.textContent)||"")}),(a=x("spam-copy-json"))==null||a.addEventListener("click",()=>{var i;return Op(((i=x("spam-proof-json"))==null?void 0:i.textContent)||"")}),(o=x("spam-print-proof"))==null||o.addEventListener("click",Nv),_renderBondSim()}window._toggleBondSim=function(){let e=x("spam-sim-panel");if(!e)return;let t=e.style.display!=="none";e.style.display=t?"none":"";let n=x("spam-sim-toggle");n&&(n.style.color=t?"":"#00d4ff")};window._renderBondSim=function(){let e=document.getElementById("sim-base"),t=document.getElementById("sim-growth"),n=document.getElementById("sim-table");if(!n)return;let s=Number((e==null?void 0:e.value)||fs),a=Number((t==null?void 0:t.value)||hs),o=fe.marketPrice.at(-1)??null;document.getElementById("sim-base-val")&&(document.getElementById("sim-base-val").textContent=s+" XRP"),document.getElementById("sim-growth-val")&&(document.getElementById("sim-growth-val").textContent=a+"\xD7");let i="";for(let r=0;r<=Ks;r++){let l=Math.round(s*a**r),c=o?"$"+(l*o).toLocaleString(void 0,{maximumFractionDigits:0}):"",d=r<3?"#50fa7b":r<6?"#ffb86c":"#ff5555";i+=`<div style="padding:5px;border-radius:6px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07)">
      <div style="font-size:.65rem;opacity:.5">L${r}</div>
      <div style="color:${d};font-weight:800">${l>=1e3?(l/1e3).toFixed(1)+"k":l}</div>
      ${c?`<div style="font-size:.62rem;opacity:.45">${c}</div>`:""}
    </div>`}n.innerHTML=i};async function Op(e){try{await navigator.clipboard.writeText(String(e||"")),ae("Copied")}catch{ge("Copy failed (browser blocked clipboard).")}}function Vs(e){let t=ke(Number(e)||0,0,Ks);return Math.round(fs*hs**t)}function Bi(){try{let e=JSON.parse(localStorage.getItem(qp)||"[]");le.allowList=new Set(e)}catch{le.allowList=new Set}}function au(){try{localStorage.setItem(qp,JSON.stringify([...le.allowList]))}catch{}}function ou(e){Xe(e)&&(le.allowList.add(e),au(),le.byAddr.delete(e),ae(`${W(e)} added to allow-list \u2014 will no longer be flagged`))}window._spamAllowAddr=ou;function iu(){try{return JSON.parse(localStorage.getItem(jp)||"{}")}catch{return{}}}function kv(e){try{localStorage.setItem(jp,JSON.stringify(e))}catch{}}function ru(){let e=iu();for(let[t,n]of Object.entries(e))le.verifiedCache.set(t,n)}window.exportSpamReputation=function(){let e=[...le.byAddr.entries()].map(([o,i])=>({addr:o,level:i.level,strikes:i.strikes,score:+(i.score||0).toFixed(4),threatType:i.threatType||"Unknown",verified:!!i.verifiedLedger,verifiedLedger:i.verifiedLedger??null,lastSeen:i.lastSeenLedger??null})),t={v:2,network:B.currentNetwork||"xrpl-mainnet",exportedAt:new Date().toISOString(),allowList:[...le.allowList],suspects:e,policy:{bondBaseXrp:fs,bondGrowth:hs,ratchetMax:Ks}},n=new Blob([JSON.stringify(t,null,2)],{type:"application/json"}),s=URL.createObjectURL(n),a=document.createElement("a");a.href=s,a.download=`naluxrp_reputation_${new Date().toISOString().slice(0,10)}.json`,document.body.appendChild(a),a.click(),document.body.removeChild(a),URL.revokeObjectURL(s),ae("Reputation list exported")};window.importSpamReputation=function(e){if(!e)return;let t=new FileReader;t.onload=n=>{var s;try{let a=JSON.parse(n.target.result);if(!a.suspects)throw new Error("Invalid format");let o=0;for(let i of a.suspects){if(!Xe(i.addr))continue;let r=le.byAddr.get(i.addr)||{};le.byAddr.set(i.addr,{...r,level:i.level??0,strikes:i.strikes??0,score:i.score??0,threatType:i.threatType??"Unknown",verifiedLedger:i.verifiedLedger??null,lastSeenLedger:i.lastSeen??null,scoreHistory:[],signalBreakdown:{}}),o++}if((s=a.allowList)!=null&&s.length){for(let i of a.allowList)Xe(i)&&le.allowList.add(i);au()}ae(`Imported ${o} reputation entries`)}catch(a){ge("Import failed: "+a.message)}},t.readAsText(e)};function $v(e){var l,c;if(!document.getElementById("spam-defense-card"))return;let t=Pv(e),n=t.reduce((d,u)=>Math.max(d,u.level),0),s=t.filter(d=>d.verified).length,a=fe.marketPrice.at(-1)??null,o=t.reduce((d,u)=>d+Vs(u.level),0),i=a?`~$${(o*a).toLocaleString(void 0,{maximumFractionDigits:0})}`:`${o} XRP`;V("spam-count",t.length),V("spam-maxlvl",`L${n}`),V("spam-verified",s),V("spam-allowcount",le.allowList.size),V("spam-bondusd",i),V("spam-badge",t.length?`${t.length} tracked \xB7 max L${n}`:"Quiet");let r=x("spam-list");if(r&&(t.length?r.innerHTML=t.map(d=>{let u=Vs(d.level),p=a?` (~$${(u*a).toFixed(0)})`:"",m=d.level>=6?"#ff5555":d.level>=3?"#ffb86c":"#50fa7b",f=d.score>=.7?"#ff5555":d.score>=.4?"#ffb86c":"#50fa7b",g={"Payment Flooder":"#ff5555","Quote Stuffer":"#ff5555","Wash Trader":"#ff5555","DEX Bot":"#ffb86c","Arb Router":"#00d4ff","Periodic Bot":"#bd93f9"}[d.threatType]||"rgba(255,255,255,.6)",b=d.verified?`<span class="spam-cred-chip">\u2714 L${d.level} verified</span>`:"",h=Sv(d.scoreHistory||[]);return`
          <div class="spam-card" data-spam-addr="${y(d.addr)}">
            <div class="spam-card-top">
              <button class="addr-link mono spam-card-addr" data-addr="${y(d.addr)}">${y(W(d.addr))}</button>
              <div class="spam-card-actions">
                <button class="spam-btn" data-action="expand"  data-spam-addr="${y(d.addr)}">\u25BE Detail</button>
                <button class="spam-btn" data-action="proof"   data-spam-addr="${y(d.addr)}">Proof</button>
                <button class="spam-btn" data-action="allow"   data-spam-addr="${y(d.addr)}" title="Trust this address permanently">\u2713 Allow</button>
                <button class="spam-btn spam-btn-clear" data-action="clear" data-spam-addr="${y(d.addr)}">\u2715</button>
              </div>
            </div>
            <div class="spam-card-meta">
              <span class="spam-meta-chip">Level <b style="color:${m}">L${d.level}</b></span>
              <span class="spam-meta-chip">Score <b style="color:${f}">${Math.round(d.score*100)}%</b></span>
              <span class="spam-meta-chip" style="color:${g}">${y(d.threatType)}</span>
              <span class="spam-meta-chip">Bond <b>${u>=1e3?(u/1e3).toFixed(1)+"k":u} XRP${p}</b></span>
              ${b}
              <span title="Score trend \u2014 last ${(d.scoreHistory||[]).length} ledgers" style="margin-left:auto">${h}</span>
            </div>
            <!-- Expandable signal breakdown (hidden by default) -->
            <div class="spam-breakdown" id="spam-bd-${y(d.addr.slice(0,10))}" style="display:none">
              ${Tv(d.breakdown,d.strikes)}
            </div>
          </div>`}).join(""):r.innerHTML=`<div class="spam-empty">No suspects flagged \u2014 allow-list has ${Vp.size} known-good entities.</div>`),_i||Cv(),le.selectedAddr){let d=le.byAddr.get(le.selectedAddr);d?Xi(le.selectedAddr,d,e.s.ledgerIndex).then(u=>ms(u)):ms(null)}((l=document.getElementById("spam-sim-panel"))==null?void 0:l.style.display)!=="none"&&((c=window._renderBondSim)==null||c.call(window))}function Sv(e){if(!(e!=null&&e.length))return"";let t=42,n=14,s=1,a=t/Math.max(1,e.length-1),o=e.map((l,c)=>`${(c*a).toFixed(1)},${(n-2-l/s*(n-4)).toFixed(1)}`).join(" "),i=e.at(-1)??0,r=i>=.7?"#ff5555":i>=.4?"#ffb86c":"#50fa7b";return`<svg width="${t}" height="${n}" xmlns="http://www.w3.org/2000/svg" style="overflow:visible">
    <polyline points="${o}" fill="none" stroke="${r}" stroke-width="1.5" stroke-linejoin="round"/>
    <circle cx="${((e.length-1)*a).toFixed(1)}" cy="${(n-2-i/s*(n-4)).toFixed(1)}"
      r="2" fill="${r}"/>
  </svg>`}function Tv(e={},t=0){let n=[{label:"Bot timing",val:e.bot??0,desc:e.botType?`Type: ${e.botType}`:"Low variance in repeated ledger appearances"},{label:"DEX dominance",val:e.dexDom??0,desc:"Share of offer tx window controlled by this address"},{label:"Cancel pattern",val:e.cancelPat??0,desc:"Heavy OfferCancel activity relative to creates"},{label:"Ping-pong loop",val:e.pingPong??0,desc:"Bidirectional repeated payments between two addresses"},{label:"Path routing",val:e.pathRoute??0,desc:"High path-payment count \u2014 common in arb bots"},{label:"Self-transfer",val:e.selfTrade??0,desc:"Payments where sender = receiver"},{label:"Round-number pay",val:e.roundPay??0,desc:"Unusual bias toward exact round-number payment amounts"}].filter(s=>s.val>.001);return n.length?`
    <div style="margin-top:8px;border-top:1px solid rgba(255,255,255,.06);padding-top:8px">
      <div style="font-size:.7rem;opacity:.45;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">
        Signal breakdown \xB7 ${t} strike${t!==1?"s":""} accumulated
      </div>
      ${n.map(s=>{let a=Math.round(s.val*100),o=a>=30?"#ff5555":a>=15?"#ffb86c":"#50fa7b";return`<div style="margin-bottom:6px">
          <div style="display:flex;justify-content:space-between;font-size:.76rem;margin-bottom:2px">
            <span style="opacity:.8">${y(s.label)}</span>
            <span class="mono" style="color:${o}">${a}%</span>
          </div>
          <div style="height:4px;background:rgba(255,255,255,.07);border-radius:2px;overflow:hidden">
            <div style="height:100%;width:${Math.min(100,a*2.5)}%;background:${o};border-radius:2px"></div>
          </div>
          <div style="font-size:.68rem;opacity:.4;margin-top:1px">${y(s.desc)}</div>
        </div>`}).join("")}
    </div>`:'<div style="opacity:.5;font-size:.78rem;padding:6px 0">No significant signal breakdown available yet.</div>'}var _i=!1;function Cv(){_i||(_i=!0,document.addEventListener("click",e=>{var a,o,i,r;let t=(o=(a=e.target).closest)==null?void 0:o.call(a,"button[data-action][data-spam-addr]");if(!t)return;let n=t.getAttribute("data-action"),s=t.getAttribute("data-spam-addr");if(s){if(n==="proof"){let l=le.byAddr.get(s);if(!l)return;le.selectedAddr=s;let c=x("spam-proof");if(c){c.style.display="";let d=x("spam-proof-hash");d&&(d.textContent="Computing SHA-512Half\u2026")}Xi(s,l,((r=(i=B.ledgerLog)==null?void 0:i[0])==null?void 0:r.ledgerIndex)||null).then(d=>{le.selectedProof=d,ms(d)}).catch(d=>ge("Proof build failed: "+d.message));return}if(n==="clear"){le.byAddr.delete(s),le.selectedAddr===s&&ms(null),ae("Cleared from session");return}if(n==="allow"){ou(s),le.byAddr.delete(s),le.selectedAddr===s&&ms(null);return}if(n==="expand"){let l=s.slice(0,10),c=document.getElementById("spam-bd-"+l);if(!c)return;let d=c.style.display!=="none";c.style.display=d?"none":"",t.textContent=d?"\u25BE Detail":"\u25B4 Hide";return}}}))}function ms(e){let t=x("spam-proof");if(!t)return;if(!e){t.style.display="none";return}t.style.display="",V("spam-proof-hash",e.hash);let n=x("spam-proof-json");n&&(n.textContent=e.canonicalJson);let s=x("spam-cred-step");s&&(s.innerHTML=`
      <div style="opacity:.9">
        To \u201Ccredential\u201D this address at level <b>L${e.level}</b>, do:
      </div>
      <ul style="margin:8px 0 0 18px;opacity:.9">
        <li><b>EscrowCreate</b> locking <b>${e.policy.bondRequiredXrp} XRP</b> to <b>itself</b> for ~24h (strong bond; funds are locked).</li>
        <li>Include a Memo that starts with <span class="mono">${mn}</span> and then the proof hash.</li>
        <li>Alternatively (cheap): send a 1-drop self-payment with <b>DestinationTag=${ls+e.level}</b> and the same memo.</li>
      </ul>
      <div style="opacity:.75;margin-top:8px">
        This dashboard will mark it verified once it sees a matching on-ledger tx in the stream.
      </div>
    `)}function Pv(e){var o,i,r,l,c;le.allowList.size||Bi();let t=new Set;(((o=e.behavior)==null?void 0:o.bots)||[]).forEach(d=>t.add(d.acct)),(((i=e.dexPatterns)==null?void 0:i.topActor)||[]).forEach(d=>t.add(d.acct)),(((r=e.dexPatterns)==null?void 0:r.topCanceller)||[]).forEach(d=>t.add(d.acct)),(((l=e.dexPatterns)==null?void 0:l.topMaker)||[]).forEach(d=>t.add(d.acct)),(e.breadcrumbs||[]).forEach(d=>{t.add(d.from),t.add(d.to)}),(e.clusters||[]).forEach(d=>{t.add(d.hub),(d.members||[]).forEach(u=>t.add(u))}),(((c=e.advanced)==null?void 0:c.topPathActors)||[]).forEach(d=>t.add(d.acct));let n=Number(e.s.ledgerIndex||0)||null,s=e.txs||[],a=[];if(n&&n%50===0){let d=Ua*24;for(let[u,p]of le.byAddr)n-(p.lastSeenLedger||0)>d&&le.byAddr.delete(u)}for(let d of t){if(!Xe(d)||Vp.has(d)||le.allowList.has(d))continue;let{score:u,breakdown:p}=Mv(d,e),m=Lv(p),f=le.byAddr.get(d)||{strikes:0,level:0,score:0,verifiedLedger:null,lastSeenLedger:null,scoreHistory:[],threatType:"Unknown",signalBreakdown:{}},g=f.strikes||0;u>=Up?g+=1:u<=Li&&(g=Math.max(0,g-1));let b=f.lastSeenLedger||n,h=n?n-b:0;if(h>Ua&&u<Li){let S=Math.floor(h/Ua);g=Math.max(0,g-S)}let v=ke(Math.floor(g/Wp),0,Ks),w=[...f.scoreHistory||[],u].slice(-10),k=le.verifiedCache.get(d),$=f.verifiedLedger??(k==null?void 0:k.ledgerIndex)??null;$||($=Av(d,v,s,n),$&&Ev(d,v,n));let T={score:u,strikes:g,level:v,verifiedLedger:$,lastSeenLedger:n,scoreHistory:w,threatType:m,signalBreakdown:p};le.byAddr.set(d,T),a.push({addr:d,score:u,strikes:g,level:v,verified:!!$,verifiedLedger:$,scoreHistory:w,threatType:m,breakdown:p})}return a.sort((d,u)=>u.level-d.level||u.score-d.score),a.slice(0,hg)}function Lv(e){let{bot:t=0,dexDom:n=0,cancelPat:s=0,pingPong:a=0,pathRoute:o=0,selfTrade:i=0,roundPay:r=0}=e,l=n+s;return t>.25&&(e.botType==="Flood / Spam"||r>.05)?"Payment Flooder":t>.2&&l>.15?"DEX Bot":l>.3&&s>.1?"Quote Stuffer":a>.1?"Wash Trader":o>.1?"Arb Router":t>.2?"Periodic Bot":"Multi-Signal"}function Mv(e,t){var m,f,g,b,h;let n={bot:0,botType:null,dexDom:0,cancelPat:0,pingPong:0,pathRoute:0,selfTrade:0,roundPay:0},s=(((m=t.behavior)==null?void 0:m.bots)||[]).find(v=>v.acct===e);if(s){let v=ke((.35-s.cv)/.35,0,1);n.bot=+(.4*(.5+.5*v)).toFixed(3),n.botType=s.botType||"Periodic"}let a=t.dexPatterns,o=((g=(f=a==null?void 0:a.topActor)==null?void 0:f[0])==null?void 0:g.acct)===e&&a.topShare||0;o>0&&(n.dexDom=+(.3*ke((o-.2)/.4,0,1)).toFixed(3));let i=((a==null?void 0:a.topCanceller)||[]).find(v=>v.acct===e);i&&(n.cancelPat=+(.2*ke(i.count/20,0,1)).toFixed(3));let r=t.breadcrumbs||[],l=r.find(v=>v.from===e&&v.to===e);l&&(n.selfTrade=+(.2*ke(l.count/20,0,1)).toFixed(3));let c=r[0];if(c&&(c.from===e||c.to===e)){let v=r.find(w=>w.from===c.to&&w.to===c.from);v&&v.count>=3&&c.count>=3&&(n.pingPong=.15)}let d=(((b=t.advanced)==null?void 0:b.topPathActors)||[]).find(v=>v.acct===e);d&&(n.pathRoute=+(.15*ke(d.count/25,0,1)).toFixed(3));let u=(h=t.advanced)==null?void 0:h.roundnessIdx;return u!=null&&u>=45&&(d||s)&&(n.roundPay=+(.1*ke((u-45)/35,0,1)).toFixed(3)),{score:ke(n.bot+n.dexDom+n.cancelPat+n.pingPong+n.pathRoute+n.selfTrade+n.roundPay,0,1),breakdown:n}}function Av(e,t,n,s){if(!(n!=null&&n.length))return null;let a=ls+t;for(let o of n)if((o==null?void 0:o.account)===e){if(o.type==="EscrowCreate"&&o.destination===e){let i=typeof o.amountXrp=="number"?o.amountXrp:null,r=Vs(t);if(i!=null&&i>=r&&Di(o.memos).startsWith(mn))return s}if(o.type==="Payment"&&o.destination===e&&Number(o.destinationTag)===a&&Di(o.memos).startsWith(mn))return s}return null}async function Ev(e,t,n){var a;let s=le.byAddr.get(e);if(s)try{let o=await Xi(e,s,n),i=mn+o.hash;if((((a=B.ledgerLog)==null?void 0:a.flatMap(c=>c.transactions||[]))||[]).some(c=>(c==null?void 0:c.account)!==e?!1:Di(c.memos).startsWith(i))){let c=iu();c[e]={ledgerIndex:n,hash:o.hash,level:t},kv(c),le.verifiedCache.set(e,{ledgerIndex:n,hash:o.hash}),ae(`\u2714 Credential verified for ${W(e)} at L${t}`)}}catch{}}function Di(e){if(!Array.isArray(e))return"";let t=[];for(let n of e){let s=(n==null?void 0:n.Memo)||(n==null?void 0:n.memo)||null;if(!s)continue;let a=s.MemoData||s.memo_data||"";try{if(typeof a=="string"&&/^[0-9A-Fa-f]+$/.test(a)&&a.length%2===0){let o=Uint8Array.from(a.match(/../g),i=>parseInt(i,16));t.push(new TextDecoder().decode(o))}else typeof a=="string"&&t.push(a)}catch{}}return t.join(" ")}async function Xi(e,t,n){let s=t.level||0,a=Vs(s),o=fe.marketPrice.at(-1)??null,i=o?(a*o).toFixed(2):null,r={hashAlgorithm:"SHA-512Half",ratchetMax:Ks,strikesToLevel:Wp,strikeUp:Up,strikeDown:Li,decayLedgers:Ua,bondBaseXrp:fs,bondGrowthFactor:hs,bondRequiredXrp:a,bondRequiredUsd:i,credTagBase:ls,memoPrefix:mn,credentialTag:ls+s},l={v:2,hashAlg:"SHA-512Half",network:B.currentNetwork||"xrpl-mainnet",address:e,ledgerIndex:n!=null?Number(n):null,level:s,threatType:t.threatType||"Unknown",score:Number((t.score||0).toFixed(4)),strikes:Number(t.strikes||0),signalBreakdown:t.signalBreakdown||{},credential:{destinationTag:ls+s,memoFormat:mn+"<SHA-512Half-of-this-proof>",verifiedLedger:t.verifiedLedger??null},policy:r,note:"Generated by NaluXRP Spam Defense POC. Hash uses XRPL-native SHA-512Half (first 256 bits of SHA-512). A gateway or relayer policy can require the indicated bond/credential before providing service to this address.",generatedAt:new Date().toISOString()},c=JSON.stringify(l,Object.keys(l).sort(),0),d=await xg(c);l.credential.memoFormat=mn+d;let u=JSON.stringify(l,null,2);return{hash:d,canonicalJson:u,level:s,policy:r,threatType:t.threatType}}function Nv(){let e=le.selectedProof;if(!e){ge("Generate a proof first using the Proof button.");return}let t=le.selectedAddr||"\u2014",n=fe.marketPrice.at(-1)??null,s=e.policy.bondRequiredXrp,a=n?` (~$${(s*n).toFixed(0)} USD)`:"",o=e.hash.startsWith("FALLBACK")?'<div style="padding:8px 12px;background:#fff3cd;border:1px solid #f0ad4e;border-radius:4px;margin-bottom:12px">\u26A0 Hash is non-cryptographic (SubtleCrypto unavailable). Do NOT use for enforcement.</div>':"",i=window.open("","_blank","width=760,height=660");i.document.write(`<!DOCTYPE html><html><head>
    <title>NaluXRP Spam Proof \u2014 ${t}</title>
    <style>
      body{font-family:-apple-system,system-ui,sans-serif;background:#fff;color:#111;margin:36px;line-height:1.6;font-size:14px}
      h1{font-size:1.15rem;margin-bottom:4px}
      .meta{color:#555;font-size:.82rem;margin-bottom:18px}
      .section{margin-bottom:16px}
      .section-h{font-weight:700;font-size:.85rem;border-bottom:2px solid #eee;padding-bottom:4px;margin-bottom:8px}
      .hash-box{font-family:monospace;font-size:.76rem;word-break:break-all;background:#f0f8ff;
                border:1px solid #c0d8f0;padding:10px;border-radius:4px;margin:6px 0;color:#005080}
      pre{font-family:monospace;font-size:.72rem;background:#f8f8f8;padding:12px;border-radius:4px;
          max-height:320px;overflow:auto;border:1px solid #eee;white-space:pre-wrap;word-break:break-all}
      .pill{display:inline-block;padding:2px 8px;border-radius:999px;background:#f0f0f0;
            font-size:.78rem;font-weight:700;margin-right:4px}
      button{padding:8px 18px;background:#111;color:#fff;border:none;border-radius:4px;cursor:pointer;margin-bottom:18px}
      @media print{button{display:none}}
    </style></head><body>
    <button onclick="window.print()">\u{1F5A8} Print / Save as PDF</button>
    ${o}
    <h1>\u{1F6E1}\uFE0F NaluXRP Spam Defense Proof</h1>
    <div class="meta">
      Address: <b>${t}</b> &nbsp;\xB7&nbsp;
      Level: <b>L${e.level}</b> &nbsp;\xB7&nbsp;
      Type: <b>${e.threatType||"Unknown"}</b> &nbsp;\xB7&nbsp;
      Bond: <b>${s.toLocaleString()} XRP${a}</b><br>
      Generated: ${new Date().toLocaleString()} &nbsp;\xB7&nbsp;
      Hash algorithm: <b>SHA-512Half (XRPL-native)</b>
    </div>
    <div class="section">
      <div class="section-h">SHA-512Half Proof Hash</div>
      <div class="hash-box">${e.hash}</div>
      <div style="font-size:.75rem;color:#555;margin-top:4px">
        SHA-512Half = first 256 bits of SHA-512 \u2014 same algorithm used by XRPL for transaction and ledger hashes.
      </div>
    </div>
    <div class="section">
      <div class="section-h">Credential Steps</div>
      <p style="font-size:.85rem"><b>Option A (Bond Escrow):</b> EscrowCreate from suspect address to itself,
        ${s.toLocaleString()} XRP, finish ~25,000 ledgers from now, memo = <code>${mn}${e.hash}</code></p>
      <p style="font-size:.85rem"><b>Option B (1-drop payment):</b> Payment of 1 drop to itself,
        DestinationTag = ${ls+e.level}, same memo.</p>
    </div>
    <div class="section">
      <div class="section-h">Canonical Proof JSON (v2)</div>
      <pre>${e.canonicalJson.replace(/</g,"&lt;").replace(/>/g,"&gt;")}</pre>
    </div>
    </body></html>`),i.document.close()}var lu=null;function Rv(){if(Mi)return;Mi=!0;let e=document.querySelector('[aria-label="Pattern detection"]');if(!e){e=document.createElement("section"),e.className="widget-card",e.setAttribute("aria-label","Pattern detection");let t=document.querySelector(".dashboard-col-main");if(!t)return;let n=t.querySelector(".dashboard-metrics");n?n.insertAdjacentElement("afterend",e):t.prepend(e)}e.innerHTML=`
    <div class="widget-header">
      <span class="widget-title">&#129504; Dominant Pattern</span>
      <span class="widget-tag mono cut" id="pattern-badge">Waiting for ledger data\u2026</span>
    </div>
    <p class="widget-help">Quick "at a glance" read. If one thing dominates, patterns are easier to spot (but can be noisy).</p>
    <div class="pattern-body">
      <div class="pattern-donut-wrap">
        <canvas id="pattern-donut-canvas" width="160" height="160"></canvas>
        <div class="pattern-donut-center" id="pattern-donut-center"><span style="opacity:.45">&#8212;</span></div>
      </div>
      <div class="pattern-stats">
        <div class="pattern-stat-row"><span class="pattern-stat-k">Type</span><span class="pattern-stat-v mono" id="pattern-dom-type">&#8212;</span></div>
        <div class="pattern-stat-row"><span class="pattern-stat-k">Dominance</span><span class="pattern-stat-v mono" id="pattern-dom-pct">&#8212;</span></div>
        <div class="pattern-stat-row"><span class="pattern-stat-k">Runner-up</span><span class="pattern-stat-v mono" id="pattern-2nd-type">&#8212;</span></div>
        <div class="pattern-stat-row"><span class="pattern-stat-k">Mix (HHI)</span><span class="pattern-stat-v mono" id="pattern-hhi">&#8212;</span></div>
      </div>
    </div>`,lu=document.getElementById("pattern-donut-canvas")}function _v(e,t){if(!Mi)return;let n=typeof It<"u"?It:{},s=Object.entries(e||{}).filter(([,m])=>m>0).sort(([,m],[,f])=>f-m);if(!s.length)return;let a=s.reduce((m,[,f])=>m+f,0)||1,[o,i]=s[0],r=Math.round(i/a*100),l=s[1],c=x("pattern-badge");c&&(c.textContent=o+" \xB7 "+r+"%");let d=x("pattern-dom-type");if(d&&(d.textContent=o,d.style.color=n[o]||"rgba(255,255,255,.9)"),V("pattern-dom-pct",r+"% of ledger"),l){let m=Math.round(l[1]/a*100),f=x("pattern-2nd-type");f&&(f.textContent=l[0]+" ("+m+"%)",f.style.color=n[l[0]]||"rgba(255,255,255,.7)")}else V("pattern-2nd-type","\u2014");let u=x("pattern-hhi");u&&t!=null&&(u.textContent=t.toFixed(3),u.style.color=t>=.35?"#ff5555":t>=.25?"#ffb86c":"#50fa7b");let p=x("pattern-donut-center");p&&(p.innerHTML='<span style="color:'+(n[o]||"#fff")+';font-size:1.15rem">'+r+"%</span>"),Dv(s,a,n)}function Dv(e,t,n){let s=lu||x("pattern-donut-canvas");if(!(s!=null&&s.getContext))return;let a=s.getContext("2d"),o=s.width/2,i=s.height/2,r=Math.min(s.width,s.height)/2-6,l=r*.56;a.clearRect(0,0,s.width,s.height);let c=e.slice(0,7),d=e.slice(7).reduce((m,[,f])=>m+f,0),u=d>0?[...c,["Other",d]]:[...c],p=-Math.PI/2;for(let[m,f]of u){let g=f/t*Math.PI*2,b=ds(n[m]||"#6b7280",.88)||"#6b7280";a.beginPath(),a.moveTo(o+Math.cos(p)*l,i+Math.sin(p)*l),a.arc(o,i,r,p,p+g),a.arc(o,i,l,p+g,p,!0),a.closePath(),a.fillStyle=b,a.fill(),a.strokeStyle="rgba(0,8,20,0.85)",a.lineWidth=2,a.stroke(),p+=g}a.beginPath(),a.arc(o,i,l-1,0,Math.PI*2),a.fillStyle="rgba(0,21,36,0.94)",a.fill()}function Iv(e,t){let n=!1;for(let s of e){if((s==null?void 0:s.type)!=="Payment")continue;let a=typeof(s==null?void 0:s.amountXrp)=="number"?s.amountXrp:null;a==null||a<Bn.whaleTxXrp||(_t.unshift({ts:Date.now(),ledgerIndex:t,from:s.account||"\u2014",to:s.destination||"\u2014",amtXrp:a,hash:s.hash||""}),Qe.whaleCount++,n=!0)}if(n){for(;_t.length>gg;)_t.pop();Ov()}}function Fv(){if(Lp)return;Lp=!0;let e=document.querySelector(".dashboard-col-side");if(!e)return;let t=document.createElement("section");t.className="widget-card",t.id="whale-feed-card",t.setAttribute("aria-label","Whale alert feed"),t.innerHTML=`
    <div class="widget-header">
      <span class="widget-title">\u{1F40B} Whale Alert Feed</span>
      <span class="widget-tag mono cut" id="whale-badge">Watching\u2026</span>
    </div>
    <p class="widget-help">Payments \u2265 ${Bn.whaleTxXrp.toLocaleString()} XRP from the live stream. Click address to peek.</p>
    <div id="whale-feed-list" style="max-height:260px;overflow-y:auto">
      <div style="opacity:.5;font-size:.82rem;padding:8px 0">Watching for large transfers\u2026</div>
    </div>`,e.prepend(t)}function Ov(){let e=x("whale-feed-list");if(!e)return;let t=x("whale-badge");if(t&&(t.textContent=_t.length?`${_t.length} alerts`:"Watching\u2026"),!_t.length){e.innerHTML='<div style="opacity:.5;font-size:.82rem;padding:8px 0">No whale transactions yet.</div>';return}e.innerHTML=_t.slice(0,20).map(n=>{let s=n.amtXrp>=1e6?`${(n.amtXrp/1e6).toFixed(2)}M`:n.amtXrp>=1e3?`${(n.amtXrp/1e3).toFixed(0)}K`:n.amtXrp.toFixed(0),a=Math.floor((Date.now()-n.ts)/1e3),o=a<60?`${a}s`:a<3600?`${Math.floor(a/60)}m`:`${Math.floor(a/3600)}h`;return`<div style="border-bottom:1px solid rgba(255,255,255,.05);padding:7px 0">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">
        <span>\u{1F40B}</span><span style="font-size:.95rem;font-weight:700;color:#50fa7b">${s} XRP</span>
        <span style="font-size:.7rem;opacity:.45;margin-left:auto">${o} \xB7 #${n.ledgerIndex.toLocaleString()}</span>
      </div>
      <div style="display:flex;gap:4px;align-items:center;font-size:.74rem">
        <button class="addr-link mono cut" data-addr="${y(n.from)}" style="max-width:100px">${y(W(n.from))}</button>
        <span style="opacity:.5">\u2192</span>
        <button class="addr-link mono cut" data-addr="${y(n.to)}" style="max-width:100px">${y(W(n.to))}</button>
        ${n.hash?`<a href="https://livenet.xrpl.org/transactions/${y(n.hash)}" target="_blank" rel="noopener" style="margin-left:auto;color:var(--accent,#00d4ff);font-size:.7rem;text-decoration:none">\u{1F517}</a>`:""}
      </div>
    </div>`}).join("")}function Bv(){if(Mp)return;Mp=!0;let e=document.querySelector(".dashboard-col-main");if(!e)return;let t=document.createElement("section");t.className="widget-card",t.id="network-health-card",t.setAttribute("aria-label","Network health"),t.innerHTML=`
    <div class="widget-header">
      <span class="widget-title">\u{1F49A} Network Health Score</span>
      <span class="widget-tag mono cut" id="health-badge">\u2014</span>
    </div>
    <p class="widget-help">Composite: TPS health + fee stability + success rate + close time. Separate from the risk score (which tracks manipulation patterns).</p>
    <div style="display:flex;align-items:center;gap:16px;padding:8px 0 12px">
      <div style="text-align:center;flex-shrink:0">
        <div style="font-size:2.4rem;font-weight:900;line-height:1" id="health-score">\u2014</div>
        <div style="font-size:.65rem;text-transform:uppercase;letter-spacing:.1em;opacity:.5;margin-top:2px">/100</div>
      </div>
      <div style="flex:1"><div style="display:flex;flex-direction:column;gap:5px" id="health-bars"></div></div>
    </div>`;let n=document.getElementById("landscape-card");n?e.insertBefore(t,n):e.prepend(t)}function Xv(e){var g;if(!document.getElementById("network-health-card"))return;let t=Ht(B.tpsHistory,Yt),n=Ht(B.feeHistory,Yt),s=e.successRate!=null?Number(e.successRate):null,a=((g=e.latestLedger)==null?void 0:g.closeTimeSec)!=null?Number(e.latestLedger.closeTimeSec):null,o=t.cur!=null?ke(Math.round(Math.min(t.cur,50)/50*25),0,25):12,i=n.deltaPct!=null?ke(Math.round(25-Math.abs(n.deltaPct)/100*25),0,25):12,r=s!=null?ke(Math.round(s/100*25),0,25):12,l=a!=null?ke(Math.round(25-Math.max(0,(a-3)/7)*25),0,25):12,c=o+i+r+l,d=c>=75?"#50fa7b":c>=50?"#ffb86c":"#ff5555",u=c>=75?"Healthy":c>=50?"Degraded":"Stressed",p=x("health-score");p&&(p.textContent=c,p.style.color=d);let m=x("health-badge");m&&(m.textContent=u,m.style.color=d);let f=x("health-bars");f&&(f.innerHTML=[{label:"TPS",score:o,note:t.cur!=null?`${t.cur.toFixed(1)} tx/s`:"\u2014"},{label:"Fee Stable",score:i,note:n.deltaPct!=null?vn(n.deltaPct,0)+" vs avg":"\u2014"},{label:"Success",score:r,note:s!=null?`${s.toFixed(1)}%`:"\u2014"},{label:"Close Time",score:l,note:a!=null?`${a.toFixed(1)}s`:"\u2014"}].map(b=>{let h=b.score/25*100,v=b.score>=20?"#50fa7b":b.score>=12?"#ffb86c":"#ff5555";return`<div style="display:flex;align-items:center;gap:8px">
        <span style="font-size:.7rem;min-width:68px;opacity:.7">${b.label}</span>
        <div style="flex:1;height:5px;background:rgba(255,255,255,.08);border-radius:3px;overflow:hidden">
          <div style="height:100%;width:${h}%;background:${v};border-radius:3px"></div></div>
        <span style="font-size:.7rem;min-width:48px;text-align:right;opacity:.65">${b.note}</span>
      </div>`}).join(""))}function Hv(){if(Ap)return;Ap=!0;let e=document.querySelector(".dashboard-col-side");if(!e)return;let t=document.createElement("section");t.className="widget-card",t.id="session-stats-card",t.setAttribute("aria-label","Session stats"),t.innerHTML=`
    <div class="widget-header">
      <span class="widget-title">\u{1F4C8} Session Stats</span>
      <span class="widget-tag mono cut" id="ss-badge">\u2014</span>
    </div>
    <div class="dex-mini" style="flex-wrap:wrap;gap:8px">
      <div><span>Ledgers</span><b class="mono" id="ss-ledgers">0</b></div>
      <div><span>Total Tx</span><b class="mono" id="ss-tx">0</b></div>
      <div><span>Whale Alerts</span><b class="mono" id="ss-whales">0</b></div>
      <div><span>Fee Spikes</span><b class="mono" id="ss-feespikes">0</b></div>
      <div><span>Bots Seen</span><b class="mono" id="ss-bots">0</b></div>
      <div><span>DEX Alerts</span><b class="mono" id="ss-dexalerts">0</b></div>
      <div><span>Uptime</span><b class="mono" id="ss-time">0m</b></div>
    </div>`,e.appendChild(t)}function zv(){if(!document.getElementById("session-stats-card"))return;let e=Math.floor((Date.now()-Qe.startTime)/6e4);V("ss-ledgers",Qe.ledgersProcessed.toLocaleString()),V("ss-tx",Qe.totalTx.toLocaleString()),V("ss-whales",Qe.whaleCount),V("ss-feespikes",Qe.feeSpikes),V("ss-bots",Qe.botDetections),V("ss-dexalerts",Qe.dexAlerts),V("ss-time",`${e}m`),V("ss-badge",`${Qe.ledgersProcessed} ledgers`)}function Wv(e,t){var o,i,r,l,c,d,u,p;if(Gp=t,_t.length&&_t[0].ledgerIndex===t){let m=_t[0],f=m.amtXrp>=1e6?`${(m.amtXrp/1e6).toFixed(1)}M`:`${(m.amtXrp/1e3).toFixed(0)}K`;ae(`\u{1F40B} Whale: ${f} XRP  ${W(m.from)} \u2192 ${W(m.to)}`)}let n=Zp(),s=(o=B.feeHistory)==null?void 0:o.at(-1);s&&n&&s>n*Bn.feeSpikeMultiple&&(Qe.feeSpikes++,ge(`\u{1F525} Fee spike: ${fn(s)} (${Math.round(s/n)}\xD7 baseline)`));let a=(((i=e.behavior)==null?void 0:i.bots)||[]).filter(m=>m.cv<Bn.botCvThreshold&&m.total>8);a.length&&(Qe.botDetections=Math.max(Qe.botDetections,a.length),a[0].botType==="Flood / Spam"&&ge(`\u{1F916} Spam bot: ${W(a[0].acct)} (CV ${a[0].cv.toFixed(2)})`)),((l=(r=e.dexPatterns)==null?void 0:r.window)==null?void 0:l.cancelRatio)>=Bn.dexCancelAlert&&((d=(c=e.dexPatterns)==null?void 0:c.window)==null?void 0:d.total)>=20&&(Qe.dexAlerts++,ge(`\u{1F9E0} DEX: ${Math.round(e.dexPatterns.window.cancelRatio*100)}% cancel ratio \u2014 possible quote-stuffing`)),((p=(u=e.clusters)==null?void 0:u[0])==null?void 0:p.size)>=Bn.clusterMinSize&&ae(`\u{1F578} Cluster: ${e.clusters[0].size} wallets around ${W(e.clusters[0].hub)}`),e.friction>=75&&e.regime==="Manipulated"&&ge(`\u26A0\uFE0F Risk score: ${e.friction}/100 \u2014 ${e.regime} regime`),Xv(e.s)}function Uv(){var n,s,a,o;if(Ep)return;Ep=!0;let e=document.createElement("button");e.id="customize-btn",e.className="customize-btn",e.setAttribute("aria-pressed","false"),e.innerHTML="\u2699 Customize",(n=document.querySelector(".dashboard-header"))==null||n.appendChild(e);let t=document.createElement("div");t.id="customize-panel",t.className="customize-panel",t.setAttribute("aria-label","Dashboard customizer"),t.innerHTML=`
    <div class="customize-panel-head">
      <span class="customize-panel-title">\u2699 Customize Dashboard</span>
      <button class="customize-close" id="customize-close">\u2715</button>
    </div>
    <p class="customize-help">Drag cards to reorder \xB7 toggle visibility \xB7 changes save automatically.</p>
    <div class="customize-list" id="customize-list"></div>
    <div style="display:flex;gap:8px;margin-top:10px">
      <button class="customize-reset" id="customize-reset">Reset to default</button>
      <button class="customize-reset" id="customize-export"
        style="background:rgba(0,212,255,.08);border-color:rgba(0,212,255,.2);color:var(--accent,#00d4ff)">Export Config</button>
    </div>`,document.body.appendChild(t),e.addEventListener("click",()=>Bp()),(s=document.getElementById("customize-close"))==null||s.addEventListener("click",()=>Bp(!1)),(a=document.getElementById("customize-reset"))==null||a.addEventListener("click",()=>{try{localStorage.removeItem(Va),localStorage.removeItem(gs)}catch{}Xp(),Ii(),Hi()}),(o=document.getElementById("customize-export"))==null||o.addEventListener("click",()=>{var i;try{let r={order:JSON.parse(localStorage.getItem(Va)||"[]"),hidden:JSON.parse(localStorage.getItem(gs)||"[]"),alertConfig:Bn};(i=navigator.clipboard)==null||i.writeText(JSON.stringify(r,null,2)),ae("Config copied to clipboard")}catch{ge("Export failed")}}),Xp(),Ii()}function Bp(e){var s;let t=document.getElementById("customize-panel"),n=document.getElementById("customize-btn");!t||!n||(On=e??!On,t.classList.toggle("customize-panel--open",On),n.setAttribute("aria-pressed",String(On)),n.textContent=On?"\u2715 Close":"\u2699 Customize",On&&Hi(),(s=document.querySelector(".dashboard-col-side"))==null||s.classList.toggle("customize-mode",On))}function Gs(){var e;return[...((e=document.querySelector(".dashboard-col-side"))==null?void 0:e.querySelectorAll(":scope > .widget-card"))||[]]}function vs(e){return e.id||e.getAttribute("aria-label")||""}function jv(e){var t,n;return((n=(t=e.querySelector(".widget-title"))==null?void 0:t.textContent)==null?void 0:n.trim())||vs(e)}function Xp(){let e=document.querySelector(".dashboard-col-side");if(!e)return;let t;try{t=JSON.parse(localStorage.getItem(Va)||"null")}catch{t=null}if(!Array.isArray(t)||!t.length)return;let n=new Map(Gs().map(s=>[vs(s),s]));t.forEach(s=>{let a=n.get(s);a&&e.appendChild(a)})}function Ii(){let e;try{e=JSON.parse(localStorage.getItem(gs)||"[]")}catch{e=[]}Gs().forEach(t=>t.classList.toggle("widget-hidden",e.includes(vs(t))))}function qv(){try{localStorage.setItem(Va,JSON.stringify(Gs().map(e=>vs(e))))}catch{}}function Vv(e){let t;try{t=JSON.parse(localStorage.getItem(gs)||"[]")}catch{t=[]}t=t.includes(e)?t.filter(n=>n!==e):[...t,e];try{localStorage.setItem(gs,JSON.stringify(t))}catch{}Ii(),Hi()}function Hi(){let e=document.getElementById("customize-list");if(!e)return;let t;try{t=JSON.parse(localStorage.getItem(gs)||"[]")}catch{t=[]}e.innerHTML="",Gs().forEach(n=>{var r;let s=vs(n),a=jv(n),o=!t.includes(s),i=document.createElement("div");i.className="customize-row",i.setAttribute("draggable","true"),i.dataset.widgetId=s,i.innerHTML=`
      <span class="customize-drag-handle" title="Drag to reorder">\u283F</span>
      <span class="customize-row-title">${y(a)}</span>
      <button class="customize-vis-btn ${o?"vis-on":"vis-off"}" data-id="${y(s)}">${o?"\u{1F441} Visible":"\u{1F6AB} Hidden"}</button>`,i.addEventListener("dragstart",l=>{os=i,l.dataTransfer.effectAllowed="move",i.classList.add("customize-dragging")}),i.addEventListener("dragend",()=>{i.classList.remove("customize-dragging"),e.querySelectorAll(".customize-row").forEach(d=>d.classList.remove("customize-over"));let l=[...e.querySelectorAll(".customize-row")].map(d=>d.dataset.widgetId),c=document.querySelector(".dashboard-col-side");if(c){let d=new Map(Gs().map(u=>[vs(u),u]));l.forEach(u=>{let p=d.get(u);p&&c.appendChild(p)})}qv()}),i.addEventListener("dragover",l=>{if(l.preventDefault(),l.dataTransfer.dropEffect="move",os&&os!==i){e.querySelectorAll(".customize-row").forEach(d=>d.classList.remove("customize-over")),i.classList.add("customize-over");let c=[...e.querySelectorAll(".customize-row")];c.indexOf(os)<c.indexOf(i)?e.insertBefore(os,i.nextSibling):e.insertBefore(os,i)}}),i.addEventListener("dragleave",()=>i.classList.remove("customize-over")),i.addEventListener("drop",l=>l.preventDefault()),(r=i.querySelector(".customize-vis-btn"))==null||r.addEventListener("click",()=>Vv(s)),e.appendChild(i)})}function Gv(){if(Np)return;Np=!0;let e=document.querySelector(".dashboard-header");if(!e||document.getElementById("global-pause-btn"))return;let t=document.createElement("button");t.id="global-pause-btn",t.className="global-pause-btn",t.setAttribute("aria-pressed","false"),t.title="Pause all updates \u2014 numbers stop changing so you can read",t.innerHTML="\u23F8 Live",t.addEventListener("click",()=>{Vt=!Vt,t.setAttribute("aria-pressed",String(Vt)),t.innerHTML=Vt?"\u25B6 Paused":"\u23F8 Live",t.classList.toggle("global-pause-btn--paused",Vt),Rt=Vt&&!qs?Vt:Rt;let s=document.querySelector(".dashboard-sticky-strip");s&&s.classList.toggle("metrics-paused",Vt)});let n=document.getElementById("customize-btn");n?e.insertBefore(t,n):e.appendChild(t)}var Hp=!1;function Kv(){if(Hp)return;Hp=!0;let e=(t=0)=>{let n=document.querySelector("#risk-card .widget-header"),s=document.querySelector("#landscape-card .widget-header");if(!n&&!s&&t<20){setTimeout(()=>e(t+1),300);return}if(n&&!n.querySelector(".friction-sparkline-wrap")){let a=document.createElement("div");a.className="friction-sparkline-wrap",a.title="Risk score \u2014 last 30 ledgers",a.innerHTML='<canvas id="friction-sparkline-canvas" width="80" height="22"></canvas>',n.appendChild(a)}if(s&&!s.querySelector(".friction-sparkline-wrap")){let a=document.createElement("div");a.className="friction-sparkline-wrap",a.title="Risk score history",a.innerHTML='<canvas id="friction-sparkline-canvas-2" width="60" height="18"></canvas>',s.appendChild(a)}cu()};e()}function cu(){cs.length&&(zp("friction-sparkline-canvas",80,22),zp("friction-sparkline-canvas-2",60,18))}function zp(e,t,n){let s=document.getElementById(e);if(!(s!=null&&s.getContext))return;let a=s.getContext("2d");a.clearRect(0,0,t,n);let o=cs;if(o.length<2)return;let i=100,r=t/(o.length-1),l=o.map((g,b)=>[b*r,n-2-g.friction/i*(n-4)]),c=n-2-60/i*(n-4);a.fillStyle="rgba(255,85,85,.07)",a.fillRect(0,0,t,c);let d=a.createLinearGradient(0,0,0,n);d.addColorStop(0,"rgba(255,184,108,.35)"),d.addColorStop(1,"rgba(255,184,108,.05)"),a.beginPath(),l.forEach(([g,b],h)=>h===0?a.moveTo(g,b):a.lineTo(g,b)),a.lineTo(l.at(-1)[0],n),a.lineTo(0,n),a.closePath(),a.fillStyle=d,a.fill();let u=o.at(-1).friction,p=u<26?"#50fa7b":u<61?"#ffb86c":"#ff5555";a.beginPath(),l.forEach(([g,b],h)=>h===0?a.moveTo(g,b):a.lineTo(g,b)),a.strokeStyle=p,a.lineWidth=1.5,a.lineJoin="round",a.stroke();let[m,f]=l.at(-1);a.beginPath(),a.arc(m,f,2.5,0,Math.PI*2),a.fillStyle=p,a.fill()}window.printLandscapeReport=function(){var i,r,l,c;if(!document.getElementById("landscape-card"))return;let t=((i=document.getElementById("d2-ledger-index"))==null?void 0:i.textContent)||"\u2014",n=((r=document.getElementById("landscape-badge"))==null?void 0:r.textContent)||"",s=new Date().toLocaleString(),a=window.open("","_blank","width=860,height=700");a.document.write(`<!DOCTYPE html><html><head>
  <title>NaluXRP Landscape Report \u2014 Ledger ${t}</title>
  <style>
    body { font-family: -apple-system, system-ui, sans-serif; background:#fff; color:#111;
           margin: 40px; line-height: 1.6; font-size: 14px; }
    h1 { font-size: 1.4rem; margin-bottom: 4px; }
    .meta { color: #555; font-size: .85rem; margin-bottom: 24px; }
    .section { margin-bottom: 20px; }
    .section-h { font-size: 1rem; font-weight: 800; border-bottom: 2px solid #eee;
                 padding-bottom: 6px; margin-bottom: 10px; }
    .row { padding: 5px 0; border-bottom: 1px solid #f0f0f0; font-size: .88rem; }
    .row:last-child { border-bottom: none; }
    .watchitem { padding: 8px 10px; border-left: 3px solid #ffb86c;
                 margin-bottom: 8px; background: #fffbf3; border-radius: 0 4px 4px 0; }
    .watchitem b { font-size: .9rem; }
    .watchitem p { margin: 4px 0 0; color: #555; font-size: .82rem; }
    button { display: block; margin: 0 auto 20px;
             padding: 10px 24px; background: #111; color: #fff;
             border: none; border-radius: 6px; cursor: pointer; font-size: .9rem; }
    @media print { button { display: none; } body { margin: 20px; } }
  </style>
  </head><body>
  <button onclick="window.print()">\u{1F5A8} Print / Save as PDF</button>
  <h1>\u{1F9FE} NaluXRP Landscape Report</h1>
  <div class="meta">Ledger #${t} \xB7 ${n} \xB7 Generated ${s}</div>`);let o=[{id:"landscape-text",label:"Situation Summary"},{id:"landscape-why",label:"Why It Matters"},{id:"landscape-now",label:"What Is Happening"},{id:"landscape-watch",label:"What To Watch Next"},{id:"landscape-watchlist",label:"Who To Watch"}];for(let{id:d,label:u}of o){let p=document.getElementById(d);if(!(!p||!p.textContent.trim())){if(a.document.write(`<div class="section"><div class="section-h">${u}</div>`),d==="landscape-watchlist"){let m=p.querySelectorAll(".landscape-watchitem");if(m.length)for(let f of m){let g=((l=f.querySelector(".addr-link"))==null?void 0:l.textContent)||"\u2014",b=((c=f.querySelector(".landscape-watchwhy"))==null?void 0:c.textContent)||"";a.document.write(`<div class="watchitem"><b>${g}</b><p>${b}</p></div>`)}else a.document.write(`<div class="row">${p.textContent.trim()}</div>`)}else{let m=p.querySelectorAll(".landscape-row");if(m.length)for(let f of m)a.document.write(`<div class="row">${f.innerHTML}</div>`);else a.document.write(`<div class="row">${p.innerHTML}</div>`)}a.document.write("</div>")}}a.document.write("</body></html>"),a.document.close()};function Jv(){if(xp)return;xp=!0;let e=document.getElementById("dashboard");if(!e||document.getElementById("dash-bottom-nav"))return;let t=document.createElement("nav");t.id="dash-bottom-nav",t.setAttribute("aria-label","Dashboard quick nav"),t.innerHTML=`
    <button data-go="stream" class="bn-btn"><span>\u{1F30A}</span><small>Stream</small></button>
    <button data-go="inspector" class="bn-btn"><span>\u{1F50D}</span><small>Inspect</small></button>
    <button data-go="network" class="bn-btn"><span>\u{1F4E1}</span><small>Health</small></button>
    <button data-go="dex" class="bn-btn"><span>\u{1F9E0}</span><small>DEX</small></button>
    <button data-go="risk" class="bn-btn"><span>\u26A0\uFE0F</span><small>Risk</small></button>
  `,e.appendChild(t);let n=s=>{var a;return(a=document.querySelector(`.dash-tab[data-tab="${s}"]`))==null?void 0:a.click()};t.addEventListener("click",s=>{let a=s.target.closest("button[data-go]");if(!a)return;let o=a.dataset.go;if(o==="stream"||o==="inspector"||o==="network"){n(o);return}n("stream"),setTimeout(()=>{var r;let i=o==="dex"?"dex-pattern-card":"risk-card";(r=document.getElementById(i))==null||r.scrollIntoView({behavior:"smooth",block:"start"})},80)})}function Yv(){var a,o;if(kp)return;kp=!0;let e=document.querySelector(".dashboard-header");if(!e||document.getElementById("compactToggleBtn"))return;let t=document.createElement("button");t.id="compactToggleBtn",t.type="button",t.className="dash-accordion-toggle",t.textContent="Compact: OFF",e.appendChild(t);let n=(i,r=!0)=>{if(document.body.classList.toggle("dash-accordion",i),t.textContent=i?"Compact: ON":"Compact: OFF",r)try{localStorage.setItem(up,i?"1":"0")}catch{}if(i){let l=document.querySelector(".dashboard-col-side .widget-card");l&&l.classList.add("is-open")}else document.querySelectorAll(".dashboard-col-side .widget-card.is-open").forEach(l=>l.classList.remove("is-open"))},s=null;try{s=localStorage.getItem(up)}catch{}n(s==="1"?!0:s==="0"?!1:((o=(a=window.matchMedia)==null?void 0:a.call(window,"(max-width: 600px)"))==null?void 0:o.matches)??!1,!1),t.addEventListener("click",()=>n(!document.body.classList.contains("dash-accordion"),!0))}function Qv(){if($p)return;$p=!0;let e=document.querySelector(".dashboard-col-side");e&&e.addEventListener("click",t=>{var o,i;if(!document.body.classList.contains("dash-accordion"))return;let n=t.target;if((o=n==null?void 0:n.closest)!=null&&o.call(n,"button, a, input, textarea, select, kbd"))return;let s=(i=n==null?void 0:n.closest)==null?void 0:i.call(n,".widget-card");if(!s)return;let a=s.classList.contains("is-open");e.querySelectorAll(".widget-card.is-open").forEach(r=>{r!==s&&r.classList.remove("is-open")}),s.classList.toggle("is-open",!a)})}var Ne={lsfPasswordSpent:65536,lsfRequireDestTag:131072,lsfRequireAuth:262144,lsfDisallowXRP:524288,lsfDisableMaster:1048576,lsfNoFreeze:2097152,lsfGlobalFreeze:4194304,lsfDefaultRipple:8388608,lsfDepositAuth:16777216},du={lsfBurnable:1,lsfOnlyXRP:2,lsfTrustLine:4,lsfTransferable:8},Zv=new Set(["SetRegularKey","SignerListSet","AccountSet","AccountDelete","EscrowCreate","PaymentChannelCreate","DepositPreauth"]),bn={blackhole:"#ff5555",exchange:"#00d4ff",newWallet:"#ff79c6",issuer:"#ffb86c",wallet:"#bd93f9",other:"#8be9fd"},eb=.55,tb=.15,Ki=20,fu=946684800;function De({module:e,category:t=null,sev:n,confidence:s=null,headline:a,detail:o="",observed:i=[],alternativeExplanations:r=[],evidenceAgainstBenign:l=[],classification:c=null,hashes:d=[]}={}){return{module:e,category:t,sev:n,confidence:s,headline:a,label:a,detail:o,observed:i,alternativeExplanations:r,evidenceAgainstBenign:l,classification:c,hashes:d}}var nb=new Map([["rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy",{name:"Bitstamp",type:"exchange"}],["rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B",{name:"Bitstamp",type:"exchange"}],["rrpNnNLKrartuEqfJGpqyDwPj1BBN1ih7",{name:"Bitstamp",type:"exchange"}],["rN7n3473SaZBCG4dFL83w7PB9judJ7qdDo",{name:"Binance",type:"exchange"}],["rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh",{name:"Binance",type:"exchange"}],["rBKPS4oLSaV2KVVuHH8EpQqMGgGefGFQs7",{name:"Bitso",type:"exchange"}],["rfk5bwaKCoNU84fTzdqWQowqnNaZorDmiV",{name:"Gate.io",type:"exchange"}],["rGFuMiw48HdbnrUbkRYDTvT5i9imC5fvv9",{name:"Gate.io",type:"exchange"}],["rwYHCs2EYBMBvRXFmxDrCUSorPsuqCck7t",{name:"Kraken",type:"exchange"}],["rLHzPsX6oXkzU2qL12kHCH8G8cnZv1rBJh",{name:"Kraken",type:"exchange"}],["ra5nK24KXen9AHvsdFTKHSANinZseWnPcX",{name:"Uphold",type:"exchange"}],["rGWrZyax5eXbi5gs49MRZKkE9eKNL9p4B",{name:"Bittrex",type:"exchange"}],["rDsbeomae4FXwgQTJp9Rs64Qg9vDiTCdBv",{name:"Coinone",type:"exchange"}],["rHsMUQFzBb7S6GnQFVgNirqvHRcLpAn5dU",{name:"Bithumb",type:"exchange"}],["rMQ98K56yXJbDGv49ZSmW51sLn94Xe1mu1",{name:"Huobi",type:"exchange"}],["rHcFoo6a9qT5NHiVn1THwX3B4QF2VQKWZ",{name:"Huobi",type:"exchange"}],["rKiCet8SdvWxPXnAgYarFUXMh1zCPz432Y",{name:"Coinbase",type:"exchange"}],["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",{name:"Coinbase",type:"exchange"}],["r9mhdcT2K7FdCGDEPqfbMJwVXsXCqEr5bP",{name:"OKX",type:"exchange"}],["r32U8WFxhqEAVkKcTb1GGRR1VH2oaFdexN",{name:"OKX",type:"exchange"}],["r4GDFMLGJUKMjNEycBKPGnRSNXyNVLQLHi",{name:"Bybit",type:"exchange"}],["rBETszU65yYoFcYdRkiGqFaYmhZpHWC7sj",{name:"Bybit",type:"exchange"}],["rMWUykAmNQDaM9poSes8VLDZDDkEoutilities",{name:"KuCoin",type:"exchange"}],["rUA1S9qobBkxLqzdfGEzh5wm5KdLfbf8bx",{name:"KuCoin",type:"exchange"}],["rHtbQzmN4BDaEBnGSXp3AZaZAuZamNVsME",{name:"MEXC",type:"exchange"}],["rDN1gPWW3XQFXVJFQSiJxPHGZiRLMVSi7K",{name:"MEXC",type:"exchange"}],["rB3gZey7VWHoDokMt3tCiXBSRmaZi5xJi9",{name:"Crypto.com",type:"exchange"}],["rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq",{name:"GateHub",type:"exchange"}],["razqnFn6FqBaYBdNaGnVzmGaNE6XPRQ9bG",{name:"GateHub",type:"exchange"}],["rGQdkxNBQeQC1WTQDQ2F2QoGBZxYcMxBBg",{name:"GateHub",type:"exchange"}],["rpXTzCuXtjiPDFysxq8uNmtZBe9Xo97JbW",{name:"Bitbank",type:"exchange"}],["rsuUjfWxrACCAwGQDsNeZUhpzXf1n1NK5Z",{name:"Bitbank",type:"exchange"}],["r9oxUGJqMfMEhGBxrMJnmNvVh1LKkMv7fz",{name:"Coincheck",type:"exchange"}],["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",{name:"Genesis (Black Hole)",type:"blackhole"}],["r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59",{name:"Black Hole #2",type:"blackhole"}],["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",{name:"Genesis Wallet",type:"ripple"}],["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",{name:"Ripple Labs Ops",type:"ripple"}],["rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY",{name:"XAMAN (XUMM)",type:"wallet"}],["rBj4eVRWn6mCELVTNkVFDfGNByE9VFTM3R",{name:"XAMAN",type:"wallet"}],["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",{name:"XRPL AMM Engine",type:"dex"}],["rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz",{name:"SOLO Issuer",type:"issuer"}],["rcoreNywaoz2ZCVt2sc3JiEi7G7MpZxZgm",{name:"CORE Token",type:"issuer"}],["rhXo4TcWbLY4GqTSmscMpgZ1KMXFBi9V55",{name:"XRPL DeFi Pool",type:"issuer"}],["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",{name:"UNL Validator Set",type:"validator"}]]);function Hn(e){return nb.get(e)||null}var sb=null,ut=!1;var bs=null,pu=!1,Ui=!0;function Za(){return Ui&&B.currentPage==="dashboard"&&B.currentTab==="inspector"&&!document.hidden}async function ab(e){let t=[s=>`https://corsproxy.io/?${encodeURIComponent(s)}`,s=>`https://api.allorigins.win/raw?url=${encodeURIComponent(s)}`],n=async s=>{let a=typeof(AbortSignal==null?void 0:AbortSignal.timeout)=="function"?AbortSignal.timeout(6e3):void 0,o=await fetch(s,{mode:"cors",cache:"no-store",signal:a});if(!o.ok)throw new Error(`HTTP ${o.status}`);return await o.json()};try{return await n(e)}catch{for(let s of t)try{return await n(s(e))}catch{}throw new Error("Price feed unavailable")}}async function ob(){if(pu)return bs;pu=!0;try{let e=await ab("https://api.exchange.coinbase.com/products/XRP-USD/ticker");bs=Number((e==null?void 0:e.price)||0)||null}catch{bs=null}return bs}function yn(e){if(!bs||!e)return"";let t=e*bs;return t>=1e6?` (~$${(t/1e6).toFixed(2)}M)`:t>=1e3?` (~$${(t/1e3).toFixed(1)}K)`:` (~$${t.toFixed(2)})`}var Ys=null;function hu(){return Ys||(Ys={input:()=>document.getElementById("inspect-addr"),err:document.getElementById("inspect-err"),result:document.getElementById("inspect-result"),empty:document.getElementById("inspect-empty"),loading:document.getElementById("inspect-loading"),loadMsg:document.getElementById("inspect-loading-msg"),warn:document.getElementById("inspect-warn"),badge:document.getElementById("inspect-addr-badge"),score:document.getElementById("inspect-risk-score"),label:document.getElementById("inspect-risk-label")},Ys)}function ib(){Ys=null,hu()}function gu(){var n,s,a,o,i;My(),Ay(),Ey(),(n=x("inspect-addr"))==null||n.addEventListener("keydown",r=>{r.key==="Enter"&&ys()}),(s=x("inspect-addr"))==null||s.addEventListener("paste",()=>{setTimeout(()=>{var l;let r=(l=x("inspect-addr"))==null?void 0:l.value.trim();r&&Xe(r)&&ys()},60)});let e=r=>{let l=r==null?void 0:r.closest(".inspector-section");if(!l)return;let c=l.classList.toggle("collapsed");r.setAttribute("aria-expanded",String(!c))};(a=document.getElementById("tab-inspector"))==null||a.addEventListener("click",r=>{if(r.target.closest("button"))return;let l=r.target.closest(".section-header");l&&e(l)}),(o=document.getElementById("tab-inspector"))==null||o.addEventListener("keydown",r=>{var c,d;if(r.key!=="Enter"&&r.key!==" ")return;let l=(d=(c=r.target).closest)==null?void 0:d.call(c,".section-header");l&&(r.preventDefault(),e(l))}),(i=document.getElementById("inspector-nav"))==null||i.addEventListener("click",r=>{var d;let l=r.target.closest("[data-jump]");if(!l)return;let c=document.getElementById("section-"+l.dataset.jump);c&&(c.classList.remove("collapsed"),(d=c.querySelector(".section-header"))==null||d.setAttribute("aria-expanded","true"),c.scrollIntoView({behavior:"smooth",block:"start"})),Au(l.dataset.jump)});let t=!1;window.addEventListener("scroll",()=>{Za()&&(t||(t=!0,requestAnimationFrame(()=>{Ny(),t=!1})))},{passive:!0}),window.runInspect=ys,window.inspectorCopyAddr=_y,window.showInspectorHowTo=Dy,window.hideInspectorHowTo=Vi,ib(),By(),window.addEventListener("naluxrp:tabchange",r=>{var l;((l=r.detail)==null?void 0:l.tabId)==="inspector"&&Za()&&(Qi(),Zi(),ta(),eo())})}function vu(e){Ui=!!e,Ui||(ut=!0)}async function ys(){var a,o,i,r,l,c,d,u,p,m,f,g,b,h,v;if(!Za())return;let e=hu(),t=((a=e.input())==null?void 0:a.value.trim())||"";if([e.err,e.result,e.empty,e.warn].forEach(w=>w&&(w.style.display="none")),ut=!0,!t){e.empty&&(e.empty.style.display="");return}if(!Xe(t)){e.err&&(e.err.textContent=`\u26A0 Invalid address: ${y(t)}`,e.err.style.display="");return}if(B.connectionState!=="connected"){e.warn&&(e.warn.style.display="");return}sb=t,ut=!1;let n=w=>{e.loading&&(e.loading.style.display="",e.loadMsg&&(e.loadMsg.textContent=w))};n("Fetching account data\u2026");let s=w=>new Promise(k=>setTimeout(k,w));try{n("Fetching account data\u2026");let[w,k,$]=await Promise.all([Me({command:"account_info",account:t,ledger_index:"validated"}),Me({command:"account_offers",account:t,ledger_index:"validated"}),Me({command:"account_nfts",account:t,ledger_index:"validated"}).catch(()=>null)]);if(ut)return;let T=((o=w==null?void 0:w.result)==null?void 0:o.account_data)||{},S=((i=k==null?void 0:k.result)==null?void 0:i.offers)||[],M=((r=$==null?void 0:$.result)==null?void 0:r.account_nfts)||[];n("Fetching trustlines\u2026");let C=[],E,R=0;do{R++;let K={command:"account_lines",account:t,ledger_index:"validated",limit:400};E&&(K.marker=E);let ue=await Me(K).catch(()=>null);if(ut)return;let be=((l=ue==null?void 0:ue.result)==null?void 0:l.lines)||[];C.push(...be),E=((c=ue==null?void 0:ue.result)==null?void 0:c.marker)||null,R>1&&await s(50)}while(E&&C.length<4e3);n("Fetching account objects\u2026");let O=[],I,D=0;do{D++;let K={command:"account_objects",account:t,ledger_index:"validated",limit:400};I&&(K.marker=I);let ue=await Me(K).catch(()=>null);if(ut)return;let be=((d=ue==null?void 0:ue.result)==null?void 0:d.account_objects)||[];O.push(...be),I=((u=ue==null?void 0:ue.result)==null?void 0:u.marker)||null,D>1&&await s(50)}while(I&&O.length<2e3);n("Fetching token supply, AMM data & price\u2026");let F=15,H=C.filter(K=>K.currency&&Number(K.balance)!==0&&K.currency.startsWith("03")&&K.currency.length===40),[N,,...z]=await Promise.all([Me({command:"gateway_balances",account:t,ledger_index:"validated"}).catch(()=>null),ob(),...H.slice(0,F).map(K=>Me({command:"amm_info",amm_account:K.account,ledger_index:"validated"}).catch(()=>null))]);if(ut)return;let te=(N==null?void 0:N.result)||null,oe=new Map;H.slice(0,F).forEach((K,ue)=>{var be,ze;(ze=(be=z[ue])==null?void 0:be.result)!=null&&ze.amm&&oe.set(K.currency,z[ue].result.amm)});let pe=400,ie=250,ne=window._inspectMaxTx||5e3,ce=Math.ceil(ne/pe),G=[],Se=new Set,X=K=>{var ue,be;for(let ze of K||[]){let ft=((ue=ze.tx_json)==null?void 0:ue.hash)||((be=ze.tx)==null?void 0:be.hash)||ze.hash||null;ft&&Se.has(ft)||(ft&&Se.add(ft),G.push(ze))}},q={newestToOldestComplete:!1,oldestToNewestFetched:!1,hitTxCap:!1,hitPageCap:!1,fetchErrorOccurred:!1},se,me=0;for(let K=1;K<=ce&&G.length<ne;K++){if(me=K,ut)return;n(`Fetching transactions \u2014 page ${K} (${G.length.toLocaleString()} so far)\u2026`);let ue={command:"account_tx",account:t,limit:pe,ledger_index_min:-1,ledger_index_max:-1,forward:!1};se&&(ue.marker=se);let be=await Me(ue).catch(()=>null);if(ut)return;if(be==null&&(q.fetchErrorOccurred=!0),X((p=be==null?void 0:be.result)==null?void 0:p.transactions),se=((m=be==null?void 0:be.result)==null?void 0:m.marker)||null,!se)break;K<ce&&G.length<ne&&await s(ie)}if(q.hitTxCap=G.length>=ne,q.hitPageCap=!!se&&me>=ce,q.newestToOldestComplete=!se,G.length<ne){if(ut)return;n("Fetching oldest transactions (anchoring history start)\u2026");let K=await Me({command:"account_tx",account:t,limit:pe,ledger_index_min:-1,ledger_index_max:-1,forward:!0}).catch(()=>null);if(ut)return;K==null&&(q.fetchErrorOccurred=!0),X((f=K==null?void 0:K.result)==null?void 0:f.transactions),q.oldestToNewestFetched=K!=null&&!((g=K==null?void 0:K.result)!=null&&g.marker),await s(ie)}e.loading&&(e.loading.style.display="none");let xe=rb(G).sort((K,ue)=>(K.tx.date??0)-(ue.tx.date??0)),Te=946684800,qe=null,Fe=null,Re=q.newestToOldestComplete||q.oldestToNewestFetched;if(xe.length>0){let K=xe[0].tx;K!=null&&K.date&&(Fe=(K.date+Te)*1e3,qe=Math.floor((Date.now()-Fe)/864e5))}let Y=new Map;for(let{tx:K}of xe){if(K.TransactionType!=="OfferCreate"||!K.TakerPays||!K.TakerGets)continue;let ue=ze=>typeof ze=="string"?"XRP":`${ze.currency}+${ze.issuer||""}`,be=[ue(K.TakerPays),ue(K.TakerGets)].sort().join("\u2194");Y.set(be,(Y.get(be)||0)+1)}let he=null;if(Y.size>0){let K=[...Y.entries()].sort((nn,da)=>da[1]-nn[1])[0][0],[ue,be]=K.split("\u2194"),ze=nn=>nn==="XRP"?{currency:"XRP"}:{currency:nn.split("+")[0],issuer:nn.split("+")[1]},ft=await Me({command:"book_offers",taker_pays:ze(ue),taker_gets:ze(be),limit:20,ledger_index:"validated"}).catch(()=>null);(h=(b=ft==null?void 0:ft.result)==null?void 0:b.offers)!=null&&h.length&&(he={pair:K,offers:ft.result.offers})}let tt=[...new Set(xe.filter(({tx:K})=>K.TransactionType==="Payment"&&K.Account===t&&K.Destination).map(({tx:K})=>K.Destination))].slice(0,6),it=new Map;for(let K of tt){if(ut)return;let ue=await Me({command:"account_info",account:K,ledger_index:"validated"}).catch(()=>null),be=(v=ue==null?void 0:ue.result)==null?void 0:v.account_data;be&&it.set(K,{sequence:be.Sequence||0,balance:Number(be.Balance||0)/1e6}),await s(80)}ub(t,T,C,S,M,O,xe,{gatewayBalances:te,ammInfoMap:oe,destAgeMap:it,walletAgeDays:qe,walletCreatedTs:Fe,walletAgeVerified:Re,historyCoverage:q,liveOrderBook:he}),e.result&&(e.result.style.display="",er());let Ct=e.score?Number(e.score.textContent):null;qy(t,isNaN(Ct)?null:Ct);let Dt=window._lastAllFindings||[];Vy(t,isNaN(Ct)?null:Ct,Dt),e0(t,Dt),Gi(t)&&Ky(t,isNaN(Ct)?null:Ct),Qy()}catch(w){if(ut)return;e.loading&&(e.loading.style.display="none"),e.err&&(e.err.textContent=`Error: ${y(w.message)}`,e.err.style.display="")}}function rb(e){return e.map(t=>{let n=t.tx_json||t.tx||t.transaction||{},s=t.metadata||t.meta||{};return n.date==null&&t.date!=null&&(n.date=t.date),!n.hash&&t.hash&&(n.hash=t.hash),{tx:n,meta:s}})}function Qt(e){if(e==null)return null;if(typeof e=="string")return Number(e)/1e6;let t=Number(e.value);return Number.isFinite(t)?t:null}function ji(e){return typeof e=="string"?"XRP":(e==null?void 0:e.currency)||null}function bu(e){return typeof e=="string"&&e.length===40&&e.startsWith("03")}function Ji(e,t,n){var a,o,i,r,l,c,d,u,p,m,f,g;let s={xrpDelta:0,tokenDeltas:[],tokenDeltaMap:new Map,lpDeltas:[],lpDeltaMap:new Map};if(!((a=t==null?void 0:t.AffectedNodes)!=null&&a.length))return s;for(let b of t.AffectedNodes){let h=b.CreatedNode,v=b.ModifiedNode,w=b.DeletedNode,k=h||v||w;if(k){if(k.LedgerEntryType==="AccountRoot"){if((((o=k.FinalFields)==null?void 0:o.Account)||((i=k.NewFields)==null?void 0:i.Account))!==n)continue;let T=Number(((r=k.FinalFields||k.NewFields)==null?void 0:r.Balance)??0),S=h?0:Number(((l=k.PreviousFields)==null?void 0:l.Balance)??T),M=(T-S)/1e6;M&&(s.xrpDelta+=M);continue}if(k.LedgerEntryType==="RippleState"){let $=k.FinalFields||k.NewFields,T=(c=$==null?void 0:$.LowLimit)==null?void 0:c.issuer,S=(d=$==null?void 0:$.HighLimit)==null?void 0:d.issuer,M=T===n;if(!M&&!(S===n))continue;let E=M?1:-1,R=M?S:T,O=(u=$==null?void 0:$.Balance)==null?void 0:u.currency,I=w?0:Number(((p=$==null?void 0:$.Balance)==null?void 0:p.value)??0),D=h?0:Number(((f=(m=k.PreviousFields)==null?void 0:m.Balance)==null?void 0:f.value)??(w?((g=$==null?void 0:$.Balance)==null?void 0:g.value)??0:I)),F=(I-D)*E;if(!F||!O)continue;let H=bu(O)?s.lpDeltaMap:s.tokenDeltaMap,N=`${O}.${R}`,z=H.get(N)||{currency:O,issuer:R,delta:0};z.delta+=F,H.set(N,z)}}}return s.tokenDeltas=[...s.tokenDeltaMap.values()],s.lpDeltas=[...s.lpDeltaMap.values()],delete s.tokenDeltaMap,delete s.lpDeltaMap,s}function yu(e,t){return e.map(({tx:n,meta:s})=>{let a=Ji(n,s,t);return{txHash:n.hash,date:n.date,type:n.TransactionType,result:(s==null?void 0:s.TransactionResult)||null,xrpDelta:a.xrpDelta,tokenDeltas:a.tokenDeltas,lpDeltas:a.lpDeltas}})}function wu(e,t,n){let s=yu(e,t),a=n,o=new Array(s.length);for(let i=s.length-1;i>=0;i--){let r=a;a-=s[i].xrpDelta,o[i]={...s[i],balanceBefore:a,balanceAfter:r}}return o}var lb=[86400,3*86400],cb=.5,db=10;function xu(e,t,n,s={}){var d;let a=[],o=e.length,i=t.filter(({tx:u})=>["SetRegularKey","SignerListSet"].includes(u.TransactionType)).map(({tx:u})=>u.date).filter(u=>u!=null);for(let u of lb)for(let p=0;p<o;p++){let m=e[p];if(m.date==null||m.balanceBefore<=0)continue;let f=0,g=p,b=[];for(;g<o&&e[g].date!=null&&e[g].date-m.date<=u;)e[g].xrpDelta<0&&(f+=-e[g].xrpDelta,b.push(e[g])),g++;let h=m.balanceBefore>0?f/m.balanceBefore:0;h>=cb&&f>db&&a.push({windowSec:u,startDate:m.date,endDate:((d=e[Math.min(g,o)-1])==null?void 0:d.date)??m.date,balanceAtStart:m.balanceBefore,totalOutflowXrp:f,pctOfBalanceMoved:h,startIdx:p,endIdx:Math.min(g,o)-1,triggeredByAuthChange:i.some(v=>v<=m.date&&m.date-v<=u)})}let r=300;a.sort((u,p)=>p.pctOfBalanceMoved-u.pctOfBalanceMoved);let l=[];for(let u of a)l.some(m=>m.windowSec===u.windowSec&&u.startDate<=m.endDate+r&&u.endDate>=m.startDate-r)||l.push(u);l.sort((u,p)=>u.startDate-p.startDate);let c=s.fetchErrorOccurred?"possibly-incomplete":"complete";return l.map(u=>({...u,dataCompleteness:c}))}function pb(e,t,n,s){let a=t.slice(e.startIdx,e.endIdx+1).filter(C=>C.xrpDelta<0),o=new Set(a.map(C=>C.txHash)),i=n.filter(({tx:C})=>o.has(C.hash)&&C.TransactionType==="Payment"),r=new Set(n.filter(({tx:C})=>C.TransactionType==="Payment"&&C.Account===s&&C.date<e.startDate).map(({tx:C})=>C.Destination).filter(Boolean)),l=[...new Set(i.map(({tx:C})=>C.Destination).filter(Boolean))],c=l.filter(C=>!r.has(C)),d=l.length?c.length/l.length:null,u=new Map;for(let{tx:C}of i){let E=typeof C.Amount=="string"?Number(C.Amount)/1e6:0;u.set(C.Destination,(u.get(C.Destination)||0)+E)}let p=[...u.entries()].sort((C,E)=>E[1]-C[1]),m=e.totalOutflowXrp>0&&p[0]?p[0][1]/e.totalOutflowXrp:null,f=p.map(([C,E])=>({addr:C,xrp:E,entity:Hn(C)})),g=n.filter(({tx:C})=>C.TransactionType==="Payment"&&C.Account===s&&(C.date<e.startDate||C.date>e.endDate)&&typeof C.Amount=="string").map(({tx:C})=>Number(C.Amount)/1e6).filter(C=>C>0),b=C=>{let E=[...C].sort((R,O)=>R-O);return E.length?E[Math.floor(E.length/2)]:null},h=b(g),v=i.map(({tx:C})=>Number(C.Amount)/1e6).filter(C=>C>0),w=b(v),k=h&&w?w/h>=5:!1,$=new Map;for(let C of t.slice(e.startIdx,e.endIdx+1))for(let E of C.tokenDeltas){if(E.delta>=0)continue;let R=`${E.currency}.${E.issuer}`;$.set(R,($.get(R)||0)+-E.delta)}let T=[...$.entries()].map(([C,E])=>({key:C,amount:E})),M=t.filter(C=>C.date!=null&&C.date<e.startDate&&e.startDate-C.date<=172800).some(C=>C.xrpDelta>0&&C.tokenDeltas.some(E=>E.delta<0));return{...e,newRecipientPct:d,newDestCount:c.length,episodeDestCount:l.length,topDestShare:m,destinations:f.slice(0,5),transferSizeAnomaly:k,historicalMedianXrp:h,episodeMedianXrp:w,trustlineLiquidations:T,dexConversionPrecedingWithdrawal:M}}function ub(e,t,n,s,a,o,i,r={}){let{gatewayBalances:l=null,ammInfoMap:c=new Map,destAgeMap:d=new Map,walletAgeDays:u=null,walletCreatedTs:p=null,walletAgeVerified:m=!1,historyCoverage:f=null,liveOrderBook:g=null}=r,b=Number(t.Balance||0)/1e6,h=Number(t.OwnerCount||0),v=10+h*2,w=Number(t.Flags||0),k=t.Sequence??"\u2014",$=o.filter(Y=>Y.LedgerEntryType==="SignerList"),T=o.filter(Y=>Y.LedgerEntryType==="Escrow"),S=o.filter(Y=>Y.LedgerEntryType==="PayChannel"),M=o.filter(Y=>Y.LedgerEntryType==="DepositPreauth"),C=o.filter(Y=>Y.LedgerEntryType==="Check"),E=vb(t,w,$,i,f),R=Tu(t,w,$,i,S,T,e,b,f),O=wb(a,i,e),I=Vb(g,e),D=Cu(i,e,f||{}),F=kb(D,e),H=Pb(i,e,n,D,F,I),N=Ob(t,n,w,i),z=Bb(n,i,o,c,e),te=Nb(i),oe=Fb(i,e),pe=Rb(i,e),ie=_b(i,e),ne=Db(i),ce=Ib(i,e),G=mb(i,e,d),Se=Xb(i),X=Hb(i,e),q=zb(i,e),se=fb(i,e,n,l),me=Wb(i,e),xe=Ub(i,e),Te=jb(o,i,e),qe=qb(o),Fe=Kb(E,R,O,H,te,oe,pe,ie,ne,ce,Se);sy(e,t,b,v,h,k,Fe,u,p,m),ay(E,t,w,$,M),oy(R,S,T,C),my(G,b,me),iy(O,a),ly(H),Jb(te),Yb(oe),Qb(pe),Zb(ie),ey(ne),ty(ce),ny(te,pe,ie,ne,ce),cy(N,n),fy(se,n),hy(Se),gy(X),vy(q),dy(z,n),by(me),yy(xe),wy(Te),xy(qe),ky(I),$y(Fe,E,R,O,H,te,oe,pe,ie,ne,ce,Se,me,xe),py(n),uy(i,e),mu(i),n0(i,e,G,me),window._lastTxList=i,window._lastBalXrp=b,window._lastHistoryCoverage=f;let Re=x("inspect-report-body");Re&&(Ly(Re,e,t,b,Fe,E,R,O,H,te,oe,N,z,G,se,i,pe,ie,ne,ce,{feeAnalysis:Se,destTagAnalysis:X,pathDepthAnalysis:q,gatewayBalances:l,inboundFlowAnalysis:me,memoAnalysis:xe,escrowDepthAnalysis:Te,checkAnalysis:qe,liveBookAnalysis:I,walletAgeDays:u,walletCreatedTs:p}),mu(i,"inspect-report-activity-chart"),Zy(Fe,window._lastAllFindings||[],u,i.length),window._lastInspectResult={addr:e,riskScore:Fe,walletAgeDays:u,walletAgeVerified:m,historyCoverage:f,txCount:i.length,findings:window._lastAllFindings||[],timestamp:new Date().toISOString()},_u(),Du(e))}function mb(e,t,n=new Map){let s=new Map,a=[];for(let{tx:p,meta:m}of e){if(p.TransactionType!=="Payment"||p.Account!==t)continue;let f=p.Destination;if(!f)continue;let g=0,b=null,h=p.Amount;typeof h=="string"?g=Number(h)/1e6:h!=null&&h.value&&(b={value:Number(h.value),currency:Xn(h.currency),issuer:h.issuer});let v=Array.isArray(p.Paths)&&p.Paths.length>0,w=p.SendMax!=null,k=v||w,$=v?p.Paths.reduce((C,E)=>Math.max(C,(E||[]).length+1),1):k?2:1,T=ws(p),S={dest:f,amtXrp:g,amtToken:b,ts:T,isPathPay:k,hopCount:$,hash:p.hash||p.Hash||"",ledger:p.ledger_index||p.LedgerIndex||0,destTag:p.DestinationTag};a.push(S),s.has(f)||s.set(f,{addr:f,totalXrp:0,txCount:0,firstSeen:T,lastSeen:T,entity:Hn(f)||null,pathCount:0,maxHops:1,tokens:new Map});let M=s.get(f);if(M.totalXrp+=g,M.txCount++,M.lastSeen=Math.max(M.lastSeen,T),M.firstSeen=Math.min(M.firstSeen,T),k&&(M.pathCount++,M.maxHops=Math.max(M.maxHops,$)),b){let C=`${b.currency}.${W(b.issuer||"")}`;M.tokens.set(C,(M.tokens.get(C)||0)+b.value)}}let o=[...s.values()].sort((p,m)=>m.totalXrp-p.totalXrp||m.txCount-p.txCount).slice(0,10).map(p=>({...p,tokens:[...p.tokens.entries()].map(([m,f])=>({k:m,v:f}))})),i=o.reduce((p,m)=>p+m.totalXrp,0),r=a.filter(p=>p.isPathPay).length,l=o.filter(p=>{let m=n.get(p.addr);return m&&m.sequence<10&&p.totalXrp>10}),c=o.filter(p=>{var m;return((m=p.entity)==null?void 0:m.type)==="exchange"}),d=o.filter(p=>{var m;return((m=p.entity)==null?void 0:m.type)==="blackhole"});return{timeline:[...a].filter(p=>p.amtXrp>.01||p.amtToken).sort((p,m)=>p.ts-m.ts).slice(0,30),destinations:o,totalOut:i,totalPathPay:r,uniqueDests:s.size,exchangeDests:c,blackHoleDests:d,newWalletDests:l}}function fb(e,t,n,s=null){var T,S;let a=null;if(s!=null&&s.obligations){let M=Object.values(s.obligations);M.length===1?a=Number(M[0])||null:M.length>1&&(a=null)}let o=[],i=new Map,r=new Map,l=new Set,c=new Set(n.filter(M=>Number(M.balance)<0).map(M=>Xn(M.currency)));for(let{tx:M,meta:C}of e)if(M.Account===t&&M.TransactionType==="Payment"){((S=(T=C==null?void 0:C.AffectedNodes)==null?void 0:T.some)==null?void 0:S.call(T,O=>{var I,D,F;return((I=O.CreatedNode)==null?void 0:I.LedgerEntryType)==="AccountRoot"&&((F=(D=O.CreatedNode)==null?void 0:D.NewFields)==null?void 0:F.Account)===M.Destination}))&&M.Destination&&l.add(M.Destination);let R=M.Amount;if(typeof R=="object"&&(R!=null&&R.value)&&(R!=null&&R.currency)){let O=Xn(R.currency);if(c.has(O)){let I=Number(R.value),D=M.Destination;i.has(D)||(i.set(D,0),r.set(D,ws(M))),i.set(D,i.get(D)+I)}}}let d=[...i.entries()].sort((M,C)=>C[1]-M[1]),u=[];if(d.length>=3){let M=new Map;for(let[C,E]of d){if(E<=0)continue;let R=Math.pow(10,Math.floor(Math.log10(E))),I=(Math.round(E/R/.1)*.1*R).toPrecision(2);M.has(I)||M.set(I,[]),M.get(I).push({addr:C,amt:E})}for(let[,C]of M.entries())if(C.length>=3){let E=C.reduce((R,O)=>R+O.amt,0)/C.length;u.push({approxAmt:E,accounts:C}),o.push({sev:"warn",label:`${C.length} accounts each received ~${_(E,0)} tokens`,detail:"Highly similar token amounts suggest coordinated wallets, pre-arranged airdrop clusters, or sybil accounts."})}}let p=[...r.values()].sort();if(p.length>=5){let M=p[p.length-1]-p[0];M<3600&&p.length>=10&&o.push({sev:"warn",label:`${p.length} accounts funded within ${Math.ceil(M/60)} minutes`,detail:"Rapid token distribution to many wallets in a narrow time window. Matches pre-sale airdrop or coordinated distribution for wash trading."})}l.size>0&&o.push({sev:l.size>10?"warn":"info",label:`${l.size} account(s) created by this address`,detail:"This issuer funded the activation of these accounts. They may be controlled by the same entity."});let m=n.filter(M=>Number(M.balance)<0),f=a,g=m.reduce((M,C)=>M+Math.abs(Number(C.balance)),0),b=f??g,h=f==null&&m.length>0,v=h?` (based on ${m.length} visible trustlines \u2014 actual total supply may be higher if there are more holders)`:"",w=m.map(M=>({addr:M.account,balance:Math.abs(Number(M.balance)),currency:Xn(M.currency)})).sort((M,C)=>C.balance-M.balance).slice(0,10),k=f??g,$=k>0&&(f!=null||m.length>=50);if(w.length>=2&&$){let M=w[0].balance/k*100,C=f!=null?"":" (of visible sample)";M>50?o.push({sev:"critical",label:`Top holder controls ${M.toFixed(0)}%${C} of supply`,detail:`${W(w[0].addr)} holds ${_(w[0].balance,0)} of ${_(k,0)} total${v}. `+(f!=null?"Extreme dump risk \u2014 one wallet could sell everything.":"Check gateway_balances or a block explorer to confirm the full supply picture.")}):M>25&&o.push({sev:"warn",label:`Top holder controls ${M.toFixed(0)}%${C} of supply`,detail:`Large single-holder concentration${v}. Monitor for coordinated sell events.`});let R=w.slice(0,5).reduce((O,I)=>O+I.balance,0)/k*100;R>75&&o.push({sev:"warn",label:`Top 5 holders own ${R.toFixed(0)}%${C} of supply`,detail:`Supply heavily concentrated in a few wallets${v}. This pattern is common in pre-launch setups or tokens with limited real distribution.`})}else m.length>0&&!$&&o.push({sev:"info",label:`${m.length} trustline holder(s) visible \u2014 supply data limited`,detail:`Only ${m.length} trustlines returned by account_lines. The true holder count and total supply cannot be determined from this data alone. Use a block explorer (XRPScan, Bithomp) for a complete holder distribution.`});return o.length===0&&b===0&&o.push({sev:"info",label:"No token issuance detected",detail:"This account does not appear to be an active token issuer."}),{signals:o,totalIssued:b,holderCount:m.length,topHolders:w,mirrorGroups:u,createdAccts:[...l],distributions:d.slice(0,10),isSampleOnly:h}}var hb=new Set(["rrrrrrrrrrrrrrrrrrrrrhoLvTp","rrrrrrrrrrrrrrrrrrrrBZbvji","rrrrrrrrrrrrrrrrrNAMEtxvNvQ","rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh","r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59"]);function ku(e){return!!e&&hb.has(e)}function $u(e,t,n=[],s=[]){let a=!!(t&Ne.lsfDisableMaster),o=(e==null?void 0:e.RegularKey)||"",i=Array.isArray(n)&&n.length>0,r=ku(o);return!!(a&&r&&!i)}function Su(e,t,n=[]){let s=!!(t&Ne.lsfDefaultRipple),a=!!(t&Ne.lsfRequireAuth),o=!!(t&Ne.lsfGlobalFreeze),i=!!(t&Ne.lsfNoFreeze),r=n.filter(({tx:c})=>c.TransactionType==="TrustSet").length,l=n.filter(({tx:c})=>{var d;return c.TransactionType==="Payment"&&typeof c.Amount=="object"&&((d=c.Amount)==null?void 0:d.currency)}).length;return s||a||o||i||r>=3||l>=5}var Oe={NORMAL:"Normal",REGULAR_KEY:"Regular-Key Controlled",MULTISIG:"Multisig Controlled",BLACKHOLED:"Blackholed",RECOVERABLE:"Recoverable",MISCONFIGURED:"Potentially Misconfigured",UNKNOWN:"Unknown"},zi=4;function gb(e,t,n,s,a={}){let o=!!(t&Ne.lsfDisableMaster),i=!!e.RegularKey,r=n.length>0,l=ku(e.RegularKey),c=s.filter(({tx:g})=>g.TransactionType==="AccountSet"&&g.Account===e.Account&&(g.SetFlag===zi||g.ClearFlag===zi)).map(({tx:g})=>({date:g.date,hash:g.hash,action:g.SetFlag===zi?"disabled":"enabled"})).sort((g,b)=>(g.date??0)-(b.date??0)),d=c.some((g,b)=>g.action==="enabled"&&c.slice(0,b).some(h=>h.action==="disabled")),u=n.filter(g=>(g.SignerEntries||[]).reduce((v,w)=>{var k;return v+Number(((k=w.SignerEntry)==null?void 0:k.SignerWeight)||0)},0)<Number(g.SignerQuorum||1)),p,m,f;return u.length?(p=Oe.MISCONFIGURED,m="blocked \u2014 quorum exceeds total signer weight, unreachable as configured",f=.9):r?(p=Oe.MULTISIG,m="controlled by signer quorum",f=.85):o&&i&&l?(p=Oe.BLACKHOLED,m="none \u2014 regular key points to a provably unusable address",f=.85):o&&!i?(p=Oe.BLACKHOLED,m="none \u2014 no working key exists",f=.75):o&&i&&d?(p=Oe.RECOVERABLE,m="proven historically \u2014 master key has been re-enabled from this state before",f=.7):o&&i?(p=Oe.REGULAR_KEY,m="possible \u2014 whoever holds the regular key can re-enable the master key or act directly",f=.6):o?(p=Oe.UNKNOWN,m="undetermined",f=.3):(p=Oe.NORMAL,m="full \u2014 master key is active",f=.9),a!=null&&a.fetchErrorOccurred&&!(a!=null&&a.newestToOldestComplete)&&(f=Math.min(f,.5)),{state:p,reversibility:m,confidence:f,masterDisabled:o,hasRegularKey:i,hasSignerList:r,masterKeyHistory:c,wasEverReenabled:d,misconfiguredSignerListCount:u.length}}function vb(e,t,n,s,a={}){let o=[],i=100,r=!!(t&Ne.lsfDisableMaster),l=!!e.RegularKey,c=n.length>0,d=$u(e,t,n,s),u=Su(e,t,s),p=gb(e,t,n,s,a);{let f={[Oe.BLACKHOLED]:"info",[Oe.MISCONFIGURED]:"critical",[Oe.REGULAR_KEY]:"info",[Oe.MULTISIG]:"info",[Oe.RECOVERABLE]:"info",[Oe.NORMAL]:"ok",[Oe.UNKNOWN]:"warn"};o.push(De({module:"Security",category:"security",sev:f[p.state]||"info",confidence:p.confidence,headline:`Account Control State: ${p.state}`,detail:`Reversibility: ${p.reversibility}`,observed:[`Master key: ${p.masterDisabled?"disabled":"active"}`,`Regular key: ${p.hasRegularKey?e.RegularKey:"not set"}`,`Signer list: ${p.hasSignerList?`${n.length} list(s)`:"none"}`,p.wasEverReenabled?"Master key has been re-enabled from a disabled state at least once in fetched history":null].filter(Boolean),classification:p.state===Oe.MISCONFIGURED?"Signer quorum cannot be reached with the current signer weights as configured \u2014 this account may be functionally stuck regardless of anyone's intent.":p.state===Oe.REGULAR_KEY?"A disabled master key with an active regular key is not the same as a locked/irreversible account \u2014 the regular key holder retains full control, including the ability to re-enable the master key.":null})),p.state===Oe.BLACKHOLED&&(i-=40),p.state===Oe.MISCONFIGURED&&(i-=30),d&&u&&o.push({sev:"warn",label:"Blackholed issuer caution",detail:"This account appears issuer-like and intentionally blackholed. Sending issued tokens back here may make them unrecoverable or effectively burn them."})}if(l){let f=s.find(({tx:b})=>b.TransactionType==="SetRegularKey"),g=f&&Date.now()/1e3-ws(f.tx)<86400*30;d?o.push({sev:"info",label:"Regular key points to blackhole address",detail:e.RegularKey}):g?(o.push({sev:"warn",label:"Regular key set recently",detail:`Key: ${e.RegularKey} \u2014 changed within 30 days. Verify you intended this.`}),i-=15):o.push({sev:"info",label:"Regular key active",detail:e.RegularKey})}n.forEach(f=>{let g=f.SignerEntries||[],b=f.SignerQuorum||1;o.push({sev:"info",label:`Multisig: ${g.length} signers, quorum ${b}`,detail:g.map(h=>{var v;return W(((v=h.SignerEntry)==null?void 0:v.Account)||"")}).join(", ")})}),t&Ne.lsfGlobalFreeze&&(o.push({sev:"warn",label:"Global Freeze active",detail:"This issuer has frozen all token balances."}),i-=10),t&Ne.lsfDepositAuth&&o.push({sev:"ok",label:"Deposit Authorization enabled",detail:"Only pre-authorized senders can deposit."}),t&Ne.lsfDefaultRipple&&o.push({sev:"info",label:"Default Ripple enabled",detail:"Balances can ripple through this account (issuer behaviour)."});let m=s.filter(({tx:f})=>f.TransactionType==="AccountDelete");return m.length&&(o.push({sev:"warn",label:`${m.length} AccountDelete attempt(s)`,detail:"Account deletion was attempted."}),i-=5),t&Ne.lsfRequireAuth&&o.push({sev:"info",label:"Require Auth enabled",detail:"This account must individually approve each trustline before it can hold a balance \u2014 restricts who can hold what it issues."}),t&Ne.lsfNoFreeze&&o.push({sev:"info",label:"No Freeze enabled",detail:"This account has permanently given up the ability to freeze trustlines \u2014 an irreversible choice, typically made to reassure holders."}),t&Ne.lsfRequireDestTag&&o.push({sev:"info",label:"Require Destination Tag enabled",detail:"Payments to this account must include a destination tag \u2014 common for exchange/custodial deposit accounts."}),t&Ne.lsfDisallowXRP&&o.push({sev:"info",label:"Disallow XRP flag set",detail:"A client-side hint requesting senders avoid sending XRP to this account. Not enforced by the protocol \u2014 XRP can still be sent."}),t&Ne.lsfPasswordSpent&&o.push({sev:"info",label:"Password Spent flag set",detail:"This account has already used its one free SetRegularKey transaction; further regular-key changes will cost the standard transaction fee."}),o.length===0&&o.push({sev:"ok",label:"No security issues detected",detail:"Master key active, no regular key or signer list overrides, no risky flags set."}),{findings:o,score:Math.max(0,i),controlState:p}}function bb(e,t,n,s,a,o){let i=[],r="low",l=!!(t&Ne.lsfDisableMaster),c=$u(e,t,n,s),d=Su(e,t,s);c?(i.push({sev:"info",label:"Intentional blackhole detected",detail:`Master key is disabled and regular key ${e.RegularKey} is a known blackhole address. This is typical for a permanently locked issuer/account, not a classic drain setup.`}),d&&i.push({sev:"warn",label:"Caution: sending assets back may burn them",detail:"Because this account appears to be an intentionally blackholed issuer, sending issued tokens back to it may strand or effectively burn those tokens."})):l&&e.RegularKey&&(i.push({sev:"critical",label:"Classic drain setup detected",detail:`Master key disabled. Regular key ${e.RegularKey} controls the account. If this key was set by an attacker, funds are at risk.`}),r="critical");let u=s.filter(({tx:m})=>m.TransactionType==="SetRegularKey"&&m.Account!==e.Account);if(!c&&u.length&&(i.push({sev:"critical",label:"Regular key set by external account",detail:`${u.length} key change(s) where sender \u2260 account owner. This is unusual.`}),r="critical"),a.length){let m=a.reduce((f,g)=>f+Number(g.Amount||0)/1e6,0);i.push({sev:"warn",label:`${a.length} open payment channel(s) \u2014 ${_(m,2)} XRP locked`,detail:`Destination(s): ${a.map(f=>W(f.Destination)).join(", ")}`}),r==="low"&&(r="medium")}if(o.length){let m=o.reduce((f,g)=>f+Number(g.Amount||0)/1e6,0);i.push({sev:"info",label:`${o.length} open escrow(s) \u2014 ${_(m,2)} XRP escrowed`,detail:`Escrow(s): ${o.map(f=>f.Destination?W(f.Destination):"self-escrow").join(", ")}`})}let p=s.filter(({tx:m})=>m.TransactionType==="DepositPreauth"&&m.Authorize);return p.length>5&&(i.push({sev:"warn",label:`${p.length} DepositPreauth grants issued`,detail:"Account pre-authorized many senders. Review if all are trusted."}),r==="low"&&(r="medium")),i.length===0&&i.push({sev:"ok",label:"No compromise-risk patterns detected",detail:"Auth structure looks intact."}),{signals:i,riskLevel:r}}function yb(e,t,n,s={}){let a=wu(e,t,n),i=xu(a,e,t,s).map(c=>pb(c,a,e,t)),r=[],l="none";for(let c of i){let d=c.windowSec===86400?"24h":`${Math.round(c.windowSec/86400)}d`,u=[`${_(c.totalOutflowXrp,2)} XRP moved out (${(c.pctOfBalanceMoved*100).toFixed(0)}% of the ${_(c.balanceAtStart,2)} XRP balance at window start) within ${d}`,c.newRecipientPct!=null?`${(c.newRecipientPct*100).toFixed(0)}% of destinations (${c.newDestCount}/${c.episodeDestCount}) were first-time recipients`:null,c.topDestShare!=null?`${(c.topDestShare*100).toFixed(0)}% of the outflow went to a single destination`:null,c.transferSizeAnomaly?`Transfer sizes in this window are ${(c.episodeMedianXrp/c.historicalMedianXrp).toFixed(1)}x this account's own historical median`:null,c.trustlineLiquidations.length?`${c.trustlineLiquidations.length} token position(s) liquidated shortly before/during this window`:null,c.dexConversionPrecedingWithdrawal?"A token\u2192XRP conversion occurred in the 48h before this outflow began":null,c.triggeredByAuthChange?"A regular-key or signer-list change occurred immediately before this window":null].filter(Boolean),p=[];c.newRecipientPct!=null&&c.newRecipientPct>.7&&p.push("Nearly all destinations are first-time recipients, not established counterparties"),c.triggeredByAuthChange&&p.push("Outflow immediately follows an authorization change \u2014 the classic compromise-then-drain sequence"),c.dexConversionPrecedingWithdrawal&&c.trustlineLiquidations.length&&p.push("Assets were converted to XRP shortly before leaving, consistent with liquidating a position specifically to withdraw everything");let m=c.destinations.some(g=>g.entity),f=c.triggeredByAuthChange||c.pctOfBalanceMoved>=.9?"critical":"warn";f==="critical"?l="critical":l!=="critical"&&(l=l==="none"||l==="low"?"high":l),r.push(De({module:"Asset Drain Behavior",category:"security",sev:f,confidence:c.triggeredByAuthChange?.75:.5,headline:`${_(c.totalOutflowXrp,2)} XRP (${(c.pctOfBalanceMoved*100).toFixed(0)}% of balance) moved out within ${d}`,detail:"Sliding-window balance reconstruction flagged this as an unusually large, fast depletion.",observed:u,alternativeExplanations:["A planned, deliberate transfer by the account's own owner (exchange withdrawal, consolidation, moving to a new wallet)",m?"Destination is a known exchange or labeled entity, consistent with a routine cash-out":"Destination(s) not in the known-entity registry \u2014 inconclusive either way"],evidenceAgainstBenign:p,classification:c.triggeredByAuthChange?"Outflow following an authorization change is a strong compromise-and-drain signal, but ledger data alone cannot distinguish an attacker from an owner who changed their own key and then withdrew funds themselves.":"Large, fast depletion observed. This describes behavior, not intent \u2014 see Account Compromise Risk above for whether the account's access controls show separate signs of being compromised."}))}return r.length||r.push(De({module:"Asset Drain Behavior",category:"security",sev:"ok",headline:"No abnormal depletion detected",detail:"No window scanned showed a large, fast balance drop relative to this account's own history."})),{episodes:i,findings:r,severity:l}}var uu={low:0,medium:1,high:2,critical:3,none:-1};function Tu(e,t,n,s,a,o,i,r,l){let c=bb(e,t,n,s,a,o),d=yb(s,i,r,l),u=d.severity==="none"?"low":d.severity==="high"?"critical":d.severity,p=uu[u]>uu[c.riskLevel]?u:c.riskLevel;return{signals:[...c.signals,...d.findings],riskLevel:p,compromiseRiskLevel:c.riskLevel,assetDrainSeverity:d.severity,episodes:d.episodes}}function wb(e,t,n){let s=[],a=new Map(e.map(m=>[m.NFTokenID,m])),i=t.filter(({tx:m})=>m.TransactionType==="NFTokenCreateOffer"&&m.Account===n).filter(({tx:m})=>{let f=m.Amount;return f?typeof f=="string"?Number(f)<1e6:!1:!0});i.length&&s.push({sev:"critical",label:`${i.length} NFT offer(s) created for \u22641 XRP`,detail:"You created sell offers at near-zero price. This is a common NFT drain vector \u2014 attackers trick victims into listing their NFTs for free."});let r=t.filter(({tx:m})=>m.TransactionType==="NFTokenAcceptOffer"&&m.Account===n);r.length&&s.push({sev:"warn",label:`${r.length} NFT offer(s) accepted`,detail:"Review these transactions to confirm they were intentional sales/purchases."});let l=t.filter(({tx:m})=>m.TransactionType==="NFTokenBurn"&&m.Account===n);l.length&&s.push({sev:"warn",label:`${l.length} NFT(s) burned`,detail:"Burned NFTs cannot be recovered. Confirm these were intentional."});let c=t.filter(({tx:m})=>m.TransactionType==="NFTokenMint"&&m.Account===n),d=t.filter(({tx:m})=>m.TransactionType==="NFTokenCreateOffer"||m.TransactionType==="NFTokenAcceptOffer");c.length>0&&d.length>0&&s.push({sev:"info",label:`${c.length} NFT(s) minted \xB7 ${d.length} transfer event(s)`,detail:"This account has minting activity."});let u=e.filter(m=>m.TransferFee&&m.TransferFee>0);if(u.length){let m=u.reduce((f,g)=>f+g.TransferFee,0)/u.length;s.push({sev:"info",label:`${u.length} NFT(s) carry transfer fees (avg ${(m/1e3).toFixed(1)}%)`,detail:"These NFTs pay royalties on each transfer."})}let p=e.filter(m=>!m.URI);return p.length>2&&s.push({sev:"warn",label:`${p.length} NFT(s) have no URI / metadata`,detail:"NFTs without a URI may be spam or placeholder tokens used in scams."}),s.length===0&&e.length===0?s.push({sev:"ok",label:"No NFT activity detected",detail:"This account holds no NFTs."}):s.length===0&&s.push({sev:"ok",label:`${e.length} NFT(s) held \u2014 no risk signals`,detail:"NFT posture looks normal."}),{flags:s,nftCount:e.length,mintCount:c.length}}var Qa={tfPassive:65536,tfImmediateOrCancel:131072,tfFillOrKill:262144,tfSell:524288};function xb(e,t){var n;for(let s of(e==null?void 0:e.AffectedNodes)||[]){let a=s.CreatedNode;if((a==null?void 0:a.LedgerEntryType)==="Offer"&&((n=a.NewFields)==null?void 0:n.Account)===t)return a}return null}function Cu(e,t,n={}){var r,l,c,d,u,p,m;let s=new Map,a=[],o=n.newestToOldestComplete||n.oldestToNewestFetched?"complete":"possibly-truncated";e.forEach((f,g)=>{var E,R,O,I,D;let{tx:b,meta:h}=f;if(b.TransactionType!=="OfferCreate"||b.Account!==t||(h==null?void 0:h.TransactionResult)!=="tesSUCCESS")return;let v={currency:ji(b.TakerGets),issuer:typeof b.TakerGets=="object"?b.TakerGets.issuer:null,value:Qt(b.TakerGets)},w={currency:ji(b.TakerPays),issuer:typeof b.TakerPays=="object"?b.TakerPays.issuer:null,value:Qt(b.TakerPays)},k=xb(h,t),$=k?{gets:Qt((E=k.NewFields)==null?void 0:E.TakerGets),pays:Qt((R=k.NewFields)==null?void 0:R.TakerPays)}:null,T={gets:Math.max(0,(v.value??0)-(($==null?void 0:$.gets)??0)),pays:Math.max(0,(w.value??0)-(($==null?void 0:$.pays)??0))},S=[];for(let F of h.AffectedNodes||[]){let H=F.DeletedNode||F.ModifiedNode;if(!H||H.LedgerEntryType!=="Offer")continue;let N=(O=H.FinalFields)==null?void 0:O.Account;!N||N===t||S.push({account:N,gets:Qt((I=H.FinalFields)==null?void 0:I.TakerGets),pays:Qt((D=H.FinalFields)==null?void 0:D.TakerPays)})}let M=Number(b.Flags||0),C={offerId:`${t}:${b.Sequence}`,createHash:b.hash,createDate:b.date,createLedgerIndex:(k==null?void 0:k.LedgerIndex)||null,takerGetsOriginal:v,takerPaysOriginal:w,offerSequence:b.Sequence,replacesOfferSeq:b.OfferSequence||null,flags:{passive:!!(M&Qa.tfPassive),immediateOrCancel:!!(M&Qa.tfImmediateOrCancel),fillOrKill:!!(M&Qa.tfFillOrKill),sell:!!(M&Qa.tfSell)},expiration:b.Expiration||null,crossedAtCreation:T,counterpartiesAtCreation:S,restingAmount:$,status:k?"resting":"filled-immediately",consumedEvents:[],cancelHash:null,cancelDate:null,timeRestingSeconds:null,realizedFillPct:null,expiryUncertain:!1,dataCompleteness:o,_createIdx:g};s.set(C.offerId,C),a.push(C)});for(let f of a){if(!f.createLedgerIndex)continue;for(let h=f._createIdx+1;h<e.length;h++){let{tx:v,meta:w}=e[h];if((w==null?void 0:w.TransactionResult)!=="tesSUCCESS"&&(w==null?void 0:w.TransactionResult)!=="tecKILLED"&&!((r=w==null?void 0:w.AffectedNodes)!=null&&r.length))continue;let k=null;for(let $ of(w==null?void 0:w.AffectedNodes)||[]){let T=$.CreatedNode,S=$.ModifiedNode,M=$.DeletedNode,C=T||S||M;if(!(!C||C.LedgerEntryType!=="Offer")&&C.LedgerIndex===f.createLedgerIndex){k={node:C,kind:M?"deleted":S?"modified":"created"};break}}if(k){if(k.kind==="deleted"){let $=v.Account===t&&v.TransactionType==="OfferCancel"&&v.OfferSequence===f.offerSequence,T=v.Account===t&&v.TransactionType==="OfferCreate"&&v.OfferSequence===f.offerSequence;if($||T)f.status="cancelled",f.cancelHash=v.hash,f.cancelDate=v.date;else{let S=Ji(v,w,t);S.xrpDelta!==0||S.tokenDeltas.some(C=>C.delta!==0)?(f.status="consumed-later",f.consumedEvents.push({hash:v.hash,date:v.date,counterpartyAccount:v.Account!==t?v.Account:null})):(f.status="expired",f.expiryUncertain=!0)}f.timeRestingSeconds=(v.date??f.createDate)-f.createDate,f.dataCompleteness=f.dataCompleteness;break}if(k.kind==="modified"){let $=Qt((l=k.node.FinalFields)==null?void 0:l.TakerGets),T=Qt((c=k.node.FinalFields)==null?void 0:c.TakerPays);f.consumedEvents.push({hash:v.hash,date:v.date,counterpartyAccount:v.Account!==t?v.Account:null,gets:Math.max(0,(((d=f.restingAmount)==null?void 0:d.gets)??0)-($??0)),pays:Math.max(0,(((u=f.restingAmount)==null?void 0:u.pays)??0)-(T??0))}),f.restingAmount={gets:$,pays:T},f.status="partially-filled-then-resting"}}}if(f.status==="resting"||f.status==="partially-filled-then-resting"){let h=Math.floor(Date.now()/1e3)-fu,v=((m=(p=e[e.length-1])==null?void 0:p.tx)==null?void 0:m.date)??h;f.expiration!=null&&f.expiration<=v?(f.status="expired",f.expiryUncertain=!0):f.status="unknown-open",f.timeRestingSeconds=v-f.createDate,f.dataCompleteness}let g=f.consumedEvents.reduce((h,v)=>h+(v.gets||0),0),b=f.crossedAtCreation.gets+g;f.realizedFillPct=f.takerGetsOriginal.value?Math.min(100,b/f.takerGetsOriginal.value*100):null,delete f._createIdx}let i={total:a.length,filledImmediately:a.filter(f=>f.status==="filled-immediately").length,cancelled:a.filter(f=>f.status==="cancelled").length,consumedLater:a.filter(f=>f.status==="consumed-later").length,partiallyFilled:a.filter(f=>f.status==="partially-filled-then-resting").length,expired:a.filter(f=>f.status==="expired").length,unknownOpen:a.filter(f=>f.status==="unknown-open").length};return{byOfferId:s,list:a,stats:i}}function kb(e,t){let n=e.list,s=n.length,a=n.filter(v=>v.status==="filled-immediately").length,o=n.filter(v=>v.status==="resting"||v.status==="partially-filled-then-resting"||v.status==="unknown-open").length,i=n.filter(v=>v.status==="consumed-later").length,r=n.filter(v=>v.status==="cancelled").length,l=n.filter(v=>v.status==="expired").length,c=n.filter(v=>v.status==="unknown-open").length,d=n.map(v=>v.timeRestingSeconds).filter(v=>v!=null),u=d.length?d.reduce((v,w)=>v+w,0)/d.length:null,p=[...d].sort((v,w)=>v-w),m=p.length?p[Math.floor(p.length/2)]:null,f=n.map(v=>v.realizedFillPct).filter(v=>v!=null),g=f.length?f.reduce((v,w)=>v+w,0)/f.length:null,b=new Map;for(let v of n){let w=[v.takerGetsOriginal.currency||"?",v.takerPaysOriginal.currency||"?"].sort().join("\u2194"),k=b.get(w)||{created:0,filled:0,cancelled:0,fillPctSum:0,fillPctCount:0};k.created++,(v.status==="filled-immediately"||v.status==="consumed-later")&&k.filled++,v.status==="cancelled"&&k.cancelled++,v.realizedFillPct!=null&&(k.fillPctSum+=v.realizedFillPct,k.fillPctCount++),b.set(w,k)}for(let v of b.values())v.avgFillPct=v.fillPctCount?v.fillPctSum/v.fillPctCount:null;let h=[];if(s>=10){let v=r/s;g!=null&&g<5&&v>.5?h.push(De({module:"Offer Fill Rate",category:"liquidity",sev:"warn",confidence:.6,headline:`Low realized fill rate: ${g.toFixed(1)}% across ${s} offers`,detail:`${r} of ${s} offers were cancelled, most with minimal execution before cancellation.`,observed:[`${r} cancelled (${(v*100).toFixed(0)}%)`,`${i} consumed by a counterparty after resting`,`${l} expired/removed unfunded`,`${c} still open as of the last analyzed transaction`,`Average time resting before resolution: ${u!=null?u.toFixed(0)+"s":"unknown"}`],alternativeExplanations:["Active order management \u2014 repricing as the market moves","Automated market-making that requeues orders frequently"],evidenceAgainstBenign:g<1?["Realized fill percentage is near zero, not just below average"]:[],classification:"A low fill rate is observed. On its own this does not establish intent \u2014 see the Spoofing and Market-Maker Automation scores for further context."})):h.push(De({module:"Offer Fill Rate",category:"liquidity",sev:"ok",confidence:.7,headline:`${g!=null?g.toFixed(1)+"%":"Normal"} realized fill rate across ${s} offers`,detail:`${a} filled immediately, ${i} consumed after resting, ${r} cancelled, ${l} expired.`}))}else h.push(De({module:"Offer Fill Rate",category:"liquidity",sev:"info",headline:`Only ${s} offer(s) placed \u2014 insufficient sample for fill-rate analysis`,detail:"Need at least 10 OfferCreate transactions for a meaningful fill-rate read."}));return{createdCount:s,immediateFillCount:a,restingCount:o,laterConsumedCount:i,cancelledCount:r,expiredCount:l,unknownOpenCount:c,avgTimeRestingSeconds:u,medianTimeRestingSeconds:m,realizedFillPctOverall:g,byPair:b,findings:h}}function $b(e,t,n){let s=e.list,a=s.map(h=>h.createDate).filter(h=>h!=null).sort((h,v)=>h-v),o=h=>{if(!a.length)return 0;let v=1;for(let w=0;w<a.length;w++){let k=1;for(let $=w+1;$<a.length&&a[$]-a[w]<=h;$++)k++;v=Math.max(v,k)}return v},i={thirtySec:o(30),oneHour:o(3600)},r=s.map(h=>h.takerGetsOriginal.value).filter(h=>h!=null&&h>0),l=null;if(r.length>=Ki){let h=r.reduce((w,k)=>w+k,0)/r.length,v=Math.sqrt(r.reduce((w,k)=>w+(k-h)**2,0)/r.length);l=h>0?v/h:null}let c=[100,1e3,1e4,1e5],d=r.filter(h=>c.some(v=>Math.abs(h%v)<1e-6&&h/v>=1)).length,u=r.length?d/r.length:0,p=new Map;s.forEach(h=>{let v=[h.takerGetsOriginal.currency||"?",h.takerPaysOriginal.currency||"?"].sort().join("\u2194");p.set(v,(p.get(v)||0)+1)});let m=[...p.entries()].sort((h,v)=>v[1]-h[1])[0]||null,f=m&&s.length?m[1]/s.length:0,g=s.length?s.filter(h=>h.status==="cancelled").length/s.length:0,b=s.map(h=>h.timeRestingSeconds).filter(h=>h!=null);return{burstWindows:i,sizeCV:l,roundNumberPct:u,pairConcentration:f,dominantPair:m,cancelRatio:g,restingTimes:b,createdCount:s.length}}function Sb(e,t,n,s){let a=[],o=0,i=n.filter(({tx:u})=>u.TransactionType==="Payment"),r=new Set(i.filter(({tx:u})=>u.Account===s&&u.Destination).map(({tx:u})=>u.Destination)),l=new Set(i.filter(({tx:u})=>u.Destination===s&&u.Account).map(({tx:u})=>u.Account)),c=[...r].filter(u=>l.has(u));if(c.length>0&&i.length>=Ki){let u=c.length/r.size;if(u>tb){let p=new Set;for(let f of t.list){for(let g of f.counterpartiesAtCreation)p.add(g.account);for(let g of f.consumedEvents)g.counterpartyAccount&&p.add(g.counterpartyAccount)}let m=c.filter(f=>p.has(f));a.push(De({module:"Wash Execution",category:"market-integrity",sev:"warn",confidence:m.length?.55:.4,headline:`${c.length} round-trip payment counterpart(s) detected`,detail:`${(u*100).toFixed(1)}% of payment recipients also sent back to this account.`,observed:[`${c.length} of ${r.size} outbound recipients also sent payments back`,m.length?`${m.length} of those also traded directly on the DEX with this account`:"No overlap found with DEX trading counterparties"],alternativeExplanations:["Ordinary reciprocal business/personal payments","Exchange deposit/withdrawal cycling through the same account"],evidenceAgainstBenign:m.length?["Payment round-trip AND direct DEX trading with the same counterparty(ies)"]:[],classification:"Round-trip payment pattern observed. Cannot confirm circular multi-account flow (A\u2192B\u2192C\u2192A) from this account's history alone \u2014 that would require the counterparties' own transaction histories."})),o+=m.length?25:15}}let d=i.filter(({tx:u})=>u.Account===s&&u.Destination===s);return d.length>0&&(a.push(De({module:"Wash Execution",category:"market-integrity",sev:"critical",confidence:.85,headline:`${d.length} self-payment(s): sender = receiver`,detail:"Payments where origin and destination are the same address.",observed:[`${d.length} Payment transaction(s) with Account === Destination`],alternativeExplanations:["A no-op transaction used to mark an account active, or to test a memo/path"],evidenceAgainstBenign:d.length>2?["Repeated, not a single isolated instance"]:[],classification:"Confirmed self-payment. Creates recorded volume with zero net economic transfer \u2014 this is a fact about the transaction, not an inference."})),o+=30),a.length||a.push(De({module:"Wash Execution",category:"market-integrity",sev:"ok",headline:"No wash-execution signals",detail:`${t.list.length} offers, ${d.length} self-payments \u2014 patterns look normal.`})),{score:Math.min(100,o),findings:a,stats:{roundTrip:c.length,selfTrades:d.length}}}function Tb(e,t,n,s,a){var u;let o=[],i=0,r=t.list,l=t.byOfferId,c=0,d=0;for(let p of r){if(!p.replacesOfferSeq)continue;let m=l.get(`${s}:${p.replacesOfferSeq}`);if(!m)continue;c++;let f=m.takerPaysOriginal.value&&m.takerGetsOriginal.value?m.takerPaysOriginal.value/m.takerGetsOriginal.value:null,g=p.takerPaysOriginal.value&&p.takerGetsOriginal.value?p.takerPaysOriginal.value/p.takerGetsOriginal.value:null;f&&g&&Math.abs(g-f)/f<.02&&d++}if(c>=5&&d/c>.6&&(o.push(De({module:"Spoofing",category:"market-integrity",sev:"warn",confidence:.45,headline:`${d} of ${c} order replacements kept nearly the same price`,detail:"Cancel-and-immediately-recreate at a near-identical price, repeated \u2014 a quote-management pattern worth a closer look.",observed:[`${c} create-and-replace chains found`,`${d} replaced within 2% of the prior price`],alternativeExplanations:["Routine order refresh/repricing by an active trader or market maker","Bumping sequence to avoid an unrelated conflict"],classification:"Replacement pattern observed. On its own this is common in both legitimate quote maintenance and layering \u2014 see Market-Maker Automation for the explanatory read."})),i+=15),r.length>=10){let p=r.filter(m=>m.takerGetsOriginal.currency==="XRP"&&m.takerGetsOriginal.value!=null);if(p.length>=10){let m=p.map(v=>v.takerGetsOriginal.value).sort((v,w)=>w-v),f=m[Math.floor(m.length*.05)]||0,g=p.filter(v=>v.takerGetsOriginal.value>=f),b=g.filter(v=>v.status==="cancelled"||v.status==="expired"),h=g.length>=5?b.length/g.length:0;h>=.95&&(o.push(De({module:"Spoofing",category:"market-integrity",sev:"warn",confidence:.3,headline:`${(h*100).toFixed(0)}% of this wallet's largest orders were cancelled without meaningful fill (own-history proxy)`,detail:`${b.length} of ${g.length} top-5%-by-this-wallet's-own-size orders cancelled or expired.`,observed:["Sizing is relative to this wallet's own order history, not current book depth",`${b.length}/${g.length} cancelled or expired without fill`],alternativeExplanations:["A large order sized appropriately for a genuinely deep, liquid market","Cancelled for unrelated reasons (funding change, strategy shift)"],classification:"Own-history size proxy only \u2014 true book-depth-relative sizing and price-distance-from-executable checks need historical order-book state this app cannot reliably obtain from public XRPL nodes. Treat as a weaker signal than a book-relative measurement would be."})),i+=10)}}if((u=a==null?void 0:a.signals)!=null&&u.length)for(let p of a.signals)(p.sev==="critical"||p.sev==="warn")&&(o.push(p),i+=p.sev==="critical"?20:10);return o.length||o.push(De({module:"Spoofing",category:"market-integrity",sev:"ok",headline:"No spoofing signals",detail:"No large-order cancel pattern, replacement pattern, or live book wall detected."})),{score:Math.min(100,i),findings:o}}function Cb(e,t,n,s,a){let o=[],i=!1,r=e.cancelRatio>eb,l=e.sizeCV!=null&&e.sizeCV<.2,c=e.burstWindows.thirtySec>=8||e.burstWindows.oneHour>100,d=(a==null?void 0:a.realizedFillPctOverall)!=null&&a.realizedFillPctOverall>=5;return e.createdCount>=Ki&&r&&(l||c)?(i=!0,o.push(De({module:"Market-Maker Automation",category:"automation",sev:"info",confidence:d?.6:.4,headline:"Behavior consistent with automated market-making / quote maintenance",detail:`${(e.cancelRatio*100).toFixed(0)}% cancel ratio, ${e.sizeCV!=null?"CV "+e.sizeCV.toFixed(2):"no size-uniformity read"}, max ${e.burstWindows.thirtySec} offers/30s.`,observed:[`Cancel ratio: ${(e.cancelRatio*100).toFixed(0)}%`,e.sizeCV!=null?`Order-size coefficient of variation: ${e.sizeCV.toFixed(2)}`:null,`Burst: up to ${e.burstWindows.thirtySec} offers in 30s, ${e.burstWindows.oneHour} in 1h`,d?`Realized fill rate: ${a.realizedFillPctOverall.toFixed(1)}% \u2014 not zero, consistent with a working market-making strategy`:"Realized fill rate is low or unknown"].filter(Boolean),alternativeExplanations:["Spoofing/layering dressed up with uniform sizing to look automated"],evidenceAgainstBenign:d?[]:["Fill rate is low despite the high order volume \u2014 automation alone does not explain that combination"],classification:d?"High cancel/burst/uniformity plus a non-trivial realized fill rate is the expected signature of legitimate automated market-making. This explanation should reduce confidence in Wash Execution and Spoofing findings above, not add to them.":"High cancel/burst/uniformity WITHOUT meaningful fills is less consistent with genuine market-making \u2014 weigh the Spoofing and Wash Execution findings above accordingly."}))):o.push(De({module:"Market-Maker Automation",category:"automation",sev:"ok",headline:"No strong automation signature",detail:"Order behavior does not show the high-cancel/tight-sizing/burst pattern typical of automated market-making."})),{automationLikely:i,findings:o}}function Pb(e,t,n,s,a,o){let i=$b(s,e,t),r=Sb(i,s,e,t),l=Tb(i,s,e,t,o),c=Cb(i,s,e,t,a),d=[...r.findings,...l.findings,...c.findings,...(a==null?void 0:a.findings)||[]],u=Math.min(100,r.score+l.score),p=u===0?"clean":u<25?"low-risk":u<50?"suspicious":"high-risk";return{signals:d,score:u,verdict:p,executionScore:r.score,spoofingScore:l.score,automationLikely:c.automationLikely,stats:{creates:s.list.length,cancels:s.list.filter(m=>m.status==="cancelled").length,fills:(a==null?void 0:a.immediateFillCount)??0,payments:e.filter(({tx:m})=>m.TransactionType==="Payment").length,roundTrip:r.stats.roundTrip,selfTrades:r.stats.selfTrades}}}var Lb=[0,.301,.176,.125,.097,.079,.067,.058,.051,.046];function Mb(e){let t=new Map;for(let{tx:n}of e){let s=n.TransactionType==="Payment"?"Payment":n.TransactionType==="OfferCreate"||n.TransactionType==="OfferCancel"?"Offer":null;if(!s)continue;let a=[n.Amount,n.TakerGets,n.TakerPays,n.SendMax,n.DeliverMin];for(let o of a){let i=ji(o),r=Qt(o);if(r==null||r<=0||!Number.isFinite(r)||!i)continue;let l=`${i}|${s}`;t.has(l)||t.set(l,{currency:i,txClass:s,values:[]}),t.get(l).values.push(r)}}return t}function Ab(e){let t=e.length,n=[];if(t<50)return{level:"LOW",reasons:[`Only ${t} observations in this group (need \u226550)`],n:t};let s=[...e].sort((u,p)=>u-p),a=s[0],o=s[s.length-1],i=a>0?Math.log10(o/a):0,r=[100,1e3,1e4,1e5],c=e.filter(u=>r.some(p=>Math.abs(u%p)<1e-6&&u/p>=1)).length/t,d="HIGH";return i<1?(d="LOW",n.push(`Values span only ${i.toFixed(1)} orders of magnitude \u2014 Benford needs a wide spread to be meaningful`)):i<2&&(d="MEDIUM",n.push(`Narrow magnitude spread (${i.toFixed(1)} orders of magnitude)`)),c>.5?(d="LOW",n.push(`${(c*100).toFixed(0)}% round-number amounts \u2014 suggests fixed lot sizes or tick constraints, not organically-generated values`)):c>.25&&d==="HIGH"&&(d="MEDIUM",n.push(`${(c*100).toFixed(0)}% round-number amounts`)),t<100&&d==="HIGH"&&(d="MEDIUM",n.push(`Sample size (${t}) clears the minimum but is still modest`)),n.length||n.push("Sufficient sample size, wide magnitude spread, low round-number concentration"),{level:d,reasons:n,magnitudeSpread:i,roundPct:c,n:t}}function Eb(e){let t=e.length,n=new Array(10).fill(0);for(let o of e){let i=o.toFixed(6).replace(/^0+\.?0*/,""),r=parseInt(i[0],10);r>=1&&r<=9&&n[r]++}let s=0,a=[];for(let o=1;o<=9;o++){let i=n[o]/t,r=Lb[o];s+=t*Math.pow(i-r,2)/r,a.push({digit:o,obs:(i*100).toFixed(1),exp:(r*100).toFixed(1),delta:((i-r)*100).toFixed(1)})}return{chiSq:s,digitBreakdown:a,n:t}}function Pu(e){if((e==null?void 0:e.chiSq)==null)return 0;let t={HIGH:1,MEDIUM:.5,LOW:.15}[e.overallApplicability]??.15;return Math.min(10,e.chiSq/20.09*10)*t}function Nb(e){let t=Mb(e),n=[];for(let[i,r]of t){if(r.values.length<50)continue;let l=Ab(r.values),c=Eb(r.values);n.push({key:i,currency:r.currency,txClass:r.txClass,...c,applicability:l})}if(n.sort((i,r)=>r.n-i.n),!n.length)return{signals:[{sev:"info",label:"Insufficient data for Benford's Law",detail:"No single currency/transaction-class group reached the 50-observation minimum \u2014 amounts are too fragmented across assets to test any one distribution meaningfully."}],results:[],overallApplicability:"LOW",chiSq:null,verdict:"insufficient",digitBreakdown:[],sampleSize:0};let s=n.map(i=>De({module:"Benford's Law",category:"market-integrity",sev:i.applicability.level==="LOW"?"info":i.chiSq>20.09?"warn":"ok",confidence:{HIGH:.7,MEDIUM:.4,LOW:.15}[i.applicability.level],headline:`${i.currency==="XRP"?"XRP":W(i.currency)} ${i.txClass} amounts: \u03C7\xB2=${i.chiSq.toFixed(1)}, Applicability ${i.applicability.level}`,detail:`n=${i.n} observations`,observed:[`Benford Applicability: ${i.applicability.level}`,...i.applicability.reasons,`Chi-square statistic: ${i.chiSq.toFixed(2)} (critical values: 15.51 at p<0.05, 20.09 at p<0.01)`],classification:i.applicability.level==="LOW"?"Benford's Law is not reliably applicable to this group (narrow magnitude spread and/or high round-number concentration) \u2014 a deviation here says nothing about whether amounts were fabricated.":i.chiSq>20.09?"Amount-generation pattern is non-natural under this model. This describes the shape of the distribution, not a conclusion about intent \u2014 fixed pricing tiers, algorithmic strategies, and token denomination conventions are common legitimate causes of Benford deviation.":"First-digit distribution is consistent with organic, unconstrained amount generation."})),a=n[0],o=n.some(i=>i.applicability.level==="HIGH")?"HIGH":n.some(i=>i.applicability.level==="MEDIUM")?"MEDIUM":"LOW";return{signals:s,results:n,overallApplicability:o,chiSq:a.chiSq,verdict:a.chiSq>20.09?"high-deviation":a.chiSq>15.51?"moderate-deviation":"normal",digitBreakdown:a.digitBreakdown,sampleSize:a.n}}function Rb(e,t){let s=[],a=[];for(let{tx:b}of e){let h=[b.Amount,b.TakerGets,b.TakerPays];for(let v of h){let w=typeof v=="string"?Number(v)/1e6:v!=null&&v.value?Number(v.value):null;w&&w>0&&Number.isFinite(w)&&a.push(w)}}let o=a.length>=30?(()=>{let b=new Array(12).fill(0);for(let h of a){let v=Math.min(11,Math.max(0,Math.floor(Math.log10(h+1)*2)));b[v]++}return Qs(b)})():null,i={};for(let{tx:b}of e){let h=b.Account===t?b.Destination:b.Account;h&&h!==t&&(i[h]=(i[h]||0)+1)}let r=Object.values(i),l=r.length>=3?Qs(r):null,c=new Array(24).fill(0),d=!1;for(let{tx:b}of e)if(b.date){let v=new Date((b.date+946684800)*1e3).getUTCHours();c[v]++,d=!0}let u=d&&e.length>=30?Qs(c):null,p={};for(let{tx:b}of e)p[b.TransactionType]=(p[b.TransactionType]||0)+1;let m=Qs(Object.values(p)),f="normal",g=0;if(o!==null&&(o<1.5?(f="low-entropy",g+=18,s.push({sev:"warn",label:`Amount entropy critically low (H=${o.toFixed(2)} bits)`,detail:"Transaction amounts are highly repetitive. A bot or scripted actor tends to reuse the same values. Organic wallets show entropy \u22652.4 bits across amount magnitudes."})):o<2.2?(g+=8,s.push({sev:"info",label:`Amount entropy below natural range (H=${o.toFixed(2)} bits)`,detail:"Some amount repetition detected. Could indicate automated activity mixed with organic transactions."})):o>4.5?(g+=10,s.push({sev:"info",label:`Amount entropy abnormally high (H=${o.toFixed(2)} bits)`,detail:"Transaction amounts are maximally varied \u2014 more than organic activity typically shows. This can indicate amounts were artificially randomized to evade Benford detection."})):s.push({sev:"ok",label:`Amount entropy normal (H=${o.toFixed(2)} bits)`,detail:"Transaction amount diversity is consistent with organic financial activity."})),l!==null&&(l<1&&r.length<4?(g+=14,s.push({sev:"warn",label:`Counterparty entropy very low (H=${l.toFixed(2)} bits)`,detail:"This wallet transacts with very few unique addresses and with high repetition \u2014 a structural signature of round-trip wash trading rings."})):l<2?(g+=5,s.push({sev:"info",label:`Counterparty entropy low (H=${l.toFixed(2)} bits)`,detail:"Most interactions are concentrated among a small set of counterparties."})):s.push({sev:"ok",label:`Counterparty diversity healthy (H=${l.toFixed(2)} bits)`,detail:"Counterparty distribution reflects diverse interaction patterns."})),u!==null){let b=Math.log2(24),h=u/b;h<.45?(g+=10,s.push({sev:"warn",label:`Time-of-day entropy low (H=${u.toFixed(2)} bits, ${(h*100).toFixed(0)}% of max)`,detail:"Transactions cluster heavily in a few hours of the day. Bots typically run at fixed UTC hours; organic users spread activity across the day."})):s.push({sev:"ok",label:`Time-of-day distribution natural (H=${u.toFixed(2)} bits)`,detail:"Transaction timing is distributed across hours in a pattern consistent with human activity."})}return s.length||s.push({sev:"info",label:"Insufficient data for entropy analysis",detail:`Need \u226530 transactions. Found ${e.length}.`}),g>=18?f="anomalous":g>=8&&(f="elevated"),{signals:s,verdict:f,riskPenalty:g,amountEntropy:o,counterpartyEntropy:l,timeEntropy:u,typeEntropy:m,uniqueCounterparties:r.length,sampleSize:e.length}}function Qs(e){let t=e.reduce((n,s)=>n+s,0);return t?-e.reduce((n,s)=>{if(!s)return n;let a=s/t;return n+a*Math.log2(a)},0):0}function _b(e,t){let s=[],a={};for(let{tx:C}of e){let E=C.Account===t?C.Destination:C.Account;E&&E!==t&&(a[E]=(a[E]||0)+1)}let o=Object.values(a).sort((C,E)=>E-C);if(o.length<8)return{signals:[{sev:"info",label:`Insufficient counterparties for Zipf's Law (need \u22658, found ${o.length})`,detail:"Zipf analysis becomes meaningful with a broader counterparty network."}],verdict:"insufficient",zipfExponent:null,riskPenalty:0,freqTable:[],uniqueCounterparties:o.length};let i=o.length,r=0,l=0,c=0,d=0,u=o.map((C,E)=>({rank:E+1,freq:C,lx:Math.log(E+1),ly:Math.log(C)}));for(let{lx:C,ly:E}of u)r+=C,l+=E,c+=C*E,d+=C*C;let p=i*d-r*r,m=p!==0?(i*c-r*l)/p:null,f=m!==null?Math.abs(m):null,g=l/i,b=0,h=0,v=(l-m*r)/i;for(let{lx:C,ly:E}of u)b+=Math.pow(E-g,2),h+=Math.pow(E-(m*C+v),2);let w=b>0?1-h/b:0,k="normal",$=0;f!==null&&(w<.55?($+=12,s.push({sev:"warn",label:`Counterparty distribution doesn't follow Zipf's Law (R\xB2=${w.toFixed(2)})`,detail:`Natural networks follow a power-law rank-frequency relationship. This wallet's counterparty network has poor Zipf fit (R\xB2=${w.toFixed(2)}), suggesting artificial or script-driven interaction structure.`}),k="anomalous"):f<.4?($+=15,s.push({sev:"warn",label:`Zipf exponent too flat (s=${f.toFixed(2)}, expected 0.8\u20131.3)`,detail:"A very flat Zipf exponent means counterparties are used with surprisingly equal frequency. In organic networks, you transact far more often with a few key addresses. Flat distribution is consistent with round-trip wash trading rings."}),k="anomalous"):f>2.2?($+=10,s.push({sev:"warn",label:`Zipf exponent hyper-concentrated (s=${f.toFixed(2)}, expected 0.8\u20131.3)`,detail:"Extreme concentration on one or two counterparties with steep dropoff. While not unusual for simple wallets, combined with other signals this suggests coordinated narrow-ring activity."}),k="elevated"):s.push({sev:"ok",label:`Counterparty network follows Zipf's Law (s=${f.toFixed(2)}, R\xB2=${w.toFixed(2)})`,detail:"The rank-frequency distribution of counterparties follows the expected natural power-law pattern. This is consistent with organic wallet activity."}));let T={};for(let{tx:C}of e){let E=typeof C.Amount=="string"?Math.round(Number(C.Amount)/1e4)*10:null;E&&E>0&&(T[E]=(T[E]||0)+1)}let S=Object.values(T).sort((C,E)=>E-C),M=S.length?S[0]/S.reduce((C,E)=>C+E,0):0;return M>.45&&($+=8,s.push({sev:"warn",label:`Single amount dominates ${(M*100).toFixed(0)}% of transactions`,detail:"One transaction amount value accounts for nearly half of all payments. Round-number dominance is a hallmark of scripted or wash-trading activity."})),s.length||s.push({sev:"info",label:"Zipf analysis: no anomalies detected",detail:"Counterparty distribution consistent with natural activity."}),{signals:s,verdict:k,riskPenalty:$,zipfExponent:f,rSquared:w,freqTable:o.slice(0,12),uniqueCounterparties:o.length}}function Db(e){let n=[];if(e.length<20)return{signals:[{sev:"info",label:`Insufficient transactions for time series analysis (need \u226520, found ${e.length})`,detail:"Time series analysis requires a longer transaction history."}],verdict:"insufficient",riskPenalty:0,intervalCV:null,autocorrelation:null,burstScore:null,periodicityScore:null};let a=e.filter(({tx:w})=>w.date!=null).map(({tx:w})=>(w.date+946684800)*1e3).sort((w,k)=>w-k);if(a.length<20)return{signals:[{sev:"info",label:"No timestamp data available",detail:"Time series requires date-stamped transactions."}],verdict:"insufficient",riskPenalty:0,intervalCV:null,autocorrelation:null,burstScore:null,periodicityScore:null};let o=[];for(let w=1;w<a.length;w++){let k=(a[w]-a[w-1])/1e3;k>0&&k<86400*30&&o.push(k)}let i=null;if(o.length>=5){let w=o.reduce(($,T)=>$+T,0)/o.length,k=Math.sqrt(o.reduce(($,T)=>$+Math.pow(T-w,2),0)/o.length);i=w>0?k/w:null}let r={};for(let w of a){let k=new Date(w).toISOString().slice(0,10);r[k]=(r[k]||0)+1}let l=Object.values(r),c=0;if(l.length>=4){let w=l.reduce((T,S)=>T+S,0)/l.length,k=Math.sqrt(l.reduce((T,S)=>T+Math.pow(S-w,2),0)/l.length),$=Math.max(...l);c=k>0?($-w)/k:0}let d=null;if(l.length>=6){let w=l.reduce((T,S)=>T+S,0)/l.length,k=l.map(T=>T-w),$=k.reduce((T,S)=>T+S*S,0);$>0&&(d=k.slice(0,-1).reduce((S,M,C)=>S+M*k[C+1],0)/$)}let u=new Array(7).fill(0);for(let w of a)u[new Date(w).getUTCDay()]++;let p=Qs(u),m=Math.log2(7),f=0;if(o.length>=10){let w=[...o].sort((T,S)=>T-S),k=w[Math.floor(w.length/2)];f=o.filter(T=>Math.abs(T-k)/k<.2).length/o.length}let g="normal",b=0;i!==null&&(i<.25?(b+=20,g="bot-pattern",n.push({sev:"warn",label:`Transaction intervals mechanically regular (CV=${i.toFixed(2)})`,detail:"The time gaps between transactions are too regular for human behavior (CV < 0.25). Organic wallets show irregular timing (CV 0.8\u20133.0). This pattern is a strong bot signature."})):i<.5?(b+=8,n.push({sev:"info",label:`Transaction timing somewhat regular (CV=${i.toFixed(2)})`,detail:"Interval regularity is below typical human variance. Could indicate scheduled automation."})):n.push({sev:"ok",label:`Transaction timing is irregular (CV=${i.toFixed(2)})`,detail:"Inter-transaction intervals show natural human-like variance."})),f>.55&&(b+=12,n.push({sev:"warn",label:`Strong periodicity detected (${(f*100).toFixed(0)}% of intervals near median)`,detail:"More than half of transaction intervals cluster around the same duration. This mechanical repetition is consistent with an automated script executing on a fixed schedule."})),c>3.5&&n.push({sev:"info",label:`Activity burst detected (peak day z-score=${c.toFixed(1)})`,detail:"One or more days had extreme transaction volume compared to baseline. Could indicate a coordinated pump event or account recovery sweep."}),d!==null&&d>.6&&(b+=6,n.push({sev:"info",label:`High day-to-day volume autocorrelation (\u03C1=${d.toFixed(2)})`,detail:"Transaction volume is strongly self-correlated \u2014 today's activity predicts tomorrow's. This is consistent with an automated routine that maintains a constant pace."}));let h=p/m;h<.7&&a.length>30&&(b+=6,n.push({sev:"info",label:`Day-of-week distribution concentrated (${(h*100).toFixed(0)}% of max entropy)`,detail:"Transactions cluster heavily on specific days. Automated systems often run every day (maximally flat) or skip weekends \u2014 both deviate from natural human patterns."})),n.length||n.push({sev:"ok",label:"No temporal anomalies detected",detail:"Transaction timing patterns are consistent with organic human activity."}),b>=20?g="bot-pattern":b>=8&&(g="elevated");let v=a.length>=2?Math.round((a[a.length-1]-a[0])/864e5):null;return{signals:n,verdict:g,riskPenalty:b,intervalCV:i,autocorrelation:d,burstScore:c,periodicityScore:f,dowEntropy:p,dowBins:u,dailyVolume:Object.entries(r).slice(-30),activeSpanDays:v,totalTimestamped:a.length}}function Ib(e,t){let s=[];if(e.length<20)return{signals:[{sev:"info",label:`Insufficient data for offer/flow coupling analysis (need \u226520, found ${e.length})`,detail:"Testing for lead-lag correlation requires enough temporal observations."}],verdict:"insufficient",riskPenalty:0,offerCancelCausality:null,inflowOutflowCausality:null};let o=12*3600*1e3,i=D=>D.date?Math.floor((D.date+946684800)*1e3/o):null,r={},l=D=>{r[D]||(r[D]={offerCreate:0,offerCancel:0,inflow:0,outflow:0,nftList:0,nftAccept:0})};for(let{tx:D,meta:F}of e){let H=i(D);if(H===null)continue;l(H);let N=r[H],z=D.TransactionType;z==="OfferCreate"?N.offerCreate++:z==="OfferCancel"&&N.offerCancel++,z==="NFTokenCreateOffer"?N.nftList++:z==="NFTokenAcceptOffer"&&N.nftAccept++;let te=(F==null?void 0:F.delivered_amount)||D.Amount,oe=typeof te=="string"?Number(te)/1e6:0;oe>0&&(D.Destination===t?N.inflow+=oe:D.Account===t&&(N.outflow+=oe))}let c=Object.keys(r).map(Number).sort((D,F)=>D-F);if(c.length<6)return{signals:[{sev:"info",label:"Insufficient temporal windows for coupling analysis",detail:"Need activity spread across multiple time windows."}],verdict:"insufficient",riskPenalty:0,offerCancelCausality:null,inflowOutflowCausality:null};let d=D=>c.map(F=>r[F][D]||0),u=(D,F,H=4)=>{let N=D.length,z=D.reduce((ce,G)=>ce+G,0)/N,te=F.reduce((ce,G)=>ce+G,0)/N,oe=D.map(ce=>ce-z),pe=F.map(ce=>ce-te),ie=Math.sqrt(oe.reduce((ce,G)=>ce+G*G,0)/N),ne=Math.sqrt(pe.reduce((ce,G)=>ce+G*G,0)/N);return!ie||!ne?Array(H+1).fill(0):Array.from({length:H+1},(ce,G)=>{let Se=0,X=0;for(let q=0;q+G<N;q++)Se+=oe[q]*pe[q+G],X++;return X>0?Se/(X*ie*ne):0})},p="normal",m=0,f=d("offerCreate"),g=d("offerCancel"),b=u(f,g),h=b.indexOf(Math.max(...b)),v=Math.max(...b),w={ccf:b,maxCorr:v,maxLag:h};v>.55&&h<=2?(m+=18,p="strong-coupling",s.push(De({module:"Offer Coupling",category:"market-integrity",sev:"warn",confidence:.4,headline:`Offer Creation/Cancellation Coupling: HIGH (\u03C1=${v.toFixed(2)}, lag=${h} window${h===1?"":"s"})`,detail:`Offer creation and cancellation are strongly correlated ${h} window(s) apart (${h*12}h).`,observed:[`Cross-correlation \u03C1=${v.toFixed(2)} at a ${h}-window lag`,"Correlation, not a causality test \u2014 no autoregressive model or significance test was run"],alternativeExplanations:["Active order management/repricing that naturally pairs creates with cancels","A market maker's normal quote-refresh cycle"],classification:"Statistical coupling observed between offer creation and cancellation timing. This is the kind of pattern wash trading can produce, but correlation at a lag is not proof of it \u2014 see Wash Execution and Spoofing for behavior-level evidence."}))):v>.35?(m+=6,s.push(De({module:"Offer Coupling",category:"market-integrity",sev:"info",confidence:.25,headline:`Offer Creation/Cancellation Coupling: MODERATE (\u03C1=${v.toFixed(2)}, lag=${h})`,detail:"A mild temporal link between creating and cancelling offers."}))):s.push({sev:"ok",label:"Offer Creation/Cancellation Coupling: LOW",detail:"Offer creation and cancellation timing appear independent."});let k=d("inflow"),$=d("outflow"),T=u(k,$),S=T.indexOf(Math.max(...T)),M=Math.max(...T),C={ccf:T,maxCorr:M,maxLag:S};M>.65&&S===0?(m+=12,s.push(De({module:"Offer Coupling",category:"market-integrity",sev:"warn",confidence:.4,headline:`Inflow/Outflow Contemporaneous Correlation: HIGH (\u03C1=${M.toFixed(2)})`,detail:"Funds entering and leaving the wallet in the same 12h window are strongly correlated.",observed:[`Zero-lag correlation \u03C1=${M.toFixed(2)} \u2014 same-window co-movement, not a lead-lag relationship`,"A lag-0 result cannot show which direction (if either) leads the other"],alternativeExplanations:["Pass-through/consolidation behavior (an intermediary account by design)","Routine deposit-then-forward operational pattern"],classification:"Same-window co-movement between inflow and outflow, not a demonstrated lead-lag pattern. Consistent with pass-through/round-trip activity, but zero lag means the data alone cannot establish which value moved first."}))):M>.55&&S<=1?(m+=8,s.push(De({module:"Offer Coupling",category:"market-integrity",sev:"info",confidence:.3,headline:`Inflow/Outflow Coupling: MODERATE (\u03C1=${M.toFixed(2)}, lag=${S})`,detail:"Incoming funds are correlated with outgoing funds at a short lag."}))):s.push({sev:"ok",label:"Inflow/Outflow Coupling: LOW",detail:"Inflow and outflow timing are not predictably linked."});let E=d("nftList"),R=d("nftAccept"),O=E.reduce((D,F)=>D+F,0),I=R.reduce((D,F)=>D+F,0);if(O>3&&I>3){let D=u(E,R),F=Math.max(...D),H=D.indexOf(F);F>.6&&H<=1&&(m+=8,s.push(De({module:"Offer Coupling",category:"market-integrity",sev:"warn",confidence:.3,headline:`NFT Listing/Acceptance Coupling: HIGH (\u03C1=${F.toFixed(2)}, lag=${H})`,detail:"NFT sell-offer creation is closely correlated with acceptance timing.",alternativeExplanations:["A pre-arranged legitimate sale between known parties"],classification:"Timing coupling only \u2014 combined with the NFT trap detection module's own evidence, this can support (but does not by itself prove) a coordinated-acceptance pattern."})))}return s.some(D=>D.sev==="warn"||D.sev==="critical")||s.length||s.push({sev:"ok",label:"No coupling anomalies detected",detail:"Temporal relationships between transaction types show no notable lead-lag or contemporaneous correlation."}),m>=18?p="strong-coupling":m>=8&&(p="elevated"),{signals:s,verdict:p,riskPenalty:m,offerCancelCausality:w,inflowOutflowCausality:C,windowCount:c.length}}function Fb(e,t){let n=new Map;for(let{tx:o}of e){let i=[o.TakerGets,o.Amount];for(let r of i){if(!r||typeof r!="object")continue;let l=r.currency,c=Number(r.value||0),d=o.Account;if(!l||!d||c<=0||!Number.isFinite(c))continue;n.has(l)||n.set(l,{senders:new Set,vol:0,trades:0});let u=n.get(l);u.senders.add(d),u.vol+=c,u.trades++}}let s=[],a=[];for(let[o,i]of n.entries()){if(i.trades<8)continue;let r=i.senders.size;a.push({currency:o,uniqueActors:r,vol:i.vol,trades:i.trades}),r<5?s.push({sev:"critical",label:`${o}: ${r} wallet(s) driving all volume`,detail:`${i.trades} trades totalling ${i.vol.toFixed(2)} ${o} from only ${r} address(es). Fewer than 5 unique actors generating most volume is a wash trading red flag.`}):r<10&&s.push({sev:"warn",label:`${o}: low actor diversity (${r} wallets, ${i.trades} trades)`,detail:`Volume concentrated among only ${r} addresses. Organic markets typically have broader participation.`})}return a.length?s.length||s.push({sev:"ok",label:"Volume concentration normal",detail:`${a.length} token(s) analysed \u2014 all have \u226510 unique trading participants.`}):s.push({sev:"info",label:"No IOU/token volume data",detail:"No token-denominated transactions found in history (XRP-only activity)."}),{signals:s,concentrations:a}}function Ob(e,t,n,s){let a=[],o=!!(n&Ne.lsfDefaultRipple)||t.some(p=>p.account===e.Account),i=t.filter(p=>Number(p.balance)<0),r=i.reduce((p,m)=>p+Math.abs(Number(m.balance)),0);i.length>0&&a.push({sev:"info",label:`Token issuer: ${i.length} outstanding currency lines`,detail:`Total outstanding: ${_(r,2)} across ${i.length} holder(s).`});let l=t.filter(p=>p.freeze),c=t.filter(p=>p.freeze_peer);l.length&&a.push({sev:"warn",label:`${l.length} trustline(s) frozen by this account`,detail:"This account has frozen specific trustlines."}),c.length&&a.push({sev:"critical",label:`${c.length} of your trustline(s) frozen by issuer`,detail:`Frozen currencies: ${c.map(p=>p.currency).join(", ")}. You cannot transfer these tokens.`}),n&Ne.lsfGlobalFreeze&&a.push({sev:"critical",label:"Global Freeze \u2014 all token transfers suspended",detail:"No holders can transfer tokens issued by this account."}),n&Ne.lsfNoFreeze&&a.push({sev:"ok",label:"NoFreeze flag set \u2014 issuer cannot freeze balances",detail:"Token holders are protected against future freeze actions."});let d=Number(e.Balance||0)/1e6,u=10+Number(e.OwnerCount||0)*2;return i.length>0&&d<u+1&&a.push({sev:"warn",label:"Issuer balance near reserve \u2014 possible black hole",detail:"Issuer with outstanding tokens has almost no XRP above reserve. Tokens may be stranded."}),a.length===0&&a.push({sev:"ok",label:"No token issuer flags",detail:"This account does not appear to be a token issuer."}),{signals:a,isIssuer:o,obligationCount:i.length}}function Bb(e,t,n,s=new Map,a=null){var f,g,b;let o=[],i=[],r=e.filter(h=>h.currency&&Number(h.balance)!==0&&bu(h.currency)),l=t.filter(({tx:h})=>h.TransactionType==="AMMDeposit"),c=t.filter(({tx:h})=>h.TransactionType==="AMMWithdraw"),d=t.filter(({tx:h})=>h.TransactionType==="AMMCreate"),u=t.filter(({tx:h})=>h.TransactionType==="AMMVote"),p=t.filter(({tx:h})=>h.TransactionType==="AMMBid");if(r.forEach(h=>{let v=Number(h.balance),w=Number(h.limit);i.push({currency:h.currency,issuer:h.account,balance:v,limit:w})}),a)for(let h of i){let v=[...l,...c].filter(({tx:T,meta:S})=>{var M,C;return(C=(M=S==null?void 0:S.AffectedNodes)==null?void 0:M.some)==null?void 0:C.call(M,E=>{var R;return((R=E.CreatedNode||E.ModifiedNode||E.DeletedNode)==null?void 0:R.LedgerEntryType)==="RippleState"&&[E.CreatedNode,E.ModifiedNode,E.DeletedNode].some(O=>{var I,D,F,H;return((D=(I=O==null?void 0:O.FinalFields)==null?void 0:I.Balance)==null?void 0:D.currency)===h.currency||((H=(F=O==null?void 0:O.NewFields)==null?void 0:F.Balance)==null?void 0:H.currency)===h.currency})})}),w=0,k=[],$=[];for(let{tx:T,meta:S}of v){let M=Ji(T,S,a),C=M.lpDeltas.find(R=>R.currency===h.currency);if(!C)continue;let E={hash:T.hash,date:T.date,lpTokenDelta:C.delta,xrpDelta:M.xrpDelta,tokenDeltas:M.tokenDeltas};T.TransactionType==="AMMDeposit"?(k.push(E),w+=-M.xrpDelta):($.push(E),w-=-M.xrpDelta)}(k.length||$.length)&&(h.depositEvents=k,h.withdrawEvents=$,h.costBasisXrp=w>0?w:null)}if(i.length){o.push({sev:"info",label:`${i.length} LP token position(s)`,detail:`Active liquidity provider in ${i.length} AMM pool(s).`});for(let h of i){let v=s.get(h.currency);if(v){if(h.tvl=v.amount?Number(v.amount)/1e6:null,h.tvl2=(f=v.amount2)!=null&&f.value?Number(v.amount2.value):null,h.feeRate=v.trading_fee!=null?v.trading_fee/1e3:null,h.lpSupply=(g=v.lp_token)!=null&&g.value?Number(v.lp_token.value):null,h.lpSupply&&h.balance){let w=Math.abs(h.balance)/h.lpSupply*100;h.ownerPct=w,w>50&&o.push({sev:"warn",label:`Dominant AMM position: ${w.toFixed(0)}% of pool`,detail:`This account controls ${w.toFixed(0)}% of the LP token supply for pool ${W(h.currency)}. Withdrawing all at once would severely impact pool liquidity and anyone currently trading in it.`})}h.tvl!=null&&o.push({sev:"info",label:`Pool TVL: ${_(h.tvl,2)} XRP${h.tvl2?` + ${_(h.tvl2,2)} tokens`:""} \xB7 Fee: ${((b=h.feeRate)==null?void 0:b.toFixed(2))??"?"}%`,detail:`Actual pool context from amm_info. Your LP position represents ${h.ownerPct!=null?h.ownerPct.toFixed(1)+"% of the pool.":"an unknown share of the pool."}`})}}}return d.length&&o.push({sev:"info",label:`Created ${d.length} AMM pool(s)`,detail:"This account bootstrapped one or more liquidity pools."}),(l.length||c.length)&&o.push({sev:"info",label:`${l.length} deposit(s) \xB7 ${c.length} withdrawal(s)`,detail:"LP activity history."}),u.length&&o.push({sev:"info",label:`${u.length} AMM fee vote(s)`,detail:"This account has voted on AMM trading fee parameters."}),p.length&&o.push({sev:"info",label:`${p.length} continuous auction bid(s)`,detail:"Bid for the AMM auction slot (reduced fee trading window)."}),i.filter(h=>Math.abs(h.balance)>1e3).length&&o.push({sev:"warn",label:"Large LP positions \u2014 impermanent loss risk",detail:"Significant liquidity positions carry exposure to price divergence between pool assets."}),o.length===0&&o.push({sev:"ok",label:"No AMM positions",detail:"This account is not a liquidity provider."}),{signals:o,positions:i,deposits:l.length,withdrawals:c.length}}function Xb(e){let t=[],s=e.filter(({tx:p})=>p.Fee&&Number(p.Fee)>0);if(s.length<10)return{signals:[],verdict:"insufficient",riskPenalty:0,avgFeeMultiplier:null,spikeCount:0,topFeeHashes:[]};let a=s.map(({tx:p})=>Number(p.Fee)/12),o=a.reduce((p,m)=>p+m,0)/a.length,r=s.filter(({tx:p})=>Number(p.Fee)/12>100).length,l=r/s.length,c=0,d="normal",u=[...s].sort((p,m)=>Number(m.tx.Fee)-Number(p.tx.Fee)).slice(0,5).map(({tx:p})=>({hash:p.hash,mult:(Number(p.Fee)/12).toFixed(0),fee:Number(p.Fee)}));return l>.15&&r>=5?(c=10,d="elevated",t.push({sev:"warn",label:`Fee spike pattern: ${r} txs paid >100x base fee (${(l*100).toFixed(0)}% of history)`,detail:`Average fee multiplier: ${o.toFixed(0)}x. In XRPL, bots often pay elevated fees to guarantee same-ledger execution as a counterparty \u2014 a technique used in coordinated wash trading and sandwich attacks. Organic users rarely pay more than 2\u20135x the base fee. Top hashes: ${u.slice(0,3).map(p=>W(p.hash)).join(", ")}.`,hashes:u.map(p=>p.hash)})):o>20?(c=4,t.push({sev:"info",label:`Elevated average fee (${o.toFixed(0)}x base fee)`,detail:"This wallet consistently pays above-average fees. Could indicate priority execution requirements or automated trading."})):t.push({sev:"ok",label:`Fee levels normal (avg ${o.toFixed(1)}x base fee)`,detail:"Transaction fees are within typical organic ranges."}),{signals:t,verdict:d,riskPenalty:c,avgFeeMultiplier:+o.toFixed(2),spikeCount:r,topFeeHashes:u}}function Hb(e,t){let n=[],s=new Map;for(let{tx:r}of e){if(r.TransactionType!=="Payment"||r.Account!==t)continue;let l=r.Destination,c=r.DestinationTag;l&&(s.has(l)||s.set(l,new Set),c!=null&&s.get(l).add(c))}let a=[...s.entries()].filter(([r])=>{let l=Hn(r);return(l==null?void 0:l.type)==="exchange"}),o=0,i=[];for(let[r,l]of s.entries()){let c=Hn(r),d=(c==null?void 0:c.name)||W(r),u=l.size,p=e.filter(({tx:m})=>m.Account===t&&m.Destination===r).length;i.push({dest:r,name:d,uniqueTags:u,txCount:p,tags:[...l].slice(0,10)}),u===1&&p>=5&&(c==null?void 0:c.type)==="exchange"?n.push({sev:"info",label:`${d}: ${p} payments all using tag ${[...l][0]}`,detail:`Single destination tag used across all ${p} payments to ${d}. This is the normal pattern for one person funding their own exchange account.`}):u>10&&(c==null?void 0:c.type)==="exchange"?(o=Math.max(o,8),n.push({sev:"warn",label:`${d}: ${u} different destination tags used`,detail:`${p} payments to ${d} used ${u} different tags \u2014 each tag typically identifies a different customer account. Funding many exchange sub-accounts can indicate either a service (legitimate) or coordinated deposit layering where funds are spread across many exchange wallets to avoid detection.`})):u===0&&p>=2&&(c==null?void 0:c.type)==="exchange"&&n.push({sev:"warn",label:`${d}: ${p} payments with no destination tag`,detail:"Payments to exchange addresses without a destination tag may not be credited. Most exchanges require a tag to identify which customer account receives the funds."})}return n.length===0&&s.size>0?n.push({sev:"ok",label:"Destination tag patterns normal",detail:"Payment routing tags are consistent with regular outbound payments."}):s.size===0&&n.push({sev:"info",label:"No outbound payments to analyse for destination tags",detail:"No outbound Payment transactions found in history."}),{signals:n,riskPenalty:o,tagProfiles:i}}function zb(e,t){var c,d;let n=[],s=e.filter(({tx:u})=>u.TransactionType==="Payment"&&u.Account===t&&(Array.isArray(u.Paths)&&u.Paths.length>0||u.SendMax!=null));if(s.length===0)return{signals:[],riskPenalty:0,roundTripCount:0,deepHopCount:0,selfRoutedCount:0,noData:!0};let a=s.length<5?` (small sample: ${s.length} path payments found \u2014 patterns may not be statistically significant)`:"",o=s.filter(({tx:u})=>{let p=typeof u.Amount=="string",m=typeof u.SendMax=="string";return p&&m}),i=s.filter(({tx:u})=>Array.isArray(u.Paths)?u.Paths.some(p=>Array.isArray(p)&&p.length>=3):!1),r=s.filter(({tx:u})=>u.Destination===t),l=0;return o.length>=1&&(l+=12,n.push({sev:"warn",label:`${o.length} XRP\u2192IOU\u2192XRP round-trip path payments`,detail:`Sending XRP and receiving XRP via intermediate token pairs means the payment routes through the DEX and creates trading volume without changing economic position. ${o.length} occurrences suggests this is deliberate. This is the classic cross-currency wash-trading arb pattern on XRPL. Example hash: ${(d=(c=o[0])==null?void 0:c.tx)!=null&&d.hash?W(o[0].tx.hash):"N/A"}.`,hashes:o.slice(0,5).map(({tx:u})=>u.hash).filter(Boolean)})),i.length>=1&&(l+=6,n.push({sev:"info",label:`${i.length} path payments with \u22653 intermediate hops`,detail:"Deep routing chains (3+ hops) can indicate: legitimate arbitrage, liquidity optimization, or deliberate obfuscation of fund origin. Check each transaction for the intermediate issuers in the path."})),r.length>0&&(l+=15,n.push({sev:"critical",label:`${r.length} path payment(s) where sender = destination`,detail:`Money sent to your own address via a multi-hop path creates DEX trading volume with no net change in balance. This is a direct wash-trading technique: the path through the order book generates artificial volume on every intermediate pair. Hashes: ${r.slice(0,3).map(({tx:u})=>W(u.hash||"")).join(", ")}.`,hashes:r.slice(0,5).map(({tx:u})=>u.hash).filter(Boolean)})),n.length===0&&n.push({sev:"ok",label:`${s.length} path payment(s) \u2014 no suspicious routing patterns${a}`,detail:"No circular routing (XRP\u2192IOU\u2192XRP), self-routing, or unusual deep hop chains detected."}),{signals:n,riskPenalty:l,roundTripCount:o.length,deepHopCount:i.length,selfRoutedCount:r.length}}function Wb(e,t){var u;let n=new Map,s=[];for(let{tx:p,meta:m}of e){if(p.TransactionType!=="Payment"||p.Destination!==t)continue;let f=p.Account;if(!f||f===t)continue;let g=0,b=null,h=(m==null?void 0:m.delivered_amount)||p.Amount;typeof h=="string"?g=Number(h)/1e6:h!=null&&h.value&&(b={value:Number(h.value),currency:Xn(h.currency),issuer:h.issuer});let v=ws(p);s.push({src:f,amtXrp:g,amtToken:b,ts:v,hash:p.hash||"",destTag:p.DestinationTag}),n.has(f)||n.set(f,{addr:f,totalXrp:0,txCount:0,firstSeen:v,lastSeen:v,entity:Hn(f)||null});let w=n.get(f);w.totalXrp+=g,w.txCount++,w.lastSeen=Math.max(w.lastSeen,v),w.firstSeen=Math.min(w.firstSeen,v)}let a=[...n.values()].sort((p,m)=>m.totalXrp-p.totalXrp||m.txCount-p.txCount).slice(0,10),o=a.reduce((p,m)=>p+m.totalXrp,0),i=a.filter(p=>{var m;return((m=p.entity)==null?void 0:m.type)==="exchange"}),r={};for(let p of s){if(p.amtXrp<=0)continue;let m=Math.round(p.amtXrp/10)*10;r[m]=(r[m]||0)+1}let l=Object.entries(r).sort((p,m)=>m[1]-p[1])[0],c=l&&l[1]>=5&&l[1]/s.length>.4,d=[];if(i.length){let p=[...new Set(i.map(m=>m.entity.name))].join(", ");d.push({sev:"info",label:`Funding from ${i.length} known exchange(s): ${p}`,detail:`${_(i.reduce((m,f)=>m+f.totalXrp,0),2)} XRP received from exchange withdrawals \u2014 typical for a personal trading wallet.`})}if(c&&d.push({sev:"warn",label:`Structured inbound pattern: ${l[1]} payments near ~${l[0]} XRP`,detail:`Over 40% of inbound payments cluster around the same amount (~${l[0]} XRP). Structured deposits can indicate layering \u2014 deliberately splitting large amounts into smaller equal transfers to avoid detection.`}),n.size===1&&s.length>=5){let p=a[0];d.push({sev:"info",label:`Single funding source: all ${s.length} inbound payments from one address`,detail:`${((u=p.entity)==null?void 0:u.name)||W(p.addr)} is the sole funding source. This is normal for a personal wallet but notable for a wallet claiming broad community usage.`})}return!d.length&&s.length>0&&d.push({sev:"ok",label:`${s.length} inbound payment(s) from ${n.size} source(s)`,detail:`Total received: ${_(o,2)} XRP. No unusual inbound patterns.`}),s.length===0&&d.push({sev:"info",label:"No inbound payments found in analysed history",detail:"Wallet may be funded via DEX activity or in ledgers outside the analysed range."}),{signals:d,topSources:a,totalIn:o,uniqueSources:n.size,timeline:s.slice(-20).reverse(),exchangeSrcs:i,structuredFlag:!!c}}function Ub(e,t){var l,c;let n=[],s=[],a=[/airdrop/i,/claim.*reward/i,/free.*xrp/i,/verify.*wallet/i,/support.*team/i,/urgent/i,/suspended/i,/confirm.*seed/i,/your.*account.*hold/i,/unlock/i];for(let{tx:d}of e)if((l=d.Memos)!=null&&l.length)for(let u of d.Memos){let p=((c=u.Memo)==null?void 0:c.MemoData)||"";if(!p)continue;let m="";try{m=decodeURIComponent(p.replace(/../g,f=>"%"+f))}catch{m=p}if(!m||m===p)try{let f="";for(let g=0;g<p.length;g+=2){let b=parseInt(p.slice(g,g+2),16);b>=32&&b<127&&(f+=String.fromCharCode(b))}f.length>4&&(m=f)}catch{}s.push({tx:d.hash||"",type:d.TransactionType,sender:d.Account,text:m.slice(0,200),raw:p})}if(s.length===0)return{signals:[],allMemos:[],scamMemos:[],repeatedMemos:[]};let o=s.filter(d=>a.some(u=>u.test(d.text)));o.length&&n.push({sev:"critical",label:`${o.length} memo(s) match known scam patterns`,detail:`Memos containing phrases like "airdrop", "claim reward", "verify wallet", or "urgent" are used in social engineering attacks. These payments were likely sent to trick the recipient into taking action. Examples: ${o.slice(0,2).map(d=>'"'+d.text.slice(0,40)+'"').join(", ")}`});let i={};for(let d of s){let u=d.text.slice(0,50).trim().toLowerCase();u.length>3&&(i[u]=(i[u]||0)+1)}let r=Object.entries(i).filter(([,d])=>d>=3).sort((d,u)=>u[1]-d[1]);return r.length&&n.push({sev:"warn",label:`${r.length} memo text(s) repeated \u22653 times`,detail:`Identical memo text across multiple transactions suggests scripted or automated activity. Most repeated: "${r[0][0]}" (${r[0][1]}\xD7)`}),n.length||n.push({sev:"ok",label:`${s.length} memo(s) found \u2014 no suspicious patterns`,detail:"Memo content looks normal."}),{signals:n,allMemos:s,scamMemos:o,repeatedMemos:r.slice(0,5)}}function jb(e,t,n){let s=e.filter(u=>u.LedgerEntryType==="Escrow");if(!s.length)return{signals:[],escrows:[],hasThirdParty:!1};let a=[],o=Math.floor(Date.now()/1e3),i=946684800,r=s.map(u=>{let p=u.Account||null,m=u.Destination||null,f=Number(u.Amount||0)/1e6,g=u.FinishAfter?u.FinishAfter+i:null,b=u.CancelAfter?u.CancelAfter+i:null,h=p&&p!==n&&m===n,v=p===n&&m===n,w=g?Math.ceil((g-o)/86400):null;return{creator:p,dest:m,amtXrp:f,finishAfter:g,cancelAfter:b,isThirdParty:h,isSelfEscrow:v,daysToFinish:w,conditional:!!u.Condition}}),l=r.filter(u=>u.isThirdParty),c=r.reduce((u,p)=>u+p.amtXrp,0);l.length&&a.push({sev:"warn",label:`${l.length} escrow(s) created by external account(s) \u2014 funds locked to this address`,detail:`${_(l.reduce((u,p)=>u+p.amtXrp,0),2)} XRP in escrows that an outside party controls. The creator sets the conditions. Escrows created by attackers just before a drain attempt have been observed in some compromise patterns \u2014 verify who created these.`});let d=r.filter(u=>u.daysToFinish!=null&&u.daysToFinish>=0&&u.daysToFinish<=7);return d.length&&a.push({sev:"info",label:`${d.length} escrow(s) mature within 7 days`,detail:`${_(d.reduce((u,p)=>u+p.amtXrp,0),2)} XRP will become claimable soon. If these are third-party escrows, the creator can claim funds once the condition is met.`}),a.length||a.push({sev:"ok",label:`${s.length} self-escrow(s) \u2014 ${_(c,2)} XRP locked`,detail:"All escrows appear to be self-controlled time-locks. No third-party escrow risk."}),{signals:a,escrows:r,hasThirdParty:l.length>0,totalLocked:c}}function qb(e){let t=e.filter(l=>l.LedgerEntryType==="Check");if(!t.length)return{signals:[],checks:[]};let n=[],s=946684800,a=Math.floor(Date.now()/1e3),o=t.map(l=>{let c=typeof l.SendMax=="string"?Number(l.SendMax)/1e6:null,d=typeof l.SendMax=="object"?l.SendMax:null,u=l.Expiration?l.Expiration+s:null,p=(l.ledger_index,null),m=u&&u<a;return{sender:l.Account,dest:l.Destination,amtXrp:c,amtToken:d,expiry:u,expired:m,id:l.index||""}}),i=o.filter(l=>l.amtXrp&&l.amtXrp>100),r=o.filter(l=>l.expired);return i.length&&n.push({sev:"info",label:`${i.length} large uncashed check(s) \u2014 ${_(i.reduce((l,c)=>l+(c.amtXrp||0),0),2)} XRP pending`,detail:"Open checks can be cashed by the recipient at any time before expiry. Large uncashed checks represent a future outflow commitment."}),r.length&&n.push({sev:"info",label:`${r.length} expired check(s) \u2014 should be cancelled to reclaim reserve`,detail:"Expired checks still occupy owner reserve slots (2 XRP each). Cancelling them returns the reserved XRP."}),n.length||n.push({sev:"ok",label:`${t.length} check(s) found \u2014 no unusual patterns`,detail:"Check amounts are within normal range."}),{signals:n,checks:o}}function Vb(e,t){var m,f,g;if(!e||!((m=e.offers)!=null&&m.length))return{signals:[],hasData:!1};let{pair:n,offers:s}=e,a=[],o=new Map;for(let b of s){let h=b.Account,v=typeof b.TakerGets=="string"?Number(b.TakerGets)/1e6:Number(((f=b.TakerGets)==null?void 0:f.value)||0);o.set(h,(o.get(h)||0)+v)}let i=[...o.values()].reduce((b,h)=>b+h,0),r=o.get(t)||0,l=i>0?r/i:0,d=[...s].sort((b,h)=>{var k,$;let v=typeof b.TakerGets=="string"?Number(b.TakerGets)/1e6:Number(((k=b.TakerGets)==null?void 0:k.value)||0);return(typeof h.TakerGets=="string"?Number(h.TakerGets)/1e6:Number((($=h.TakerGets)==null?void 0:$.value)||0))-v})[0],u=typeof(d==null?void 0:d.TakerGets)=="string"?Number(d.TakerGets)/1e6:Number(((g=d==null?void 0:d.TakerGets)==null?void 0:g.value)||0),p=i>0?u/i:0;return p>.4&&(d==null?void 0:d.Account)===t?a.push({sev:"critical",label:`Active wall order: this wallet controls ${(p*100).toFixed(0)}% of current book depth`,detail:`A single order from this address represents ${(p*100).toFixed(0)}% of the visible order book depth on pair ${n}. Large orders placed to make a market look deeper than it is \u2014 without intent to fill \u2014 is spoofing. This order is live right now.`}):p>.4&&a.push({sev:"warn",label:`Wall order present: ${(p*100).toFixed(0)}% of book depth in one order`,detail:`A single address controls ${(p*100).toFixed(0)}% of the current order book for pair ${n}. Wall orders dominate book depth and can be removed instantly \u2014 they create false liquidity signals.`}),l>.25&&a.push({sev:"info",label:`This wallet controls ${(l*100).toFixed(0)}% of current order book depth`,detail:`${_(r,2)} of ${_(i,2)} total book volume on pair ${n}.`}),a.length||a.push({sev:"ok",label:`Live order book looks normal (${s.length} orders, pair: ${n.split("\u2194").map(b=>b.split("+")[0]).join("\u2194")})`,detail:"No wall orders or unusual depth concentration detected in the current order book."}),{signals:a,hasData:!0,pair:n,offerCount:s.length,ourShare:l,wallShare:p}}function Gb(e,t,n,s,a,o,i,r,l,c,d,u,p,m){var g,b;return[{label:"Security",pts:Math.round((100-t.score)*.4),max:40,color:"#ff5555",icon:"\u{1F510}"},{label:"Drain Risk",pts:{low:0,medium:10,high:25,critical:35}[n.riskLevel]||0,max:35,color:"#ff5555",icon:"\u26A0\uFE0F"},{label:"Wash Trading",pts:Math.min(15,Math.round((a.score||0)*.15)),max:15,color:"#ffb86c",icon:"\u{1F4CA}"},{label:"NFT Risk",pts:Math.min(15,s.flags.filter(h=>h.sev==="critical").length*8+s.flags.filter(h=>h.sev==="warn").length*3),max:15,color:"#bd93f9",icon:"\u{1F3A8}"},{label:"Benford's",pts:Math.round(Pu(o)),max:10,color:"#f1fa8c",icon:"\u{1F4D0}"},{label:"Forensic Suite",pts:Math.min(20,Math.min(8,Math.round(((r==null?void 0:r.riskPenalty)||0)*.35))+Math.min(8,Math.round(((l==null?void 0:l.riskPenalty)||0)*.4))+Math.min(8,Math.round(((c==null?void 0:c.riskPenalty)||0)*.35))+Math.min(8,Math.round(((d==null?void 0:d.riskPenalty)||0)*.35))),max:20,color:"#00d4ff",icon:"\u{1F9EC}"},{label:"Vol Conc",pts:Math.min(10,(((g=i==null?void 0:i.signals)==null?void 0:g.filter(h=>h.sev==="critical").length)||0)*6+(((b=i==null?void 0:i.signals)==null?void 0:b.filter(h=>h.sev==="warn").length)||0)*3),max:10,color:"#ffb86c",icon:"\u{1FAE7}"},{label:"Fee Spikes",pts:Math.min(5,(u==null?void 0:u.riskPenalty)||0),max:5,color:"#ffb86c",icon:"\u{1F4B8}"}].filter(h=>h.pts>0)}function Kb(e,t,n,s,a,o,i,r,l,c,d=null){let u=0;u+=Math.round((100-e.score)*.4),u+={low:0,medium:10,high:25,critical:35}[t.riskLevel]||0;let m=n.flags.filter(g=>g.sev==="critical").length,f=n.flags.filter(g=>g.sev==="warn").length;if(u+=Math.min(15,m*8+f*3),u+=Math.min(15,Math.round(s.score*.15)),u+=Pu(a),o!=null&&o.signals){let g=o.signals.filter(h=>h.sev==="critical").length,b=o.signals.filter(h=>h.sev==="warn").length;u+=Math.min(10,g*6+b*3)}return i!=null&&i.riskPenalty&&(u+=Math.min(8,Math.round(i.riskPenalty*.35))),r!=null&&r.riskPenalty&&(u+=Math.min(8,Math.round(r.riskPenalty*.4))),l!=null&&l.riskPenalty&&(u+=Math.min(8,Math.round(l.riskPenalty*.35))),c!=null&&c.riskPenalty&&(u+=Math.min(8,Math.round(c.riskPenalty*.35))),d!=null&&d.riskPenalty&&(u+=Math.min(5,d.riskPenalty)),Math.round(Math.min(100,u))}function Jb(e){var b;let t=document.getElementById("inspect-benfords-body");if(!t)return;let n={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},s=e.signals.map(h=>`
    <div class="finding finding--${h.sev}">
      <span class="finding-sev ${n[h.sev]||""}">${h.sev.toUpperCase()}</span>
      <div class="finding-body">
        <div class="finding-label">${y(h.label)}</div>
        <div class="finding-detail">${y(h.detail)}</div>
      </div>
    </div>`).join(""),a=(b=e.digitBreakdown)!=null&&b.length?`
    <div class="benford-grid">
      <div class="benford-grid-h">Digit</div>
      <div class="benford-grid-h">Observed</div>
      <div class="benford-grid-h">Expected</div>
      <div class="benford-grid-h">Bar</div>
      ${e.digitBreakdown.map(h=>{let v=parseFloat(h.obs),w=parseFloat(h.exp),k=v-w,$=Math.abs(k)>5?"#ff5555":Math.abs(k)>2.5?"#ffb86c":"#50fa7b",T=`<div style="height:6px;border-radius:3px;background:rgba(255,255,255,.08);overflow:hidden">
          <div style="height:100%;width:${Math.min(100,v*3.3).toFixed(0)}%;background:${$};border-radius:3px"></div>
        </div>`;return`<div class="mono" style="text-align:center">${h.digit}</div>
                <div class="mono" style="color:${$}">${h.obs}%</div>
                <div class="mono" style="opacity:.6">${h.exp}%</div>
                <div>${T}</div>`}).join("")}
    </div>`:"",o=e.chiSq!=null?`<div class="wash-stat-row" style="margin-top:8px">
        <span>Sample size</span><span class="mono">${e.sampleSize}</span>
       </div>
       <div class="wash-stat-row">
        <span>Chi-squared (\u03C7\xB2)</span>
        <span class="mono ${e.chiSq>20.09?"risk-text-high":e.chiSq>15.51?"risk-text-med":""}">${e.chiSq.toFixed(2)}</span>
       </div>
       <div class="wash-stat-row">
        <span>Critical values</span><span class="mono" style="opacity:.6">p&lt;0.05: 15.51 \xB7 p&lt;0.01: 20.09</span>
       </div>`:"",i=e.verdict,r=e.chiSq,l=e.sampleSize,c="\u{1F4CA}",d="What is Benford\u2019s Law?",u="In nature \u2014 population sizes, river lengths, stock prices, real financial transactions \u2014 the leading (first) digit of numbers is NOT random. The number 1 appears as the first digit about 30% of the time. The number 9 appears only 4.6% of the time. This predictable pattern is Benford's Law.",p="",m="rgba(255,255,255,.08)",f="rgba(255,255,255,.10)";i==="insufficient"?p=`<p class="benford-explain-result">Not enough data yet \u2014 we need at least 50 transaction amounts to run this test. This account has ${l} so far. The more activity, the more reliable the analysis.</p>`:i==="high-deviation"?(c="\u{1F6A8}",m="rgba(255,85,85,.06)",f="rgba(255,85,85,.22)",p=`<p class="benford-explain-result">
      <strong style="color:#ff5555">What this means for this account:</strong>
      The transaction amounts here deviate strongly from what you'd expect in real organic activity
      (\u03C7\xB2&nbsp;=&nbsp;${r==null?void 0:r.toFixed(1)}, which is above the suspicious threshold of 20.09 at 99% confidence).
    </p>
    <p class="benford-explain-result">
      In plain terms: the mix of numbers being used feels <em>too calculated</em>.
      Real human spending is messy \u2014 you buy things for $7.43, $312.50, $1,200 \u2014 and the leading digits
      naturally follow Benford's pattern. When a bot or script generates amounts, it tends to use
      suspiciously round numbers, repeat the same values, or avoid certain digits \u2014 and that breaks
      the pattern.
    </p>
    <p class="benford-explain-result" style="color:#ffb86c">
      This is a supporting signal, not proof of fraud on its own. Cross-reference with the Wash Trading
      and Volume Concentration sections for a fuller picture.
    </p>`):i==="moderate-deviation"?(c="\u26A0",m="rgba(255,184,108,.05)",f="rgba(255,184,108,.20)",p=`<p class="benford-explain-result">
      <strong style="color:#ffb86c">What this means for this account:</strong>
      There's a moderate mismatch from natural patterns (\u03C7\xB2&nbsp;=&nbsp;${r==null?void 0:r.toFixed(1)}).
      This could mean some automated or repeated transactions are mixed in with genuine activity.
      It isn't alarming on its own but is worth watching \u2014 especially if other sections also show signals.
    </p>`):i==="normal"&&(c="\u2705",m="rgba(80,250,123,.04)",f="rgba(80,250,123,.15)",p=`<p class="benford-explain-result">
      <strong style="color:#50fa7b">What this means for this account:</strong>
      The transaction amounts follow the natural Benford's pattern closely (\u03C7\xB2&nbsp;=&nbsp;${r==null?void 0:r.toFixed(1)}).
      This is what you'd expect from organic, real-world financial activity.
      No statistical red flags here.
    </p>`);let g=`
    <div class="benford-explainer" style="background:${m};border-color:${f}">
      <div class="benford-explainer-head">
        <span class="benford-explainer-icon">${c}</span>
        <span class="benford-explainer-title">${d}</span>
      </div>
      <p class="benford-explain-text">
        ${u}
      </p>
      <div class="benford-explain-visual">
        <div class="benford-visual-row">
          <span class="benford-digit-ex">Digit 1</span>
          <div class="benford-visual-bar" style="width:30.1%;background:rgba(80,250,123,.55)"></div>
          <span class="benford-visual-pct">30.1%</span>
          <span class="benford-visual-note">most common</span>
        </div>
        <div class="benford-visual-row">
          <span class="benford-digit-ex">Digit 5</span>
          <div class="benford-visual-bar" style="width:7.9%;background:rgba(255,184,108,.55)"></div>
          <span class="benford-visual-pct">7.9%</span>
          <span class="benford-visual-note"></span>
        </div>
        <div class="benford-visual-row">
          <span class="benford-digit-ex">Digit 9</span>
          <div class="benford-visual-bar" style="width:4.6%;background:rgba(255,85,85,.55)"></div>
          <span class="benford-visual-pct">4.6%</span>
          <span class="benford-visual-note">least common</span>
        </div>
      </div>
      <p class="benford-explain-text" style="margin-top:6px;opacity:.75">
        When real money moves \u2014 payments, trades, escrows \u2014 these proportions hold up remarkably well.
        When amounts are <em>generated by a script</em> or deliberately faked, they don't.
        That's why forensic accountants use Benford's Law to detect fraud in financial records.
      </p>
      ${p}
    </div>
  `;t.innerHTML=s+o+a+g}function Yb(e){var o;let t=document.getElementById("inspect-volconc-body");if(!t)return;let n={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},s=e.signals.map(i=>`
    <div class="finding finding--${i.sev}">
      <span class="finding-sev ${n[i.sev]||""}">${i.sev.toUpperCase()}</span>
      <div class="finding-body">
        <div class="finding-label">${y(i.label)}</div>
        <div class="finding-detail">${y(i.detail)}</div>
      </div>
    </div>`).join(""),a=(o=e.concentrations)!=null&&o.length?`
    <table class="benford-grid" style="margin-top:10px;width:100%">
      <tr style="opacity:.5;font-size:10px">
        <th style="text-align:left">Currency</th>
        <th>Unique actors</th>
        <th>Trades</th>
        <th>Indicator</th>
      </tr>
      ${e.concentrations.map(i=>{let r=i.uniqueActors<5?"#ff5555":i.uniqueActors<10?"#ffb86c":"#50fa7b",l=i.uniqueActors<5?"\u{1F6A8} Wash risk":i.uniqueActors<10?"\u26A0 Low diversity":"\u2713 OK";return`<tr>
          <td class="mono" style="padding:3px 0">${y(i.currency.slice(0,10))}</td>
          <td class="mono" style="text-align:center;color:${r}">${i.uniqueActors}</td>
          <td class="mono" style="text-align:center;opacity:.7">${i.trades}</td>
          <td style="font-size:11px;color:${r}">${l}</td>
        </tr>`}).join("")}
    </table>`:"";t.innerHTML=s+a}function to(e,t,n){let s=document.getElementById(e);if(!s)return;let a={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},o=t.signals.map(i=>`
    <div class="finding finding--${i.sev}">
      <span class="finding-sev ${a[i.sev]||""}">${i.sev.toUpperCase()}</span>
      <div class="finding-body">
        <div class="finding-label">${y(i.label)}</div>
        <div class="finding-detail">${y(i.detail)}</div>
      </div>
    </div>`).join("");s.innerHTML=o+(n||"")}function Qb(e){let t=[["Sample size",e.sampleSize],["Amount entropy",e.amountEntropy!=null?e.amountEntropy.toFixed(2)+" bits":"\u2014",e.amountEntropy!=null&&e.amountEntropy<2?"risk-text-high":""],["Counterparty entropy",e.counterpartyEntropy!=null?e.counterpartyEntropy.toFixed(2)+" bits":"\u2014"],["Time-of-day entropy",e.timeEntropy!=null?e.timeEntropy.toFixed(2)+" bits":"\u2014"],["Unique counterparties",e.uniqueCounterparties],["Verdict",e.verdict,e.verdict==="anomalous"?"risk-text-high":e.verdict==="elevated"?"risk-text-med":""]];to("inspect-entropy-body",e,'<div class="wash-stat-row" style="margin-top:10px"><span>Metric</span><span class="mono" style="opacity:.45">Value</span></div>'+t.map(([n,s,a])=>`<div class="wash-stat-row"><span>${n}</span><span class="mono ${a||""}">${s}</span></div>`).join(""))}function Zb(e){var s;let t=[["Unique counterparties",e.uniqueCounterparties],["Zipf exponent (s)",e.zipfExponent!=null?e.zipfExponent.toFixed(3):"\u2014",e.zipfExponent!=null&&(e.zipfExponent<.4||e.zipfExponent>2.2)?"risk-text-high":""],["Fit quality (R\xB2)",e.rSquared!=null?e.rSquared.toFixed(3):"\u2014",e.rSquared!=null&&e.rSquared<.55?"risk-text-high":""],["Natural range","s \u2248 0.8\u20131.3, R\xB2 > 0.55"],["Verdict",e.verdict,e.verdict==="anomalous"?"risk-text-high":e.verdict==="elevated"?"risk-text-med":""]],n=((s=e.freqTable)==null?void 0:s.slice(0,10).map((a,o)=>{let i=e.freqTable[0]||1,r=(a/i*100).toFixed(0),l=e.freqTable[0]?(e.freqTable[0]/Math.pow(o+1,e.zipfExponent||1)).toFixed(1):0;return`<div class="wash-stat-row">
      <span class="mono" style="min-width:28px">Rank ${o+1}</span>
      <div style="flex:1;height:6px;background:rgba(255,255,255,.06);border-radius:3px;overflow:hidden;margin:0 8px">
        <div style="height:100%;width:${r}%;background:var(--accent);border-radius:3px"></div>
      </div>
      <span class="mono" style="opacity:.6">${a}</span>
    </div>`}).join(""))||"";to("inspect-zipf-body",e,t.map(([a,o,i])=>`<div class="wash-stat-row" style="margin-top:${a==="Unique counterparties"?10:0}px"><span>${a}</span><span class="mono ${i||""}">${o}</span></div>`).join("")+(n?`<div style="margin-top:14px;opacity:.75;font-size:.72rem;letter-spacing:.08em;color:rgba(255,255,255,.45);margin-bottom:6px">COUNTERPARTY RANK\u2013FREQUENCY</div>${n}`:""))}function ey(e){let t=[["Transactions timed",e.totalTimestamped||"\u2014"],["Active span",e.activeSpanDays!=null?e.activeSpanDays+" days":"\u2014"],["Interval CV",e.intervalCV!=null?e.intervalCV.toFixed(3):"\u2014",e.intervalCV!=null&&e.intervalCV<.5?"risk-text-high":""],["Periodicity score",e.periodicityScore!=null?(e.periodicityScore*100).toFixed(0)+"%":"\u2014",e.periodicityScore>.55?"risk-text-high":""],["Burst score (z)",e.burstScore!=null?e.burstScore.toFixed(2):"\u2014"],["Lag-1 autocorrelation",e.autocorrelation!=null?e.autocorrelation.toFixed(3):"\u2014",e.autocorrelation>.6?"risk-text-med":""],["Day-of-week entropy",e.dowEntropy!=null?e.dowEntropy.toFixed(2)+" bits":"\u2014"],["Verdict",e.verdict,e.verdict==="bot-pattern"?"risk-text-high":e.verdict==="elevated"?"risk-text-med":""]],n=["Sun","Mon","Tue","Wed","Thu","Fri","Sat"],s=e.dowBins?Math.max(...e.dowBins,1):1,a=e.dowBins?`
    <div style="margin-top:14px;opacity:.75;font-size:.72rem;letter-spacing:.08em;color:rgba(255,255,255,.45);margin-bottom:6px">DAY-OF-WEEK DISTRIBUTION</div>
    <div style="display:flex;gap:5px;align-items:flex-end;height:42px">
      ${e.dowBins.map((o,i)=>`
        <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:3px">
          <div style="width:100%;height:${(o/s*36).toFixed(0)}px;background:rgba(0,212,255,.35);border-radius:2px 2px 0 0;min-height:2px"></div>
          <div style="font-size:.6rem;opacity:.5">${n[i]}</div>
        </div>`).join("")}
    </div>`:"";to("inspect-timeseries-body",e,t.map(([o,i,r])=>`<div class="wash-stat-row" style="margin-top:${o==="Transactions timed"?10:0}px"><span>${o}</span><span class="mono ${r||""}">${i}</span></div>`).join("")+a)}function ty(e){let t=e.offerCancelCausality,n=e.inflowOutflowCausality,s=(o,i)=>{if(!(o!=null&&o.length))return"";let r=Math.max(.01,...o.map(Math.abs));return`<div style="margin-top:12px;opacity:.75;font-size:.72rem;letter-spacing:.08em;color:rgba(255,255,255,.45);margin-bottom:6px">${i}</div>
    <div style="display:flex;gap:4px;align-items:flex-end;height:40px">
      ${o.map((l,c)=>{let d=(Math.abs(l)/r*36).toFixed(0),u=l>.5?"rgba(255,85,85,.7)":l>.3?"rgba(255,184,108,.6)":"rgba(0,212,255,.3)";return`<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:3px">
          <div style="width:100%;height:${d}px;background:${u};border-radius:2px 2px 0 0;min-height:2px"></div>
          <div style="font-size:.6rem;opacity:.5">L${c}</div>
        </div>`}).join("")}
    </div>`},a=[["Time windows",e.windowCount||"\u2014"],["OfferCreate\u2194Cancel \u03C1",t?t.maxCorr.toFixed(3):"\u2014",t&&t.maxCorr>.55?"risk-text-high":""],["OC lag",t?`${t.maxLag} window${t.maxLag===1?"":"s"} (${t.maxLag*12}h)`:"\u2014"],["Inflow\u2194Outflow \u03C1",n?n.maxCorr.toFixed(3):"\u2014",n&&n.maxCorr>.65?"risk-text-high":""],["IO lag",n?`${n.maxLag} window${n.maxLag===1?"":"s"}`:"\u2014"],["Verdict",e.verdict,e.verdict==="strong-coupling"?"risk-text-high":e.verdict==="elevated"?"risk-text-med":""]];to("inspect-granger-body",e,a.map(([o,i,r])=>`<div class="wash-stat-row" style="margin-top:${o==="Time windows"?10:0}px"><span>${o}</span><span class="mono ${r||""}">${i}</span></div>`).join("")+s(t==null?void 0:t.ccf,"OFFER-CREATE \u2194 CANCEL CROSS-CORRELATION")+s(n==null?void 0:n.ccf,"INFLOW \u2194 OUTFLOW CROSS-CORRELATION"))}function ny(e,t,n,s,a){let o=document.getElementById("inspect-forensic-suite-body");if(!o)return;let i=(v,w=25)=>{if(!v||v.verdict==="insufficient")return null;if(v.chiSq!=null)return v.verdict==="high-deviation"?{val:w,cls:"risk-text-high",label:"HIGH DEVIATION"}:v.verdict==="moderate-deviation"?{val:Math.round(w*.5),cls:"risk-text-med",label:"MODERATE"}:{val:0,cls:"",label:"NORMAL"};let k=v.riskPenalty||0;return k>=18?{val:w,cls:"risk-text-high",label:"ANOMALOUS"}:k>=8?{val:Math.round(w*.5),cls:"risk-text-med",label:"ELEVATED"}:{val:0,cls:"",label:"NORMAL"}},r=[{name:"Benford's Law",icon:"\u{1F4D0}",desc:"First-digit digit distribution vs log-uniform expected",s:i(e)},{name:"Shannon's Entropy",icon:"\u{1F500}",desc:"Randomness of amounts, counterparties, time-of-day, tx types",s:i(t)},{name:"Zipf's Law",icon:"\u{1F4C8}",desc:"Counterparty rank-frequency power-law fit",s:i(n)},{name:"Time Series",icon:"\u{1F550}",desc:"Interval regularity, periodicity, burst detection, autocorrelation",s:i(s)},{name:"Offer/Flow Coupling",icon:"\u{1F517}",desc:"Cross-correlation, not causality: offer create\u2194cancel, inflow\u2194outflow",s:i(a)}],l=r.some(v=>v.s&&v.s.val>0),c=r.filter(v=>{var w;return((w=v.s)==null?void 0:w.cls)==="risk-text-high"}).length,d=r.filter(v=>{var w;return((w=v.s)==null?void 0:w.cls)==="risk-text-med"}).length,u=r.filter(v=>!v.s).length,p,m,f;c>=3?(p="STRONG MANIPULATION SIGNALS \u2014 Multiple independent engines converging on anomalous patterns.",m="#ff5555",f="\u{1F6A8}"):c>=2||c>=1&&d>=2?(p="SIGNIFICANT ANOMALIES \u2014 At least two engines detect non-organic behavior. Cross-reference with Wash Trading and Drain Risk.",m="#ff5555",f="\u26A0\uFE0F"):c>=1||d>=2?(p="ELEVATED RISK \u2014 One or more engines flag behavioral anomalies. Investigate the specific modules for detail.",m="#ffb86c",f="\u26A0\uFE0F"):!l&&u<3?(p="NO ANOMALIES \u2014 All five engines return results consistent with organic financial activity.",m="#50fa7b",f="\u2705"):(p="INSUFFICIENT DATA \u2014 More transaction history needed for a reliable multi-engine assessment.",m="rgba(255,255,255,.4)",f="\u{1F4CA}");let g=r.map(v=>{let w=!v.s,k=w?"rgba(255,255,255,.25)":v.s.val===0?"#50fa7b":v.s.cls==="risk-text-high"?"#ff5555":"#ffb86c",$=w?"NO DATA":v.s.label,T=w?0:v.s.val===0?4:v.s.cls==="risk-text-high"?100:55;return`<div style="background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);border-radius:12px;padding:14px 14px 12px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span style="font-size:1.05rem">${v.icon}</span>
        <div style="flex:1">
          <div style="font-size:.82rem;font-weight:700;color:rgba(255,255,255,.85)">${v.name}</div>
          <div style="font-size:.7rem;color:rgba(255,255,255,.35);margin-top:1px;line-height:1.4">${v.desc}</div>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        <div style="flex:1;height:5px;background:rgba(255,255,255,.08);border-radius:3px;overflow:hidden">
          <div style="height:100%;width:${T}%;background:${k};border-radius:3px;transition:width .6s ease"></div>
        </div>
        <span style="font-size:.65rem;font-weight:800;color:${k};min-width:80px;text-align:right;letter-spacing:.06em">${$}</span>
      </div>
    </div>`}).join(""),b=r.filter(v=>v.s&&v.s.val>0),h="";b.length>=2?h=`<div style="background:rgba(255,184,108,.05);border:1px solid rgba(255,184,108,.2);border-radius:12px;padding:14px 16px;margin-top:14px">
      <div style="font-size:.68rem;font-weight:900;color:#ffb86c;letter-spacing:.12em;text-transform:uppercase;margin-bottom:8px">\u26A1 Convergence Analysis</div>
      <p style="font-size:.84rem;color:rgba(255,255,255,.65);line-height:1.7;margin:0">
        ${b.map(v=>v.name).join(" and ")} are all flagging behavioral anomalies.
        When multiple independent statistical methods converge on the same conclusion \u2014 each using
        different mathematical principles \u2014 the combined signal is substantially stronger than any
        single engine alone. This convergence reduces the probability that the findings are false positives
        from sample-specific artifacts or edge cases.
        ${c>=2?" The strength and breadth of these signals warrants serious investigation.":" Monitor alongside the Wash Trading and Security modules for a complete picture."}
      </p>
    </div>`:l?h=`<div style="background:rgba(0,212,255,.04);border:1px solid rgba(0,212,255,.12);border-radius:12px;padding:14px 16px;margin-top:14px">
      <p style="font-size:.84rem;color:rgba(255,255,255,.55);line-height:1.7;margin:0">
        Only one engine is currently flagging anomalies. A single-engine signal is a hypothesis, not a conclusion.
        Cross-reference with Wash Trading, Benford's Law, and Drain Risk modules to determine whether
        the pattern is isolated or part of a broader behavioral signature.
      </p>
    </div>`:h=`<div style="background:rgba(80,250,123,.04);border:1px solid rgba(80,250,123,.12);border-radius:12px;padding:14px 16px;margin-top:14px">
      <p style="font-size:.84rem;color:rgba(255,255,255,.55);line-height:1.7;margin:0">
        No engine in the forensic suite has flagged this account.
        The five methods use independent mathematical frameworks \u2014
        digit distribution (Benford), information theory (entropy), power laws (Zipf),
        temporal statistics (time series), and cross-correlation (offer/flow coupling).
        Agreement across all five is a strong indicator of organic activity.
      </p>
    </div>`,o.innerHTML=`
    <div style="background:rgba(${m==="#ff5555"?"255,85,85":"255,255,255"},.04);border:1px solid rgba(${m==="#ff5555"?"255,85,85":"255,255,255"},.15);border-radius:12px;padding:14px 16px;margin-bottom:14px;display:flex;align-items:flex-start;gap:12px">
      <span style="font-size:1.4rem;flex-shrink:0;margin-top:2px">${f}</span>
      <div>
        <div style="font-size:.68rem;font-weight:900;letter-spacing:.12em;text-transform:uppercase;color:${m};margin-bottom:5px">FORENSIC SUITE VERDICT</div>
        <p style="font-size:.88rem;color:rgba(255,255,255,.7);line-height:1.65;margin:0">${p}</p>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px">
      ${g}
    </div>
    ${h}`}function sy(e,t,n,s,a,o,i,r=null,l=null,c=!1){let d=x("inspect-addr-badge");d&&(d.textContent=e.length>20?e.slice(0,10)+"\u2026"+e.slice(-8):e,d.title=e,d.dataset.fullAddr=e);let u=x("inspect-risk-score");u&&(u.textContent=i,u.className="irb-score-val "+qi(i));let p=x("inspect-risk-label");p&&(p.textContent=i<20?"Low Risk":i<45?"Moderate":i<70?"High Risk":"Critical",p.className="irb-score-label "+qi(i));let m=x("inspect-acct-grid");if(!m)return;let f=Math.max(0,n-s),g=Number(t.Flags||0),b=r!=null?r===0?"Created today":r===1?"1 day old":r<30?`${r} days old`:r<365?`${Math.floor(r/30)} months old`:`${(r/365).toFixed(1)} years old`:"\u2014",h=l?new Date(l).toLocaleDateString("en-US",{year:"numeric",month:"short",day:"numeric"}):null,v=h?c?`Created ${h}`:`Created ${h} (estimated \u2014 full history not confirmed)`:null,w=yn(n),k=yn(f),$=[{label:"XRP Balance",value:`${_(n,6)} XRP${w}`,mono:!0},{label:"Spendable",value:`${_(f,6)} XRP${k}`,mono:!0,note:`${s} XRP reserved`},{label:"Wallet Age",value:b,note:v,highlight:r!=null&&r<7?"new":null},{label:"Owner Count",value:a,note:`${a*2} XRP tied up`},{label:"Sequence",value:o,mono:!0},{label:"Regular Key",value:t.RegularKey?W(t.RegularKey):"None",warn:!!t.RegularKey,mono:!0},{label:"Master Key",value:g&Ne.lsfDisableMaster?"Disabled":"Active",warn:!!(g&Ne.lsfDisableMaster)}];m.innerHTML=$.map(T=>`
    <div class="acct-cell ${T.warn?"acct-cell--warn":""} ${T.highlight==="new"?"acct-cell--new":""}">
      <div class="acct-cell-label">${y(T.label)}</div>
      <div class="acct-cell-value ${T.mono?"mono":""}">${y(String(T.value))}</div>
      ${T.note?`<div class="acct-cell-note">${y(T.note)}</div>`:""}
      ${T.highlight==="new"?'<div class="acct-cell-new-badge">\u26A0 New wallet</div>':""}
    </div>`).join("")}function ay(e,t,n,s,a){let o=x("inspect-security-body");if(!o)return;let i=Object.entries(Ne).filter(([,d])=>n&d).map(([d])=>d.replace("lsf","")),r=e.controlState,c=r&&{Normal:"#50fa7b","Regular-Key Controlled":"rgba(255,255,255,.7)","Multisig Controlled":"rgba(255,255,255,.7)",Blackholed:"rgba(255,255,255,.7)",Recoverable:"rgba(255,255,255,.7)","Potentially Misconfigured":"#ff5555",Unknown:"#ffb86c"}[r.state]||"rgba(255,255,255,.7)";o.innerHTML=`
    ${r?`
    <div class="drain-level" style="border-color:${c}44;margin-bottom:10px" title="${y(r.reversibility)}">
      <span class="drain-level-icon" style="color:${c}">\u25CF</span>
      <span class="drain-level-text">Account Control State: <strong style="color:${c}">${y(r.state)}</strong></span>
    </div>`:""}
    <div class="audit-items">
      ${e.findings.map(d=>zn(d)).join("")}
    </div>
    ${i.length?`
    <div class="audit-flags">
      <div class="audit-flags-label">Active Flags</div>
      <div class="audit-flags-pills">
        ${i.map(d=>`<span class="flag-pill">${y(d)}</span>`).join("")}
      </div>
    </div>`:""}
    ${s.length?`
    <div class="signer-list-block">
      <div class="signer-list-title">Signer List (Multisig)</div>
      ${s.map(d=>`
        <div class="signer-entries">
          ${(d.SignerEntries||[]).map(u=>{var p,m;return`
            <div class="signer-entry">
              <span class="signer-addr mono">${y(((p=u.SignerEntry)==null?void 0:p.Account)||"\u2014")}</span>
              <span class="signer-weight">weight ${((m=u.SignerEntry)==null?void 0:m.SignerWeight)||1}</span>
            </div>`}).join("")}
          <div class="signer-quorum">Quorum: ${d.SignerQuorum}</div>
        </div>`).join("")}
    </div>`:""}
    ${a.length?`
    <div class="audit-note">
      <span class="audit-note-label">DepositPreauth grants:</span>
      ${a.slice(0,8).map(d=>`<span class="mono">${W(d.Authorize||"")}</span>`).join(", ")}
      ${a.length>8?`+${a.length-8} more`:""}
    </div>`:""}
  `,no("badge-security",e.findings)}function oy(e,t,n,s){let a=x("inspect-drain-body");if(!a)return;let o={low:"#50fa7b",medium:"#ffb86c",high:"#ff8c42",critical:"#ff5555",none:"#50fa7b"},i={low:"\u2713",medium:"\u26A0",high:"\u26A0",critical:"\u26D4",none:"\u2713"},r=e.compromiseRiskLevel??e.riskLevel,l=e.assetDrainSeverity??"none";a.innerHTML=`
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px">
      <div class="drain-level drain-level--${r}" style="flex:1;min-width:220px" title="Could someone else drain this account \u2014 permission/key-state signals only.">
        <span class="drain-level-icon">${i[r]}</span>
        <span class="drain-level-text">Account Compromise Risk: <strong>${r.toUpperCase()}</strong></span>
      </div>
      <div class="drain-level drain-level--${l==="none"?"low":l}" style="flex:1;min-width:220px" title="Is value actually leaving abnormally \u2014 independent of whether keys were ever touched.">
        <span class="drain-level-icon">${i[l]}</span>
        <span class="drain-level-text">Asset Drain Behavior: <strong>${l==="none"?"NONE OBSERVED":l.toUpperCase()}</strong></span>
      </div>
    </div>
    <div class="audit-items">
      ${e.signals.map(c=>zn(c)).join("")}
    </div>
    ${t.length?`
    <div class="drain-sub-section">
      <div class="drain-sub-title">Open Payment Channels</div>
      ${t.map(c=>`
        <div class="drain-channel-row">
          <span class="mono">${W(c.Destination)}</span>
          <span>${_(Number(c.Amount||0)/1e6,2)} XRP allocated</span>
          <span>${_(Number(c.Balance||0)/1e6,2)} XRP claimed</span>
        </div>`).join("")}
    </div>`:""}
    ${n.length?`
    <div class="drain-sub-section">
      <div class="drain-sub-title">Open Escrows</div>
      ${n.slice(0,5).map(c=>`
        <div class="drain-channel-row">
          <span>${c.Destination?W(c.Destination):"self"}</span>
          <span>${_(Number(c.Amount||0)/1e6,2)} XRP</span>
          <span class="mono">${c.Condition?"conditional":c.FinishAfter?"time-locked":""}</span>
        </div>`).join("")}
    </div>`:""}
  `,Ry("badge-drain",e.riskLevel)}function iy(e,t){let n=x("inspect-nft-body");n&&(n.innerHTML=`
    <div class="audit-items">
      ${e.flags.map(s=>zn(s)).join("")}
    </div>
    ${t.length?`
    <div class="nft-grid">
      ${t.slice(0,12).map(s=>ry(s)).join("")}
    </div>
    ${t.length>12?`<div class="nft-more">+${t.length-12} more NFTs</div>`:""}
    `:""}
  `,no("badge-nft",e.flags))}function ry(e){let t=Number(e.Flags||0),n=!!(t&du.lsfTransferable),s=!!(t&du.lsfBurnable),a=e.NFTokenTaxon||0,o=e.TransferFee?`${(e.TransferFee/1e3).toFixed(1)}%`:"0%";return`
    <div class="nft-card">
      <div class="nft-id mono">${e.NFTokenID?W(e.NFTokenID):"\u2014"}</div>
      <div class="nft-meta">
        <span class="nft-badge ${n?"nft-badge--ok":"nft-badge--warn"}">
          ${n?"Transferable":"Non-transferable"}
        </span>
        ${s?'<span class="nft-badge nft-badge--info">Burnable</span>':""}
      </div>
      <div class="nft-details">
        <span>Taxon: ${a}</span>
        <span>Fee: ${o}</span>
      </div>
      ${e.Issuer&&e.Issuer!==e.Account?`<div class="nft-issuer mono">Issuer: ${W(e.Issuer)}</div>`:""}
    </div>`}function ly(e){let t=x("inspect-wash-body");if(!t)return;let n=e.verdict==="clean"||e.verdict==="low-risk"?"#50fa7b":e.verdict==="suspicious"?"#ffb86c":"#ff5555";t.innerHTML=`
    <div class="wash-header">
      <div class="wash-score-wrap">
        <div class="wash-score-bar">
          <div class="wash-score-fill" style="width:${e.score}%;background:${n}"></div>
        </div>
        <div class="wash-score-labels">
          <span>Clean</span>
          <span style="color:${n};font-weight:900">${e.verdict.replace("-"," ").toUpperCase()} (${e.score}/100)</span>
          <span>Certain</span>
        </div>
      </div>
    </div>
    <div class="wash-stats">
      ${Js("Offer Creates",e.stats.creates)}
      ${Js("Offer Cancels",e.stats.cancels)}
      ${Js("Filled Offers",e.stats.fills)}
      ${Js("Payments",e.stats.payments)}
      ${Js("Round-trip Counterparties",e.stats.roundTrip)}
    </div>
    <div class="audit-items">
      ${e.signals.map(a=>zn(a)).join("")}
    </div>
  `;let s=x("badge-wash");if(s){let a=e.verdict==="clean"||e.verdict==="low-risk"?"ok":e.verdict==="suspicious"?"warn":"crit";s.textContent=e.verdict.replace("-"," "),s.className="section-badge section-badge--"+a}}function Js(e,t){return`<div class="wash-stat"><span class="wash-stat-label">${y(e)}</span><span class="wash-stat-val">${t}</span></div>`}function cy(e,t){let n=x("inspect-issuer-body");if(!n)return;let s=t.filter(a=>a.currency&&(a.currency.length===3||a.currency.length===40));n.innerHTML=`
    <div class="audit-items">
      ${e.signals.map(a=>zn(a)).join("")}
    </div>
    ${s.length?`
    <div class="trustline-list">
      ${s.slice(0,10).map(a=>`
        <div class="trustline-row">
          <span class="trustline-currency">${y(Xn(a.currency))}</span>
          <span class="trustline-issuer mono">${W(a.account)}</span>
          <span class="trustline-balance ${Number(a.balance)<0?"trustline-owed":""} mono">
            ${Number(a.balance)<0?"\u25BC ":""}${_(Math.abs(Number(a.balance)),2)}
            ${a.freeze?'<span class="trustline-frozen">FROZEN</span>':""}
            ${a.freeze_peer?'<span class="trustline-frozen trustline-frozen--peer">FROZEN BY ISSUER</span>':""}
          </span>
        </div>`).join("")}
      ${s.length>10?`<div class="trustline-more">+${s.length-10} more trustlines</div>`:""}
    </div>`:""}
  `,no("badge-issuer",e.signals)}function dy(e,t){let n=x("inspect-amm-body");n&&(n.innerHTML=`
    <div class="audit-items">
      ${e.signals.map(s=>zn(s)).join("")}
    </div>
    ${e.positions.length?`
    <div class="amm-positions">
      ${e.positions.map(s=>`
        <div class="amm-position-card">
          <div class="amm-position-currency mono">${W(s.currency)}</div>
          <div class="amm-position-meta">
            <span>Pool: ${W(s.issuer)}</span>
            <span class="amm-position-balance">${_(Math.abs(s.balance),4)} LP tokens</span>
          </div>
        </div>`).join("")}
    </div>`:""}
  `,no("badge-amm",e.signals))}function py(e){let t=x("trust-count-badge");t&&(t.textContent=e.length);let n=x("inspect-trust-body");n&&(n.innerHTML=e.length?e.map(s=>{let a=s.freeze?'<span class="trustline-frozen">Frozen</span>':"",o=s.freeze_peer?'<span class="trustline-frozen trustline-frozen--peer">Issuer Frozen</span>':"",i=s.no_ripple?'<span class="trustline-norip">NoRipple</span>':"";return`
          <div class="trustline-row">
            <span class="trustline-currency">${y(Xn(s.currency))}</span>
            <span class="trustline-issuer mono">${W(s.account)}</span>
            <span class="trustline-balance mono">${y(s.balance)} / ${y(s.limit)}</span>
            <span class="trustline-flags">${a}${o}${i}</span>
          </div>`}).join(""):'<div class="inspect-empty-note">No trustlines found.</div>')}function uy(e,t){let n=x("inspect-tx-timeline");if(!n)return;let s=60,a=e.slice(0,s),o=x("badge-tx");if(o){let i=window._inspectMaxTx||5e3,r=e.length>=i;o.textContent=e.length.toLocaleString()+" tx"+(r?" (cap reached)":""),o.className="section-badge section-badge--neutral",r&&(o.title=`Fetched ${e.length.toLocaleString()} transactions \u2014 cap of ${i.toLocaleString()} reached. Set window._inspectMaxTx = 20000 in console to go deeper.`)}n.innerHTML=a.length?a.map(({tx:i,meta:r})=>{let l=i.TransactionType||"Unknown",c=(r==null?void 0:r.TransactionResult)==="tesSUCCESS",d=Sy(i,r,t),u=ws(i),p=u?new Date(u*1e3).toLocaleString():"\u2014",m=Ty(i,t),f=i.hash?i.hash.slice(0,8)+"\u2026"+i.hash.slice(-4):"",g=i.hash?`https://livenet.xrpl.org/transactions/${i.hash}`:null,b=i.hash?`https://xrpscan.com/tx/${i.hash}`:null;return`
          <div class="tx-row tx-row--${d}">
            <span class="tx-type-badge tx-type-badge--${Cy(l)}">${y(l)}</span>
            <span class="tx-brief">${m}</span>
            <span class="tx-result ${c?"tx-ok":"tx-fail"}">${c?"\u2713":"\u2717"}</span>
            <span class="tx-time">${p}</span>
            ${g?`<span class="tx-links">
              <a href="${g}" target="_blank" rel="noopener" class="tx-explorer-link" title="View on XRPL Livenet">\u{1F517}</a>
              <a href="${b}" target="_blank" rel="noopener" class="tx-explorer-link" title="View on XRPScan">\u{1F50D}</a>
            </span>`:""}
          </div>`}).join(""):'<div class="inspect-empty-note">No transactions found.</div>',e.length>s&&(n.innerHTML+=`<div class="tx-more">Showing ${s} of ${e.length} transactions</div>`)}function Lu(e,t,n){let s=Number((n==null?void 0:n.totalIn)||0),a=Number((t==null?void 0:t.totalOut)||0),o=Number(e||0);if(s<=0&&a<=0)return'<div class="inspect-empty-note">No inbound or outbound XRP flow found in the analysed transaction history.</div>';let i=new Set(((t==null?void 0:t.blackHoleDests)||[]).map(k=>k.addr)),r=new Set(((t==null?void 0:t.exchangeDests)||[]).map(k=>k.addr)),l=new Set(((t==null?void 0:t.newWalletDests)||[]).map(k=>k.addr)),c=0,d=0,u=0,p=0;for(let k of(t==null?void 0:t.destinations)||[])i.has(k.addr)?c+=k.totalXrp:r.has(k.addr)?d+=k.totalXrp:l.has(k.addr)?u+=k.totalXrp:p+=k.totalXrp;let m=Math.max(s,a,o,1),f=k=>(k>0?Math.max(1.5,k/m*100):0).toFixed(1),g=[{label:"Black hole",xrp:c,color:bn.blackhole},{label:"Exchange",xrp:d,color:bn.exchange},{label:"New wallet",xrp:u,color:bn.newWallet},{label:"Other",xrp:p,color:bn.other}].filter(k=>k.xrp>0),b=a>0?Math.max(1.5,a/m*100):0,h=g.map(k=>`<div style="width:${(a>0?k.xrp/a*100:0).toFixed(1)}%;background:${k.color};height:100%" title="${y(k.label)}: ${_(k.xrp,2)} XRP"></div>`).join(""),v=(k,$,T,S,M)=>`
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
      <div style="width:84px;font-size:.72rem;color:rgba(255,255,255,.55);flex-shrink:0">${k}</div>
      <div style="flex:1;height:16px;border-radius:5px;overflow:hidden;background:rgba(255,255,255,.05)">
        <div style="width:${T}%;height:100%;display:flex">${S||`<div style="width:100%;height:100%;background:${M}"></div>`}</div>
      </div>
      <div class="mono" style="width:92px;text-align:right;font-size:.75rem;color:rgba(255,255,255,.75);flex-shrink:0">${_($,2)} XRP</div>
    </div>`,w=g.map(k=>`<span style="font-size:.66rem;color:${k.color};margin-right:12px">\u25CF ${y(k.label)} ${_(k.xrp,0)}</span>`).join("");return`
    <div style="margin-bottom:16px">
      <div style="font-size:.65rem;color:rgba(255,255,255,.35);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px">
        Fund Flow \u2014 Inbound vs Outbound vs Current Balance
      </div>
      ${v("Total In",s,f(s),null,"#50fa7b")}
      ${v("Total Out",a,b,g.length?h:null,"rgba(255,255,255,.3)")}
      ${v("Balance Now",o,f(o),null,"#00d4ff")}
      ${g.length?`<div style="margin-top:2px">${w}</div>`:""}
    </div>`}function my(e,t,n){var l;let s=x("inspect-fundflow-body");if(!s)return;let a=x("badge-fundflow");if(!e.timeline.length&&!e.destinations.length){s.innerHTML='<div class="audit-row audit-row--ok"><span class="audit-icon">\u2713</span><div class="audit-text"><div class="audit-label">No outbound payments found in analysed transaction history</div></div></div>',a&&(a.textContent="Clear",a.className="section-badge section-badge--ok");return}let o=e.exchangeDests.length?`<div class="flow-alert flow-alert--exchange">\u{1F4B1} Funds reached ${e.exchangeDests.length} known exchange(s): ${e.exchangeDests.map(c=>c.entity.name).join(", ")}</div>`:"",i=e.blackHoleDests.length?'<div class="flow-alert flow-alert--blackhole">\u{1F573} Funds sent to black hole address \u2014 irrecoverable!</div>':"",r=(l=e.newWalletDests)!=null&&l.length?`<div class="flow-alert" style="background:rgba(255,85,85,.06);border:1px solid rgba(255,85,85,.25);color:#ff5555;border-radius:8px;padding:10px 14px;margin-bottom:8px">
        \u26A0\uFE0F <strong>${e.newWalletDests.length} destination(s) are brand-new wallets</strong> (Sequence &lt; 10) receiving large XRP amounts.
        New wallets receiving large transfers shortly after creation are a common pattern in drain attacks \u2014 the attacker creates a disposable wallet and drains funds there.
       </div>`:"";if(s.innerHTML=`
    ${Lu(t,e,n)}
    ${r}${o}${i}
    <div class="flow-summary">
      <div class="flow-stat"><span>Unique destinations</span><b>${e.uniqueDests}</b></div>
      <div class="flow-stat"><span>Path payments</span><b>${e.totalPathPay}</b></div>
      <div class="flow-stat"><span>Exchange dests</span><b>${e.exchangeDests.length}</b></div>
    </div>

    <div class="flow-section-h">\u{1F4CD} Top Destinations</div>
    <div class="flow-dest-list">
      ${e.destinations.map((c,d)=>{var g,b,h,v;let u=e.totalOut>0?c.totalXrp/e.totalOut*100:0,p=c.entity?`<span class="flow-entity-badge flow-entity--${c.entity.type}">${y(c.entity.name)}</span>`:"",m=c.pathCount>0?`<span class="flow-path-badge">${c.maxHops}-hop path \xD7${c.pathCount}</span>`:"",f=c.tokens.slice(0,2).map(w=>`<span class="flow-token-chip">${y(w.k.split(".")[0])}</span>`).join("");return`
          <div class="flow-dest-row">
            <div class="flow-dest-rank ${((g=c.entity)==null?void 0:g.type)==="exchange"?"flow-rank--exchange":((b=c.entity)==null?void 0:b.type)==="blackhole"?"flow-rank--blackhole":""}">${d+1}</div>
            <div class="flow-dest-info">
              <div class="flow-dest-top">
                <button class="addr-link mono cut flow-dest-addr" data-addr="${y(c.addr)}" title="${y(c.addr)}">${y(W(c.addr))}</button>
                <a href="https://xrpscan.com/account/${y(c.addr)}" target="_blank" rel="noopener" class="tx-explorer-link" title="View on XRPScan">\u{1F50D}</a>
                ${p}${m}${f}
              </div>
              <div class="flow-bar-row">
                <div class="flow-dest-bar"><div class="flow-dest-fill" style="width:${Math.min(100,u).toFixed(1)}%;background:${((h=c.entity)==null?void 0:h.type)==="exchange"?"#00d4ff":((v=c.entity)==null?void 0:v.type)==="blackhole"?"#ff5555":"rgba(80,250,123,.7)"}"></div></div>
                <span class="mono flow-dest-pct">${u.toFixed(0)}%</span>
              </div>
              <div class="flow-dest-meta">
                <span class="mono">${_(c.totalXrp,2)} XRP</span>
                <span class="flow-dest-cnt">${c.txCount} tx</span>
                ${c.txCount>1?`<span class="flow-dest-span">${Mu(c.firstSeen,c.lastSeen)}</span>`:""}
              </div>
            </div>
          </div>`}).join("")}
    </div>

    <div class="flow-section-h" style="margin-top:18px">\u23F1 Outflow Timeline</div>
    <div class="flow-timeline">
      ${e.timeline.map(c=>{let d=new Date(c.ts*1e3).toLocaleDateString(),u=new Date(c.ts*1e3).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"}),p=c.amtXrp>0?`${_(c.amtXrp,2)} XRP`:c.amtToken?`${_(c.amtToken.value,2)} ${c.amtToken.currency}`:"\u2014",m=Hn(c.dest),f=m?`<span class="flow-entity-badge flow-entity--${m.type}" style="font-size:.65rem">${y(m.name)}</span>`:"";return`
          <div class="flow-tx-row">
            <span class="flow-tx-date">${d} ${u}</span>
            <button class="addr-link mono cut flow-tx-dest" data-addr="${y(c.dest)}" title="${y(c.dest)}">${y(W(c.dest))}</button>
            ${f}
            <span class="flow-tx-amt mono">${p}</span>
            ${c.isPathPay?`<span class="flow-path-tag">${c.hopCount}-hop</span>`:""}
          </div>`}).join("")}
    </div>
  `,a){let c=e.blackHoleDests.length||e.exchangeDests.length>2;a.textContent=`${e.uniqueDests} dests`,a.className=`section-badge section-badge--${c?"crit":e.uniqueDests>0?"warn":"ok"}`}}function Mu(e,t){if(!e||!t)return"";let n=new Date(e*1e3).toLocaleDateString(),s=new Date(t*1e3).toLocaleDateString();return n===s?n:`${n} \u2013 ${s}`}function fy(e,t){let n=x("inspect-issuer-connections-body");if(!n)return;let s=e.totalIssued,a=x("badge-issuer-connections");if(n.innerHTML=`
    <div class="audit-items">
      ${e.signals.map(o=>zn(o)).join("")}
    </div>

    ${s>0?`
    <div class="conn-stats">
      <div class="conn-stat"><span>Total Supply</span><b class="mono">${_(s,0)}</b></div>
      <div class="conn-stat"><span>Trustline Holders</span><b>${e.holderCount}</b></div>
      <div class="conn-stat"><span>Accts Created</span><b>${e.createdAccts.length}</b></div>
      <div class="conn-stat"><span>Distribution txs</span><b>${e.distributions.length}</b></div>
    </div>

    ${e.topHolders.length?`
    <div class="conn-section-h">\u{1F3C6} Supply Distribution \u2014 Top Holders</div>
    <div class="conn-holders">
      ${e.topHolders.map((o,i)=>{let r=s>0?o.balance/s*100:0,l=r>50?"#ff5555":r>25?"#ffb86c":r>10?"#f1fa8c":"#50fa7b";return`
          <div class="conn-holder-row">
            <span class="conn-holder-rank">${i+1}</span>
            <button class="addr-link mono cut conn-holder-addr" data-addr="${y(o.addr)}" title="${y(o.addr)}">${y(W(o.addr))}</button>
            <div class="conn-holder-bar-wrap">
              <div class="conn-holder-bar">
                <div class="conn-holder-fill" style="width:${Math.min(100,r).toFixed(1)}%;background:${l}"></div>
              </div>
              <span class="mono conn-holder-pct">${r.toFixed(1)}%</span>
            </div>
            <span class="mono conn-holder-amt">${_(o.balance,0)} ${y(o.currency.slice(0,8))}</span>
          </div>`}).join("")}
    </div>`:""}

    ${e.createdAccts.length?`
    <div class="conn-section-h">\u{1F195} Accounts Created by This Issuer</div>
    <div class="conn-created-list">
      ${e.createdAccts.slice(0,12).map(o=>`
        <button class="addr-chip mono" data-addr="${y(o)}" title="${y(o)}">${y(W(o))}</button>
      `).join("")}
      ${e.createdAccts.length>12?`<span style="opacity:.65;font-size:.78rem">+${e.createdAccts.length-12} more</span>`:""}
    </div>`:""}

    `:""}

    ${e.mirrorGroups.length?`
    <div class="conn-section-h">\u{1F501} Mirror Wallet Clusters</div>
    <div class="conn-mirror-list">
      ${e.mirrorGroups.map(o=>`
        <div class="conn-mirror-group">
          <div class="conn-mirror-h">~${_(o.approxAmt,0)} tokens \xB7 ${o.accounts.length} wallets</div>
          <div class="conn-mirror-addrs">
            ${o.accounts.slice(0,8).map(i=>`
              <button class="addr-chip mono" data-addr="${y(i.addr)}" title="${y(i.addr)}">${y(W(i.addr))}</button>
            `).join("")}
            ${o.accounts.length>8?`<span class="conn-mirror-more">+${o.accounts.length-8} more</span>`:""}
          </div>
        </div>
      `).join("")}
    </div>`:""}
  `,a){let o=e.signals.some(i=>i.sev==="critical")?"crit":e.signals.some(i=>i.sev==="warn")?"warn":e.signals.some(i=>i.sev==="info")?"neutral":"ok";a.className=`section-badge section-badge--${o}`,a.textContent=s>0?`${e.holderCount} holders`:"No issuance"}}function hy(e){var d;let t=document.getElementById("inspect-fee-analysis-body");if(!t||!e)return;let n={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},s=(e.signals||[]).map(u=>`
    <div class="finding finding--${u.sev}">
      <span class="finding-sev ${n[u.sev]||""}">${u.sev.toUpperCase()}</span>
      <div class="finding-body">
        <div class="finding-label">${y(u.label)}</div>
        <div class="finding-detail">${y(u.detail)}</div>
      </div>
    </div>`).join(""),a=e.avgFeeMultiplier!=null?`
    <div class="wash-stat-row" style="margin-top:10px">
      <span>Average fee multiplier</span><span class="mono">${e.avgFeeMultiplier}x base (12 drops)</span>
    </div>
    <div class="wash-stat-row">
      <span>High-fee transactions (>100x)</span><span class="mono ${e.spikeCount>5?"risk-text-high":""}">${e.spikeCount}</span>
    </div>`:"",o=(d=e.topFeeHashes)!=null&&d.length?`
    <div style="margin-top:12px;font-size:.72rem;color:rgba(255,255,255,.4);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">TOP FEE TRANSACTIONS</div>
    ${e.topFeeHashes.map(u=>`
      <div class="wash-stat-row">
        <a href="https://livenet.xrpl.org/transactions/${y(u.hash)}" target="_blank" rel="noopener"
           class="mono" style="font-size:.75rem;color:var(--accent);text-decoration:none">${W(u.hash)}</a>
        <span class="mono" style="color:#ffb86c">${u.mult}x base fee</span>
      </div>`).join("")}`:"",i=document.getElementById("section-fee-analysis"),r=(e.signals||[]).some(u=>u.sev==="warn"||u.sev==="critical");i&&(i.style.display="");let l=r?"":`
    <div class="finding finding--ok">
      <span class="finding-sev sev-ok">OK</span>
      <div class="finding-body">
        <div class="finding-label">No elevated fees detected</div>
        <div class="finding-detail">Transaction fees across this account's history are within normal ranges.</div>
      </div>
    </div>`;t.innerHTML=l+s+a+o;let c=document.getElementById("badge-fee-analysis");c&&(c.textContent=r?"Elevated":"Normal",c.className=`section-badge section-badge--${r?"warn":"ok"}`)}function gy(e){var d,u;let t=document.getElementById("inspect-desttag-body");if(!t||!e)return;let n={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},s=(e.signals||[]).map(p=>`
    <div class="finding finding--${p.sev}">
      <span class="finding-sev ${n[p.sev]||""}">${p.sev.toUpperCase()}</span>
      <div class="finding-body">
        <div class="finding-label">${y(p.label)}</div>
        <div class="finding-detail">${y(p.detail)}</div>
      </div>
    </div>`).join(""),a=(d=e.tagProfiles)!=null&&d.length?`
    <div style="margin-top:12px;font-size:.72rem;color:rgba(255,255,255,.4);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">DESTINATION TAG SUMMARY</div>
    ${e.tagProfiles.slice(0,8).map(p=>`
      <div class="wash-stat-row">
        <span>${y(p.name)}</span>
        <span class="mono" style="opacity:.65">${p.txCount} tx \xB7 ${p.uniqueTags} unique tag${p.uniqueTags!==1?"s":""}</span>
      </div>`).join("")}`:"",o=document.getElementById("section-desttag"),i=(e.signals||[]).some(p=>p.sev==="warn"||p.sev==="critical"),r=((u=e.tagProfiles)==null?void 0:u.length)>0;o&&(o.style.display="");let l=!i&&!r?`
    <div class="finding finding--ok">
      <span class="finding-sev sev-ok">OK</span>
      <div class="finding-body">
        <div class="finding-label">No destination tag patterns to report</div>
        <div class="finding-detail">No exchange payments with destination tags were found in this account's history.</div>
      </div>
    </div>`:"";t.innerHTML=l+s+a;let c=document.getElementById("badge-desttag");c&&(c.textContent=i?"Check":"Normal",c.className=`section-badge section-badge--${i?"warn":"ok"}`)}function vy(e){var r;let t=document.getElementById("section-pathdepth"),n=document.getElementById("inspect-pathdepth-body"),s=document.getElementById("badge-pathdepth");if(t&&(t.style.display=""),!n)return;if(!e||e.noData||!((r=e.signals)!=null&&r.length)){n.innerHTML='<div class="inspect-empty-note">No path payments found.</div>',s&&(s.textContent="None",s.className="section-badge section-badge--neutral");return}let a={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},o=e.signals.map(l=>`
    <div class="finding finding--${l.sev}">
      <span class="finding-sev ${a[l.sev]||""}">${l.sev.toUpperCase()}</span>
      <div class="finding-body">
        <div class="finding-label">${y(l.label)}</div>
        <div class="finding-detail">${y(l.detail)}</div>
      </div>
    </div>`).join(""),i=`
    <div class="wash-stat-row" style="margin-top:10px">
      <span>Total path payments</span><span class="mono">${e.roundTripCount+e.deepHopCount+(e.selfRoutedCount||0)+(e.signals.filter(l=>l.sev==="ok").length>0?1:0)}</span>
    </div>
    ${e.roundTripCount?`<div class="wash-stat-row"><span>XRP\u2192IOU\u2192XRP round-trips</span><span class="mono ${e.roundTripCount>=3?"risk-text-high":"risk-text-med"}">${e.roundTripCount}</span></div>`:""}
    ${e.deepHopCount?`<div class="wash-stat-row"><span>Deep hop chains (\u22653 hops)</span><span class="mono">${e.deepHopCount}</span></div>`:""}
    ${e.selfRoutedCount?`<div class="wash-stat-row"><span>Self-routed payments</span><span class="mono risk-text-high">${e.selfRoutedCount}</span></div>`:""}`;if(n.innerHTML=o+i,s){let l=e.signals.some(d=>d.sev==="critical"),c=e.signals.some(d=>d.sev==="warn");s.textContent=l?"Critical":c?"Check":"Normal",s.className=`section-badge section-badge--${l?"crit":c?"warn":"ok"}`}}function by(e){var r,l,c;let t=x("inspect-inbound-body");if(!t)return;let n={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},s=(e.signals||[]).map(d=>`
    <div class="finding finding--${d.sev}">
      <span class="finding-sev ${n[d.sev]||""}">${d.sev.toUpperCase()}</span>
      <div class="finding-body"><div class="finding-label">${y(d.label)}</div>
      <div class="finding-detail">${y(d.detail)}</div></div>
    </div>`).join(""),a=`
    <div class="flow-summary" style="margin-top:10px">
      <div class="flow-stat"><span>Inbound payments</span><b>${((r=e.timeline)==null?void 0:r.length)||0}</b></div>
      <div class="flow-stat"><span>Unique sources</span><b>${e.uniqueSources}</b></div>
      <div class="flow-stat"><span>Total XRP received</span><b class="mono">${_(e.totalIn,2)}</b></div>
      <div class="flow-stat"><span>Exchange sources</span><b>${((l=e.exchangeSrcs)==null?void 0:l.length)||0}</b></div>
    </div>`,o=(c=e.topSources)!=null&&c.length?`
    <div class="flow-section-h" style="margin-top:14px">\u{1F4E5} Top Funding Sources</div>
    <div class="flow-dest-list">
      ${e.topSources.map((d,u)=>{let p=e.totalIn>0?(d.totalXrp/e.totalIn*100).toFixed(0):0,m=d.entity,f=m?`<span class="flow-entity-badge flow-entity--${m.type}">${y(m.name)}</span>`:"";return`<div class="flow-dest-row">
          <div class="flow-dest-rank">${u+1}</div>
          <div class="flow-dest-info">
            <div class="flow-dest-top">
              <a href="https://xrpscan.com/account/${y(d.addr)}" target="_blank" rel="noopener" class="addr-link mono cut">${y(W(d.addr))}</a>
              ${f}
            </div>
            <div class="flow-bar-row">
              <div class="flow-dest-bar"><div class="flow-dest-fill" style="width:${Math.min(100,p)}%;background:${(m==null?void 0:m.type)==="exchange"?"#00d4ff":"rgba(80,250,123,.7)"}"></div></div>
              <span class="mono flow-dest-pct">${p}%</span>
            </div>
            <div class="flow-dest-meta">
              <span class="mono">${_(d.totalXrp,2)} XRP${yn(d.totalXrp)}</span>
              <span class="flow-dest-cnt">${d.txCount} tx</span>
            </div>
          </div>
        </div>`}).join("")}
    </div>`:"";t.innerHTML=s+a+o;let i=x("badge-inbound");if(i){let d=(e.signals||[]).some(u=>u.sev==="warn"||u.sev==="critical");i.textContent=`${e.uniqueSources} src${e.uniqueSources!==1?"s":""}`,i.className=`section-badge section-badge--${d?"warn":"neutral"}`}}function yy(e){var r;let t=x("section-memos"),n=x("inspect-memos-body");if(t&&(t.style.display=""),!n)return;if(!e||!((r=e.allMemos)!=null&&r.length)){n.innerHTML='<div class="inspect-empty-note">No memos found.</div>';let l=x("badge-memos");l&&(l.textContent="None",l.className="section-badge section-badge--neutral");return}let s={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},a=(e.signals||[]).map(l=>`
    <div class="finding finding--${l.sev}">
      <span class="finding-sev ${s[l.sev]||""}">${l.sev.toUpperCase()}</span>
      <div class="finding-body"><div class="finding-label">${y(l.label)}</div>
      <div class="finding-detail">${y(l.detail)}</div></div>
    </div>`).join(""),o=e.allMemos.slice(0,10).map(l=>`
    <div class="wash-stat-row" style="flex-direction:column;align-items:flex-start;gap:2px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.05)">
      <div style="font-size:.72rem;color:rgba(255,255,255,.35)">${y(l.type)} \xB7 <a href="https://livenet.xrpl.org/transactions/${y(l.tx)}" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none">${W(l.tx)}</a></div>
      <div style="font-size:.82rem;word-break:break-all;color:rgba(255,255,255,.75)">${y(l.text.slice(0,120))}${l.text.length>120?"\u2026":""}</div>
    </div>`).join("");n.innerHTML=a+`<div style="margin-top:10px;font-size:.72rem;color:rgba(255,255,255,.4);text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px">MEMO CONTENTS (${e.allMemos.length} found)</div>`+o;let i=x("badge-memos");if(i){let l=(e.signals||[]).some(d=>d.sev==="critical"),c=(e.signals||[]).some(d=>d.sev==="warn");i.textContent=l?"Scam text":c?"Patterns":"Normal",i.className=`section-badge section-badge--${l?"crit":c?"warn":"ok"}`}}function wy(e){var l;let t=x("section-escrow-depth"),n=x("inspect-escrow-depth-body");if(t&&(t.style.display=""),!n)return;if(!e||!((l=e.escrows)!=null&&l.length)){n.innerHTML='<div class="inspect-empty-note">No escrows found.</div>';let c=x("badge-escrow-depth");c&&(c.textContent="None",c.className="section-badge section-badge--neutral");return}let s={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},a=(e.signals||[]).map(c=>`
    <div class="finding finding--${c.sev}">
      <span class="finding-sev ${s[c.sev]||""}">${c.sev.toUpperCase()}</span>
      <div class="finding-body"><div class="finding-label">${y(c.label)}</div>
      <div class="finding-detail">${y(c.detail)}</div></div>
    </div>`).join(""),o=946684800,i=e.escrows.map(c=>`
    <div class="wash-stat-row">
      <span>${c.isSelfEscrow?"Self-escrow":c.isThirdParty?'<span style="color:#ff5555">Third-party \u2192</span>':W(c.dest||"")}</span>
      <span class="mono">${_(c.amtXrp,2)} XRP${yn(c.amtXrp)}</span>
      <span style="font-size:.72rem;opacity:.55">${c.daysToFinish!=null?c.daysToFinish<0?"matured":c.daysToFinish+"d":c.conditional?"conditional":"\u2014"}</span>
    </div>`).join("");n.innerHTML=a+`<div style="margin-top:10px">${i}</div>`;let r=x("badge-escrow-depth");if(r){let c=e.hasThirdParty;r.textContent=`${e.escrows.length} escrow${e.escrows.length!==1?"s":""}`,r.className=`section-badge section-badge--${c?"warn":"neutral"}`}}function xy(e){var r;let t=x("section-checks"),n=x("inspect-checks-body");if(t&&(t.style.display=""),!n)return;if(!e||!((r=e.checks)!=null&&r.length)){n.innerHTML='<div class="inspect-empty-note">No open Checks found.</div>';let l=x("badge-checks");l&&(l.textContent="None",l.className="section-badge section-badge--neutral");return}let s={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},a=(e.signals||[]).map(l=>`
    <div class="finding finding--${l.sev}">
      <span class="finding-sev ${s[l.sev]||""}">${l.sev.toUpperCase()}</span>
      <div class="finding-body"><div class="finding-label">${y(l.label)}</div>
      <div class="finding-detail">${y(l.detail)}</div></div>
    </div>`).join(""),o=e.checks.map(l=>{var c,d;return`
    <div class="wash-stat-row">
      <span class="mono">${W(l.sender)} \u2192 ${W(l.dest||"")}</span>
      <span class="mono">${l.amtXrp!=null?_(l.amtXrp,2)+" XRP"+yn(l.amtXrp):(((c=l.amtToken)==null?void 0:c.value)||"?")+" "+((d=l.amtToken)==null?void 0:d.currency)}</span>
      <span style="font-size:.72rem;${l.expired?"color:#ff5555":"opacity:.55"}">${l.expired?"Expired":"Open"}</span>
    </div>`}).join("");n.innerHTML=a+`<div style="margin-top:10px">${o}</div>`;let i=x("badge-checks");i&&(i.textContent=`${e.checks.length} check${e.checks.length!==1?"s":""}`,i.className="section-badge section-badge--neutral")}function ky(e){let t=x("section-livebook"),n=x("inspect-livebook-body");if(t&&(t.style.display=""),!n)return;if(!(e!=null&&e.hasData)){n.innerHTML='<div class="inspect-empty-note">No live order book activity found for this wallet.</div>';let r=x("badge-livebook");r&&(r.textContent="None",r.className="section-badge section-badge--neutral");return}let s={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},a=(e.signals||[]).map(r=>`
    <div class="finding finding--${r.sev}">
      <span class="finding-sev ${s[r.sev]||""}">${r.sev.toUpperCase()}</span>
      <div class="finding-body"><div class="finding-label">${y(r.label)}</div>
      <div class="finding-detail">${y(r.detail)}</div></div>
    </div>`).join(""),o=`
    <div class="wash-stat-row" style="margin-top:10px">
      <span>Pair</span><span class="mono">${y(e.pair.split("\u2194").map(r=>r.split("+")[0]).join(" \u2194 "))}</span>
    </div>
    <div class="wash-stat-row">
      <span>Live orders in book</span><span class="mono">${e.offerCount}</span>
    </div>
    ${e.ourShare>0?`<div class="wash-stat-row"><span>This wallet's book share</span><span class="mono ${e.ourShare>.25?"risk-text-high":""}">${(e.ourShare*100).toFixed(1)}%</span></div>`:""}
    ${e.wallShare>.3?`<div class="wash-stat-row"><span>Largest single order share</span><span class="mono ${e.wallShare>.4?"risk-text-high":"risk-text-med"}">${(e.wallShare*100).toFixed(1)}%</span></div>`:""}`;n.innerHTML=a+o;let i=x("badge-livebook");if(i){let r=(e.signals||[]).some(c=>c.sev==="critical"),l=(e.signals||[]).some(c=>c.sev==="warn");i.textContent=r?"Wall order":l?"Check":"Normal",i.className=`section-badge section-badge--${r?"crit":l?"warn":"ok"}`}}function $y(e,...t){let n=x("inspect-risk-breakdown");if(!n)return;let s=Gb(e,...t);if(!s.length){n.innerHTML="";return}let a=Math.max(1,s.reduce((o,i)=>o+i.pts,0));n.innerHTML=`
    <div style="margin-top:8px">
      <div style="font-size:.65rem;color:rgba(255,255,255,.35);text-transform:uppercase;letter-spacing:.1em;margin-bottom:5px">Score Breakdown</div>
      <div style="display:flex;height:8px;border-radius:4px;overflow:hidden;gap:1px">
        ${s.map(o=>`<div style="flex:${o.pts};background:${o.color};opacity:.85" title="${y(o.label)}: ${o.pts} pts"></div>`).join("")}
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px">
        ${s.map(o=>`<span style="font-size:.67rem;color:${o.color};opacity:.8">${o.icon} ${y(o.label)} ${o.pts}pts</span>`).join("")}
      </div>
    </div>`}function zn({sev:e,label:t,detail:n,confidence:s,observed:a,alternativeExplanations:o,evidenceAgainstBenign:i,classification:r}){let l={ok:"\u2713",info:"\u2139",warn:"\u26A0",critical:"\u26D4"},c=(d,u)=>u&&u.length?`<div class="audit-evidence-group">
         <div class="audit-evidence-title">${y(d)}</div>
         <ul class="audit-evidence-list">${u.map(p=>`<li>${y(p)}</li>`).join("")}</ul>
       </div>`:"";return`
    <div class="audit-row audit-row--${e}">
      <span class="audit-icon">${l[e]||"\u2139"}</span>
      <div class="audit-text">
        <div class="audit-label">${y(t)}${s!=null?` <span class="audit-confidence">confidence ${Math.round(s*100)}%</span>`:""}</div>
        ${n?`<div class="audit-detail">${y(n)}</div>`:""}
        ${c("Observed",a)}
        ${c("Alternative explanations",o)}
        ${c("Evidence against benign explanation",i)}
        ${r?`<div class="audit-classification">${y(r)}</div>`:""}
      </div>
    </div>`}function qi(e){return e<20?"risk-ok":e<45?"risk-medium":e<70?"risk-high":"risk-critical"}function Sy(e,t,n){if(Zv.has(e.TransactionType))return"warn";if(e.TransactionType==="NFTokenCreateOffer"){let s=e.Amount;if(!s||typeof s=="string"&&Number(s)<1e6)return"critical"}return t!=null&&t.TransactionResult&&t.TransactionResult!=="tesSUCCESS"?"fail":"normal"}function Ty(e,t){var s,a,o,i,r;let n=e.TransactionType;if(n==="Payment"){let l=e.Account===t?`\u2192 ${W(e.Destination)}`:`\u2190 ${W(e.Account)}`,c=typeof e.Amount=="string"?`${_(Number(e.Amount)/1e6,2)} XRP`:(s=e.Amount)!=null&&s.value?`${_(Number(e.Amount.value),2)} ${e.Amount.currency}`:"";return y(`${c} ${l}`)}if(n==="OfferCreate"){let l=typeof e.TakerPays=="string"?`${_(Number(e.TakerPays)/1e6,2)} XRP`:`${_(Number((a=e.TakerPays)==null?void 0:a.value),2)} ${(o=e.TakerPays)==null?void 0:o.currency}`,c=typeof e.TakerGets=="string"?`${_(Number(e.TakerGets)/1e6,2)} XRP`:`${_(Number((i=e.TakerGets)==null?void 0:i.value),2)} ${(r=e.TakerGets)==null?void 0:r.currency}`;return y(`${l} for ${c}`)}return n==="SetRegularKey"?y(`Key: ${e.RegularKey?W(e.RegularKey):"REMOVED"}`):n==="NFTokenMint"?y(`Taxon: ${e.NFTokenTaxon??"\u2014"}`):n==="NFTokenBurn"?y(`Token: ${e.NFTokenID?W(e.NFTokenID):"\u2014"}`):n==="AMMDeposit"?y("Pool deposit"):n==="AMMWithdraw"?y("LP withdrawal"):n==="EscrowCreate"?y(`${_(Number(e.Amount||0)/1e6,2)} XRP \u2192 ${W(e.Destination)}`):""}function Cy(e){return{Payment:"payment",OfferCreate:"offer",OfferCancel:"offer",NFTokenMint:"nft",NFTokenBurn:"nft",NFTokenCreateOffer:"nft",NFTokenAcceptOffer:"nft",SetRegularKey:"auth",SignerListSet:"auth",AccountSet:"auth",AccountDelete:"auth",TrustSet:"trust",AMMCreate:"amm",AMMDeposit:"amm",AMMWithdraw:"amm",AMMVote:"amm",AMMBid:"amm",EscrowCreate:"escrow",EscrowFinish:"escrow",EscrowCancel:"escrow",PaymentChannelCreate:"channel",PaymentChannelFund:"channel",PaymentChannelClaim:"channel"}[e]||"other"}function ws(e){let t=(e==null?void 0:e.date)||(e==null?void 0:e.close_time)||(e==null?void 0:e.ledger_close_time);return t?Number(t)+fu:0}function Xn(e){if(!e||e.length!==40)return e||"";try{let t="";for(let n=0;n<e.length;n+=2){let s=parseInt(e.slice(n,n+2),16);if(s!==0){if(s<32||s>126)return e;t+=String.fromCharCode(s)}}return t||e}catch{return e}}function Py(e,t,n,s,a,o,i,r,l,c,d,u,p,m,f,g,b,h,v,w={}){var K,ue,be,ze,ft,nn,da,br,yr,wr,xr,kr,$r;let{feeAnalysis:k=null,destTagAnalysis:$=null,pathDepthAnalysis:T=null,gatewayBalances:S=null,inboundFlowAnalysis:M=null,memoAnalysis:C=null,escrowDepthAnalysis:E=null,checkAnalysis:R=null,liveBookAnalysis:O=null,walletAgeDays:I=null,walletCreatedTs:D=null}=w,F=946684800,H=new Date().toLocaleString(),N=e.slice(0,10)+"\u2026"+e.slice(-8),z=s<20?"LOW":s<45?"MODERATE":s<70?"HIGH":"CRITICAL",te=s<20?"#50fa7b":s<45?"#ffb86c":s<70?"#ff8c42":"#ff5555",oe=f.filter(({tx:A})=>A.date!=null),pe=f.length.toLocaleString()+" transactions",ie="",ne=0;if(oe.length>=2){let A=oe[0].tx.date+F,Pe=oe[oe.length-1].tx.date+F;ne=Math.round((Pe-A)/86400);let sn=new Date(A*1e3).toLocaleDateString("en-US",{year:"numeric",month:"short",day:"numeric"}),rt=new Date(Pe*1e3).toLocaleDateString("en-US",{year:"numeric",month:"short",day:"numeric"});ie=`${sn} \u2013 ${rt} (${ne} days)`,pe=`${f.length.toLocaleString()} transactions from ${ie}`}let ce=[],G=(A,Pe,sn,rt,Vn,ht={})=>ce.push({module:A,sev:Pe,headline:sn,detail:rt||"",hashes:Vn||[],category:ht.category??null,confidence:ht.confidence??null,observed:ht.observed??[],alternativeExplanations:ht.alternativeExplanations??[],evidenceAgainstBenign:ht.evidenceAgainstBenign??[],classification:ht.classification??null});for(let A of a.findings||[])G("Security",A.sev,A.label,A.detail,A.hashes,A);G("Drain Risk",o.riskLevel==="low"?"ok":o.riskLevel==="medium"?"warn":"critical","Drain Risk Level: "+o.riskLevel.toUpperCase(),null);for(let A of o.signals||[])A.sev!=="ok"&&G("Drain Risk",A.sev,A.label,A.detail,A.hashes,A);for(let A of i.flags||[])A.sev!=="ok"&&G("NFT",A.sev,A.label,A.detail,A.hashes,A);r.verdict&&!["clean","low-risk"].includes(r.verdict)&&G("Wash Trading",r.score>=60?"critical":"warn",`Wash score ${r.score}/100 \u2014 ${r.verdict.replace("-"," ")}`,null);for(let A of r.signals||[])A.sev!=="ok"&&G("Wash Trading",A.sev,A.label,A.detail,A.hashes,A);for(let A of l.signals||[])A.sev!=="ok"&&G("Benford's Law",A.sev,A.label,A.detail,A.hashes,A);for(let A of c.signals||[])A.sev!=="ok"&&G("Volume Concentration",A.sev,A.label,A.detail,A.hashes,A);for(let A of(g==null?void 0:g.signals)||[])A.sev!=="ok"&&G("Shannon's Entropy",A.sev,A.label,A.detail,A.hashes,A);for(let A of(b==null?void 0:b.signals)||[])A.sev!=="ok"&&G("Zipf's Law",A.sev,A.label,A.detail,A.hashes,A);for(let A of(h==null?void 0:h.signals)||[])A.sev!=="ok"&&G("Time Series",A.sev,A.label,A.detail,A.hashes,A);for(let A of(v==null?void 0:v.signals)||[])A.sev!=="ok"&&G("Offer/Flow Coupling",A.sev,A.label,A.detail,A.hashes,A);for(let A of d.signals||[])A.sev!=="ok"&&G("Token Issuer",A.sev,A.label,A.detail,A.hashes,A);for(let A of u.signals||[])A.sev!=="ok"&&G("AMM",A.sev,A.label,A.detail,A.hashes,A);(K=p.blackHoleDests)!=null&&K.length&&G("Fund Flow","critical",`Funds sent to ${p.blackHoleDests.length} black hole address(es)`,"These funds are permanently irrecoverable."),(ue=p.exchangeDests)!=null&&ue.length&&G("Fund Flow","warn",`${p.exchangeDests.length} known exchange(s) received funds`,p.exchangeDests.map(A=>A.entity.name).join(", ")),(be=p.newWalletDests)!=null&&be.length&&G("Fund Flow","critical",`${p.newWalletDests.length} brand-new wallet(s) received large XRP transfers`,"New wallets (Sequence < 10) receiving large amounts are a classic drain-mule pattern.");for(let A of m.signals||[])A.sev!=="ok"&&G("Issuer Connections",A.sev,A.label,A.detail);for(let A of(k==null?void 0:k.signals)||[])A.sev!=="ok"&&G("Fee Spikes",A.sev,A.label,A.detail,A.hashes);for(let A of($==null?void 0:$.signals)||[])A.sev!=="ok"&&G("Destination Tags",A.sev,A.label,A.detail);for(let A of(T==null?void 0:T.signals)||[])A.sev!=="ok"&&G("Path Payments",A.sev,A.label,A.detail,A.hashes);for(let A of(M==null?void 0:M.signals)||[])A.sev!=="ok"&&G("Inbound Flow",A.sev,A.label,A.detail);for(let A of(C==null?void 0:C.signals)||[])A.sev!=="ok"&&G("Memo Analysis",A.sev,A.label,A.detail);for(let A of(E==null?void 0:E.signals)||[])A.sev!=="ok"&&G("Escrow Depth",A.sev,A.label,A.detail);for(let A of(O==null?void 0:O.signals)||[])A.sev!=="ok"&&G("Live Order Book",A.sev,A.label,A.detail);let Se=ce.filter(A=>A.sev==="critical"),X=ce.filter(A=>A.sev==="warn");window._lastAllFindings=ce;let q=A=>{let Pe={critical:"background:rgba(255,85,85,.15);border:1px solid rgba(255,85,85,.35);color:#ff5555",warn:"background:rgba(255,184,108,.10);border:1px solid rgba(255,184,108,.30);color:#ffb86c",info:"background:rgba(120,180,255,.08);border:1px solid rgba(120,180,255,.18);color:rgba(120,180,255,.9)",ok:"background:rgba(80,250,123,.08);border:1px solid rgba(80,250,123,.22);color:#50fa7b"};return`<span style="padding:2px 8px;border-radius:999px;font-size:.68rem;font-weight:900;letter-spacing:.3px;text-transform:uppercase;${Pe[A]||Pe.info}">${A.toUpperCase()}</span>`};function se(){var rt,Vn,ht,$n,Sr,Tr,Cr,Pr,Lr,Mr,Ar,Er;let A=[];A.push(`<strong>Address ${N}</strong> was inspected on ${H}. The account holds <strong>${_(n,4)} XRP</strong>. This report analyzed <strong>${pe}</strong>, plus all open on-chain objects (escrows, payment channels, trustlines, NFTs, AMM positions). The overall risk score is <strong style="color:${te}">${s}/100 \u2014 ${z}</strong>. <em style="opacity:.7">Risk scores reflect statistical patterns \u2014 not legal proof. A high score means unusual patterns were detected. Always verify before drawing conclusions.</em>`),Se.length&&A.push(`\u26A0\uFE0F The scan found <strong>${Se.length} critical issue${Se.length>1?"s":""}</strong> and <strong>${X.length} warning${X.length!==1?"s":""}</strong> \u2014 explained in plain English below.`);{let Le=o.riskLevel==="critical"||o.riskLevel==="high",gt=((rt=p.newWalletDests)==null?void 0:rt.length)>0,pa=((Vn=p.blackHoleDests)==null?void 0:Vn.length)>0,ua=r.score>=60,ho=(k==null?void 0:k.verdict)==="elevated",go=[l.verdict==="high-deviation",(g==null?void 0:g.verdict)==="anomalous",(b==null?void 0:b.verdict)==="anomalous"||(b==null?void 0:b.verdict)==="elevated",(h==null?void 0:h.verdict)==="bot-pattern",(v==null?void 0:v.verdict)==="strong-coupling"].filter(Boolean).length>=2,Sn=null;if(Le&&gt)Sn="The key change and the transfers to freshly-created wallets aren't separate concerns \u2014 together they're the specific sequence a drain follows: take control of signing, then move funds somewhere that isn't the attacker's known address.";else if(Le&&pa)Sn="A compromised-looking key change followed by funds reaching an address nobody controls is consistent with a drain where the funds are gone rather than just moved.";else if(ua&&ho)Sn="The order-cancellation pattern and the fee spikes reinforce each other: overpaying fees to guarantee same-ledger execution is how the cancel-before-fill pattern gets coordinated with a counterparty.";else if(ua&&go)Sn="This isn't just one statistical test disagreeing with the others \u2014 the wash-trading signal from actual order behavior and the independent mathematical tests are pointing at the same conclusion from two different directions.";else if(Se.length+X.length>=3){let vo=[...new Set(Se.concat(X).map(bm=>bm.module))];Sn=`${vo.length} different analysis categories flagged this account (${vo.slice(0,4).join(", ")}${vo.length>4?", \u2026":""}) \u2014 any one alone could be circumstantial, but that many independent methods agreeing is the stronger signal here.`}Sn&&A.push(`<strong>\u{1F9E9} How these findings fit together:</strong> ${Sn}`)}if(o.riskLevel==="critical"?A.push(`<span style="color:#ff5555"><strong>\u{1F6A8} WALLET DRAIN RISK \u2014 CRITICAL</strong></span><br><strong>What was found:</strong> The account's security structure matches a known attack pattern \u2014 the master signing key has been disabled and replaced with a different key.<br><strong>What it means in plain English:</strong> If you did not personally do this, your wallet may have been taken over. An attacker who controls the replacement key can drain every XRP and token from the account.<br><strong>What to do right now:</strong> Stop sending any funds to this address. If it's your wallet, contact a security professional immediately.`):o.riskLevel==="high"&&A.push("<strong>\u26A0\uFE0F Elevated Drain Risk:</strong> Unusual security patterns found \u2014 possibly a key change followed by large outflows. See the Drain Risk section for exact transactions."),(ht=p.newWalletDests)!=null&&ht.length&&A.push(`<strong>\u{1F195} Brand-New Receiving Wallets:</strong> ${p.newWalletDests.length} of the top destinations are freshly-created wallets (fewer than 10 lifetime transactions) that received significant XRP. Creating a new disposable wallet to receive drained funds \u2014 then disappearing \u2014 is the most common drain attack pattern on XRPL.`),($n=p.blackHoleDests)!=null&&$n.length&&A.push('<span style="color:#ff5555"><strong>\u{1F573} Funds Sent to Uncontrolled Address:</strong></span> Some XRP reached a "black hole" \u2014 an address nobody controls. <strong>These funds cannot be recovered by anyone.</strong>'),(Sr=p.exchangeDests)!=null&&Sr.length){let Le=[...new Set(p.exchangeDests.map(gt=>gt.entity.name))].join(", ");A.push(`<strong>\u{1F4B1} Exchange Activity:</strong> Funds reached known exchange(s): <strong>${Le}</strong>. Total outflow tracked: ${_(p.totalOut,2)} XRP to ${p.uniqueDests} destination(s). This is often normal \u2014 people cash out to exchanges. It becomes a concern when combined with the security or timing signals above.`)}else p.totalOut>0&&A.push(`<strong>Outbound payments:</strong> ${_(p.totalOut,2)} XRP sent to ${p.uniqueDests} destination(s). None matched known exchange addresses.`);if(r.score>=60){let Le=r.stats,gt=Le.creates>0?(Le.cancels/Le.creates*100).toFixed(0):0;A.push(`<strong>\u{1F4CA} Wash Trading Signals (Score: ${r.score}/100 \u2014 ${r.verdict.replace("-"," ").toUpperCase()}):</strong><br><strong>What was found:</strong> Out of ${Le.creates} DEX offers placed, ${Le.cancels} (${gt}%) were cancelled before filling. Only ${Le.fills} actually filled.`+(Le.selfTrades>0?` ${Le.selfTrades} payment(s) were sent from and back to the same address.`:"")+"<br><strong>What it means:</strong> Placing orders and cancelling them before they fill inflates a token's visible trading activity without any real buying or selling. It makes a thin market look active to attract other traders.<br><strong>Caveat:</strong> Legitimate market makers do cancel many orders as prices move. This finding is strongest when combined with the self-trade and fee-spike signals.")}else r.score>=30?A.push(`<strong>Moderate trading signals</strong> (score ${r.score}/100): Some DEX patterns look unusual but not conclusive alone. See Wash Trading section for specifics.`):A.push(`<strong>\u2705 DEX activity looks normal</strong> (wash score ${r.score}/100). Cancel ratios, fill rates, and trade sizes are within organic ranges.`);(T==null?void 0:T.selfRoutedCount)>0&&A.push(`<strong>\u{1F504} Self-Routing Path Payments:</strong> ${T.selfRoutedCount} payment(s) where the sender and destination are the same address. Routing XRP through the DEX back to yourself creates trading volume on every intermediate pair with no net economic transfer \u2014 a DEX-specific wash trading technique that's harder to detect than simple self-trades.`),(T==null?void 0:T.roundTripCount)>=3&&A.push(`<strong>XRP\u2192IOU\u2192XRP round-trips:</strong> ${T.roundTripCount} path payments paid and received XRP through intermediate token pairs \u2014 generating DEX volume without changing economic position.`),(k==null?void 0:k.verdict)==="elevated"&&A.push(`<strong>\u{1F4B8} Fee Spike Pattern:</strong> ${k.spikeCount} transaction(s) paid more than 100\xD7 the normal fee. Bots often overpay fees to guarantee same-ledger execution alongside a counterparty \u2014 a coordination technique used in wash trading and front-running. Organic users almost never need fees this high.`);let Pe=[l.verdict==="high-deviation",(g==null?void 0:g.verdict)==="anomalous",(b==null?void 0:b.verdict)==="anomalous"||(b==null?void 0:b.verdict)==="elevated",(h==null?void 0:h.verdict)==="bot-pattern",(v==null?void 0:v.verdict)==="strong-coupling"].filter(Boolean).length;if(Pe>=3?A.push(`<strong>\u{1F52C} Statistical Analysis \u2014 Multiple Engines Agree:</strong><br>${Pe} out of 5 independent mathematical tests found patterns inconsistent with human organic activity. These tests each use different mathematical approaches (number patterns, information theory, power laws, timing, causality) so they can't all be false alarms from the same data artifact.<br><strong>What it means:</strong> When unrelated statistical methods all flag the same account, the probability that all findings are coincidental false positives drops dramatically. This strongly suggests automated or coordinated activity, though it's not proof of fraud.`):Pe>=2?A.push(`<strong>Statistical analysis:</strong> ${Pe}/5 tests flagged unusual patterns. Multiple independent tests agreeing is a meaningful signal \u2014 see the Forensic Suite section.`):Pe===1?A.push("<strong>Statistical analysis:</strong> 1/5 tests flagged an unusual pattern. A single flag is a hypothesis to investigate further, not a conclusion."):f.length>=30&&A.push(`<strong>\u2705 All statistical tests normal:</strong> Benford's Law, entropy, Zipf's Law, time series, and offer/flow coupling all returned results consistent with organic activity across ${f.length} transactions.`),l.verdict==="high-deviation"&&l.chiSq!=null&&A.push(`<strong>Benford's Law detail (\u03C7\xB2=${l.chiSq.toFixed(1)}):</strong> In real financial data, "1" appears as the first digit ~30% of the time and "9" only ~4.6%. Computer-generated amounts break this pattern. This wallet's amounts deviate significantly (\u03C7\xB2=${l.chiSq.toFixed(1)} exceeds the 99% confidence threshold of 20.09).`),m.totalIssued>0){let Le=(Tr=m.topHolders)==null?void 0:Tr[0],gt=Le?(Le.balance/m.totalIssued*100).toFixed(0):null,pa=(Cr=S==null?void 0:S.result)!=null&&Cr.obligations?Object.values(S.result.obligations).reduce((ho,go)=>ho+Number(go),0):null,ua=pa?` (verified via gateway_balances: ${_(pa,0)} total obligations)`:"";A.push(`<strong>\u{1FA99} Token Issuance:</strong> This account has issued tokens \u2014 <strong>${_(m.totalIssued,0)} outstanding</strong> across ${m.holderCount} holder(s)${ua}. `+(gt?`The largest single holder controls <strong>${gt}% of supply</strong>. `:"")+(gt&&Number(gt)>50?"Holding more than half the supply means one wallet could dump and collapse the token price. ":"")+((Pr=m.mirrorGroups)!=null&&Pr.length?`<strong>${m.mirrorGroups.length} cluster(s)</strong> of wallets each received identical token amounts \u2014 possible coordinated/insider wallets. `:"")+((Lr=m.createdAccts)!=null&&Lr.length?`This issuer also created ${m.createdAccts.length} wallet(s) \u2014 they may be controlled by the same entity. `:""))}let sn=(i.flags||[]).filter(Le=>Le.sev==="critical");if(sn.length&&A.push(`<strong>\u{1F3A8} NFT Risk:</strong> ${sn.length} critical NFT issue(s) \u2014 most commonly a zero-price sell offer. The most common XRPL NFT scam: a malicious dApp tricks the wallet owner into signing a transaction that creates a sell offer for 0 XRP, making the NFT free for anyone to take.`),M!=null&&M.structuredFlag)A.push(`<strong>\u{1F4E5} Structured Inbound Pattern:</strong> ${M.uniqueSources} source(s) funded this wallet \u2014 many payments arrive at near-identical amounts. Structured deposits deliberately break large transfers into smaller equal amounts to reduce traceability.`);else if((Mr=M==null?void 0:M.exchangeSrcs)!=null&&Mr.length){let Le=[...new Set(M.exchangeSrcs.map(gt=>gt.entity.name))].join(", ");A.push(`<strong>\u{1F4E5} Funding Sources:</strong> Wallet received funds from ${M.uniqueSources} source(s) \u2014 ${Le} among them. Total inbound: ${_(M.totalIn,2)} XRP.`)}return(Ar=C==null?void 0:C.scamMemos)!=null&&Ar.length&&A.push(`<strong>\u{1F4DD} Scam Memo Content Detected:</strong> ${C.scamMemos.length} transaction memo(s) contain text matching known scam patterns (airdrop claims, wallet verification requests, urgency language). These payments were likely sent by attackers attempting social engineering.`),(Er=O==null?void 0:O.signals)!=null&&Er.some(Le=>Le.sev==="critical")&&A.push("<strong>\u{1F4D6} Active Spoofing Detected Right Now:</strong> This wallet currently has an order that controls over 40% of the visible order book depth. Large orders placed without intent to fill \u2014 then quickly cancelled when approached \u2014 is spoofing. This is happening in the live order book at time of inspection."),($==null?void 0:$.riskPenalty)>0&&A.push("<strong>\u{1F3F7} Destination Tag Pattern:</strong> Payments to exchanges used an unusually wide variety of destination tags \u2014 each tag identifies a different customer account. This can indicate a service routing payments to many accounts, or deliberate spread of deposits across exchange accounts to reduce traceability."),Se.length===0&&X.length===0&&A.push(`<span style="color:#50fa7b"><strong>\u2705 No Elevated Signals Found</strong></span><br>All checks returned results within normal ranges across ${pe}. This does not guarantee the account is trustworthy \u2014 it means no identifiable red flags were found in the data analyzed.`),f.length<100&&A.push(`<em style="opacity:.6;font-size:.86em">Data coverage: ${pe}. Fewer than 100 transactions means some statistical tests above may not reach reliable conclusions \u2014 treat those specifically as weaker signal.</em>`),A}let me={Security:{icon:"\u{1F510}",desc:"Keys, flags, multisig, auth changes"},"Drain Risk":{icon:"\u26A0\uFE0F",desc:"Auth changes \u2192 large outflows, external key injection"},"Fund Flow":{icon:"\u{1F30A}",desc:"Exchange flows, black holes, new-wallet recipients, path routing"},NFT:{icon:"\u{1F3A8}",desc:"Zero-value offers, no-metadata tokens, burns"},"Wash Trading":{icon:"\u{1F4CA}",desc:"Cancel ratios, self-trades, order uniformity, burst patterns"},"Benford's Law":{icon:"\u{1F4D0}",desc:"First-digit natural distribution test on all amounts"},"Volume Concentration":{icon:"\u{1FAE7}",desc:"How many wallets drive token trading volume"},"Shannon's Entropy":{icon:"\u{1F500}",desc:"Randomness of amounts, counterparties, timing, tx types"},"Zipf's Law":{icon:"\u{1F4C8}",desc:"Counterparty frequency power-law distribution"},"Time Series":{icon:"\u{1F550}",desc:"Interval regularity, periodicity \u2014 bot vs human timing"},"Offer/Flow Coupling":{icon:"\u{1F517}",desc:"Cross-correlation (not causality): create\u2194cancel, inflow\u2194outflow"},"Token Issuer":{icon:"\u{1FA99}",desc:"Supply, freeze state, concentration"},AMM:{icon:"\u{1F4A7}",desc:"LP positions, pool TVL, ownership share"},"Issuer Connections":{icon:"\u{1F578}",desc:"Distribution patterns, mirror wallets, account creation chains"},"Fee Spikes":{icon:"\u{1F4B8}",desc:"Elevated fee transactions \u2014 coordination signal"},"Destination Tags":{icon:"\u{1F3F7}",desc:"Exchange sub-account routing patterns"},"Path Payments":{icon:"\u{1F504}",desc:"Circular routing, self-routing, deep-hop obfuscation"},"Inbound Flow":{icon:"\u{1F4E5}",desc:"Funding sources, exchange deposits, structured inbound patterns"},"Memo Analysis":{icon:"\u{1F4DD}",desc:"Scam patterns, coordination text, hex-decoded memo data"},"Escrow Depth":{icon:"\u{1F512}",desc:"Third-party escrows, maturity dates, conditional locks"},"Live Order Book":{icon:"\u{1F4D6}",desc:"Current spoofing detection \u2014 wall orders, book depth concentration"}},xe=["Security","Drain Risk","Fund Flow","NFT","Wash Trading","Benford's Law","Volume Concentration","Shannon's Entropy","Zipf's Law","Time Series","Offer/Flow Coupling","Token Issuer","AMM","Issuer Connections","Fee Spikes","Destination Tags","Path Payments"],Te={};for(let A of xe)Te[A]=ce.filter(Pe=>Pe.module===A&&Pe.sev!=="ok"&&Pe.sev!=="info");let qe=xe.filter(A=>Te[A].length>0).map(A=>{let Pe=me[A]||{icon:"\u{1F4CB}",desc:""},sn=Te[A].map(rt=>{var ht;let Vn=(ht=rt.hashes)!=null&&ht.length?`
          <div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:6px">
            ${rt.hashes.slice(0,5).map($n=>`
              <a href="https://livenet.xrpl.org/transactions/${y($n)}" target="_blank" rel="noopener"
                 style="font-size:.7rem;font-family:monospace;color:var(--accent);text-decoration:none;
                        background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.2);
                        border-radius:4px;padding:2px 6px" title="${y($n)}">
                ${$n.slice(0,8)}\u2026${$n.slice(-4)} \u{1F517}
              </a>`).join("")}
          </div>`:"";return`
          <div class="report-finding-row">
            <div class="report-finding-top">
              ${q(rt.sev)}
              <span class="report-finding-headline">${y(rt.headline)}</span>
            </div>
            ${rt.detail?`<div class="report-finding-detail">${y(rt.detail)}</div>`:""}
            ${Vn}
          </div>`}).join("");return`
        <div class="report-module">
          <div class="report-module-h">
            <span style="margin-right:6px">${Pe.icon}</span>${y(A)}
            <span style="font-size:.72rem;font-weight:400;opacity:.45;margin-left:8px">${y(Pe.desc)}</span>
          </div>
          ${sn}
        </div>`}).join(""),Fe=[{k:"Address",v:e,mono:!0},{k:"Balance",v:_(n,4)+" XRP"+yn(n),mono:!0},{k:"Wallet Age",v:I!=null?(I<1?"Created today":I+" days")+(D?" \u2014 created "+new Date(D).toLocaleDateString("en-US",{year:"numeric",month:"short",day:"numeric"}):""):"\u2014"},{k:"Risk Score",v:s+"/100 \u2014 "+z,color:te},{k:"Transactions Analyzed",v:f.length+(ie?" \xB7 "+ie:"")},{k:"Activity Span",v:ne>0?ne+" days":"unknown"},{k:"Outbound Destinations",v:p.uniqueDests+" addresses received funds"},{k:"Total XRP Sent Out",v:_(p.totalOut,2)+" XRP",mono:!0},{k:"New-Wallet Recipients",v:(((ze=p.newWalletDests)==null?void 0:ze.length)||0)+((ft=p.newWalletDests)!=null&&ft.length?" \u26A0":" \u2014 none"),color:(nn=p.newWalletDests)!=null&&nn.length?"#ff5555":null},{k:"Wash Trading Score",v:(r.score||0)+"/100 \u2014 "+(r.verdict||"\u2014").replace("-"," ")+(r.score<25?" \u2713":r.score<50?" \u26A0 moderate":" \u{1F6A8} elevated")},{k:"Fee Spike Count (>100\xD7 base)",v:((k==null?void 0:k.spikeCount)??"N/A")+((k==null?void 0:k.spikeCount)>5?" \u26A0":""),mono:!0},{k:"Benford \u03C7\xB2 (normal \u2264 15.5)",v:l.chiSq!=null?l.chiSq.toFixed(2)+" \u2014 "+l.verdict.replace("-"," "):"insufficient data",mono:!0},{k:"Amount Entropy (natural 2.4\u20134.2)",v:(g==null?void 0:g.amountEntropy)!=null?g.amountEntropy.toFixed(2)+" bits":"N/A",mono:!0},{k:"Zipf Exponent (natural 0.8\u20131.3)",v:(b==null?void 0:b.zipfExponent)!=null?b.zipfExponent.toFixed(3)+"  R\xB2="+((da=b.rSquared)==null?void 0:da.toFixed(2)):"N/A",mono:!0},{k:"Timing Regularity CV (bot < 0.25)",v:(h==null?void 0:h.intervalCV)!=null?h.intervalCV.toFixed(3)+(h.intervalCV<.25?" \u26A0 bot-level":" \u2713"):"N/A",mono:!0},{k:"Offer Create\u2194Cancel Correlation",v:((br=v==null?void 0:v.offerCancelCausality)==null?void 0:br.maxCorr)!=null?v.offerCancelCausality.maxCorr.toFixed(3)+(v.offerCancelCausality.maxCorr>.55?" \u26A0":" \u2713"):"N/A",mono:!0},{k:"XRP\u2192IOU\u2192XRP Round-Trips",v:((T==null?void 0:T.roundTripCount)??0)+((T==null?void 0:T.roundTripCount)>=3?" \u26A0":""),mono:!0},{k:"Token Holders",v:m.holderCount>0?m.holderCount+" wallets hold tokens from this issuer":"Not a token issuer"},{k:"Critical Findings",v:Se.length+(Se.length===0?" \u2014 none":""),color:Se.length>0?"#ff5555":"#50fa7b"},{k:"Warnings",v:X.length+(X.length===0?" \u2014 none":""),color:X.length>0?"#ffb86c":"#50fa7b"}].map(A=>`
    <div class="report-stat-row">
      <span class="report-stat-k">${y(A.k)}</span>
      <span class="report-stat-v ${A.mono?"mono":""}" style="${A.color?"color:"+A.color:""}">${y(String(A.v))}</span>
    </div>`).join(""),Re={critical:"rgba(255,85,85,.08)",warn:"rgba(255,184,108,.06)",info:"rgba(120,180,255,.05)",ok:"rgba(80,250,123,.05)"},Y={critical:"rgba(255,85,85,.25)",warn:"rgba(255,184,108,.20)",info:"rgba(120,180,255,.15)",ok:"rgba(80,250,123,.15)"},he=[];(o.riskLevel==="critical"||o.riskLevel==="high")&&he.push({icon:"\u{1F534}",sev:"critical",text:"If this is your wallet: stop sending funds here immediately. The account's security keys match a known drain attack pattern. Contact a security professional or the XRPL community before taking any action."}),(yr=p.newWalletDests)!=null&&yr.length&&he.push({icon:"\u26A0\uFE0F",sev:"critical",text:`${p.newWalletDests.length} brand-new wallet(s) received large XRP transfers. This is a classic drain pattern. If this was unexpected, the funds have likely already been moved further down the chain.`}),(wr=p.blackHoleDests)!=null&&wr.length&&he.push({icon:"\u26D4",sev:"critical",text:"Funds sent to black hole addresses are gone permanently. No exchange, no support team, and no legal action can retrieve them."}),(xr=p.exchangeDests)!=null&&xr.length&&he.push({icon:"\u{1F4B1}",sev:"warn",text:`If this was a drain: contact ${[...new Set(p.exchangeDests.map(A=>A.entity.name))].join(", ")} exchange support immediately with the transaction hashes from the Fund Flow section. Act within hours \u2014 exchanges can sometimes freeze funds quickly but not after they've been withdrawn.`}),r.score>=60&&he.push({icon:"\u{1F4CA}",sev:"warn",text:"Significant wash trading signals detected. If you're a market maker: high cancel ratios are normal for your role \u2014 review the self-trade and self-routing signals specifically. If you're a token holder or researcher: this pattern suggests the token's apparent volume may be artificial."}),(T==null?void 0:T.selfRoutedCount)>0&&he.push({icon:"\u{1F504}",sev:"warn",text:`${T.selfRoutedCount} path payment(s) routed XRP from and back to the same address through the DEX. This creates artificial trading volume on every intermediate pair. Check the Path Payments section for specific transaction hashes.`}),(kr=m.mirrorGroups)!=null&&kr.length&&he.push({icon:"\u{1F578}",sev:"warn",text:"Mirror wallet clusters found. If you are the issuer, determine whether these are genuine holders or insider accounts used to create the appearance of broader distribution. These wallets could coordinate a sell-off."}),($r=i.flags)!=null&&$r.some(A=>A.sev==="critical")&&he.push({icon:"\u{1F3A8}",sev:"critical",text:"Zero-value NFT offer detected. If you didn't intentionally list your NFT for free: identify what website or app you used around the time this transaction was signed, and revoke any approvals it has."}),(k==null?void 0:k.verdict)==="elevated"&&he.push({icon:"\u{1F4B8}",sev:"info",text:`${k.spikeCount} transactions paid >100\xD7 normal fees. Check the Fee Spikes section to see if these align with moments of concentrated trading \u2014 elevated fees often mark coordinated activity windows.`}),he.length===0&&he.push({icon:"\u2705",sev:"ok",text:"No immediate actions required. The account shows no identifiable red flags. Continue monitoring as activity grows \u2014 some patterns only become statistically significant with more data."});let tt=he.map(A=>`
    <div style="background:${Re[A.sev]||Re.info};border:1px solid ${Y[A.sev]||Y.info};border-radius:10px;padding:12px 14px;margin-bottom:8px;display:flex;gap:12px;align-items:flex-start">
      <span style="font-size:1.15rem;flex-shrink:0;margin-top:1px">${A.icon}</span>
      <span style="font-size:.85rem;line-height:1.65;color:rgba(255,255,255,.78)">${A.text}</span>
    </div>`).join(""),Ct=`
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:8px;margin-top:10px">
      ${[["Benford's Law","In organic financial data, amounts starting with '1' appear ~30% of the time. Computer-generated amounts often break this law."],["Shannon's Entropy","Measures how 'predictable' transaction amounts and partners are. Bots repeat the same amounts; humans don't."],["Zipf's Law","Natural networks have a few heavy relationships and many light ones. Wash rings show unnaturally equal relationships."],["Time Series CV","Coefficient of Variation of gaps between transactions. Humans: >0.8 (irregular). Bots: <0.3 (clock-like)."],["Offer/Flow Coupling","Cross-correlation between two event series at a time lag \u2014 e.g., offer creation and cancellation moving together. A correlation, not a causality test; it can't show which one actually drives the other."],["Interval CV","The regularity of timing between transactions. Very low = mechanical/automated. Very high = erratic/bursty."],["Gateway Balances","The XRPL API command that returns the true outstanding obligations of a token issuer \u2014 more accurate than just reading trustlines."],["Destination Tag","A number attached to a payment that identifies the recipient sub-account at an exchange. Like a bank account reference number."],["Path Payment","An XRPL payment that routes through intermediate DEX pairs. Can create trading volume on pairs the sender never intended to trade."],["XRP Round-Trip","A path payment that starts and ends in XRP, routed through IOU pairs. Creates DEX volume with no net economic transfer."],["Fee Multiplier","XRPL's base transaction fee is 12 drops (~$0.000001). Paying 100\xD7 means paying 1,200 drops \u2014 bots do this for guaranteed same-ledger execution."]].map(([A,Pe])=>`
        <div style="background:rgba(255,255,255,.03);border-radius:8px;padding:10px 12px;border:1px solid rgba(255,255,255,.05)">
          <div style="font-size:.78rem;font-weight:700;color:rgba(255,255,255,.75);margin-bottom:4px">${y(A)}</div>
          <div style="font-size:.74rem;color:rgba(255,255,255,.42);line-height:1.5">${y(Pe)}</div>
        </div>`).join("")}
    </div>`,Dt=se();return`
    <div class="report-wrap">

      <!-- \u2500\u2500 Cover \u2500\u2500 -->
      <div class="report-cover">
        <div class="report-cover-left">
          <div class="report-logo">\u26A1 NaluXRP</div>
          <h2 class="report-title">Account Investigation Report</h2>
          <div class="report-addr mono">${y(e)}</div>
          <div class="report-ts">Generated ${H}</div>
          <div style="font-size:.75rem;color:rgba(255,255,255,.38);margin-top:4px">Coverage: ${y(pe)}</div>
        </div>
        <div class="report-score-circle" style="--score-color:${te}">
          <div class="report-score-num" style="color:${te}">${s}</div>
          <div class="report-score-den">/100</div>
          <div class="report-score-word" style="color:${te}">${z}</div>
        </div>
      </div>

      <!-- \u2500\u2500 Executive Summary \u2500\u2500 -->
      <div class="report-section">
        <h3 class="report-section-h">\u{1F4CB} Executive Summary</h3>
        <div class="report-narrative">
          ${Dt.map(A=>`<p style="margin-bottom:12px;line-height:1.7">${A}</p>`).join("")}
        </div>
      </div>

      <!-- \u2500\u2500 Copy Analysis for AI \u2500\u2500
           Deliberately its own section, clearly separate from the
           deterministic Executive Summary above. Rather than the app making
           its own API call (which needs a key, a proxy, or a multi-GB local
           model download), this formats every finding into one clean block
           the user copies and pastes into whatever AI model they already
           use \u2014 same idea as Project Intelligence's "Copy for AI" button. -->
      <div class="report-section">
        <h3 class="report-section-h">\u{1F4CB} Copy Analysis for AI</h3>
        <div id="ai-explanation-body">
          <p style="font-size:.82rem;color:rgba(255,255,255,.45);margin-bottom:12px;line-height:1.6">
            Copy every finding from this inspection as plain text, ready to paste into ChatGPT, Claude, or any model
            you already use, for a plain-language read of what this account's activity suggests.
          </p>
          <button class="settings-btn settings-btn--primary" onclick="copyInspectorAnalysisForAi()">\u{1F4CB} Copy for AI</button>
        </div>
      </div>

      <!-- \u2500\u2500 Account Activity & Interactions \u2500\u2500
           Activity timeline reuses the same chart built for the Account
           Overview section up top (renderActivityTimeline targets this
           element id as a second mount point). The counterparty breakdown
           deliberately does NOT reuse the radial network map here \u2014 that
           map is good for clicking around and exploring, which fits Account
           Overview, but a report is read top-to-bottom, so who-transacts-
           with-whom is shown as a ranked, volume-sorted list instead: easier
           to scan, and prints/exports cleanly. Same underlying data either way. -->
      <div class="report-section">
        <h3 class="report-section-h">\u{1F5FA}\uFE0F Account Activity &amp; Interactions</h3>
        <p style="font-size:.8rem;color:rgba(255,255,255,.4);margin-bottom:10px;line-height:1.6">
          Transaction volume over time, who this account actually transacts with \u2014 ranked by volume,
          colored by category (exchange, black hole, issuer, other) \u2014 and how much moved in versus out
          relative to the current balance.
        </p>
        <div id="inspect-report-activity-chart" style="margin-bottom:14px"></div>
        <div style="margin-bottom:16px">${t0(f,e)}</div>
        ${Lu(n,p,M)}
      </div>

      <!-- \u2500\u2500 Stats Snapshot \u2500\u2500 -->
      <div class="report-section">
        <h3 class="report-section-h">\u{1F4D0} Account Snapshot
          <button onclick="exportTxCSV(window._lastTxList)" title="Export all transactions to CSV"
            style="margin-left:12px;background:rgba(0,212,255,.10);border:1px solid rgba(0,212,255,.25);
                   color:var(--accent);border-radius:6px;padding:3px 10px;font-size:.7rem;cursor:pointer">
            \u2B07 Export CSV
          </button>
        </h3>
        <div class="report-stats-grid">${Fe}</div>
      </div>

      <!-- \u2500\u2500 Findings by Module \u2500\u2500 -->
      ${qe?`
      <div class="report-section">
        <h3 class="report-section-h">\u{1F52C} Findings by Module
          <span class="report-counts">
            <span class="report-count report-count--crit">${Se.length} Critical</span>
            <span class="report-count report-count--warn">${X.length} Warnings</span>
          </span>
        </h3>
        <p style="font-size:.8rem;color:rgba(255,255,255,.4);margin-bottom:14px;line-height:1.6">
          Each module below used a different method to analyse the account.
          Findings include clickable transaction hash links so you can verify everything on-chain.
        </p>
        <div class="report-findings">${qe}</div>
      </div>`:`
      <div class="report-section">
        <h3 class="report-section-h">\u{1F52C} Findings</h3>
        <div class="report-clean-note">\u2705 No elevated findings across all ${xe.length} analysis modules.</div>
      </div>`}

      <!-- \u2500\u2500 Recommendations \u2500\u2500 -->
      <div class="report-section">
        <h3 class="report-section-h">\u{1F4A1} Recommended Actions</h3>
        ${tt}
      </div>

      <!-- \u2500\u2500 Glossary \u2500\u2500 -->
      <div class="report-section">
        <h3 class="report-section-h">\u{1F4D6} Understanding This Report</h3>
        <p style="font-size:.82rem;color:rgba(255,255,255,.45);line-height:1.65;margin-bottom:10px">
          Plain-English definitions for every technical term used in this report.
        </p>
        ${Ct}
      </div>

      <!-- \u2500\u2500 Disclaimer \u2500\u2500 -->
      <div class="report-disclaimer">
        <strong>Important:</strong> This report is generated automatically from public on-chain data using
        statistical pattern analysis. Signals are not proof. Legitimate market makers, bots, and active
        users can trigger individual flags. Always cross-reference with additional evidence before making
        legal, financial, or reputational decisions. NaluXRP Inspector is a transparency and research tool \u2014
        not a legal or forensic authority.
      </div>

    </div>
  `}function Ly(e,...t){e.innerHTML=Py(...t)}function My(){let e=document.getElementById("tab-inspector");e&&(e.querySelector("[data-inspector-v2]")||(e.innerHTML=`
    <style>
      /* \u2500\u2500 Analyst mode visibility \u2500\u2500 */
      #inspect-result.mode-simple  .advanced-only { display: none !important; }
      #inspect-result.mode-advanced .advanced-only { /* inherit display */ }
      /* Advanced-only sections that default hidden */
      #inspect-result.mode-simple  #section-volconc,
      #inspect-result.mode-simple  #section-issuer,
      #inspect-result.mode-simple  #section-issuer-connections,
      #inspect-result.mode-simple  #section-amm,
      #inspect-result.mode-simple  #section-fee-analysis,
      #inspect-result.mode-simple  #section-desttag,
      #inspect-result.mode-simple  #section-pathdepth,
      #inspect-result.mode-simple  #section-memos,
      #inspect-result.mode-simple  #section-escrow-depth,
      #inspect-result.mode-simple  #section-checks,
      #inspect-result.mode-simple  #section-livebook,
      #inspect-result.mode-simple  #section-trustlines { display: none !important; }
      /* Forensic engine tabs styling */
      .forensic-engine-tabs { }
      .forensic-sub-section { border-radius: 8px; overflow: hidden; }
      .forensic-tab-btn {
        background: rgba(0,212,255,.05); border: 1px solid rgba(0,212,255,.12);
        color: rgba(255,255,255,.65); border-radius: 8px; padding: 8px 12px;
        font-size: .78rem; cursor: pointer; display: flex; align-items: center; gap: 6px;
        width: 100%; text-align: left; transition: background .15s;
      }
      .forensic-tab-btn:hover { background: rgba(0,212,255,.10); color: rgba(255,255,255,.9); }
      .forensic-tab-body { background: rgba(0,212,255,.02); border: 1px solid rgba(0,212,255,.08); border-top: none; border-radius: 0 0 8px 8px; padding: 0 12px; }
      /* New wallet badge in header */
      .acct-cell--new { border-color: rgba(255,184,108,.4) !important; }
      .acct-cell-new-badge { font-size: .65rem; color: #ffb86c; margin-top: 2px; font-weight: 700; }
    </style>
    <div class="inspector-wrap" data-inspector-v2="1">

      <div class="inspector-page-header">
        <div class="inspector-title-row">
          <h1 class="inspector-page-title">\u{1F50D} Account Inspector</h1>
          <button class="inspector-howto-btn" onclick="showInspectorHowTo()">
            <span>?</span> How to use
          </button>
        </div>
        <p class="inspector-sub">
          Deep-dive any XRPL address \u2014 security posture, drain risk, NFT exposure,
          wash-trading signals, token issuer status and AMM liquidity positions.
        </p>
      </div>

      <div class="search-row">
        <input id="inspect-addr" class="xrpl-input" type="text"
          placeholder="rXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
          autocomplete="off" spellcheck="false"
          aria-label="XRPL address to inspect" />
        <button class="xrpl-btn btn-inspect" onclick="runInspect()">Inspect \u2192</button>
      </div>

      <div id="inspect-warn"    class="alert-warn"    style="display:none" role="alert">\u26A1 Not connected \u2014 connect to an XRPL node first.</div>
      <div id="inspect-err"     class="alert-err"     style="display:none" role="alert"></div>
      <div id="inspect-loading" class="inspect-loading-state" style="display:none" role="status" aria-live="polite">
        <div class="inspect-spinner"></div>
        <span id="inspect-loading-msg">Analyzing\u2026</span>
      </div>

      <!-- \u2550\u2550 Initial State Dashboard \u2550\u2550 -->
      <div id="inspect-empty">

        <!-- \u2500\u2500 Network health strip \u2500\u2500 -->
        <div class="isd-net-strip">

          <!-- Status pill -->
          <div class="isd-conn-pill" id="isd-conn-pill">
            <span class="isd-conn-dot" id="isd-conn-dot"></span>
            <span id="isd-conn-label">Connecting\u2026</span>
          </div>

          <!-- Live metrics -->
          <div class="isd-metrics-row">

            <div class="isd-metric-card">
              <div class="isd-metric-label">Ledger</div>
              <div class="isd-metric-val mono" id="isd-ledger-idx">\u2014</div>
              <div class="isd-metric-sub" id="isd-ledger-age">\u2014</div>
            </div>

            <div class="isd-metric-card">
              <div class="isd-metric-label">TPS</div>
              <div class="isd-metric-val" id="isd-tps">\u2014</div>
              <div class="isd-metric-sub" id="isd-tps-trend">waiting\u2026</div>
            </div>

            <div class="isd-metric-card">
              <div class="isd-metric-label">Avg Fee</div>
              <div class="isd-metric-val mono" id="isd-fee">\u2014</div>
              <div class="isd-metric-sub" id="isd-fee-level">\u2014</div>
            </div>

            <div class="isd-metric-card">
              <div class="isd-metric-label">Close Time</div>
              <div class="isd-metric-val" id="isd-close-time">\u2014</div>
              <div class="isd-metric-sub">secs / ledger</div>
            </div>

            <div class="isd-metric-card">
              <div class="isd-metric-label">Reserve</div>
              <div class="isd-metric-val mono" id="isd-reserve">10 XRP</div>
              <div class="isd-metric-sub">+2 per object</div>
            </div>

            <div class="isd-metric-card">
              <div class="isd-metric-label">Dominant TX</div>
              <div class="isd-metric-val" id="isd-dom-tx">\u2014</div>
              <div class="isd-metric-sub" id="isd-dom-pct">\u2014</div>
            </div>

          </div>

          <!-- Fee pressure bar -->
          <div class="isd-fee-bar-wrap">
            <span class="isd-fee-bar-label">Fee Pressure</span>
            <div class="isd-fee-bar-track">
              <div class="isd-fee-bar-fill" id="isd-fee-bar"></div>
            </div>
            <span class="isd-fee-bar-level" id="isd-fee-bar-label">Low</span>
          </div>

        </div>

        <!-- \u2500\u2500 My Wallets \u2500\u2500 -->
        <div class="isd-section" id="isd-wallets-section" style="display:none">
          <div class="isd-section-hdr">
            <div class="isd-section-left">
              <span class="isd-section-icon">\u{1F4BC}</span>
              <h2 class="isd-section-title">My Wallets</h2>
            </div>
            <span class="isd-section-hint">tap to inspect</span>
          </div>
          <div class="isd-wallet-grid" id="isd-wallet-list"></div>
        </div>

        <!-- \u2500\u2500 Recent Inspections \u2500\u2500 -->
        <div class="isd-section" id="isd-recent-section" style="display:none">
          <div class="isd-section-hdr">
            <div class="isd-section-left">
              <span class="isd-section-icon">\u{1F550}</span>
              <h2 class="isd-section-title">Recent Inspections</h2>
            </div>
            <button class="isd-text-btn" onclick="inspectorClearHistory()">Clear all</button>
          </div>
          <div class="isd-recent-list" id="isd-recent-list"></div>
        </div>

        <!-- \u2500\u2500 Watchlist \u2500\u2500 -->
        <div class="isd-section" id="isd-watchlist-section" style="display:none">
          <div class="isd-section-hdr">
            <div class="isd-section-left">
              <span class="isd-section-icon">\u2605</span>
              <h2 class="isd-section-title">Watchlist</h2>
            </div>
            <button class="isd-text-btn" onclick="inspectorClearWatchlist()">Clear</button>
          </div>
          <div class="isd-recent-list" id="isd-watchlist-list"></div>
        </div>

        <!-- \u2500\u2500 Notable Addresses \u2500\u2500 -->
        <div class="isd-section">
          <div class="isd-section-hdr">
            <div class="isd-section-left">
              <span class="isd-section-icon">\u{1F310}</span>
              <h2 class="isd-section-title">Notable XRPL Addresses</h2>
            </div>
            <span class="isd-section-hint">tap to explore</span>
          </div>
          <div class="isd-notable-grid" id="isd-notable-grid"></div>
        </div>

        <!-- \u2500\u2500 What We Detect \u2500\u2500 -->
        <div class="isd-section">
          <div class="isd-section-hdr">
            <div class="isd-section-left">
              <span class="isd-section-icon">\u{1F6E1}</span>
              <h2 class="isd-section-title">What The Inspector Detects</h2>
            </div>
          </div>
          <div class="isd-cap-grid" id="isd-cap-grid"></div>
        </div>

      </div>

      <div id="inspect-result" style="display:none">

        <div class="inspect-risk-banner">
          <div class="irb-left">
            <button class="irb-back-btn" onclick="inspectorGoBack()" title="Back to search">\u2190 Back</button>
            <div class="irb-addr-group">
              <span class="irb-addr mono" id="inspect-addr-badge">\u2014</span>
              <button class="irb-copy-btn" onclick="inspectorCopyAddr()" title="Copy address" aria-label="Copy address">\u{1F4CB}</button>
              <button id="watchlist-btn" class="irb-copy-btn" title="Add to watchlist">\u2606 Watch</button>
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:8px">
            <button id="analyst-mode-btn" onclick="toggleAnalystMode()" aria-pressed="false"
              style="background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);color:rgba(255,255,255,.6);
                     border-radius:6px;padding:4px 10px;font-size:.72rem;cursor:pointer">\u{1F441} Simple</button>
            <div class="irb-score-group">
              <div class="irb-score-val" id="inspect-risk-score">\u2014</div>
              <div class="irb-score-label" id="inspect-risk-label">Risk Score</div>
            </div>
          </div>
        </div>

        <!-- Change detection banner (hidden until 2nd+ inspection of same addr) -->
        <div id="change-banner"></div>

        <!-- Quick Verdict (3-line summary, always first thing you see) -->
        <div id="quick-verdict" style="background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);border-radius:12px;padding:14px 16px;margin-bottom:10px">
          <div id="quick-verdict-body" style="opacity:.5;font-size:.82rem" role="status" aria-live="polite">Analysing\u2026</div>
        </div>

        <section class="widget-card inspector-section" id="section-overview">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1F4CA} Account Overview</h2>
            <button onclick="exportInspectorJSON()" title="Export full analysis as JSON"
              style="margin-left:auto;background:rgba(0,212,255,.07);border:1px solid rgba(0,212,255,.18);
                     color:var(--accent);border-radius:6px;padding:3px 9px;font-size:.68rem;cursor:pointer">\u2B07 JSON</button>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body account-grid" id="inspect-acct-grid"></div>
          <div id="inspect-risk-breakdown" style="padding:0 12px 8px"></div>
          <div id="inspect-activity-chart" style="padding:0 12px 12px"></div>
          <div id="inspect-network-map" style="padding:0 12px 12px"></div>
        </section>

        <section class="widget-card inspector-section" id="section-security">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1F510} Security Audit</h2>
            <span class="section-badge" id="badge-security"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-security-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-drain">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u26A0 Drain Risk</h2>
            <span class="section-badge" id="badge-drain"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-drain-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-fundflow">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1F30A} Fund Flow Tracer</h2>
            <span class="section-badge" id="badge-fundflow"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-fundflow-body">
            <p class="widget-help" style="opacity:.6;font-size:.84rem">
              Traces every outbound payment \u2014 shows where funds went, which exchanges they reached,
              multi-hop path payment routes, and a chronological drain timeline.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-inbound">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1F4E5} Inbound Flow Analysis</h2>
            <span class="section-badge" id="badge-inbound"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-inbound-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              Who funded this wallet \u2014 top sources, exchange withdrawals, structured deposit patterns,
              and single-source concentration. Pairs with Fund Flow for a complete in/out picture.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-nft">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1F3A8} NFT Analysis</h2>
            <span class="section-badge" id="badge-nft"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-nft-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-wash">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1F4CA} Wash Trading</h2>
            <span class="section-badge" id="badge-wash"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-wash-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-forensic-suite" style="border-color:rgba(0,212,255,.2)">
          <header class="widget-header section-header" style="background:rgba(0,212,255,.03)" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1F9EC} Forensic Analytics Suite</h2>
            <span class="section-badge" id="badge-forensic-suite" style="background:rgba(0,212,255,.12);color:var(--accent);border-color:rgba(0,212,255,.3)">5 Engines</span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-forensic-suite-body"></div>

          <!-- Engine detail panels \u2014 always visible, collapsed by default, expandable -->
          <div class="forensic-engine-tabs" style="border-top:1px solid rgba(0,212,255,.1);margin-top:4px;padding:8px 12px 4px">
            <div style="font-size:.65rem;color:rgba(0,212,255,.5);text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px">
              Individual Engine Details \u2014 click any to expand
            </div>

            <div id="section-benfords" class="forensic-sub-section">
              <button id="ftab-btn-benfords" class="forensic-tab-btn" onclick="_toggleForensicTab('benfords')" aria-expanded="false" aria-controls="forensic-tab-benfords" style="width:100%;justify-content:space-between">
                <span>\u{1F4D0} Benford's Law</span>
                <span style="display:flex;align-items:center;gap:8px"><span class="section-badge" id="badge-benfords"></span><span id="ftab-chevron-benfords" style="opacity:.5">\u25BE</span></span>
              </button>
              <div id="forensic-tab-benfords" class="forensic-tab-body" style="display:none"><div id="inspect-benfords-body" style="padding:8px 0"></div></div>
            </div>

            <div id="section-entropy" class="forensic-sub-section" style="margin-top:4px">
              <button id="ftab-btn-entropy" class="forensic-tab-btn" onclick="_toggleForensicTab('entropy')" aria-expanded="false" aria-controls="forensic-tab-entropy" style="width:100%;justify-content:space-between">
                <span>\u{1F500} Shannon's Entropy</span>
                <span style="display:flex;align-items:center;gap:8px"><span class="section-badge" id="badge-entropy"></span><span id="ftab-chevron-entropy" style="opacity:.5">\u25BE</span></span>
              </button>
              <div id="forensic-tab-entropy" class="forensic-tab-body" style="display:none"><div id="inspect-entropy-body" style="padding:8px 0"></div></div>
            </div>

            <div id="section-zipf" class="forensic-sub-section" style="margin-top:4px">
              <button id="ftab-btn-zipf" class="forensic-tab-btn" onclick="_toggleForensicTab('zipf')" aria-expanded="false" aria-controls="forensic-tab-zipf" style="width:100%;justify-content:space-between">
                <span>\u{1F4C8} Zipf's Law</span>
                <span style="display:flex;align-items:center;gap:8px"><span class="section-badge" id="badge-zipf"></span><span id="ftab-chevron-zipf" style="opacity:.5">\u25BE</span></span>
              </button>
              <div id="forensic-tab-zipf" class="forensic-tab-body" style="display:none"><div id="inspect-zipf-body" style="padding:8px 0"></div></div>
            </div>

            <div id="section-timeseries" class="forensic-sub-section" style="margin-top:4px">
              <button id="ftab-btn-timeseries" class="forensic-tab-btn" onclick="_toggleForensicTab('timeseries')" aria-expanded="false" aria-controls="forensic-tab-timeseries" style="width:100%;justify-content:space-between">
                <span>\u{1F550} Time Series Analysis</span>
                <span style="display:flex;align-items:center;gap:8px"><span class="section-badge" id="badge-timeseries"></span><span id="ftab-chevron-timeseries" style="opacity:.5">\u25BE</span></span>
              </button>
              <div id="forensic-tab-timeseries" class="forensic-tab-body" style="display:none"><div id="inspect-timeseries-body" style="padding:8px 0"></div></div>
            </div>

            <div id="section-granger" class="forensic-sub-section" style="margin-top:4px">
              <button id="ftab-btn-granger" class="forensic-tab-btn" onclick="_toggleForensicTab('granger')" aria-expanded="false" aria-controls="forensic-tab-granger" style="width:100%;justify-content:space-between">
                <span>\u{1F517} Offer/Flow Coupling</span>
                <span style="display:flex;align-items:center;gap:8px"><span class="section-badge" id="badge-granger"></span><span id="ftab-chevron-granger" style="opacity:.5">\u25BE</span></span>
              </button>
              <div id="forensic-tab-granger" class="forensic-tab-body" style="display:none"><div id="inspect-granger-body" style="padding:8px 0"></div></div>
            </div>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-volconc">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1FAE7} Volume Concentration</h2>
            <span class="section-badge" id="badge-volconc"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-volconc-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-issuer">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1FA99} Token Issuer</h2>
            <span class="section-badge" id="badge-issuer"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-issuer-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-issuer-connections">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1F578} Issuer Connection Graph</h2>
            <span class="section-badge" id="badge-issuer-connections"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-issuer-connections-body">
            <p class="widget-help" style="opacity:.6;font-size:.84rem">
              Token supply distribution, holder concentration, accounts created by this issuer,
              and mirror-wallet clusters (accounts receiving identical amounts \u2014 possible sybil rings).
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-amm">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1F4A7} AMM / Liquidity</h2>
            <span class="section-badge" id="badge-amm"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-amm-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-fee-analysis">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1F4B8} Fee Spike Analysis</h2>
            <span class="section-badge" id="badge-fee-analysis"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-fee-analysis-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              Detects transactions where fees were paid at 100\xD7 or more above the base rate.
              Bots overpay fees to guarantee same-ledger execution alongside a counterparty \u2014
              a coordination technique used in wash trading and front-running.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-desttag">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1F3F7} Destination Tag Patterns</h2>
            <span class="section-badge" id="badge-desttag"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-desttag-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              Analyses destination tags used in exchange payments. The same tag repeated = one person's exchange account.
              Many different tags = a service routing to many accounts, or deliberate deposit spreading.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-pathdepth">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1F504} Path Payment Depth</h2>
            <span class="section-badge" id="badge-pathdepth"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-pathdepth-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              Analyses multi-hop path payments for circular routing (XRP\u2192IOU\u2192XRP round-trips),
              self-routing (paying yourself through the DEX to generate artificial volume),
              and deep hop chains that may obscure fund origin.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-memos" style="display:none">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1F4DD} Memo Analysis</h2>
            <span class="section-badge" id="badge-memos"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-memos-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              Scans all memo fields for scam patterns, repeated coordination text, and hex-encoded data.
              Memos are a vector for social engineering \u2014 attackers embed instructions inside payments.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-escrow-depth" style="display:none">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1F512} Escrow Depth</h2>
            <span class="section-badge" id="badge-escrow-depth"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-escrow-depth-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              Identifies third-party escrows (created by external accounts), maturity dates,
              and conditional escrows. Third-party escrows can lock funds with conditions the wallet owner didn't set.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-checks" style="display:none">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1F9FE} Open Checks</h2>
            <span class="section-badge" id="badge-checks"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-checks-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              XRPL Checks are deferred payments \u2014 like a paper check, the recipient can cash them at any time.
              Open checks represent future outflow commitments. Expired checks waste reserve slots.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-livebook" style="display:none">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1F4D6} Live Order Book</h2>
            <span class="section-badge" id="badge-livebook"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-livebook-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              Current live order book for this wallet's most-traded pair.
              Detects wall orders (one address dominating book depth), uniform bot-placed sizes,
              and whether this wallet's open offers make up an unusual share of visible liquidity.
            </p>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-trustlines">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1F517} Trustlines</h2>
            <span class="section-badge section-badge--neutral" id="trust-count-badge">0</span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-trust-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-tx">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1F4DC} Transaction History</h2>
            <span class="section-badge section-badge--neutral" id="badge-tx">\u2014</span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-tx-timeline"></div>
        </section>

        <section class="widget-card inspector-section report-card" id="section-report">
          <header class="widget-header section-header" tabindex="0" role="button" aria-expanded="true">
            <h2 class="widget-title">\u{1F4C4} Full Investigation Report</h2>
            <span class="section-badge section-badge--neutral" id="badge-report">Auto-generated</span>
            <button class="report-export-btn" id="report-export-btn" onclick="exportInspectorReport()" title="Copy report to clipboard">\u{1F4CB} Copy</button>
            <button class="report-export-btn" onclick="printInspectorReport()" title="Print or save as PDF" style="margin-left:4px">\u{1F5A8} Print / PDF</button>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-report-body">
            <p class="widget-help" style="opacity:.55;font-size:.84rem">
              A plain-English summary of every finding, recommended actions, and a full data snapshot.
              Generates automatically after each inspection.
            </p>
          </div>
        </section>

      </div>
    </div>
  `))}function Ay(){if(document.getElementById("inspector-nav"))return;let e=document.createElement("nav");e.id="inspector-nav",e.setAttribute("aria-label","Inspector navigation"),e.innerHTML=`
    <div class="inspector-nav-track">

      <!-- SIMPLE MODE: always visible -->
      <div class="nav-group nav-group--security">
        <div class="nav-group-label">Security</div>
        <div class="nav-group-btns">
          <button class="in-btn" data-jump="security"><span class="in-icon">\u{1F510}</span><span class="in-label">Security</span></button>
          <button class="in-btn" data-jump="drain"><span class="in-icon">\u26A0\uFE0F</span><span class="in-label">Drain</span></button>
          <button class="in-btn" data-jump="fundflow"><span class="in-icon">\u{1F30A}</span><span class="in-label">Flow</span></button>
          <button class="in-btn" data-jump="inbound"><span class="in-icon">\u{1F4E5}</span><span class="in-label">Inbound</span></button>
          <button class="in-btn" data-jump="nft"><span class="in-icon">\u{1F3A8}</span><span class="in-label">NFT</span></button>
        </div>
      </div>

      <div class="nav-group-divider"></div>

      <div class="nav-group">
        <div class="nav-group-label">Analytics</div>
        <div class="nav-group-btns">
          <button class="in-btn" data-jump="wash"><span class="in-icon">\u{1F4CA}</span><span class="in-label">Wash</span></button>
          <button class="in-btn in-btn--suite" data-jump="forensic-suite"><span class="in-icon">\u{1F9EC}</span><span class="in-label">Forensic</span></button>
          <!-- Advanced-only forensic engine buttons -->
          <button class="in-btn" data-jump="benfords"><span class="in-icon">\u{1F4D0}</span><span class="in-label">Benford</span></button>
          <button class="in-btn" data-jump="entropy"><span class="in-icon">\u{1F500}</span><span class="in-label">Entropy</span></button>
          <button class="in-btn" data-jump="zipf"><span class="in-icon">\u{1F4C8}</span><span class="in-label">Zipf</span></button>
          <button class="in-btn" data-jump="timeseries"><span class="in-icon">\u{1F550}</span><span class="in-label">Time</span></button>
          <button class="in-btn" data-jump="granger"><span class="in-icon">\u{1F517}</span><span class="in-label">Coupling</span></button>
        </div>
      </div>

      <div class="nav-group-divider"></div>

      <!-- ADVANCED MODE: account + data groups -->
      <div class="nav-group nav-group--account advanced-only">
        <div class="nav-group-label">Account</div>
        <div class="nav-group-btns">
          <button class="in-btn" data-jump="volconc"><span class="in-icon">\u{1FAE7}</span><span class="in-label">Vol</span></button>
          <button class="in-btn" data-jump="issuer"><span class="in-icon">\u{1FA99}</span><span class="in-label">Issuer</span></button>
          <button class="in-btn" data-jump="issuer-connections"><span class="in-icon">\u{1F578}</span><span class="in-label">Network</span></button>
          <button class="in-btn" data-jump="amm"><span class="in-icon">\u{1F4A7}</span><span class="in-label">AMM</span></button>
        </div>
      </div>

      <div class="nav-group-divider advanced-only"></div>

      <div class="nav-group advanced-only">
        <div class="nav-group-label">Deep Data</div>
        <div class="nav-group-btns">
          <button class="in-btn" data-jump="fee-analysis"><span class="in-icon">\u{1F4B8}</span><span class="in-label">Fees</span></button>
          <button class="in-btn" data-jump="desttag"><span class="in-icon">\u{1F3F7}</span><span class="in-label">Tags</span></button>
          <button class="in-btn" data-jump="pathdepth"><span class="in-icon">\u{1F504}</span><span class="in-label">Paths</span></button>
          <button class="in-btn" data-jump="memos"><span class="in-icon">\u{1F4DD}</span><span class="in-label">Memos</span></button>
          <button class="in-btn" data-jump="escrow-depth"><span class="in-icon">\u{1F512}</span><span class="in-label">Escrow</span></button>
          <button class="in-btn" data-jump="checks"><span class="in-icon">\u{1F9FE}</span><span class="in-label">Checks</span></button>
          <button class="in-btn" data-jump="livebook"><span class="in-icon">\u{1F4D6}</span><span class="in-label">Book</span></button>
          <button class="in-btn" data-jump="trustlines"><span class="in-icon">\u{1F517}</span><span class="in-label">Lines</span></button>
          <button class="in-btn" data-jump="tx"><span class="in-icon">\u{1F4DC}</span><span class="in-label">Txns</span></button>
        </div>
      </div>

      <div class="nav-group-divider"></div>

      <div class="nav-group">
        <div class="nav-group-label">Output</div>
        <div class="nav-group-btns">
          <button class="in-btn in-btn--report" data-jump="report"><span class="in-icon">\u{1F4C4}</span><span class="in-label">Report</span></button>
          <button class="in-btn in-btn--guide" onclick="showInspectorHowTo()"><span class="in-icon">?</span><span class="in-label">Guide</span></button>
        </div>
      </div>

    </div>
  `;let t=document.getElementById("tab-inspector");t&&t.appendChild(e)}function Ey(){if(document.getElementById("inspector-howto"))return;let e=document.createElement("div");e.id="inspector-howto",e.className="howto-overlay",e.style.display="none",e.innerHTML=`
    <div class="howto-modal">
      <button class="howto-close" onclick="hideInspectorHowTo()" aria-label="Close guide">\u2715</button>

      <div class="howto-head">
        <div class="howto-head-icon">\u{1F50D}</div>
        <h2 class="howto-title">Inspector Guide</h2>
        <p class="howto-subtitle">What each section tells you and what to watch for</p>
      </div>

      <div class="howto-items">

        <div class="howto-item">
          <div class="howto-item-icon">\u{1F510}</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Security Audit</div>
            <div class="howto-item-desc">Decodes every account flag, checks master key status, regular key age, and multisig signer lists.
              <strong class="howto-red">Red flag:</strong> master key disabled with no regular key and no signer list = funds permanently inaccessible.</div>
          </div>
        </div>

        <div class="howto-item howto-item--warn">
          <div class="howto-item-icon">\u26A0</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Drain Risk</div>
            <div class="howto-item-desc">Detects classic wallet-drain patterns. A drained account typically has master key disabled and a new regular key set by the attacker.
              We also detect large outflows within 48h of an auth change, open payment channels, and external key injections (a 3rd party setting your key).</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">\u{1F3A8}</div>
          <div class="howto-item-body">
            <div class="howto-item-title">NFT Analysis</div>
            <div class="howto-item-desc">Catches the most common NFT scam: creating a sell offer for 0 XRP or \u22641 XRP \u2014 the victim thinks they're signing something else but listed their NFT for free.
              Also flags NFTs with no metadata URI (common in fake-offer scams) and unexpected burns.</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">\u{1F4CA}</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Wash Trading</div>
            <div class="howto-item-desc">Scores 0\u2013100 across five signals: cancel ratio &gt;55%, round-trip counterparties, single-pair concentration &gt;70%, fill rate &lt;5%, and 8+ offers in 30 seconds.
              Score above 50 warrants review \u2014 market makers may score moderately without manipulation intent.</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">\u{1FA99}</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Token Issuer</div>
            <div class="howto-item-desc">Shows outstanding token obligations (negative balances = tokens issued). Checks individual line freezes, global freeze, and the NoFreeze flag \u2014
              the most important trust signal for token holders since it permanently prevents issuer freeze actions.</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">\u{1F4A7}</div>
          <div class="howto-item-body">
            <div class="howto-item-title">AMM / Liquidity</div>
            <div class="howto-item-desc">Detects LP token positions (03\u2026 currency prefix), deposit/withdrawal history, fee votes, and auction slot bids.
              Large positions carry impermanent loss risk when pool asset prices diverge.</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">\u{1F517}</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Trustlines</div>
            <div class="howto-item-desc"><span class="howto-red">Frozen by issuer</span> = you cannot transfer that token.
              NoRipple is normal and protective. Negative balance = this account owes that amount to the counterparty.
              Limit=0 with negative balance is common for DEX issuers.</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">\u{1F4DC}</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Transaction History</div>
            <div class="howto-item-desc">Up to 5,000 transactions fetched via deep sequential pagination (configurable via <code>window._inspectMaxTx</code>) \u2014 color-coded by risk.
              <span class="howto-amber">Amber border</span> = auth-changing tx (key changes, signer lists).
              <span class="howto-red">Red border</span> = high risk (free NFT offers). Faded = failed tx.
              Click the \u{1F517} or \u{1F50D} icon on any row to open it on XRPL Livenet or XRPScan.</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">\u{1F4B8}</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Fee Spike Analysis</div>
            <div class="howto-item-desc">Bots often pay 100\u2013500\xD7 the normal fee to guarantee their transaction lands in the same ledger as a counterparty's.
              Organic users almost never pay more than 2\u20135\xD7.
              This section flags bursts of elevated fees and links the specific transaction hashes.</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">\u{1F3F7}</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Destination Tag Patterns</div>
            <div class="howto-item-desc">Exchanges use destination tags to identify which customer account receives a deposit \u2014 like a bank reference number.
              One tag used repeatedly = the same person's exchange account. Many different tags to one exchange = a service routing to multiple customer accounts, or deliberate deposit spreading.</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">\u{1F504}</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Path Payment Depth</div>
            <div class="howto-item-desc">Path payments route through intermediate DEX pairs.
              <strong class="howto-red">XRP\u2192IOU\u2192XRP round-trips</strong> pay and receive XRP via token pairs \u2014 generating DEX volume with no economic transfer.
              <strong class="howto-red">Self-routing</strong> (destination = source) is pure wash volume.
              Deep hop chains (3+ intermediaries) can obscure fund origin.</div>
          </div>
        </div>

        <div class="howto-item">
          <div class="howto-item-icon">\u{1F578}</div>
          <div class="howto-item-body">
            <div class="howto-item-title">Issuer Connection Graph</div>
            <div class="howto-item-desc">Shows token supply distribution across holders, accounts the issuer funded/created, and mirror-wallet clusters \u2014
              groups of wallets that all received nearly identical token amounts. Mirror clusters often indicate sybil rings or insider pre-allocations.
              <strong>Note:</strong> supply percentages are only reliable when gateway_balances data is available; otherwise a "visible sample" caveat is shown.</div>
          </div>
        </div>

        <div class="howto-tip">
          <span class="howto-tip-icon">\u{1F4A1}</span>
          <span><strong>Pro tips:</strong> Connect your wallet in Profile to auto-populate your address here.
            Click any address in the live stream to inspect it instantly.
            Paste an address \u2014 inspection runs automatically.
            Use the \u2B07 Export CSV button in the report to take transaction data into Excel or Python.</span>
        </div>

      </div>
    </div>
  `,e.addEventListener("click",t=>{t.target===e&&Vi()}),document.addEventListener("keydown",t=>{t.key==="Escape"&&e.style.display!=="none"&&Vi()}),document.body.appendChild(e)}function Au(e){Be("#inspector-nav .in-btn[data-jump]").forEach(t=>t.classList.toggle("in-btn--active",t.dataset.jump===e))}function Ny(){var n;if(!document.body.classList.contains("inspector")||((n=x("inspect-result"))==null?void 0:n.style.display)==="none")return;let e=["security","drain","nft","wash","issuer","amm","trustlines","tx"],t=null;for(let s of e){let a=document.getElementById("section-"+s);a&&a.getBoundingClientRect().top<=150&&(t=s)}t&&Au(t)}function no(e,t){let n=x(e);if(!n)return;let s=t.filter(o=>o.sev==="critical").length,a=t.filter(o=>o.sev==="warn").length;s?(n.textContent=s+" critical",n.className="section-badge section-badge--crit"):a?(n.textContent=a+" warn",n.className="section-badge section-badge--warn"):(n.textContent="OK",n.className="section-badge section-badge--ok")}function Ry(e,t){let n=x(e);if(!n)return;let s={low:"ok",medium:"warn",high:"warn",critical:"crit"};n.textContent=t,n.className="section-badge section-badge--"+(s[t]||"ok")}window._toggleForensicTab=function(e){var a,o;let t=document.getElementById("forensic-tab-"+e);if(!t)return;let n=t.style.display!=="none";t.style.display=n?"none":"";let s=document.getElementById("ftab-chevron-"+e);s&&(s.textContent=n?"\u25BE":"\u25B4"),(a=document.getElementById("ftab-btn-"+e))==null||a.setAttribute("aria-expanded",String(!n)),!n&&((o=t.querySelector('[id^="inspect-"]'))==null?void 0:o.innerHTML)===""&&(t.querySelector('[id^="inspect-"]').innerHTML='<div style="opacity:.45;font-size:.8rem;padding:8px 0">Run an inspection first.</div>')};function _y(){var n,s;let e=x("inspect-addr-badge"),t=((n=e==null?void 0:e.dataset)==null?void 0:n.fullAddr)||(e==null?void 0:e.textContent);!t||t==="\u2014"||(s=navigator.clipboard)==null||s.writeText(t).then(()=>{let a=document.querySelector(".irb-copy-btn");a&&(a.textContent="\u2713",setTimeout(()=>a.textContent="\u{1F4CB}",1500))})}window.inspectorGoBack=function(){let e=x("inspect-result"),t=x("inspect-empty"),n=x("inspect-err"),s=x("inspect-addr");e&&(e.style.display="none"),n&&(n.style.display="none"),t&&(t.style.display=""),s&&(s.value=""),Qi(),Zi(),window.scrollTo({top:0,behavior:"smooth"}),setTimeout(()=>s==null?void 0:s.focus(),300)};function Dy(){let e=document.getElementById("inspector-howto");e&&(e.style.display="",requestAnimationFrame(()=>e.classList.add("howto-visible")))}function Vi(){let e=document.getElementById("inspector-howto");e&&(e.classList.remove("howto-visible"),setTimeout(()=>{e.classList.contains("howto-visible")||(e.style.display="none")},260))}var Yi="nalulf_inspect_history",Iy="nalulf_wallets",Zs="nalulf_watchlist",Eu="nalulf_analyst_mode";var Fy=[{label:"SOLO Issuer",addr:"rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz",tag:"Token Issuer",icon:"\u{1FA99}",note:"200 trustlines \xB7 master disabled \xB7 liquidity provider",color:"#ffb86c"},{label:"Ripple Genesis",addr:"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",tag:"Genesis",icon:"\u{1F310}",note:"Original genesis wallet \xB7 100 billion XRP issued",color:"#50fa7b"},{label:"Bitstamp Hot",addr:"rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B",tag:"Exchange",icon:"\u{1F3E6}",note:"Major exchange hot wallet \xB7 high payment volume",color:"#8be9fd"},{label:"GateHub Hot",addr:"rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq",tag:"Exchange",icon:"\u{1F3E6}",note:"GateHub gateway \xB7 multi-currency issuance",color:"#8be9fd"},{label:"XAMAN Wallet",addr:"rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY",tag:"Wallet App",icon:"\u{1F4F1}",note:"XAMAN (XUMM) custodial wallet address",color:"#bd93f9"},{label:"DEX Market Maker",addr:"r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59",tag:"Market Maker",icon:"\u{1F4CA}",note:"High-volume DEX activity \xB7 offer patterns",color:"#ff79c6"}],Oy=[{icon:"\u{1F510}",title:"Security Audit",desc:"Decodes all account flags, checks master key status, regular key age, multisig signer lists, and suspicious auth changes.",color:"#50fa7b"},{icon:"\u26A0",title:"Drain Detection",desc:"Classic drain setup, external key injection (3rd party sets your key), large outflows within 48h of auth change, open payment channels.",color:"#ff5555"},{icon:"\u{1F3A8}",title:"NFT Risk",desc:"Zero-value sell offers (free NFT drain vector), no-URI spam tokens, unexpected burns, transfer fee exposure.",color:"#bd93f9"},{icon:"\u{1F4CA}",title:"Wash Trading",desc:"Five-signal scoring: cancel ratio, round-trip counterparties, single-pair concentration, fill rate, burst activity.",color:"#ffb86c"},{icon:"\u{1FA99}",title:"Token Issuer",desc:"Outstanding obligations, individual line freezes, global freeze, NoFreeze protection, black hole risk detection.",color:"#f1fa8c"},{icon:"\u{1F4A7}",title:"AMM & Liquidity",desc:"LP token positions, deposit/withdrawal history, fee votes, auction slot bids, impermanent loss warnings.",color:"#8be9fd"},{icon:"\u{1F30A}",title:"Fund Flow Tracer",desc:"Traces every outbound payment from a wallet \u2014 where funds went, which exchanges they reached, multi-hop path payment routes, and a full chronological drain timeline.",color:"#00d4ff"},{icon:"\u{1F578}",title:"Issuer Connection Graph",desc:"Token supply concentration, top holder %, accounts the issuer created/funded, and mirror-wallet clusters \u2014 groups of wallets receiving identical token amounts (sybil detection).",color:"#bd93f9"}];function By(){Xy(),Hy(),Qi(),Zi(),ta(),zy(),_u()}function Xy(){let e=document.getElementById("isd-notable-grid");e&&(e.innerHTML=Fy.map(t=>`
    <button class="isd-notable-card" onclick="inspectorLoadAddr('${t.addr}')" type="button">
      <div class="isd-notable-top">
        <span class="isd-notable-icon" style="color:${t.color}">${t.icon}</span>
        <span class="isd-notable-tag" style="border-color:${t.color}40;color:${t.color}">${y(t.tag)}</span>
      </div>
      <div class="isd-notable-label">${y(t.label)}</div>
      <div class="isd-notable-addr mono">${t.addr.slice(0,8)}\u2026${t.addr.slice(-6)}</div>
      <div class="isd-notable-note">${y(t.note)}</div>
    </button>
  `).join(""))}function Hy(){let e=document.getElementById("isd-cap-grid");e&&(e.innerHTML=Oy.map(t=>`
    <div class="isd-cap" style="--cap-color:${t.color}">
      <div class="isd-cap-icon-wrap"><span class="isd-cap-icon">${t.icon}</span></div>
      <div class="isd-cap-body">
        <div class="isd-cap-title">${y(t.title)}</div>
        <div class="isd-cap-desc">${y(t.desc)}</div>
      </div>
    </div>
  `).join(""))}function Qi(){let e=document.getElementById("isd-wallets-section"),t=document.getElementById("isd-wallet-list");if(!e||!t)return;let n=ve(Q(Iy))||[];if(!n.length){e.style.display="none";return}e.style.display="",t.innerHTML=n.map(s=>{let a=s.color||"#50fa7b",o=s.emoji||"\u{1F48E}",i=s.label||"Wallet",r=s.address||"",l=r?r.slice(0,8)+"\u2026"+r.slice(-6):"\u2014",c=s.testnet?'<span class="isd-wallet-testnet">TESTNET</span>':"";return`
      <button class="isd-wallet-card" onclick="inspectorLoadAddr('${y(r)}')" type="button">
        <div class="isd-wallet-avatar" style="background:${a}20;border-color:${a}50">${o}</div>
        <div class="isd-wallet-info">
          <div class="isd-wallet-name">${y(i)} ${c}</div>
          <div class="isd-wallet-addr mono">${l}</div>
        </div>
        <div class="isd-wallet-inspect">Inspect \u2192</div>
      </button>
    `}).join("")}function Zi(){let e=document.getElementById("isd-recent-section"),t=document.getElementById("isd-recent-list");if(!e||!t)return;let n=so();if(!n.length){e.style.display="none";return}e.style.display="",t.innerHTML=n.map((s,a)=>{let o=s.addr?s.addr.slice(0,10)+"\u2026"+s.addr.slice(-8):"\u2014",i=s.riskScore!=null?`<span class="isd-risk-pill isd-risk-pill--${Ru(s.riskScore)}">${s.riskScore}</span>`:"";return`
      <button class="isd-recent-row" onclick="inspectorLoadAddr('${y(s.addr)}')" type="button">
        <span class="isd-recent-n">${a+1}</span>
        <span class="isd-recent-addr mono">${o}</span>
        <div class="isd-recent-right">
          ${i}
          <span class="isd-recent-time">${ao(s.ts)}</span>
        </div>
      </button>
    `}).join("")}function zy(){eo(),window.addEventListener("xrpl-ledger",Wy),window.addEventListener("xrpl-connection",eo)}function Wy(e){Za()&&eo(e.detail)}var Wi=null;function Uy(){return Wi||(Wi={idx:document.getElementById("isd-ledger-idx"),age:document.getElementById("isd-ledger-age"),tps:document.getElementById("isd-tps"),tpsTrnd:document.getElementById("isd-tps-trend"),fee:document.getElementById("isd-fee"),feeLv:document.getElementById("isd-fee-level"),close:document.getElementById("isd-close-time"),dot:document.getElementById("isd-conn-dot"),connLbl:document.getElementById("isd-conn-label"),pill:document.getElementById("isd-conn-pill"),domTx:document.getElementById("isd-dom-tx"),domPct:document.getElementById("isd-dom-pct"),bar:document.getElementById("isd-fee-bar"),barLbl:document.getElementById("isd-fee-bar-label")})}function eo(){let{idx:e,age:t,tps:n,tpsTrnd:s,fee:a,feeLv:o,close:i,dot:r,connLbl:l,pill:c,domTx:d,domPct:u,bar:p,barLbl:m}=Uy(),f=B.connectionState||"disconnected",g={connected:{label:"Connected",cls:"conn--live"},connecting:{label:"Connecting\u2026",cls:"conn--warn"},disconnected:{label:"Disconnected",cls:"conn--dead"}},b=g[f]||g.disconnected;r&&(r.className="isd-conn-dot"),l&&(l.textContent=b.label),c&&(c.className=`isd-conn-pill ${b.cls}`);let h=B.ledgerLog||[];if(h.length&&e){let T=h[0];if(e.textContent=Number(T.ledgerIndex||0).toLocaleString(),t&&(t.textContent=T.closeTimeSec!=="\u2014"?T.closeTimeSec+"s close":"\u2014"),i){let S=parseFloat(T.closeTimeSec);i.textContent=isNaN(S)?"\u2014":S.toFixed(1)}}let v=B.tpsHistory||[];if(v.length&&n){let T=v.slice(-5),S=T.reduce((M,C)=>M+C,0)/T.length;if(n.textContent=S.toFixed(1),s&&v.length>=6){let M=v.slice(-10,-5),C=M.reduce((R,O)=>R+O,0)/M.length,E=S-C;s.textContent=E>.5?"\u2191 rising":E<-.5?"\u2193 falling":"\u2192 stable",s.className=`isd-metric-sub ${E>.5?"isd-up":E<-.5?"isd-down":""}`}}let w=B.feeHistory||[];if(w.length&&a){let T=w.slice(-5),S=T.reduce((E,R)=>E+R,0)/T.length,M=S/1e6;a.textContent=S<5e3?S.toFixed(0)+" drops":M.toFixed(5)+" XRP";let C=S<20?{lbl:"Low",cls:"fee-low",pct:10}:S<100?{lbl:"Normal",cls:"fee-normal",pct:28}:S<500?{lbl:"Elevated",cls:"fee-elevated",pct:60}:S<2e3?{lbl:"High",cls:"fee-high",pct:82}:{lbl:"Congested",cls:"fee-congest",pct:100};o&&(o.textContent=C.lbl,o.className=`isd-metric-sub ${C.cls}`),p&&(p.style.width=C.pct+"%",p.className=`isd-fee-bar-fill ${C.cls}`),m&&(m.textContent=C.lbl,m.className=`isd-fee-bar-level ${C.cls}`)}let k=B.txMixAccum||{},$=Object.entries(k).filter(([,T])=>T>0).sort(([,T],[,S])=>S-T);if($.length&&d){let T=$.reduce((C,[,E])=>C+E,0),[S,M]=$[0];d.textContent=S,u&&(u.textContent=(M/T*100).toFixed(0)+"% of traffic")}}window.exportTxCSV=function(e){var l,c;if(!e||!e.length){alert("No transaction data to export. Run an inspection first.");return}let t=946684800,s=[["Hash","Date","Type","Account","Destination","Amount_XRP","Amount_Token","Currency","Fee_Drops","DestinationTag","Result","LedgerIndex"],...e.map(({tx:d,meta:u})=>{var h,v;let p=d.date?new Date((d.date+t)*1e3).toISOString():"",m=typeof d.Amount=="string"?(Number(d.Amount)/1e6).toFixed(6):"",f=(h=d.Amount)!=null&&h.value?d.Amount.value:"",g=((v=d.Amount)==null?void 0:v.currency)||(typeof d.Amount=="string"?"XRP":""),b=(u==null?void 0:u.TransactionResult)||"";return[d.hash||"",p,d.TransactionType||"",d.Account||"",d.Destination||"",m,f,g,d.Fee||"",d.DestinationTag??"",b,d.ledger_index||""]})].map(d=>d.map(u=>{let p=String(u);return p.includes(",")||p.includes('"')||p.includes(`
`)?'"'+p.replace(/"/g,'""')+'"':p}).join(",")).join(`
`),a=new Blob([s],{type:"text/csv;charset=utf-8;"}),o=URL.createObjectURL(a),i=document.createElement("a"),r=((c=(l=document.getElementById("inspect-addr-badge"))==null?void 0:l.dataset)==null?void 0:c.fullAddr)||"wallet";i.href=o,i.download=`naluxrp_${r.slice(0,10)}_${new Date().toISOString().slice(0,10)}.csv`,document.body.appendChild(i),i.click(),document.body.removeChild(i),URL.revokeObjectURL(o)};function jy(e,t){let s=so().find(o=>o.addr===e);if(!s||s.riskScore==null||t==null)return null;let a=t-s.riskScore;return{prev:s.riskScore,curr:t,diff:a,ts:s.ts}}function qy(e,t){let n=jy(e,t);if(!n||Math.abs(n.diff)<2)return;let s=document.getElementById("inspect-risk-score");if(!s)return;let a=n.diff>0?`<span style="color:#ff5555;font-size:.7rem;font-weight:700"> \u2191${n.diff}</span>`:`<span style="color:#50fa7b;font-size:.7rem;font-weight:700"> \u2193${Math.abs(n.diff)}</span>`,o=ao(n.ts);s.insertAdjacentHTML("afterend",`<span class="risk-score-diff" title="Changed from ${n.prev} \u2192 ${n.curr} since ${o}">${a} vs ${o}</span>`)}window._inspectMaxTx||(window._inspectMaxTx=5e3);window._debugBalanceDeltas=yu;window._debugOfferLifecycles=Cu;window._debugReconstructBalanceHistory=wu;window._debugFindDrainEpisodes=xu;window._debugDrainRisk=Tu;window.inspectorLoadAddr=function(e){let t=x("inspect-addr");t&&(t.value=e),ys()};window.inspectWalletAddr=function(e){var n,s;window.inspectorLoadAddr(e);let t=document.querySelector('[data-tab="inspector"]');t&&((n=window.switchTab)==null||n.call(window,t,"inspector")),(s=window.showDashboard)==null||s.call(window)};window.printInspectorReport=function(){var s,a;let e=document.getElementById("inspect-report-body");if(!e)return;let t=((a=(s=document.getElementById("inspect-addr-badge"))==null?void 0:s.dataset)==null?void 0:a.fullAddr)||"wallet",n=window.open("","_blank","width=900,height=700");n.document.write(`<!DOCTYPE html><html><head>
    <title>NaluXRP Report \u2014 ${t}</title>
    <style>
      body { font-family: -apple-system, system-ui, sans-serif; background:#fff; color:#111; margin:40px; line-height:1.6; }
      .report-cover { display:flex; justify-content:space-between; align-items:flex-start; border-bottom:2px solid #111; padding-bottom:20px; margin-bottom:24px; }
      .report-section { margin-bottom:28px; }
      .report-section-h { font-size:1.05rem; font-weight:800; border-bottom:1px solid #ddd; padding-bottom:6px; margin-bottom:12px; }
      .report-stat-row { display:flex; gap:12px; padding:4px 0; border-bottom:1px solid #f0f0f0; font-size:.88rem; }
      .report-stat-k { color:#555; min-width:220px; flex-shrink:0; }
      .report-finding-row { margin-bottom:10px; padding:8px; border-left:3px solid #ddd; }
      .report-module-h { font-weight:700; font-size:.9rem; margin:16px 0 6px; color:#333; }
      .report-rec { display:flex; gap:10px; margin-bottom:8px; font-size:.88rem; }
      @media print { body { margin:20px; } button { display:none; } }
    </style>
  </head><body>
    <button onclick="window.print()" style="margin-bottom:20px;padding:8px 16px;cursor:pointer">\u{1F5A8} Print / Save as PDF</button>
    ${e.innerHTML}
  </body></html>`),n.document.close()};window.exportInspectorReport=function(){var n;let e=document.getElementById("inspect-report-body");if(!e)return;let t=e.innerText||e.textContent||"";(n=navigator.clipboard)==null||n.writeText(t).then(()=>{let s=document.getElementById("report-export-btn");s&&(s.textContent="\u2713 Copied!",setTimeout(()=>{s.textContent="\u{1F4CB} Copy Report"},2e3))}).catch(()=>{let s=document.createRange();s.selectNodeContents(e);let a=window.getSelection();a.removeAllRanges(),a.addRange(s)})};window.inspectorClearHistory=function(){vt(Yi);let e=document.getElementById("isd-recent-section");e&&(e.style.display="none")};window.inspectorClearWatchlist=function(){vt(Zs),ta()};function so(){return ve(Q(Yi))||[]}function Vy(e,t,n=[]){let s=so();s=s.filter(o=>o.addr!==e);let a=n.filter(o=>o.sev==="critical"||o.sev==="warn").map(o=>o.module+":"+o.headline.slice(0,40)).sort().join("|");s.unshift({addr:e,riskScore:t,ts:Date.now(),fingerprint:a}),s=s.slice(0,12),Z(Yi,JSON.stringify(s))}function ea(){return ve(Q(Zs))||[]}function Gy(e,t){let n=ea().filter(s=>s.addr!==e);n.unshift({addr:e,label:t||W(e),addedTs:Date.now(),lastScore:null,lastTs:null}),Z(Zs,JSON.stringify(n.slice(0,50)))}function Nu(e){Z(Zs,JSON.stringify(ea().filter(t=>t.addr!==e)))}function Gi(e){return ea().some(t=>t.addr===e)}function Ky(e,t){let n=ea().map(s=>s.addr===e?{...s,lastScore:t,lastTs:Date.now()}:s);Z(Zs,JSON.stringify(n))}function ao(e){let t=Date.now()-e;return t<6e4?"just now":t<36e5?Math.floor(t/6e4)+"m ago":t<864e5?Math.floor(t/36e5)+"h ago":Math.floor(t/864e5)+"d ago"}function Ru(e){return qi(e).replace("risk-","")}var Zt=!1;function _u(){Zt=localStorage.getItem(Eu)==="true",er()}function er(){let e=document.getElementById("inspect-result");if(!e)return;e.classList.toggle("mode-advanced",Zt),e.classList.toggle("mode-simple",!Zt);let t=document.getElementById("analyst-mode-btn");t&&(t.textContent=Zt?"\u2697 Advanced":"\u{1F441} Simple",t.title=Zt?"Switch to Simple view":"Switch to Advanced (analyst) view",t.setAttribute("aria-pressed",String(Zt)))}window.toggleAnalystMode=function(){Zt=!Zt,localStorage.setItem(Eu,Zt),er()};var Jy=new Set(["section-overview","section-report"]),Yy=new Set(["section-security","section-drain","section-fundflow","section-inbound"]);function Qy(){let e=document.getElementById("inspect-result");if(!e)return;let t=[...e.querySelectorAll(".inspector-section")],n={crit:0,warn:1,neutral:2,ok:3,"":4},s=t.filter(i=>!Jy.has(i.id)&&!Yy.has(i.id));s.sort((i,r)=>{let l=c=>{let d=c.querySelector(".section-badge");if(!d)return"";let u=d.className;return u.includes("crit")?"crit":u.includes("warn")?"warn":u.includes("neutral")?"neutral":u.includes("ok")?"ok":""};return(n[l(i)]??4)-(n[l(r)]??4)});let a=document.getElementById("section-inbound")||document.getElementById("section-drain");if(!a)return;let o=a;for(let i of s)o.after(i),o=i}function Zy(e,t,n,s){let a=document.getElementById("quick-verdict-body");if(!a)return;let o=t.filter(u=>u.sev==="critical"),i=t.filter(u=>u.sev==="warn"),r=e<20?"#50fa7b":e<45?"#ffb86c":e<70?"#ff8c42":"#ff5555",l=e<20?"Low Risk":e<45?"Moderate":e<70?"High Risk":"Critical",c="",d="";if(o.length===0&&i.length===0)c=`No elevated signals found across ${s.toLocaleString()} transactions${n!=null?` and ${n} days of history`:""}.`,d="This wallet appears to operate within normal parameters.";else{let u=o.slice(0,2).map(m=>m.headline).join("; "),p=i.slice(0,2).map(m=>m.headline).join("; ");c=o.length?`${o.length} critical issue${o.length>1?"s":""}: ${u}.`:`${i.length} warning${i.length>1?"s":""}: ${p}.`,d=o.length?"Review the highlighted sections below. Scroll to the Report for full recommendations.":"Review the flagged sections below for context before drawing conclusions."}a.innerHTML=`
    <div style="display:flex;align-items:flex-start;gap:16px;flex-wrap:wrap">
      <div style="text-align:center;flex-shrink:0">
        <div style="font-size:2.2rem;font-weight:900;color:${r};line-height:1">${e}</div>
        <div style="font-size:.65rem;font-weight:800;color:${r};letter-spacing:.1em;text-transform:uppercase">${l}</div>
      </div>
      <div style="flex:1;min-width:200px">
        <div style="font-size:.92rem;color:rgba(255,255,255,.88);line-height:1.6;margin-bottom:6px">${y(c)}</div>
        <div style="font-size:.8rem;color:rgba(255,255,255,.45);line-height:1.5">${y(d)}</div>
        ${o.length||i.length?`
        <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
          ${o.length?`<span style="background:rgba(255,85,85,.12);border:1px solid rgba(255,85,85,.3);color:#ff5555;border-radius:999px;padding:2px 10px;font-size:.72rem;font-weight:700">${o.length} Critical</span>`:""}
          ${i.length?`<span style="background:rgba(255,184,108,.10);border:1px solid rgba(255,184,108,.25);color:#ffb86c;border-radius:999px;padding:2px 10px;font-size:.72rem;font-weight:700">${i.length} Warnings</span>`:""}
          <button onclick="document.getElementById('section-report')?.scrollIntoView({behavior:'smooth'})"
            style="background:rgba(0,212,255,.08);border:1px solid rgba(0,212,255,.2);color:var(--accent);border-radius:999px;padding:2px 10px;font-size:.72rem;cursor:pointer">Full Report \u2193</button>
        </div>`:""}
      </div>
    </div>`}function e0(e,t){let n=document.getElementById("change-banner");if(!n)return;n.style.display="none";let a=so().find(u=>u.addr===e);if(!(a!=null&&a.fingerprint))return;let o=new Set(t.filter(u=>u.sev==="critical"||u.sev==="warn").map(u=>u.module+":"+u.headline.slice(0,40))),i=new Set((a.fingerprint||"").split("|").filter(Boolean)),r=[...o].filter(u=>!i.has(u)),l=[...i].filter(u=>!o.has(u));if(!r.length&&!l.length)return;let c=ao(a.ts),d=[];r.length&&d.push(`<span style="color:#ff5555">+${r.length} new finding${r.length>1?"s":""}</span>`),l.length&&d.push(`<span style="color:#50fa7b">${l.length} resolved</span>`),n.style.display="",n.innerHTML=`
    <div style="background:rgba(255,184,108,.07);border:1px solid rgba(255,184,108,.25);border-radius:10px;
                padding:10px 14px;margin-bottom:10px;display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <span style="font-size:1rem">\u{1F514}</span>
      <span style="font-size:.84rem;color:rgba(255,255,255,.75)">
        Since last inspection <strong>${c}</strong>: ${d.join(", ")}
        ${r.length?"\u2014 "+r.slice(0,2).map(u=>u.split(":")[1]).join("; "):""}
      </span>
      <button onclick="document.getElementById('change-banner').style.display='none'" aria-label="Dismiss"
        style="margin-left:auto;background:none;border:none;color:rgba(255,255,255,.35);font-size:.9rem;cursor:pointer">\u2715</button>
    </div>`}function ta(){let e=document.getElementById("isd-watchlist-section"),t=document.getElementById("isd-watchlist-list");if(!e||!t)return;let n=ea();if(!n.length){e.style.display="none";return}e.style.display="",t.innerHTML=n.map(s=>{let a=s.addr.slice(0,8)+"\u2026"+s.addr.slice(-6),o=s.lastScore!=null?`<span class="isd-risk-pill isd-risk-pill--${Ru(s.lastScore)}">${s.lastScore}</span>`:"",i=s.lastTs?ao(s.lastTs):"never checked";return`
      <div class="isd-recent-row" style="align-items:center">
        <button class="isd-recent-addr mono" style="flex:1;text-align:left;background:none;border:none;cursor:pointer;color:inherit"
          onclick="inspectorLoadAddr('${y(s.addr)}')">${y(s.label||a)} <span style="opacity:.45;font-size:.75em">${a}</span></button>
        <div style="display:flex;align-items:center;gap:8px">
          ${o}
          <span style="font-size:.72rem;opacity:.45">${i}</span>
          <button onclick="_removeFromWatchlistUI('${y(s.addr)}')" aria-label="Remove ${y(s.label||a)} from watchlist"
            style="background:none;border:none;color:rgba(255,85,85,.6);font-size:.85rem;cursor:pointer;padding:2px 4px">\u2715</button>
        </div>
      </div>`}).join("")}window._removeFromWatchlistUI=function(e){Nu(e),ta()};function Du(e){let t=document.getElementById("watchlist-btn");if(!t)return;let n=Gi(e);t.textContent=n?"\u2605 Watching":"\u2606 Watch",t.title=n?"Remove from watchlist":"Add to watchlist",t.style.color=n?"#ffb86c":"",t.onclick=()=>{Gi(e)?Nu(e):Gy(e,null),Du(e),ta()}}function mu(e,t="inspect-activity-chart"){let n=document.getElementById(t);if(!n)return;if(!e.length){n.innerHTML='<div style="opacity:.4;font-size:.8rem;padding:10px 0">No transaction history to chart.</div>';return}let s=946684800,a={Payment:"#50fa7b",OfferCreate:"#00d4ff",OfferCancel:"#8be9fd",NFTokenMint:"#bd93f9",NFTokenCreateOffer:"#bd93f9",NFTokenAcceptOffer:"#ff79c6",AMMDeposit:"#ffb86c",AMMWithdraw:"#ffb86c",AMMCreate:"#ffb86c",SetRegularKey:"#ff5555",SignerListSet:"#ff5555",AccountSet:"#f1fa8c"},o="rgba(255,255,255,.25)",i={};for(let{tx:f}of e){if(!f.date)continue;let g=new Date((f.date+s)*1e3),b=new Date(g.getFullYear(),0,1),h=Math.ceil(((g-b)/864e5+b.getDay()+1)/7),v=`${g.getFullYear()}-${String(h).padStart(2,"0")}`;i[v]||(i[v]={count:0,types:{}}),i[v].count++;let w=f.TransactionType||"Other";i[v].types[w]=(i[v].types[w]||0)+1}let r=Object.entries(i).sort((f,g)=>f[0].localeCompare(g[0]));if(r.length<2){n.innerHTML='<div style="opacity:.4;font-size:.8rem;padding:10px 0">Not enough dated transactions for timeline.</div>';return}let l=Math.max(...r.map(([,f])=>f.count),1),c=Math.max(3,Math.min(16,Math.floor(600/r.length))),d=1,u=60,p=r.length*(c+d),m=r.map(([f,g])=>{var k;let b=Math.max(2,Math.round(g.count/l*u)),h=u-b,v=((k=Object.entries(g.types).sort(($,T)=>T[1]-$[1])[0])==null?void 0:k[0])||"Other",w=a[v]||o;return`<rect x="0" y="${h}" width="${c}" height="${b}" fill="${w}" opacity=".8" rx="1">
      <title>${f}: ${g.count} tx (dominant: ${v})</title></rect>`}).join("");n.innerHTML=`
    <div style="font-size:.65rem;color:rgba(255,255,255,.35);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">
      Activity Timeline \u2014 ${r.length} weeks \xB7 ${e.length.toLocaleString()} transactions
    </div>
    <div style="overflow-x:auto;padding-bottom:4px">
      <svg width="${p}" height="${u}" xmlns="http://www.w3.org/2000/svg" style="display:block;min-width:${p}px">
        ${r.map(([,f],g)=>{var k;let b=Math.max(2,Math.round(f.count/l*u)),h=u-b,v=((k=Object.entries(f.types).sort(($,T)=>T[1]-$[1])[0])==null?void 0:k[0])||"Other",w=a[v]||o;return`<rect x="${g*(c+d)}" y="${h}" width="${c}" height="${b}"
            fill="${w}" opacity=".8" rx="1">
            <title>${r[g][0]}: ${f.count} tx (${v})</title></rect>`}).join("")}
      </svg>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:5px">
      ${Object.entries(a).slice(0,8).map(([f,g])=>`<span style="font-size:.62rem;color:${g};opacity:.7">\u25CF ${f}</span>`).join("")}
    </div>`}function Iu(e,t){let n=new Map;for(let{tx:s,meta:a}of e){let o=s.Account===t,i=s.Destination===t;if(!o&&!i)continue;let r=o?s.Destination:s.Account;if(!r||r===t)continue;let l=ws(s);n.has(r)||n.set(r,{cnt:0,xrpOut:0,xrpIn:0,entity:Hn(r),firstSeen:l,lastSeen:l});let c=n.get(r);c.cnt++,l&&(c.firstSeen=c.firstSeen?Math.min(c.firstSeen,l):l,c.lastSeen=Math.max(c.lastSeen,l));let d=(a==null?void 0:a.delivered_amount)||s.Amount,u=typeof d=="string"?Number(d)/1e6:0;o?c.xrpOut+=u:c.xrpIn+=u}return n}function t0(e,t,n=15){let s=Iu(e,t),a=[...s.entries()].sort((r,l)=>l[1].xrpOut+l[1].xrpIn-(r[1].xrpOut+r[1].xrpIn)||l[1].cnt-r[1].cnt).slice(0,n);if(!a.length)return'<div class="inspect-empty-note">No counterparty interactions found.</div>';let o=Math.max(...a.map(([,r])=>r.xrpOut+r.xrpIn),1),i=a.map(([r,l],c)=>{var h;let d=l.xrpOut+l.xrpIn,u=Math.max(1.5,d/o*100),p=bn[(h=l.entity)==null?void 0:h.type]||bn.other,m=d>0?l.xrpOut/d:.5,f=m>.65?"\u2192 out":m<.35?"\u2190 in":"\u21C4 both",g=l.entity?`<span style="font-size:.64rem;color:${p};border:1px solid ${p};border-radius:999px;padding:1px 7px;margin-left:6px">${y(l.entity.name)}</span>`:"",b=Mu(l.firstSeen,l.lastSeen);return`
      <div style="display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.05)">
        <div style="width:18px;text-align:center;font-size:.7rem;color:rgba(255,255,255,.35);flex-shrink:0">${c+1}</div>
        <div style="width:150px;flex-shrink:0;overflow:hidden">
          <div style="display:flex;align-items:center">
            <span class="mono" style="font-size:.76rem;color:rgba(255,255,255,.85)" title="${y(r)}">${y(W(r))}</span>
            ${g}
          </div>
          ${b?`<div style="font-size:.62rem;color:rgba(255,255,255,.35);margin-top:1px">${y(b)}</div>`:""}
        </div>
        <div style="flex:1;height:10px;border-radius:4px;overflow:hidden;background:rgba(255,255,255,.05)">
          <div style="width:${u.toFixed(1)}%;height:100%;background:${p}"></div>
        </div>
        <div style="width:46px;text-align:center;font-size:.66rem;color:rgba(255,255,255,.5);flex-shrink:0">${f}</div>
        <div class="mono" style="width:100px;text-align:right;font-size:.75rem;color:rgba(255,255,255,.8);flex-shrink:0">${_(d,2)} XRP</div>
        <div style="width:46px;text-align:right;font-size:.68rem;color:rgba(255,255,255,.4);flex-shrink:0">${l.cnt} tx</div>
      </div>`}).join("");return`
    <div style="font-size:.65rem;color:rgba(255,255,255,.35);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px">
      Top Counterparties \u2014 ${a.length} of ${s.size} addresses, ranked by volume
    </div>
    ${i}`}function n0(e,t,n,s,a="inspect-network-map"){let o=document.getElementById(a);if(!o)return;let r=[...Iu(e,t).entries()].sort((S,M)=>M[1].xrpOut+M[1].xrpIn-(S[1].xrpOut+S[1].xrpIn)||M[1].cnt-S[1].cnt).slice(0,20);if(r.length<2){o.style.display="",o.innerHTML=`<div class="inspect-empty-note">${r.length===0?"No counterparty interactions found.":"Only one counterparty found \u2014 not enough to chart a network map."}</div>`;return}o.style.display="";let l=560,c=340,d=l/2,u=c/2,p=95,m=7,f=155,g=13,b=r[0][1].xrpOut+r[0][1].xrpIn||1,h=r[0][1].cnt||1,v=[{id:t,x:d,y:u,r:13,main:!0,label:W(t),color:"#00d4ff",xrpOut:0,xrpIn:0,cnt:0}];r.forEach(([S,M],C)=>{let E=C<m?p:f,R=C<m?m:g,I=(C<m?C:C-m)/R*2*Math.PI-Math.PI/2,D=M.xrpOut+M.xrpIn,F=Math.max(5,Math.min(14,4+D/b*10)),H=M.entity,N=bn[H==null?void 0:H.type]||bn.other,z=D>0?M.xrpOut/D:.5,te=z>.65?"out":z<.35?"in":"both";v.push({id:S,x:d+E*Math.cos(I),y:u+E*Math.sin(I),r:F,color:N,label:(H==null?void 0:H.name)||W(S),ent:H,xrpOut:M.xrpOut,xrpIn:M.xrpIn,cnt:M.cnt,dir:te,vol:D,ring:E})});let w=`<defs>
    <marker id="arrow-out" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
      <path d="M0,0 L6,3 L0,6 Z" fill="rgba(80,250,123,.6)"/>
    </marker>
    <marker id="arrow-in" markerWidth="6" markerHeight="6" refX="1" refY="3" orient="auto-start-reverse">
      <path d="M0,0 L6,3 L0,6 Z" fill="rgba(0,212,255,.6)"/>
    </marker>
    <marker id="arrow-both" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
      <path d="M0,0 L6,3 L0,6 Z" fill="rgba(255,184,108,.6)"/>
    </marker>
    <filter id="glow-red">
      <feGaussianBlur stdDeviation="3" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
  </defs>`,k=v.slice(1).map(S=>{let M=S.vol/b,C=Math.max(.8,M*3),E=.12+M*.45,R=S.dir==="out"?"rgba(80,250,123,":S.dir==="in"?"rgba(0,212,255,":"rgba(255,184,108,",O=S.dir==="out"?`rgba(80,250,123,${E})`:S.dir==="in"?`rgba(0,212,255,${E})`:`rgba(255,184,108,${E})`,I=S.dir==="in"?"5,3":"none",D=`marker-end="url(#arrow-${S.dir})"`,F=S.x-d,H=S.y-u,N=Math.sqrt(F*F+H*H),z=(S.r+2)/N,te=d+F*(1-z),oe=u+H*(1-z),pe=`${S.xrpOut>0?"\u2192 "+_(S.xrpOut,2)+" XRP out":""}${S.xrpIn>0?(S.xrpOut>0?" / ":"")+"\u2190 "+_(S.xrpIn,2)+" XRP in":""}, ${S.cnt} tx`;return`<line x1="${d}" y1="${u}" x2="${te.toFixed(1)}" y2="${oe.toFixed(1)}"
      stroke="${O}" stroke-width="${C.toFixed(1)}" stroke-dasharray="${I}" ${D}>
      <title>${pe}</title></line>`}).join(""),$=v.map(S=>{var H,N;if(S.main){let z=W(S.id);return`<g>
        <title>Inspected account: ${y(S.id)}</title>
        <circle cx="${d}" cy="${u}" r="13" fill="rgba(0,212,255,.2)" stroke="#00d4ff" stroke-width="2"/>
        <circle cx="${d}" cy="${u}" r="13" fill="rgba(0,212,255,.15)"/>
        <text x="${d}" y="${u+4}" text-anchor="middle" font-size="6.5" fill="#00d4ff" font-weight="800">${y(z)}</text>
        <text x="${d}" y="${u+13+10}" text-anchor="middle" font-size="6"
          fill="rgba(255,255,255,.4)">Inspected account</text>
      </g>`}let M=((H=S.ent)==null?void 0:H.type)==="blackhole",C=((N=S.ent)==null?void 0:N.type)==="exchange",E=M?'filter="url(#glow-red)"':"",R=S.dir==="out"?"rgba(80,250,123,.5)":S.dir==="in"?"rgba(0,212,255,.5)":"rgba(255,184,108,.5)",O=1.5,I=S.label.length>14?S.label.slice(0,14)+"\u2026":S.label,D=S.vol>0?S.xrpOut>0&&S.xrpIn>0?`\u21C4 ${_(S.vol,0)} XRP`:S.xrpOut>0?`\u2192 ${_(S.xrpOut,0)} XRP`:`\u2190 ${_(S.xrpIn,0)} XRP`:`${S.cnt} tx`,F=S.id+(S.ent?" ("+S.ent.name+")":"")+" | "+(S.xrpOut>0?"Sent: "+_(S.xrpOut,2)+" XRP"+yn(S.xrpOut)+" | ":"")+(S.xrpIn>0?"Received: "+_(S.xrpIn,2)+" XRP"+yn(S.xrpIn)+" | ":"")+"Interactions: "+S.cnt;return`<g style="cursor:pointer" onclick="inspectorLoadAddr('${S.id}')">
      <title>${F}</title>
      ${M?`<circle cx="${S.x}" cy="${S.y}" r="${S.r+4}" fill="rgba(255,85,85,.1)" stroke="rgba(255,85,85,.4)" stroke-width="1" stroke-dasharray="3,2"/>`:""}
      <circle cx="${S.x}" cy="${S.y}" r="${S.r}" fill="${S.color}" opacity=".18" ${E}/>
      <circle cx="${S.x}" cy="${S.y}" r="${S.r}" fill="${S.color}" opacity=".1" stroke="${R}" stroke-width="${O}"/>
      <text x="${S.x}" y="${S.y+3.5}" text-anchor="middle" font-size="${S.ring===p?7.5:6.5}"
        fill="${S.color}" font-weight="700" opacity=".95">${y(I)}</text>
      <text x="${S.x}" y="${S.y+S.r+10}" text-anchor="middle" font-size="6"
        fill="rgba(255,255,255,.4)">${y(D)}</text>
    </g>`}).join(""),T=`
    <text x="${d}" y="${u-p-8}" text-anchor="middle" font-size="6"
      fill="rgba(255,255,255,.15)" font-style="italic">inner ring</text>
    <text x="${d}" y="${u-f-8}" text-anchor="middle" font-size="6"
      fill="rgba(255,255,255,.10)" font-style="italic">outer ring</text>`;o.innerHTML=`
    <div style="font-size:.65rem;color:rgba(255,255,255,.35);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">
      Counterparty Network Map \u2014 ${r.length} addresses \xB7 click any node to inspect
    </div>
    <div style="overflow-x:auto">
      <svg width="${l}" height="${c}" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${l} ${c}"
        style="display:block;border-radius:10px;background:rgba(255,255,255,.015);border:1px solid rgba(255,255,255,.06);min-width:${Math.min(l,360)}px">
        ${w}${T}${k}${$}
      </svg>
    </div>
    <div style="display:flex;gap:12px;margin-top:8px;flex-wrap:wrap;align-items:center">
      <span style="font-size:.66rem;color:rgba(80,250,123,.8)">\u2192 Outbound</span>
      <span style="font-size:.66rem;color:rgba(0,212,255,.8)">\u2190 Inbound</span>
      <span style="font-size:.66rem;color:rgba(255,184,108,.8)">\u21C4 Both</span>
      <span style="font-size:.66rem;color:rgba(255,255,255,.3)">|</span>
      <span style="font-size:.66rem;color:#00d4ff">\u25CF Exchange</span>
      <span style="font-size:.66rem;color:#ff5555">\u25CF Blackhole</span>
      <span style="font-size:.66rem;color:#ffb86c">\u25CF Issuer</span>
      <span style="font-size:.66rem;color:#8be9fd">\u25CF Other</span>
      <span style="font-size:.66rem;color:rgba(255,255,255,.3)">|</span>
      <span style="font-size:.66rem;color:rgba(255,255,255,.3)">Node size = XRP volume \xB7 Edge thickness = volume</span>
    </div>`}function s0(){let e=window._lastInspectResult,t=window._lastAllFindings||[];if(!e)return null;let n=t.length?t.map(a=>`- [${a.sev.toUpperCase()}] ${a.module}: ${a.headline}${a.detail?" \u2014 "+a.detail:""}`).join(`
`):"(No elevated findings \u2014 all checks returned normal ranges.)",s=e.walletAgeDays!=null?e.walletAgeVerified?" (verified \u2014 full history confirmed)":" (estimated \u2014 full history not confirmed, true age may be older)":"";return`XRPL ACCOUNT FORENSIC ANALYSIS
Account: ${e.addr}
Risk score: ${e.riskScore}/100
Wallet age: ${e.walletAgeDays!=null?e.walletAgeDays+" days":"unknown"}${s}
Transactions analyzed: ${e.txCount}
Snapshot taken: ${e.timestamp}

Automated findings from a rule-based XRPL forensics scan:
${n}

---
You are acting as a security analyst explaining automated blockchain forensics findings to someone who isn't a blockchain expert. Write a clear, plain-English explanation of what this account's activity suggests. Synthesize the findings above into a coherent read of the account rather than restating them one by one \u2014 call out which ones reinforce each other and which are weak signals on their own. Be direct about how concerning (or not) this looks, and be skeptical of your own confidence where the evidence is thin rather than overstating it. Do not repeat the address or risk score back verbatim; the reader can already see those above your response.`}window.copyInspectorAnalysisForAi=function(){let e=document.getElementById("ai-explanation-body"),t=s0();if(!t){e&&(e.innerHTML='<p style="font-size:.82rem;color:#ff5555">Run an inspection first.</p>');return}Hs(t)};window.exportInspectorJSON=function(){var o,i;let e=window._lastInspectResult;if(!e){alert("Run an inspection first.");return}let t=new Blob([JSON.stringify(e,null,2)],{type:"application/json"}),n=URL.createObjectURL(t),s=document.createElement("a"),a=((i=(o=document.getElementById("inspect-addr-badge"))==null?void 0:o.dataset)==null?void 0:i.fullAddr)||"wallet";s.href=n,s.download=`naluxrp_${a.slice(0,10)}_${new Date().toISOString().slice(0,10)}.json`,document.body.appendChild(s),s.click(),document.body.removeChild(s),URL.revokeObjectURL(n)};var a0=6e4,o0=1e4,i0=12e4,r0=8e3,l0=12e4,c0=300,Gu="nalulf_net_baseline_v2",d0=80,p0=5,aa="/api/v1/validatorregistry",Ku="/api/v1/validator";var u0=5*60*1e3,Ju=10*60*1e3,Fu=1e4,Yu=8e3,ar=new Map,or=new Map;var tn={quorumTight:{w:3,label:"Quorum within 3 validators of failure threshold"},nUnlActive:{w:2,label:"Negative UNL active \u2014 validators currently being ignored"},amendVeto:{w:1,label:"Amendment veto clustering \u2014 protocol governance dispute"},feeSpike:{w:2,label:"Open ledger fee 10\xD7 minimum \u2014 DDoS / spam attack likely"},burnAnomaly:{w:2,label:"XRP burn rate z-score > 3\u03C3 \u2014 resource exhaustion pattern"},peerSaturate:{w:2,label:"Inbound peers > 80% of connections \u2014 Eclipse Attack risk"},eclipseRisk:{w:3,label:"Peer count < 6 \u2014 node highly vulnerable to isolation"},dexSpike:{w:1,label:"DEX volume > 3\xD7 AMM baseline \u2014 unusual event-driven flow"},reserveSpike:{w:1,label:"New account rate > 3\xD7 baseline \u2014 possible bot creation"},slowConverge:{w:2,label:"Consensus convergence > 6s \u2014 network agreement degraded"},lowProposers:{w:2,label:"Proposer count below quorum \u2014 validator participation low"},queuePressure:{w:2,label:"TX queue > 80% full \u2014 fee surge imminent"},spamLedger:{w:1,label:"Ledger > 2\xD7 expected size \u2014 ledger spam in progress"},ioStressed:{w:1,label:"Node IO latency > 5ms \u2014 storage or network I/O stress"},peerChurn:{w:1,label:"Elevated peer disconnect rate \u2014 DDoS or instability"},staleLedger:{w:3,label:"Ledger age > 10s \u2014 validation appears stalled"}},Qu={MultiSign:{purpose:"Multi-signature authorization",intro:"rippled 0.31",desc:"Lets multiple keys jointly authorize one transaction. Essential for institutional custody and hardware-wallet setups.",impact:"New transaction: SignerListSet. All signers submit their signature; the last one broadcasts."},MultiSignReserve:{purpose:"Cheaper signer-list reserve",intro:"rippled 1.2",desc:"Cuts the owner reserve for SignerList objects from 5 owner-items (10 XRP) down to 1 owner-item (2 XRP).",impact:"Existing SignerLists do not gain the reduction automatically; delete and re-create the list."},DepositAuth:{purpose:"Block unsolicited incoming payments",intro:"rippled 0.90",desc:"An account can set lsfDepositAuth so it only receives payments explicitly pre-authorized via DepositPreauth.",impact:"Senders to un-authorized accounts receive tecNO_PERMISSION."},DeletableAccounts:{purpose:"Permanent account deletion + reserve reclaim",intro:"rippled 1.4",desc:"An account with no objects and sequence \u2265 (current ledger \u2212 256) can permanently delete itself and recover the base reserve.",impact:"New transaction: AccountDelete. Sends all XRP minus fees to a destination."},NegativeUNL:{purpose:"Fault-tolerant consensus during outages",intro:"rippled 1.6",desc:"When validators are persistently offline, the network may add them to the Negative UNL so they do not count against quorum.",impact:"Enables the network to survive planned outages of up to 20% of trusted validators."},Checks:{purpose:"Deferred, cancellable payments",intro:"rippled 1.0",desc:"The sender creates a Check; the recipient can later cash it up to the authorized amount or let it expire. The sender can cancel at any time.",impact:"New transactions: CheckCreate, CheckCash, CheckCancel. Each open Check uses one owner-reserve slot."},AMM:{purpose:"Native Automated Market Maker DEX",intro:"rippled 1.12",desc:"Adds a Constant-Product (x*y=k) AMM directly in the ledger. Anyone can deposit two assets to earn LP tokens and a share of swap fees.",impact:"New transactions: AMMCreate, AMMDeposit, AMMWithdraw, AMMVote, AMMBid, AMMDelete."},XChainBridge:{purpose:"Cross-chain bridge protocol",intro:"rippled 2.0",desc:"Lets assets move between XRPL Mainnet, sidechains, and EVM chains via a locking/minting bridge secured by Witness servers.",impact:"New ledger objects: Bridge, XChainOwnedCreateAccountClaimID, etc. Requires Witness infrastructure."},Clawback:{purpose:"Token-issuer recovery",intro:"rippled 1.12",desc:"Issuers who set lsfAllowTrustLineClawback before issuing tokens can claw back tokens from any holder.",impact:"Must be enabled on a fresh account before any trust lines are created."},NonFungibleTokensV1:{purpose:"Native NFT support",intro:"rippled 1.9",desc:"Adds NFTokenMint, NFTokenBurn, and offer-based transfer mechanics for non-fungible tokens stored in NFTokenPage objects.",impact:"Each NFTokenPage holds up to 32 tokens and costs one owner-reserve slot. Royalties up to 50%."},NonFungibleTokensV1_1:{purpose:"NFT V1 corrections",intro:"rippled 1.10",desc:"Fixes pagination bugs, transfer-fee edge cases, and minting with the URI field that were present in V1.",impact:"Breaking fix for some V1 edge cases. Wallets built for V1 should test V1_1 compatibility."},PayChan:{purpose:"Payment channels for streaming micropayments",intro:"rippled 0.33",desc:"Sender deposits XRP into a channel, then issues signed claims off-ledger. Recipient submits the highest claim at any time to settle on-ledger.",impact:"New transactions: PaymentChannelCreate, PaymentChannelFund, PaymentChannelClaim."},Escrow:{purpose:"Time-locked and condition-based XRP transfers",intro:"rippled 0.60",desc:"Lock XRP until a future time OR a cryptographic fulfillment (PREIMAGE-SHA-256) is revealed, enabling vesting schedules and atomic swaps.",impact:"New transactions: EscrowCreate, EscrowFinish, EscrowCancel. Locked XRP counts against reserves."},DisallowIncoming:{purpose:"Block unsolicited ledger-object creation",intro:"rippled 1.10",desc:"New account flags let you individually block incoming Trust Lines, Check objects, NFToken offers, and Payment Channels.",impact:"Four new AccountSet flags; existing incoming objects are unaffected."},ExpandedSignerList:{purpose:"Larger multi-sig signer lists",intro:"rippled 1.9.1",desc:"Increases the maximum signers per SignerList from 8 to 32, enabling more complex institutional multi-sig and DAO governance.",impact:"Reserve cost scales with signer count. Requires MultiSignReserve to be cost-effective."},OwnerPaysFee:{purpose:"Correct fee payer in PayChan",intro:"rippled 0.33",desc:"Fixes a spec inconsistency where the channel owner correctly pays the transaction fee when closing or expiring channels.",impact:"Purely a fee-accounting fix; no user-visible behavior changes."},fixMasterKeyAsRegularKey:{purpose:"Master-key mis-use bug fix",intro:"rippled 0.90",desc:"Prevents accounts from setting their master key as their regular key \u2014 an operation that could create an unusable account state.",impact:"No application changes needed; existing accounts are not affected."},TrustSetAuth:{purpose:"Authorized trust lines",intro:"rippled 0.30",desc:"Issuers can require explicit authorization before anyone can hold their token \u2014 a prerequisite for regulatory-grade stablecoins.",impact:"New flow: issuer sends TrustSet with tfSetfAuth to approve each holder."}},Ou=new Set(["xrpscan.com","xrpl.aesthetes.art","xrpkuwait.com","xrpgoat.com","xrp.vet","xrp.unic.ac.cy","xrp-validator.interledger.org","xpmarket.com","verum.eminence.im","validator.xrpl.robertswarthout.com","validator.xrpl-labs.com","validator.poli.usp.br","validator.gatehub.net","validator.aspired.nz","v2.xrpl-commons.org","tequ.dev","squidrouter.com","ripple.ittc.ku.edu","ripple.com","peersyst.cloud","onxrp.com","katczynski.net","jon-nilsen.no","ekiserrepe.es","cabbit.tech","bithomp.com","aureusox.com","arrington-xrp-capital.blockdaemon.com","anodos.finance","bitso.com","ripple.kenan-flagler.unc.edu","ripplevalidator.uwaterloo.ca","shadow.haas.berkeley.edu","www.bitrue.com","xrp-col.anu.edu.au"]),m0=new Set(["nHBu3iuq1SQ9Z686pYwWYVKpScSMDWfpUJHdNEQRxn5XyETui7Db","nHDwBbubxJswoweWQKEgWLNRJv2hNRCTR4GGApJmbtCcbtYNSpdB","nHU2FpRbPrvVcyQQpkqrAUDJDTRHZpjij8DpKeSC481PYY9ikYkb","nHUbmg8QNzEGjHzgnt99e9YE2scU3DZGH7FsF6MCcK5eiPt3AtaH","nHUxBD1UPb383SdWgJx62GGQ7W2WKvgpUtUXLjiGGRRcPb3nbSXd","nHUP6rfQfgzg6tKga3k9ziEvtjwn1PB32gcr5dLcamqzmitszYv2","nHBT58yHyDdPdJ6gzaBMT7gqwTMpj5ERji1s9SvfKKtfoZUS89WX","nHBxsUzx3Bbf6J4yJ3fLQ3VizPtdREVwTJ6mdqkuDTjLcVbggVbk","nHUeUNSn3zce2xQZWNghQvd9WRH6FWEnCBKYVJu2vAizMxnXegfJ","nHUCAdca6VoWWYVdBH1bwCUQggEX2e5acQSqxM3DwyuhsFknxmh3","nHDDiwQBqXhEL1CFoRHdMXD33x9K7rpYJfniXxL7kFavpPd21EGe","nHBipbbREjNEiCs4hpy3K2489dRf27MPnxdivTTWKSd8ZUhfRvn8","nHDDe5uAdiv6RA59MA1oM4JLDtVSYKNShgjEqq1KsdJXZiR47CQT","nHBbiP5ua5dUqCTz5i5vd3ia9jg3KJthohDjgKxnc7LxtmnauW7Z","nHBQ3CT3EWYZ4uzbnL3k6TRf9bBPhWRFVcK1F5NjtwCBksMEt5yy","nHU16DF2kq7TmbR1Y5z8yKNXiLEf3oHT19HVpVXv7unFLfxa17nT","nHUC23NnutZyYeQxQbAbPUpKoVGj5aisBxf2zzcZzJ43fcw5rc9z","nHUgdMvuchx7AWG4ATMQdNNuMryo1SFoNptLCEVt2Dn7wEc625mF","nHUhQVE93dajM3srxubsEj1mK1gzRwJob14QSrJefY1FdLs6r7WJ","nHUU8xBczYzW6kZ6Ei9DsggzTJXRFkN3wE3FP5H4SLYzhbodeYcG","nHUGqooyfGqFkyH6uskbaEi6y2MjXjdA7QdbmyZ6p9etL5isRKLT","nHDp1ZXxEn7eo5YaUtiagaxSLwXudnKZDx68C96p4tdVLGLLLUFn","nHBcLEB4S6moQGrhMjJo1jbp58WL5psHY9EMDWNAtdqykUYiA1rF","nHUAECq1v1cKwn3NsYVyD7v6BNbfqyXmNVSF3e4XCVxPgBHRWkvv","nHUif4sukXu9pJGyyBaeVMwmE8L1fJ5KJj4X4ksgTKhgjG6k96s2","nHUVJR7SeT3nn6JPTz46JHqYRf7vX2if1sdTxnceywmSBWa167pt","nHUEYz4TtTv7yebjhY3aDib5KYPHnKjnY5mPYK5y4QuKdocwS5tD","nHUN5n2S3nQ8bzKm7bqeFMiQeDijh1LMgEocyNyQbb4mREazVdZ5","nHUgchANqM3giYSSvY5HsafFW6qxmG5jJ3CvPiv7n8gjNQuNm8Uz","nHDUqGoM7KR1pgbdYBRgKpGKdFLhpnMzVbECs8RE73RGZm3Va6MJ","nHUVxTi8XfXjaaJppw7mLSrYDRpkDpf8H9ypzgVKxfSXShcWwAoK","nHBveTxA1NaBj5AayRAU91f6YopuFWt9rmxfGaEh77a32Q6ZzzHc"]),f0=new Set(["validator.pftperry.com","rip973.com","preaware.org","postfiat.org","pftmeech.xyz","pft.xbtseal.com","pft.wizbubba.xyz","pft.permanentupperclass.com","pft.g.money","pft.akirax.xyz","jollydinger.com","auri0x.io","app.w.ai"]);function Zu(e,t){let n=(t||"").toLowerCase().replace(/^www\./,"");return m0.has(e)||f0.has(n)?{chain:"test",isUnl:!1}:Ou.has(n)||Ou.has("www."+n)?{chain:"main",isUnl:!0}:{chain:"main",isUnl:!1}}var mr={"xrpscan.com":{label:"XRP Scan",domain:"xrpscan.com",chain:"main",category:"unl"},"xrpl.aesthetes.art":{label:"Aesthetes",domain:"xrpl.aesthetes.art",chain:"main",category:"unl"},"xrpkuwait.com":{label:"XRP Kuwait",domain:"xrpkuwait.com",chain:"main",category:"unl"},"xrpgoat.com":{label:"XRP Goat",domain:"xrpgoat.com",chain:"main",category:"unl"},"xrp.vet":{label:"XRP Vet",domain:"xrp.vet",chain:"main",category:"unl"},"xrp.unic.ac.cy":{label:"Univ. of Nicosia",domain:"xrp.unic.ac.cy",chain:"main",category:"unl"},"xrp-validator.interledger.org":{label:"Interledger",domain:"xrp-validator.interledger.org",chain:"main",category:"unl"},"xpmarket.com":{label:"XPMarket",domain:"xpmarket.com",chain:"main",category:"unl"},"verum.eminence.im":{label:"Eminence",domain:"verum.eminence.im",chain:"main",category:"unl"},"validator.xrpl.robertswarthout.com":{label:"R. Swarthout",domain:"validator.xrpl.robertswarthout.com",chain:"main",category:"unl"},"validator.xrpl-labs.com":{label:"XRPL Labs",domain:"validator.xrpl-labs.com",chain:"main",category:"unl"},"validator.poli.usp.br":{label:"USP",domain:"validator.poli.usp.br",chain:"main",category:"unl"},"validator.gatehub.net":{label:"Gatehub",domain:"validator.gatehub.net",chain:"main",category:"unl"},"validator.aspired.nz":{label:"Aspired NZ",domain:"validator.aspired.nz",chain:"main",category:"unl"},"v2.xrpl-commons.org":{label:"XRPL Commons",domain:"v2.xrpl-commons.org",chain:"main",category:"unl"},"tequ.dev":{label:"Tequ",domain:"tequ.dev",chain:"main",category:"unl"},"squidrouter.com":{label:"Squid Router",domain:"squidrouter.com",chain:"main",category:"unl"},"ripple.ittc.ku.edu":{label:"Univ. of Kansas",domain:"ripple.ittc.ku.edu",chain:"main",category:"unl"},"ripple.com":{label:"Ripple",domain:"ripple.com",chain:"main",category:"unl"},"peersyst.cloud":{label:"Peersyst",domain:"peersyst.cloud",chain:"main",category:"unl"},"onxrp.com":{label:"OnXRP",domain:"onxrp.com",chain:"main",category:"unl"},"katczynski.net":{label:"Katczynski",domain:"katczynski.net",chain:"main",category:"unl"},"jon-nilsen.no":{label:"Jon Nilsen",domain:"jon-nilsen.no",chain:"main",category:"unl"},"ekiserrepe.es":{label:"Ekiserrepe",domain:"ekiserrepe.es",chain:"main",category:"unl"},"cabbit.tech":{label:"Cabbit",domain:"cabbit.tech",chain:"main",category:"unl"},"bithomp.com":{label:"Bithomp",domain:"bithomp.com",chain:"main",category:"unl"},"aureusox.com":{label:"Aureus Ox",domain:"aureusox.com",chain:"main",category:"unl"},"arrington-xrp-capital.blockdaemon.com":{label:"Arrington / Blockdaemon",domain:"arrington-xrp-capital.blockdaemon.com",chain:"main",category:"unl"},"anodos.finance":{label:"Anodos Finance",domain:"anodos.finance",chain:"main",category:"unl"},"bitso.com":{label:"Bitso",domain:"bitso.com",chain:"main",category:"unl"},"ripple.kenan-flagler.unc.edu":{label:"UNC Kenan-Flagler",domain:"ripple.kenan-flagler.unc.edu",chain:"main",category:"unl"},"ripplevalidator.uwaterloo.ca":{label:"Univ. of Waterloo",domain:"ripplevalidator.uwaterloo.ca",chain:"main",category:"unl"},"shadow.haas.berkeley.edu":{label:"UC Berkeley Haas",domain:"shadow.haas.berkeley.edu",chain:"main",category:"unl"},"www.bitrue.com":{label:"Bitrue",domain:"www.bitrue.com",chain:"main",category:"unl"},"xrp-col.anu.edu.au":{label:"ANU",domain:"xrp-col.anu.edu.au",chain:"main",category:"unl"},"xrpval.rawsec.de":{label:"Rawsec",domain:"xrpval.rawsec.de",chain:"main",category:"other"},"xrplvl.carbonvibe.com":{label:"Carbon Vibe",domain:"xrplvl.carbonvibe.com",chain:"main",category:"other"},"xrplvalidator.alloy.ee":{label:"Alloy",domain:"xrplvalidator.alloy.ee",chain:"main",category:"other"},"xrpl.uni.lu":{label:"Univ. of Luxembourg",domain:"xrpl.uni.lu",chain:"main",category:"other"},"xrpl.to":{label:"XRPL.to",domain:"xrpl.to",chain:"main",category:"other"},"xrpl.su":{label:"XRPL.su",domain:"xrpl.su",chain:"main",category:"other"},"xrpl.sbivc.co.jp":{label:"SBI VC Trade",domain:"xrpl.sbivc.co.jp",chain:"main",category:"other"},"xrpl-verification.flare.network":{label:"Flare Network",domain:"xrpl-verification.flare.network",chain:"main",category:"other"},"xrpl-validator.7rev.dev":{label:"7Rev",domain:"xrpl-validator.7rev.dev",chain:"main",category:"other"},"xrp.teacopula.com":{label:"Teacopula",domain:"xrp.teacopula.com",chain:"main",category:"other"},"xrp.moneymindedapes.com":{label:"MoneyMindedApes",domain:"xrp.moneymindedapes.com",chain:"main",category:"other"},"xrp.hazza-systems.de":{label:"Hazza Systems",domain:"xrp.hazza-systems.de",chain:"main",category:"other"},"xrp.cs.uoregon.edu":{label:"Univ. of Oregon",domain:"xrp.cs.uoregon.edu",chain:"main",category:"other"},"xrp.bpsqn.com":{label:"BPSQN",domain:"xrp.bpsqn.com",chain:"main",category:"other"},"xrp-validator.grapedrop.xyz":{label:"Grapedrop",domain:"xrp-validator.grapedrop.xyz",chain:"main",category:"other"},"xaodao.io":{label:"XaoDAO",domain:"xaodao.io",chain:"main",category:"other"},"vl.xrpsalute.com":{label:"XRP Salute",domain:"vl.xrpsalute.com",chain:"main",category:"other"},"validator.xrpl.app":{label:"XRPL App",domain:"validator.xrpl.app",chain:"main",category:"other"},"validator.ukcbt.org":{label:"UKCBT",domain:"validator.ukcbt.org",chain:"main",category:"other"},"validator.sugarxrpl.com":{label:"SugarXRPL",domain:"validator.sugarxrpl.com",chain:"main",category:"other"},"validator.boscaern.digital":{label:"Boscaern",domain:"validator.boscaern.digital",chain:"main",category:"other"},"trimaera.tech":{label:"Trimaera",domain:"trimaera.tech",chain:"main",category:"other"},"textrp.io":{label:"TextRP",domain:"textrp.io",chain:"main",category:"other"},"tesbert.com":{label:"Tesbert",domain:"tesbert.com",chain:"main",category:"other"},"tachyon-xrpl-validator.github.io":{label:"Tachyon",domain:"tachyon-xrpl-validator.github.io",chain:"main",category:"other"},"solonation.io":{label:"SoloNation",domain:"solonation.io",chain:"main",category:"other"},"smokydrip.com":{label:"SmokyDrip",domain:"smokydrip.com",chain:"main",category:"other"},"rippled-validator.us":{label:"rippled-validator.us",domain:"rippled-validator.us",chain:"main",category:"other"},"rippleat.snt.uni.lu":{label:"Univ. Luxembourg (SNT)",domain:"rippleat.snt.uni.lu",chain:"main",category:"other"},"ripple.uni.lu":{label:"Univ. Luxembourg",domain:"ripple.uni.lu",chain:"main",category:"other"},"ripple.j2b.com":{label:"J2B",domain:"ripple.j2b.com",chain:"main",category:"other"},"rich-list.info":{label:"Rich List",domain:"rich-list.info",chain:"main",category:"other"},"proptoexchange.com":{label:"ProPtoExchange",domain:"proptoexchange.com",chain:"main",category:"other"},"printscierge.com":{label:"Printscierge",domain:"printscierge.com",chain:"main",category:"other"},"opulencex.io":{label:"OpulenceX",domain:"opulencex.io",chain:"main",category:"other"},"onledger.net":{label:"OnLedger",domain:"onledger.net",chain:"main",category:"other"},"oclost.art":{label:"Oclost",domain:"oclost.art",chain:"main",category:"other"},"managednetwork.us":{label:"ManagedNetwork",domain:"managednetwork.us",chain:"main",category:"other"},"joshuahamsa.com":{label:"Joshua Hamsa",domain:"joshuahamsa.com",chain:"main",category:"other"},"grimmsxrpflow.jwscott.net":{label:"Grimm XRP Flow",domain:"grimmsxrpflow.jwscott.net",chain:"main",category:"other"},"getlol.xyz":{label:"GetLol",domain:"getlol.xyz",chain:"main",category:"other"},"gen3labs.xyz":{label:"Gen3 Labs",domain:"gen3labs.xyz",chain:"main",category:"other"},"garveyvalid.com":{label:"Garvey",domain:"garveyvalid.com",chain:"main",category:"other"},"easynpl.kr":{label:"EasyNPL",domain:"easynpl.kr",chain:"main",category:"other"},"diseb.ewi.tudelft.nl":{label:"TU Delft",domain:"diseb.ewi.tudelft.nl",chain:"main",category:"other"},"datamossa.com":{label:"DataMossa",domain:"datamossa.com",chain:"main",category:"other"},"crypto.unibe.ch":{label:"Univ. of Bern",domain:"crypto.unibe.ch",chain:"main",category:"other"},"commonprefix.com":{label:"Common Prefix",domain:"commonprefix.com",chain:"main",category:"other"},"catalyze-research.com":{label:"Catalyze Research",domain:"catalyze-research.com",chain:"main",category:"other"},"catalog.org":{label:"Catalog",domain:"catalog.org",chain:"main",category:"other"},"blockchain.korea.ac.kr":{label:"Korea Univ.",domain:"blockchain.korea.ac.kr",chain:"main",category:"other"},"astatiumprotocol.com":{label:"Astatium Protocol",domain:"astatiumprotocol.com",chain:"main",category:"other"},"ladykxrpl.mywire.org":{label:"LadyK XRPL",domain:"LadyKXRPL.mywire.org",chain:"main",category:"other"},"eelap-p1201-xrp.abudhabi.nyu.edu":{label:"NYU Abu Dhabi",domain:"EELAP-P1201-XRP.ABUDHABI.NYU.EDU",chain:"main",category:"other"},"589.clouds.hspeed.ch":{label:"HSpeed",domain:"589.clouds.hspeed.ch",chain:"main",category:"other"},"validator.pftperry.com":{label:"PFT Perry",domain:"validator.pftperry.com",chain:"test",category:"other"},"rip973.com":{label:"rip973",domain:"rip973.com",chain:"test",category:"other"},"preaware.org":{label:"Preaware",domain:"preaware.org",chain:"test",category:"other"},"postfiat.org":{label:"PostFiat",domain:"postfiat.org",chain:"test",category:"other"},"pftmeech.xyz":{label:"PFT Meech",domain:"pftmeech.xyz",chain:"test",category:"other"},"pft.xbtseal.com":{label:"PFT XBT Seal",domain:"pft.xbtseal.com",chain:"test",category:"other"},"pft.wizbubba.xyz":{label:"PFT Wizbubba",domain:"pft.wizbubba.xyz",chain:"test",category:"other"},"pft.permanentupperclass.com":{label:"PFT Perm Upper Class",domain:"pft.permanentupperclass.com",chain:"test",category:"other"},"pft.g.money":{label:"PFT G.Money",domain:"pft.g.money",chain:"test",category:"other"},"pft.akirax.xyz":{label:"PFT Akirax",domain:"pft.akirax.xyz",chain:"test",category:"other"},"jollydinger.com":{label:"Jollydinger",domain:"jollydinger.com",chain:"test",category:"other"},"auri0x.io":{label:"Auri0x",domain:"auri0x.io",chain:"test",category:"other"},"app.w.ai":{label:"W.ai",domain:"app.w.ai",chain:"test",category:"other"}},po={nHB8QMKGt9VB4Vg71VszjBVQnDW3v3QudM4436zXRZgiuUBBSWJe:{lat:37.77,lng:-122.42,city:"San Francisco",org:"Ripple"},nHUon2tpyJEHHYGmxqNd3h3oGNQwNyX8PNS3aHe3bNpCrNXZlHo:{lat:37.77,lng:-122.41,city:"San Francisco",org:"Ripple"},nHUpwrafS45zmi6eT72XS5ijpkW5JwfL5mLdPhEibrqUvtRcMAjU:{lat:37.78,lng:-122.4,city:"San Francisco",org:"Ripple"},nHUkp7WhouVMobBUKGrV5FNqjsdD9zKP5jpGnnLfQXCMNe4dkDqo:{lat:37.76,lng:-122.43,city:"San Francisco",org:"Ripple"},nHUryiyDqEtyWVtFG24AAhaYjMf9FRLietZGBWYwUTojmugMsx3o:{lat:37.79,lng:-122.38,city:"San Francisco",org:"Ripple"},nHUpcmNsxAw47yt2ADDoNoQrzLyTJPgnyq16u6Qx2kRPA17oUNHz:{lat:37.8,lng:-122.39,city:"San Francisco",org:"Ripple"},nHUnhRJK3csknycNK5SXRFi8jvDp3sKoWvS9wKWLq1ATBBGgPBjp:{lat:37.75,lng:-122.44,city:"San Francisco",org:"Ripple"},nHUq9tJvk5QTDkwurB7EzbzkZ2uuoHjS3GKjP6pZiU3DJGnobNYK:{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"AWS (Coil)"},nHUvcCcmoH1FJMMC6NtF9KKA4LpCWhjsxk2reCQidsp5AHQ7QY9H:{lat:49.45,lng:11.08,city:"Nuremberg",org:"Hetzner (Gatehub)"},nHDH7bQJpVfDhVSqdui3Z8GPvKEBQpo6AKHcnXe21zoD4nABA6xj:{lat:52.37,lng:4.9,city:"Amsterdam",org:"GCP (XRPL Labs)"},nHUED59jjpQ5QbNtesAbB6Es3uUPv3c9Ri5MNNgfMv5t5Lhb5ndW:{lat:19.43,lng:-99.13,city:"Mexico City",org:"AWS (Bitso)"},nHBidG3pZK11zqjeVos6hFxTDPGYuqfRFZ5gu9b7tQFdB8nPZujG:{lat:35.69,lng:139.69,city:"Tokyo",org:"NTT (Digital Garage)"},nHDB2PAPYqF86j9j3c6w1F1ZqwvQfiWcFShZ9Pokg9q4ohNDSkAz:{lat:47.61,lng:-122.33,city:"Seattle, WA",org:"Azure (Arrington)"},nHUdphn3LXa31w5sLd39MQdPEKQNrNYL3DQFByijVXiNQ3G6BYBZ:{lat:1.35,lng:103.82,city:"Singapore",org:"AWS (Tokenize)"},nHUFCyRCrUjvtZmKiLeF8ReopzKuSkVzdl1VsMCqm75aqyohLYEg:{lat:48.86,lng:2.35,city:"Paris",org:"OVH (XRPL Commons)"},nHULqGBkJtWeNFjhTzYeAsHA3qKKS7HoBh8CV3BAGTGMZuepEhWC:{lat:40.71,lng:-74.01,city:"New York",org:"Equinix (Blockchain LLC)"},nHBdXSF6YHAHSZUk7rvox6jwbvvyqBnsWGcewBtq8x1XuH6KXKXr:{lat:37.79,lng:-122.4,city:"San Francisco",org:"Cloudflare (XRP Scan)"}},Bu={"xrpscan.com":{lat:51.51,lng:-.13,city:"London",org:"XRPScan"},"xrpl.aesthetes.art":{lat:52.37,lng:4.9,city:"Amsterdam",org:"Aesthetes"},"xrpkuwait.com":{lat:29.37,lng:47.98,city:"Kuwait City",org:"XRP Kuwait"},"xrpgoat.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"XRP Goat"},"xrp.vet":{lat:48.86,lng:2.35,city:"Paris",org:"XRP Vet"},"xrp.unic.ac.cy":{lat:35.17,lng:33.37,city:"Nicosia",org:"Univ. of Nicosia"},"xrp-validator.interledger.org":{lat:40.71,lng:-74.01,city:"New York",org:"Interledger Foundation"},"xpmarket.com":{lat:52.37,lng:4.9,city:"Amsterdam",org:"XPMarket"},"verum.eminence.im":{lat:51.51,lng:-.13,city:"London",org:"Eminence"},"validator.xrpl.robertswarthout.com":{lat:52.37,lng:4.9,city:"Amsterdam",org:"R. Swarthout"},"validator.xrpl-labs.com":{lat:52.37,lng:4.9,city:"Amsterdam",org:"XRPL Labs"},"validator.xrpl.app":{lat:52.37,lng:4.9,city:"Amsterdam",org:"XRPL App"},"validator.poli.usp.br":{lat:-23.55,lng:-46.63,city:"S\xE3o Paulo",org:"USP"},"validator.gatehub.net":{lat:46.05,lng:14.51,city:"Ljubljana",org:"Gatehub"},"validator.aspired.nz":{lat:-36.86,lng:174.76,city:"Auckland",org:"Aspired NZ"},"v2.xrpl-commons.org":{lat:48.86,lng:2.35,city:"Paris",org:"XRPL Commons"},"tequ.dev":{lat:60.17,lng:24.94,city:"Helsinki",org:"Tequ"},"squidrouter.com":{lat:37.77,lng:-122.42,city:"San Francisco",org:"Squid Router"},"ripple.ittc.ku.edu":{lat:38.97,lng:-95.24,city:"Lawrence, KS",org:"Univ. of Kansas"},"ripple.com":{lat:37.77,lng:-122.42,city:"San Francisco",org:"Ripple"},"peersyst.cloud":{lat:41.39,lng:2.15,city:"Barcelona",org:"Peersyst"},"onxrp.com":{lat:51.51,lng:-.13,city:"London",org:"OnXRP"},"katczynski.net":{lat:52.23,lng:21.01,city:"Warsaw",org:"Katczynski"},"jon-nilsen.no":{lat:59.91,lng:10.75,city:"Oslo",org:"Jon Nilsen"},"ekiserrepe.es":{lat:40.42,lng:-3.7,city:"Madrid",org:"Ekiserrepe"},"cabbit.tech":{lat:51.51,lng:-.13,city:"London",org:"Cabbit"},"bithomp.com":{lat:59.33,lng:18.07,city:"Stockholm",org:"Bithomp"},"aureusox.com":{lat:40.71,lng:-74.01,city:"New York",org:"Aureus Ox"},"arrington-xrp-capital.blockdaemon.com":{lat:40.71,lng:-74.01,city:"New York",org:"Blockdaemon"},"anodos.finance":{lat:37.98,lng:23.73,city:"Athens",org:"Anodos Finance"},"bitso.com":{lat:19.43,lng:-99.13,city:"Mexico City",org:"Bitso"},"ripple.kenan-flagler.unc.edu":{lat:35.9,lng:-79.05,city:"Chapel Hill, NC",org:"UNC Kenan-Flagler"},"ripplevalidator.uwaterloo.ca":{lat:43.47,lng:-80.54,city:"Waterloo, ON",org:"Univ. of Waterloo"},"shadow.haas.berkeley.edu":{lat:37.87,lng:-122.26,city:"Berkeley, CA",org:"UC Berkeley Haas"},"www.bitrue.com":{lat:1.35,lng:103.82,city:"Singapore",org:"Bitrue"},"xrp-col.anu.edu.au":{lat:-35.28,lng:149.13,city:"Canberra",org:"ANU"},"xrpval.rawsec.de":{lat:51.17,lng:10.45,city:"Germany",org:"Rawsec"},"xrplvl.carbonvibe.com":{lat:51.51,lng:-.13,city:"London",org:"Carbon Vibe"},"xrplvalidator.alloy.ee":{lat:59.44,lng:24.75,city:"Tallinn",org:"Alloy"},"xrpl.uni.lu":{lat:49.61,lng:6.13,city:"Luxembourg",org:"Univ. of Luxembourg"},"xrpl.to":{lat:48.86,lng:2.35,city:"Paris",org:"XRPL.to"},"xrpl.su":{lat:55.75,lng:37.62,city:"Moscow",org:"XRPL.su"},"xrpl.sbivc.co.jp":{lat:35.69,lng:139.69,city:"Tokyo",org:"SBI VC Trade"},"xrpl-verification.flare.network":{lat:51.51,lng:-.13,city:"London",org:"Flare Network"},"xrpl-validator.7rev.dev":{lat:52.52,lng:13.4,city:"Berlin",org:"7Rev"},"xrp.teacopula.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"Teacopula"},"xrp.moneymindedapes.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"MoneyMindedApes"},"xrp.hazza-systems.de":{lat:52.52,lng:13.4,city:"Berlin",org:"Hazza Systems"},"xrp.cs.uoregon.edu":{lat:44.05,lng:-123.08,city:"Eugene, OR",org:"Univ. of Oregon"},"xrp.bpsqn.com":{lat:37.77,lng:-122.42,city:"San Francisco",org:"BPSQN"},"xrp-validator.grapedrop.xyz":{lat:52.37,lng:4.9,city:"Amsterdam",org:"Grapedrop"},"xaodao.io":{lat:1.35,lng:103.82,city:"Singapore",org:"XaoDAO"},"vl.xrpsalute.com":{lat:40.71,lng:-74.01,city:"New York",org:"XRP Salute"},"validator.ukcbt.org":{lat:51.51,lng:-.13,city:"London",org:"UKCBT"},"validator.sugarxrpl.com":{lat:37.77,lng:-122.42,city:"San Francisco",org:"SugarXRPL"},"validator.boscaern.digital":{lat:53.33,lng:-6.25,city:"Dublin",org:"Boscaern"},"trimaera.tech":{lat:48.86,lng:2.35,city:"Paris",org:"Trimaera"},"textrp.io":{lat:1.35,lng:103.82,city:"Singapore",org:"TextRP"},"tesbert.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"Tesbert"},"tachyon-xrpl-validator.github.io":{lat:37.77,lng:-122.42,city:"San Francisco",org:"Tachyon"},"solonation.io":{lat:1.35,lng:103.82,city:"Singapore",org:"SoloNation"},"smokydrip.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"SmokyDrip"},"rippled-validator.us":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"rippled-validator.us"},"rippleat.snt.uni.lu":{lat:49.61,lng:6.13,city:"Luxembourg",org:"Univ. of Luxembourg"},"ripple.uni.lu":{lat:49.61,lng:6.13,city:"Luxembourg",org:"Univ. of Luxembourg"},"ripple.j2b.com":{lat:37.77,lng:-122.42,city:"San Francisco",org:"J2B"},"rich-list.info":{lat:51.51,lng:-.13,city:"London",org:"Rich List"},"proptoexchange.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"ProPtoExchange"},"printscierge.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"Printscierge"},"opulencex.io":{lat:1.35,lng:103.82,city:"Singapore",org:"OpulenceX"},"onledger.net":{lat:52.37,lng:4.9,city:"Amsterdam",org:"OnLedger"},"oclost.art":{lat:48.86,lng:2.35,city:"Paris",org:"Oclost"},"managednetwork.us":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"ManagedNetwork"},"joshuahamsa.com":{lat:37.77,lng:-122.42,city:"San Francisco",org:"Joshua Hamsa"},"grimmsxrpflow.jwscott.net":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"Grimm XRP Flow"},"getlol.xyz":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"GetLol"},"gen3labs.xyz":{lat:37.77,lng:-122.42,city:"San Francisco",org:"Gen3 Labs"},"garveyvalid.com":{lat:40.71,lng:-74.01,city:"New York",org:"Garvey"},"easynpl.kr":{lat:37.57,lng:126.98,city:"Seoul",org:"EasyNPL"},"diseb.ewi.tudelft.nl":{lat:52,lng:4.36,city:"Delft",org:"TU Delft"},"datamossa.com":{lat:48.86,lng:2.35,city:"Paris",org:"DataMossa"},"crypto.unibe.ch":{lat:46.95,lng:7.45,city:"Bern",org:"Univ. of Bern"},"commonprefix.com":{lat:37.98,lng:23.73,city:"Athens",org:"Common Prefix"},"catalyze-research.com":{lat:51.51,lng:-.13,city:"London",org:"Catalyze Research"},"catalog.org":{lat:37.77,lng:-122.42,city:"San Francisco",org:"Catalog"},"blockchain.korea.ac.kr":{lat:37.57,lng:126.98,city:"Seoul",org:"Korea Univ."},"astatiumprotocol.com":{lat:1.35,lng:103.82,city:"Singapore",org:"Astatium Protocol"},"ladykxrpl.mywire.org":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"LadyK XRPL"},"eelap-p1201-xrp.abudhabi.nyu.edu":{lat:24.47,lng:54.37,city:"Abu Dhabi",org:"NYU Abu Dhabi"},"589.clouds.hspeed.ch":{lat:47.38,lng:8.54,city:"Zurich",org:"HSpeed"},"www.payonline.financial":{lat:55.75,lng:37.62,city:"Moscow",org:"PayOnline"}};function fr(e){if(!e)return null;let t=e.toLowerCase().replace(/^www\./,"");return Bu[t]??Bu["www."+t]??null}var h0=[{lat:37.34,lng:-121.89,label:"s1.ripple.com",city:"San Jose, CA",org:"Ripple"},{lat:37.34,lng:-121.87,label:"s2.ripple.com",city:"San Jose, CA",org:"Ripple"},{lat:52.37,lng:4.91,label:"xrplcluster.com",city:"Amsterdam",org:"Cluster"},{lat:52.36,lng:4.89,label:"xrpl.ws",city:"Amsterdam",org:"Cluster"}],Ie={nunl:{hex:"#ff5555",glow:"rgba(255,85,85,.4)",label:"Negative UNL"},both:{hex:"#50fa7b",glow:"rgba(80,250,123,.4)",label:"UNL + dUNL"},unl:{hex:"#00fff0",glow:"rgba(0,255,240,.35)",label:"UNL"},dunl:{hex:"#bd93f9",glow:"rgba(189,147,249,.4)",label:"dUNL only"},other:{hex:"#ffb86c",glow:"rgba(255,184,108,.4)",label:"Other"},pub:{hex:"#50fa7b",glow:"rgba(80,250,123,.4)",label:"Public Node"}},ir="https://api.xrpscan.com/api/v1/validatorregistry",$e=new Map,wn={},lo=0,jn=!1,xn="fallback";function em(){if(!jn){$e.clear();for(let[e,t]of Object.entries(mr)){let n=t.domain??e,s=Zu("",n),a=fr(n)??null;$e.set(e,{key:e,label:t.label,domain:n,domainVerified:!1,provider:t.provider??(a==null?void 0:a.org)??null,lists:t.lists??[],category:s.isUnl?"unl":"other",chain:s.chain,unl:s.isUnl,dunl:!1,geo:a,meta:{},agreement:{"1h":null,"24h":null,"30d":null}})}xn="fallback",hr({ok:!1,source:"fallback",error:"using hardcoded data \u2014 mount /api/v1 router"})}}var rr=0,g0=5*60*1e3;function Xu(e,t){var s,a;let n=Array.isArray(e)?e:e.validators??e.data??[];if(!n.length)throw new Error("Empty validators array");$e.clear();for(let o of n){let i=o.key??o.validation_public_key??o.master_key??o.signing_key??null;if(!i)continue;let r=o.domain??null,l=r?r.toLowerCase().replace(/^www\./,""):null,c=o.unl===!0||o.unl===1||o.unl==="true",d=Zu(i,l),u=c||d.isUnl,p=d.chain,m=u?"unl":"other",f=Object.values(mr).find(w=>w.domain&&w.domain.toLowerCase().replace(/^www\./,"")===l),g=(f==null?void 0:f.label)??o.label??o.account_name??o.name??l??null??`${i.slice(0,8)}\u2026${i.slice(-6)}`,b=po[i]??fr(l)??null,v=(((s=o.geo)==null?void 0:s.lat)!=null&&((a=o.geo)==null?void 0:a.lng)!=null?o.geo:null)??b;$e.set(i,{key:i,label:g,domain:r??null,domainVerified:!!(o.domainVerified??o.domain_verified),provider:o.provider??(v==null?void 0:v.org)??(f==null?void 0:f.provider)??null,lists:Array.isArray(o.lists)?o.lists:[],category:m,chain:p,unl:u,dunl:!1,geo:v,version:o.version??o.build_version??null,baseFee:o.base_fee_xrp??o.base_fee??null,ownerReserve:o.reserve_inc_xrp??o.owner_reserve??null,meta:o.meta??{},agreement:o.agreement??{"1h":tr(o.agreement_1h??o.agr_1h),"24h":tr(o.agreement_24h??o.agr_24h),"30d":tr(o.agreement_30d??o.agr_30d)}})}wn=e.lists??{},lo=Date.now(),jn=!0,xn=t,rr=0,hr({ok:!0,count:$e.size,lists:wn,source:t})}function tr(e){if(!e)return null;let t=Number(e.total??e.ledgers??0),n=Number(e.missed??0),s=t-n,a=t>0?(s/t*100).toFixed(1):null;return{total:t,missed:n,hit:s,score:a?`${a}%`:null,scoreRaw:e.score??null}}async function ro(e=!1){let t=Date.now();if(!e&&jn&&t-lo<u0)return!0;if(!e&&!jn&&t-rr<g0)return!1;let n=typeof aa=="string"&&aa.startsWith("/api/"),s=location.protocol==="file:"||location.hostname==="127.0.0.1"||location.hostname==="localhost";if(!(n&&s))try{let a=new AbortController,o=setTimeout(()=>a.abort(),Fu),i=await fetch(aa,{signal:a.signal,headers:{Accept:"application/json"}});if(clearTimeout(o),!i.ok)throw new Error(`HTTP ${i.status}`);let r=await i.json();return Xu(r,"proxy"),!0}catch(a){console.warn("[registry] tier 1 (proxy) failed:",a.message)}try{let a=new AbortController,o=setTimeout(()=>a.abort(),Fu),i=await fetch(ir,{signal:a.signal});if(clearTimeout(o),!i.ok)throw new Error(`HTTP ${i.status}`);let r=await i.text(),l=JSON.parse(r);return Xu(l,"xrpscan"),!0}catch(a){console.warn("[registry] tier 2 (xrpscan direct) failed:",a.message),(a.message.includes("Failed to fetch")||a.message.includes("CORS"))&&console.warn("[registry] CORS blocked \u2014 mount the backend proxy route (see validatorregistry.js)")}return console.warn("[registry] all sources failed \u2014 showing",Object.keys(mr).length,"hardcoded validators"),rr=Date.now(),jn||em(),hr({ok:!1,source:"fallback",error:"all sources failed \u2014 mount /api/v1 router"}),!1}window.debugRegistry=async function(){console.group("\u{1F50D} Registry debug"),console.log("Current source:",xn),console.log("Validators loaded:",$e.size),console.log("Registry ok:",jn),console.log("Last fetch:",lo?new Date(lo).toLocaleTimeString():"never"),console.log(""),console.log("Testing proxy \u2192",aa);try{let e=await fetch(aa),t=await e.text();console.log("  Status:",e.status,"\u2014 body preview:",t.slice(0,300))}catch(e){console.warn("  Failed:",e.message)}console.log(""),console.log("Testing XRPScan direct \u2192",ir);try{let e=await fetch(ir),t=await e.text();console.log("  Status:",e.status,"\u2014 body preview:",t.slice(0,300))}catch(e){console.warn("  Failed:",e.message)}return console.groupEnd(),{source:xn,size:$e.size,ok:jn}};function ot(e){return $e.get(e)??{key:e,label:`${e.slice(0,10)}\u2026${e.slice(-6)}`,domain:null,provider:null,lists:[],category:"other",geo:po[e]??null,meta:{}}}function kn(e){var n;if(!e)return null;if(((n=e.geo)==null?void 0:n.lat)!=null)return e.geo;let t=po[e.key];return t||fr(e.domain)}function tm(){return[...$e.values()].filter(e=>(e.category==="unl"||e.category==="both")&&e.chain!=="test").map(e=>e.key)}function v0(){return[...$e.values()].filter(e=>(e.category==="dunl"||e.category==="both")&&e.chain!=="test").map(e=>e.key)}function b0(){return[...$e.values()].filter(e=>e.category==="other"&&e.chain!=="test").map(e=>e.key)}function y0(){return[...$e.values()].filter(e=>e.chain==="test").map(e=>e.key)}function hr({ok:e,count:t,lists:n,source:s,error:a}){let o=x("m1-registry-badge");if(o)if(e){let i=[...$e.values()].filter(c=>c.category==="unl").length,r=[...$e.values()].filter(c=>c.chain==="test").length,l=t-r;o.textContent=`${l} mainnet \xB7 ${i} UNL \xB7 ${r} testnet \xB7 live`,o.className="registry-badge registry-badge--ok"}else o.textContent=s==="fallback"?`Fallback data \xB7 ${$e.size} known \xB7 ${a??"endpoint unreachable"}`:"Refreshing\u2026",o.className="registry-badge registry-badge--warn"}var co=null,Hu=!1,nr=!1,zu=0,Wu=0,Uu=0,sr=0,nm=!0,et=null,Un=null,ra=null,zt=null,He={},oo=null,lr={},Ze=null,en=[],io=null,cr={},na="unl",mt={fees:[],burnDrops:[],dexOffers:[],ammSwaps:[],newAccounts:[],converge:[],proposers:[],peerCounts:[],peerDiscon:[]};function sm(){var t,n;if(Hu)return;Hu=!0,q0(),em(),ro(!0),W0(),U0(),window.addEventListener("xrpl-connected",()=>{sa(),$s()&&(oa({force:!0}),ia({force:!1}))}),window.addEventListener("xrpl-disconnected",()=>{dr(),ur(null)}),window.addEventListener("xrpl-connection",s=>{var a;((a=s==null?void 0:s.detail)==null?void 0:a.state)==="connecting"&&(dr(),ur(null,"Switching networks\u2026"))}),window.addEventListener("xrpl-ledger",s=>{X0(s.detail),$s()&&H0(s.detail)}),(t=x("btn-network-refresh"))==null||t.addEventListener("click",()=>{oa({force:!0}),ro(!0),ia({force:!0})}),(n=document.querySelector('.dash-tab[data-tab="network"]'))==null||n.addEventListener("click",()=>{sa(),oa({force:!0}),ro(!1),ia({force:!1})});let e=x("tab-network");e&&new MutationObserver(sa).observe(e,{attributes:!0,attributeFilter:["style","class"]}),document.addEventListener("visibilitychange",sa)}function $s(){let e=x("tab-network"),t=e?e.style.display!=="none":!1;return nm&&B.currentPage==="dashboard"&&B.currentTab==="network"&&t&&!document.hidden}function sa(){$s()?w0():dr()}function am(e){nm=!!e,sa()}function w0(){co||(oa({force:!1}),co=setInterval(()=>{$s()&&oa({force:!1})},a0))}function dr(){clearInterval(co),co=null}async function oa({force:e=!1}={}){var n;if(!$s()&&!e)return;let t=Date.now();if(!(!e&&(t-zu<o0||nr||t<Wu))){nr=!0,zu=t,He={},ju(!0);try{await Promise.allSettled([ro(!1),x0(),k0(),$0(),S0(),T0()]),C0(),A0(),E0(),N0(),O0(),ur({info:et,fee:Un,vals:ra}),V0()}catch(s){String((s==null?void 0:s.message)??"").toLowerCase().includes("too much load")&&(Wu=Date.now()+i0,(n=ge)==null||n("Rate-limited \u2014 backing off 2 min."))}finally{ju(!1),nr=!1}}}function ju(e){var t;(t=x("btn-network-refresh"))==null||t.classList.toggle("spinning",e)}async function x0(){var n,s,a;let e=await Me({command:"server_info"});if(et=((n=e==null?void 0:e.result)==null?void 0:n.info)??null,!et)return;at("converge",Number(((s=et.last_close)==null?void 0:s.converge_time_s)??0)),at("proposers",Number(((a=et.last_close)==null?void 0:a.proposers)??0)),at("peerCounts",Number(et.peers??0));let t=Number(et.peer_disconnects_resources??0);oo!==null&&t>oo&&at("peerDiscon",t-oo),oo=t}async function k0(){var t;let e=await Me({command:"fee"});Un=(e==null?void 0:e.result)??null,((t=Un==null?void 0:Un.drops)==null?void 0:t.open_ledger_fee)!=null&&at("fees",Number(Un.drops.open_ledger_fee))}async function $0(){try{let e=await Me({command:"validators"});ra=(e==null?void 0:e.result)??null}catch{ra=null}}async function S0(){var e;try{let t=await Me({command:"peers"});zt=Array.isArray((e=t==null?void 0:t.result)==null?void 0:e.peers)?t.result.peers:null}catch{zt=null}}async function T0(){var e;try{let t=await Me({command:"feature"});(e=t==null?void 0:t.result)!=null&&e.features&&(R0(t.result.features),im(t.result.features))}catch{}}function C0(){var C,E,R,O,I,D;let e=et,t=ra,n=(t==null?void 0:t.trusted_validator_keys)??[],s=tm(),a=v0(),o=n.length?n:s,i=a,r=Number((t==null?void 0:t.validation_quorum)??(e==null?void 0:e.validation_quorum)??0),l=o.length,c=l-r,d=l>0?r/l*100:0,u=o.filter(F=>$e.has(F)).length,p=l>0?Math.round(u/l*100):0,m=Number(((C=e==null?void 0:e.last_close)==null?void 0:C.converge_time_s)??0),f=Number(((E=e==null?void 0:e.last_close)==null?void 0:E.proposers)??0),g=r>0?Math.round(f/r*100):0,b=Array.isArray(e==null?void 0:e.negative_unl)?e.negative_unl:[],h=!!ra;c>=0&&c<=3&&(He.quorumTight=!0),b.length>0&&(He.nUnlActive=!0),m>6&&(He.slowConverge=!0),f>0&&r>0&&f<r&&(He.lowProposers=!0),J("m1-active",h?l:"\u2014"),J("m1-quorum",r>0?r:"\u2014"),J("m1-margin",h?c>=0?c:`\u2212${Math.abs(c)}`:"\u2014"),J("m1-overlap",h?`${p}%`:"\u2014"),J("m1-known",h?`${u} / ${l} identified`:"\u2014 (validators cmd unavailable)"),J("m1-proposers",((R=e==null?void 0:e.last_close)==null?void 0:R.proposers)!=null?f:"\u2014"),J("m1-particip",r>0&&((O=e==null?void 0:e.last_close)==null?void 0:O.proposers)!=null?`${g}%`:"\u2014"),J("m1-converge",((I=e==null?void 0:e.last_close)==null?void 0:I.converge_time_s)!=null?`${m.toFixed(2)}s`:"\u2014"),J("m1-converge-avg",la("converge")>0?`avg ${la("converge").toFixed(2)}s`:"\u2014"),Tt("m1-qbar",d,d>90?"bar-danger":d>80?"bar-warn":"bar-ok"),Tt("m1-obar",p,p<40?"bar-danger":p<70?"bar-warn":"bar-ok"),Tt("m1-pbar",g,g<80?"bar-danger":g<95?"bar-warn":"bar-ok"),Tt("m1-cvgbar",Math.min(100,m/10*100),m>6?"bar-danger":m>4?"bar-warn":"bar-ok"),M0({active:l,quorum:r,margin:c,nUnl:b,valsAvail:h});let v=(D=t==null?void 0:t.publisher_lists)==null?void 0:D[0],w=(wn==null?void 0:wn.ripple)??(wn==null?void 0:wn.xrplf)??null,k=(v==null?void 0:v.uri)??(w==null?void 0:w.uri)??"\u2014",$=(v==null?void 0:v.seq)??(w==null?void 0:w.seq)??"\u2014";if(J("m1-vl-uri",k),J("m1-vl-seq",$),v!=null&&v.expiration||w!=null&&w.expiration){let F=x("m1-vl-expiry");if(F){let H=(v==null?void 0:v.expiration)??(w==null?void 0:w.expiration),N=Math.floor((new Date(H)-Date.now())/864e5);F.textContent=N>0?`Expires ${N}d`:"\u26A0 EXPIRED",F.className=`expiry-pill ${N>30?"pill-ok":N>7?"pill-warn":"pill-bad"}`,F.style.display=""}}let T=x("m1-nunl-list");if(J("m1-nunl-count",b.length||"0"),T)if(!b.length)T.innerHTML='<div class="nunl-empty">\u2713 No validators on Negative UNL</div>';else{let F={};T.innerHTML=b.map(N=>{let z=ot(N);return z.provider&&(F[z.provider]=(F[z.provider]||0)+1),`<div class="nunl-entry">
          <span class="nunl-dot"></span>
          <div class="nunl-info">
            <span class="nunl-label">${y(z.label)}</span>
            ${z.domain?`<span class="nunl-prov">${y(z.domain)}</span>`:""}
          </div>
          <span class="nunl-key" onclick="navigator.clipboard?.writeText('${y(N)}')">${N.slice(0,8)}...</span>
        </div>`}).join("");let H=Object.entries(F).sort((N,z)=>z[1]-N[1])[0];(H==null?void 0:H[1])>1&&(T.innerHTML+=`<div class="nunl-alert">\u26A0 ${H[1]} offline validators share <b>${y(H[0])}</b> \u2014 likely provider outage</div>`)}om(o,i,r,b,h);let S=Number((et==null?void 0:et.peers)??0);J("wm-stat-val",h?`${l} validators`:`${$e.size} in registry`),J("wm-stat-nunl",`${b.length} on nUNL`),J("wm-stat-peers",`${zt?zt.length:S} peers`);let M=[...$e.keys()];D0(o,i,b,zt,!h)}function om(e,t,n,s,a){let o=x("m1-val-grid");if(!o)return;let i=new Set(e),r=new Set(t),l=new Set(s),c=tm(),d=y0(),u=b0(),p=e.length?e:c,m=[...$e.keys()],f=m.filter(I=>{var D;return(((D=$e.get(I))==null?void 0:D.chain)??"main")==="main"}),g=d,b=u,h=p.filter(I=>!!ot(I).domain),v=p.filter(I=>!ot(I).domain),w=b.filter(I=>!!ot(I).domain),k=b.filter(I=>!ot(I).domain),$=m.filter(I=>!!kn(ot(I))),T=[{id:"unl",label:"UNL",count:p.length,dot:"unl"},{id:"others",label:"Others",count:b.length,dot:"other"},{id:"all",label:"All",count:f.length,dot:null},{id:"test",label:"Testnet",count:g.length,dot:null}],S={unl:"#00fff0",dunl:"#bd93f9",both:"#50fa7b",nunl:"#ff5555",other:"#ffb86c"},M='<div class="vg-tabs" role="tablist">'+T.map(I=>`<button class="vg-tab ${na===I.id?"vg-tab--active":""}" data-vgtab="${I.id}">
        ${I.dot?`<span class="vg-tab-dot" style="background:${S[I.dot]}"></span>`:""}
        ${y(I.label)}
        <span class="vg-tab-count">${I.count}</span>
      </button>`).join("")+"</div>",C=[],E="";if(na==="unl"){let I=p.filter(N=>l.has(N)),D=h.filter(N=>!l.has(N)),F=v.filter(N=>!l.has(N));I.length&&C.push({title:`\u26A0 Negative UNL (${I.length})`,keys:I,cls:"vgs-warn"}),C.push({title:`Named UNL validators \xB7 ${D.length}`,keys:D}),F.length&&C.push({title:`Key-only UNL validators \xB7 ${F.length}`,keys:F,collapsed:!0}),p.length||C.push({title:"No UNL data",keys:[],notice:"Registry not loaded yet"});let H=a?"live rippled":`registry (${xn})`;E=`${p.length} trusted \xB7 quorum ${n} \xB7 ${s.length} on nUNL \xB7 source: ${H}`}else if(na==="others")C.push({title:`Named mainnet (non-UNL) \xB7 ${w.length}`,keys:w}),k.length&&C.push({title:`Key-only mainnet \xB7 ${k.length}`,keys:k,collapsed:!0}),E=`${b.length} mainnet validators not on UNL \xB7 source: ${xn}`;else if(na==="test"){let I=g.filter(F=>!!ot(F).domain),D=g.filter(F=>!ot(F).domain);I.length&&C.push({title:`Named testnet \xB7 ${I.length}`,keys:I}),D.length&&C.push({title:`Key-only testnet \xB7 ${D.length}`,keys:D,collapsed:!0}),E=`${g.length} testnet validators`}else C.push({title:`\u2B50 UNL \xB7 ${p.length}`,keys:p}),C.push({title:`Other mainnet \xB7 ${b.length}`,keys:b,collapsed:!0}),g.length&&C.push({title:`Testnet \xB7 ${g.length}`,keys:g,collapsed:!0}),E=`${f.length} mainnet \xB7 ${g.length} testnet \xB7 ${$.length} geo-located \xB7 source: ${xn}`;function R(I,D){var xe;let F=ot(I),H=l.has(I),N=i.has(I),z=r.has(I),te=F.chain==="test",oe,pe,ie;H?(oe="vp-nunl",pe="nUNL",ie=S.nunl):N&&z?(oe="vp-both",pe="UNL+dUNL",ie=S.both):N?(oe="vp-unl",pe="UNL",ie=S.unl):z?(oe="vp-dunl",pe="dUNL",ie=S.dunl):(oe="vp-other",pe="Other",ie=S.other);let ne=kn(F),ce=!!ne,G=ne?`\u{1F4CD} ${ne.city??""}`:"",Se=F.domain?F.domain.replace(/^www\./,"").replace(/^validator\./,"").replace(/^xrp\./,""):null,X=`${I.slice(0,8)}\u2026${I.slice(-6)}`,q=N&&D!=null?`<span class="vg-num">${D+1}</span>`:"",se=(xe=F.agreement)==null?void 0:xe["24h"],me=se!=null&&se.score?`<span class="vg-agr" style="color:${parseFloat(se.score)>=99?"#50fa7b":parseFloat(se.score)>=95?"#ffb86c":"#ff5555"}" title="24h agreement">${se.score}</span>`:"";return`<div class="vpill ${oe} ${ce?"vp-locatable":""}"
                 title="${y([F.label,F.domain,ne==null?void 0:ne.city,I].filter(Boolean).join(" \xB7 "))}"
                 onclick="window.focusValidator('${y(I)}')"
                 data-key="${y(I)}">
      ${q}
      <span class="vpdot" style="background:${ie};box-shadow:0 0 5px ${ie}55"></span>
      <div class="vptext">
        <span class="vplabel">${y(Se??F.label??X)}</span>
        ${G?`<span class="vpprov vp-geo">${y(G)}</span>`:""}
      </div>
      <div class="vpactions">
        ${me}
        <span class="vntag vntag-cat" style="border-color:${ie}44;color:${ie}">${pe}</span>
        ${te?'<span class="vntag" style="opacity:.5">test</span>':""}
      </div>
    </div>`}let O="";C.forEach(I=>{if(!I.keys.length)return;let D=I.keys.some(z=>i.has(z)),F=I.keys.map((z,te)=>R(z,D?te:null)).join(""),H=`vgs-${Math.random().toString(36).slice(2,8)}`,N=!I.collapsed;O+=`
      <div class="vg-section ${I.cls??""}">
        <button class="vg-section-hdr" onclick="
          const c=document.getElementById('${H}');
          const open=c.style.display!=='none';
          c.style.display=open?'none':'';
          this.querySelector('.vg-chevron').textContent=open?'\u25B6':'\u25BC';
        ">
          <span class="vg-chevron">${N?"\u25BC":"\u25B6"}</span>
          <span class="vg-sec-title">${y(I.title)}</span>
        </button>
        <div id="${H}" class="vg-section-body" style="display:${N?"":"none"}">
          ${F}
        </div>
      </div>`}),O||(O='<div class="nunl-empty">No validators in this view.</div>'),o.innerHTML=M+O,J("m1-val-summary",E),o.querySelectorAll(".vg-tab").forEach(I=>{I.addEventListener("click",D=>{D.stopPropagation();let F=I.getAttribute("data-vgtab");F&&(na=F,om(e,t,n,s,a))})})}async function P0(e){let t=ar.get(e);if(t&&Date.now()-t.cachedAt<Ju)return t.data;try{let n=new AbortController,s=setTimeout(()=>n.abort(),Yu),a=await fetch(`${Ku}/${encodeURIComponent(e)}`,{signal:n.signal});if(clearTimeout(s),!a.ok)throw new Error(`HTTP ${a.status}`);let o=await a.json();return ar.set(e,{data:o,cachedAt:Date.now()}),o}catch{return null}}async function L0(e){let t=or.get(e);if(t&&Date.now()-t.cachedAt<Ju)return t.data;try{let n=new AbortController,s=setTimeout(()=>n.abort(),Yu),a=await fetch(`${Ku}/${encodeURIComponent(e)}/reports`,{signal:n.signal});if(clearTimeout(s),!a.ok)throw new Error(`HTTP ${a.status}`);let o=await a.json(),i=o.reports??o??[];return or.set(e,{data:i,cachedAt:Date.now()}),i}catch{return[]}}window.focusValidator=async function(e){let t=ot(e),n=kn(t);document.querySelectorAll(".vpill").forEach(o=>o.classList.remove("vp-active"));let s=document.querySelector(`.vpill[data-key="${CSS.escape(e)}"]`);if(s&&(s.classList.add("vp-active"),s.scrollIntoView({behavior:"smooth",block:"nearest"})),pr(e,t,null),P0(e).then(o=>{o&&pr(e,t,o)}),!n){let o=x("world-map-container");if(o){let i=o.querySelector(".wm-no-geo");i&&i.remove();let r=document.createElement("div");r.className="wm-no-geo",r.textContent=`\u{1F4CD} ${t.label} \u2014 geographic location unknown`,o.appendChild(r),setTimeout(()=>r.remove(),3500)}return}let a=x("world-map-container");a&&a.scrollIntoView({behavior:"smooth",block:"nearest"}),Ze&&(Ze.flyTo([n.lat,n.lng],6,{duration:1.2}),setTimeout(()=>{let o=cr[e];o&&o.openPopup()},1300))};function pr(e,t,n){var C,E,R,O,I;let s=x("amend-modal-overlay"),a=x("amend-modal-body");if(!s||!a)return;let o=n??{},i=t.label??o.label??o.account_name??e.slice(0,16)+"\u2026",r=t.domain??o.domain??null,l=t.chain??o.chain??"main",c=t.category??"other",d=Ie[c]??Ie.other,u=kn(t),p=t.unl||c==="unl"||c==="both",m=t.dunl||c==="dunl"||c==="both",f=t.domainVerified||o.domain_verified?"\u2713 Verified":r?"Unverified":"\u2014",g=t.agreement??o.agreement??{},b=!n&&!((C=t.agreement)!=null&&C["24h"]);function h(D,F){if(!F||!F.total)return`<div class="adm-mi"><span class="adm-mk">${D}</span><span class="adm-mv" style="opacity:.5">\u2014</span></div>`;let H=parseFloat(F.score)||0,N=H>=99?"color:#50fa7b":H>=95?"color:#ffb86c":"color:#ff5555";return`<div class="adm-mi">
      <span class="adm-mk">${D}</span>
      <span class="adm-mv mono" style="${N}">${F.score??"\u2014"}
        <span style="opacity:.55;font-size:10px;font-weight:400"> \xB7 ${F.missed??0} missed / ${F.total??0}</span>
      </span>
    </div>`}function v(D,F,H=!1){return!F&&F!==0?"":`<div class="adm-mi"><span class="adm-mk">${D}</span><span class="adm-mv ${H?"mono":""}">${y(String(F))}</span></div>`}let w=or.get(e),k=((E=w==null?void 0:w.data)==null?void 0:E.slice(-14))??[],$=k.length?`<div class="adm-section">
        <div class="adm-slbl">Ledger agreement \u2014 last ${k.length} days</div>
        <div style="display:flex;gap:2px;align-items:flex-end;height:32px;margin-top:6px;">
          ${k.map(D=>{let F=Number(D.missed??D.miss??0),H=Number(D.total??D.ledgers??1),N=H>0?(H-F)/H*100:100,z=Math.round(4+N/100*28),te=N>=99?"#50fa7b":N>=95?"#ffb86c":"#ff5555";return`<div title="${D.date??""} \xB7 ${N.toFixed(1)}% (${F} missed)" style="flex:1;height:${z}px;background:${te};border-radius:2px 2px 0 0;opacity:.85;transition:opacity .15s" onmouseover="this.style.opacity=1" onmouseout="this.style.opacity=.85"></div>`}).join("")}
        </div>
      </div>`:"",T=c==="unl"?"\u2B50 UNL":c==="both"?"\u2B50 UNL + dUNL":c==="nunl"?"\u26A0 Neg-UNL":c==="dunl"?"dUNL":"Non-UNL",S=c==="unl"||c==="both"?"background:rgba(0,255,240,.15);color:#00fff0;border-color:#00fff044":c==="nunl"?"background:rgba(255,85,85,.15);color:#ff5555;border-color:#ff555544":"background:rgba(255,184,108,.1);color:#ffb86c;border-color:#ffb86c44",M=r?`https://xrpscan.com/validator/${encodeURIComponent(r)}`:`https://xrpscan.com/validator/${encodeURIComponent(e)}`;a.innerHTML=`
    <div class="adm-header" style="border-bottom:1px solid rgba(255,255,255,.08);padding-bottom:12px;margin-bottom:12px;">
      <div class="adm-title-row" style="display:flex;align-items:flex-start;gap:10px;margin-bottom:6px;">
        <div style="flex:1">
          <h2 class="adm-title" style="color:${d.hex};margin:0;font-size:17px;font-weight:700">${y(i)}</h2>
          ${r?`<div style="font-size:12px;opacity:.65;margin-top:2px">${y(r)} <span style="opacity:.6">${y(f)}</span></div>`:""}
        </div>
        <span style="font-size:11px;padding:3px 8px;border-radius:10px;border:1px solid;flex-shrink:0;font-weight:600;${S}">${T}</span>
      </div>
      <div style="font-family:monospace;font-size:10px;opacity:.45;word-break:break-all;cursor:pointer" title="Click to copy" onclick="navigator.clipboard?.writeText('${y(e)}');this.style.opacity=.8;setTimeout(()=>this.style.opacity=.45,800)">${y(e)}</div>
    </div>

    <div class="adm-section">
      <div class="adm-slbl">Identity &amp; Status</div>
      ${v("Chain",l==="main"?"\u{1F310} Mainnet":"\u{1F9EA} Testnet")}
      ${v("UNL",p?"\u2B50 Yes \u2014 Ripple UNL":"No")}
      ${v("dUNL",m?"\u2713 Yes \u2014 XRPL Foundation UNL":"No")}
      ${u?v("Location",[u.city,u.country].filter(Boolean).join(", ")||"\u2014"):""}
      ${u!=null&&u.org?v("Provider",u.org):""}
      ${v("Version",t.version??o.version??o.build_version??null)}
      ${v("Base fee",t.baseFee??o.base_fee_xrp??o.baseFee??null)}
      ${v("Ledger",o.currentIndex?Number(o.currentIndex).toLocaleString():null,!0)}
    </div>

    <div class="adm-section">
      <div class="adm-slbl">Ledger Agreement ${b?'<span style="opacity:.4;font-size:10px;margin-left:6px">loading\u2026</span>':""}</div>
      ${h("1-hour",g["1h"]??((R=o.agreement)==null?void 0:R["1h"]))}
      ${h("24-hour",g["24h"]??((O=o.agreement)==null?void 0:O["24h"]))}
      ${h("30-day",g["30d"]??((I=o.agreement)==null?void 0:I["30d"]))}
    </div>

    ${$}

    <div class="adm-footer" style="display:flex;gap:10px;margin-top:12px;padding-top:10px;border-top:1px solid rgba(255,255,255,.07)">
      <a class="adm-link" href="${M}" target="_blank" rel="noopener noreferrer">\u2197 XRPScan</a>
      <button class="adm-link" style="background:none;border:none;cursor:pointer;color:inherit;padding:0" onclick="window._loadValidatorReports('${y(e)}')">\u{1F4CA} Load reports</button>
      ${(u==null?void 0:u.lat)!=null?`<button class="adm-link" style="background:none;border:none;cursor:pointer;color:inherit;padding:0" onclick="window.closeAmendModal();setTimeout(()=>window.focusValidator('${y(e)}'),200)">\u{1F4CD} Show on map</button>`:""}
    </div>`,s.style.display="flex",s.addEventListener("click",D=>{D.target===s&&window.closeAmendModal()},{once:!0})}window._loadValidatorReports=async function(e){var n;let t=ot(e);await L0(e),pr(e,t,((n=ar.get(e))==null?void 0:n.data)??null)};function M0({active:e,quorum:t,margin:n,nUnl:s,valsAvail:a}){let o=x("m1-quorum-ring");if(!o)return;if(!a||!t||!e){o.innerHTML='<div style="opacity:.4;font-size:12px;text-align:center;padding:16px">Connect to view quorum</div>';return}let i=44,r=2*Math.PI*i,l=new Set(s),c=e-s.length,d=s.length,u=Math.max(0,e-t),p=t,m=n<=0?"#ff5555":n<=3?"#ffb86c":"#50fa7b",f=e>0?c/e:0,g=e>0?d/e:0,b=e>0?t/e:0,h=e>0?Math.max(0,n)/e:0,v=e>0?d/e:0;function w(k,$,T,S=8){if($<=0)return"";let M=k*r,C=$*r;return`<circle r="${i}" cx="50" cy="50" fill="none"
      stroke="${T}" stroke-width="${S}" opacity=".85"
      stroke-dasharray="${C} ${r-C}"
      stroke-dashoffset="${r-M}"
      stroke-linecap="round"
      style="transform-origin:50px 50px;transform:rotate(-90deg)"/>`}o.innerHTML=`
    <div class="qr-wrap">
      <svg viewBox="0 0 100 100" width="100" height="100" style="overflow:visible">
        <!-- Background ring -->
        <circle r="${i}" cx="50" cy="50" fill="none" stroke="rgba(255,255,255,.06)" stroke-width="9"/>
        <!-- Quorum zone (required validators) -->
        ${w(0,b,"rgba(0,255,240,.25)",9)}
        <!-- Margin zone (extra validators) -->
        ${w(b,h,"#50fa7b",9)}
        <!-- Negative UNL (offline) -->
        ${v>0?w(b+h,v,"#ff5555",9):""}
        <!-- Centre text -->
        <text x="50" y="45" text-anchor="middle" fill="${m}" font-size="18" font-weight="700" font-family="monospace">${e}</text>
        <text x="50" y="57" text-anchor="middle" fill="rgba(255,255,255,.45)" font-size="9">validators</text>
      </svg>
      <div class="qr-legend">
        <div class="qr-leg-row"><span class="qr-dot" style="background:rgba(0,255,240,.5)"></span>Required for quorum <strong>${t}</strong></div>
        <div class="qr-leg-row"><span class="qr-dot" style="background:#50fa7b"></span>Margin <strong style="color:${m}">${Math.max(0,n)}</strong></div>
        ${d>0?`<div class="qr-leg-row"><span class="qr-dot" style="background:#ff5555"></span>Offline (nUNL) <strong style="color:#ff5555">${d}</strong></div>`:""}
        <div class="qr-leg-row" style="margin-top:6px;border-top:1px solid rgba(255,255,255,.06);padding-top:6px">
          <span style="opacity:.5;font-size:10px">Need ${t} \xB7 have ${e} \xB7 ${n>0?n+" can fail safely":"\u26A0 AT QUORUM LIMIT"}</span>
        </div>
      </div>
    </div>`}function A0(){var F,H,N;let e=et,t=(e==null?void 0:e.server_state)??"unknown",n=(e==null?void 0:e.build_version)??"\u2014",s=Number((e==null?void 0:e.uptime)??0),a=e==null?void 0:e.network_id,o=Number((e==null?void 0:e.io_latency_ms)??0),i=String((e==null?void 0:e.jq_trans_overflow)??"0"),r=Number((e==null?void 0:e.peer_disconnects_resources)??0),l=Number((e==null?void 0:e.load_factor)??1),c=Number((e==null?void 0:e.load_factor_net)??1),d=Number((e==null?void 0:e.load_factor_server)??(e==null?void 0:e.load_factor_local)??1),u=Number(((F=e==null?void 0:e.validated_ledger)==null?void 0:F.age)??0),p=(H=e==null?void 0:e.validated_ledger)==null?void 0:H.seq,m=(e==null?void 0:e.complete_ledgers)??"",f=(e==null?void 0:e.state_accounting)??null;u>10&&(He.staleLedger=!0),o>5&&(He.ioStressed=!0),la("peerDiscon")>5&&(He.peerChurn=!0);let g=x("m2-state");if(g){g.textContent=t;let z=["full","proposing","validating"].includes(t),te=["syncing","tracking","connected"].includes(t);g.className=`state-pill state-${z?"ok":te?"warn":"bad"}`}J("m2-version",n),J("m2-uptime",K0(s)),J("m2-netid",a===0?"0 (Mainnet)":a===1?"1 (Testnet)":a??"\u2014"),J("m2-ledger-seq",p!=null?Number(p).toLocaleString():"\u2014"),J("m2-ledger-age",u>0?`${u}s`:"< 1s"),J("m2-io-ms",o>0?`${o}ms`:"< 1ms"),J("m2-jq",i==="0"?"0 (clean)":`\u26A0 ${i}`),J("m2-discon",r.toLocaleString());let b=x("m2-ledger-age");b&&(b.className=`kv-v ${u>10?"text-danger":u>5?"text-warn":""}`);let h=Math.min(100,(l-1)/49*100);Tt("m2-load-bar",h,l>5?"bar-danger":l>2?"bar-warn":"bar-ok"),J("m2-load-total",`${l.toFixed(2)}\xD7`),J("m2-load-net",`${c.toFixed(2)}\xD7`),J("m2-load-local",`${d.toFixed(2)}\xD7`);let v=d>c*1.5?"Local node stressed":c>d*1.5?"Network-wide stress":l>1.2?"Distributed":"Normal";J("m2-load-src",v);let w=B.tpsHistory.length?B.tpsHistory[B.tpsHistory.length-1]:null;J("m2-tps",w!=null?w.toFixed(1):"\u2014"),J("m2-txcount",((N=B.ledgerLog[0])==null?void 0:N.txCount)??"\u2014");let k=m==="entire ledger"||m.startsWith("32570"),$=k?100:G0(m);if(J("m2-ledger-range",m||"\u2014"),J("m2-hist-type",k?"Full History Node":"Pruned / Partial"),J("m2-hist-score",`${$}%`),Tt("m2-hist-bar",$,$<30?"bar-danger":$<70?"bar-warn":"bar-ok"),f){let z=x("m2-state-acct");if(z){let te=["full","syncing","tracking","connected","disconnected"],oe=0,pe={};te.forEach(ie=>{var ne;pe[ie]=Number(((ne=f[ie])==null?void 0:ne.duration_us)??0),oe+=pe[ie]}),z.innerHTML=oe>0?te.map(ie=>{let ne=Math.round(pe[ie]/oe*100);return ne?`<div class="sa-row"><span class="sa-lbl">${ie}</span>
          <div class="bar-track sa-bar"><div class="bar-fill ${ie==="full"?"bar-ok":ie==="syncing"?"bar-warn":"bar-danger"}" style="width:${ne}%"></div></div>
          <span class="sa-pct">${ne}%</span></div>`:""}).join(""):'<span class="dim">No data</span>'}}let T=(e==null?void 0:e.peers)!=null?Number(e.peers):null,S=T!=null,M=0,C=0,E=!1;zt&&(zt.forEach(z=>{z.inbound===!0?M++:C++}),E=!0);let R=E&&M+C>0?Math.round(M/(M+C)*100):0,O=E?zt.length:T??0,I=O<6?"HIGH":O<15?"MEDIUM":"LOW";O<6&&(He.eclipseRisk=!0),R>80&&(He.peerSaturate=!0),J("m2-peers",S?O:"\u2014"),J("m2-inbound",E?M:S?"\u2014 (cmd restricted)":"\u2014"),J("m2-outbound",E?C:S?"\u2014 (cmd restricted)":"\u2014"),J("m2-ib-pct",E?`${R}%`:"\u2014"),Tt("m2-peer-bar",Math.min(100,O/21*100),O>18?"bar-danger":O>15?"bar-warn":"bar-ok"),Tt("m2-ib-bar",R,R>80?"bar-danger":R>60?"bar-warn":"bar-ok");let D=x("m2-eclipse");D&&(D.textContent=I,D.className=`risk-badge risk-${I.toLowerCase()}`)}function E0(){var C,E,R,O;let e=Un,t=Number(((C=e==null?void 0:e.drops)==null?void 0:C.minimum_fee)??10),n=Number(((E=e==null?void 0:e.drops)==null?void 0:E.open_ledger_fee)??10),s=Number(((R=e==null?void 0:e.drops)==null?void 0:R.median_fee)??10),a=Number(((O=e==null?void 0:e.drops)==null?void 0:O.base_fee)??10),o=Number((e==null?void 0:e.current_ledger_size)??0),i=Number((e==null?void 0:e.expected_ledger_size)??1),r=Number((e==null?void 0:e.current_queue_size)??0),l=Number((e==null?void 0:e.max_queue_size)??1),c=l>0?Math.round(r/l*100):0,d=i>0?o/i:1,u=la("fees"),p=u>0?Math.round((n-u)/u*100):0,m=Math.min(100,Math.round(Math.log2(Math.max(1,n/10))*14));n>t*10&&(He.feeSpike=!0),c>80&&(He.queuePressure=!0),d>2&&(He.spamLedger=!0);let f=mt.burnDrops.slice(-10),g=f.length?f.reduce((I,D)=>I+D,0)/f.length:0,b=j0(mt.burnDrops),h=la("burnDrops"),v=b>0&&mt.burnDrops.length>5?((g-h)/b).toFixed(2):"0.00",w=Math.min(100,Math.abs(Number(v))*20);Math.abs(Number(v))>3&&(He.burnAnomaly=!0);let k=n>5e3?"Severe":n>500?"High":n>100?"Elevated":n>20?"Normal":"Minimal",T={Severe:"#ff5555",High:"#ff9955",Elevated:"#ffb86c",Normal:"#50fa7b",Minimal:"#6272a4"}[k]??"#50fa7b",S=x("m3-pressure");S&&(S.textContent=k,S.className=`pressure-badge p-${k.toLowerCase()}`),J("m3-open",`${n} drops`),J("m3-med",`${s} drops`),J("m3-base",`${a} drops`),J("m3-devpct",`${p>0?"+":""}${p}% vs baseline`),J("m3-spam",`${m} / 100`),J("m3-qsize",`${r} / ${l}`),J("m3-qpct",`${c}%`),J("m3-szratio",`${d.toFixed(2)}\xD7`),J("m3-curledger",`${o} txs`),J("m3-expledger",`${i} expected`),J("m3-burn",g>0?`${(g/1e6).toFixed(4)} XRP / ledger`:"\u2014"),J("m3-burnz",`z = ${v}`),Tt("m3-spam-bar",m,m>70?"bar-danger":m>40?"bar-warn":"bar-ok"),Tt("m3-q-bar",c,c>80?"bar-danger":c>50?"bar-warn":"bar-ok"),Tt("m3-sz-bar",Math.min(100,d*50),d>2?"bar-danger":d>1.5?"bar-warn":"bar-ok"),Tt("m3-burn-bar",w,w>60?"bar-danger":w>30?"bar-warn":"bar-ok");let M=x("m3-congestion-summary");if(M){let I=[];d>2&&I.push({icon:"\u{1F6A8}",txt:`Ledger ${d.toFixed(1)}\xD7 normal size \u2014 possible spam burst`,col:"#ff5555"}),c>80&&I.push({icon:"\u26A0",txt:`TX queue ${c}% full \u2014 fee surge imminent`,col:"#ffb86c"}),m>70&&I.push({icon:"\u26A0",txt:`Spam index ${m}/100 \u2014 elevated DDoS risk`,col:"#ffb86c"}),Math.abs(Number(v))>3&&I.push({icon:"\u{1F4C9}",txt:`Burn rate z=${v} \u2014 resource exhaustion pattern`,col:"#ff9955"}),p>200&&I.push({icon:"\u{1F4B8}",txt:`Open fee ${p}% above baseline \u2014 network stress`,col:"#ffb86c"}),M.innerHTML=I.length?I.map(D=>`<div class="cong-line"><span>${D.icon}</span><span style="color:${D.col}">${y(D.txt)}</span></div>`).join(""):'<div class="cong-clear"><span style="color:#50fa7b">\u2713</span> No congestion signals \u2014 network traffic is normal</div>'}}function N0(){var u,p;let e={},t=0;for(let m of $e.values()){if(m.chain==="test")continue;let f=m.version??"unknown";e[f]=(e[f]??0)+1,t++}let n={},s=0;if(Array.isArray(zt))for(let m of zt){let f=(m.version??"unknown").replace(/rippled-/i,"").split(" ")[0];n[f]=(n[f]??0)+1,s++}let a=x("m4-version-dist");if(a&&t>0){let m=Object.entries(e).sort((h,v)=>v[1]-h[1]),f=((u=m[0])==null?void 0:u[0])??"?",g=t>0?Math.round((((p=m[0])==null?void 0:p[1])??0)/t*100):0,b=["#00fff0","#50fa7b","#ffb86c","#bd93f9","#ff5555","#8be9fd"];a.innerHTML=m.slice(0,6).map(([h,v],w)=>{let k=Math.round(v/t*100),$=b[w%b.length],T=h.includes("beta")||h.includes("rc")||h.includes("RC");return`<div class="vd-row">
        <div class="vd-ver-label">
          <span style="color:${$};font-weight:600">${y(h)}</span>
          ${T?'<span class="vd-beta-tag">beta</span>':""}
        </div>
        <div class="vd-bar-wrap">
          <div class="vd-bar-fill" style="width:${k}%;background:${$};opacity:.75"></div>
        </div>
        <span class="vd-count">${v} <span style="opacity:.5">(${k}%)</span></span>
      </div>`}).join("")+`<div class="vd-summary">${t} validators \xB7 ${m.length} versions \xB7 ${g}% on latest (${y(f)})</div>`}let o={"North America":0,Europe:0,"Asia Pacific":0,"Middle East":0,"South America":0,Other:0};function i(m,f){return m>15&&f<-30?"North America":m>-60&&f<-30?"South America":m>35&&f>-30&&f<60?"Europe":m>10&&f>=60&&f<150||m>=-40&&f>=110?"Asia Pacific":m>10&&m<40&&f>=30&&f<70?"Middle East":"Other"}let r=0;for(let m of $e.values()){if(m.chain==="test")continue;let f=kn(m);if(!(f!=null&&f.lat))continue;let g=i(f.lat,f.lng);o[g]=(o[g]??0)+1,r++}let l=x("m4-geo-dist");if(l&&r>0){let m={"North America":"#00fff0",Europe:"#50fa7b","Asia Pacific":"#bd93f9","Middle East":"#ffb86c","South America":"#8be9fd",Other:"#6272a4"},f=Object.entries(o).filter(([,v])=>v>0).sort((v,w)=>w[1]-v[1]),g=f.reduce((v,[,w])=>v+(w/r)**2,0),b=g>.4?"Concentrated":g>.25?"Moderate":"Distributed",h=g>.4?"#ff5555":g>.25?"#ffb86c":"#50fa7b";l.innerHTML=f.map(([v,w])=>{let k=Math.round(w/r*100),$=m[v]??"#6272a4";return`<div class="vd-row">
        <span class="vd-ver-label" style="color:${$};font-weight:600">${y(v)}</span>
        <div class="vd-bar-wrap">
          <div class="vd-bar-fill" style="width:${k}%;background:${$};opacity:.65"></div>
        </div>
        <span class="vd-count">${w} <span style="opacity:.5">(${k}%)</span></span>
      </div>`}).join("")+`<div class="vd-summary">${r} geo-located \xB7 <span style="color:${h}">${b}</span> (HHI ${g.toFixed(2)})</div>`}let c={};for(let m of $e.values()){if(m.chain==="test")continue;let f=kn(m),g=m.provider??(f==null?void 0:f.org)??"Unknown",b=g.match(/AWS|Amazon/i)?"AWS":g.match(/Azure|Microsoft/i)?"Azure":g.match(/GCP|Google/i)?"GCP":g.match(/Hetzner/i)?"Hetzner":g.match(/OVH/i)?"OVH":g.match(/Cloudflare/i)?"Cloudflare":g.match(/Equinix/i)?"Equinix":g.match(/NTT/i)?"NTT":g.match(/Ripple/i)?"Ripple":"Other";c[b]=(c[b]??0)+1}let d=x("m4-provider-dist");if(d){let m=Object.values(c).reduce((f,g)=>f+g,0);if(m>0){let f=Object.entries(c).sort((b,h)=>h[1]-b[1]),g=["#ff5555","#ffb86c","#50fa7b","#00fff0","#bd93f9","#8be9fd","#6272a4"];d.innerHTML=f.slice(0,7).map(([b,h],v)=>{let w=Math.round(h/m*100),k=g[v%g.length],$=w>33?"\u26A0 ":"";return`<div class="vd-row">
          <span class="vd-ver-label" style="color:${k};font-weight:600">${$}${y(b)}</span>
          <div class="vd-bar-wrap">
            <div class="vd-bar-fill" style="width:${w}%;background:${k};opacity:.7;${w>33?"box-shadow:0 0 6px "+k+"88":""}"></div>
          </div>
          <span class="vd-count">${h} <span style="opacity:.5">(${w}%)</span></span>
        </div>`}).join("")}}}var xs="pending";function im(e){let t=x("amendment-list");if(!t)return;let n=x("amend-pipeline-header"),s=Object.entries(e).map(([d,u])=>({hash:d,...u})),a=s.filter(d=>d.enabled),o=s.filter(d=>!d.enabled&&!d.vetoed).sort((d,u)=>(u.count??0)-(d.count??0)),i=s.filter(d=>d.vetoed),r=o.filter(d=>d.majority),l=o.filter(d=>!d.majority&&(d.count??0)>=(d.threshold??28)*.8);if(o.some(d=>(d.count??0)<(d.threshold??28)*.5)&&(He.amendVeto=!0),n){let d=[{id:"pending",label:"Voting",count:o.length,color:"#8be9fd"},{id:"active",label:"Active",count:a.length,color:"#50fa7b"},{id:"vetoed",label:"Vetoed",count:i.length,color:"#ff5555"},{id:"all",label:"All",count:s.length,color:null}];n.innerHTML=`
      <div class="ap-tabs">
        ${d.map(u=>`
          <button class="ap-tab ${xs===u.id?"ap-tab--active":""}" data-aptab="${u.id}">
            ${u.color?`<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:${u.color};margin-right:5px;vertical-align:middle"></span>`:""}
            ${u.label}
            <span class="ap-tab-count">${u.count}</span>
          </button>`).join("")}
      </div>
      ${r.length?`<div class="ap-alert-bar">\u23F3 ${r.length} amendment${r.length>1?"s":""} reached validator majority \u2014 activates in ~14 days if maintained</div>`:""}
      ${l.length?`<div class="ap-near-bar">\u{1F4C8} ${l.length} amendment${l.length>1?"s":""} approaching 80% threshold</div>`:""}`,n.querySelectorAll(".ap-tab").forEach(u=>{u.onclick=()=>{xs=u.dataset.aptab,im(e)}})}let c=xs==="active"?a:xs==="vetoed"?i:xs==="all"?s.sort((d,u)=>d.enabled!==u.enabled?d.enabled?1:-1:d.vetoed!==u.vetoed?d.vetoed?1:-1:(u.count??0)-(d.count??0)):o;if(!c.length){t.innerHTML=`<div class="amend-empty">${xs==="vetoed"?"No vetoed amendments":"No data"}</div>`;return}t.innerHTML=c.map(d=>{var S;let u=d.count??0,p=d.threshold??28,m=Math.min(100,Math.round(u/p*100)),f=d.name??`${d.hash.slice(0,10)}...`,g=!!d.enabled,b=!!d.vetoed,h=!!d.majority,v=Qu[f]??{},w=(S=mt.amendMomentum)==null?void 0:S[d.hash],k="";if(h&&!g&&d.majority){let M=Date.now()-new Date(d.majority).getTime(),C=M>0?Math.floor(M/864e5):0,E=Math.max(0,14-C),R=Math.min(100,Math.round(C/14*100));k=`<div class="ap-countdown">
        <span class="ap-countdown-lbl">Majority held ${C}d \xB7 activates in ~${E}d</span>
        <div class="ap-countdown-track"><div class="ap-countdown-fill" style="width:${R}%"></div></div>
      </div>`}let $=g?"#50fa7b":b?"#ff5555":h?"#ffb86c":m>=80?"#8be9fd":"rgba(255,255,255,.3)",T=g?"Active":b?"Vetoed":h?"Majority":m>=80?"Near":"Voting";return`<div class="ap-row" onclick="window.showAmendDetail('${y(d.hash)}')">
      <div class="ap-row-main">
        <div class="ap-row-top">
          <span class="ap-name">${y(f)}</span>
          <span class="ap-status-tag" style="border-color:${$}44;color:${$}">${T}</span>
        </div>
        ${v.purpose?`<div class="ap-purpose">${y(v.purpose)}</div>`:""}
        ${g?`<div class="ap-active-note">\u2713 Running on all ledgers${v.intro?" \xB7 since "+v.intro:""}</div>`:`<div class="ap-vote-row">
          <div class="ap-vote-track">
            <div class="ap-vote-fill" style="width:${m}%;background:${$};opacity:${g?1:.75}"></div>
            <div class="ap-vote-thresh" title="80% threshold"></div>
          </div>
          <span class="ap-vote-label">${u}/${p} <span style="opacity:.5">(${m}%)</span></span>
        </div>`}
        ${k}
      </div>
    </div>`}).join("")}function R0(e){lr={},Object.entries(e).forEach(([t,n])=>{lr[t]={hash:t,...n}})}window.showAmendDetail=function(e){let t=lr[e];if(!t)return;let n=t.name||`${e.slice(0,16)}...`,s=Qu[n]||{},a=t.count??0,o=t.threshold??28,i=Math.min(100,Math.round(a/o*100)),r=t.enabled?"Active on Ledger":t.vetoed?"Vetoed":t.majority?"Majority Reached":"Voting in Progress",l=t.enabled?"adm-s-ok":t.vetoed?"adm-s-bad":t.majority?"adm-s-warn":"adm-s-info",c=t.enabled?"bar-ok":t.vetoed?"bar-danger":t.majority?"bar-warn":"bar-info",d=t.majority&&!t.enabled?`
    <div class="adm-note adm-note-warn">
      Majority reached. If maintained for 2 weeks this amendment will auto-activate.
      Majority since: ${y(String(t.majority))}
    </div>`:"",u=x("amend-modal-overlay"),p=x("amend-modal-body");!u||!p||(p.innerHTML=`
    <div class="adm-header">
      <div class="adm-title-row">
        <h2 class="adm-title">${y(n)}</h2>
        <span class="adm-status ${l}">${y(r)}</span>
      </div>
      <div class="adm-hash mono">${y(e)}</div>
    </div>
    ${s.purpose?`<div class="adm-purpose-row"><span class="adm-purpose-tag">Purpose</span>${y(s.purpose)}</div>`:""}
    ${s.desc?`<div class="adm-section"><div class="adm-slbl">What it does</div><div class="adm-sdesc">${y(s.desc)}</div></div>`:""}
    ${s.impact?`<div class="adm-section"><div class="adm-slbl">Technical Impact</div><div class="adm-sdesc">${y(s.impact)}</div></div>`:""}
    <div class="adm-section">
      <div class="adm-slbl">Validator Votes</div>
      ${t.enabled?'<div class="adm-ratified">Fully ratified \u2014 running on all ledgers</div>':`
        <div class="adm-vote-wrap">
          <div class="adm-vote-track">
            <div class="bar-fill ${c} adm-vote-fill" style="width:${i}%"></div>
            <div class="adm-vote-line" style="left:80%" title="80% threshold"></div>
          </div>
          <div class="adm-vote-lbl">
            <span class="adm-vote-n">${a} / ${o} validators</span>
            <span>${i}% \u2014 need 80%</span>
          </div>
        </div>
        ${d}`}
    </div>
    <div class="adm-meta">
      <div class="adm-mi"><span class="adm-mk">Node supports</span><span class="adm-mv ${t.supported?"adm-ok":"adm-bad"}">${t.supported?"Yes":"No \u2014 upgrade required"}</span></div>
      <div class="adm-mi"><span class="adm-mk">Vetoed by node</span><span class="adm-mv ${t.vetoed?"adm-bad":""}">${t.vetoed?"Yes":"No"}</span></div>
      ${s.intro?`<div class="adm-mi"><span class="adm-mk">First available</span><span class="adm-mv">${y(s.intro)}</span></div>`:""}
    </div>
    <div class="adm-footer">
      <a class="adm-link" href="https://xrpl.org/known-amendments.html" target="_blank" rel="noopener noreferrer">Amendment Reference</a>
      <a class="adm-link" href="https://xrpl.org/consensus.html" target="_blank" rel="noopener noreferrer">Consensus Docs</a>
    </div>`,u.style.display="flex",u.addEventListener("click",m=>{m.target===u&&window.closeAmendModal()},{once:!0}))};window.closeAmendModal=function(){let e=x("amend-modal-overlay");e&&(e.style.display="none")};function _0(e){if(window.L){e();return}if(!document.querySelector("#leaflet-css")){let n=document.createElement("link");n.id="leaflet-css",n.rel="stylesheet",n.href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css",document.head.appendChild(n)}let t=document.createElement("script");t.src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js",t.onload=e,document.head.appendChild(t)}function D0(e,t,n,s,a=!1){x("world-map-container")&&_0(()=>I0(e,t,n,s,a))}function I0(e,t,n,s,a=!1){let o=x("world-map-container");if(!o)return;let i=new Set(n||[]),r=new Set(e||[]),l=new Set(t||[]),c=B.currentNetwork||"xrpl-mainnet";if(Ze&&io!==c&&(Ze.remove(),Ze=null,en=[],io=null),!Ze){o.innerHTML="";let k=document.createElement("div");k.id="wm-leaflet",k.style.cssText="width:100%;height:440px;",o.appendChild(k),Ze=L.map("wm-leaflet",{center:[25,5],zoom:2,minZoom:1,maxZoom:12,zoomControl:!0,attributionControl:!0,worldCopyJump:!0}),L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",{attribution:'&copy; <a href="https://carto.com">CARTO</a> &copy; <a href="https://openstreetmap.org">OSM</a>',subdomains:"abcd",maxZoom:19}).addTo(Ze),io=c}en.forEach(k=>{try{k.remove()}catch{}}),en=[];function d(k){return i.has(k)?"nunl":r.has(k)&&l.has(k)?"both":r.has(k)?"unl":l.has(k)?"dunl":"other"}cr={};let u={};for(let[k,$]of $e){let T=kn($);if(!(T!=null&&T.lat)||!(T!=null&&T.lng))continue;let S=`${(Math.round(T.lat*2)/2).toFixed(1)},${(Math.round(T.lng*2)/2).toFixed(1)}`;u[S]||(u[S]={lat:T.lat,lng:T.lng,keys:[],city:T.city,org:T.org}),u[S].keys.push(k)}if(Object.values(u).forEach(k=>{let $=k.keys.length,T=k.keys.map(d),S=["nunl","both","unl","dunl","other"].find(O=>T.includes(O))||"other",M=Ie[S],C=$>5?13:$>2?10:7,E=L.divIcon({html:`<div class="wm-lmarker wm-lmarker-val ${S==="nunl"?"wm-lmarker-nunl":""} ${a?"wm-lmarker-ref":""}"
                  style="--mc:${M.hex};--mg:${M.glow};"
                  title="${k.keys.map(O=>ot(O).label).join(", ")}">
        <div class="wm-lring"></div>
        <div class="wm-ldot" style="width:${C*2}px;height:${C*2}px;">${$>1?`<span>${$}</span>`:""}</div>
      </div>`,className:"",iconSize:[(C+8)*2,(C+8)*2],iconAnchor:[C+8,C+8]}),R=L.marker([k.lat,k.lng],{icon:E}).bindPopup(F0(k.keys,k.city,k.org,i,r,l,a),{maxWidth:380,className:"wm-popup-wrap"}).addTo(Ze);k.keys.forEach(O=>{cr[O]=R}),en.push(R)}),a){let k=L.control({position:"bottomleft"});k.onAdd=()=>{let $=L.DomUtil.create("div","wm-ref-banner");return $.innerHTML="\u{1F4E1} Reference positions \xB7 live validator list unavailable from endpoint",$},k.addTo(Ze),en.push(k)}let p=[...$e.keys()].filter(k=>{var T;return((T=$e.get(k).geo)==null?void 0:T.lat)!=null||po[k]}).length,m=$e.size-p;if(m>0){let k=L.control({position:"bottomright"});k.onAdd=()=>{let $=L.DomUtil.create("div","wm-unknown-ctrl");return $.innerHTML=`+ ${m} validators \xB7 location unknown`,$},k.addTo(Ze),en.push(k)}h0.forEach(k=>{let $=L.divIcon({html:`<div class="wm-lmarker wm-lmarker-pub">
        <div class="wm-lring"></div>
        <div class="wm-ldot" style="width:10px;height:10px;"></div>
      </div>`,className:"",iconSize:[20,20],iconAnchor:[10,10]}),T=L.marker([k.lat,k.lng],{icon:$}).bindPopup(`
        <div class="wm-popup-inner">
          <div class="wm-popup-badge wm-popup-badge-pub">Public Node</div>
          <div class="wm-popup-name">${y(k.label)}</div>
          <div class="wm-popup-row"><span class="wm-popup-key">Location</span><span>\u{1F4CD} ${y(k.city)}</span></div>
          <div class="wm-popup-row"><span class="wm-popup-key">Operator</span><span>${y(k.org)}</span></div>
          <div class="wm-popup-row"><span class="wm-popup-key">Type</span><span>Full history node</span></div>
        </div>`,{maxWidth:260,className:"wm-popup-wrap"}).addTo(Ze);en.push(T)});let f=Array.isArray(s)?s:[],g=f.filter(k=>k.inbound===!0).length,b=f.length-g,h=f.length>0?`${f.length} peers (${g}\u2193 ${b}\u2191)`:`${Number((et==null?void 0:et.peers)??0)} peers`,v=L.control({position:"topleft"});v.onAdd=()=>{let k=L.DomUtil.create("div","wm-legend-ctrl");return k.innerHTML=`
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${Ie.unl.hex};box-shadow:0 0 5px ${Ie.unl.glow}"></span>UNL Validator</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${Ie.dunl.hex};box-shadow:0 0 5px ${Ie.dunl.glow}"></span>dUNL only</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${Ie.both.hex};box-shadow:0 0 5px ${Ie.both.glow}"></span>UNL + dUNL</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${Ie.other.hex};box-shadow:0 0 5px ${Ie.other.glow}"></span>Other validator</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${Ie.nunl.hex};box-shadow:0 0 5px ${Ie.nunl.glow}"></span>Negative UNL</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${Ie.pub.hex};box-shadow:0 0 5px ${Ie.pub.glow}"></span>Public Node</div>
      <div class="wm-leg-row wm-leg-peers"><span class="wm-leg-dot" style="background:#8be9fd"></span>${h}</div>
      <div class="wm-leg-src" style="opacity:.55;font-size:10px;margin-top:4px;">
        Registry: ${xn==="live"?"\u{1F7E2} live":"\u{1F7E1} fallback"}
      </div>`,k},v.addTo(Ze),en.push(v);let w=en.filter(k=>k&&typeof k.getLatLng=="function");if(w.length>=2)try{let k=L.latLngBounds(w.map($=>$.getLatLng()));k.isValid()&&Ze.fitBounds(k.pad(.15),{maxZoom:6})}catch{}try{window.dispatchEvent(new CustomEvent("nalulf-network-map",{detail:{map:Ze,networkId:io}}))}catch{}}function F0(e,t,n,s,a,o,i=!1){let r=e.length>1,l=e.map(d=>{let u=ot(d),p=s.has(d),m=a.has(d),f=o.has(d),g=d.slice(0,20)+"...",b,h;return p?(b=Ie.nunl.hex,h="Negative UNL"):m&&f?(b=Ie.both.hex,h="UNL + dUNL"):m?(b=Ie.unl.hex,h="UNL"):f?(b=Ie.dunl.hex,h="dUNL"):(b=Ie.other.hex,h="Other"),`<div class="wm-popup-val-row">
      <span class="wm-popup-val-dot" style="background:${b};box-shadow:0 0 6px ${b}66"></span>
      <div class="wm-popup-val-info">
        <span class="wm-popup-val-name">${y(u.label)}</span>
        ${u.domain?`<span class="wm-popup-val-domain">${y(u.domain)}</span>`:""}
        <span class="wm-popup-val-key"
              onclick="navigator.clipboard?.writeText('${y(d)}');this.textContent='\u2713 Copied!';setTimeout(()=>this.textContent='${y(g)}',1400)"
              title="Click to copy full key">${y(g)}</span>
        <div class="wm-popup-val-tags">
          <span class="wm-popup-ok-tag" style="border-color:${b}66;color:${b}">${h}</span>
          ${u.provider?`<span class="wm-popup-prov">${y(u.provider)}</span>`:""}
        </div>
      </div>
    </div>`}).join(""),c=[...new Set(e.map(d=>{var p;let u=ot(d);return u.provider??((p=kn(u))==null?void 0:p.org)??null}).filter(Boolean))];return`<div class="wm-popup-inner">
    <div class="wm-popup-loc-row">
      <span class="wm-popup-loc-icon">\u{1F4CD}</span>
      <div>
        <div class="wm-popup-name">${y(t||"Unknown Location")}</div>
        ${c.map(d=>`<div class="wm-popup-org">${y(d)}</div>`).join("")}
      </div>
    </div>
    <div class="wm-popup-badges">
      ${r?`<div class="wm-popup-badge wm-popup-badge-cluster">${e.length} Validators at this location</div>`:""}
      ${i?'<div class="wm-popup-badge wm-popup-badge-ref">Reference data</div>':""}
    </div>
    <div class="wm-popup-divider"></div>
    <div class="wm-popup-vals">${l}</div>
  </div>`}var ks=[];function O0(){let e=Object.keys(He),t=e.reduce((r,l)=>{var c;return r+(((c=tn[l])==null?void 0:c.w)??1)},0),n=t>=p0;for(e.forEach(r=>{var l,c;ks.find(d=>d.key===r&&Date.now()-d.ts<3e5)||ks.push({key:r,label:((l=tn[r])==null?void 0:l.label)??r,ts:Date.now(),weight:((c=tn[r])==null?void 0:c.w)??1})});ks.length>20;)ks.shift();let s=x("adversarial-alert");s&&(s.classList.toggle("adv-active",n),s.classList.toggle("adv-inactive",!n));let a=x("adversarial-score");if(a){let r=t===0?"All Clear":t<3?"Monitor":t<5?"Elevated":t<10?"High":"Critical",l=t===0?"#50fa7b":t<3?"#8be9fd":t<5?"#ffb86c":t<10?"#ff9955":"#ff5555";a.innerHTML=`<span style="color:${l};font-weight:700">${r}</span>
      <span style="opacity:.5;font-size:11px;margin-left:8px">threat score ${t}</span>`,a.className="adv-score"}let o=x("adversarial-signals");if(!o)return;if(!e.length)o.innerHTML=`<div class="adv-clear-card">
      <span class="adv-clear-icon">\u2713</span>
      <div>
        <div class="adv-clear-title">No Active Signals</div>
        <div class="adv-clear-sub">All ${Object.keys(tn).length} threat indicators are nominal</div>
      </div>
    </div>`;else{let r=e.filter(u=>{var p;return(((p=tn[u])==null?void 0:p.w)??1)>=3}),l=e.filter(u=>{var p;return(((p=tn[u])==null?void 0:p.w)??1)===2}),c=e.filter(u=>{var p;return(((p=tn[u])==null?void 0:p.w)??1)===1}),d=(u,p,m)=>p.length===0?"":`
      <div class="adv-group-title" style="color:${m}">${u} (${p.length})</div>
      ${p.map(f=>{let g=tn[f]??{w:1,label:f},b=g.label.split(" \u2014 "),h=b[0],v=b[1]||"";return`<div class="adv-sig-card adv-sig-${g.w>=3?"critical":g.w>=2?"elevated":"monitor"}">
          <div class="adv-sig-top">
            <span class="adv-sig-dot" style="background:${m}"></span>
            <span class="adv-sig-title">${y(h)}</span>
            <span class="adv-sig-badge" style="border-color:${m}44;color:${m}">W${g.w}</span>
          </div>
          ${v?`<div class="adv-sig-detail">${y(v)}</div>`:""}
        </div>`}).join("")}`;o.innerHTML=d("Critical",r,"#ff5555")+d("Elevated",l,"#ffb86c")+d("Monitor",c,"#8be9fd")}let i=x("adversarial-history");if(i&&ks.length){let r=Date.now();i.innerHTML=ks.slice(-8).reverse().map(l=>{let c=Math.round((r-l.ts)/6e4),d=e.includes(l.key);return`<div class="adv-hist-row ${d?"adv-hist-active":"adv-hist-resolved"}">
        <span class="adv-hist-dot"></span>
        <span class="adv-hist-lbl">${y(l.label.split(" \u2014 ")[0].substring(0,40))}</span>
        <span class="adv-hist-time">${c<1?"now":`${c}m ago`} ${d?'<span class="adv-hist-tag-active">active</span>':'<span class="adv-hist-tag-res">resolved</span>'}</span>
      </div>`}).join("")}}function ur(e,t){var T,S,M,C;let n=x("nh-banner");if(!n)return;if(!e||B.connectionState!=="connected"){J("nh-score","\u2014"),J("nh-grade","Disconnected"),J("nh-sub",t||"Connect to begin"),n.className="nh-banner nh-dead",qu({}),Vu(null);return}let{info:s,fee:a,vals:o}=e,i=100,r=(s==null?void 0:s.server_state)??"unknown";["full","proposing","validating"].includes(r)||(i-=r==="syncing"?20:40);let l=Number((s==null?void 0:s.load_factor)??1);l>2&&(i-=10),l>5&&(i-=15),l>20&&(i-=20);let c=Number((s==null?void 0:s.peers)??0);c<6?i-=30:c<15&&(i-=10);let d=Number(((T=s==null?void 0:s.last_close)==null?void 0:T.converge_time_s)??0);d>6&&(i-=10),d>10&&(i-=15);let u=Number(((S=s==null?void 0:s.validated_ledger)==null?void 0:S.age)??0);u>5&&(i-=5),u>10&&(i-=15);let p=Number(((M=a==null?void 0:a.drops)==null?void 0:M.open_ledger_fee)??10);p>500&&(i-=5),p>2e3&&(i-=10);let m=((C=o==null?void 0:o.trusted_validator_keys)==null?void 0:C.length)??0,f=(o==null?void 0:o.validation_quorum)??0;f>0&&m<f&&(i-=30);let g=((s==null?void 0:s.negative_unl)??[]).length;i-=Math.min(20,g*4);let b=Object.keys(He).reduce((E,R)=>{var O;return E+(((O=tn[R])==null?void 0:O.w)??1)},0);i-=Math.min(25,b*3),i=Math.max(0,Math.min(100,Math.round(i)));let h=Object.keys(He).length,{grade:v,status:w,cls:k}=B0(i);J("nh-score",w),J("nh-grade",v),J("nh-sub",`${new Date().toLocaleTimeString()} \xB7 ${h>0?h+" signal"+(h!==1?"s":"")+" active":"All signals clear"}`),n.className=`nh-banner nh-${k}`;let $=x("nh-ring");if($){let E=2*Math.PI*28;$.style.strokeDasharray=E,$.style.strokeDashoffset=E*(1-i/100);let R=k==="great"?"#00fff0":k==="good"?"#50fa7b":k==="fair"?"#ffb86c":k==="warn"?"#ff9955":"#ff5555";$.style.stroke=R}qu({st:r,pc:c,q:f,tc:m,lf:l,cvg:d,age:u,nc:g}),Vu({info:s,fee:a,vals:o})}function B0(e){return e>=90?{grade:"All Systems Nominal",status:"Optimal",cls:"great"}:e>=70?{grade:"Operating Normally",status:"Good",cls:"good"}:e>=50?{grade:"Minor Issues Detected",status:"Watch",cls:"fair"}:e>=30?{grade:"Attention Required",status:"Warning",cls:"warn"}:{grade:"Critical Issues",status:"Critical",cls:"bad"}}function qu(e){Wn("nh-v-state",["full","proposing","validating"].includes(e.st)?"ok":e.st==="syncing"?"warn":"bad",e.st??"\u2014"),Wn("nh-v-peers",(e.pc??0)>=15?"ok":(e.pc??0)>=6?"warn":"bad",e.pc!=null?`${e.pc} peers`:"\u2014"),Wn("nh-v-cvg",(e.cvg??0)<4?"ok":(e.cvg??0)<7?"warn":"bad",e.cvg!=null?`${Number(e.cvg).toFixed(1)}s`:"\u2014"),Wn("nh-v-age",(e.age??0)<3?"ok":(e.age??0)<8?"warn":"bad",e.age!=null?`${Number(e.age)}s ago`:"\u2014"),Wn("nh-v-load",(e.lf??1)<2?"ok":(e.lf??1)<5?"warn":"bad",e.lf!=null?`${Number(e.lf).toFixed(2)}\xD7 load`:"\u2014"),Wn("nh-v-nunl",(e.nc??0)===0?"ok":(e.nc??0)<=2?"warn":"bad",e.nc!=null?e.nc===0?"None offline":`${e.nc} offline`:"\u2014");let t=e.q??0,n=e.tc??0,s=n-t;Wn("nh-v-quorum",s>3?"ok":s>0?"warn":"bad",t>0?`${t} required \xB7 margin ${s}`:"\u2014")}function Wn(e,t,n){let s=x(e);s&&(s.textContent=n,s.className=`nh-vval nh-vval--${t}`)}function Vu(e){let t=x("nh-health-checks");if(!t)return;if(!e){t.innerHTML='<div class="hc-disconnected">Connect to an XRPL node to run health checks</div>';return}let{info:n,fee:s,vals:a}=e,i=[{label:"Node State",group:"consensus",icon:"\u2B21",check:()=>{let p=(n==null?void 0:n.server_state)||"unknown",m=["full","proposing","validating"].includes(p),f=p==="syncing"||p==="tracking";return{value:p,status:m?"ok":f?"watch":"alert",note:m?"Participating in consensus":f?"Catching up to network":"Not participating"}}},{label:"Quorum Margin",group:"consensus",icon:"\u2696",check:()=>{var g;let p=((g=a==null?void 0:a.trusted_validator_keys)==null?void 0:g.length)??0,m=(a==null?void 0:a.validation_quorum)??0,f=p-m;return m?{value:`${f} spare`,status:f>3?"ok":f>0?"watch":"alert",note:f>3?`${m} of ${p} needed \u2014 ${f} can go offline safely`:f>0?`Only ${f} validator(s) above quorum \u2014 very tight`:"Below quorum \u2014 consensus may stall"}:{value:"\u2014",status:"watch",note:"Validator data not available"}}},{label:"Negative UNL",group:"consensus",icon:"\u26D4",check:()=>{let p=((n==null?void 0:n.negative_unl)||[]).length;return{value:p===0?"None":`${p} listed`,status:p===0?"ok":p<=2?"watch":"alert",note:p===0?"All UNL validators are online":`${p} validator(s) temporarily excluded from consensus counting`}}},{label:"Ledger Age",group:"consensus",icon:"\u23F1",check:()=>{var m;let p=Number(((m=n==null?void 0:n.validated_ledger)==null?void 0:m.age)??0);return{value:p<2?"< 1s":`${p}s`,status:p<5?"ok":p<10?"watch":"alert",note:p<5?"Ledger closing on schedule (3\u20134s target)":p<10?"Slightly delayed \u2014 network may be busy":"Ledger stalled \u2014 consensus issue likely"}}},{label:"Convergence Time",group:"consensus",icon:"\u{1F504}",check:()=>{var m;let p=Number(((m=n==null?void 0:n.last_close)==null?void 0:m.converge_time_s)??0);return{value:p>0?`${p.toFixed(1)}s`:"\u2014",status:p<4?"ok":p<7?"watch":"alert",note:p<4?"Validators agreeing quickly":p<7?"Slightly slow \u2014 check for network latency":"Slow convergence \u2014 validator disagreement or network partition"}}},{label:"Peer Count",group:"infra",icon:"\u{1F517}",check:()=>{let p=Number((n==null?void 0:n.peers)??0);return{value:`${p} peers`,status:p>=15?"ok":p>=6?"watch":"alert",note:p>=15?"Well-connected to the network":p>=6?"Below recommended (15+) \u2014 consider adding peers":"Critically low \u2014 eclipse attack risk is high"}}},{label:"Load Factor",group:"infra",icon:"\u26A1",check:()=>{let p=Number((n==null?void 0:n.load_factor)??1);return{value:`${p.toFixed(2)}\xD7`,status:p<2?"ok":p<5?"watch":"alert",note:p<2?"Normal load \u2014 node processing freely":p<5?"Elevated load \u2014 fees increasing":"High load \u2014 this node is throttling transactions"}}},{label:"IO Latency",group:"infra",icon:"\u{1F4BE}",check:()=>{let p=Number((n==null?void 0:n.io_latency_ms)??0);return{value:p>0?`${p}ms`:"< 1ms",status:p<2?"ok":p<10?"watch":"alert",note:p<2?"Storage and network I/O responding well":p<10?"Moderate I/O latency \u2014 monitor disk/network":"High I/O latency \u2014 storage or network bottleneck"}}},{label:"Job Queue",group:"infra",icon:"\u{1F4CB}",check:()=>{let p=Number((n==null?void 0:n.jq_trans_overflow)??0);return{value:p===0?"Clear":`${p} overflow`,status:p===0?"ok":"alert",note:p===0?"No transaction job queue overflows":"Queue overflowing \u2014 node is overwhelmed, upgrade resources"}}},{label:"Fee Pressure",group:"ledger",icon:"\u{1F4B8}",check:()=>{var f;let p=Number(((f=s==null?void 0:s.drops)==null?void 0:f.open_ledger_fee)??10),m=p<100?"Minimal":p<500?"Elevated":p<5e3?"High":"Severe";return{value:`${p} drops`,status:p<100?"ok":p<500?"watch":"alert",note:p<100?"Normal transaction fees \u2014 network not congested":p<500?"Fees rising \u2014 moderate network congestion":"High fees \u2014 significant congestion or spam attack"}}},{label:"TX Queue Fill",group:"ledger",icon:"\u{1F5C2}",check:()=>{let p=Number((s==null?void 0:s.current_queue_size)??0),m=Number((s==null?void 0:s.max_queue_size)??1),f=m>0?Math.round(p/m*100):0;return{value:`${f}% (${p}/${m})`,status:f<50?"ok":f<80?"watch":"alert",note:f<50?`Queue at ${f}% \u2014 plenty of headroom`:f<80?`Queue ${f}% full \u2014 fee spike likely soon`:"Queue nearly full \u2014 transactions being dropped"}}}].map(p=>({...p,result:p.check()})),r=i.filter(p=>p.result.status==="ok").length,l=i.filter(p=>p.result.status==="watch").length,c=i.filter(p=>p.result.status==="alert").length,d=x("nh-health-summary");d&&(d.innerHTML=`
      <span class="hcs-count hcs-pass">${r}</span><span class="hcs-lbl">nominal</span>
      <span class="hcs-sep">\xB7</span>
      <span class="hcs-count hcs-warn">${l}</span><span class="hcs-lbl">watch</span>
      <span class="hcs-sep">\xB7</span>
      <span class="hcs-count hcs-fail">${c}</span><span class="hcs-lbl">alert</span>
      <span class="hcs-total">of ${i.length} checks</span>`);let u={consensus:"Consensus Health",infra:"Node Infrastructure",ledger:"Ledger & Fees"};t.innerHTML=Object.entries(u).map(([p,m])=>{let f=i.filter(w=>w.group===p),g=f.map(w=>{let k=w.result.status,$=k==="ok"?"hc-ok":k==="watch"?"hc-warn":"hc-fail",T="\u25CF";return`<div class="hc-item ${$}">
        <div class="hc-item-top">
          <span class="hc-dot" style="background:${k==="ok"?"#50fa7b":k==="watch"?"#ffb86c":"#ff5555"}"></span>
          <span class="hc-label">${y(w.icon)} ${y(w.label)}</span>
          <span class="hc-value">${y(w.result.value)}</span>
        </div>
        <div class="hc-note">${y(w.result.note)}</div>
      </div>`}).join(""),b=f.filter(w=>w.result.status==="ok").length;return`<div class="hc-group ${f.filter(w=>w.result.status==="alert").length>0?"hcg-alert":b===f.length?"hcg-ok":"hcg-watch"}">
      <div class="hc-group-title">${y(m)}
        <span class="hcg-badge">${b}/${f.length}</span>
      </div>
      <div class="hc-group-items">${g}</div>
    </div>`}).join("")}function X0(e){var t,n,s,a,o,i,r,l,c,d;e&&(at("burnDrops",(e.avgFee||0)*1e6*(e.txPerLedger??0)),at("dexOffers",((t=e.txTypes)==null?void 0:t.OfferCreate)??0),at("ammSwaps",(((n=e.txTypes)==null?void 0:n.AMMDeposit)??0)+(((s=e.txTypes)==null?void 0:s.AMMWithdraw)??0)+(((a=e.txTypes)==null?void 0:a.AMMBid)??0)),at("newAccounts",((o=e.txTypes)==null?void 0:o.AccountSet)??0),at("txPayment",((i=e.txTypes)==null?void 0:i.Payment)??0),at("txNFT",(((r=e.txTypes)==null?void 0:r.NFTokenMint)??0)+(((l=e.txTypes)==null?void 0:l.NFTokenBurn)??0)+(((c=e.txTypes)==null?void 0:c.NFTokenCreateOffer)??0)+(((d=e.txTypes)==null?void 0:d.NFTokenAcceptOffer)??0)),at("txLedger",e.txPerLedger??0),at("tps",e.tps??(e.txPerLedger??0)/3.5),at("closeTime",e.closeTime??3.5))}function H0(e){let t=B.tpsHistory.length?B.tpsHistory[B.tpsHistory.length-1]:null;J("m2-tps",t!=null?t.toFixed(1):"\u2014"),J("m2-txcount",e.txPerLedger??"\u2014"),e.successRate!=null&&J("m2-success",`${e.successRate.toFixed(0)}%`)}async function ia({force:e=!1}={}){if(!$s()&&!e)return;let t=Date.now();if(!e&&t-Uu<l0)return;Uu=t;let n=x("latency-list");if(!n)return;let s=Nr[B.currentNetwork]??[],a=++sr;n.innerHTML=s.map((i,r)=>`
    <div class="latency-row lat-pending" id="lat-row-${r}">
      <div class="lat-ep">
        <span class="lat-name">${y(i.name)}</span>
        <span class="lat-url">${y(i.url)}</span>
      </div>
      <div class="lat-bwrap"><div class="lat-bfill" id="lat-bar-${r}" style="width:0%"></div></div>
      <span class="lat-val" id="lat-val-${r}">\u2014</span>
    </div>`).join("");let o=x("btn-ping-all");o&&(o.disabled=!0);try{for(let i=0;i<s.length;i++){if(a!==sr)return;await z0(s[i],i),await J0(c0)}}finally{a===sr&&o&&(o.disabled=!1)}}async function z0(e,t){var i;let n=x(`lat-val-${t}`),s=x(`lat-bar-${t}`),a=x(`lat-row-${t}`);a==null||a.classList.remove("lat-pending"),a==null||a.classList.add("lat-probing"),n&&(n.innerHTML='<span class="spinner"></span>');let o=performance.now();try{let r=new WebSocket(e.url);await new Promise((d,u)=>{let p=setTimeout(()=>u(),r0);r.onopen=()=>{clearTimeout(p),d()},r.onerror=()=>{clearTimeout(p),u()}});let l=Math.round(performance.now()-o);try{r.close()}catch{}let c=l<100?"lat-fast":l<300?"lat-med":"lat-slow";n&&(n.textContent=`${l}ms`,n.className=`lat-val ${c}`),s&&(s.style.width=`${Math.min(100,l/600*100)}%`),a==null||a.classList.toggle("lat-active",((i=B.wsConn)==null?void 0:i.url)===e.url)}catch{n&&(n.textContent="timeout",n.className="lat-val lat-slow")}finally{a==null||a.classList.remove("lat-probing")}}function W0(){if(document.getElementById("vg-tab-styles"))return;let e=document.createElement("style");e.id="vg-tab-styles",e.textContent=`
    /* \u2500\u2500 Validator grid layout \u2500\u2500 */
    .vg-tabs { display:flex; gap:4px; flex-wrap:wrap; margin-bottom:10px; padding-bottom:8px; border-bottom:1px solid rgba(255,255,255,.07); }
    .vg-tab {
      padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600;
      cursor: pointer; background: transparent;
      border: 1px solid rgba(255,255,255,.18); color: rgba(255,255,255,.6);
      transition: background .15s, color .15s, border-color .15s; white-space: nowrap;
    }
    .vg-tab:hover  { background: rgba(255,255,255,.06); color: #fff; }
    .vg-tab--active { background: rgba(0,255,240,.12); border-color: rgba(0,255,240,.5); color: #00fff0; }

    .vpill.vp-both  .vpdot { background: #50fa7b; box-shadow: 0 0 6px rgba(80,250,123,.6); }
    .vpill.vp-dunl  .vpdot { background: #bd93f9; box-shadow: 0 0 6px rgba(189,147,249,.6); }
    .vpill.vp-other .vpdot { background: #ffb86c; box-shadow: 0 0 6px rgba(255,184,108,.6); }

    .vntag-cat {
      font-size: 10px; padding: 1px 6px; border-radius: 10px;
      border: 1px solid rgba(255,255,255,.2); color: rgba(255,255,255,.6);
      background: rgba(255,255,255,.04);
    }
    .vp-both  .vntag-cat { border-color: rgba(80,250,123,.4);  color: #50fa7b; }
    .vp-dunl  .vntag-cat { border-color: rgba(189,147,249,.4); color: #bd93f9; }
    .vp-nunl  .vntag-cat { border-color: rgba(255,85,85,.4);   color: #ff5555; }
    .vp-other .vntag-cat { border-color: rgba(255,184,108,.4); color: #ffb86c; }
    .vp-unl   .vntag-cat { border-color: rgba(0,255,240,.4);   color: #00fff0; }

    /* \u2500\u2500 Validator grid sections \u2500\u2500 */
    .vg-section { margin-bottom: 6px; border: 1px solid rgba(255,255,255,.07); border-radius: 8px; overflow: hidden; }
    .vg-section.vgs-warn { border-color: rgba(255,85,85,.3); }
    .vg-section-hdr {
      width:100%; display:flex; align-items:center; gap:8px;
      padding:7px 10px; background:rgba(255,255,255,.03);
      border:none; cursor:pointer; color:rgba(255,255,255,.75);
      font-size:11px; font-weight:600; text-align:left;
      transition: background .15s;
    }
    .vg-section-hdr:hover { background:rgba(255,255,255,.06); }
    .vg-chevron { font-size:9px; opacity:.5; min-width:10px; }
    .vg-sec-title { flex:1; }
    .vg-section-body { display:flex; flex-wrap:wrap; gap:5px; padding:8px; }
    .vg-num {
      font-size:10px; font-weight:700; min-width:18px; text-align:center;
      color:rgba(255,255,255,.35); flex-shrink:0;
    }
    .vg-agr { font-size:10px; font-weight:700; }
    .vg-tab-dot { display:inline-block; width:7px; height:7px; border-radius:50%; margin-right:3px; vertical-align:middle; }
    .vg-tab-count {
      background:rgba(255,255,255,.1); border-radius:10px;
      font-size:10px; padding:0px 5px; margin-left:3px;
    }
    .vg-tab--active .vg-tab-count { background:rgba(0,255,240,.15); }
    .vp-geo { font-size:10px; opacity:.7; }

    /* \u2500\u2500 Congestion summary card \u2500\u2500 */
    .cong-line  { display:flex; align-items:flex-start; gap:8px; font-size:12px; padding:4px 0; border-bottom:1px solid rgba(255,255,255,.04); }
    .cong-clear { font-size:12px; padding:6px 0; }
    /* Pressure badge colours */
    .p-severe   { background:rgba(255,85,85,.15);   color:#ff5555; border-color:rgba(255,85,85,.3)   !important; }
    .p-high     { background:rgba(255,153,85,.12);  color:#ff9955; border-color:rgba(255,153,85,.3)  !important; }
    .p-elevated { background:rgba(255,184,108,.10); color:#ffb86c; border-color:rgba(255,184,108,.3) !important; }
    .p-normal   { background:rgba(80,250,123,.08);  color:#50fa7b; border-color:rgba(80,250,123,.25) !important; }
    .p-minimal  { background:rgba(98,114,164,.10);  color:#6272a4; border-color:rgba(98,114,164,.2)  !important; }

    /* \u2500\u2500 Health banner grade variants \u2500\u2500 */
    .nh-banner.nh-warn .nh-score-num { color:#ff9955; }

        /* Registry status badge */
    .registry-badge {
      display: inline-block; font-size: 11px; padding: 2px 8px; border-radius: 10px;
      margin-left: 8px; vertical-align: middle;
    }
    .registry-badge--ok   { background: rgba(80,250,123,.12); border: 1px solid rgba(80,250,123,.3); color: #50fa7b; }
    .registry-badge--warn { background: rgba(255,184,108,.10); border: 1px solid rgba(255,184,108,.3); color: #ffb86c; }

    /* \u2500\u2500 Quorum Ring \u2500\u2500 */
    .qr-wrap    { display:flex; align-items:center; gap:16px; padding:8px 0; }
    .qr-legend  { display:flex; flex-direction:column; gap:5px; flex:1; }
    .qr-leg-row { display:flex; align-items:center; gap:7px; font-size:11px; }
    .qr-dot     { width:9px; height:9px; border-radius:50%; flex-shrink:0; }

    /* \u2500\u2500 Amendment Pipeline tabs \u2500\u2500 */
    .ap-tabs { display:flex; gap:4px; flex-wrap:wrap; margin-bottom:8px; }
    .ap-tab {
      padding:3px 10px; border-radius:16px; font-size:11px; font-weight:600;
      cursor:pointer; background:transparent; border:1px solid rgba(255,255,255,.15);
      color:rgba(255,255,255,.5); transition:all .15s;
    }
    .ap-tab:hover { background:rgba(255,255,255,.05); color:#fff; }
    .ap-tab--active { background:rgba(0,255,240,.1); border-color:rgba(0,255,240,.4); color:#00fff0; }
    .ap-tab-count { font-size:9px; padding:1px 5px; border-radius:8px; background:rgba(255,255,255,.08); margin-left:3px; }
    .ap-alert-bar { font-size:11px; color:#ffb86c; background:rgba(255,184,108,.08); border:1px solid rgba(255,184,108,.2); border-radius:6px; padding:5px 10px; margin-bottom:6px; }
    .ap-near-bar  { font-size:11px; color:#8be9fd; background:rgba(139,233,253,.06); border:1px solid rgba(139,233,253,.2); border-radius:6px; padding:5px 10px; margin-bottom:6px; }
    .ap-row {
      padding:9px 12px; border-radius:7px; cursor:pointer;
      border:1px solid rgba(255,255,255,.06); margin-bottom:5px;
      background:rgba(255,255,255,.02); transition:background .15s;
    }
    .ap-row:hover { background:rgba(255,255,255,.05); }
    .ap-row-top { display:flex; align-items:center; gap:8px; margin-bottom:3px; }
    .ap-name { font-size:13px; font-weight:600; flex:1; color:rgba(255,255,255,.9); }
    .ap-status-tag { font-size:10px; padding:2px 7px; border-radius:10px; border:1px solid; flex-shrink:0; }
    .ap-purpose { font-size:11px; opacity:.55; margin-bottom:6px; }
    .ap-active-note { font-size:11px; color:#50fa7b; opacity:.8; }
    .ap-vote-row { display:flex; align-items:center; gap:8px; margin-top:5px; }
    .ap-vote-track { flex:1; height:5px; background:rgba(255,255,255,.07); border-radius:3px; overflow:visible; position:relative; }
    .ap-vote-fill { height:100%; border-radius:3px; transition:width .4s; }
    .ap-vote-thresh { position:absolute; left:80%; top:-3px; bottom:-3px; width:2px; background:rgba(255,255,255,.3); border-radius:1px; }
    .ap-vote-label { font-size:11px; opacity:.6; white-space:nowrap; }
    .ap-countdown { margin-top:6px; }
    .ap-countdown-lbl { font-size:10px; color:#ffb86c; display:block; margin-bottom:3px; }
    .ap-countdown-track { height:3px; background:rgba(255,255,255,.07); border-radius:2px; overflow:hidden; }
    .ap-countdown-fill  { height:100%; background:#ffb86c; border-radius:2px; transition:width .5s; }

    /* \u2500\u2500 Health check matrix \u2500\u2500 */
    .hc-item { padding:8px 10px; border-radius:6px; margin-bottom:4px; background:rgba(255,255,255,.02); border:1px solid rgba(255,255,255,.05); }
    .hc-item-top { display:flex; align-items:center; gap:8px; margin-bottom:3px; }
    .hc-dot  { width:8px; height:8px; border-radius:50%; flex-shrink:0; }
    .hc-label { font-size:12px; font-weight:600; flex:1; }
    .hc-value { font-size:11px; font-weight:700; font-family:monospace; opacity:.85; }
    .hc-note  { font-size:10px; opacity:.5; padding-left:16px; line-height:1.4; }
    .hc-ok   { border-color:rgba(80,250,123,.15); }
    .hc-warn { border-color:rgba(255,184,108,.15); }
    .hc-fail { border-color:rgba(255,85,85,.2); }
    .hc-group { margin-bottom:12px; }
    .hc-group-title { font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:.08em; opacity:.5; margin-bottom:6px; display:flex; align-items:center; gap:8px; }
    .hcg-badge { background:rgba(255,255,255,.08); border-radius:8px; padding:1px 6px; font-size:9px; font-weight:600; }
    .hcg-ok    .hcg-badge { background:rgba(80,250,123,.15); color:#50fa7b; }
    .hcg-alert .hcg-badge { background:rgba(255,85,85,.15);  color:#ff5555; }
    .hcg-watch .hcg-badge { background:rgba(255,184,108,.15);color:#ffb86c; }
    .hc-disconnected { opacity:.4; font-size:12px; padding:16px; text-align:center; }

    /* \u2500\u2500 Adversarial Signal Monitor \u2500\u2500 */
    .adv-clear-card { display:flex; align-items:center; gap:12px; padding:14px; border-radius:8px; background:rgba(80,250,123,.05); border:1px solid rgba(80,250,123,.15); }
    .adv-clear-icon { font-size:22px; color:#50fa7b; }
    .adv-clear-title { font-size:14px; font-weight:700; color:#50fa7b; }
    .adv-clear-sub   { font-size:11px; opacity:.6; margin-top:2px; }
    .adv-group-title { font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:.07em; margin:10px 0 5px; }
    .adv-sig-card { padding:8px 10px; border-radius:6px; margin-bottom:4px; border:1px solid; }
    .adv-sig-critical { border-color:rgba(255,85,85,.25);  background:rgba(255,85,85,.04); }
    .adv-sig-elevated  { border-color:rgba(255,184,108,.2); background:rgba(255,184,108,.04); }
    .adv-sig-monitor  { border-color:rgba(139,233,253,.15); background:rgba(139,233,253,.03); }
    .adv-sig-top   { display:flex; align-items:center; gap:8px; }
    .adv-sig-dot   { width:7px; height:7px; border-radius:50%; flex-shrink:0; }
    .adv-sig-title { font-size:12px; font-weight:600; flex:1; }
    .adv-sig-badge { font-size:9px; padding:1px 5px; border-radius:8px; border:1px solid; }
    .adv-sig-detail { font-size:10px; opacity:.55; margin-top:4px; padding-left:15px; line-height:1.4; }
    .adv-hist-row { display:flex; align-items:center; gap:8px; padding:4px 0; border-bottom:1px solid rgba(255,255,255,.04); font-size:11px; }
    .adv-hist-active   .adv-hist-dot { background:#ffb86c; }
    .adv-hist-resolved .adv-hist-dot { background:rgba(255,255,255,.2); }
    .adv-hist-dot { width:6px; height:6px; border-radius:50%; flex-shrink:0; }
    .adv-hist-lbl  { flex:1; opacity:.7; }
    .adv-hist-time { font-size:10px; opacity:.5; white-space:nowrap; }
    .adv-hist-tag-active   { background:rgba(255,184,108,.15); color:#ffb86c; border-radius:6px; padding:1px 5px; font-size:9px; margin-left:4px; }
    .adv-hist-tag-res      { background:rgba(80,250,123,.1);   color:#50fa7b; border-radius:6px; padding:1px 5px; font-size:9px; margin-left:4px; }
  `,document.head.appendChild(e)}function U0(){if(document.getElementById("m4-panel"))return;let e=[()=>document.querySelector('[data-section="fee-market"]'),()=>document.querySelector('[data-section="infrastructure"]'),()=>document.querySelector("#tab-network .section-grid"),()=>document.querySelector("#tab-network"),()=>document.body],t=null;for(let a of e)if(t=a(),t)break;if(!t)return;t.insertAdjacentHTML("beforeend",`
  <!-- \u2500\u2500 Decentralization Panel \u2500\u2500 -->
  <div id="m4-panel" class="net-panel" style="margin-top:12px">
    <div class="net-panel-header">
      <span class="net-panel-title">\u{1F310} Decentralization Metrics</span>
      <span class="net-panel-sub">Version distribution \xB7 geographic spread \xB7 provider concentration</span>
    </div>
    <div class="net-panel-body">
      <div class="m4-grid">

        <div class="m4-col">
          <div class="np-section-title">Validator Versions</div>
          <div id="m4-version-dist" class="vd-list">
            <span style="opacity:.4;font-size:12px">Loading registry\u2026</span>
          </div>
        </div>

        <div class="m4-col">
          <div class="np-section-title">Geographic Distribution</div>
          <div id="m4-geo-dist" class="vd-list">
            <span style="opacity:.4;font-size:12px">Loading\u2026</span>
          </div>
        </div>

        <div class="m4-col">
          <div class="np-section-title">Provider Concentration</div>
          <div class="np-section-sub">\u26A0 bars &gt; 33% indicate single-provider risk</div>
          <div id="m4-provider-dist" class="vd-list">
            <span style="opacity:.4;font-size:12px">Loading\u2026</span>
          </div>
        </div>

      </div>
    </div>
  </div>`);let s=document.createElement("style");s.id="net-panel-styles",s.textContent=`
    /* \u2500\u2500 Network Panels \u2500\u2500 */
    .net-panel {
      background: rgba(255,255,255,.025);
      border: 1px solid rgba(255,255,255,.07);
      border-radius: 12px;
      overflow: hidden;
      margin-bottom: 12px;
    }
    .net-panel-header {
      display: flex; align-items: center; gap: 10px;
      padding: 12px 16px;
      border-bottom: 1px solid rgba(255,255,255,.06);
      background: rgba(255,255,255,.02);
    }
    .net-panel-title { font-size: 14px; font-weight: 700; color: rgba(255,255,255,.9); }
    .net-panel-sub   { font-size: 11px; opacity: .5; }
    .net-panel-body  { padding: 16px; }

    /* Section titles */
    .np-section-title { font-size: 11px; font-weight: 600; opacity: .6; text-transform: uppercase; letter-spacing: .07em; margin-bottom: 8px; }
    .np-section-sub   { font-size: 10px; opacity: .45; margin-bottom: 6px; margin-top: -4px; }

    /* TX breakdown */
    .np-tx-list { display: flex; flex-direction: column; gap: 5px; }
    .np-tx-row  { display: grid; grid-template-columns: 80px 1fr 100px; align-items: center; gap: 8px; }
    .np-tx-label { font-size: 12px; font-weight: 600; }
    .np-tx-bar-wrap { height: 6px; background: rgba(255,255,255,.06); border-radius: 3px; overflow: hidden; }
    .np-tx-cnt { font-size: 11px; opacity: .7; text-align: right; }

    /* Supply grid */

    /* Decentralization m4 grid */
    .m4-grid { display: grid; grid-template-columns: repeat(3,1fr); gap: 14px; }
    @media (max-width: 800px) { .m4-grid { grid-template-columns: 1fr 1fr; } }
    @media (max-width: 500px) { .m4-grid { grid-template-columns: 1fr; } }
    .m4-col {}

    /* Version/geo distribution bars */
    .vd-list    { display: flex; flex-direction: column; gap: 6px; }
    .vd-row     { display: grid; grid-template-columns: 110px 1fr 70px; align-items: center; gap: 8px; }
    .vd-ver-label { font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .vd-bar-wrap  { height: 6px; background: rgba(255,255,255,.07); border-radius: 3px; overflow: hidden; }
    .vd-bar-fill  { height: 100%; border-radius: 3px; transition: width .5s; }
    .vd-count     { font-size: 11px; opacity: .65; text-align: right; white-space: nowrap; }
    .vd-summary   { font-size: 10px; opacity: .45; margin-top: 8px; border-top: 1px solid rgba(255,255,255,.05); padding-top: 6px; }
    .vd-beta-tag  { font-size: 9px; padding: 1px 5px; background: rgba(255,184,108,.15); color: #ffb86c; border-radius: 8px; border: 1px solid rgba(255,184,108,.3); margin-left: 4px; }
  `,document.getElementById("net-panel-styles")||document.head.appendChild(s)}function at(e,t){mt[e]||(mt[e]=[]),mt[e].push(Number(t)),mt[e].length>d0&&mt[e].shift()}function la(e){let t=mt[e]??[];return t.length?t.reduce((n,s)=>n+s,0)/t.length:0}function j0(e){if(e.length<2)return 0;let t=e.reduce((n,s)=>n+s,0)/e.length;return Math.sqrt(e.reduce((n,s)=>n+(s-t)**2,0)/e.length)}function q0(){try{let e=localStorage.getItem(Gu);if(!e)return;let t=JSON.parse(e);Object.keys(mt).forEach(n=>{Array.isArray(t[n])&&(mt[n]=t[n])})}catch{}}function V0(){try{localStorage.setItem(Gu,JSON.stringify(mt))}catch{}}function J(e,t){let n=x(e);n&&(n.textContent=t??"\u2014")}function Tt(e,t,n){let s=x(e);s&&(s.style.width=`${Math.min(100,Math.max(0,Number(t)||0))}%`,s.className=`bar-fill ${n??""}`)}function G0(e){if(!e)return 0;let t=e.match(/(\d+)-(\d+)/);if(!t)return 10;let n=Number(t[2])-Number(t[1]);return n>1e7?95:n>1e6?70:n>1e5?40:15}function K0(e){if(!e)return"\u2014";let t=Math.floor(e/86400),n=Math.floor(e%86400/3600),s=Math.floor(e%3600/60);return t>0?`${t}d ${n}h`:n>0?`${n}h ${s}m`:`${s}m`}function J0(e){return new Promise(t=>setTimeout(t,e))}var Y0={"xrpl-ledger":{title:"XRPL Ledger",subtitle:"What a ledger is, what validated means, and how to interpret ledger snapshots.",sections:[{heading:"In simple terms",paragraphs:["Think of the XRP Ledger (XRPL) as a public spreadsheet that the whole network agrees on.","A \u201Cledger version\u201D is one snapshot of that spreadsheet: balances, trustlines, offers, AMMs, and more.","When a ledger becomes \u201Cvalidated\u201D, it\u2019s final\u2014analytics based on validated ledgers reflect settled history."],bullets:["Ledger Index = the ledger number (sequence).","Ledger Hash = fingerprint of that ledger\u2019s contents.","Open \u2192 Closed \u2192 Validated = in-progress \u2192 proposed snapshot \u2192 final snapshot."]},{heading:"How NaluLF uses this",paragraphs:["NaluLF listens to validated ledger events, then summarizes what changed and what patterns are emerging.","You can quickly see dominant transaction types, fee pressure, DEX/AMM bursts, and concentration signals."],bullets:["Live stream cards summarize each ledger close.","Narratives turn raw changes into readable reporting.","Signals are heuristics (useful indicators, not proof)."]}],links:[{label:"XRPL Docs: Ledgers (overview)",url:"https://xrpl.org/docs/concepts/ledgers"},{label:"Open / Closed / Validated Ledgers",url:"https://xrpl.org/docs/concepts/ledgers/open-closed-validated-ledgers"},{label:"Ledger Structure",url:"https://xrpl.org/docs/concepts/ledgers/ledger-structure"},{label:"Ledger Header (hash/index basics)",url:"https://xrpl.org/docs/references/protocol/ledger-data/ledger-header"}],ctas:[{label:"Launch Dashboard \u2192",action:"auth:signup"},{label:"Close",action:"modal:close"}]},"accounts-trustlines":{title:"Accounts, Reserves, and Trustlines",subtitle:"How addresses work, why reserves exist, and what trustlines mean for tokens.",sections:[{heading:"In simple terms",paragraphs:["An XRPL account is a public address with a balance and settings (flags).","Reserves exist to prevent ledger spam: certain objects (offers, trustlines, signer lists) require reserved XRP.","Trustlines are \u201Cpermission slips\u201D that prevent you from receiving random issued tokens you didn\u2019t opt into."],bullets:["Reserves: base reserve + owner reserve for certain objects.","Trustlines: define limits and balances for issued tokens.","Flags/settings: control behaviors like Deposit Authorization."]},{heading:"Why this matters for investigations",paragraphs:["During compromises, account settings and objects can change quickly.","Trustlines and offers can reveal what tokens/markets are being targeted."],bullets:["Inspector helps you read balances, flags, and trustlines.","Reserve signals can hint at heavy offer/trustline usage."]}],links:[{label:"AccountRoot (ledger entry)",url:"https://xrpl.org/docs/references/protocol/ledger-data/ledger-entry-types/accountroot"},{label:"Reserves (why they exist)",url:"https://xrpl.org/docs/concepts/accounts/reserves"},{label:"Trust Line Tokens (concept)",url:"https://xrpl.org/docs/concepts/tokens/fungible-tokens/trust-line-tokens"},{label:"account_lines API (trustlines)",url:"https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_lines"},{label:"Deposit Authorization (DepositAuth)",url:"https://xrpl.org/docs/concepts/accounts/depositauth"},{label:"XRPL: Cryptographic Keys",url:"https://xrpl.org/docs/concepts/accounts/cryptographic-keys"}],ctas:[{label:"Inspect an Address \u2192",action:"auth:login"},{label:"Close",action:"modal:close"}]},"dex-amm":{title:"DEX, Offers, and AMMs",subtitle:"How trading works on XRPL and how AMM liquidity moves show up on-ledger.",sections:[{heading:"How XRPL trading works",paragraphs:["XRPL has a built-in decentralized exchange (DEX). People place \u201Coffers\u201D (limit orders) to trade between XRP and tokens, or token-to-token.","AMMs (Automated Market Makers) hold pools of two assets. Liquidity providers deposit/withdraw and traders swap against the pool."],bullets:["OfferCreate = place an order (limit order).","OfferCancel = remove an order (may still succeed even if nothing cancels).","AMMCreate/Deposit/Withdraw = liquidity lifecycle signals."]},{heading:"Manipulation signals (heuristics)",paragraphs:["On-ledger \u201Cspoofing\u201D isn\u2019t identical to centralized exchanges, but suspicious churn can still stand out.","Rapid OfferCreate/OfferCancel bursts, concentrated actors, and repeated short-lived behavior can indicate bot-driven or staged activity."],bullets:["Offer churn: creates vs cancels intensity.","Concentration: whether a small set of accounts dominates.","AMM bursts: sudden waves of deposits/withdraws."]}],links:[{label:"DEX (concept)",url:"https://xrpl.org/docs/concepts/tokens/decentralized-exchange"},{label:"Offers (concept)",url:"https://xrpl.org/docs/concepts/tokens/decentralized-exchange/offers"},{label:"OfferCreate (tx type)",url:"https://xrpl.org/docs/references/protocol/transactions/types/offercreate"},{label:"OfferCancel (tx type)",url:"https://xrpl.org/docs/references/protocol/transactions/types/offercancel"},{label:"AMMs (concept)",url:"https://xrpl.org/docs/concepts/tokens/decentralized-exchange/automated-market-makers"},{label:"book_offers API (order book)",url:"https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/path-and-order-book-methods/book_offers"}],ctas:[{label:"Launch Dashboard \u2192",action:"auth:signup"},{label:"Close",action:"modal:close"}]},"security-drains":{title:"Wallet Safety + Compromise Response (Defensive)",subtitle:"How to read suspicious patterns safely and what to watch for during incident response.",sections:[{heading:"What a \u201Cdrain\u201D usually means",paragraphs:["A wallet drain typically follows a compromise: stolen keys, malicious signing requests, phishing, or unsafe approvals.","NaluLF is designed for defensive investigation and monitoring\u2014NOT for unauthorized access or theft."],bullets:["Watch for sudden outbound bursts from a previously quiet account.","Look for new trustlines/offers right before the loss.","Check transaction result codes and whether actions are validated."]},{heading:"How NaluLF helps (defensive)",paragraphs:["Inspect the address, review counterparties, and watch for repeated interactions or suspicious churn.","Use narratives to communicate what changed and what to check next."],bullets:["Inspector: balances, trustlines, flags, reserve signals.","Breadcrumbs: repeating \u201Cwho touches who\u201D pairs.","Signals: concentration + churn + bot-like timing proxies."]}],links:[{label:"XRPL Learning: Security Best Practices",url:"https://learn.xrpl.org/lesson/security-best-practices-for-xrp/"},{label:"XRPL Learning: DeFi Security 101",url:"https://learn.xrpl.org/course/blockchain-for-business/lesson/defi-security-101-staying-safe-in-the-new-decentralized-world/"},{label:"XRPL: Secure Signing",url:"https://xrpl.org/docs/concepts/transactions/secure-signing"},{label:"Transaction Results",url:"https://xrpl.org/docs/references/protocol/transactions/transaction-results"},{label:"tesSUCCESS",url:"https://xrpl.org/docs/references/protocol/transactions/transaction-results/tes-success"}],ctas:[{label:"Inspect an Address \u2192",action:"auth:login"},{label:"Close",action:"modal:close"}]},"bots-data":{title:"Bots on the Data (Monitoring / Alerts)",subtitle:"How to build legit automation on top of public XRPL data.",sections:[{heading:"What to automate",paragraphs:["XRPL is public, so you can build monitoring bots for events: whale payments, DEX churn spikes, AMM liquidity changes, or sudden flag updates.","Good bots explain what they saw and provide confidence/validation steps."],bullets:["Use WebSocket subscriptions for live events.","Use API methods for snapshots (account_info, account_lines, book_offers).","Treat signals as indicators and confirm with multiple checks."]},{heading:"How NaluLF fits",paragraphs:["NaluLF is the \u201Chuman dashboard\u201D to validate what the bot flags.","You can click addresses (breadcrumbs/clusters) and open Inspector for context."],bullets:["Bots: alerting, reporting, research, and risk monitoring.","Not for unauthorized access."]}],links:[{label:"subscribe (WebSocket)",url:"https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/subscription-methods/subscribe"},{label:"Monitor Incoming Payments (tutorial)",url:"https://xrpl.org/docs/tutorials/http-websocket-apis/build-apps/monitor-incoming-payments-with-websocket"},{label:"account_info API",url:"https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_info"},{label:"account_lines API",url:"https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_lines"},{label:"book_offers API",url:"https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/path-and-order-book-methods/book_offers"}],ctas:[{label:"Launch Dashboard \u2192",action:"auth:signup"},{label:"Close",action:"modal:close"}]},"crypto-basics":{title:"Crypto Basics: Keys + Signing",subtitle:"Why keys matter, what signing does, and why validated actions are final.",sections:[{heading:"Key concepts",paragraphs:["Your private key proves ownership. If someone has it, they can sign actions as you.","A digital signature is a tamper-proof stamp: the network can verify it, but nobody can forge it without the private key.","This is why phishing is so dangerous: a valid signature is usually final once validated."],bullets:["Public key: shareable.","Private key: never share.","Hashing: detects tampering."]}],links:[{label:"XRPL: Cryptographic Keys",url:"https://xrpl.org/docs/concepts/accounts/cryptographic-keys"},{label:"XRPL: Secure Signing",url:"https://xrpl.org/docs/concepts/transactions/secure-signing"},{label:"Cloudflare: Public key cryptography",url:"https://www.cloudflare.com/learning/ssl/how-does-public-key-encryption-work/"},{label:"Cloudflare: What is a cryptographic key?",url:"https://www.cloudflare.com/learning/ssl/what-is-a-cryptographic-key/"}],ctas:[{label:"Close",action:"modal:close"}]},"about-naluxrp":{title:"What is NaluLF?",subtitle:"Client-only XRPL forensic & analytics suite: readable reporting + manipulation signals + investigation workflow.",sections:[{heading:"The goal",paragraphs:["NaluLF turns raw ledger firehose data into something you can understand quickly:","what happened, who seems involved, what changed, and what looks unusual."],bullets:["Live stream: what the network is doing right now.","Inspector: what\u2019s going on with this address.","Signals: what looks unusual or coordinated (heuristics)."]},{heading:"How it helps defenders",paragraphs:["When investigating suspicious activity (compromises, scams, wash-like churn), you need context fast.","NaluLF helps you gather data, pivot between entities, and produce a clear report of what the ledger shows."],bullets:["Pattern windows (repeat pairs, cluster-like co-activity).","DEX churn signals (OfferCreate/Cancel intensity + concentration).","AMM/LP bursts (deposit/withdraw waves)."]},{heading:"Ethics",paragraphs:["Designed for defensive monitoring, research, and investigations.","Not for stealing funds or unauthorized access."]}],links:[{label:"XRPL Docs: Transactions",url:"https://xrpl.org/docs/concepts/transactions"},{label:"XRPL Docs: DEX",url:"https://xrpl.org/docs/concepts/tokens/decentralized-exchange"},{label:"XRPL Docs: AMMs",url:"https://xrpl.org/docs/concepts/tokens/decentralized-exchange/automated-market-makers"},{label:"XRPL Learning: Scam safety checklist",url:"https://learn.xrpl.org/blog/safeguarding-your-crypto-wallet-your-essential-checklist-against-defi-scams/"}],ctas:[{label:"Launch Dashboard \u2192",action:"auth:signup"},{label:"Close",action:"modal:close"}]}},Q0=[{icon:"\u{1F4D8}",title:"XRPL Ledgers",body:"Ledgers, validation, and indices.",topic:"xrpl-ledger"},{icon:"\u{1F464}",title:"Accounts",body:"Balances, reserves, flags, and keys.",topic:"accounts-trustlines"},{icon:"\u{1FA99}",title:"Trustlines",body:"Token safety model on XRPL.",topic:"accounts-trustlines"},{icon:"\u{1F501}",title:"DEX + Offers",body:"OfferCreate/Cancel + churn signals.",topic:"dex-amm"},{icon:"\u{1F4A7}",title:"AMMs / LPs",body:"Liquidity lifecycle and bursts.",topic:"dex-amm"},{icon:"\u{1F6E1}\uFE0F",title:"Security",body:"Defensive investigation workflow.",topic:"security-drains"}],Z0=[{icon:"\u{1F6E1}\uFE0F",title:"NaluLF Overview",desc:"What the app does, how it helps investigations, and what signals mean.",topic:"about-naluxrp"},{icon:"\u{1F4D8}",title:"XRPL Ledger",desc:"Ledgers, validated finality, and how to interpret snapshots.",topic:"xrpl-ledger"},{icon:"\u{1F464}",title:"Accounts + Trustlines",desc:"Reserves, flags, and trustline fundamentals for tokens.",topic:"accounts-trustlines"},{icon:"\u{1F501}",title:"DEX / Offers / AMMs",desc:"Trading primitives + what churn signals can indicate.",topic:"dex-amm"},{icon:"\u{1F9EF}",title:"Compromise Response",desc:"How to read suspicious flows defensively and safely.",topic:"security-drains"},{icon:"\u{1F916}",title:"Bots + Monitoring",desc:"Legit automation ideas using public XRPL data + validation steps.",topic:"bots-data"},{icon:"\u{1F510}",title:"Keys + Signing",desc:"Why signatures matter and how to stay safe.",topic:"crypto-basics"}],ew=[{num:1,title:"Learn the ecosystem with real sources",body:"Open learning cards with detailed explanations and trusted references.",topic:"xrpl-ledger"},{num:2,title:"Investigate suspicious wallet activity (defensive)",body:"Inspector + counterparties + patterns to build a clear timeline.",topic:"security-drains"},{num:3,title:"Monitor DEX/AMM churn for anomaly signals",body:"OfferCreate/Cancel bursts, concentration, and LP waves.",topic:"dex-amm"},{num:4,title:"Build monitoring bots on public data",body:"Subscriptions + APIs for alerts, reporting, and research.",topic:"bots-data"}],rm=!1;function tw(){if(document.getElementById("learnModalOverlay"))return;let e=document.createElement("div");e.id="learnModalOverlay",e.className="learn-modal-overlay",e.innerHTML=`
    <div class="learn-modal" role="dialog" aria-modal="true" aria-labelledby="learnModalTitle">
      <button class="learn-close" type="button" data-action="modal:close" aria-label="Close">\u2715</button>
      <div class="learn-head">
        <div class="learn-title" id="learnModalTitle"></div>
        <div class="learn-sub" id="learnModalSub"></div>
      </div>
      <div class="learn-body" id="learnModalBody"></div>
      <div class="learn-links-wrap">
        <div class="learn-links-title">Learning sources</div>
        <div class="learn-links" id="learnModalLinks"></div>
      </div>
      <div class="learn-cta-row" id="learnModalCtas"></div>
    </div>
  `,document.body.appendChild(e),e.addEventListener("click",t=>{t.target===e&&ca()}),document.addEventListener("keydown",t=>{t.key==="Escape"&&e.classList.contains("show")&&ca()})}function nw(e){let t=Y0[e];if(!t)return;tw();let n=document.getElementById("learnModalOverlay"),s=document.getElementById("learnModalTitle"),a=document.getElementById("learnModalSub"),o=document.getElementById("learnModalBody"),i=document.getElementById("learnModalLinks"),r=document.getElementById("learnModalCtas");!n||!s||!a||!o||!i||!r||(s.textContent=t.title,a.textContent=t.subtitle||"",o.innerHTML=(t.sections||[]).map(l=>`
    <section class="learn-sec">
      <h4>${y(l.heading||"")}</h4>
      ${(l.paragraphs||[]).map(c=>`<p>${y(c)}</p>`).join("")}
      ${l.bullets&&l.bullets.length?`<ul>${l.bullets.map(c=>`<li>${y(c)}</li>`).join("")}</ul>`:""}
    </section>
  `).join(""),i.innerHTML=(t.links||[]).map(l=>`
    <a class="learn-link" href="${y(l.url)}" target="_blank" rel="noopener noreferrer">
      ${y(l.label)}
      <span aria-hidden="true">\u2197</span>
    </a>
  `).join(""),r.innerHTML=(t.ctas||[]).map(l=>`
    <button class="learn-cta ${l.action==="auth:signup"?"primary":""}" type="button" data-action="${y(l.action)}">
      ${y(l.label)}
    </button>
  `).join(""),n.classList.add("show"),document.body.classList.add("modal-open"))}function ca(){var e;(e=document.getElementById("learnModalOverlay"))==null||e.classList.remove("show"),document.body.classList.remove("modal-open")}function sw(e){var t,n,s;if(e==="modal:close")return ca();if(e==="auth:signup"){ca(),(t=window.openAuth)==null||t.call(window,"signup");return}if(e==="auth:login"){ca(),(n=window.openAuth)==null||n.call(window,"login");return}if(e.startsWith("topic:"))return nw(e.split(":")[1]);if(e.startsWith("scroll:")){let a=e.split(":")[1];(s=document.getElementById(a))==null||s.scrollIntoView({behavior:"smooth",block:"start"})}}function aw(){rm||(rm=!0,document.addEventListener("click",e=>{var s,a;let t=(a=(s=e.target).closest)==null?void 0:a.call(s,"[data-action]");if(!t)return;let n=t.getAttribute("data-action")||"";n&&(e.preventDefault(),sw(n))}))}function lm(){var l,c,d,u,p;aw(),(l=document.querySelector(".landing-features"))==null||l.setAttribute("id","learn"),(c=document.querySelector(".landing-simple-value"))==null||c.setAttribute("id","use-cases"),(d=document.querySelector(".landing-cta"))==null||d.setAttribute("id","about"),(u=document.querySelector(".landing-tagline"))==null||u.classList.add("tagline-pill");let e=document.querySelector(".landing-stats-strip");e&&(e.classList.add("landing-learn-strip"),e.innerHTML=Q0.map(m=>`
      <button class="learn-tile reveal" type="button" data-action="topic:${y(m.topic)}" aria-label="${y(m.title)}">
        <div class="learn-tile-ico">${m.icon}</div>
        <div class="learn-tile-t">${y(m.title)}</div>
        <div class="learn-tile-b">${y(m.body)}</div>
      </button>
    `).join(""));let t=x("features-grid");t&&(t.innerHTML=Z0.map(m=>`
      <div class="feature-card reveal">
        <span class="feature-icon">${m.icon}</span>
        <h3>${y(m.title)}</h3>
        <p>${y(m.desc)}</p>
        <button class="feature-cta" type="button" data-action="topic:${y(m.topic)}">
          Learn more \u2192
        </button>
      </div>
    `).join(""));let n=document.querySelector(".landing-simple-value"),s=n==null?void 0:n.querySelector("h2");s&&(s.textContent="What you can do with NaluLF");let a=x("value-grid");a&&(a.innerHTML=ew.map(m=>`
      <div class="value-card reveal">
        <div class="value-number">${m.num}</div>
        <h3>${y(m.title)}</h3>
        <p>${y(m.body)}</p>
        <div class="value-actions">
          <button class="value-cta" type="button" data-action="topic:${y(m.topic)}">Open guide \u2192</button>
          <button class="value-cta primary" type="button" data-action="auth:signup">Launch Dashboard \u2192</button>
        </div>
      </div>
    `).join(""));let o=document.querySelector(".landing-footer-bar .footer-brand");if(o){let m=((p=document.querySelector(".brand-glyph"))==null?void 0:p.getAttribute("src"))||"NaluLF/images/NLF-Shield-blue.jpg";o.innerHTML=`
      <img class="footer-icon" src="${y(m)}" alt="NaluLF shield" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline-flex';" />
      <span class="footer-icon-fallback" style="display:none">\u{1F6E1}\uFE0F</span>
      <span class="brand-name">NaluLF</span>
    `}let i=document.querySelector(".landing-footer-bar .footer-tagline");i&&(i.textContent="Client-only XRPL analytics + decentralized cybersecurity signals \u2014 readable reporting, investigation workflow, and heuristic anomaly detection.");let r=document.querySelector(".landing-footer-bar .footer-tags");r&&(r.innerHTML=`
      <span class="ftag">XRPL Analytics</span>
      <span class="ftag">Forensics</span>
      <span class="ftag">DEX / AMM</span>
      <span class="ftag">Manipulation Signals</span>
      <span class="ftag">Incident Response</span>
      <span class="ftag">Client-Only</span>
      <span class="ftag">No Tracking</span>
    `)}function cm(){let e=new IntersectionObserver(t=>t.forEach(n=>{n.isIntersecting&&n.target.classList.add("visible")}),{threshold:.12});document.querySelectorAll(".reveal").forEach(t=>e.observe(t))}function dm(){let e=document.getElementById("particle-canvas");if(!e)return;let t=e.getContext("2d"),n,s,a=[],o=80,i=120;function r(){n=e.width=window.innerWidth,s=e.height=window.innerHeight}function l(){return{x:Math.random()*n,y:Math.random()*s,vx:(Math.random()-.5)*.4,vy:(Math.random()-.5)*.4,r:Math.random()*1.5+.5,alpha:Math.random()*.5+.1}}function c(){r(),a=Array.from({length:o},l)}function d(){return getComputedStyle(document.body).getPropertyValue("--accent-secondary").trim()||"#ffd700"}function u(){t.clearRect(0,0,n,s);let g=d();for(let b=0;b<a.length;b++)for(let h=b+1;h<a.length;h++){let v=a[b].x-a[h].x,w=a[b].y-a[h].y,k=Math.sqrt(v*v+w*w);k<i&&(t.beginPath(),t.moveTo(a[b].x,a[b].y),t.lineTo(a[h].x,a[h].y),t.strokeStyle=`rgba(255,255,255,${(1-k/i)*.06})`,t.lineWidth=1,t.stroke())}a.forEach(b=>{t.beginPath(),t.arc(b.x,b.y,b.r,0,Math.PI*2),t.fillStyle=`rgba(255,255,255,${b.alpha*.6})`,t.fill()})}function p(){a.forEach(g=>{g.x+=g.vx,g.y+=g.vy,(g.x<0||g.x>n)&&(g.vx*=-1),(g.y<0||g.y>s)&&(g.vy*=-1)})}let m;function f(){p(),u(),m=requestAnimationFrame(f)}c(),f(),document.addEventListener("visibilitychange",()=>{document.hidden?(m&&cancelAnimationFrame(m),m=null):!m&&B.currentPage==="landing"&&f()}),window.addEventListener("naluxrp:pagechange",g=>{var b;((b=g==null?void 0:g.detail)==null?void 0:b.pageId)!=="landing"?(m&&cancelAnimationFrame(m),m=null):m||f()}),window.addEventListener("resize",()=>{r(),a.forEach(g=>{g.x=Math.min(g.x,n),g.y=Math.min(g.y,s)})}),e.style.cssText=`
    position: fixed; inset: 0;
    width: 100%; height: 100%;
    pointer-events: none;
    z-index: 0; opacity: 0.4;
  `}function Ss(e){var t;(t=window.showProfile)==null||t.call(window),setTimeout(()=>e==null?void 0:e(),250)}var gr=[{label:"\u{1F30A} Live Stream",hint:"Dashboard \u2192 Stream tab",action:()=>Mn(document.querySelector('[data-tab="stream"]'),"stream")},{label:"\u{1F50D} Inspector",hint:"Dashboard \u2192 Inspector tab",action:()=>Mn(document.querySelector('[data-tab="inspector"]'),"inspector")},{label:"\u{1F4E1} Network Health",hint:"Dashboard \u2192 Network tab",action:()=>Mn(document.querySelector('[data-tab="network"]'),"network")},{label:"\u{1F464} Profile",hint:"View your profile",action:()=>{var e;return(e=window.showProfile)==null?void 0:e.call(window)}},{label:"\u{1F48E} Wallets",hint:"Profile \u2192 Wallets",action:()=>Ss(()=>{var e;return(e=window.switchProfileTab)==null?void 0:e.call(window,"wallets")})},{label:"\u{1F4CA} Portfolio Analytics",hint:"Profile \u2192 Balance history, heatmap, flow",action:()=>Ss(()=>{var e;return(e=window.switchProfileTab)==null?void 0:e.call(window,"analytics")})},{label:"\u{1F517} Social Links",hint:"Profile \u2192 Connect Discord, X, GitHub\u2026",action:()=>Ss(()=>{var e;return(e=window.switchProfileTab)==null?void 0:e.call(window,"social")})},{label:"\u{1F4DC} Activity Log",hint:"Profile \u2192 Recent account activity",action:()=>Ss(()=>{var e;return(e=window.switchProfileTab)==null?void 0:e.call(window,"activity")})},{label:"\u2699\uFE0F Settings",hint:"Profile \u2192 Preferences & AI Explanations",action:()=>Ss(()=>{var e;return(e=window.switchProfileTab)==null?void 0:e.call(window,"settings")})},{label:"\u{1F52C} Analyze a Project",hint:"Liquidity depth, holder/LP concentration, issuer risk",action:()=>Ss(()=>{var e;return(e=window.jumpToProjectIntelLookup)==null?void 0:e.call(window)})},{label:"\u{1F9ED} Replay App Tour",hint:"Retake the onboarding walkthrough",action:()=>{var e;(e=window.showDashboard)==null||e.call(window),setTimeout(()=>{var t;return(t=window.startTour)==null?void 0:t.call(window)},300)}},{label:"\u2753 Help & Glossary",hint:"Search app features and on-chain terms",action:()=>{var e;return(e=window.openHelp)==null?void 0:e.call(window)}},{label:"\u{1F511} Sign In",hint:"Open auth",action:()=>{var e;return(e=window._openAuth)==null?void 0:e.call(window,"login")}},{label:"\u2728 Sign Up",hint:"Create account",action:()=>{var e;return(e=window._openAuth)==null?void 0:e.call(window,"signup")}},{label:"\u{1F3E0} Landing Page",hint:"Go home",action:()=>{var e;return(e=window._goHome)==null?void 0:e.call(window)}},{label:"\u{1F3A8} Cycle Theme",hint:"gold \u2192 cosmic \u2192 starry \u2192",action:()=>{var e;return(e=window._cycleTheme)==null?void 0:e.call(window)}}];function ow(e){let t=e.trim();return Xe(t)?[{label:`\u{1F50D} Inspect ${t.slice(0,8)}\u2026${t.slice(-6)}`,hint:"Run the full account inspection on this address",action:()=>{Mn(document.querySelector('[data-tab="inspector"]'),"inspector"),setTimeout(()=>{var s;let n=document.getElementById("inspect-addr");n&&(n.value=t),(s=window.runInspect)==null||s.call(window)},200)}}]:[]}var qn=0,uo=[...gr];function mo(e=""){let t=x("cmdkOverlay"),n=x("cmdkInput");!t||!n||(t.classList.add("show"),n.value=e||"",mm(e),n.focus())}function Ts(){var e;(e=x("cmdkOverlay"))==null||e.classList.remove("show")}function um(){let e=x("cmdkOverlay"),t=x("cmdkInput");!e||!t||(t.addEventListener("input",()=>mm(t.value)),t.addEventListener("keydown",n=>{n.key==="ArrowDown"&&(n.preventDefault(),pm(1)),n.key==="ArrowUp"&&(n.preventDefault(),pm(-1)),n.key==="Enter"&&(n.preventDefault(),iw()),n.key==="Escape"&&Ts()}),e.addEventListener("click",n=>{n.target===e&&Ts()}))}function mm(e=""){let t=x("cmdkList");if(!t)return;let n=e.toLowerCase().trim(),s=ow(e);uo=n?[...s,...gr.filter(a=>a.label.toLowerCase().includes(n)||a.hint.toLowerCase().includes(n))]:[...s,...gr],qn=0,t.innerHTML=uo.length?uo.map((a,o)=>`
        <button class="cmdk-item${o===0?" is-active":""}" data-index="${o}">
          <span class="cmdk-label">${y(a.label)}</span>
          <span class="cmdk-hint2">${y(a.hint)}</span>
        </button>`).join(""):'<div class="cmdk-section-label">No results</div>',t.querySelectorAll(".cmdk-item").forEach(a=>{a.addEventListener("click",()=>fm(Number(a.dataset.index)))})}function pm(e){var n,s,a;let t=Be("#cmdkList .cmdk-item");t.length&&((n=t[qn])==null||n.classList.remove("is-active"),qn=(qn+e+t.length)%t.length,(s=t[qn])==null||s.classList.add("is-active"),(a=t[qn])==null||a.scrollIntoView({block:"nearest"}))}function fm(e){let t=uo[e];t&&(Ts(),t.action())}function iw(){fm(qn)}var fo=!1;function vr(){let e=B.currentPage,t=B.currentTab,n=e==="dashboard"&&t==="stream",s=e==="dashboard"&&t==="inspector",a=e==="dashboard"&&t==="network";Yp(n),vu(s),am(a)}function hm(){fo||(Jp(),gu(),sm(),Wl(),vr(),fo=!0)}window.openAuth=e=>No(e);window.closeAuth=()=>rn();window.showAuthView=e=>on(e);window.authKeydown=e=>al(e);window.submitSignIn=()=>_o();window.submitSignUp=()=>Do();window.refreshCaptcha=()=>Ur();window.showForgotView=()=>Kr();window.forgotRestoreFromFile=()=>Jr();window.forgotWipeConfirm=()=>Yr();window.forgotWipeExecute=()=>Qr();window.forgotBackToOptions=()=>Zr();window.submitSyncImport=()=>Io();window.exportVaultSyncCode=()=>el();window.syncImportFromFile=()=>tl();window.signupNext=()=>Ro();window.signupBack=()=>Wr();window.logout=()=>nl();window.goHome=()=>Pn();window.showLandingPage=()=>Pn();window.showDashboard=()=>Ln();window.showProfile=()=>xo();window.switchTab=(e,t)=>Mn(e,t);window.runInspect=()=>ys();window.closeCommandPalette=()=>Ts();window.openCmdk=()=>mo();window.setTheme=e=>Cn(e);window.cycleTheme=()=>yo();window.measureLatency=()=>ia();window.switchProfileTab=e=>ii(e);window.openProfileEditor=()=>Nd();window.closeProfileEditor=()=>Bs();window.saveProfileEditor=()=>Rd();window.selectAvatar=e=>_d(e);window.selectBanner=e=>Dd(e);window.uploadAvatarImage=e=>Id(e);window.removeAvatarImage=()=>Fd();window.uploadBannerImage=e=>Od(e);window.removeBannerImage=()=>Bd();window.prefSetTheme=e=>ap(e);window.setPrefCurrency=e=>op(e);window.setPrefNetwork=e=>ip(e);window.setPrefAutoLock=e=>rp(e);window.openPublicProfilePreview=()=>sp();window.exportVaultBackup=()=>Xd();window.logActivity=(e,t)=>kt(e,t);window.toggleWalletDrawer=e=>Pd(e);window.switchWalletDrawerTab=(e,t)=>Ld(e,t);window.cancelOffer=(e,t,n)=>Ad(e,t,n);window.fetchBalance=e=>Fn(e);window.setActiveWallet=e=>Vl(e);window.openImportAddressModal=()=>Yd();window.closeImportAddressModal=()=>wi();window.importWatchOnlyWallet=()=>Qd();window.openImportSeedModal=()=>Zd();window.closeImportSeedModal=()=>xi();window.executeImportFromSeed=()=>ep();window.openTokenDetailsModal=(e,t,n)=>tp(e,t,n);window.closeTokenDetailsModal=()=>np();window.refreshXrplDashboard=()=>es();window.refreshMarketData=()=>hd();window.refreshNftGallery=()=>gd();window.refreshAmmPools=()=>vd();window.refreshPoolExplorer=()=>bd();window.loadCustomAmmPool=()=>rc();window.sendNft=e=>yd(e);window.toggleSeedBackupStatus=()=>bc();window.setDexPair=e=>yc(e);window.setDexInterval=e=>wc(e);window.setDexChartType=e=>xc(e);window.refreshDexChart=()=>kc();window.setComparePair=e=>Ic(e);window.toggleIndicator=(e,t)=>$c(e,t);window.toggleTerminalTheme=()=>Gc();window.toggleChartFullscreen=()=>Kc();window.exportChartPng=()=>Jc();window.saveChartLayoutPreset=()=>Qc();window.loadChartLayoutPreset=()=>Zc();window.setIndicatorFromDropdown=e=>Fc(e);window.toggleIndicatorMenu=()=>Sc();window.toggleChartMoreMenu=()=>Tc();window.setIndicatorQuery=e=>Cc(e);window.addIndicatorFromMenu=e=>Pc(e);window.removeIndicator=e=>Lc(e);window.openIndicatorSettings=e=>Mc(e);window.closeIndicatorSettings=()=>Ac();window.applyIndicatorSettings=e=>Ec(e);window.resetIndicatorSettings=e=>Nc(e);window.copyChartLink=()=>Rc();window.toggleThreeEffects=()=>_c();window.setThreeEffects=e=>Dc(e);window.setDrawingTool=e=>Oc(e);window.clearAllDrawings=()=>Hc();window.addPriceAlert=()=>Bc();window.removePriceAlert=e=>Xc(e);window.zoomChartIn=()=>zc();window.zoomChartOut=()=>Wc();window.panChartLeft=()=>Uc();window.panChartRight=()=>jc();window.toggleEducationPanel=()=>qc();window.selectEducationTab=e=>Vc(e);window.searchTokens=e=>nd(e);window.lookupIssuedAsset=()=>mi();window.lookupAndAnalyzeProject=()=>md();window.addTokenToWatchlist=e=>cd(e);window.removeTokenFromWatchlist=e=>dd(e);window.openTokenOnChart=e=>Da(e);window.loadToken=e=>pd(e);window.refreshTokenDiscovery=()=>ud();window.refreshRecentTransactions=()=>fd();window.setTokenFilter=(e,t)=>sd(e,t);window.clearTokenFilters=()=>ad();window.selectTokenDetails=e=>ld(e);window.openProjectIntel=e=>ci(e);window.jumpToProjectIntelLookup=()=>Kl();window.toggleProjectIntelSubScore=e=>Jl(e);window.copyProjectIntelForAi=()=>tc();window.closeProjectIntel=()=>Yl();window.showMoreIssuedTokens=()=>od();window.showAllIssuedTokens=()=>id();window.resetIssuedTokenLimit=()=>rd();window.openWalletCreator=()=>bi();window.closeWalletCreator=()=>Xs();window.wizardNext=()=>Hd();window.wizardBack=()=>zd();window.selectAlgo=e=>Wd(e);window.selectWalletEmoji=e=>Ud(e);window.selectWalletColor=e=>jd(e);window.toggleSecurityCheck=e=>qd(e);window.revealSeed=()=>Gd();window.copySeed=()=>Kd();window.copyAddress=()=>Jd();window.copyToClipboard=e=>Hs(e);window.deleteWallet=e=>Td(e);window.inspectWalletAddr=e=>Cd(e);window.openSocialModal=e=>xd(e);window.closeSocialModal=()=>as();window.saveSocialModal=()=>kd();window.deleteSocial=()=>$d();window.viewSocial=e=>Sd(e);window.connectXRPL=()=>import("./xrpl-6AERZ5KD.js").then(({connectXRPL:e})=>e());window._openAuth=No;window._goHome=Pn;window._cycleTheme=yo;window._showProfile=xo;window.startTour=()=>So();window.tourNext=()=>Xr();window.tourPrev=()=>Hr();window.tourSkip=()=>fa();window.openHelp=()=>lp();window.closeHelp=()=>Oa();window.filterHelp=e=>$i(e);document.addEventListener("DOMContentLoaded",()=>{var e;console.log("\u{1F30A} NaluLF: booting\u2026"),_r(),Pn(),lm(),cm(),dm(),um(),cp(),rw(),window.addEventListener("naluxrp:pagechange",t=>{var s;let n=(s=t==null?void 0:t.detail)==null?void 0:s.pageId;(n==="dashboard"||n==="inspector"||n==="profile")&&hm(),fo&&vr()}),window.addEventListener("naluxrp:tabchange",()=>{fo&&vr()}),document.addEventListener("keydown",t=>{var s;let n=["INPUT","TEXTAREA"].includes((s=document.activeElement)==null?void 0:s.tagName);if((t.ctrlKey||t.metaKey)&&t.key==="k"){t.preventDefault(),mo();return}if(t.key==="/"&&!n){t.preventDefault(),mo();return}t.key==="Escape"&&(Ts(),rn(),Bs(),Xs(),as(),fa(),Oa())}),(e=document.getElementById("auth-overlay"))==null||e.addEventListener("click",t=>{t.target===t.currentTarget&&rn()}),sl()&&(hm(),Ln(),import("./xrpl-6AERZ5KD.js").then(({connectXRPL:t})=>t())),console.log("\u2705 NaluLF: ready")});function rw(){vm(),setInterval(()=>{document.hidden||vm()},3e4)}async function gm(e){let t=[s=>`https://corsproxy.io/?${encodeURIComponent(s)}`,s=>`https://api.allorigins.win/raw?url=${encodeURIComponent(s)}`],n=async s=>{let a=typeof(AbortSignal==null?void 0:AbortSignal.timeout)=="function"?AbortSignal.timeout(7e3):void 0,o=await fetch(s,{mode:"cors",cache:"no-store",signal:a});if(!o.ok)throw new Error(`HTTP ${o.status}`);return await o.json()};try{return await n(e)}catch{for(let s of t)try{return await n(s(e))}catch{}throw new Error("Price feed unreachable")}}async function vm(){try{let e=await gm("https://api.exchange.coinbase.com/products/XRP-USD/ticker"),t=await gm("https://api.exchange.coinbase.com/products/XRP-USD/candles?granularity=86400");if(e!=null&&e.price){let n=Number(e.price),s=Array.isArray(t)&&t.length?t[0]:null,a=s?Number(s[3]||n):n,o=a?(n-a)/a*100:0,i=document.getElementById("xrpPrice"),r=document.getElementById("xrpChange");if(i&&(i.textContent=`$${Number(n).toFixed(3)}`),r){let l=o>=0;r.textContent=`${l?"+":""}${Number(o).toFixed(2)}%`,r.className=`xrp-price-change ${Math.abs(o)<.1?"flat":l?"up":"down"}`}}}catch{}}
