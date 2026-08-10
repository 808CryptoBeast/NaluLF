import{a as Qi,b as Ua,c as pn,d as Tt,e as y,f as Ie,g,h as Ue,i as D,j as U,k as Z,l as te,m as lt,n as ve,o as ne,p as be,q as Nt,r as O,s as Ws,v as Ne,w as Zi}from"./chunk-R7KFE7J7.js";function un(e){pn.includes(e)||(e="gold"),O.currentTheme=e,pn.forEach(t=>document.body.classList.remove(`theme-${t}`)),document.body.classList.add(`theme-${e}`),te(Ua,e)}function Wa(){let e=pn.indexOf(O.currentTheme);un(pn[(e+1)%pn.length])}function er(){let e=Z(Ua);un(pn.includes(e)?e:"gold")}var tr={landing:"landing-page",dashboard:"dashboard",inspector:"inspector",profile:"dashboard"};function ja(e){document.body.classList.remove("modal-open"),Object.values(tr).forEach(i=>document.body.classList.remove(i)),document.body.classList.add(tr[e]||"dashboard");let t=y("landing"),n=y("dashboard"),s=y("profile-page");t&&(t.style.display=e==="landing"?"":"none"),n&&(n.style.display=e==="dashboard"?"":"none"),s&&(s.style.display=e==="profile"?"":"none");let a=e==="landing",o={landingActions:y("navbar-landing-actions"),dashActions:y("navbar-dash-actions"),navConn:y("navbar-conn"),cmdkHint:y("cmdk-hint")};o.landingActions&&(o.landingActions.style.display=a?"":"none"),o.dashActions&&(o.dashActions.style.display=a?"none":""),o.navConn&&(o.navConn.style.display=a?"none":""),o.cmdkHint&&(o.cmdkHint.style.display=a?"none":""),O.currentPage=e,window.scrollTo({top:0,behavior:"smooth"}),window.dispatchEvent(new CustomEvent("naluxrp:pagechange",{detail:{pageId:e}}))}function mn(){ja("landing")}function fn(){ja("dashboard")}function qa(){ja("profile")}function Nn(e,t){Ie(".dash-tab").forEach(n=>{n.classList.toggle("active",n===e),n.setAttribute("aria-selected",String(n===e))}),["stream","inspector","network"].forEach(n=>{let s=y(`tab-${n}`);s&&(s.style.display=n===t?"":"none")}),t==="inspector"?(document.body.classList.remove("dashboard"),document.body.classList.add("inspector")):(document.body.classList.remove("inspector"),document.body.classList.add("dashboard")),O.currentTab=t,window.dispatchEvent(new CustomEvent("naluxrp:tabchange",{detail:{tabId:t}}))}var Ct="naluxrp_vault_meta",_t="naluxrp_vault_data",Rn="naluxrp_session",Ga="nalulf_used_names",Ka="nalulf_used_emails",Ja="nalulf_used_domains",Va=15e4,js="naluxrp_v2",Ee={_key:null,_vault:null,_lockTimer:null,AUTO_LOCK_MS:30*60*1e3,get isUnlocked(){return this._key!==null&&this._vault!==null},get vault(){return this._vault},hasVault(){return!!Z(Ct)&&!!Z(_t)},async create(e,t,n,s){let a=crypto.getRandomValues(new Uint8Array(32));this._key=await this._deriveKey(e,a);let o=(s||t).toLowerCase().replace(/[^a-z0-9_]/g,"");return this._vault={checksum:js,identity:{name:t,email:n,domain:o,createdAt:new Date().toISOString()},profile:{},wallets:[],social:{}},te(Ct,JSON.stringify({salt:Array.from(a),iterations:Va,version:js})),await this._persist(),this._startLockTimer(),this._vault},async unlock(e){let t=ve(Z(Ct));if(!t)throw new Error("No account found. Create one first.");this._key=await this._deriveKey(e,new Uint8Array(t.salt));let n;try{let s=ve(Z(_t));if(!s)throw new Error("missing");n=await this._decrypt(s)}catch{throw this._key=null,new Error("Incorrect password. Please try again.")}if((n==null?void 0:n.checksum)!==js)throw this._key=null,new Error("Account data corrupted. Restore from backup.");return this._vault=n,this._startLockTimer(),this._vault},async update(e){if(!this.isUnlocked)throw new Error("Sign in to continue.");e(this._vault),await this._persist()},lock(){this._key=null,this._vault=null,clearTimeout(this._lockTimer),this._lockTimer=null},resetTimer(){this.isUnlocked&&this._startLockTimer()},async changePassword(e){if(!this.isUnlocked)throw new Error("Sign in first.");let t=crypto.getRandomValues(new Uint8Array(32));this._key=await this._deriveKey(e,t),te(Ct,JSON.stringify({salt:Array.from(t),iterations:Va,version:js})),await this._persist()},async exportBlob(){if(!this.isUnlocked)throw new Error("Sign in before exporting.");let e={vault:ve(Z(_t)),meta:ve(Z(Ct)),exportedAt:new Date().toISOString()},t=URL.createObjectURL(new Blob([JSON.stringify(e,null,2)],{type:"application/json"}));Object.assign(document.createElement("a"),{href:t,download:`naluxrp-backup-${Date.now()}.json`}).click(),URL.revokeObjectURL(t)},async _deriveKey(e,t){let n=new TextEncoder,s=await crypto.subtle.importKey("raw",n.encode(e),"PBKDF2",!1,["deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt:t,iterations:Va,hash:"SHA-256"},s,{name:"AES-GCM",length:256},!1,["encrypt","decrypt"])},async _encrypt(e){let t=crypto.getRandomValues(new Uint8Array(12)),n=new TextEncoder,s=await crypto.subtle.encrypt({name:"AES-GCM",iv:t},this._key,n.encode(JSON.stringify(e)));return{iv:Array.from(t),cipher:Array.from(new Uint8Array(s))}},async _decrypt(e){let t=new TextDecoder,n=await crypto.subtle.decrypt({name:"AES-GCM",iv:new Uint8Array(e.iv)},this._key,new Uint8Array(e.cipher).buffer);return JSON.parse(t.decode(n))},async _persist(){!this._key||!this._vault||te(_t,JSON.stringify(await this._encrypt(this._vault)))},_startLockTimer(){clearTimeout(this._lockTimer),this._lockTimer=setTimeout(()=>{this.lock(),window.dispatchEvent(new CustomEvent("naluxrp:vault-locked"))},this.AUTO_LOCK_MS)}},Qe=1;function Qa(e){var t;Ee.hasVault()?jt(e||"login"):jt("welcome"),(t=y("auth-overlay"))==null||t.classList.add("show")}function qt(){var e;(e=y("auth-overlay"))==null||e.classList.remove("show"),Vt(),Qe=1,hn(1)}function jt(e){var s,a,o,i,r;Js(".auth-view").forEach(l=>l.classList.remove("active")),(s=y(`auth-view-${e}`))==null||s.classList.add("active"),(a=y("auth-overlay"))==null||a.setAttribute("data-view",e);let t=["welcome","forgot","sync","celebrate","syncaware"].includes(e),n=y("auth-tab-row");n&&(n.style.display=t?"none":""),(o=y("tab-login-btn"))==null||o.classList.toggle("active",e==="login"),(i=y("tab-signup-btn"))==null||i.classList.toggle("active",e==="signup"),(r=y("tab-sync-btn"))==null||r.classList.toggle("active",e==="sync"),e==="signup"&&(Qe=1,hn(1),_n()),Vt()}function hn(e){[1,2,3].forEach(s=>{let a=y(`signup-step-${s}`);a&&(a.style.display=s===e?"":"none");let o=y(`signup-dot-${s}`);o&&(o.classList.toggle("active",s===e),o.classList.toggle("done",s<e))});let t=["","Step 1 of 3 \u2014 Identity","Step 2 of 3 \u2014 Security","Step 3 of 3 \u2014 Sync setup"],n=y("signup-step-label");n&&(n.textContent=t[e]||"")}function Za(){var e,t,n,s,a,o;if(Vt(),Qe===1){let i=((e=y("inp-signup-name"))==null?void 0:e.value.trim())||"",r=((t=y("inp-signup-email"))==null?void 0:t.value.trim())||"",l=((n=y("inp-signup-domain"))==null?void 0:n.value.trim())||"";if(!i||i.length<3)return Pe("Display name must be at least 3 characters.");if(ir(i))return Pe(`"${i}" is already in use on this device.`);if(!r||!r.includes("@"))return Pe("Enter a valid email address.");if(rr(r))return Pe("That email is already registered on this device.");if(l&&lr(l))return Pe(`@${l} is already taken on this device.`);if(l&&!/^[a-z0-9_]{2,30}$/.test(l))return Pe("Handle: 2-30 lowercase letters, numbers, underscores only.");Qe=2,hn(2),_n(),setTimeout(()=>{var c;return(c=y("inp-signup-pass"))==null?void 0:c.focus()},80)}else if(Qe===2){let i=((s=y("inp-signup-pass"))==null?void 0:s.value)||"",r=((a=y("inp-signup-confirm"))==null?void 0:a.value)||"";if(!i||i.length<8)return Pe("Password must be at least 8 characters.");if(!yr(i))return Pe("Add uppercase, lowercase, and a number.");if(i!==r)return Pe("Passwords do not match.");if(!or())return _n(),Pe("Type the word from the image exactly.");Qe=3,hn(3);let l=y("syncaware-name"),c=((o=y("inp-signup-name"))==null?void 0:o.value.trim())||"there";l&&(l.textContent=c.split(" ")[0])}}function sr(){Qe>1&&(Qe--,hn(Qe),Vt(),Qe===1&&setTimeout(()=>{var e;return(e=y("inp-signup-name"))==null?void 0:e.focus()},80))}var nr=["XRPL","LEDGER","VAULT","CRYPTO","BLOCK","TOKEN","CHAIN","WAVE","ATLAS","FORGE","NEXUS","ORBIT","PRISM","DELTA","NOVA","SONIC","PIXEL","GHOST","FLARE","SPARK","TITAN","LUNAR","STORM","PROXY","CIPHER","RELAY","PULSE","SCOUT"],Ya="";function _n(){Ya=nr[Math.floor(Math.random()*nr.length)];let e=document.getElementById("captcha-canvas"),t=y("inp-captcha");if(t&&(t.value=""),!e)return;let n=e.getContext("2d"),s=e.width,a=e.height;n.clearRect(0,0,s,a),n.fillStyle="#080f1e",n.fillRect(0,0,s,a),n.strokeStyle="rgba(0,255,240,.05)",n.lineWidth=1;for(let r=0;r<s;r+=18)n.beginPath(),n.moveTo(r,0),n.lineTo(r,a),n.stroke();for(let r=0;r<a;r+=18)n.beginPath(),n.moveTo(0,r),n.lineTo(s,r),n.stroke();for(let r=0;r<55;r++)n.fillStyle=`rgba(${Math.random()>.5?"0,255,240":"160,180,255"},${(Math.random()*.22+.05).toFixed(2)})`,n.beginPath(),n.arc(Math.random()*s,Math.random()*a,Math.random()*2+.5,0,Math.PI*2),n.fill();for(let r=0;r<4;r++)n.strokeStyle=`rgba(0,255,240,${(Math.random()*.1+.03).toFixed(2)})`,n.lineWidth=1,n.beginPath(),n.moveTo(0,Math.random()*a),n.bezierCurveTo(s*.3,Math.random()*a,s*.7,Math.random()*a,s,Math.random()*a),n.stroke();let o=Ya.split(""),i=(s-o.length*26)/2+8;o.forEach((r,l)=>{let c=i+l*26+(Math.random()*8-4),d=a/2+8+(Math.random()*10-5);n.save(),n.translate(c,d),n.rotate(Math.random()*.35-.175),n.shadowColor="rgba(0,255,240,.5)",n.shadowBlur=8,n.fillStyle=`rgb(${Math.random()>.4?"180,255,240":"140,200,255"})`,n.font=`bold ${24+Math.random()*4}px 'JetBrains Mono','Courier New',monospace`,n.fillText(r,0,0),n.restore()})}function ar(){_n()}function or(){var e;return(((e=y("inp-captcha"))==null?void 0:e.value)||"").trim().toUpperCase()===Ya}function ir(e){return(ve(Z(Ga))||[]).some(t=>t.toLowerCase()===e.toLowerCase())}function rr(e){return(ve(Z(Ka))||[]).some(t=>t.toLowerCase()===e.toLowerCase())}function lr(e){return(ve(Z(Ja))||[]).some(t=>t.toLowerCase()===e.toLowerCase())}function vu(e,t,n){let s=ve(Z(Ga))||[],a=ve(Z(Ka))||[],o=ve(Z(Ja))||[];s.includes(e.toLowerCase())||s.push(e.toLowerCase()),a.includes(t.toLowerCase())||a.push(t.toLowerCase()),n&&!o.includes(n.toLowerCase())&&o.push(n.toLowerCase()),te(Ga,JSON.stringify(s)),te(Ka,JSON.stringify(a)),te(Ja,JSON.stringify(o))}async function eo(){var s,a,o;let e=((s=y("inp-login-email"))==null?void 0:s.value.trim())||"",t=((a=y("inp-login-pass"))==null?void 0:a.value)||"";if(Vt(),!e)return Pe("Enter your email address.");if(!t)return Pe("Enter your password.");let n=y("signin-btn");qs(n,!0,"Signing in\u2026");try{let i=await Ee.unlock(t);O.session={name:i.identity.name,email:i.identity.email,domain:i.identity.domain||""},te(Rn,JSON.stringify(O.session)),qt(),Ks(O.session),fn(),Ws(),window.dispatchEvent(new CustomEvent("naluxrp:vault-ready",{detail:Ee.vault})),wu()}catch(i){Pe(i.message),(o=y("auth-modal-inner"))==null||o.classList.add("shake"),setTimeout(()=>{var r;return(r=y("auth-modal-inner"))==null?void 0:r.classList.remove("shake")},500)}finally{qs(n,!1,"Sign In \u2192")}}async function to(){var i,r,l,c,d;let e=((i=y("inp-signup-name"))==null?void 0:i.value.trim())||"",t=((r=y("inp-signup-email"))==null?void 0:r.value.trim())||"",n=((l=y("inp-signup-domain"))==null?void 0:l.value.trim())||e.toLowerCase().replace(/[^a-z0-9_]/g,"_"),s=((c=y("inp-signup-pass"))==null?void 0:c.value)||"",a=((d=y("inp-signup-confirm"))==null?void 0:d.value)||"";if(Vt(),!s||s.length<8)return Pe("Password must be at least 8 characters.");if(!yr(s))return Pe("Add uppercase, lowercase, and a number.");if(s!==a)return Pe("Passwords do not match.");if(!or())return _n(),Qe=2,hn(2),Pe("Type the word from the image exactly.");let o=y("signup-btn");qs(o,!0,"Creating vault\u2026");try{await Ee.create(s,e,t,n),vu(e,t,n),O.session={name:e,email:t,domain:n},te(Rn,JSON.stringify(O.session)),Ks(O.session),bu(e,()=>{qt(),fn(),Ws(),window.dispatchEvent(new CustomEvent("naluxrp:vault-ready",{detail:Ee.vault})),setTimeout(xu,3500)})}catch(u){Pe(u.message),_n(),Qe=2,hn(2)}finally{qs(o,!1,"Create Account \u2192")}}function bu(e,t){jt("celebrate");let n=y("celebrate-name");n&&(n.textContent=e.split(" ")[0]);let s=setTimeout(t,2800),a=y("celebrate-continue-btn");a&&(a.onclick=()=>{clearTimeout(s),t()})}function cr(){jt("forgot"),Js(".forgot-step").forEach(t=>t.style.display="none");let e=y("forgot-step-options");e&&(e.style.display="")}function dr(){let e=document.createElement("input");e.type="file",e.accept=".json,application/json",e.onchange=async t=>{let n=t.target.files[0];if(n)try{let s=await n.text(),a=JSON.parse(s);if(!(a!=null&&a.vault)||!(a!=null&&a.meta))throw new Error("Invalid backup file.");te(_t,JSON.stringify(a.vault)),te(Ct,JSON.stringify(a.meta)),ne("Backup restored \u2014 sign in with your original password."),jt("login")}catch(s){Nt("Could not read backup: "+s.message)}},e.click()}function pr(){Js(".forgot-step").forEach(n=>n.style.display="none");let e=y("forgot-step-wipe");e&&(e.style.display="");let t=y("inp-wipe-confirm");t&&(t.value="")}function ur(){var t;if((((t=y("inp-wipe-confirm"))==null?void 0:t.value.trim())||"")!=="DELETE")return Pe("Type DELETE exactly.");lt(Ct),lt(_t),lt(Rn),Ee.lock(),O.session=null,ne("Account cleared. Create a new one."),qt(),jt("signup"),window.dispatchEvent(new Event("naluxrp:logout"))}function mr(){Js(".forgot-step").forEach(t=>t.style.display="none");let e=y("forgot-step-options");e&&(e.style.display=""),Vt()}function fr(){let e=Z(_t),t=Z(Ct);if(!e||!t){Nt("No vault to export.");return}let n=btoa(JSON.stringify({vault:JSON.parse(e),meta:JSON.parse(t)})),s=document.createElement("div");s.id="sync-code-overlay",s.style.cssText="position:fixed;inset:0;background:rgba(0,0,0,.92);backdrop-filter:blur(14px);z-index:99999;display:flex;align-items:center;justify-content:center;padding:20px;",s.innerHTML=`<div style="background:#0d1829;border:1.5px solid rgba(0,255,240,.22);border-radius:22px;padding:28px;max-width:500px;width:100%;box-shadow:0 28px 70px rgba(0,0,0,.95);"><div style="font-size:1rem;font-weight:900;margin-bottom:6px;color:#00fff0;">\u{1F4F1} Vault Sync Code</div><p style="font-size:.82rem;color:rgba(255,255,255,.55);margin-bottom:16px;line-height:1.6;">On your new device open NaluLF \u2192 <strong style="color:rgba(255,255,255,.8)">\u{1F4F1} New Device</strong> tab, paste this code and enter your password.</p><textarea readonly id="sync-code-output" style="width:100%;height:110px;background:#060e1a;border:1px solid rgba(255,255,255,.12);border-radius:10px;color:rgba(0,255,240,.85);font-family:monospace;font-size:.7rem;padding:10px;resize:none;box-sizing:border-box;" spellcheck="false">${n}</textarea><div style="display:flex;gap:10px;margin-top:14px;justify-content:flex-end;"><button onclick="document.getElementById('sync-code-overlay').remove()" style="padding:9px 16px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);border-radius:9px;color:rgba(255,255,255,.65);font-size:.85rem;font-weight:700;cursor:pointer;font-family:inherit;">Close</button><button onclick="navigator.clipboard.writeText(document.getElementById('sync-code-output').value).then(()=>{this.textContent='\u2713 Copied!';setTimeout(()=>this.textContent='Copy Code',2000)})" style="padding:9px 18px;background:linear-gradient(135deg,#00d4ff,#00fff0);border:none;border-radius:9px;color:#000;font-size:.85rem;font-weight:900;cursor:pointer;font-family:inherit;">Copy Code</button></div></div>`,document.body.appendChild(s),s.addEventListener("click",a=>{a.target===s&&s.remove()})}async function no(){var s,a;let e=((s=y("inp-sync-code"))==null?void 0:s.value.trim())||"",t=((a=y("inp-sync-pass"))==null?void 0:a.value)||"";if(Vt(),!e)return Pe("Paste your vault sync code or load a backup file first.");if(!t)return Pe("Enter the password from your original device.");let n=document.querySelector("#auth-view-sync .auth-submit-btn");n&&(n.disabled=!0,n.textContent="Importing\u2026");try{let o;try{o=JSON.parse(atob(e))}catch{try{o=JSON.parse(e)}catch{throw new Error("Invalid sync code. Paste the full code from your other device.")}}if(!(o!=null&&o.vault)||!(o!=null&&o.meta))throw new Error("Invalid sync code format \u2014 make sure you copied the entire code.");te(_t,JSON.stringify(o.vault)),te(Ct,JSON.stringify(o.meta));let i=await Ee.unlock(t);O.session={name:i.identity.name,email:i.identity.email,domain:i.identity.domain||""},te(Rn,JSON.stringify(O.session)),qt(),Ks(O.session),fn(),Ws(),window.dispatchEvent(new CustomEvent("naluxrp:vault-ready",{detail:Ee.vault})),ne("\u2705 Account imported to this device!")}catch(o){let i=o.message.includes("decrypt")||o.message.includes("Incorrect");Pe(i?"Wrong password \u2014 use the password from your original device.":"Could not import: "+o.message),lt(_t),lt(Ct)}finally{n&&(n.disabled=!1,n.textContent="Import & Sign In \u2192")}}function hr(){let e=document.createElement("input");e.type="file",e.accept=".json,application/json",e.onchange=async t=>{var s;let n=t.target.files[0];if(n)try{let a=await n.text(),o=JSON.parse(a);if(!(o!=null&&o.vault)||!(o!=null&&o.meta))throw new Error("Invalid backup file format.");let i=y("inp-sync-code");i&&(i.value=btoa(JSON.stringify({vault:o.vault,meta:o.meta})));let r=y("sync-file-feedback");r&&(r.textContent=`\u2713 File loaded: ${n.name}`,r.style.color="#50fa7b"),(s=y("inp-sync-pass"))==null||s.focus()}catch(a){Nt("Could not read backup: "+a.message)}},e.click()}function gr(){Ee.lock(),O.session=null,lt(Rn),mn(),window.dispatchEvent(new Event("naluxrp:logout"))}function vr(){let e=ve(Z(Rn));return e!=null&&e.email&&Ee.hasVault()?(O.session=e,Ks(e),!0):!1}function yu(){if(y("vault-lock-banner"))return;let e=document.createElement("div");e.id="vault-lock-banner",e.className="vault-lock-banner",e.innerHTML=`<span class="vlb-icon">\u{1F512}</span><span class="vlb-text">Vault locked for security after 30 min of inactivity.</span><button class="vlb-btn" onclick="openAuth('login')">Unlock \u2192</button><button class="vlb-close" onclick="this.closest('.vault-lock-banner').remove()" title="Dismiss">\u2715</button>`,document.body.prepend(e),requestAnimationFrame(()=>e.classList.add("show"))}function wu(){let e=y("vault-lock-banner");e&&(e.classList.remove("show"),setTimeout(()=>e.remove(),300))}function xu(){if(y("backup-reminder-banner")||!Ee.hasVault())return;let e=document.createElement("div");e.id="backup-reminder-banner",e.className="backup-reminder-banner",e.innerHTML=`<span class="brb-icon">\u26A0\uFE0F</span><div class="brb-body"><strong>Back up your vault</strong> \u2014 you'll lose access if browser storage is cleared. <button class="brb-btn" onclick="window.exportVaultBackup?.()">Export Backup</button></div><button class="brb-close" onclick="this.closest('.backup-reminder-banner').remove()">\u2715</button>`;let t=document.getElementById("profile-page");t?t.prepend(e):document.body.prepend(e),requestAnimationFrame(()=>e.classList.add("show"))}function br(e){var n;let t=((n=y("auth-overlay"))==null?void 0:n.getAttribute("data-view"))||"login";if(e.key==="Enter"&&(t==="login"&&eo(),t==="signup"&&(Qe<3?Za():to()),t==="sync"&&no()),e.key==="Tab"){let s=y("auth-modal-inner");if(!s)return;let a=Array.from(s.querySelectorAll("button:not([disabled]),input,textarea,select")).filter(r=>r.offsetParent!==null);if(!a.length)return;let o=a[0],i=a[a.length-1];e.shiftKey&&document.activeElement===o&&(e.preventDefault(),i.focus()),!e.shiftKey&&document.activeElement===i&&(e.preventDefault(),o.focus())}}function Vs(e){let t=y(e);t==null||t.classList.add("valid"),t==null||t.classList.remove("invalid")}function gn(e){let t=y(e);t==null||t.classList.add("invalid"),t==null||t.classList.remove("valid")}function Gs(e){let t=y(e);t==null||t.classList.remove("valid","invalid")}window.validateSignupName=()=>{var s;let e=((s=y("inp-signup-name"))==null?void 0:s.value.trim())||"",t=y("hint-signup-name");if(!e){Gs("inp-signup-name"),t&&(t.textContent="");return}if(e.length<3){gn("inp-signup-name"),t&&(t.textContent="At least 3 characters");return}if(ir(e)){gn("inp-signup-name"),t&&(t.textContent="Already in use on this device");return}Vs("inp-signup-name"),t&&(t.textContent="\u2713 Looks good!");let n=y("inp-signup-domain");n&&!n.dataset.manuallyEdited&&(n.value=e.toLowerCase().replace(/[^a-z0-9]/g,"_").replace(/_+/g,"_").replace(/^_|_$/g,""),window.validateSignupDomain())};window.validateSignupEmail=()=>{var n;let e=((n=y("inp-signup-email"))==null?void 0:n.value.trim())||"",t=y("hint-signup-email");if(!e){Gs("inp-signup-email"),t&&(t.textContent="");return}if(!e.includes("@")||!e.includes(".")){gn("inp-signup-email"),t&&(t.textContent="Enter a valid email");return}if(rr(e)){gn("inp-signup-email"),t&&(t.textContent="Already registered on this device");return}Vs("inp-signup-email"),t&&(t.textContent="\u2713 Available")};window.validateSignupDomain=()=>{var s;let e=((s=y("inp-signup-domain"))==null?void 0:s.value.trim())||"",t=y("hint-signup-domain"),n=y("inp-signup-domain");if(!e){Gs("inp-signup-domain"),t&&(t.textContent="");return}if(!/^[a-z0-9_]{2,30}$/.test(e)){gn("inp-signup-domain"),t&&(t.textContent="2-30 chars: a-z, 0-9, underscore only");return}if(lr(e)){gn("inp-signup-domain"),t&&(t.textContent="Already taken on this device");return}Vs("inp-signup-domain"),t&&(t.textContent=`\u2713 @${e}`),n&&(n.dataset.manuallyEdited="1")};window.validateLoginEmail=()=>{var t;let e=((t=y("inp-login-email"))==null?void 0:t.value.trim())||"";if(!e)return Gs("inp-login-email");e.includes("@")?Vs("inp-login-email"):gn("inp-login-email")};window.switchSyncMethod=function(e){var i,r;let t=e==="code";(i=document.getElementById("sync-method-code"))==null||i.classList.toggle("sync-method-card--active",t),(r=document.getElementById("sync-method-file"))==null||r.classList.toggle("sync-method-card--active",!t);let n=document.getElementById("sync-code-section"),s=document.getElementById("sync-file-section"),a=document.getElementById("sync-method-code-steps"),o=document.getElementById("sync-method-file-steps");n&&(n.style.display=t?"":"none"),s&&(s.style.display=t?"none":""),a&&(a.style.display=t?"":"none"),o&&(o.style.display=t?"none":"")};window.togglePwVisibility=function(e,t){let n=y(e);if(!n)return;let s=n.type==="password";n.type=s?"text":"password",t.textContent=s?"\u{1F648}":"\u{1F441}"};window.updatePwStrength=function(e){let t=y("pw-strength-fill"),n=y("pw-strength-label");if(!t||!n)return;let s=0;e.length>=8&&s++,/[A-Z]/.test(e)&&s++,/[a-z]/.test(e)&&s++,/[0-9]/.test(e)&&s++,/[^A-Za-z0-9]/.test(e)&&s++;let a=[{w:"0%",bg:"transparent",txt:""},{w:"20%",bg:"#ff5555",txt:"Very weak"},{w:"40%",bg:"#ff8c42",txt:"Weak"},{w:"60%",bg:"#ffb86c",txt:"Fair"},{w:"80%",bg:"#00d4ff",txt:"Good"},{w:"100%",bg:"#50fa7b",txt:"Strong \u2713"}],o=a[s]||a[0];t.style.width=o.w,t.style.background=o.bg,n.textContent=o.txt,n.style.color=o.bg};function yr(e){return/[A-Z]/.test(e)&&/[a-z]/.test(e)&&/[0-9]/.test(e)}function Ks(e){let t=y("user-avatar"),n=y("user-name");t&&(t.textContent=e.name.charAt(0).toUpperCase()),n&&(n.textContent=e.name)}function Pe(e){let t=y("auth-error");t&&(t.textContent=e,t.style.display="")}function Vt(){let e=y("auth-error");e&&(e.textContent="")}function qs(e,t,n){e&&(e.disabled=t,e.textContent=n)}function Js(e){return Array.from(document.querySelectorAll(e))}["click","keydown","mousemove","touchstart"].forEach(e=>document.addEventListener(e,()=>Ee.resetTimer(),{passive:!0}));window.addEventListener("naluxrp:vault-locked",()=>{O.vaultLocked=!0,yu()});var ku=180,Bt=12,wr=5,xr="naluxrp_compact_mode",$u=1e5,Su=18,so=16,Tu=96,kr=96,Cu=96,Lu=5*6e4,Ys=72,$r=80,Mu=1e4,Pu=20,hs=8,Qr=3,Zr=.7,ro=.35,na=12,Wn=10,jn=2,Bn=61e3,Kt="NALU-SPAM-PROOF:",el="naluxrp_spam_verified",tl="naluxrp_spam_allowlist",nl=new Set(["rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy","rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B","rrpNnNLKrartuEqfJGpqyDwPj1BBN1ih7","rN7n3473SaZBCG4dFL83w7PB9judJ7qdDo","rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh","rBKPS4oLSaV2KVVuHH8EpQqMGgGefGFQs7","rfk5bwaKCoNU84fTzdqWQowqnNaZorDmiV","rGFuMiw48HdbnrUbkRYDTvT5i9imC5fvv9","rwYHCs2EYBMBvRXFmxDrCUSorPsuqCck7t","rLHzPsX6oXkzU2qL12kHCH8G8cnZv1rBJh","ra5nK24KXen9AHvsdFTKHSANinZseWnPcX","rGWrZyax5eXbi5gs49MRZKkE9eKNL9p4B","rHsMUQFzBb7S6GnQFVgNirqvHRcLpAn5dU","rDsbeomae4FXwgQTJp9Rs64Qg9vDiTCdBv","rMQ98K56yXJbDGv49ZSmW51sLn94Xe1mu1","rKiCet8SdvWxPXnAgYarFUXMh1zCPz432Y","r9mhdcT2K7FdCGDEPqfbMJwVXsXCqEr5bP","r4GDFMLGJUKMjNEycBKPGnRSNXyNVLQLHi","rUA1S9qobBkxLqzdfGEzh5wm5KdLfbf8bx","rHtbQzmN4BDaEBnGSXp3AZaZAuZamNVsME","rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq","razqnFn6FqBaYBdNaGnVzmGaNE6XPRQ9bG","rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh","r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59","rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY","rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz"]),he={dexPressure:[],nftMints:[],nftBurns:[],autoBridge:[],marketPrice:[],marketVol:[]},Gt=null,ao=0,vt={acct:new Map},ds={window:[],totals:new Map,maxLedgers:12},Ae={window:[],smoothCancelPerMin:null,smoothBurst:null},ae={byAddr:new Map,selectedAddr:null,selectedProof:null,allowList:new Set,verifiedCache:new Map},Sr=!1,Tr=!1,Cr=!1,lo=!1,Lr=!1,Mr=!1,Pr=!1,Ar=!1,Er=!1,Nr=!1,_r=!1,Rr=!1,Dr=!1,Ir=!1,Fr=!1,Br=!1,Or=!1,Xr=!1,vn=!1,us=!1,co={};var po=new Map;function Qs(e,t,n=2){let s=po.get(e)??-999;return Number(t)-s<n?!1:(po.set(e,Number(t)),!0)}var We={ledgersProcessed:0,startTime:Date.now(),totalTx:0,whaleCount:0,feeSpikes:0,botDetections:0,dexAlerts:0},yt=[],Au=40,bn={whaleTxXrp:1e5,feeSpikeMultiple:5,botCvThreshold:.2,dexCancelAlert:.75,clusterMinSize:5},sl=0,oa="naluxrp_widget_order",qn="naluxrp_widget_hidden",Dn=null,Rt=!1,Hr=!1,al=!0;function Ft(){return al&&O.currentPage==="dashboard"&&O.currentTab==="stream"&&!document.hidden}var On=[],Eu=30,Nu=0;function ol(){Hu(),Uu(),Nm(),Dm(),Gu(),Zu(),$m(),Sm(),Ku(),Iu(),Fu(),Vm(),Tm(),Mm(),Am(),Ym(),Zm(),tf(),Ft()&&ra(),cf(),df(),af(),pf(),uf(),mf(),window.addEventListener("xrpl-connection",e=>{var n;!!((n=e==null?void 0:e.detail)!=null&&n.connected)&&sm()}),window.addEventListener("xrpl-ledger",e=>{if(!Ft())return;let t=e.detail,n=Number(t.ledgerIndex||0);We.ledgersProcessed++,We.totalTx+=Number(t.txPerLedger||0),["risk-badge","risk-regime","risk-friction","risk-signalcount","landscape-badge","dexp-badge","dexP-badge","ab-badge","nft-badge","whale-badge","ss-badge","health-badge","pattern-badge"].forEach(a=>delete co[a]),Wu(t),Ju(),Vu(),Yu(),om(t.latestLedger),Jm(t.recentTransactions||[],n);let s=cm(t);for(On.push({li:n,friction:s.friction,regime:s.regime});On.length>Eu;)On.shift();yl(),!Rt&&(Qs("breadcrumbs",n,1)&&wm(s.breadcrumbs),Qs("clusters",n,2)&&xm(s.clusters),Qs("narratives",n,2)&&km(s.narratives),Qs("landscape",n,3)&&Cm(s),Gm(t.txTypes,s.hhi),Pm(s.dexPatterns),Em(s),Rm(s),Fm(s),nf(),n-sl>=8&&sf(s,n))}),document.addEventListener("visibilitychange",()=>{Ft()?ra():bo()})}function il(e){al=!!e,Ft()?ra():bo()}function V(e,t){let n=y(e);n&&(n.textContent=String(t))}function ke(e,t,n){return Math.max(t,Math.min(n,e))}function Qt(e){return e!=null&&e.length?e.reduce((t,n)=>t+n,0)/e.length:null}function vo(e){if(!e||e.length<2)return null;let t=Qt(e),n=Qt(e.map(s=>(s-t)**2));return Math.sqrt(n)}function _u(e,t){return e!=null&&e.length?e.slice(Math.max(0,e.length-t)):[]}function Ru(e,t){let n=[];for(let s=0;s<e.length;s++){let a=Math.max(0,s-t+1);n.push(Qt(e.slice(a,s+1)))}return n}function Zt(e,t=0){return e==null||!Number.isFinite(e)?"\u2014":`${e>=0?"\u2191":"\u2193"}${Math.abs(e).toFixed(t)}%`}function In(e,t=2){return e==null||!Number.isFinite(e)?"\u2014":Number(e).toFixed(t)}function Jt(e){if(e==null||!Number.isFinite(e))return"\u2014";let t=Number(e);return t===0?"0 XRP":t>=1e3?`${t.toLocaleString(void 0,{maximumFractionDigits:2})} XRP`:t>=1?`${t.toFixed(4)} XRP`:t>=.01?`${t.toFixed(5)} XRP`:`${t.toFixed(6)} XRP`}function Xn(e,t=1){if(!e)return null;let n=ke(Number(t),0,1),s=String(e).trim();if(s.startsWith("rgba("))return s;if(s.startsWith("rgb(")){let a=s.match(/^rgb\(\s*([0-9]+)\s*,\s*([0-9]+)\s*,\s*([0-9]+)\s*\)$/i);if(!a)return null;let o=ke(Number(a[1]),0,255),i=ke(Number(a[2]),0,255),r=ke(Number(a[3]),0,255);return`rgba(${o},${i},${r},${n})`}if(s[0]==="#"){let a=s.slice(1);if(a.length===3&&(a=a.split("").map(l=>l+l).join("")),a.length!==6)return null;let o=parseInt(a.slice(0,2),16),i=parseInt(a.slice(2,4),16),r=parseInt(a.slice(4,6),16);return[o,i,r].every(Number.isFinite)?`rgba(${o},${i},${r},${n})`:null}return null}function zr(e,t,n=.45){return t==null||!Number.isFinite(t)?e:e==null||!Number.isFinite(e)?t:e*(1-n)+t*n}async function Du(e){if(typeof crypto<"u"&&crypto.subtle){let n=new TextEncoder().encode(e),s=await crypto.subtle.digest("SHA-512",n),a=new Uint8Array(s,0,32);return Array.from(a).map(o=>o.toString(16).padStart(2,"0")).join("")}let t=0x811c9dc5n;for(let n=0;n<e.length;n++)t^=BigInt(e.charCodeAt(n)),t=BigInt.asUintN(32,t*0x01000193n);return"FALLBACK-NON-CRYPTO-"+t.toString(16).padStart(8,"0").repeat(4).slice(0,44)}function Iu(){var n,s;if(Rr||(Rr=!0,document.getElementById("acctPeekOverlay")))return;let e=document.createElement("div");e.id="acctPeekOverlay",e.className="acct-peek-overlay",e.style.display="none",e.innerHTML=`
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
  `,document.body.appendChild(e);let t=()=>{e.style.display="none",e.removeAttribute("data-addr"),document.body.classList.remove("modal-open"),us=!1,bt=!1};e.addEventListener("click",a=>{a.target===e&&t()}),(n=y("acctPeekClose"))==null||n.addEventListener("click",t),(s=y("acctPeekInspect"))==null||s.addEventListener("click",async()=>{let a=e.getAttribute("data-addr");a&&await Xu(a),t()})}function Fu(){_r||(_r=!0,document.addEventListener("click",e=>{var s,a;let t=(a=(s=e.target).closest)==null?void 0:a.call(s,"[data-addr]");if(!t)return;let n=t.getAttribute("data-addr");n&&(e.preventDefault(),Ou(n))}))}function Ur(e){var r,l,c;if(!e||!((r=Ae==null?void 0:Ae.window)!=null&&r.length))return null;let t=0,n=0,s=0;for(let d of Ae.window)s+=Number(d.total||0),t+=Number(((l=d.byActorCreate)==null?void 0:l.get(e))||0),n+=Number(((c=d.byActorCancel)==null?void 0:c.get(e))||0);let a=t+n;if(!a)return null;let o=a?n/a:0,i=s?a/s:null;return{create:t,cancel:n,total:a,cancelRatio:o,share:i}}function Bu(e){var o;let t=(o=vt==null?void 0:vt.acct)==null?void 0:o.get(e);if(!t||!t.intervals||t.intervals.length<6)return null;let n=Qt(t.intervals),s=vo(t.intervals);return!n||s==null?null:{cv:s/n,total:t.total||0}}async function Ou(e){var i,r,l;if(!Ue(e))return;let t=document.getElementById("acctPeekOverlay");if(!t)return;t.style.display="flex",t.setAttribute("data-addr",e),document.body.classList.add("modal-open"),us=!0,bt=!0,V("acctPeekAddr",e),V("acctPeekBal","\u2026"),V("acctPeekSeq","\u2026"),V("acctPeekOwner","\u2026"),V("acctPeekFlags","\u2026");let n=y("acctPeekNote"),s=y("acctPeekCtx");n&&(n.textContent="Fetching account_info\u2026"),s&&(s.textContent="Building context\u2026");let a=vt.acct.get(e),o=((i=a==null?void 0:a.ledgers)==null?void 0:i.length)||0;try{if(!O.wsConn||O.wsConn.readyState!==1){n&&(n.textContent="Not connected to XRPL. Connect first.");return}let c=await Ne({command:"account_info",account:e,ledger_index:"validated",strict:!0}),d=(r=c==null?void 0:c.result)==null?void 0:r.account_data,u=Number((d==null?void 0:d.Balance)??NaN),p=Number.isFinite(u)?u/1e6:null;if(V("acctPeekBal",p==null?"\u2014":`${p.toLocaleString(void 0,{maximumFractionDigits:6})} XRP`),V("acctPeekSeq",(d==null?void 0:d.Sequence)??"\u2014"),V("acctPeekOwner",(d==null?void 0:d.OwnerCount)??"\u2014"),V("acctPeekFlags",(d==null?void 0:d.Flags)!=null?`0x${Number(d.Flags).toString(16)}`:"\u2014"),n){let m=[];p!=null&&p>=$u&&m.push("Large balance (whale-sized).");let f=Bu(e);f&&f.cv<.35&&f.total>10&&m.push(`Bot-like timing signal (CV ${f.cv.toFixed(2)}).`);let v=Ur(e);if(v){let w=Math.round(v.cancelRatio*100),k=v.share!=null?Math.round(v.share*100):null;m.push(`DEX activity: ${v.total} offer tx in window.`),m.push(`Creates ${v.create}, cancels ${v.cancel} (${w}% cancels).`),k!=null&&m.push(`~${k}% of window activity.`)}let h=ae.byAddr.get(e);if(h){let w=ms(h.level);m.push(`Spam-defense: score ${(h.score*100).toFixed(0)}% \xB7 level L${h.level} \xB7 bond ${w.toLocaleString()} XRP.`),h.verifiedLedger!=null&&m.push(`Credential verified at ledger #${Number(h.verifiedLedger).toLocaleString()}.`)}o>=6&&m.push(`Shows up often in recent ledgers (${o} times).`),m.length||m.push("No obvious red flags from this quick read."),n.textContent=m.join(" ")}if(s){let m=(l=a==null?void 0:a.ledgers)==null?void 0:l.at(-1),f=Ur(e),v=f?`DEX window: ${f.total} (creates ${f.create}, cancels ${f.cancel})`:null,h=yt.filter(x=>x.from===e||x.to===e).slice(0,3),w=h.length?`${h.length} whale tx in session (${h.map(x=>(x.amtXrp>=1e6?(x.amtXrp/1e6).toFixed(1)+"M":(x.amtXrp/1e3).toFixed(0)+"K")+" XRP").join(", ")})`:null,k=ae.byAddr.get(e),b=k?`Spam-defense: L${k.level} \xB7 score ${Math.round(k.score*100)}%`:null;s.textContent=[m?`Last seen around ledger #${Number(m).toLocaleString()}`:"Not in recent window.",v,w,b].filter(Boolean).join(" \xB7 ")}}catch(c){n&&(n.textContent=`Lookup failed: ${String((c==null?void 0:c.message)||c)}`),s&&(s.textContent="\u2014")}}async function Xu(e){if(!Ue(e))return;let t=document.querySelector('.dash-tab[data-tab="inspector"]'),n=document.getElementById("tab-inspector"),s=async()=>n&&n.style.display!=="none"?!0:(typeof window.switchTab=="function"&&t?window.switchTab(t,"inspector"):t==null||t.click(),await new Promise(o=>setTimeout(o,80)),n?n.style.display!=="none":!0);for(let o=0;o<6&&!await s();o++)await new Promise(r=>setTimeout(r,80));let a=document.getElementById("inspect-addr");a&&(a.value=e,a.focus()),await new Promise(o=>setTimeout(o,60)),typeof window.runInspect=="function"?window.runInspect():be("Inspector not ready yet.")}function Hu(){Ie(".net-btn[data-network]").forEach(e=>{e.addEventListener("click",()=>{let t=e.getAttribute("data-network");Ie(".net-btn").forEach(s=>{s.classList.toggle("active",s===e),s.setAttribute("aria-pressed",String(s===e))}),vt.acct.clear(),ds.window=[],ds.totals=new Map,Ae.window=[],Ae.smoothCancelPerMin=null,Ae.smoothBurst=null,Lt.length=0,aa.clear(),Oe=0,Dt=0,Ze=0,cs=0,It=!0,ia=0,mo=!1,ps=null,bt=!1,Yt=0,Hn=0,la=!1;let n=y("ledgerStreamTrack");n&&(n.innerHTML="",n.style.transform="translateX(0px)"),ul(null,null),_m(),ae.byAddr.clear(),ae.selectedAddr=null,ae.selectedProof=null,yo(),vl(),Un(null),Zi(t),ra({force:!0})})})}var sa=[],zu=8,oo=null,uo=0,ls=null;function Uu(){let e=document.querySelector(".dashboard-metric-grid");if(!e)return;let t=e.closest(".dashboard-metrics")||e.parentElement;t&&t.classList.add("dashboard-sticky-strip"),e.innerHTML=`
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
  `}function Wu(e){var v,h,w,k;let t=e.ledgerIndex?Number(e.ledgerIndex):null;V("d2-ledger-index",t?t.toLocaleString():"\u2014");let n=((v=e.latestLedger)==null?void 0:v.closeTimeSec)!=null?Number(e.latestLedger.closeTimeSec):null,s=y("d2-ledger-age");if(s&&(n!=null?(s.textContent=`${n<2?n.toFixed(2):n.toFixed(1)}s close`,s.style.color=n<=3?"#50fa7b":n<=6?"#ffb86c":"#ff6e6e"):(s.textContent="Waiting\u2026",s.style.color="")),n!=null&&(sa.push(n),sa.length>zu&&sa.shift(),ju()),uo=Date.now(),qu(),e.tps!=null){let b=Number(e.tps),x=y("d2-tps");x&&(x.textContent=b.toFixed(1),x.style.color=b<10?"rgba(255,255,255,.65)":b<40?"#50fa7b":b<80?"#ffb86c":"#ff6e6e");let S=y("d2-tps-trend");if(S){let T=O.tpsHistory||[],$=T.length>2?(T.slice(-10).reduce((M,N)=>M+N,0)/Math.min(T.length,10)).toFixed(1):null,P=b<10?"Low":b<40?"Normal":b<80?"High":"Peak";S.textContent=$?`${P} \xB7 avg ${$}`:P,S.style.color=b<10?"rgba(255,255,255,.55)":b<40?"#50fa7b":b<80?"#ffb86c":"#ff6e6e"}}let a=(((h=e.latestLedger)==null?void 0:h.totalTx)??e.txPerLedger)||0,o=y("d2-tx-per-ledger");o&&(o.textContent=a>0?a.toLocaleString():"\u2014",o.style.color=a<10?"rgba(255,255,255,.65)":a<150?"#50fa7b":a<400?"#ffb86c":"#ff6e6e");let i=y("d2-tx-spread");i&&a>0&&(i.textContent=a<10?"Very light":a<50?"Light":a<150?"Normal":a<400?"High volume":"Very high volume",i.style.color=a<150?"":a<400?"#ffb86c":"#ff6e6e");let r=e.avgFee!=null?Number(e.avgFee):((w=e.latestLedger)==null?void 0:w.avgFee)!=null?Number(e.latestLedger.avgFee):null;if(r!=null){let b=Math.round(r*1e6),x=y("d2-fee-value");x&&(x.textContent=Jt(r),x.style.color=b<=15?"#50fa7b":b<=50?"rgba(255,255,255,.9)":b<=200?"#ffb86c":"#ff6e6e");let S=y("d2-fee-delta");if(S)if(oo!=null){let $=r/oo;$>1.05?(S.textContent="\u2191",S.style.color="#ff6e6e",S.title=`+${(($-1)*100).toFixed(0)}% vs prev ledger`):$<.95?(S.textContent="\u2193",S.style.color="#50fa7b",S.title=`-${((1-$)*100).toFixed(0)}% vs prev ledger`):(S.textContent="\u2192",S.style.color="rgba(255,255,255,.35)",S.title="Stable vs prev ledger")}else S.textContent="";oo=r;let T=y("d2-fee-pressure");if(T){let $=b<=15?"Base fee":b<=50?`${b} drops`:b<=200?`${b} drops \xB7 Elevated`:`${b} drops \xB7 Surge`;T.textContent=$,T.style.color=b<=50?"":b<=200?"#ffb86c":"#ff6e6e"}}let l=e.successRate!=null?Number(e.successRate):((k=e.latestLedger)==null?void 0:k.successRate)!=null?Number(e.latestLedger.successRate):null;if(l!=null){let b=y("d2-success-rate");b&&(b.textContent=`${l.toFixed(1)}%`,b.style.color=l>=90?"#50fa7b":l>=75?"#ffb86c":"#ff6e6e");let x=y("d2-success-note");if(x){let S=(100-l).toFixed(1);x.textContent=l>=90?`${S}% failed \xB7 Normal`:l>=75?`${S}% failed \xB7 Watch`:`${S}% failed \xB7 Alert`,x.style.color=l>=90?"":l>=75?"#ffb86c":"#ff6e6e"}}let c=a>0?Math.min(100,a/500*100):null,d=y("d2-network-capacity"),u=y("d2-capacity-note");c!=null&&(d&&(d.textContent=`${c.toFixed(1)}%`,d.style.color=c<20?"rgba(255,255,255,.65)":c<50?"#50fa7b":c<80?"#ffb86c":"#ff6e6e"),u&&(u.textContent=c<20?"Low usage":c<50?"Moderate":c<80?"Heavy":"Near capacity",u.style.color=c<50?"":c<80?"#ffb86c":"#ff6e6e"));let p=e.txTypes||{},m=Object.entries(p).sort(([,b],[,x])=>x-b);if(m.length){let[b,x]=m[0],S=m.reduce((N,[,_])=>N+_,0)||1,T=(x/S*100).toFixed(0),$=typeof Tt<"u"?Tt:{},P=y("d2-dominant-type");P&&(P.textContent=b,P.style.color=$[b]||"rgba(255,255,255,.9)");let M=y("d2-dominance-score");if(M){let N=m[1];M.textContent=N?`${T}% \xB7 2nd: ${N[0]}`:`${T}% of txs`}}let f=y("stream-loading");f&&(f.style.display="none")}function ju(){let e=y("d2-close-sparkline");if(!e||!e.getContext)return;let t=sa;if(t.length<2)return;let n=e.width,s=e.height,a=e.getContext("2d");a.clearRect(0,0,n,s);let o=Math.max(...t,4),i=Math.floor((n-(t.length-1))/t.length),r=1;t.forEach((l,c)=>{let d=Math.max(3,Math.round(l/o*(s-2))),u=c*(i+r),p=s-d,m=l<=3?"rgba(80,250,123,.80)":l<=6?"rgba(255,184,108,.80)":"rgba(255,110,110,.85)";a.fillStyle=m;let f=Math.min(2,i/2);a.beginPath(),a.moveTo(u+f,p),a.lineTo(u+i-f,p),a.quadraticCurveTo(u+i,p,u+i,p+f),a.lineTo(u+i,s),a.lineTo(u,s),a.lineTo(u,p+f),a.quadraticCurveTo(u,p,u+f,p),a.closePath(),a.fill(),c===t.length-1&&(a.fillStyle="rgba(255,255,255,.18)",a.fillRect(u,p,i,Math.min(3,d)))})}function qu(){if(ls&&cancelAnimationFrame(ls),!Ft())return;let e=0,t=n=>{if(!Ft()){ls=null;return}if(n-e>=120){e=n;let s=y("d2-ledger-age-timer");if(s&&uo>0){let a=(Date.now()-uo)/1e3;s.textContent=`${a.toFixed(1)}s ago`,s.style.color=a<4?"rgba(255,255,255,.55)":a<7?"#ffb86c":"#ff6e6e",s.style.opacity=a>=7?(.6+.4*Math.sin(Date.now()/300)).toFixed(2):"1"}}ls=requestAnimationFrame(t)};ls=requestAnimationFrame(t)}function Vu(){let e=y("tx-mix");if(!e)return;let t=Object.entries(O.txMixAccum||{}).filter(([,s])=>s>0).sort(([,s],[,a])=>a-s).slice(0,10),n=t.reduce((s,[,a])=>s+a,0);n&&(e.innerHTML=t.map(([s,a])=>{let o=(a/n*100).toFixed(1),i=Tt[s]||"#6b7280";return`
      <div class="tx-mix-row">
        <span class="tx-mix-label">${g(s)}</span>
        <div class="tx-mix-bar">
          <div class="tx-mix-fill" style="width:${o}%;background:${i}"></div>
        </div>
        <span class="tx-mix-pct">${o}%</span>
      </div>`}).join(""))}var ct=class{constructor(t,n="#00fff0",s="area"){this.canvasId=t,this.canvas=y(t),this.color=n,this.mode=s}_resolveCanvas(){return this.canvas||(this.canvas=y(this.canvasId)),this.canvas}draw(t){let n=this._resolveCanvas();if(!n||!(t!=null&&t.length))return;let s=n.getContext("2d");if(!s)return;let a=n.width=n.offsetWidth||300,o=n.height=n.offsetHeight||180;if(s.clearRect(0,0,a,o),t.length<2)return;let i=Math.min(...t)*.9,r=Math.max(...t)*1.05||1,l=h=>1-(h-i)/(r-i||1),c={l:10,r:10,t:10,b:12},d=a-c.l-c.r,u=o-c.t-c.b,p=d/(t.length-1),m=t.map((h,w)=>[c.l+w*p,c.t+l(h)*u]),f=Qt(t);if(f!=null){let h=c.t+l(f)*u;s.beginPath(),s.moveTo(c.l,h),s.lineTo(c.l+d,h),s.strokeStyle="rgba(255,255,255,0.16)",s.lineWidth=1,s.stroke()}if(t.length>=wr+2){let w=Ru(t,wr).map((k,b)=>[c.l+b*p,c.t+l(k)*u]);s.beginPath(),w.forEach(([k,b],x)=>x===0?s.moveTo(k,b):s.lineTo(k,b)),s.strokeStyle="rgba(255,255,255,0.22)",s.lineWidth=1.5,s.stroke()}if(this.mode==="bar"){let h=Math.max(1,p-3);t.forEach((w,k)=>{let b=(1-l(w))*u,x=c.l+k*p-h/2,S=s.createLinearGradient(0,c.t,0,c.t+u);S.addColorStop(0,this.color),S.addColorStop(1,this.color+"33"),s.fillStyle=S,s.fillRect(x,c.t+u-b,h,b)});return}let v=s.createLinearGradient(0,c.t,0,c.t+u);v.addColorStop(0,this.color+"aa"),v.addColorStop(1,this.color+"11"),s.beginPath(),m.forEach(([h,w],k)=>k===0?s.moveTo(h,w):s.lineTo(h,w)),s.lineTo(m.at(-1)[0],c.t+u),s.lineTo(m[0][0],c.t+u),s.closePath(),s.fillStyle=v,s.fill(),s.beginPath(),m.forEach(([h,w],k)=>k===0?s.moveTo(h,w):s.lineTo(h,w)),s.strokeStyle=this.color,s.lineWidth=2,s.lineJoin="round",s.stroke()}},ye={};function Gu(){ye.tps=new ct("chart-tps","#50fa7b","area"),ye.fee=new ct("chart-fee","#ffb86c","area"),ye.tps2=new ct("chart-tps2","#50fa7b","bar"),ye.fee2=new ct("chart-fee2","#ffb86c","area"),ye.dexPressure=new ct("chart-dex-pressure","#00d4ff","bar"),ye.nftMints=new ct("chart-nft-mints","#bd93f9","bar"),ye.nftBurns=new ct("chart-nft-burns","#ff5555","bar"),ye.autoBridge=new ct("chart-autobridge","#f1fa8c","bar"),ye.marketPrice=new ct("chart-market-price","#50fa7b","area"),ye.marketVol=new ct("chart-market-vol","#8be9fd","bar")}function Mt(e,t=Bt){let n=_u(e,t).filter(r=>Number.isFinite(r));if(!n.length)return{cur:null,avg:null,deltaPct:null,vol:null};let s=n.at(-1),a=Qt(n),o=vo(n),i=a&&a!==0?(s-a)/a*100:null;return{cur:s,avg:a,deltaPct:i,vol:o}}function Ku(){if(Cr)return;Cr=!0;let e=(t,n)=>{let s=y(t);if(!s)return;let a=s.closest(".widget-card"),o=a==null?void 0:a.querySelector(".widget-header");if(!o||document.getElementById(n))return;let i=document.createElement("div");i.className="trend-mini",i.id=n,i.innerHTML=`
      <div class="trend-mini-row">
        <div class="trend-mini-cell"><span class="trend-mini-k">Now</span><span class="trend-mini-v" data-k="now">\u2014</span></div>
        <div class="trend-mini-cell"><span class="trend-mini-k">Avg</span><span class="trend-mini-v" data-k="avg">\u2014</span></div>
      </div>
      <div class="trend-mini-row">
        <div class="trend-mini-cell"><span class="trend-mini-k">\u0394</span><span class="trend-mini-v" data-k="delta">\u2014</span></div>
        <div class="trend-mini-cell"><span class="trend-mini-k">\u03C3</span><span class="trend-mini-v" data-k="sigma">\u2014</span></div>
      </div>
    `,o.appendChild(i)};e("chart-tps","tpsTrendMini"),e("chart-fee","feeTrendMini"),e("chart-tps2","tpsTrendMini2"),e("chart-fee2","feeTrendMini2")}function Zs(e,t,n,s){let a=document.getElementById(e);if(!a)return;let o=(i,r)=>{let l=a.querySelector(`[data-k="${i}"]`);l&&(l.textContent=r)};if(t.cur==null){o("now","\u2014"),o("avg","\u2014"),o("delta","\u2014"),o("sigma","\u2014");return}o("now",`${Number(t.cur).toFixed(n)}${s}`),o("avg",t.avg!=null?`${Number(t.avg).toFixed(n)}${s}`:"\u2014"),o("delta",t.deltaPct==null?"\u2014":Zt(t.deltaPct,0)),o("sigma",t.vol==null?"\u2014":`${Number(t.vol).toFixed(Math.max(0,n-1))}${s}`)}function Ju(){var n,s,a,o,i,r,l,c,d,u;(n=ye.tps)==null||n.draw(O.tpsHistory),(s=ye.fee)==null||s.draw(O.feeHistory),(a=ye.tps2)==null||a.draw(O.tpsHistory),(o=ye.fee2)==null||o.draw(O.feeHistory);let e=Mt(O.tpsHistory,Bt),t=Mt(O.feeHistory,Bt);Zs("tpsTrendMini",e,2,""),Zs("tpsTrendMini2",e,2,""),Zs("feeTrendMini",t,0,"d"),Zs("feeTrendMini2",t,0,"d"),(i=ye.dexPressure)==null||i.draw(he.dexPressure),(r=ye.nftMints)==null||r.draw(he.nftMints),(l=ye.nftBurns)==null||l.draw(he.nftBurns),(c=ye.autoBridge)==null||c.draw(he.autoBridge),(d=ye.marketPrice)==null||d.draw(he.marketPrice),(u=ye.marketVol)==null||u.draw(he.marketVol)}function Yu(){let e=y("ledger-log"),t=y("ledger-log-loading"),n=y("ledger-log-count");if(!e||!(O.ledgerLog||[]).length)return;t&&(t.style.display="none"),n&&(n.textContent=O.ledgerLog.length);let s=y("tab-network");!s||s.style.display==="none"||(e.innerHTML=`<div class="ledger-log-row log-head">
      <span>Ledger</span><span>TXs</span><span>TPS</span><span>Close</span><span>Time</span>
    </div>`+O.ledgerLog.slice(0,60).map(a=>`
      <div class="ledger-log-row">
        <span class="log-index">#${a.ledgerIndex.toLocaleString()}</span>
        <span class="log-tx">${a.txCount}</span>
        <span class="log-tps">${a.tps}</span>
        <span class="log-close">${a.closeTimeSec}s</span>
        <span class="log-time">${a.time}</span>
      </div>`).join(""))}var Lt=[],aa=new Set,Oe=0,ea=null,cs=0,Dt=0,Ze=0,It=!0,ta=0,bt=!1,ia=0,mo=!1,ps=null,Yt=0,Hn=0,la=!1,Qu=.18;function Zu(){em(),tm()}function em(){let e=y("ledgerStreamParticles");if(e){e.innerHTML="";for(let t=0;t<14;t++){let n=document.createElement("div");n.className="ledger-particle",n.style.left=Math.random()*100+"%",n.style.top=20+Math.random()*60+"%",n.style.animationDuration=6+Math.random()*8+"s",n.style.animationDelay=Math.random()*5+"s",e.appendChild(n)}}}function tm(){if(ea)return;let e=y("ledgerStreamShell");e&&(e.addEventListener("mouseenter",()=>{bt=!0}),e.addEventListener("mouseleave",()=>{us||(bt=!1)}));let t=y("ledgerStreamTrack");t&&t.addEventListener("click",s=>{let a=s.target.closest("article.ledger-card");if(!a)return;let o=Number(a.dataset.ledgerIndex);Number.isFinite(o)&&(s.shiftKey?ps===o?(ps=null,us||(bt=!1),Wr()):(ps=o,bt=!0,Wr()):nm(o))});let n=s=>{cs||(cs=s);let a=Math.min(.05,(s-cs)/1e3);cs=s;let o=Ft()?y("ledgerStreamTrack"):null;if(o&&Oe>0){if(It){let i=o.scrollWidth||0;if(i>100)Ze=Math.floor(i/2),It=!1,ta=0,Oe>0&&(Yt=Ze/Oe);else{ta++,ta>30&&(It=!1,ta=0),ea=requestAnimationFrame(n);return}}if(Ze>0&&!bt&&la){let i=Math.min(1,a/Qu);Dt+=(Hn-Dt)*i,Math.abs(Hn-Dt)<.5&&(Dt=Hn);let r=Dt%Ze;o.style.transform=`translateX(${-r}px)`}if(!bt&&Math.floor(s/250)!==Math.floor((s-a*1e3)/250)){let i=Date.now(),r=o.querySelectorAll("article.ledger-card[data-arrival-ts]"),l=12e4;r.forEach(c=>{let d=i-Number(c.dataset.arrivalTs||i),u=Math.max(.52,1-d/l*.48);c.style.opacity=u.toFixed(3)})}if(ia>0){let i=Date.now()-ia>Mu;ll(i)}}ea=requestAnimationFrame(n)};ea=requestAnimationFrame(n),window.addEventListener("resize",()=>{It=!0})}function rl(){if(Yt<=0||Ze<=0||Oe===0)return Dt;let e=y("ledgerStreamShell"),t=e&&e.offsetWidth||800,n=Yt-14,a=(Oe-1)*Yt+n-t+18;a=Math.max(0,a);let i=Math.floor(Dt/Ze)*Ze+a;return i<Dt-2&&(i+=Ze),i}function ll(e){if(e===mo)return;mo=e;let t=y("ledgerStreamShell");if(!t)return;let n=t.querySelector(".stream-stall-overlay");e?n||(n=document.createElement("div"),n.className="stream-stall-overlay",n.innerHTML='<span class="stream-stall-dot"></span> Waiting for ledgers\u2026',t.appendChild(n)):n==null||n.remove()}function Wr(){document.querySelectorAll(".ledger-card").forEach(e=>{let t=Number(e.dataset.ledgerIndex);e.classList.toggle("ledger-card--pinned",t===ps)})}function nm(e){let t=document.querySelector('.dash-tab[data-tab="inspector"]');typeof window.switchTab=="function"&&t?window.switchTab(t,"inspector"):t==null||t.click();let n=document.getElementById("inspect-addr");n&&(n.placeholder=`Ledger #${e.toLocaleString()} \u2014 paste an address`,n.focus())}function sm(){var t;let e=y("ledgerStreamShell");e&&(e.classList.remove("stream-reconnect-flash"),e.offsetWidth,e.classList.add("stream-reconnect-flash"),setTimeout(()=>e.classList.remove("stream-reconnect-flash"),1200),Nu=((t=On.at(-1))==null?void 0:t.li)??0,am())}function am(){let e=document.getElementById("reconnect-banner");if(!e){e=document.createElement("div"),e.id="reconnect-banner",e.className="reconnect-banner";let s=document.querySelector(".dashboard-col-main");s&&s.prepend(e)}e.style.display="",e.innerHTML=`
    <span class="reconnect-dot"></span>
    <span>Reconnected \u2014 rebuilding signal baseline (<span id="reconnect-countdown">3</span> ledgers)</span>
    <button onclick="document.getElementById('reconnect-banner').style.display='none'"
      style="margin-left:auto;background:none;border:none;color:inherit;opacity:.5;cursor:pointer;font-size:.9rem">\u2715</button>`;let t=3,n=setInterval(()=>{let s=document.getElementById("reconnect-countdown");if(s&&(s.textContent=t),t--,t<0){clearInterval(n);let a=document.getElementById("reconnect-banner");a&&(a.style.display="none")}},4e3)}function jr(){let e=y("ledgerStreamTrack"),t=y("ledgerStreamShell"),n=y("stream-loading");if(!e||!t)return;if(n&&(n.style.display="none"),Lt.length===0){e.innerHTML='<div style="padding:40px;opacity:.6">Waiting for ledgers\u2026</div>',Oe=0,It=!0;return}let s=[...Lt].sort((o,i)=>o.ledgerIndex-i.ledgerIndex),a=s.map((o,i)=>dl(o,{prevIndex:i>0?s[i-1].ledgerIndex:null}));e.innerHTML=a.concat(a).join(""),Oe=s.length,It=!0,requestAnimationFrame(()=>{var i;let o=((i=y("ledgerStreamTrack"))==null?void 0:i.scrollWidth)||0;o>100&&(Ze=Math.floor(o/2),Yt=Oe>0?Ze/Oe:0,Hn=rl(),la=!0,It=!1)})}function om(e){var f,v;if(!e)return;let t=Number(e.ledgerIndex??NaN);if(!Number.isFinite(t)||aa.has(t))return;aa.add(t),Lt.push(e);let n=0;if(Lt.length>$r){let h=Lt.splice(0,Lt.length-$r);h.forEach(w=>aa.delete(w.ledgerIndex)),n=h.length}ia=Date.now(),ll(!1),rm(e.avgFee!=null?Number(e.avgFee):null);let{auraClass:s,domColor:a}=lm(e);ul(s,a);let o=y("stream-loading");o&&(o.style.display="none");let i=y("ledgerStreamTrack");if(!i)return;if(Oe===0){jr();return}let r=Lt.length>=2?Lt[Lt.length-2].ledgerIndex:0;if(t<r){jr();return}let l=Oe,c=dl(e),d=document.createElement("template");d.innerHTML=c;let u=d.content.firstElementChild,p=i.children[l];p?i.insertBefore(u,p):i.appendChild(u);let m=document.createElement("template");if(m.innerHTML=c,i.appendChild(m.content.firstElementChild),Oe=l+1,n>0){for(let w=0;w<n;w++)(f=i.children[0])==null||f.remove();let h=Oe-n;for(let w=0;w<n;w++)(v=i.children[h])==null||v.remove();Oe-=n}It=!0,requestAnimationFrame(()=>{Yt<=0&&Ze>0&&Oe>0&&(Yt=Ze/Oe),Hn=rl(),la=!0})}var zn=[],im=20;function rm(e){e==null||!Number.isFinite(e)||(zn.push(e),zn.length>im&&zn.shift())}function cl(){return zn.length===0?null:zn.reduce((e,t)=>e+t,0)/zn.length}function dl(e,t={}){let{ledgerIndex:n,closeTimeSec:s,totalTx:a,txTypes:o,avgFee:i}=e,r=o||{},l=a??0,c=Object.entries(r).sort(([,I],[,R])=>R-I)[0],d=(c==null?void 0:c[0])||"Other",u=pl(d),p=typeof Tt<"u"?Tt:{},m=I=>p[I]||"#6b7280",f=m(d),v=Xn(f,.45)||f,h=Xn(f,.14)||f,w=s==null?"\u2014":s<2?`${Number(s).toFixed(2)}s`:`${Number(s).toFixed(1)}s`,k=l>0&&s>0?(l/s).toFixed(1):null,b=i!=null?Number(i):null,x=b!=null?Jt(b):"\u2014",S=cl(),T=b!=null&&S!=null&&b>S*3,$=t.prevIndex!=null?Number(n)-t.prevIndex-1:0,P=$>0?`<div class="stream-gap-badge" title="${$} ledger(s) missing">\xB7\xB7\xB7&nbsp;${$} gap</div>`:"",M=I=>l>0?`${(I/l*100).toFixed(1)}%`:"0%",N=(I,R,F)=>R?`<div class="ledger-type-row">
      <span class="ledger-type-label cut">${g(I)}</span>
      <div class="ledger-type-bar"><div class="ledger-type-fill" style="width:${M(R)};background:${F}"></div></div>
      <span class="ledger-type-count">${R}</span>
    </div>`:"",_=(r.AMMCreate||0)+(r.AMMDeposit||0)+(r.AMMWithdraw||0)+(r.AMMVote||0),X=Date.now();return`${P}<article class="ledger-card ledger-card--${u} ledger-card--entry${T?" ledger-card--fee-spike":""}"
    data-ledger-index="${Number(n??0)}"
    data-arrival-ts="${X}"
    style="border-color:${v};box-shadow:0 0 22px ${h};flex-shrink:0">
    <div class="ledger-card-inner">
      <div class="ledger-card-header">
        <span class="ledger-id">#${(n||0).toLocaleString()}</span>
        <div class="ledger-meta">
          <span class="ledger-tag cut" style="border-color:${v};color:${f}">${g(d)}</span>
          ${T?'<span class="fee-spike-badge" title="Fee spike: 3\xD7 baseline">\u{1F525}</span>':""}
        </div>
      </div>
      <div class="ledger-main-row">
        <div class="ledger-main-stat"><span class="ledger-stat-label">TXs</span><span class="ledger-stat-value">${l}</span></div>
        <div class="ledger-main-stat"><span class="ledger-stat-label">Close</span><span class="ledger-stat-value">${w}</span></div>
        <div class="ledger-main-stat"><span class="ledger-stat-label">Avg Fee</span><span class="ledger-stat-value${T?" fee-spike-value":""}">${x}</span></div>
        ${k!=null?`<div class="ledger-main-stat"><span class="ledger-stat-label">TPS</span><span class="ledger-stat-value">${k}</span></div>`:""}
      </div>
      <div class="ledger-type-bars">
        ${N("Payment",r.Payment,m("Payment"))}
        ${N("OfferCreate",r.OfferCreate,m("OfferCreate"))}
        ${N("OfferCancel",r.OfferCancel,m("OfferCancel"))}
        ${N("TrustSet",r.TrustSet,m("TrustSet"))}
        ${N("NFT Mint",r.NFTokenMint,m("NFTokenMint"))}
        ${_?N("AMM",_,m("AMMCreate")):""}
        ${N("EscrowCreate",r.EscrowCreate,"#6b7280")}
        ${(r.Other||0)>0?N("Other",r.Other,"#6b7280"):""}
      </div>
    </div>
  </article>`}function pl(e){let t=String(e||"");return t==="Payment"?"payment":t.startsWith("Offer")?"offer":t.startsWith("NFToken")?"nft":t==="TrustSet"?"trust":t.startsWith("AMM")?"amm":"other"}function lm(e){var o;let n=((o=Object.entries(e.txTypes||{}).sort(([,i],[,r])=>r-i)[0])==null?void 0:o[0])||"Other",s=pl(n),a=Tt[n]||Tt.Other||"#6b7280";return{dominantTx:n,auraClass:s,domColor:a}}function ul(e,t){let n=y("ledgerStreamShell");if(!n)return;if(!e||!t){n.style.removeProperty("--streamTintStrong"),n.style.removeProperty("--streamTintSoft"),n.style.removeProperty("--streamTintBorder");return}let s=Xn(t,.16)||"rgba(0,255,240,0.14)",a=Xn(t,.06)||"rgba(0,255,240,0.06)",o=Xn(t,.22)||"rgba(0,255,240,0.22)";n.style.setProperty("--streamTintStrong",s),n.style.setProperty("--streamTintSoft",a),n.style.setProperty("--streamTintBorder",o),n.dataset.tint=e}function cm(e){var h,w;let t=Array.isArray(e.recentTransactions)?e.recentTransactions.slice(0,ku):[],n=e.txTypes||{},s=Number(e.ledgerIndex||0),a=Object.values(n).reduce((k,b)=>k+b,0)||1,o=0;for(let k of Object.values(n)){let b=k/a;o+=b*b}let i=dm(t);pm(ds,i);let r=um(ds.totals,i),l=mm(ds.totals),c=fm(s,t),d=hm(s,(h=e.latestLedger)==null?void 0:h.closeTimeSec,t),u=gm({txs:t,txTypes:n,dexPatterns:d}),p=r.filter(k=>k.count>=2).length,m=vm({hhi:o,repeats:p,dex:d,bots:((w=c.bots)==null?void 0:w.length)||0,advanced:u}),f=bm({friction:m,tps:Mt(O.tpsHistory),fee:Mt(O.feeHistory)}),v=ym({s:e,txTypes:n,hhi:o,dexPatterns:d,behavior:c,friction:m,regime:f,breadcrumbs:r,clusters:l,advanced:u});return{s:e,txs:t,txTypes:n,hhi:o,behavior:c,dexPatterns:d,friction:m,regime:f,breadcrumbs:r,clusters:l,narratives:v,advanced:u}}function dm(e){let t=new Map;for(let n of e){let s=n==null?void 0:n.account,a=n==null?void 0:n.destination;if(!s||!a)continue;let o=`${s}|${a}`;t.set(o,(t.get(o)||0)+1)}return t}function pm(e,t){e.window.unshift(t);for(let[n,s]of t.entries())e.totals.set(n,(e.totals.get(n)||0)+s);for(;e.window.length>e.maxLedgers;){let n=e.window.pop();for(let[s,a]of n.entries()){let o=(e.totals.get(s)||0)-a;o<=0?e.totals.delete(s):e.totals.set(s,o)}}}function um(e,t){let s=[...e.entries()].map(([o,i])=>({k:o,c:i})).sort((o,i)=>i.c-o.c).filter(o=>o.c>=2);return(s.length?s:[...t.entries()].map(([o,i])=>({k:o,c:i}))).slice(0,10).map(({k:o,c:i})=>{let[r,l]=o.split("|");return{from:r,to:l,count:i}})}function mm(e){let t=[...e.entries()].filter(([,i])=>i>=2),n=t.length?t:[...e.entries()],s=new Map;for(let[i]of n){let[r,l]=i.split("|");!r||!l||(s.has(r)||s.set(r,new Set),s.has(l)||s.set(l,new Set),s.get(r).add(l),s.get(l).add(r))}let a=new Set,o=[];for(let i of s.keys()){if(a.has(i))continue;let r=[i],l=[];for(a.add(i);r.length;){let u=r.pop();l.push(u);for(let p of s.get(u)||[])a.has(p)||(a.add(p),r.push(p))}if(l.length<2)continue;let c=l[0],d=-1;for(let u of l){let p=(s.get(u)||new Set).size;p>d&&(d=p,c=u)}o.push({members:l,size:l.length,hub:c})}return o.sort((i,r)=>r.size-i.size),o.slice(0,6)}function fm(e,t){let n=new Map;for(let a of t){let o=a==null?void 0:a.account;o&&n.set(o,(n.get(o)||0)+1)}for(let[a,o]of n.entries()){vt.acct.has(a)||vt.acct.set(a,{ledgers:[],intervals:[],total:0});let i=vt.acct.get(a),r=i.ledgers.at(-1);i.ledgers.push(e),r!=null&&e>r&&i.intervals.push(e-r),i.ledgers.length>30&&i.ledgers.shift(),i.intervals.length>29&&i.intervals.shift(),i.total+=o}let s=[];for(let[a,o]of vt.acct.entries()){if(o.intervals.length<6)continue;let i=Qt(o.intervals),r=vo(o.intervals);if(!i||r==null)continue;let l=r/i;l<.35&&o.total>10&&s.push({acct:a,cv:l,total:o.total})}if(s.sort((a,o)=>a.cv-o.cv||o.total-a.total),e%50===0)for(let[a,o]of vt.acct){let i=o.ledgers.at(-1)??e;e-i>1e3&&vt.acct.delete(a)}return{bots:s.slice(0,6),uniqueActors:n.size}}function hm(e,t,n){var P;let s=0,a=0,o=new Map,i=new Map,r=new Map;for(let M of n){let N=M==null?void 0:M.type,_=M==null?void 0:M.account;_&&(N==="OfferCreate"?(s+=1,o.set(_,(o.get(_)||0)+1),i.set(_,(i.get(_)||0)+1)):N==="OfferCancel"&&(a+=1,o.set(_,(o.get(_)||0)+1),r.set(_,(r.get(_)||0)+1)))}let l=s+a,c=l?a/l:0,d=t!=null&&Number(t)>0?a/Number(t)*60:null;for(Ae.smoothCancelPerMin=zr(Ae.smoothCancelPerMin,d,.45),Ae.window.unshift({li:e,closeTimeSec:t??null,create:s,cancel:a,total:l,cancelRatio:c,cancelsPerMin:Ae.smoothCancelPerMin,byActor:o,byActorCreate:i,byActorCancel:r});Ae.window.length>Su;)Ae.window.pop();let u={create:0,cancel:0,total:0},p=new Map,m=new Map,f=new Map;for(let M of Ae.window){u.create+=M.create,u.cancel+=M.cancel,u.total+=M.total;for(let[N,_]of M.byActor.entries())p.set(N,(p.get(N)||0)+_);for(let[N,_]of M.byActorCancel.entries())m.set(N,(m.get(N)||0)+_);for(let[N,_]of M.byActorCreate.entries())f.set(N,(f.get(N)||0)+_)}let v=io(p,5),h=io(m,5),w=io(f,5),k=u.total?(((P=v[0])==null?void 0:P.count)||0)/u.total:0,b=0;if(u.total)for(let M of p.values()){let N=M/u.total;b+=N*N}let x=Ae.window.map(M=>M.total).filter(Number.isFinite),S=Qt(x)||0,T=S>0?(l-S)/S*100:null;Ae.smoothBurst=zr(Ae.smoothBurst,T,.4);let $=[];return u.total>=so&&c>=.65&&$.push("Lots of cancels (looks like quote-stuffing/spam)"),u.total>=so&&k>=.35&&$.push("One actor dominates DEX activity"),u.total>=so&&(Ae.smoothCancelPerMin||0)>=18&&$.push("Fast cancelling (high churn)"),Ae.smoothBurst!=null&&Math.abs(Ae.smoothBurst)>=45&&$.push("Sudden DEX burst"),{now:{li:e,create:s,cancel:a,total:l,cancelRatio:c,cancelsPerMin:Ae.smoothCancelPerMin},window:{...u,cancelRatio:u.total?u.cancel/u.total:0},topShare:k,actorHHI:b,burstPct:Ae.smoothBurst,topActor:v,topCanceller:h,topMaker:w,signals:$}}function io(e,t){return[...e.entries()].sort((n,s)=>s[1]-n[1]).slice(0,t).map(([n,s])=>({acct:n,count:s}))}function gm({txs:e,txTypes:t,dexPatterns:n}){var W;let s=Number((t==null?void 0:t.OfferCreate)||0)+Number((t==null?void 0:t.OfferCancel)||0),a=Number((t==null?void 0:t.NFTokenMint)||0),o=Number((t==null?void 0:t.NFTokenBurn)||0),i=0,r=new Map,l=new Map;for(let E of e){if((E==null?void 0:E.type)!=="Payment")continue;let z=(E==null?void 0:E.paths)||(E==null?void 0:E.Paths),Q=Array.isArray(z)&&z.length>0,ie=(E==null?void 0:E.sendmax)!=null||(E==null?void 0:E.SendMax)!=null,ce=(E==null?void 0:E.delivermax)!=null||(E==null?void 0:E.DeliverMax)!=null;if(!(Q||ie||ce))continue;i+=1;let se=E==null?void 0:E.account,fe=E==null?void 0:E.destination;if(se&&r.set(se,(r.get(se)||0)+1),se&&fe){let K=`${se}|${fe}`;l.set(K,(l.get(K)||0)+1)}}let c=[...r.entries()].sort((E,z)=>z[1]-E[1]).slice(0,5).map(([E,z])=>({acct:E,count:z})),d=[...l.entries()].sort((E,z)=>z[1]-E[1]).slice(0,5).map(([E,z])=>{let[Q,ie]=E.split("|");return{from:Q,to:ie,count:z}}),u=(W=n==null?void 0:n.now)!=null&&W.total?Math.round((n.now.cancelRatio||0)*100):0,p=(n==null?void 0:n.topShare)!=null?Math.round(n.topShare*100):0,m=e.filter(E=>(E==null?void 0:E.type)==="Payment").map(E=>typeof(E==null?void 0:E.amountXrp)=="number"?E.amountXrp:null).filter(E=>E!=null&&E>0&&Number.isFinite(E)),f=[100,1e3,1e4],v=m.filter(E=>f.some(z=>Math.abs(E%z)<1e-9&&E/z>=1)).length,h=m.length>=5?Math.round(v/m.length*100):null,w=e.filter(E=>(E==null?void 0:E.type)==="Payment"&&(E==null?void 0:E.account)&&(E==null?void 0:E.destination)&&E.account===E.destination).length,k=Number((t==null?void 0:t.AMMCreate)||0),b=Number((t==null?void 0:t.AMMDeposit)||0),x=Number((t==null?void 0:t.AMMWithdraw)||0),S=Number((t==null?void 0:t.AMMVote)||0),T=Number((t==null?void 0:t.AMMBid)||0),$=Number((t==null?void 0:t.AMMDelete)||0),P=k+b+x+S+T+$,M=b-x,N=b+x>0?Math.round(b/(b+x)*100):null,_=new Set;for(let E of e)["AMMCreate","AMMDeposit","AMMWithdraw","AMMVote","AMMBid"].includes(E==null?void 0:E.type)&&(E!=null&&E.account)&&_.add(E.account);let X=_.size,I=0,R=0;for(let E of e)(E==null?void 0:E.type)==="Payment"&&Array.isArray(E==null?void 0:E.paths)&&E.paths.length>0&&(I+=E.paths.length,R++);let F=R>0?(I/R).toFixed(1):null;return{offerTotal:s,dexCancelPct:u,dexTopSharePct:p,mints:a,burns:o,pathPays:i,topPathActors:c,topPathPairs:d,roundnessIdx:h,selfTradeCount:w,ammCreate:k,ammDeposit:b,ammWithdraw:x,ammVote:S,ammBid:T,ammDelete:$,lpTotal:P,lpNetFlow:M,lpRatio:N,lpUniqueActors:X,avgPathDepth:F}}function vm({hhi:e,repeats:t,dex:n,bots:s,advanced:a}){var w,k;let o=ke((e-.22)/.25,0,1)*22,i=ke((t-2)/6,0,1)*12,r=((w=n==null?void 0:n.window)==null?void 0:w.cancelRatio)??0,l=(n==null?void 0:n.topShare)??0,c=((k=n==null?void 0:n.now)==null?void 0:k.cancelsPerMin)??0,d=ke((r-.5)/.5,0,1)*18,u=ke((l-.25)/.5,0,1)*18,p=ke(c/25,0,1)*10,m=ke(s/6,0,1)*10,f=(a==null?void 0:a.roundnessIdx)!=null?ke((a.roundnessIdx-30)/40,0,1)*8:0,v=(a==null?void 0:a.selfTradeCount)>0?Math.min(8,a.selfTradeCount*4):0,h=(a==null?void 0:a.pathPays)!=null?ke(a.pathPays/30,0,1)*6:0;return Math.round(o+i+d+u+p+m+f+v+h)}function bm({friction:e,tps:t,fee:n}){let s=(n==null?void 0:n.deltaPct)!=null&&Math.abs(n.deltaPct)>=35,a=(t==null?void 0:t.deltaPct)!=null&&Math.abs(t.deltaPct)>=25;return e>=75?"Manipulated":s||a?"Stressed":((t==null?void 0:t.cur)??0)>=12||((t==null?void 0:t.avg)??0)>=10?"Active":"Quiet"}function ym({s:e,txTypes:t,hhi:n,dexPatterns:s,behavior:a,friction:o,regime:i,breadcrumbs:r,clusters:l,advanced:c}){var w,k,b,x,S;let d=[],u=Mt(O.tpsHistory,Bt),p=Mt(O.feeHistory,Bt),m=((w=Object.entries(t||{}).sort(([,T],[,$])=>$-T)[0])==null?void 0:w[0])||"\u2014",f=Number(e.txPerLedger||0);d.push({sentiment:i==="Manipulated"||i==="Stressed"?"warn":i==="Active"?"up":"ok",title:`Overall: ${i} \xB7 Risk score ${o}/100`,detail:"Heuristic score from concentration, repeats, DEX churn, bot-like timing, and routing indicators. It's a signal, not proof."}),d.push({sentiment:"ok",title:`Ledger snapshot: #${Number(e.ledgerIndex||0).toLocaleString()} \xB7 ${f} tx \xB7 most common: ${m}`,detail:`TPS ${In(u.cur,2)} (avg ${In(u.avg,2)} \xB7 ${Zt(u.deltaPct,0)}). Fee ${p.cur!=null?Jt(p.cur):"\u2014"} (avg ${p.avg!=null?Jt(p.avg):"\u2014"} \xB7 ${Zt(p.deltaPct,0)}).`});let v=n>=.35?"high":n>=.25?"medium":"low";if(d.push({sentiment:n>=.35?"warn":"ok",title:`Transaction mix: ${v} concentration (HHI ${n.toFixed(2)})`,detail:n>=.35?"A few tx types dominate. Patterns look \u201Cstronger,\u201D but can be misleading.":"Mix is broad. Strong signals usually come from behavior, not just tx type."}),s.window.total){let T=Math.round(s.window.cancelRatio*100),$=Math.round(s.topShare*100);d.push({sentiment:s.signals.length?"warn":"ok",title:`DEX monitor: ${s.window.total} offer tx (window) \xB7 cancels ${T}% \xB7 top actor ~${$}%`,detail:s.signals.length?`Signals: ${s.signals.join(" \xB7 ")}`:"No strong DEX-pattern signals right now.",addr:((k=s.topActor[0])==null?void 0:k.acct)||null})}let h=r.filter(T=>T.count>=2).length;if(h>=2&&d.push({sentiment:"new",title:`Repeating counterparties: ${h} recurring pair(s)`,detail:"Repeated interactions can be routing loops, bots, or coordinated flows. Click addresses for a quick read."}),l!=null&&l.length&&((b=l[0])==null?void 0:b.size)>=3&&d.push({sentiment:"new",title:`Cluster forming: ${l[0].size} wallets \xB7 hub ${U(l[0].hub)}`,detail:"Clusters are co-activity groups (not identity proof). Use as \u201Clikely related behavior.\u201D",addr:l[0].hub}),(x=a.bots)!=null&&x.length){let T=a.bots[0];d.push({sentiment:"warn",title:`Bot-like timing: ${a.bots.length} candidate(s)`,detail:`Low variance in repeated appearances. Top: ${U(T.acct)} (CV ${T.cv.toFixed(2)}).`,addr:T.acct})}if(c!=null&&c.pathPays){let T=(S=c.topPathActors)==null?void 0:S[0];d.push({sentiment:c.pathPays>=18?"warn":"ok",title:`Autobridge-ish routing: ${c.pathPays} path payments (ledger sample)`,detail:T?`Most active routing wallet: ${U(T.acct)} (${T.count}).`:"Paths/SendMax/DeliverMax appear frequently in the sample.",addr:(T==null?void 0:T.acct)||null})}return c!=null&&c.selfTradeCount&&d.push({sentiment:"warn",title:`Self-transfer signal: ${c.selfTradeCount} payment(s) where sender = receiver`,detail:"Self-transfers can be benign (housekeeping) or used to fake activity. Treat as a watch signal."}),((c==null?void 0:c.roundnessIdx)??0)>=45&&d.push({sentiment:"warn",title:`Round-number bias: ${c.roundnessIdx}% of payments are exact multiples of 100/1,000/10,000`,detail:"Round-number bias often shows scripted behavior (bots) rather than human payments."}),d.slice(0,12)}function wm(e){let t=y("d2-breadcrumb-list"),n=y("d2-breadcrumb-meta");if(!t)return;if(!e.length){t.innerHTML='<div class="gateway-item" style="opacity:.6">Watching for repeated interactions\u2026</div>',n&&(n.textContent="\u2014");return}let s=e.filter(a=>a.count>=2).length;n&&(n.textContent=s?`${s} repeats`:"Top interactions"),t.innerHTML=e.slice(0,10).map(a=>`
    <div class="gateway-item gateway-row">
      <div class="gateway-left mono cut">
        <button class="addr-link mono cut gw-from" data-addr="${g(a.from)}">${g(U(a.from))}</button>
        <span class="gw-arrow">\u2192</span>
        <button class="addr-link mono cut gw-to" data-addr="${g(a.to)}">${g(U(a.to))}</button>
      </div>
      <span class="gw-count">${a.count}\xD7</span>
    </div>`).join("")}function xm(e){let t=y("d2-cluster-list"),n=y("d2-cluster-persistence");if(t){if(!e.length){t.innerHTML='<div class="gateway-item" style="opacity:.6">Building clusters\u2026 (needs repeated activity)</div>',n&&(n.textContent="\u2014");return}n&&(n.textContent=`${e.length} group${e.length!==1?"s":""}`),t.innerHTML=e.slice(0,6).map((s,a)=>{let i=`hsl(${(a*67+120)%360},70%,60%)`,r=s.members.slice(0,4);return`
      <div class="gateway-item cluster-item">
        <div class="cluster-head">
          <span class="cluster-title" style="color:${i}">Group ${a+1}</span>
          <span class="cluster-meta">${s.size} wallets</span>
        </div>
        <div class="cluster-preview">
          <span class="cluster-chip-h">Hub:</span>
          <button class="addr-chip mono" data-addr="${g(s.hub)}">${g(U(s.hub))}</button>
        </div>
        <div class="cluster-preview">
          <span class="cluster-chip-h">Members:</span>
          ${r.map(l=>`<button class="addr-chip mono" data-addr="${g(l)}">${g(U(l))}</button>`).join("")}
          ${s.members.length>r.length?`<span class="cluster-more">+${s.members.length-r.length}</span>`:""}
        </div>
      </div>`}).join("")}}function km(e){let t=y("d2-delta-narratives");if(!t)return;if(!e.length){t.innerHTML='<div class="gateway-item" style="opacity:.6">Building baseline \u2014 narratives appear after 1\u20132 ledgers\u2026</div>';return}let n={up:"#50fa7b",down:"#ff5555",new:"#00d4ff",warn:"#ffb86c",ok:"rgba(255,255,255,.85)"};t.innerHTML=e.map(s=>{let a=n[s.sentiment]||"rgba(255,255,255,.85)",o=s.addr&&Ue(s.addr)?`<button class="addr-link narrative-addr" data-addr="${g(s.addr)}">Peek</button>`:"";return`
      <details class="gateway-item narrative-item">
        <summary style="color:${a}">
          <span class="narrative-title">${g(s.title||s.text||"")}</span>
          ${o}
        </summary>
        <div class="narrative-detail">${g(s.detail||"")}</div>
      </details>`}).join("")}function $m(){if(Sr)return;Sr=!0;let e=new Map([["Pattern detection","Quick \u201Cat a glance\u201D read. If one thing dominates, patterns are easier to spot (but can be noisy)."],["Live ledger stream","Each card is a validated ledger. Glow color shows what activity dominated that ledger. Click a card to jump to inspector."],["Wallet breadcrumbs","Shows who repeatedly interacts with who. Click an address for an account peek."],["Cluster inference","Groups wallets that move together. Not identity proof. Use it as \u201Clikely related behavior.\u201D"],["Delta narratives","Plain-English summary of what changed: load, fees, DEX churn, repeats, bot-like timing."]]);document.querySelectorAll("section.widget-card[aria-label], div.widget-card[aria-label]").forEach(t=>{let n=t.getAttribute("aria-label")||"",s=e.get(n);if(!s)return;let a=t.querySelector(".widget-header");if(!a||t.querySelector(".widget-help"))return;let o=document.createElement("p");o.className="widget-help",o.textContent=s,a.insertAdjacentElement("afterend",o)})}function Sm(){if(Tr)return;Tr=!0;let e=document.querySelector(".ledger-stream-card");if(!e||e.querySelector(".ledger-legend"))return;let t=e.querySelector(".widget-help"),n=e.querySelector(".widget-header"),s=document.createElement("div");s.className="ledger-legend",s.setAttribute("aria-label","Ledger glow legend"),s.innerHTML=`
    <span class="legend-label">Glow key:</span>
    <span class="legend-chip payment">Payment</span>
    <span class="legend-chip offer">DEX</span>
    <span class="legend-chip nft">NFT</span>
    <span class="legend-chip trust">Trust</span>
    <span class="legend-chip amm">AMM</span>
    <span class="legend-chip other">Other</span>
  `,t?t.insertAdjacentElement("afterend",s):n?n.insertAdjacentElement("afterend",s):e.prepend(s)}function Tm(){if(Lr)return;Lr=!0;let e=document.querySelector(".dashboard-col-main");if(!e)return;let t=document.createElement("section");t.className="widget-card",t.id="landscape-card",t.setAttribute("aria-label","Landscape brief"),t.innerHTML=`
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
  `,e.prepend(t)}function Cm(e){var k,b,x,S,T,$,P,M,N,_,X,I,R,F,W;let t=y("landscape-badge");t&&(t.textContent=`${e.regime} \xB7 Risk ${e.friction}/100`);let n=e.s,s=e.txTypes||{},a=((k=Object.entries(s).sort(([,E],[,z])=>z-E)[0])==null?void 0:k[0])||"\u2014",o=Mt(O.tpsHistory,Bt),i=Mt(O.feeHistory,Bt),r=e.dexPatterns,l=(b=r==null?void 0:r.window)!=null&&b.total?Math.round(r.window.cancelRatio*100):0,c=y("landscape-text");if(c){let E=Number(n.ledgerIndex||0).toLocaleString(),z=Number(n.txPerLedger||0),Q=((x=n.latestLedger)==null?void 0:x.closeTimeSec)!=null?Number(n.latestLedger.closeTimeSec).toFixed(2)+"s":"\u2014",ie=o.cur!=null?`${In(o.cur,2)} TPS`:"\u2014",ce=i.cur!=null?`${Jt(i.cur)} fee`:"\u2014",de=n.successRate!=null?`${Number(n.successRate).toFixed(1)}% success`:"\u2014",se=(S=r==null?void 0:r.window)!=null&&S.total?`DEX offers are <b>${r.window.total}</b> (window), with <b>${l}% cancels</b>.`:"DEX offers look quiet right now.";c.innerHTML=`
      <b>Right now:</b> Ledger <b>#${E}</b> closed in <b>${Q}</b> with <b>${z}</b> transactions.
      Network is at <b>${ie}</b>, with <b>${ce}</b>, and <b>${de}</b>.
      Most common activity was <b>${g(a)}</b>. ${se}
    `}let d=y("landscape-why"),u=y("landscape-watchlist"),p=y("landscape-now"),m=y("landscape-watch"),f=[],v=[],h=[];if(e.regime==="Manipulated"?h.push("Risk score is very high. Patterns like churn, loops, or single-actor dominance often correlate with manipulated activity."):e.regime==="Stressed"?h.push("The network is behaving \u201Cabnormally\u201D (spikes in TPS or fees). This can be organic bursts or bots pushing volume."):e.regime==="Active"?h.push("The network is busy. Patterns are easier to detect because there\u2019s more data per minute."):h.push("The network is quiet. Signals are weaker; a few bots can dominate a small sample."),(T=r==null?void 0:r.signals)!=null&&T.length&&h.push(`DEX churn signals: <b>${g(r.signals.join(" \xB7 "))}</b>. Heavy OfferCreate/Cancel churn can indicate quote-stuffing/spoofing-like behavior.`),(($=e.advanced)==null?void 0:$.selfTradeCount)>0&&h.push(`Detected <b>${e.advanced.selfTradeCount}</b> self-transfer payment(s) in the sample. Can be benign, but can also be used to fake activity.`),(((P=e.advanced)==null?void 0:P.roundnessIdx)??0)>=45&&h.push(`Round-number bias is high (<b>${e.advanced.roundnessIdx}%</b>). That often indicates automation rather than human behavior.`),((M=e.advanced)==null?void 0:M.pathPays)>=18&&h.push(`Path payments are heavy (<b>${e.advanced.pathPays}</b> in sample). Lots of routing can mean arbitrage bots or automated bridge traffic.`),d&&(d.innerHTML=h.map(E=>`<div class="landscape-row">${E}</div>`).join("")),f.push(`Overall mode: <b>${g(e.regime)}</b> (risk score <b>${e.friction}/100</b>).`),f.push(`Traffic: <b>${In(o.cur,2)}</b> TPS (avg ${In(o.avg,2)} \xB7 ${Zt(o.deltaPct,0)}).`),f.push(`Fees: <b>${i.cur!=null?Jt(i.cur):"\u2014"}</b> (avg ${i.avg!=null?Jt(i.avg):"\u2014"} \xB7 ${Zt(i.deltaPct,0)}).`),(N=r==null?void 0:r.window)!=null&&N.total){let E=(_=r.topActor)==null?void 0:_[0];f.push(`DEX activity: <b>${r.window.total}</b> offer tx (window) \xB7 cancels <b>${l}%</b> \xB7 churn <b>${In(r.now.cancelsPerMin,1)}</b>/min.`),E&&f.push(`Most active DEX wallet: <button class="addr-link mono" data-addr="${g(E.acct)}">${g(U(E.acct))}</button> (${E.count}).`)}else f.push("DEX activity: <b>quiet</b> (few OfferCreate/OfferCancel).");let w=e.breadcrumbs.filter(E=>E.count>=2).length;if(w&&v.push(`Repeating interactions: <b>${w}</b> pair(s) keep showing up.`),(I=(X=e.behavior)==null?void 0:X.bots)!=null&&I.length){let E=e.behavior.bots[0];v.push(`Bot-like timing: top candidate <button class="addr-link mono" data-addr="${g(E.acct)}">${g(U(E.acct))}</button> (CV ${E.cv.toFixed(2)}).`)}if((R=r==null?void 0:r.signals)!=null&&R.length&&v.push(`DEX signals: <b>${g(r.signals.join(" \xB7 "))}</b>`),(F=e.clusters)!=null&&F.length&&v.push(`Largest cluster: <b>${e.clusters[0].size}</b> wallets \xB7 hub <button class="addr-link mono" data-addr="${g(e.clusters[0].hub)}">${g(U(e.clusters[0].hub))}</button>.`),(W=e.advanced)!=null&&W.pathPays&&v.push(`Autobridge/path flow: <b>${e.advanced.pathPays}</b> path payments detected in sample.`),v.length||v.push("Nothing urgent stands out in the current window."),p&&(p.innerHTML=f.map(E=>`<div class="landscape-row">${E}</div>`).join("")),m&&(m.innerHTML=v.map(E=>`<div class="landscape-row">${E}</div>`).join("")),u){let E=Lm(e);u.innerHTML=E.length?E.map(z=>`
        <div class="landscape-watchitem">
          <button class="addr-link mono cut" data-addr="${g(z.addr)}">${g(U(z.addr))}</button>
          <div class="landscape-watchwhy">${z.why}</div>
        </div>
      `).join(""):'<div style="opacity:.75">No clear \u201Ctop suspect\u201D yet \u2014 need a few more ledgers to build a baseline.</div>'}}function Lm(e){var i,r,l,c,d,u,p,m;let t=[],n=(f,v)=>{!f||!Ue(f)||t.some(h=>h.addr===f)||t.push({addr:f,why:v})};if((r=(i=e.behavior)==null?void 0:i.bots)!=null&&r.length){let f=e.behavior.bots[0];n(f.acct,`Bot-like timing (CV <span class="mono">${f.cv.toFixed(2)}</span>). High regularity is common in spam & automation.`)}let s=e.dexPatterns;if((l=s==null?void 0:s.topActor)!=null&&l.length){let f=s.topActor[0],v=s.topShare!=null?Math.round(s.topShare*100):null,h=((c=s.now)==null?void 0:c.cancelsPerMin)!=null?s.now.cancelsPerMin.toFixed(1):"\u2014";v!=null&&v>=25&&n(f.acct,`Dominates DEX activity (~<span class="mono">${v}%</span> share). Cancels/min <span class="mono">${h}</span> \u2014 watch for quote-stuffing/spoofing.`)}if((d=s==null?void 0:s.topCanceller)!=null&&d.length){let f=s.topCanceller[0];f.count>=6&&n(f.acct,`Top canceller (<span class="mono">${f.count}</span>). Heavy cancels can be a manipulation signal.`)}let a=e.breadcrumbs||[],o=a[0];if(o!=null&&o.from&&(o!=null&&o.to)){let f=a.find(v=>v.from===o.to&&v.to===o.from);f&&f.count>=3&&o.count>=3?(n(o.from,`Ping\u2011pong loop with ${U(o.to)} (<span class="mono">${o.count}\xD7</span> / <span class="mono">${f.count}\xD7</span>). Can be wash-like routing.`),n(o.to,`Ping\u2011pong loop with ${U(o.from)} (<span class="mono">${f.count}\xD7</span> / <span class="mono">${o.count}\xD7</span>).`)):o.count>=10&&n(o.from,`Repeated counterparty flow to ${U(o.to)} (<span class="mono">${o.count}\xD7</span>). Persistent repetition often indicates automation.`)}if((u=e.clusters)!=null&&u.length&&e.clusters[0].size>=3&&n(e.clusters[0].hub,`Cluster hub of <span class="mono">${e.clusters[0].size}</span> wallets. Coordination is a common feature of wash/loop tactics.`),(m=(p=e.advanced)==null?void 0:p.topPathActors)!=null&&m.length){let f=e.advanced.topPathActors[0];f.count>=6&&n(f.acct,`Heavy path\u2011payment routing (<span class="mono">${f.count}</span>). Often correlates with arbitrage bots.`)}return t.slice(0,6)}function Mm(){if(Mr)return;Mr=!0;let e=document.querySelector(".dashboard-col-side");if(!e)return;let t=document.createElement("section");t.className="widget-card",t.id="dex-pattern-card",t.setAttribute("aria-label","DEX pattern monitor"),t.innerHTML=`
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
  `,e.prepend(t)}function Pm(e){var p,m;if(!document.getElementById("dex-pattern-card"))return;let t=e.window.total||0,n=t?Math.round(e.window.cancelRatio*100):0,s=t?Math.round(e.topShare*100):0;V("dexp-badge",t?`${t} offer tx \xB7 ${n}% cancels`:"Quiet");let a=y("dexp-cancel-bar");a&&(a.style.width=`${ke(n,0,100)}%`),V("dexp-cancel-val",t?`${n}%`:"\u2014");let o=y("dexp-topshare-bar");o&&(o.style.width=`${ke(s,0,100)}%`),V("dexp-topshare-val",t?`${s}%`:"\u2014");let i=e.burstPct,r=i==null?0:Math.min(100,Math.abs(i)),l=y("dexp-burst-bar");l&&(l.style.width=`${r}%`),V("dexp-burst-val",i==null?"\u2014":Zt(i,0)),V("dexp-cpm",e.now.cancelsPerMin==null?"\u2014":e.now.cancelsPerMin.toFixed(1)),V("dexp-hhi",t?e.actorHHI.toFixed(2):"\u2014"),V("dexp-totalwin",t?`${t}`:"\u2014");let c=y("dexp-signals");c&&(c.innerHTML=e.signals.length?e.signals.map(f=>`<span class="sig-pill warn">${g(f)}</span>`).join(""):'<span class="sig-pill ok">No strong DEX signals</span>');let d=y("dexp-cancellers");d&&(d.innerHTML=(p=e.topCanceller)!=null&&p.length?e.topCanceller.slice(0,5).map(f=>`
        <div class="dex-rowline">
          <button class="addr-link mono cut" data-addr="${g(f.acct)}">${g(U(f.acct))}</button>
          <span class="mono">${f.count}</span>
        </div>`).join(""):'<div style="opacity:.7">\u2014</div>');let u=y("dexp-makers");u&&(u.innerHTML=(m=e.topMaker)!=null&&m.length?e.topMaker.slice(0,5).map(f=>`
        <div class="dex-rowline">
          <button class="addr-link mono cut" data-addr="${g(f.acct)}">${g(U(f.acct))}</button>
          <span class="mono">${f.count}</span>
        </div>`).join(""):'<div style="opacity:.7">\u2014</div>')}function Am(){if(Pr)return;Pr=!0;let e=document.querySelector(".dashboard-col-main");if(!e)return;let t=document.createElement("section");t.className="widget-card",t.id="risk-card",t.setAttribute("aria-label","Risk panel"),t.innerHTML=`
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
  `,t.querySelectorAll(".risk-box-toggle").forEach(n=>{var a;n.addEventListener("click",()=>{let o=n.getAttribute("data-target"),i=document.getElementById(o);if(!i)return;let r=n.getAttribute("aria-expanded")!=="false";n.setAttribute("aria-expanded",r?"false":"true"),i.classList.toggle("risk-collapsed",r),n.querySelector(".risk-box-chevron").textContent=r?"\u25B8":"\u25BE";try{localStorage.setItem("risk_collapsed_"+o,r?"1":"0")}catch{}});let s=n.getAttribute("data-target");try{localStorage.getItem("risk_collapsed_"+s)==="1"&&(n.setAttribute("aria-expanded","false"),(a=document.getElementById(s))==null||a.classList.add("risk-collapsed"),n.querySelector(".risk-box-chevron").textContent="\u25B8")}catch{}}),e.appendChild(t)}function Em(e){var r,l,c,d,u,p,m,f,v,h;if(!document.getElementById("risk-card"))return;V("risk-badge",`Risk ${e.friction}/100`),V("risk-regime",e.regime),V("risk-friction",`${e.friction}/100`);let t=[];e.hhi>=.35&&t.push({cls:"warn",t:"High concentration"}),e.breadcrumbs.filter(w=>w.count>=2).length>=3&&t.push({cls:"new",t:"Repeating counterparties"}),(l=(r=e.behavior)==null?void 0:r.bots)!=null&&l.length&&t.push({cls:"warn",t:"Bot-like timing"}),(d=(c=e.dexPatterns)==null?void 0:c.signals)!=null&&d.length&&t.push({cls:"warn",t:"DEX churn signals"}),((u=e.advanced)==null?void 0:u.selfTradeCount)>0&&t.push({cls:"warn",t:`Self-transfer: ${e.advanced.selfTradeCount}`}),(((p=e.advanced)==null?void 0:p.roundnessIdx)??0)>=45&&t.push({cls:"warn",t:`Round-number bias ${e.advanced.roundnessIdx}%`}),((m=e.advanced)==null?void 0:m.pathPays)>0&&t.push({cls:"warn",t:`Path flow: ${e.advanced.pathPays}`}),V("risk-signalcount",`${t.length}`);let n=y("risk-pills");n&&(n.innerHTML=t.length?t.map(w=>`<span class="sig-pill ${w.cls}">${g(w.t)}</span>`).join(""):'<span class="sig-pill ok">No elevated signals</span>');let s=y("risk-bots");if(s){let w=((f=e.behavior)==null?void 0:f.bots)||[];if(w.length){let k={};for(let x of w){let S=x.botType||"Periodic";k[S]||(k[S]=[]),k[S].push(x)}let b=["Market Maker","Arbitrage","Flood / Spam","Periodic"];s.innerHTML=b.filter(x=>k[x]).map(x=>{let S=k[x];return`<div class="bot-type-group">
          <div class="bot-type-label" style="color:${S[0].botTypeColor||"rgba(255,255,255,.8)"}">${x}</div>
          ${S.map($=>`
            <div class="risk-row bot-row">
              <button class="addr-link mono cut" data-addr="${g($.acct)}" title="${g($.acct)}">${g(U($.acct))}</button>
              <div class="bot-row-meta">
                <span class="mono bot-cv" style="color:${$.cv<.1?"#ff5555":$.cv<.2?"#ffb86c":"rgba(255,255,255,.65)"}">CV ${$.cv.toFixed(2)}</span>
                <span class="bot-total mono">${$.total}tx</span>
              </div>
            </div>
            ${$.botDesc?`<div class="bot-desc">${g($.botDesc)}</div>`:""}
          `).join("")}
        </div>`}).join("")}else s.innerHTML='<div style="opacity:.7;font-size:.84rem">No periodic bots detected yet</div>'}let a=y("risk-amm");if(a){let w=e.advanced||{},{ammCreate:k=0,ammDeposit:b=0,ammWithdraw:x=0,ammVote:S=0,ammBid:T=0,lpTotal:$=0,lpNetFlow:P=0,lpRatio:M,lpUniqueActors:N=0}=w;if($===0)a.innerHTML='<div style="opacity:.6;font-size:.84rem">No AMM activity in this ledger</div>';else{let _=P>0?"#50fa7b":P<0?"#ff5555":"rgba(255,255,255,.5)";a.innerHTML=`
        <div class="amm-chips">
          ${k?`<span class="amm-chip amm-create">\u{1F195} Create \xD7${k}</span>`:""}
          ${b?`<span class="amm-chip amm-dep">\u2193 Deposit \xD7${b}</span>`:""}
          ${x?`<span class="amm-chip amm-wd">\u2191 Withdraw \xD7${x}</span>`:""}
          ${S?`<span class="amm-chip amm-vote">\u{1F5F3} Vote \xD7${S}</span>`:""}
          ${T?`<span class="amm-chip amm-bid">\u{1F4E3} Bid \xD7${T}</span>`:""}
        </div>
        <div class="risk-row" style="margin-top:8px"><span>Net LP flow</span>
          <span class="mono" style="color:${_}">${P>0?"+"+P+" (adding LP)":P<0?P+" (removing LP)":"0 (balanced)"}</span></div>
        ${M!=null?`<div class="risk-row"><span>Deposit ratio</span><span class="mono">${M}% depositing</span></div>`:""}
        <div class="risk-row"><span>Unique LP actors</span><span class="mono">${N||"\u2014"}</span></div>
        <div class="risk-row"><span>Total LP ops</span><span class="mono">${$}</span></div>`}}let o=y("risk-path");if(o){let w=e.advanced||{},k=(v=w.topPathActors)==null?void 0:v[0],b=(h=w.topPathActors)==null?void 0:h[1],x=w.selfTradeCount>0?"#ff5555":"rgba(255,255,255,.5)",S=(w.roundnessIdx??0)>=45?"#ff5555":(w.roundnessIdx??0)>=25?"#ffb86c":"rgba(255,255,255,.5)";o.innerHTML=`
      <div class="risk-row"><span>Path payments</span><span class="mono">${w.pathPays??"\u2014"}</span></div>
      ${w.avgPathDepth!=null?`<div class="risk-row"><span>Avg path depth</span><span class="mono">${w.avgPathDepth} hops</span></div>`:""}
      ${k?`<div class="risk-row"><span>Top router</span>
        <button class="addr-link mono cut" data-addr="${g(k.acct)}">${g(U(k.acct))}</button></div>
        <div class="risk-row" style="opacity:.75"><span style="padding-left:8px">\u21B3 count</span><span class="mono">${k.count}</span></div>`:""}
      ${b?`<div class="risk-row" style="opacity:.7"><span>2nd router</span>
        <button class="addr-link mono cut" data-addr="${g(b.acct)}">${g(U(b.acct))}</button></div>`:""}
      <div class="risk-row" style="margin-top:4px;border-top:1px solid rgba(255,255,255,.05);padding-top:8px">
        <span>Round-number %</span><span class="mono" style="color:${S}">${w.roundnessIdx!=null?w.roundnessIdx+"%":"\u2014"}</span></div>
      <div class="risk-row"><span>Self-transfers</span><span class="mono" style="color:${x}">${w.selfTradeCount??0}</span></div>`}let i=y("risk-notes");i&&(i.innerHTML=`
    <div style="opacity:.85">Signals are not proof. Use them to choose what to inspect.</div>
    <div style="opacity:.85">DEX monitor uses OfferCreate/OfferCancel only \u2014 no orderbook polling.</div>
    <div style="opacity:.85">Click any address to peek, then "Open in Inspector".</div>`)}function Nm(){if(Dr)return;Dr=!0;let e=document.querySelector(".dashboard-col-side");if(e){if(!document.getElementById("dex-pressure-card")){let t=document.createElement("section");t.className="widget-card",t.id="dex-pressure-card",t.setAttribute("aria-label","DEX pressure"),t.innerHTML=`
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
    `,e.prepend(t)}}}function _m(){he.dexPressure=[],he.nftMints=[],he.nftBurns=[],he.autoBridge=[],po.clear(),Object.keys(co).forEach(e=>delete co[e]),ml({offerTotal:null,dexCancelPct:null,dexTopSharePct:null,mints:null,burns:null,pathPays:null,topPathActors:[],topPathPairs:[]})}function Fn(e,t,n){for(e.push(Number(t||0));e.length>n;)e.shift()}function Rm(e){var n,s,a,o;let t=e==null?void 0:e.advanced;t&&(Fn(he.dexPressure,t.offerTotal,Tu),Fn(he.nftMints,t.mints,kr),Fn(he.nftBurns,t.burns,kr),Fn(he.autoBridge,t.pathPays,Cu),ml(t),(n=ye.dexPressure)==null||n.draw(he.dexPressure),(s=ye.nftMints)==null||s.draw(he.nftMints),(a=ye.nftBurns)==null||a.draw(he.nftBurns),(o=ye.autoBridge)==null||o.draw(he.autoBridge))}function ml(e){var t,n,s;if(document.getElementById("dex-pressure-card")&&(V("dexP-badge",e.offerTotal==null?"Waiting\u2026":`${e.offerTotal} offer tx`),V("dexP-now",e.offerTotal==null?"\u2014":e.offerTotal),V("dexP-cancel",e.dexCancelPct==null?"\u2014":`${e.dexCancelPct}%`),V("dexP-share",e.dexTopSharePct==null?"\u2014":`${e.dexTopSharePct}%`)),document.getElementById("autobridge-card")){V("ab-badge",e.pathPays==null?"Waiting\u2026":`${e.pathPays} path pays`),V("ab-now",e.pathPays==null?"\u2014":e.pathPays);let a=(t=e.topPathActors)==null?void 0:t[0];V("ab-top-actor",a?U(a.acct):"\u2014"),V("ab-pairs",(n=e.topPathPairs)!=null&&n.length?e.topPathPairs.length:"\u2014");let o=y("ab-top-pairs");o&&(o.innerHTML=(s=e.topPathPairs)!=null&&s.length?e.topPathPairs.map(i=>`
          <div class="dex-rowline">
            <span class="mono cut">${g(U(i.from))}</span>
            <span style="opacity:.7">\u2192</span>
            <span class="mono cut">${g(U(i.to))}</span>
            <span class="mono">${i.count}</span>
          </div>`).join(""):'<div style="opacity:.7">\u2014</div>')}if(document.getElementById("nft-mint-card")){let a=Number(e.mints||0)-Number(e.burns||0);V("nft-badge",e.mints==null&&e.burns==null?"Waiting\u2026":`${e.mints||0} mints \xB7 ${e.burns||0} burns`),V("nft-mints-now",e.mints==null?"\u2014":e.mints),V("nft-burns-now",e.burns==null?"\u2014":e.burns),V("nft-net-now",`${a}`)}}function ra({force:e=!1}={}){if(!Ft()){bo();return}Gt&&!e||(Gt&&(clearInterval(Gt),Gt=null),qr(),Gt=setInterval(()=>{Ft()&&qr()},Lu))}function bo(){Gt&&(clearInterval(Gt),Gt=null)}async function qr(){var t,n,s,a,o,i,r,l,c,d;let e=++ao;V("mkt-badge","Loading\u2026");try{let p=await fetch("https://api.exchange.coinbase.com/products/XRP-USD/candles?granularity=3600",{cache:"no-store"});if(!p.ok)throw new Error("market history failed");let m=await p.json();if(!Array.isArray(m)||m.length<10)throw new Error("no history");if(e!==ao)return;let f=[...m].sort((x,S)=>Number(x[0])-Number(S[0])),v=f.map(x=>Number(x[4])).filter(Number.isFinite),h=f.map(x=>Number(x[5])).filter(Number.isFinite);he.marketPrice=v.slice(-Ys),he.marketVol=h.slice(-Ys);let w=he.marketPrice.at(-1),k=he.marketPrice.length>24?he.marketPrice.at(-25):he.marketPrice.at(0),b=k&&w?(w-k)/k*100:null;V("mkt-badge",w?`$${w.toFixed(4)}`:"\u2014"),V("mkt-price",w?`$${w.toFixed(4)}`:"\u2014"),V("mkt-chg",b==null?"\u2014":Zt(b,2)),V("mkt-upd",new Date().toLocaleTimeString()),(t=ye.marketPrice)==null||t.draw(he.marketPrice),(n=ye.marketVol)==null||n.draw(he.marketVol);return}catch{}try{let u=await fetch("https://api.coinpaprika.com/v1/tickers/xrp-xrp",{cache:"no-store"});if(!u.ok)throw new Error("tick failed");let p=await u.json();if(e!==ao)return;let m=Number((a=(s=p==null?void 0:p.quotes)==null?void 0:s.USD)==null?void 0:a.price),f=Number((i=(o=p==null?void 0:p.quotes)==null?void 0:o.USD)==null?void 0:i.volume_24h),v=Number((l=(r=p==null?void 0:p.quotes)==null?void 0:r.USD)==null?void 0:l.percent_change_24h);Number.isFinite(m)&&(Fn(he.marketPrice,m,Ys),Number.isFinite(f)&&Fn(he.marketVol,f,Ys)),V("mkt-badge",Number.isFinite(m)?`$${m.toFixed(4)}`:"\u2014"),V("mkt-price",Number.isFinite(m)?`$${m.toFixed(4)}`:"\u2014"),V("mkt-chg",Number.isFinite(v)?`${v>=0?"\u2191":"\u2193"}${Math.abs(v).toFixed(2)}%`:"\u2014"),V("mkt-upd",new Date().toLocaleTimeString()),(c=ye.marketPrice)==null||c.draw(he.marketPrice),(d=ye.marketVol)==null||d.draw(he.marketVol)}catch{V("mkt-badge","Unavailable")}}function Dm(){var n,s,a,o;if(Ir)return;Ir=!0;let e=document.querySelector(".dashboard-fullwidth");if(!e){e=document.createElement("div"),e.className="dashboard-fullwidth";let i=document.querySelector(".dashboard-columns");i?i.insertAdjacentElement("afterend",e):(n=document.querySelector(".dashboard-page"))==null||n.appendChild(e)}if(document.getElementById("spam-defense-card"))return;let t=document.createElement("section");t.className="widget-card",t.id="spam-defense-card",t.setAttribute("aria-label","Spam defense"),yo(),vl(),t.innerHTML=`
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
          <input type="range" id="sim-base" min="1" max="500" step="1" value="${Wn}"
            oninput="_renderBondSim()" style="width:100%;margin-top:4px">
          <span id="sim-base-val" class="mono" style="font-size:.72rem">${Wn} XRP</span>
        </label>
        <label style="font-size:.78rem;opacity:.7">
          Growth factor
          <input type="range" id="sim-growth" min="1.2" max="4" step="0.1" value="${jn}"
            oninput="_renderBondSim()" style="width:100%;margin-top:4px">
          <span id="sim-growth-val" class="mono" style="font-size:.72rem">${jn}\xD7</span>
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
  `,e.appendChild(t),(s=y("spam-copy-hash"))==null||s.addEventListener("click",()=>{var i;return Vr(((i=y("spam-proof-hash"))==null?void 0:i.textContent)||"")}),(a=y("spam-copy-json"))==null||a.addEventListener("click",()=>{var i;return Vr(((i=y("spam-proof-json"))==null?void 0:i.textContent)||"")}),(o=y("spam-print-proof"))==null||o.addEventListener("click",qm),_renderBondSim()}window._toggleBondSim=function(){let e=y("spam-sim-panel");if(!e)return;let t=e.style.display!=="none";e.style.display=t?"none":"";let n=y("spam-sim-toggle");n&&(n.style.color=t?"":"#00d4ff")};window._renderBondSim=function(){let e=document.getElementById("sim-base"),t=document.getElementById("sim-growth"),n=document.getElementById("sim-table");if(!n)return;let s=Number((e==null?void 0:e.value)||Wn),a=Number((t==null?void 0:t.value)||jn),o=he.marketPrice.at(-1)??null;document.getElementById("sim-base-val")&&(document.getElementById("sim-base-val").textContent=s+" XRP"),document.getElementById("sim-growth-val")&&(document.getElementById("sim-growth-val").textContent=a+"\xD7");let i="";for(let r=0;r<=hs;r++){let l=Math.round(s*a**r),c=o?"$"+(l*o).toLocaleString(void 0,{maximumFractionDigits:0}):"",d=r<3?"#50fa7b":r<6?"#ffb86c":"#ff5555";i+=`<div style="padding:5px;border-radius:6px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07)">
      <div style="font-size:.65rem;opacity:.5">L${r}</div>
      <div style="color:${d};font-weight:800">${l>=1e3?(l/1e3).toFixed(1)+"k":l}</div>
      ${c?`<div style="font-size:.62rem;opacity:.45">${c}</div>`:""}
    </div>`}n.innerHTML=i};async function Vr(e){try{await navigator.clipboard.writeText(String(e||"")),ne("Copied")}catch{be("Copy failed (browser blocked clipboard).")}}function ms(e){let t=ke(Number(e)||0,0,hs);return Math.round(Wn*jn**t)}function yo(){try{let e=JSON.parse(localStorage.getItem(tl)||"[]");ae.allowList=new Set(e)}catch{ae.allowList=new Set}}function fl(){try{localStorage.setItem(tl,JSON.stringify([...ae.allowList]))}catch{}}function hl(e){Ue(e)&&(ae.allowList.add(e),fl(),ae.byAddr.delete(e),ne(`${U(e)} added to allow-list \u2014 will no longer be flagged`))}window._spamAllowAddr=hl;function gl(){try{return JSON.parse(localStorage.getItem(el)||"{}")}catch{return{}}}function Im(e){try{localStorage.setItem(el,JSON.stringify(e))}catch{}}function vl(){let e=gl();for(let[t,n]of Object.entries(e))ae.verifiedCache.set(t,n)}window.exportSpamReputation=function(){let e=[...ae.byAddr.entries()].map(([o,i])=>({addr:o,level:i.level,strikes:i.strikes,score:+(i.score||0).toFixed(4),threatType:i.threatType||"Unknown",verified:!!i.verifiedLedger,verifiedLedger:i.verifiedLedger??null,lastSeen:i.lastSeenLedger??null})),t={v:2,network:O.currentNetwork||"xrpl-mainnet",exportedAt:new Date().toISOString(),allowList:[...ae.allowList],suspects:e,policy:{bondBaseXrp:Wn,bondGrowth:jn,ratchetMax:hs}},n=new Blob([JSON.stringify(t,null,2)],{type:"application/json"}),s=URL.createObjectURL(n),a=document.createElement("a");a.href=s,a.download=`naluxrp_reputation_${new Date().toISOString().slice(0,10)}.json`,document.body.appendChild(a),a.click(),document.body.removeChild(a),URL.revokeObjectURL(s),ne("Reputation list exported")};window.importSpamReputation=function(e){if(!e)return;let t=new FileReader;t.onload=n=>{var s;try{let a=JSON.parse(n.target.result);if(!a.suspects)throw new Error("Invalid format");let o=0;for(let i of a.suspects){if(!Ue(i.addr))continue;let r=ae.byAddr.get(i.addr)||{};ae.byAddr.set(i.addr,{...r,level:i.level??0,strikes:i.strikes??0,score:i.score??0,threatType:i.threatType??"Unknown",verifiedLedger:i.verifiedLedger??null,lastSeenLedger:i.lastSeen??null,scoreHistory:[],signalBreakdown:{}}),o++}if((s=a.allowList)!=null&&s.length){for(let i of a.allowList)Ue(i)&&ae.allowList.add(i);fl()}ne(`Imported ${o} reputation entries`)}catch(a){be("Import failed: "+a.message)}},t.readAsText(e)};function Fm(e){var l,c;if(!document.getElementById("spam-defense-card"))return;let t=Hm(e),n=t.reduce((d,u)=>Math.max(d,u.level),0),s=t.filter(d=>d.verified).length,a=he.marketPrice.at(-1)??null,o=t.reduce((d,u)=>d+ms(u.level),0),i=a?`~$${(o*a).toLocaleString(void 0,{maximumFractionDigits:0})}`:`${o} XRP`;V("spam-count",t.length),V("spam-maxlvl",`L${n}`),V("spam-verified",s),V("spam-allowcount",ae.allowList.size),V("spam-bondusd",i),V("spam-badge",t.length?`${t.length} tracked \xB7 max L${n}`:"Quiet");let r=y("spam-list");if(r&&(t.length?r.innerHTML=t.map(d=>{let u=ms(d.level),p=a?` (~$${(u*a).toFixed(0)})`:"",m=d.level>=6?"#ff5555":d.level>=3?"#ffb86c":"#50fa7b",f=d.score>=.7?"#ff5555":d.score>=.4?"#ffb86c":"#50fa7b",v={"Payment Flooder":"#ff5555","Quote Stuffer":"#ff5555","Wash Trader":"#ff5555","DEX Bot":"#ffb86c","Arb Router":"#00d4ff","Periodic Bot":"#bd93f9"}[d.threatType]||"rgba(255,255,255,.6)",h=d.verified?`<span class="spam-cred-chip">\u2714 L${d.level} verified</span>`:"",w=Bm(d.scoreHistory||[]);return`
          <div class="spam-card" data-spam-addr="${g(d.addr)}">
            <div class="spam-card-top">
              <button class="addr-link mono spam-card-addr" data-addr="${g(d.addr)}">${g(U(d.addr))}</button>
              <div class="spam-card-actions">
                <button class="spam-btn" data-action="expand"  data-spam-addr="${g(d.addr)}">\u25BE Detail</button>
                <button class="spam-btn" data-action="proof"   data-spam-addr="${g(d.addr)}">Proof</button>
                <button class="spam-btn" data-action="allow"   data-spam-addr="${g(d.addr)}" title="Trust this address permanently">\u2713 Allow</button>
                <button class="spam-btn spam-btn-clear" data-action="clear" data-spam-addr="${g(d.addr)}">\u2715</button>
              </div>
            </div>
            <div class="spam-card-meta">
              <span class="spam-meta-chip">Level <b style="color:${m}">L${d.level}</b></span>
              <span class="spam-meta-chip">Score <b style="color:${f}">${Math.round(d.score*100)}%</b></span>
              <span class="spam-meta-chip" style="color:${v}">${g(d.threatType)}</span>
              <span class="spam-meta-chip">Bond <b>${u>=1e3?(u/1e3).toFixed(1)+"k":u} XRP${p}</b></span>
              ${h}
              <span title="Score trend \u2014 last ${(d.scoreHistory||[]).length} ledgers" style="margin-left:auto">${w}</span>
            </div>
            <!-- Expandable signal breakdown (hidden by default) -->
            <div class="spam-breakdown" id="spam-bd-${g(d.addr.slice(0,10))}" style="display:none">
              ${Om(d.breakdown,d.strikes)}
            </div>
          </div>`}).join(""):r.innerHTML=`<div class="spam-empty">No suspects flagged \u2014 allow-list has ${nl.size} known-good entities.</div>`),fo||Xm(),ae.selectedAddr){let d=ae.byAddr.get(ae.selectedAddr);d?wo(ae.selectedAddr,d,e.s.ledgerIndex).then(u=>Un(u)):Un(null)}((l=document.getElementById("spam-sim-panel"))==null?void 0:l.style.display)!=="none"&&((c=window._renderBondSim)==null||c.call(window))}function Bm(e){if(!(e!=null&&e.length))return"";let t=42,n=14,s=1,a=t/Math.max(1,e.length-1),o=e.map((l,c)=>`${(c*a).toFixed(1)},${(n-2-l/s*(n-4)).toFixed(1)}`).join(" "),i=e.at(-1)??0,r=i>=.7?"#ff5555":i>=.4?"#ffb86c":"#50fa7b";return`<svg width="${t}" height="${n}" xmlns="http://www.w3.org/2000/svg" style="overflow:visible">
    <polyline points="${o}" fill="none" stroke="${r}" stroke-width="1.5" stroke-linejoin="round"/>
    <circle cx="${((e.length-1)*a).toFixed(1)}" cy="${(n-2-i/s*(n-4)).toFixed(1)}"
      r="2" fill="${r}"/>
  </svg>`}function Om(e={},t=0){let n=[{label:"Bot timing",val:e.bot??0,desc:e.botType?`Type: ${e.botType}`:"Low variance in repeated ledger appearances"},{label:"DEX dominance",val:e.dexDom??0,desc:"Share of offer tx window controlled by this address"},{label:"Cancel pattern",val:e.cancelPat??0,desc:"Heavy OfferCancel activity relative to creates"},{label:"Ping-pong loop",val:e.pingPong??0,desc:"Bidirectional repeated payments between two addresses"},{label:"Path routing",val:e.pathRoute??0,desc:"High path-payment count \u2014 common in arb bots"},{label:"Self-transfer",val:e.selfTrade??0,desc:"Payments where sender = receiver"},{label:"Round-number pay",val:e.roundPay??0,desc:"Unusual bias toward exact round-number payment amounts"}].filter(s=>s.val>.001);return n.length?`
    <div style="margin-top:8px;border-top:1px solid rgba(255,255,255,.06);padding-top:8px">
      <div style="font-size:.7rem;opacity:.45;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">
        Signal breakdown \xB7 ${t} strike${t!==1?"s":""} accumulated
      </div>
      ${n.map(s=>{let a=Math.round(s.val*100),o=a>=30?"#ff5555":a>=15?"#ffb86c":"#50fa7b";return`<div style="margin-bottom:6px">
          <div style="display:flex;justify-content:space-between;font-size:.76rem;margin-bottom:2px">
            <span style="opacity:.8">${g(s.label)}</span>
            <span class="mono" style="color:${o}">${a}%</span>
          </div>
          <div style="height:4px;background:rgba(255,255,255,.07);border-radius:2px;overflow:hidden">
            <div style="height:100%;width:${Math.min(100,a*2.5)}%;background:${o};border-radius:2px"></div>
          </div>
          <div style="font-size:.68rem;opacity:.4;margin-top:1px">${g(s.desc)}</div>
        </div>`}).join("")}
    </div>`:'<div style="opacity:.5;font-size:.78rem;padding:6px 0">No significant signal breakdown available yet.</div>'}var fo=!1;function Xm(){fo||(fo=!0,document.addEventListener("click",e=>{var a,o,i,r;let t=(o=(a=e.target).closest)==null?void 0:o.call(a,"button[data-action][data-spam-addr]");if(!t)return;let n=t.getAttribute("data-action"),s=t.getAttribute("data-spam-addr");if(s){if(n==="proof"){let l=ae.byAddr.get(s);if(!l)return;ae.selectedAddr=s;let c=y("spam-proof");if(c){c.style.display="";let d=y("spam-proof-hash");d&&(d.textContent="Computing SHA-512Half\u2026")}wo(s,l,((r=(i=O.ledgerLog)==null?void 0:i[0])==null?void 0:r.ledgerIndex)||null).then(d=>{ae.selectedProof=d,Un(d)}).catch(d=>be("Proof build failed: "+d.message));return}if(n==="clear"){ae.byAddr.delete(s),ae.selectedAddr===s&&Un(null),ne("Cleared from session");return}if(n==="allow"){hl(s),ae.byAddr.delete(s),ae.selectedAddr===s&&Un(null);return}if(n==="expand"){let l=s.slice(0,10),c=document.getElementById("spam-bd-"+l);if(!c)return;let d=c.style.display!=="none";c.style.display=d?"none":"",t.textContent=d?"\u25BE Detail":"\u25B4 Hide";return}}}))}function Un(e){let t=y("spam-proof");if(!t)return;if(!e){t.style.display="none";return}t.style.display="",V("spam-proof-hash",e.hash);let n=y("spam-proof-json");n&&(n.textContent=e.canonicalJson);let s=y("spam-cred-step");s&&(s.innerHTML=`
      <div style="opacity:.9">
        To \u201Ccredential\u201D this address at level <b>L${e.level}</b>, do:
      </div>
      <ul style="margin:8px 0 0 18px;opacity:.9">
        <li><b>EscrowCreate</b> locking <b>${e.policy.bondRequiredXrp} XRP</b> to <b>itself</b> for ~24h (strong bond; funds are locked).</li>
        <li>Include a Memo that starts with <span class="mono">${Kt}</span> and then the proof hash.</li>
        <li>Alternatively (cheap): send a 1-drop self-payment with <b>DestinationTag=${Bn+e.level}</b> and the same memo.</li>
      </ul>
      <div style="opacity:.75;margin-top:8px">
        This dashboard will mark it verified once it sees a matching on-ledger tx in the stream.
      </div>
    `)}function Hm(e){var o,i,r,l,c;ae.allowList.size||yo();let t=new Set;(((o=e.behavior)==null?void 0:o.bots)||[]).forEach(d=>t.add(d.acct)),(((i=e.dexPatterns)==null?void 0:i.topActor)||[]).forEach(d=>t.add(d.acct)),(((r=e.dexPatterns)==null?void 0:r.topCanceller)||[]).forEach(d=>t.add(d.acct)),(((l=e.dexPatterns)==null?void 0:l.topMaker)||[]).forEach(d=>t.add(d.acct)),(e.breadcrumbs||[]).forEach(d=>{t.add(d.from),t.add(d.to)}),(e.clusters||[]).forEach(d=>{t.add(d.hub),(d.members||[]).forEach(u=>t.add(u))}),(((c=e.advanced)==null?void 0:c.topPathActors)||[]).forEach(d=>t.add(d.acct));let n=Number(e.s.ledgerIndex||0)||null,s=e.txs||[],a=[];if(n&&n%50===0){let d=na*24;for(let[u,p]of ae.byAddr)n-(p.lastSeenLedger||0)>d&&ae.byAddr.delete(u)}for(let d of t){if(!Ue(d)||nl.has(d)||ae.allowList.has(d))continue;let{score:u,breakdown:p}=Um(d,e),m=zm(p),f=ae.byAddr.get(d)||{strikes:0,level:0,score:0,verifiedLedger:null,lastSeenLedger:null,scoreHistory:[],threatType:"Unknown",signalBreakdown:{}},v=f.strikes||0;u>=Zr?v+=1:u<=ro&&(v=Math.max(0,v-1));let h=f.lastSeenLedger||n,w=n?n-h:0;if(w>na&&u<ro){let $=Math.floor(w/na);v=Math.max(0,v-$)}let k=ke(Math.floor(v/Qr),0,hs),b=[...f.scoreHistory||[],u].slice(-10),x=ae.verifiedCache.get(d),S=f.verifiedLedger??(x==null?void 0:x.ledgerIndex)??null;S||(S=Wm(d,k,s,n),S&&jm(d,k,n));let T={score:u,strikes:v,level:k,verifiedLedger:S,lastSeenLedger:n,scoreHistory:b,threatType:m,signalBreakdown:p};ae.byAddr.set(d,T),a.push({addr:d,score:u,strikes:v,level:k,verified:!!S,verifiedLedger:S,scoreHistory:b,threatType:m,breakdown:p})}return a.sort((d,u)=>u.level-d.level||u.score-d.score),a.slice(0,Pu)}function zm(e){let{bot:t=0,dexDom:n=0,cancelPat:s=0,pingPong:a=0,pathRoute:o=0,selfTrade:i=0,roundPay:r=0}=e,l=n+s;return t>.25&&(e.botType==="Flood / Spam"||r>.05)?"Payment Flooder":t>.2&&l>.15?"DEX Bot":l>.3&&s>.1?"Quote Stuffer":a>.1?"Wash Trader":o>.1?"Arb Router":t>.2?"Periodic Bot":"Multi-Signal"}function Um(e,t){var m,f,v,h,w;let n={bot:0,botType:null,dexDom:0,cancelPat:0,pingPong:0,pathRoute:0,selfTrade:0,roundPay:0},s=(((m=t.behavior)==null?void 0:m.bots)||[]).find(k=>k.acct===e);if(s){let k=ke((.35-s.cv)/.35,0,1);n.bot=+(.4*(.5+.5*k)).toFixed(3),n.botType=s.botType||"Periodic"}let a=t.dexPatterns,o=((v=(f=a==null?void 0:a.topActor)==null?void 0:f[0])==null?void 0:v.acct)===e&&a.topShare||0;o>0&&(n.dexDom=+(.3*ke((o-.2)/.4,0,1)).toFixed(3));let i=((a==null?void 0:a.topCanceller)||[]).find(k=>k.acct===e);i&&(n.cancelPat=+(.2*ke(i.count/20,0,1)).toFixed(3));let r=t.breadcrumbs||[],l=r.find(k=>k.from===e&&k.to===e);l&&(n.selfTrade=+(.2*ke(l.count/20,0,1)).toFixed(3));let c=r[0];if(c&&(c.from===e||c.to===e)){let k=r.find(b=>b.from===c.to&&b.to===c.from);k&&k.count>=3&&c.count>=3&&(n.pingPong=.15)}let d=(((h=t.advanced)==null?void 0:h.topPathActors)||[]).find(k=>k.acct===e);d&&(n.pathRoute=+(.15*ke(d.count/25,0,1)).toFixed(3));let u=(w=t.advanced)==null?void 0:w.roundnessIdx;return u!=null&&u>=45&&(d||s)&&(n.roundPay=+(.1*ke((u-45)/35,0,1)).toFixed(3)),{score:ke(n.bot+n.dexDom+n.cancelPat+n.pingPong+n.pathRoute+n.selfTrade+n.roundPay,0,1),breakdown:n}}function Wm(e,t,n,s){if(!(n!=null&&n.length))return null;let a=Bn+t;for(let o of n)if((o==null?void 0:o.account)===e){if(o.type==="EscrowCreate"&&o.destination===e){let i=typeof o.amountXrp=="number"?o.amountXrp:null,r=ms(t);if(i!=null&&i>=r&&ho(o.memos).startsWith(Kt))return s}if(o.type==="Payment"&&o.destination===e&&Number(o.destinationTag)===a&&ho(o.memos).startsWith(Kt))return s}return null}async function jm(e,t,n){var a;let s=ae.byAddr.get(e);if(s)try{let o=await wo(e,s,n),i=Kt+o.hash;if((((a=O.ledgerLog)==null?void 0:a.flatMap(c=>c.transactions||[]))||[]).some(c=>(c==null?void 0:c.account)!==e?!1:ho(c.memos).startsWith(i))){let c=gl();c[e]={ledgerIndex:n,hash:o.hash,level:t},Im(c),ae.verifiedCache.set(e,{ledgerIndex:n,hash:o.hash}),ne(`\u2714 Credential verified for ${U(e)} at L${t}`)}}catch{}}function ho(e){if(!Array.isArray(e))return"";let t=[];for(let n of e){let s=(n==null?void 0:n.Memo)||(n==null?void 0:n.memo)||null;if(!s)continue;let a=s.MemoData||s.memo_data||"";try{if(typeof a=="string"&&/^[0-9A-Fa-f]+$/.test(a)&&a.length%2===0){let o=Uint8Array.from(a.match(/../g),i=>parseInt(i,16));t.push(new TextDecoder().decode(o))}else typeof a=="string"&&t.push(a)}catch{}}return t.join(" ")}async function wo(e,t,n){let s=t.level||0,a=ms(s),o=he.marketPrice.at(-1)??null,i=o?(a*o).toFixed(2):null,r={hashAlgorithm:"SHA-512Half",ratchetMax:hs,strikesToLevel:Qr,strikeUp:Zr,strikeDown:ro,decayLedgers:na,bondBaseXrp:Wn,bondGrowthFactor:jn,bondRequiredXrp:a,bondRequiredUsd:i,credTagBase:Bn,memoPrefix:Kt,credentialTag:Bn+s},l={v:2,hashAlg:"SHA-512Half",network:O.currentNetwork||"xrpl-mainnet",address:e,ledgerIndex:n!=null?Number(n):null,level:s,threatType:t.threatType||"Unknown",score:Number((t.score||0).toFixed(4)),strikes:Number(t.strikes||0),signalBreakdown:t.signalBreakdown||{},credential:{destinationTag:Bn+s,memoFormat:Kt+"<SHA-512Half-of-this-proof>",verifiedLedger:t.verifiedLedger??null},policy:r,note:"Generated by NaluXRP Spam Defense POC. Hash uses XRPL-native SHA-512Half (first 256 bits of SHA-512). A gateway or relayer policy can require the indicated bond/credential before providing service to this address.",generatedAt:new Date().toISOString()},c=JSON.stringify(l,Object.keys(l).sort(),0),d=await Du(c);l.credential.memoFormat=Kt+d;let u=JSON.stringify(l,null,2);return{hash:d,canonicalJson:u,level:s,policy:r,threatType:t.threatType}}function qm(){let e=ae.selectedProof;if(!e){be("Generate a proof first using the Proof button.");return}let t=ae.selectedAddr||"\u2014",n=he.marketPrice.at(-1)??null,s=e.policy.bondRequiredXrp,a=n?` (~$${(s*n).toFixed(0)} USD)`:"",o=e.hash.startsWith("FALLBACK")?'<div style="padding:8px 12px;background:#fff3cd;border:1px solid #f0ad4e;border-radius:4px;margin-bottom:12px">\u26A0 Hash is non-cryptographic (SubtleCrypto unavailable). Do NOT use for enforcement.</div>':"",i=window.open("","_blank","width=760,height=660");i.document.write(`<!DOCTYPE html><html><head>
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
        ${s.toLocaleString()} XRP, finish ~25,000 ledgers from now, memo = <code>${Kt}${e.hash}</code></p>
      <p style="font-size:.85rem"><b>Option B (1-drop payment):</b> Payment of 1 drop to itself,
        DestinationTag = ${Bn+e.level}, same memo.</p>
    </div>
    <div class="section">
      <div class="section-h">Canonical Proof JSON (v2)</div>
      <pre>${e.canonicalJson.replace(/</g,"&lt;").replace(/>/g,"&gt;")}</pre>
    </div>
    </body></html>`),i.document.close()}var bl=null;function Vm(){if(lo)return;lo=!0;let e=document.querySelector('[aria-label="Pattern detection"]');if(!e){e=document.createElement("section"),e.className="widget-card",e.setAttribute("aria-label","Pattern detection");let t=document.querySelector(".dashboard-col-main");if(!t)return;let n=t.querySelector(".dashboard-metrics");n?n.insertAdjacentElement("afterend",e):t.prepend(e)}e.innerHTML=`
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
    </div>`,bl=document.getElementById("pattern-donut-canvas")}function Gm(e,t){if(!lo)return;let n=typeof Tt<"u"?Tt:{},s=Object.entries(e||{}).filter(([,m])=>m>0).sort(([,m],[,f])=>f-m);if(!s.length)return;let a=s.reduce((m,[,f])=>m+f,0)||1,[o,i]=s[0],r=Math.round(i/a*100),l=s[1],c=y("pattern-badge");c&&(c.textContent=o+" \xB7 "+r+"%");let d=y("pattern-dom-type");if(d&&(d.textContent=o,d.style.color=n[o]||"rgba(255,255,255,.9)"),V("pattern-dom-pct",r+"% of ledger"),l){let m=Math.round(l[1]/a*100),f=y("pattern-2nd-type");f&&(f.textContent=l[0]+" ("+m+"%)",f.style.color=n[l[0]]||"rgba(255,255,255,.7)")}else V("pattern-2nd-type","\u2014");let u=y("pattern-hhi");u&&t!=null&&(u.textContent=t.toFixed(3),u.style.color=t>=.35?"#ff5555":t>=.25?"#ffb86c":"#50fa7b");let p=y("pattern-donut-center");p&&(p.innerHTML='<span style="color:'+(n[o]||"#fff")+';font-size:1.15rem">'+r+"%</span>"),Km(s,a,n)}function Km(e,t,n){let s=bl||y("pattern-donut-canvas");if(!(s!=null&&s.getContext))return;let a=s.getContext("2d"),o=s.width/2,i=s.height/2,r=Math.min(s.width,s.height)/2-6,l=r*.56;a.clearRect(0,0,s.width,s.height);let c=e.slice(0,7),d=e.slice(7).reduce((m,[,f])=>m+f,0),u=d>0?[...c,["Other",d]]:[...c],p=-Math.PI/2;for(let[m,f]of u){let v=f/t*Math.PI*2,h=Xn(n[m]||"#6b7280",.88)||"#6b7280";a.beginPath(),a.moveTo(o+Math.cos(p)*l,i+Math.sin(p)*l),a.arc(o,i,r,p,p+v),a.arc(o,i,l,p+v,p,!0),a.closePath(),a.fillStyle=h,a.fill(),a.strokeStyle="rgba(0,8,20,0.85)",a.lineWidth=2,a.stroke(),p+=v}a.beginPath(),a.arc(o,i,l-1,0,Math.PI*2),a.fillStyle="rgba(0,21,36,0.94)",a.fill()}function Jm(e,t){let n=!1;for(let s of e){if((s==null?void 0:s.type)!=="Payment")continue;let a=typeof(s==null?void 0:s.amountXrp)=="number"?s.amountXrp:null;a==null||a<bn.whaleTxXrp||(yt.unshift({ts:Date.now(),ledgerIndex:t,from:s.account||"\u2014",to:s.destination||"\u2014",amtXrp:a,hash:s.hash||""}),We.whaleCount++,n=!0)}if(n){for(;yt.length>Au;)yt.pop();Qm()}}function Ym(){if(Fr)return;Fr=!0;let e=document.querySelector(".dashboard-col-side");if(!e)return;let t=document.createElement("section");t.className="widget-card",t.id="whale-feed-card",t.setAttribute("aria-label","Whale alert feed"),t.innerHTML=`
    <div class="widget-header">
      <span class="widget-title">\u{1F40B} Whale Alert Feed</span>
      <span class="widget-tag mono cut" id="whale-badge">Watching\u2026</span>
    </div>
    <p class="widget-help">Payments \u2265 ${bn.whaleTxXrp.toLocaleString()} XRP from the live stream. Click address to peek.</p>
    <div id="whale-feed-list" style="max-height:260px;overflow-y:auto">
      <div style="opacity:.5;font-size:.82rem;padding:8px 0">Watching for large transfers\u2026</div>
    </div>`,e.prepend(t)}function Qm(){let e=y("whale-feed-list");if(!e)return;let t=y("whale-badge");if(t&&(t.textContent=yt.length?`${yt.length} alerts`:"Watching\u2026"),!yt.length){e.innerHTML='<div style="opacity:.5;font-size:.82rem;padding:8px 0">No whale transactions yet.</div>';return}e.innerHTML=yt.slice(0,20).map(n=>{let s=n.amtXrp>=1e6?`${(n.amtXrp/1e6).toFixed(2)}M`:n.amtXrp>=1e3?`${(n.amtXrp/1e3).toFixed(0)}K`:n.amtXrp.toFixed(0),a=Math.floor((Date.now()-n.ts)/1e3),o=a<60?`${a}s`:a<3600?`${Math.floor(a/60)}m`:`${Math.floor(a/3600)}h`;return`<div style="border-bottom:1px solid rgba(255,255,255,.05);padding:7px 0">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">
        <span>\u{1F40B}</span><span style="font-size:.95rem;font-weight:700;color:#50fa7b">${s} XRP</span>
        <span style="font-size:.7rem;opacity:.45;margin-left:auto">${o} \xB7 #${n.ledgerIndex.toLocaleString()}</span>
      </div>
      <div style="display:flex;gap:4px;align-items:center;font-size:.74rem">
        <button class="addr-link mono cut" data-addr="${g(n.from)}" style="max-width:100px">${g(U(n.from))}</button>
        <span style="opacity:.5">\u2192</span>
        <button class="addr-link mono cut" data-addr="${g(n.to)}" style="max-width:100px">${g(U(n.to))}</button>
        ${n.hash?`<a href="https://livenet.xrpl.org/transactions/${g(n.hash)}" target="_blank" rel="noopener" style="margin-left:auto;color:var(--accent,#00d4ff);font-size:.7rem;text-decoration:none">\u{1F517}</a>`:""}
      </div>
    </div>`}).join("")}function Zm(){if(Br)return;Br=!0;let e=document.querySelector(".dashboard-col-main");if(!e)return;let t=document.createElement("section");t.className="widget-card",t.id="network-health-card",t.setAttribute("aria-label","Network health"),t.innerHTML=`
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
    </div>`;let n=document.getElementById("landscape-card");n?e.insertBefore(t,n):e.prepend(t)}function ef(e){var v;if(!document.getElementById("network-health-card"))return;let t=Mt(O.tpsHistory,Bt),n=Mt(O.feeHistory,Bt),s=e.successRate!=null?Number(e.successRate):null,a=((v=e.latestLedger)==null?void 0:v.closeTimeSec)!=null?Number(e.latestLedger.closeTimeSec):null,o=t.cur!=null?ke(Math.round(Math.min(t.cur,50)/50*25),0,25):12,i=n.deltaPct!=null?ke(Math.round(25-Math.abs(n.deltaPct)/100*25),0,25):12,r=s!=null?ke(Math.round(s/100*25),0,25):12,l=a!=null?ke(Math.round(25-Math.max(0,(a-3)/7)*25),0,25):12,c=o+i+r+l,d=c>=75?"#50fa7b":c>=50?"#ffb86c":"#ff5555",u=c>=75?"Healthy":c>=50?"Degraded":"Stressed",p=y("health-score");p&&(p.textContent=c,p.style.color=d);let m=y("health-badge");m&&(m.textContent=u,m.style.color=d);let f=y("health-bars");f&&(f.innerHTML=[{label:"TPS",score:o,note:t.cur!=null?`${t.cur.toFixed(1)} tx/s`:"\u2014"},{label:"Fee Stable",score:i,note:n.deltaPct!=null?Zt(n.deltaPct,0)+" vs avg":"\u2014"},{label:"Success",score:r,note:s!=null?`${s.toFixed(1)}%`:"\u2014"},{label:"Close Time",score:l,note:a!=null?`${a.toFixed(1)}s`:"\u2014"}].map(h=>{let w=h.score/25*100,k=h.score>=20?"#50fa7b":h.score>=12?"#ffb86c":"#ff5555";return`<div style="display:flex;align-items:center;gap:8px">
        <span style="font-size:.7rem;min-width:68px;opacity:.7">${h.label}</span>
        <div style="flex:1;height:5px;background:rgba(255,255,255,.08);border-radius:3px;overflow:hidden">
          <div style="height:100%;width:${w}%;background:${k};border-radius:3px"></div></div>
        <span style="font-size:.7rem;min-width:48px;text-align:right;opacity:.65">${h.note}</span>
      </div>`}).join(""))}function tf(){if(Or)return;Or=!0;let e=document.querySelector(".dashboard-col-side");if(!e)return;let t=document.createElement("section");t.className="widget-card",t.id="session-stats-card",t.setAttribute("aria-label","Session stats"),t.innerHTML=`
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
    </div>`,e.appendChild(t)}function nf(){if(!document.getElementById("session-stats-card"))return;let e=Math.floor((Date.now()-We.startTime)/6e4);V("ss-ledgers",We.ledgersProcessed.toLocaleString()),V("ss-tx",We.totalTx.toLocaleString()),V("ss-whales",We.whaleCount),V("ss-feespikes",We.feeSpikes),V("ss-bots",We.botDetections),V("ss-dexalerts",We.dexAlerts),V("ss-time",`${e}m`),V("ss-badge",`${We.ledgersProcessed} ledgers`)}function sf(e,t){var o,i,r,l,c,d,u,p;if(sl=t,yt.length&&yt[0].ledgerIndex===t){let m=yt[0],f=m.amtXrp>=1e6?`${(m.amtXrp/1e6).toFixed(1)}M`:`${(m.amtXrp/1e3).toFixed(0)}K`;ne(`\u{1F40B} Whale: ${f} XRP  ${U(m.from)} \u2192 ${U(m.to)}`)}let n=cl(),s=(o=O.feeHistory)==null?void 0:o.at(-1);s&&n&&s>n*bn.feeSpikeMultiple&&(We.feeSpikes++,be(`\u{1F525} Fee spike: ${Jt(s)} (${Math.round(s/n)}\xD7 baseline)`));let a=(((i=e.behavior)==null?void 0:i.bots)||[]).filter(m=>m.cv<bn.botCvThreshold&&m.total>8);a.length&&(We.botDetections=Math.max(We.botDetections,a.length),a[0].botType==="Flood / Spam"&&be(`\u{1F916} Spam bot: ${U(a[0].acct)} (CV ${a[0].cv.toFixed(2)})`)),((l=(r=e.dexPatterns)==null?void 0:r.window)==null?void 0:l.cancelRatio)>=bn.dexCancelAlert&&((d=(c=e.dexPatterns)==null?void 0:c.window)==null?void 0:d.total)>=20&&(We.dexAlerts++,be(`\u{1F9E0} DEX: ${Math.round(e.dexPatterns.window.cancelRatio*100)}% cancel ratio \u2014 possible quote-stuffing`)),((p=(u=e.clusters)==null?void 0:u[0])==null?void 0:p.size)>=bn.clusterMinSize&&ne(`\u{1F578} Cluster: ${e.clusters[0].size} wallets around ${U(e.clusters[0].hub)}`),e.friction>=75&&e.regime==="Manipulated"&&be(`\u26A0\uFE0F Risk score: ${e.friction}/100 \u2014 ${e.regime} regime`),ef(e.s)}function af(){var n,s,a,o;if(Xr)return;Xr=!0;let e=document.createElement("button");e.id="customize-btn",e.className="customize-btn",e.setAttribute("aria-pressed","false"),e.innerHTML="\u2699 Customize",(n=document.querySelector(".dashboard-header"))==null||n.appendChild(e);let t=document.createElement("div");t.id="customize-panel",t.className="customize-panel",t.setAttribute("aria-label","Dashboard customizer"),t.innerHTML=`
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
    </div>`,document.body.appendChild(t),e.addEventListener("click",()=>Gr()),(s=document.getElementById("customize-close"))==null||s.addEventListener("click",()=>Gr(!1)),(a=document.getElementById("customize-reset"))==null||a.addEventListener("click",()=>{try{localStorage.removeItem(oa),localStorage.removeItem(qn)}catch{}Kr(),go(),xo()}),(o=document.getElementById("customize-export"))==null||o.addEventListener("click",()=>{var i;try{let r={order:JSON.parse(localStorage.getItem(oa)||"[]"),hidden:JSON.parse(localStorage.getItem(qn)||"[]"),alertConfig:bn};(i=navigator.clipboard)==null||i.writeText(JSON.stringify(r,null,2)),ne("Config copied to clipboard")}catch{be("Export failed")}}),Kr(),go()}function Gr(e){var s;let t=document.getElementById("customize-panel"),n=document.getElementById("customize-btn");!t||!n||(vn=e??!vn,t.classList.toggle("customize-panel--open",vn),n.setAttribute("aria-pressed",String(vn)),n.textContent=vn?"\u2715 Close":"\u2699 Customize",vn&&xo(),(s=document.querySelector(".dashboard-col-side"))==null||s.classList.toggle("customize-mode",vn))}function fs(){var e;return[...((e=document.querySelector(".dashboard-col-side"))==null?void 0:e.querySelectorAll(":scope > .widget-card"))||[]]}function Vn(e){return e.id||e.getAttribute("aria-label")||""}function of(e){var t,n;return((n=(t=e.querySelector(".widget-title"))==null?void 0:t.textContent)==null?void 0:n.trim())||Vn(e)}function Kr(){let e=document.querySelector(".dashboard-col-side");if(!e)return;let t;try{t=JSON.parse(localStorage.getItem(oa)||"null")}catch{t=null}if(!Array.isArray(t)||!t.length)return;let n=new Map(fs().map(s=>[Vn(s),s]));t.forEach(s=>{let a=n.get(s);a&&e.appendChild(a)})}function go(){let e;try{e=JSON.parse(localStorage.getItem(qn)||"[]")}catch{e=[]}fs().forEach(t=>t.classList.toggle("widget-hidden",e.includes(Vn(t))))}function rf(){try{localStorage.setItem(oa,JSON.stringify(fs().map(e=>Vn(e))))}catch{}}function lf(e){let t;try{t=JSON.parse(localStorage.getItem(qn)||"[]")}catch{t=[]}t=t.includes(e)?t.filter(n=>n!==e):[...t,e];try{localStorage.setItem(qn,JSON.stringify(t))}catch{}go(),xo()}function xo(){let e=document.getElementById("customize-list");if(!e)return;let t;try{t=JSON.parse(localStorage.getItem(qn)||"[]")}catch{t=[]}e.innerHTML="",fs().forEach(n=>{var r;let s=Vn(n),a=of(n),o=!t.includes(s),i=document.createElement("div");i.className="customize-row",i.setAttribute("draggable","true"),i.dataset.widgetId=s,i.innerHTML=`
      <span class="customize-drag-handle" title="Drag to reorder">\u283F</span>
      <span class="customize-row-title">${g(a)}</span>
      <button class="customize-vis-btn ${o?"vis-on":"vis-off"}" data-id="${g(s)}">${o?"\u{1F441} Visible":"\u{1F6AB} Hidden"}</button>`,i.addEventListener("dragstart",l=>{Dn=i,l.dataTransfer.effectAllowed="move",i.classList.add("customize-dragging")}),i.addEventListener("dragend",()=>{i.classList.remove("customize-dragging"),e.querySelectorAll(".customize-row").forEach(d=>d.classList.remove("customize-over"));let l=[...e.querySelectorAll(".customize-row")].map(d=>d.dataset.widgetId),c=document.querySelector(".dashboard-col-side");if(c){let d=new Map(fs().map(u=>[Vn(u),u]));l.forEach(u=>{let p=d.get(u);p&&c.appendChild(p)})}rf()}),i.addEventListener("dragover",l=>{if(l.preventDefault(),l.dataTransfer.dropEffect="move",Dn&&Dn!==i){e.querySelectorAll(".customize-row").forEach(d=>d.classList.remove("customize-over")),i.classList.add("customize-over");let c=[...e.querySelectorAll(".customize-row")];c.indexOf(Dn)<c.indexOf(i)?e.insertBefore(Dn,i.nextSibling):e.insertBefore(Dn,i)}}),i.addEventListener("dragleave",()=>i.classList.remove("customize-over")),i.addEventListener("drop",l=>l.preventDefault()),(r=i.querySelector(".customize-vis-btn"))==null||r.addEventListener("click",()=>lf(s)),e.appendChild(i)})}function cf(){if(Hr)return;Hr=!0;let e=document.querySelector(".dashboard-header");if(!e||document.getElementById("global-pause-btn"))return;let t=document.createElement("button");t.id="global-pause-btn",t.className="global-pause-btn",t.setAttribute("aria-pressed","false"),t.title="Pause all updates \u2014 numbers stop changing so you can read",t.innerHTML="\u23F8 Live",t.addEventListener("click",()=>{Rt=!Rt,t.setAttribute("aria-pressed",String(Rt)),t.innerHTML=Rt?"\u25B6 Paused":"\u23F8 Live",t.classList.toggle("global-pause-btn--paused",Rt),bt=Rt&&!us?Rt:bt;let s=document.querySelector(".dashboard-sticky-strip");s&&s.classList.toggle("metrics-paused",Rt)});let n=document.getElementById("customize-btn");n?e.insertBefore(t,n):e.appendChild(t)}var Jr=!1;function df(){if(Jr)return;Jr=!0;let e=(t=0)=>{let n=document.querySelector("#risk-card .widget-header"),s=document.querySelector("#landscape-card .widget-header");if(!n&&!s&&t<20){setTimeout(()=>e(t+1),300);return}if(n&&!n.querySelector(".friction-sparkline-wrap")){let a=document.createElement("div");a.className="friction-sparkline-wrap",a.title="Risk score \u2014 last 30 ledgers",a.innerHTML='<canvas id="friction-sparkline-canvas" width="80" height="22"></canvas>',n.appendChild(a)}if(s&&!s.querySelector(".friction-sparkline-wrap")){let a=document.createElement("div");a.className="friction-sparkline-wrap",a.title="Risk score history",a.innerHTML='<canvas id="friction-sparkline-canvas-2" width="60" height="18"></canvas>',s.appendChild(a)}yl()};e()}function yl(){On.length&&(Yr("friction-sparkline-canvas",80,22),Yr("friction-sparkline-canvas-2",60,18))}function Yr(e,t,n){let s=document.getElementById(e);if(!(s!=null&&s.getContext))return;let a=s.getContext("2d");a.clearRect(0,0,t,n);let o=On;if(o.length<2)return;let i=100,r=t/(o.length-1),l=o.map((v,h)=>[h*r,n-2-v.friction/i*(n-4)]),c=n-2-60/i*(n-4);a.fillStyle="rgba(255,85,85,.07)",a.fillRect(0,0,t,c);let d=a.createLinearGradient(0,0,0,n);d.addColorStop(0,"rgba(255,184,108,.35)"),d.addColorStop(1,"rgba(255,184,108,.05)"),a.beginPath(),l.forEach(([v,h],w)=>w===0?a.moveTo(v,h):a.lineTo(v,h)),a.lineTo(l.at(-1)[0],n),a.lineTo(0,n),a.closePath(),a.fillStyle=d,a.fill();let u=o.at(-1).friction,p=u<26?"#50fa7b":u<61?"#ffb86c":"#ff5555";a.beginPath(),l.forEach(([v,h],w)=>w===0?a.moveTo(v,h):a.lineTo(v,h)),a.strokeStyle=p,a.lineWidth=1.5,a.lineJoin="round",a.stroke();let[m,f]=l.at(-1);a.beginPath(),a.arc(m,f,2.5,0,Math.PI*2),a.fillStyle=p,a.fill()}window.printLandscapeReport=function(){var i,r,l,c;if(!document.getElementById("landscape-card"))return;let t=((i=document.getElementById("d2-ledger-index"))==null?void 0:i.textContent)||"\u2014",n=((r=document.getElementById("landscape-badge"))==null?void 0:r.textContent)||"",s=new Date().toLocaleString(),a=window.open("","_blank","width=860,height=700");a.document.write(`<!DOCTYPE html><html><head>
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
  <div class="meta">Ledger #${t} \xB7 ${n} \xB7 Generated ${s}</div>`);let o=[{id:"landscape-text",label:"Situation Summary"},{id:"landscape-why",label:"Why It Matters"},{id:"landscape-now",label:"What Is Happening"},{id:"landscape-watch",label:"What To Watch Next"},{id:"landscape-watchlist",label:"Who To Watch"}];for(let{id:d,label:u}of o){let p=document.getElementById(d);if(!(!p||!p.textContent.trim())){if(a.document.write(`<div class="section"><div class="section-h">${u}</div>`),d==="landscape-watchlist"){let m=p.querySelectorAll(".landscape-watchitem");if(m.length)for(let f of m){let v=((l=f.querySelector(".addr-link"))==null?void 0:l.textContent)||"\u2014",h=((c=f.querySelector(".landscape-watchwhy"))==null?void 0:c.textContent)||"";a.document.write(`<div class="watchitem"><b>${v}</b><p>${h}</p></div>`)}else a.document.write(`<div class="row">${p.textContent.trim()}</div>`)}else{let m=p.querySelectorAll(".landscape-row");if(m.length)for(let f of m)a.document.write(`<div class="row">${f.innerHTML}</div>`);else a.document.write(`<div class="row">${p.innerHTML}</div>`)}a.document.write("</div>")}}a.document.write("</body></html>"),a.document.close()};function pf(){if(Ar)return;Ar=!0;let e=document.getElementById("dashboard");if(!e||document.getElementById("dash-bottom-nav"))return;let t=document.createElement("nav");t.id="dash-bottom-nav",t.setAttribute("aria-label","Dashboard quick nav"),t.innerHTML=`
    <button data-go="stream" class="bn-btn"><span>\u{1F30A}</span><small>Stream</small></button>
    <button data-go="inspector" class="bn-btn"><span>\u{1F50D}</span><small>Inspect</small></button>
    <button data-go="network" class="bn-btn"><span>\u{1F4E1}</span><small>Health</small></button>
    <button data-go="dex" class="bn-btn"><span>\u{1F9E0}</span><small>DEX</small></button>
    <button data-go="risk" class="bn-btn"><span>\u26A0\uFE0F</span><small>Risk</small></button>
  `,e.appendChild(t);let n=s=>{var a;return(a=document.querySelector(`.dash-tab[data-tab="${s}"]`))==null?void 0:a.click()};t.addEventListener("click",s=>{let a=s.target.closest("button[data-go]");if(!a)return;let o=a.dataset.go;if(o==="stream"||o==="inspector"||o==="network"){n(o);return}n("stream"),setTimeout(()=>{var r;let i=o==="dex"?"dex-pattern-card":"risk-card";(r=document.getElementById(i))==null||r.scrollIntoView({behavior:"smooth",block:"start"})},80)})}function uf(){var a,o;if(Er)return;Er=!0;let e=document.querySelector(".dashboard-header");if(!e||document.getElementById("compactToggleBtn"))return;let t=document.createElement("button");t.id="compactToggleBtn",t.type="button",t.className="dash-accordion-toggle",t.textContent="Compact: OFF",e.appendChild(t);let n=(i,r=!0)=>{if(document.body.classList.toggle("dash-accordion",i),t.textContent=i?"Compact: ON":"Compact: OFF",r)try{localStorage.setItem(xr,i?"1":"0")}catch{}if(i){let l=document.querySelector(".dashboard-col-side .widget-card");l&&l.classList.add("is-open")}else document.querySelectorAll(".dashboard-col-side .widget-card.is-open").forEach(l=>l.classList.remove("is-open"))},s=null;try{s=localStorage.getItem(xr)}catch{}n(s==="1"?!0:s==="0"?!1:((o=(a=window.matchMedia)==null?void 0:a.call(window,"(max-width: 600px)"))==null?void 0:o.matches)??!1,!1),t.addEventListener("click",()=>n(!document.body.classList.contains("dash-accordion"),!0))}function mf(){if(Nr)return;Nr=!0;let e=document.querySelector(".dashboard-col-side");e&&e.addEventListener("click",t=>{var o,i;if(!document.body.classList.contains("dash-accordion"))return;let n=t.target;if((o=n==null?void 0:n.closest)!=null&&o.call(n,"button, a, input, textarea, select, kbd"))return;let s=(i=n==null?void 0:n.closest)==null?void 0:i.call(n,".widget-card");if(!s)return;let a=s.classList.contains("is-open");e.querySelectorAll(".widget-card.is-open").forEach(r=>{r!==s&&r.classList.remove("is-open")}),s.classList.toggle("is-open",!a)})}var ko=class extends Error{constructor(){super("AI explanations aren\u2019t set up yet \u2014 add your Anthropic API key in Profile \u2192 Settings.")}};function wl(){var t;let e=(t=Ee.vault)==null?void 0:t.ai;return!!(e!=null&&e.apiKey&&(e!=null&&e.proxyUrl))}async function xl(e,{system:t,maxTokens:n=2048}={}){var l,c;let s=(l=Ee.vault)==null?void 0:l.ai;if(!(s!=null&&s.apiKey)||!(s!=null&&s.proxyUrl))throw new ko;let a={model:s.model||"claude-opus-5",max_tokens:n,messages:[{role:"user",content:e}]};t&&(a.system=t);let o;try{o=await fetch(s.proxyUrl,{method:"POST",headers:{"content-type":"application/json","x-api-key":s.apiKey,"anthropic-version":"2023-06-01"},body:JSON.stringify(a)})}catch{throw new Error("Could not reach the AI proxy \u2014 check the proxy URL in Settings and that it\u2019s deployed and running.")}let i;try{i=await o.json()}catch{i=null}if(!o.ok){let d=((c=i==null?void 0:i.error)==null?void 0:c.message)||`AI request failed (HTTP ${o.status})`;throw new Error(d)}if((i==null?void 0:i.stop_reason)==="refusal")throw new Error("Claude declined to respond to this request.");let r=((i==null?void 0:i.content)||[]).filter(d=>d.type==="text").map(d=>d.text).join(`
`).trim();if(!r)throw new Error("AI response was empty.");return r}var Xe={lsfPasswordSpent:65536,lsfRequireDestTag:131072,lsfRequireAuth:262144,lsfDisallowXRP:524288,lsfDisableMaster:1048576,lsfNoFreeze:2097152,lsfGlobalFreeze:4194304,lsfDefaultRipple:8388608,lsfDepositAuth:16777216},kl={lsfBurnable:1,lsfOnlyXRP:2,lsfTrustLine:4,lsfTransferable:8},ff=new Set(["SetRegularKey","SignerListSet","AccountSet","AccountDelete","EscrowCreate","PaymentChannelCreate","DepositPreauth"]),en={blackhole:"#ff5555",exchange:"#00d4ff",newWallet:"#ff79c6",issuer:"#ffb86c",wallet:"#bd93f9",other:"#8be9fd"},$l=.55,hf=.15,Gn=20,gf=946684800,vf=new Map([["rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy",{name:"Bitstamp",type:"exchange"}],["rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B",{name:"Bitstamp",type:"exchange"}],["rrpNnNLKrartuEqfJGpqyDwPj1BBN1ih7",{name:"Bitstamp",type:"exchange"}],["rN7n3473SaZBCG4dFL83w7PB9judJ7qdDo",{name:"Binance",type:"exchange"}],["rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh",{name:"Binance",type:"exchange"}],["rBKPS4oLSaV2KVVuHH8EpQqMGgGefGFQs7",{name:"Bitso",type:"exchange"}],["rfk5bwaKCoNU84fTzdqWQowqnNaZorDmiV",{name:"Gate.io",type:"exchange"}],["rGFuMiw48HdbnrUbkRYDTvT5i9imC5fvv9",{name:"Gate.io",type:"exchange"}],["rwYHCs2EYBMBvRXFmxDrCUSorPsuqCck7t",{name:"Kraken",type:"exchange"}],["rLHzPsX6oXkzU2qL12kHCH8G8cnZv1rBJh",{name:"Kraken",type:"exchange"}],["ra5nK24KXen9AHvsdFTKHSANinZseWnPcX",{name:"Uphold",type:"exchange"}],["rGWrZyax5eXbi5gs49MRZKkE9eKNL9p4B",{name:"Bittrex",type:"exchange"}],["rDsbeomae4FXwgQTJp9Rs64Qg9vDiTCdBv",{name:"Coinone",type:"exchange"}],["rHsMUQFzBb7S6GnQFVgNirqvHRcLpAn5dU",{name:"Bithumb",type:"exchange"}],["rMQ98K56yXJbDGv49ZSmW51sLn94Xe1mu1",{name:"Huobi",type:"exchange"}],["rHcFoo6a9qT5NHiVn1THwX3B4QF2VQKWZ",{name:"Huobi",type:"exchange"}],["rKiCet8SdvWxPXnAgYarFUXMh1zCPz432Y",{name:"Coinbase",type:"exchange"}],["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",{name:"Coinbase",type:"exchange"}],["r9mhdcT2K7FdCGDEPqfbMJwVXsXCqEr5bP",{name:"OKX",type:"exchange"}],["r32U8WFxhqEAVkKcTb1GGRR1VH2oaFdexN",{name:"OKX",type:"exchange"}],["r4GDFMLGJUKMjNEycBKPGnRSNXyNVLQLHi",{name:"Bybit",type:"exchange"}],["rBETszU65yYoFcYdRkiGqFaYmhZpHWC7sj",{name:"Bybit",type:"exchange"}],["rMWUykAmNQDaM9poSes8VLDZDDkEoutilities",{name:"KuCoin",type:"exchange"}],["rUA1S9qobBkxLqzdfGEzh5wm5KdLfbf8bx",{name:"KuCoin",type:"exchange"}],["rHtbQzmN4BDaEBnGSXp3AZaZAuZamNVsME",{name:"MEXC",type:"exchange"}],["rDN1gPWW3XQFXVJFQSiJxPHGZiRLMVSi7K",{name:"MEXC",type:"exchange"}],["rB3gZey7VWHoDokMt3tCiXBSRmaZi5xJi9",{name:"Crypto.com",type:"exchange"}],["rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq",{name:"GateHub",type:"exchange"}],["razqnFn6FqBaYBdNaGnVzmGaNE6XPRQ9bG",{name:"GateHub",type:"exchange"}],["rGQdkxNBQeQC1WTQDQ2F2QoGBZxYcMxBBg",{name:"GateHub",type:"exchange"}],["rpXTzCuXtjiPDFysxq8uNmtZBe9Xo97JbW",{name:"Bitbank",type:"exchange"}],["rsuUjfWxrACCAwGQDsNeZUhpzXf1n1NK5Z",{name:"Bitbank",type:"exchange"}],["r9oxUGJqMfMEhGBxrMJnmNvVh1LKkMv7fz",{name:"Coincheck",type:"exchange"}],["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",{name:"Genesis (Black Hole)",type:"blackhole"}],["r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59",{name:"Black Hole #2",type:"blackhole"}],["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",{name:"Genesis Wallet",type:"ripple"}],["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",{name:"Ripple Labs Ops",type:"ripple"}],["rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY",{name:"XAMAN (XUMM)",type:"wallet"}],["rBj4eVRWn6mCELVTNkVFDfGNByE9VFTM3R",{name:"XAMAN",type:"wallet"}],["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",{name:"XRPL AMM Engine",type:"dex"}],["rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz",{name:"SOLO Issuer",type:"issuer"}],["rcoreNywaoz2ZCVt2sc3JiEi7G7MpZxZgm",{name:"CORE Token",type:"issuer"}],["rhXo4TcWbLY4GqTSmscMpgZ1KMXFBi9V55",{name:"XRPL DeFi Pool",type:"issuer"}],["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",{name:"UNL Validator Set",type:"validator"}]]);function Yn(e){return vf.get(e)||null}var bf=null,et=!1;var Kn=null,Sl=!1,So=!0;function ca(){return So&&O.currentPage==="dashboard"&&O.currentTab==="inspector"&&!document.hidden}async function yf(e){let t=[s=>`https://corsproxy.io/?${encodeURIComponent(s)}`,s=>`https://api.allorigins.win/raw?url=${encodeURIComponent(s)}`],n=async s=>{let a=typeof(AbortSignal==null?void 0:AbortSignal.timeout)=="function"?AbortSignal.timeout(6e3):void 0,o=await fetch(s,{mode:"cors",cache:"no-store",signal:a});if(!o.ok)throw new Error(`HTTP ${o.status}`);return await o.json()};try{return await n(e)}catch{for(let s of t)try{return await n(s(e))}catch{}throw new Error("Price feed unavailable")}}async function wf(){if(Sl)return Kn;Sl=!0;try{let e=await yf("https://api.exchange.coinbase.com/products/XRP-USD/ticker");Kn=Number((e==null?void 0:e.price)||0)||null}catch{Kn=null}return Kn}function nn(e){if(!Kn||!e)return"";let t=e*Kn;return t>=1e6?` (~$${(t/1e6).toFixed(2)}M)`:t>=1e3?` (~$${(t/1e3).toFixed(1)}K)`:` (~$${t.toFixed(2)})`}var vs=null;function Cl(){return vs||(vs={input:()=>document.getElementById("inspect-addr"),err:document.getElementById("inspect-err"),result:document.getElementById("inspect-result"),empty:document.getElementById("inspect-empty"),loading:document.getElementById("inspect-loading"),loadMsg:document.getElementById("inspect-loading-msg"),warn:document.getElementById("inspect-warn"),badge:document.getElementById("inspect-addr-badge"),score:document.getElementById("inspect-risk-score"),label:document.getElementById("inspect-risk-label")},vs)}function xf(){vs=null,Cl()}function Ll(){var t,n,s,a;Ph(),Ah(),Eh(),(t=y("inspect-addr"))==null||t.addEventListener("keydown",o=>{o.key==="Enter"&&Jn()}),(n=y("inspect-addr"))==null||n.addEventListener("paste",()=>{setTimeout(()=>{var i;let o=(i=y("inspect-addr"))==null?void 0:i.value.trim();o&&Ue(o)&&Jn()},60)}),(s=document.getElementById("tab-inspector"))==null||s.addEventListener("click",o=>{var r;let i=o.target.closest(".section-header");i&&((r=i.closest(".inspector-section"))==null||r.classList.toggle("collapsed"))}),(a=document.getElementById("inspector-nav"))==null||a.addEventListener("click",o=>{let i=o.target.closest("[data-jump]");if(!i)return;let r=document.getElementById("section-"+i.dataset.jump);r&&(r.classList.remove("collapsed"),r.scrollIntoView({behavior:"smooth",block:"start"})),_l(i.dataset.jump)});let e=!1;window.addEventListener("scroll",()=>{ca()&&(e||(e=!0,requestAnimationFrame(()=>{Nh(),e=!1})))},{passive:!0}),window.runInspect=Jn,window.inspectorCopyAddr=Rh,window.showInspectorHowTo=Dh,window.hideInspectorHowTo=Co,xf(),Oh(),window.addEventListener("naluxrp:tabchange",o=>{var i;((i=o.detail)==null?void 0:i.tabId)==="inspector"&&ca()&&(Po(),Ao(),xs(),da())})}function Ml(e){So=!!e,So||(et=!0)}async function Jn(){var a,o,i,r,l,c,d,u,p,m,f,v,h,w;if(!ca())return;let e=Cl(),t=((a=e.input())==null?void 0:a.value.trim())||"";if([e.err,e.result,e.empty,e.warn].forEach(k=>k&&(k.style.display="none")),et=!0,!t){e.empty&&(e.empty.style.display="");return}if(!Ue(t)){e.err&&(e.err.textContent=`\u26A0 Invalid address: ${g(t)}`,e.err.style.display="");return}if(O.connectionState!=="connected"){e.warn&&(e.warn.style.display="");return}bf=t,et=!1;let n=k=>{e.loading&&(e.loading.style.display="",e.loadMsg&&(e.loadMsg.textContent=k))};n("Fetching account data\u2026");let s=k=>new Promise(b=>setTimeout(b,k));try{n("Fetching account data\u2026");let[k,b,x]=await Promise.all([Ne({command:"account_info",account:t,ledger_index:"validated"}),Ne({command:"account_offers",account:t,ledger_index:"validated"}),Ne({command:"account_nfts",account:t,ledger_index:"validated"}).catch(()=>null)]);if(et)return;let S=((o=k==null?void 0:k.result)==null?void 0:o.account_data)||{},T=((i=b==null?void 0:b.result)==null?void 0:i.offers)||[],$=((r=x==null?void 0:x.result)==null?void 0:r.account_nfts)||[];n("Fetching trustlines\u2026");let P=[],M,N=0;do{N++;let H={command:"account_lines",account:t,ledger_index:"validated",limit:400};M&&(H.marker=M);let Y=await Ne(H).catch(()=>null);if(et)return;let me=((l=Y==null?void 0:Y.result)==null?void 0:l.lines)||[];P.push(...me),M=((c=Y==null?void 0:Y.result)==null?void 0:c.marker)||null,N>1&&await s(50)}while(M&&P.length<4e3);n("Fetching account objects\u2026");let _=[],X,I=0;do{I++;let H={command:"account_objects",account:t,ledger_index:"validated",limit:400};X&&(H.marker=X);let Y=await Ne(H).catch(()=>null);if(et)return;let me=((d=Y==null?void 0:Y.result)==null?void 0:d.account_objects)||[];_.push(...me),X=((u=Y==null?void 0:Y.result)==null?void 0:u.marker)||null,I>1&&await s(50)}while(X&&_.length<2e3);n("Fetching token supply, AMM data & price\u2026");let R=P.filter(H=>H.currency&&(H.currency.startsWith("03")||H.currency.length===40)),[F,,...W]=await Promise.all([Ne({command:"gateway_balances",account:t,ledger_index:"validated"}).catch(()=>null),wf(),...R.slice(0,5).map(H=>Ne({command:"amm_info",asset:{currency:"XRP"},asset2:{currency:H.currency,issuer:H.account},ledger_index:"validated"}).catch(()=>null))]);if(et)return;let E=(F==null?void 0:F.result)||null,z=new Map;R.slice(0,5).forEach((H,Y)=>{var me,De;(De=(me=W[Y])==null?void 0:me.result)!=null&&De.amm&&z.set(H.currency,W[Y].result.amm)});let Q=400,ie=250,ce=window._inspectMaxTx||5e3,de=Math.ceil(ce/Q),se=[],fe=new Set,K=H=>{var Y,me;for(let De of H||[]){let Be=((Y=De.tx_json)==null?void 0:Y.hash)||((me=De.tx)==null?void 0:me.hash)||De.hash||null;Be&&fe.has(Be)||(Be&&fe.add(Be),se.push(De))}},xe;for(let H=1;H<=de&&se.length<ce;H++){if(et)return;n(`Fetching transactions \u2014 page ${H} (${se.length.toLocaleString()} so far)\u2026`);let Y={command:"account_tx",account:t,limit:Q,ledger_index_min:-1,ledger_index_max:-1,forward:!1};xe&&(Y.marker=xe);let me=await Ne(Y).catch(()=>null);if(et)return;if(K((p=me==null?void 0:me.result)==null?void 0:p.transactions),xe=((m=me==null?void 0:me.result)==null?void 0:m.marker)||null,!xe)break;H<de&&se.length<ce&&await s(ie)}if(se.length<ce){if(et)return;n("Fetching oldest transactions (anchoring history start)\u2026");let H=await Ne({command:"account_tx",account:t,limit:Q,ledger_index_min:-1,ledger_index_max:-1,forward:!0}).catch(()=>null);if(et)return;K((f=H==null?void 0:H.result)==null?void 0:f.transactions),await s(ie)}e.loading&&(e.loading.style.display="none");let B=kf(se).sort((H,Y)=>(H.tx.date??0)-(Y.tx.date??0)),J=946684800,re=null,pe=null;if(B.length>0){let H=B[0].tx;H!=null&&H.date&&(pe=(H.date+J)*1e3,re=Math.floor((Date.now()-pe)/864e5))}let Se=new Map;for(let{tx:H}of B){if(H.TransactionType!=="OfferCreate"||!H.TakerPays||!H.TakerGets)continue;let Y=De=>typeof De=="string"?"XRP":`${De.currency}+${De.issuer||""}`,me=[Y(H.TakerPays),Y(H.TakerGets)].sort().join("\u2194");Se.set(me,(Se.get(me)||0)+1)}let ge=null;if(Se.size>0){let H=[...Se.entries()].sort((Ut,Hs)=>Hs[1]-Ut[1])[0][0],[Y,me]=H.split("\u2194"),De=Ut=>Ut==="XRP"?{currency:"XRP"}:{currency:Ut.split("+")[0],issuer:Ut.split("+")[1]},Be=await Ne({command:"book_offers",taker_pays:De(Y),taker_gets:De(me),limit:20,ledger_index:"validated"}).catch(()=>null);(h=(v=Be==null?void 0:Be.result)==null?void 0:v.offers)!=null&&h.length&&(ge={pair:H,offers:Be.result.offers})}let ot=[...new Set(B.filter(({tx:H})=>H.TransactionType==="Payment"&&H.Account===t&&H.Destination).map(({tx:H})=>H.Destination))].slice(0,6),it=new Map;for(let H of ot){if(et)return;let Y=await Ne({command:"account_info",account:H,ledger_index:"validated"}).catch(()=>null),me=(w=Y==null?void 0:Y.result)==null?void 0:w.account_data;me&&it.set(H,{sequence:me.Sequence||0,balance:Number(me.Balance||0)/1e6}),await s(80)}$f(t,S,P,T,$,_,B,{gatewayBalances:E,ammInfoMap:z,destAgeMap:it,walletAgeDays:re,walletCreatedTs:pe,liveOrderBook:ge}),e.result&&(e.result.style.display="",Eo());let Ce=e.score?Number(e.score.textContent):null;qh(t,isNaN(Ce)?null:Ce);let ue=window._lastAllFindings||[];Vh(t,isNaN(Ce)?null:Ce,ue),eg(t,ue),Lo(t)&&Kh(t,isNaN(Ce)?null:Ce),Qh()}catch(k){if(et)return;e.loading&&(e.loading.style.display="none"),e.err&&(e.err.textContent=`Error: ${g(k.message)}`,e.err.style.display="")}}function kf(e){return e.map(t=>{let n=t.tx_json||t.tx||t.transaction||{},s=t.metadata||t.meta||{};return n.date==null&&t.date!=null&&(n.date=t.date),!n.hash&&t.hash&&(n.hash=t.hash),{tx:n,meta:s}})}function $f(e,t,n,s,a,o,i,r={}){let{gatewayBalances:l=null,ammInfoMap:c=new Map,destAgeMap:d=new Map,walletAgeDays:u=null,walletCreatedTs:p=null,liveOrderBook:m=null}=r,f=Number(t.Balance||0)/1e6,v=Number(t.OwnerCount||0),h=10+v*2,w=Number(t.Flags||0),k=t.Sequence??"\u2014",b=o.filter(ge=>ge.LedgerEntryType==="SignerList"),x=o.filter(ge=>ge.LedgerEntryType==="Escrow"),S=o.filter(ge=>ge.LedgerEntryType==="PayChannel"),T=o.filter(ge=>ge.LedgerEntryType==="DepositPreauth"),$=o.filter(ge=>ge.LedgerEntryType==="Check"),P=Mf(t,w,b,i),M=Pf(t,w,b,i,S,x),N=Af(a,i,e),_=Ef(i,e,n),X=Bf(t,n,w,i),I=Of(n,i,o,c),R=Nf(i),F=Ff(i,e),W=_f(i,e),E=Rf(i,e),z=Df(i),Q=If(i,e),ie=Sf(i,e,d),ce=Xf(i),de=Hf(i,e),se=zf(i,e),fe=Tf(i,e,n,l),K=Uf(i,e),xe=Wf(i,e),B=jf(o,i,e),J=qf(o),re=Vf(m,e),pe=Kf(P,M,N,_,R,F,W,E,z,Q,ce);sh(e,t,f,h,v,k,pe,u,p),ah(P,t,w,b,T),oh(M,S,x,$),mh(ie,f,K),ih(N,a),lh(_),Jf(R),Yf(F),Qf(W),Zf(E),eh(z),th(Q),nh(R,W,E,z,Q),ch(X,n),fh(fe,n),hh(ce),gh(de),vh(se),dh(I,n),bh(K),yh(xe),wh(B),xh(J),kh(re),$h(pe,P,M,N,_,R,F,W,E,z,Q,ce,K,xe),ph(n),uh(i,e),Tl(i),ng(i,e,ie,K),window._lastTxList=i;let Se=y("inspect-report-body");Se&&(Mh(Se,e,t,f,pe,P,M,N,_,R,F,X,I,ie,fe,i,W,E,z,Q,{feeAnalysis:ce,destTagAnalysis:de,pathDepthAnalysis:se,gatewayBalances:l,inboundFlowAnalysis:K,memoAnalysis:xe,escrowDepthAnalysis:B,checkAnalysis:J,liveBookAnalysis:re,walletAgeDays:u,walletCreatedTs:p}),Tl(i,"inspect-report-activity-chart"),Zh(pe,window._lastAllFindings||[],u,i.length),window._lastInspectResult={addr:e,riskScore:pe,walletAgeDays:u,txCount:i.length,findings:window._lastAllFindings||[],timestamp:new Date().toISOString()},Fl(),Bl(e))}function Sf(e,t,n=new Map){let s=new Map,a=[];for(let{tx:p,meta:m}of e){if(p.TransactionType!=="Payment"||p.Account!==t)continue;let f=p.Destination;if(!f)continue;let v=0,h=null,w=p.Amount;typeof w=="string"?v=Number(w)/1e6:w!=null&&w.value&&(h={value:Number(w.value),currency:yn(w.currency),issuer:w.issuer});let k=Array.isArray(p.Paths)&&p.Paths.length>0,b=p.SendMax!=null,x=k||b,S=k?p.Paths.reduce((M,N)=>Math.max(M,(N||[]).length+1),1):x?2:1,T=Pt(p),$={dest:f,amtXrp:v,amtToken:h,ts:T,isPathPay:x,hopCount:S,hash:p.hash||p.Hash||"",ledger:p.ledger_index||p.LedgerIndex||0,destTag:p.DestinationTag};a.push($),s.has(f)||s.set(f,{addr:f,totalXrp:0,txCount:0,firstSeen:T,lastSeen:T,entity:Yn(f)||null,pathCount:0,maxHops:1,tokens:new Map});let P=s.get(f);if(P.totalXrp+=v,P.txCount++,P.lastSeen=Math.max(P.lastSeen,T),P.firstSeen=Math.min(P.firstSeen,T),x&&(P.pathCount++,P.maxHops=Math.max(P.maxHops,S)),h){let M=`${h.currency}.${U(h.issuer||"")}`;P.tokens.set(M,(P.tokens.get(M)||0)+h.value)}}let o=[...s.values()].sort((p,m)=>m.totalXrp-p.totalXrp||m.txCount-p.txCount).slice(0,10).map(p=>({...p,tokens:[...p.tokens.entries()].map(([m,f])=>({k:m,v:f}))})),i=o.reduce((p,m)=>p+m.totalXrp,0),r=a.filter(p=>p.isPathPay).length,l=o.filter(p=>{let m=n.get(p.addr);return m&&m.sequence<10&&p.totalXrp>10}),c=o.filter(p=>{var m;return((m=p.entity)==null?void 0:m.type)==="exchange"}),d=o.filter(p=>{var m;return((m=p.entity)==null?void 0:m.type)==="blackhole"});return{timeline:[...a].filter(p=>p.amtXrp>.01||p.amtToken).sort((p,m)=>p.ts-m.ts).slice(0,30),destinations:o,totalOut:i,totalPathPay:r,uniqueDests:s.size,exchangeDests:c,blackHoleDests:d,newWalletDests:l}}function Tf(e,t,n,s=null){var T,$;let a=null;if(s!=null&&s.obligations){let P=Object.values(s.obligations);P.length===1?a=Number(P[0])||null:P.length>1&&(a=null)}let o=[],i=new Map,r=new Map,l=new Set,c=new Set(n.filter(P=>Number(P.balance)<0).map(P=>yn(P.currency)));for(let{tx:P,meta:M}of e)if(P.Account===t&&P.TransactionType==="Payment"){(($=(T=M==null?void 0:M.AffectedNodes)==null?void 0:T.some)==null?void 0:$.call(T,X=>{var I,R,F;return((I=X.CreatedNode)==null?void 0:I.LedgerEntryType)==="AccountRoot"&&((F=(R=X.CreatedNode)==null?void 0:R.NewFields)==null?void 0:F.Account)===P.Destination}))&&P.Destination&&l.add(P.Destination);let _=P.Amount;if(typeof _=="object"&&(_!=null&&_.value)&&(_!=null&&_.currency)){let X=yn(_.currency);if(c.has(X)){let I=Number(_.value),R=P.Destination;i.has(R)||(i.set(R,0),r.set(R,Pt(P))),i.set(R,i.get(R)+I)}}}let d=[...i.entries()].sort((P,M)=>M[1]-P[1]),u=[];if(d.length>=3){let P=new Map;for(let[M,N]of d){if(N<=0)continue;let _=Math.pow(10,Math.floor(Math.log10(N))),I=(Math.round(N/_/.1)*.1*_).toPrecision(2);P.has(I)||P.set(I,[]),P.get(I).push({addr:M,amt:N})}for(let[,M]of P.entries())if(M.length>=3){let N=M.reduce((_,X)=>_+X.amt,0)/M.length;u.push({approxAmt:N,accounts:M}),o.push({sev:"warn",label:`${M.length} accounts each received ~${D(N,0)} tokens`,detail:"Highly similar token amounts suggest coordinated wallets, pre-arranged airdrop clusters, or sybil accounts."})}}let p=[...r.values()].sort();if(p.length>=5){let P=p[p.length-1]-p[0];P<3600&&p.length>=10&&o.push({sev:"warn",label:`${p.length} accounts funded within ${Math.ceil(P/60)} minutes`,detail:"Rapid token distribution to many wallets in a narrow time window. Matches pre-sale airdrop or coordinated distribution for wash trading."})}l.size>0&&o.push({sev:l.size>10?"warn":"info",label:`${l.size} account(s) created by this address`,detail:"This issuer funded the activation of these accounts. They may be controlled by the same entity."});let m=n.filter(P=>Number(P.balance)<0),f=a,v=m.reduce((P,M)=>P+Math.abs(Number(M.balance)),0),h=f??v,w=f==null&&m.length>0,k=w?` (based on ${m.length} visible trustlines \u2014 actual total supply may be higher if there are more holders)`:"",b=m.map(P=>({addr:P.account,balance:Math.abs(Number(P.balance)),currency:yn(P.currency)})).sort((P,M)=>M.balance-P.balance).slice(0,10),x=f??v,S=x>0&&(f!=null||m.length>=50);if(b.length>=2&&S){let P=b[0].balance/x*100,M=f!=null?"":" (of visible sample)";P>50?o.push({sev:"critical",label:`Top holder controls ${P.toFixed(0)}%${M} of supply`,detail:`${U(b[0].addr)} holds ${D(b[0].balance,0)} of ${D(x,0)} total${k}. `+(f!=null?"Extreme dump risk \u2014 one wallet could sell everything.":"Check gateway_balances or a block explorer to confirm the full supply picture.")}):P>25&&o.push({sev:"warn",label:`Top holder controls ${P.toFixed(0)}%${M} of supply`,detail:`Large single-holder concentration${k}. Monitor for coordinated sell events.`});let _=b.slice(0,5).reduce((X,I)=>X+I.balance,0)/x*100;_>75&&o.push({sev:"warn",label:`Top 5 holders own ${_.toFixed(0)}%${M} of supply`,detail:`Supply heavily concentrated in a few wallets${k}. This pattern is common in pre-launch setups or tokens with limited real distribution.`})}else m.length>0&&!S&&o.push({sev:"info",label:`${m.length} trustline holder(s) visible \u2014 supply data limited`,detail:`Only ${m.length} trustlines returned by account_lines. The true holder count and total supply cannot be determined from this data alone. Use a block explorer (XRPScan, Bithomp) for a complete holder distribution.`});return o.length===0&&h===0&&o.push({sev:"info",label:"No token issuance detected",detail:"This account does not appear to be an active token issuer."}),{signals:o,totalIssued:h,holderCount:m.length,topHolders:b,mirrorGroups:u,createdAccts:[...l],distributions:d.slice(0,10),isSampleOnly:w}}var Cf=new Set(["rrrrrrrrrrrrrrrrrrrrrhoLvTp","rrrrrrrrrrrrrrrrrrrrBZbvji","rrrrrrrrrrrrrrrrrNAMEtxvNvQ","rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh","r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59"]);function Lf(e){return!!e&&Cf.has(e)}function Pl(e,t,n=[],s=[]){let a=!!(t&Xe.lsfDisableMaster),o=(e==null?void 0:e.RegularKey)||"",i=Array.isArray(n)&&n.length>0,r=Lf(o);return!!(a&&r&&!i)}function Al(e,t,n=[]){let s=!!(t&Xe.lsfDefaultRipple),a=!!(t&Xe.lsfRequireAuth),o=!!(t&Xe.lsfGlobalFreeze),i=!!(t&Xe.lsfNoFreeze),r=n.filter(({tx:c})=>c.TransactionType==="TrustSet").length,l=n.filter(({tx:c})=>{var d;return c.TransactionType==="Payment"&&typeof c.Amount=="object"&&((d=c.Amount)==null?void 0:d.currency)}).length;return s||a||o||i||r>=3||l>=5}function Mf(e,t,n,s){let a=[],o=100,i=!!(t&Xe.lsfDisableMaster),r=!!e.RegularKey,l=n.length>0,c=Pl(e,t,n,s),d=Al(e,t,s);if(i&&!r&&!l?(a.push({sev:"critical",label:"Master key disabled \u2014 no fallback",detail:"Account cannot sign transactions. Funds are inaccessible."}),o-=40):c?(a.push({sev:"info",label:"Intentional blackhole pattern detected",detail:`Master key is disabled and regular key ${e.RegularKey} is a known blackhole address. This usually indicates the account was intentionally locked, not compromised.`}),d&&a.push({sev:"warn",label:"Blackholed issuer caution",detail:"This account appears issuer-like and intentionally blackholed. Sending issued tokens back here may make them unrecoverable or effectively burn them."})):i&&a.push({sev:"info",label:"Master key disabled",detail:"Signing via regular key or multisig only."}),r){let p=s.find(({tx:f})=>f.TransactionType==="SetRegularKey"),m=p&&Date.now()/1e3-Pt(p.tx)<86400*30;c?a.push({sev:"info",label:"Regular key points to blackhole address",detail:e.RegularKey}):m?(a.push({sev:"warn",label:"Regular key set recently",detail:`Key: ${e.RegularKey} \u2014 changed within 30 days. Verify you intended this.`}),o-=15):a.push({sev:"info",label:"Regular key active",detail:e.RegularKey})}n.forEach(p=>{let m=p.SignerEntries||[],f=p.SignerQuorum||1;a.push({sev:"info",label:`Multisig: ${m.length} signers, quorum ${f}`,detail:m.map(v=>{var h;return U(((h=v.SignerEntry)==null?void 0:h.Account)||"")}).join(", ")})}),t&Xe.lsfGlobalFreeze&&(a.push({sev:"warn",label:"Global Freeze active",detail:"This issuer has frozen all token balances."}),o-=10),t&Xe.lsfDepositAuth&&a.push({sev:"ok",label:"Deposit Authorization enabled",detail:"Only pre-authorized senders can deposit."}),t&Xe.lsfDefaultRipple&&a.push({sev:"info",label:"Default Ripple enabled",detail:"Balances can ripple through this account (issuer behaviour)."});let u=s.filter(({tx:p})=>p.TransactionType==="AccountDelete");return u.length&&(a.push({sev:"warn",label:`${u.length} AccountDelete attempt(s)`,detail:"Account deletion was attempted."}),o-=5),{findings:a,score:Math.max(0,o)}}function Pf(e,t,n,s,a,o){let i=[],r="low",l=!!(t&Xe.lsfDisableMaster),c=Pl(e,t,n,s),d=Al(e,t,s);c?(i.push({sev:"info",label:"Intentional blackhole detected",detail:`Master key is disabled and regular key ${e.RegularKey} is a known blackhole address. This is typical for a permanently locked issuer/account, not a classic drain setup.`}),d&&i.push({sev:"warn",label:"Caution: sending assets back may burn them",detail:"Because this account appears to be an intentionally blackholed issuer, sending issued tokens back to it may strand or effectively burn those tokens."})):l&&e.RegularKey&&(i.push({sev:"critical",label:"Classic drain setup detected",detail:`Master key disabled. Regular key ${e.RegularKey} controls the account. If this key was set by an attacker, funds are at risk.`}),r="critical");let u=s.filter(({tx:f})=>f.TransactionType==="SetRegularKey"&&f.Account!==e.Account);!c&&u.length&&(i.push({sev:"critical",label:"Regular key set by external account",detail:`${u.length} key change(s) where sender \u2260 account owner. This is unusual.`}),r="critical");let p=s.filter(({tx:f})=>["SetRegularKey","SignerListSet"].includes(f.TransactionType));if(!c&&p.length>0){let f=Pt(p[0].tx),v=s.filter(({tx:h})=>{if(h.TransactionType!=="Payment"||h.Account!==e.Account)return!1;let w=Pt(h);return w>f&&w<f+3600*48});if(v.length>0){let h=v.reduce((w,{tx:k})=>{let b=k.Amount;return typeof b=="string"?w+Number(b)/1e6:w},0);h>10&&(i.push({sev:"critical",label:`${D(h,2)} XRP sent within 48h of auth change`,detail:`${v.length} payment(s) shortly after key/signer modification. Pattern matches drain attack.`}),r="critical")}}if(a.length){let f=a.reduce((v,h)=>v+Number(h.Amount||0)/1e6,0);i.push({sev:"warn",label:`${a.length} open payment channel(s) \u2014 ${D(f,2)} XRP locked`,detail:`Destination(s): ${a.map(v=>U(v.Destination)).join(", ")}`}),r==="low"&&(r="medium")}if(o.length){let f=o.reduce((v,h)=>v+Number(h.Amount||0)/1e6,0);i.push({sev:"info",label:`${o.length} open escrow(s) \u2014 ${D(f,2)} XRP escrowed`,detail:`Escrow(s): ${o.map(v=>v.Destination?U(v.Destination):"self-escrow").join(", ")}`})}let m=s.filter(({tx:f})=>f.TransactionType==="DepositPreauth"&&f.Authorize);return m.length>5&&(i.push({sev:"warn",label:`${m.length} DepositPreauth grants issued`,detail:"Account pre-authorized many senders. Review if all are trusted."}),r==="low"&&(r="medium")),i.length===0&&i.push({sev:"ok",label:"No drain patterns detected",detail:"Auth structure looks intact."}),{signals:i,riskLevel:r}}function Af(e,t,n){let s=[],a=new Map(e.map(m=>[m.NFTokenID,m])),i=t.filter(({tx:m})=>m.TransactionType==="NFTokenCreateOffer"&&m.Account===n).filter(({tx:m})=>{let f=m.Amount;return f?typeof f=="string"?Number(f)<1e6:!1:!0});i.length&&s.push({sev:"critical",label:`${i.length} NFT offer(s) created for \u22641 XRP`,detail:"You created sell offers at near-zero price. This is a common NFT drain vector \u2014 attackers trick victims into listing their NFTs for free."});let r=t.filter(({tx:m})=>m.TransactionType==="NFTokenAcceptOffer"&&m.Account===n);r.length&&s.push({sev:"warn",label:`${r.length} NFT offer(s) accepted`,detail:"Review these transactions to confirm they were intentional sales/purchases."});let l=t.filter(({tx:m})=>m.TransactionType==="NFTokenBurn"&&m.Account===n);l.length&&s.push({sev:"warn",label:`${l.length} NFT(s) burned`,detail:"Burned NFTs cannot be recovered. Confirm these were intentional."});let c=t.filter(({tx:m})=>m.TransactionType==="NFTokenMint"&&m.Account===n),d=t.filter(({tx:m})=>m.TransactionType==="NFTokenCreateOffer"||m.TransactionType==="NFTokenAcceptOffer");c.length>0&&d.length>0&&s.push({sev:"info",label:`${c.length} NFT(s) minted \xB7 ${d.length} transfer event(s)`,detail:"This account has minting activity."});let u=e.filter(m=>m.TransferFee&&m.TransferFee>0);if(u.length){let m=u.reduce((f,v)=>f+v.TransferFee,0)/u.length;s.push({sev:"info",label:`${u.length} NFT(s) carry transfer fees (avg ${(m/1e3).toFixed(1)}%)`,detail:"These NFTs pay royalties on each transfer."})}let p=e.filter(m=>!m.URI);return p.length>2&&s.push({sev:"warn",label:`${p.length} NFT(s) have no URI / metadata`,detail:"NFTs without a URI may be spam or placeholder tokens used in scams."}),s.length===0&&e.length===0?s.push({sev:"ok",label:"No NFT activity detected",detail:"This account holds no NFTs."}):s.length===0&&s.push({sev:"ok",label:`${e.length} NFT(s) held \u2014 no risk signals`,detail:"NFT posture looks normal."}),{flags:s,nftCount:e.length,mintCount:c.length}}function Ef(e,t,n){let s=[],a=0,o=e.filter(({tx:b})=>b.TransactionType==="OfferCreate"),i=e.filter(({tx:b})=>b.TransactionType==="OfferCancel"),r=o.filter(({meta:b})=>{var x,S;return(S=(x=b==null?void 0:b.AffectedNodes)==null?void 0:x.some)==null?void 0:S.call(x,T=>{var $;return(($=T.DeletedNode)==null?void 0:$.LedgerEntryType)==="Offer"})}),l=e.filter(({tx:b})=>b.TransactionType==="Payment"),c=o.length>0?i.length/o.length:0;o.length>=Gn&&c>$l&&(s.push({sev:"warn",label:`High cancel ratio: ${(c*100).toFixed(1)}%`,detail:`${i.length} cancels vs ${o.length} creates. Threshold: ${($l*100).toFixed(0)}%. May indicate layering / spoofing.`}),a+=25);let d=new Set(l.filter(({tx:b})=>b.Account===t&&b.Destination).map(({tx:b})=>b.Destination)),u=new Set(l.filter(({tx:b})=>b.Destination===t&&b.Account).map(({tx:b})=>b.Account)),p=[...d].filter(b=>u.has(b));if(p.length>0&&l.length>=Gn){let b=p.length/d.size;b>hf&&(s.push({sev:"warn",label:`${p.length} round-trip counterpart(s) detected`,detail:`${(b*100).toFixed(1)}% of payment recipients also sent back to this account. Possible wash-trade cycle.`}),a+=20)}let m=new Map;o.forEach(({tx:b})=>{if(!b.TakerPays||!b.TakerGets)return;let x=T=>typeof T=="string"?"XRP":`${T.currency}.${U(T.issuer||"")}`,S=[x(b.TakerPays),x(b.TakerGets)].sort().join("\u2194");m.set(S,(m.get(S)||0)+1)});let f=[...m.entries()].sort((b,x)=>x[1]-b[1])[0];if(f&&o.length>=Gn){let b=f[1]/o.length;b>.7&&(s.push({sev:"warn",label:`${(b*100).toFixed(0)}% of offers on single pair: ${f[0]}`,detail:`${f[1]} of ${o.length} offers on one pair. High concentration is a wash trading signal.`}),a+=20)}let v=o.length>0?r.length/o.length:0;if(o.length>=Gn&&v<.05&&(s.push({sev:"warn",label:`Very low fill rate: ${(v*100).toFixed(1)}%`,detail:`Only ${r.length} of ${o.length} offers filled. Placing orders never intended to execute.`}),a+=15),o.length>=5){let b=o.map(({tx:S})=>Pt(S)).sort(),x=1;for(let S=0;S<b.length;S++){let T=1;for(let $=S+1;$<b.length&&b[$]-b[S]<=30;$++)T++;x=Math.max(x,T)}x>=8&&(s.push({sev:"warn",label:`Burst activity: ${x} offers within 30 seconds`,detail:"Rapid automated trading pattern detected."}),a+=10)}let h=l.filter(({tx:b})=>b.Account===t&&b.Destination===t);if(h.length>0&&(s.push({sev:"critical",label:`${h.length} self-trade(s): sender = receiver`,detail:"Payments where origin and destination are the same address. Classic wash-trading indicator \u2014 creates artificial volume with zero economic transfer."}),a+=30),o.length>=10){let b=o.map(({tx:P})=>{let M=P.TakerGets;return typeof M=="string"?Number(M)/1e6:null}).filter(P=>P!=null),x=b.sort((P,M)=>M-P)[Math.floor(b.length*.05)]||0,S=o.filter(({tx:P})=>{let M=P.TakerGets;return typeof M=="string"&&Number(M)/1e6>=x}),T=S.filter(({meta:P})=>{var M,N;return!((N=(M=P==null?void 0:P.AffectedNodes)==null?void 0:M.some)!=null&&N.call(M,_=>{var X;return((X=_.DeletedNode)==null?void 0:X.LedgerEntryType)==="Offer"}))}),$=S.length>=5?T.length/S.length:0;$>=.95?(s.push({sev:"critical",label:`Spoofing pattern: ${($*100).toFixed(0)}% of large orders cancelled`,detail:`${T.length} of ${S.length} top-5% size orders were cancelled without execution. \u226595% cancel rate on large orders strongly implies fake order book depth (spoofing).`}),a+=30):$>=.8&&(s.push({sev:"warn",label:`Elevated large-order cancel rate: ${($*100).toFixed(0)}%`,detail:`${T.length}/${S.length} large orders cancelled. Watch for spoofing behaviour.`}),a+=15)}if(o.length>=Gn){let b=o.map(({tx:x})=>{let S=x.TakerGets;return typeof S=="string"?Number(S)/1e6:S!=null&&S.value?Number(S.value):null}).filter(x=>x!=null&&x>0);if(b.length>=Gn){let x=b.reduce(($,P)=>$+P,0)/b.length,S=Math.sqrt(b.reduce(($,P)=>$+(P-x)**2,0)/b.length),T=x>0?S/x:null;T!==null&&T<.05?(s.push({sev:"critical",label:`Robotic trade uniformity (CV ${T.toFixed(3)})`,detail:`${(T*100).toFixed(1)}% coefficient of variation across ${b.length} offer sizes. Near-identical sizes indicate bot-generated fake volume (natural markets show CV \u2265 0.5).`}),a+=25):T!==null&&T<.2&&(s.push({sev:"warn",label:`Unusually uniform trade sizes (CV ${T.toFixed(3)})`,detail:`Only ${(T*100).toFixed(1)}% variation in offer sizes \u2014 suspiciously low for organic activity.`}),a+=10)}}let w=[...o,...l].map(({tx:b})=>{let x=b.TakerGets||b.Amount;return typeof x=="string"?Number(x)/1e6:x!=null&&x.value?Number(x.value):null}).filter(b=>b!=null&&b>0&&Number.isFinite(b));if(w.length>=10){let b=[100,1e3,1e4,1e5],x=w.filter(T=>b.some($=>Math.abs(T%$)<1e-6&&T/$>=1)).length,S=x/w.length;S>.45&&(s.push({sev:"warn",label:`Round-number bias: ${(S*100).toFixed(0)}% of amounts at exact multiples`,detail:`${x}/${w.length} trade / payment amounts are exact multiples of 100, 1,000, or 10,000. Statistical excess of round numbers is a signature of bot-generated activity.`}),a+=12)}if(o.length>=5){let b=o.map(({tx:S})=>Pt(S)).sort((S,T)=>S-T),x=0;for(let S=0;S<b.length;S++){let T=1;for(let $=S+1;$<b.length&&b[$]-b[S]<=3600;$++)T++;T>x&&(x=T)}if(x>100)s.push({sev:"critical",label:`Hourly burst: ${x} offers within 60 minutes`,detail:">100 OfferCreate txs in a single hour is a strong bot-pump indicator, especially in typically illiquid token markets."}),a+=20;else if(x>=8){let S=b,T=1;for(let $=0;$<S.length;$++){let P=1;for(let M=$+1;M<S.length&&S[M]-S[$]<=30;M++)P++;P>T&&(T=P)}T>=8&&(s.push({sev:"warn",label:`Rapid burst: ${T} offers within 30 seconds`,detail:"Automated trading pattern \u2014 bursts at this speed exceed human capability."}),a+=10)}}let k=a===0?"clean":a<25?"low-risk":a<50?"suspicious":"high-risk";return s.length===0&&s.push({sev:"ok",label:"No wash trading signals",detail:`${o.length} offers \xB7 ${i.length} cancels \xB7 ${h.length} self-trades \u2014 patterns look normal.`}),{signals:s,score:a,verdict:k,stats:{creates:o.length,cancels:i.length,fills:r.length,payments:l.length,roundTrip:p.length,selfTrades:h.length}}}function Nf(e){let t=[];for(let{tx:c}of e){let d=[c.Amount,c.TakerGets,c.TakerPays,c.SendMax,c.DeliverMin];for(let u of d){let p=typeof u=="string"?Number(u)/1e6:u!=null&&u.value?Number(u.value):null;p!=null&&p>0&&Number.isFinite(p)&&t.push(p)}}if(t.length<50)return{signals:[{sev:"info",label:"Insufficient data for Benford's Law",detail:`Need \u226550 monetary amounts, found ${t.length}.`}],chiSq:null,verdict:"insufficient",digitBreakdown:[],sampleSize:t.length};let n=[0,.301,.176,.125,.097,.079,.067,.058,.051,.046],s=new Array(10).fill(0);for(let c of t){let d=c.toFixed(6).replace(/^0+\.?0*/,""),u=parseInt(d[0],10);u>=1&&u<=9&&s[u]++}let a=t.length,o=0,i=[];for(let c=1;c<=9;c++){let d=s[c]/a,u=n[c];o+=a*Math.pow(d-u,2)/u,i.push({digit:c,obs:(d*100).toFixed(1),exp:(u*100).toFixed(1),delta:((d-u)*100).toFixed(1)})}let r=[],l;return o>20.09?(l="high-deviation",r.push({sev:"warn",label:`Benford's Law: significant deviation (\u03C7\xB2=${o.toFixed(1)})`,detail:`First-digit distribution deviates significantly from natural patterns (p<0.01, n=${a}). This is a statistical signature of fabricated or algorithmically generated transaction amounts.`})):o>15.51?(l="moderate-deviation",r.push({sev:"info",label:`Benford's Law: moderate deviation (\u03C7\xB2=${o.toFixed(1)})`,detail:`Some deviation from expected natural distribution (p<0.05, n=${a}). Worth monitoring alongside other signals.`})):(l="normal",r.push({sev:"ok",label:`Benford's Law: normal distribution (\u03C7\xB2=${o.toFixed(1)})`,detail:`First-digit distribution is consistent with organic transaction patterns (n=${a}).`})),{signals:r,chiSq:o,verdict:l,digitBreakdown:i,sampleSize:a}}function _f(e,t){let s=[],a=[];for(let{tx:h}of e){let w=[h.Amount,h.TakerGets,h.TakerPays];for(let k of w){let b=typeof k=="string"?Number(k)/1e6:k!=null&&k.value?Number(k.value):null;b&&b>0&&Number.isFinite(b)&&a.push(b)}}let o=a.length>=30?(()=>{let h=new Array(12).fill(0);for(let w of a){let k=Math.min(11,Math.max(0,Math.floor(Math.log10(w+1)*2)));h[k]++}return bs(h)})():null,i={};for(let{tx:h}of e){let w=h.Account===t?h.Destination:h.Account;w&&w!==t&&(i[w]=(i[w]||0)+1)}let r=Object.values(i),l=r.length>=3?bs(r):null,c=new Array(24).fill(0),d=!1;for(let{tx:h}of e)if(h.date){let k=new Date((h.date+946684800)*1e3).getUTCHours();c[k]++,d=!0}let u=d&&e.length>=30?bs(c):null,p={};for(let{tx:h}of e)p[h.TransactionType]=(p[h.TransactionType]||0)+1;let m=bs(Object.values(p)),f="normal",v=0;if(o!==null&&(o<1.5?(f="low-entropy",v+=18,s.push({sev:"warn",label:`Amount entropy critically low (H=${o.toFixed(2)} bits)`,detail:"Transaction amounts are highly repetitive. A bot or scripted actor tends to reuse the same values. Organic wallets show entropy \u22652.4 bits across amount magnitudes."})):o<2.2?(v+=8,s.push({sev:"info",label:`Amount entropy below natural range (H=${o.toFixed(2)} bits)`,detail:"Some amount repetition detected. Could indicate automated activity mixed with organic transactions."})):o>4.5?(v+=10,s.push({sev:"info",label:`Amount entropy abnormally high (H=${o.toFixed(2)} bits)`,detail:"Transaction amounts are maximally varied \u2014 more than organic activity typically shows. This can indicate amounts were artificially randomized to evade Benford detection."})):s.push({sev:"ok",label:`Amount entropy normal (H=${o.toFixed(2)} bits)`,detail:"Transaction amount diversity is consistent with organic financial activity."})),l!==null&&(l<1&&r.length<4?(v+=14,s.push({sev:"warn",label:`Counterparty entropy very low (H=${l.toFixed(2)} bits)`,detail:"This wallet transacts with very few unique addresses and with high repetition \u2014 a structural signature of round-trip wash trading rings."})):l<2?(v+=5,s.push({sev:"info",label:`Counterparty entropy low (H=${l.toFixed(2)} bits)`,detail:"Most interactions are concentrated among a small set of counterparties."})):s.push({sev:"ok",label:`Counterparty diversity healthy (H=${l.toFixed(2)} bits)`,detail:"Counterparty distribution reflects diverse interaction patterns."})),u!==null){let h=Math.log2(24),w=u/h;w<.45?(v+=10,s.push({sev:"warn",label:`Time-of-day entropy low (H=${u.toFixed(2)} bits, ${(w*100).toFixed(0)}% of max)`,detail:"Transactions cluster heavily in a few hours of the day. Bots typically run at fixed UTC hours; organic users spread activity across the day."})):s.push({sev:"ok",label:`Time-of-day distribution natural (H=${u.toFixed(2)} bits)`,detail:"Transaction timing is distributed across hours in a pattern consistent with human activity."})}return s.length||s.push({sev:"info",label:"Insufficient data for entropy analysis",detail:`Need \u226530 transactions. Found ${e.length}.`}),v>=18?f="anomalous":v>=8&&(f="elevated"),{signals:s,verdict:f,riskPenalty:v,amountEntropy:o,counterpartyEntropy:l,timeEntropy:u,typeEntropy:m,uniqueCounterparties:r.length,sampleSize:e.length}}function bs(e){let t=e.reduce((n,s)=>n+s,0);return t?-e.reduce((n,s)=>{if(!s)return n;let a=s/t;return n+a*Math.log2(a)},0):0}function Rf(e,t){let s=[],a={};for(let{tx:M}of e){let N=M.Account===t?M.Destination:M.Account;N&&N!==t&&(a[N]=(a[N]||0)+1)}let o=Object.values(a).sort((M,N)=>N-M);if(o.length<8)return{signals:[{sev:"info",label:`Insufficient counterparties for Zipf's Law (need \u22658, found ${o.length})`,detail:"Zipf analysis becomes meaningful with a broader counterparty network."}],verdict:"insufficient",zipfExponent:null,riskPenalty:0,freqTable:[],uniqueCounterparties:o.length};let i=o.length,r=0,l=0,c=0,d=0,u=o.map((M,N)=>({rank:N+1,freq:M,lx:Math.log(N+1),ly:Math.log(M)}));for(let{lx:M,ly:N}of u)r+=M,l+=N,c+=M*N,d+=M*M;let p=i*d-r*r,m=p!==0?(i*c-r*l)/p:null,f=m!==null?Math.abs(m):null,v=l/i,h=0,w=0,k=(l-m*r)/i;for(let{lx:M,ly:N}of u)h+=Math.pow(N-v,2),w+=Math.pow(N-(m*M+k),2);let b=h>0?1-w/h:0,x="normal",S=0;f!==null&&(b<.55?(S+=12,s.push({sev:"warn",label:`Counterparty distribution doesn't follow Zipf's Law (R\xB2=${b.toFixed(2)})`,detail:`Natural networks follow a power-law rank-frequency relationship. This wallet's counterparty network has poor Zipf fit (R\xB2=${b.toFixed(2)}), suggesting artificial or script-driven interaction structure.`}),x="anomalous"):f<.4?(S+=15,s.push({sev:"warn",label:`Zipf exponent too flat (s=${f.toFixed(2)}, expected 0.8\u20131.3)`,detail:"A very flat Zipf exponent means counterparties are used with surprisingly equal frequency. In organic networks, you transact far more often with a few key addresses. Flat distribution is consistent with round-trip wash trading rings."}),x="anomalous"):f>2.2?(S+=10,s.push({sev:"warn",label:`Zipf exponent hyper-concentrated (s=${f.toFixed(2)}, expected 0.8\u20131.3)`,detail:"Extreme concentration on one or two counterparties with steep dropoff. While not unusual for simple wallets, combined with other signals this suggests coordinated narrow-ring activity."}),x="elevated"):s.push({sev:"ok",label:`Counterparty network follows Zipf's Law (s=${f.toFixed(2)}, R\xB2=${b.toFixed(2)})`,detail:"The rank-frequency distribution of counterparties follows the expected natural power-law pattern. This is consistent with organic wallet activity."}));let T={};for(let{tx:M}of e){let N=typeof M.Amount=="string"?Math.round(Number(M.Amount)/1e4)*10:null;N&&N>0&&(T[N]=(T[N]||0)+1)}let $=Object.values(T).sort((M,N)=>N-M),P=$.length?$[0]/$.reduce((M,N)=>M+N,0):0;return P>.45&&(S+=8,s.push({sev:"warn",label:`Single amount dominates ${(P*100).toFixed(0)}% of transactions`,detail:"One transaction amount value accounts for nearly half of all payments. Round-number dominance is a hallmark of scripted or wash-trading activity."})),s.length||s.push({sev:"info",label:"Zipf analysis: no anomalies detected",detail:"Counterparty distribution consistent with natural activity."}),{signals:s,verdict:x,riskPenalty:S,zipfExponent:f,rSquared:b,freqTable:o.slice(0,12),uniqueCounterparties:o.length}}function Df(e){let n=[];if(e.length<20)return{signals:[{sev:"info",label:`Insufficient transactions for time series analysis (need \u226520, found ${e.length})`,detail:"Time series analysis requires a longer transaction history."}],verdict:"insufficient",riskPenalty:0,intervalCV:null,autocorrelation:null,burstScore:null,periodicityScore:null};let a=e.filter(({tx:b})=>b.date!=null).map(({tx:b})=>(b.date+946684800)*1e3).sort((b,x)=>b-x);if(a.length<20)return{signals:[{sev:"info",label:"No timestamp data available",detail:"Time series requires date-stamped transactions."}],verdict:"insufficient",riskPenalty:0,intervalCV:null,autocorrelation:null,burstScore:null,periodicityScore:null};let o=[];for(let b=1;b<a.length;b++){let x=(a[b]-a[b-1])/1e3;x>0&&x<86400*30&&o.push(x)}let i=null;if(o.length>=5){let b=o.reduce((S,T)=>S+T,0)/o.length,x=Math.sqrt(o.reduce((S,T)=>S+Math.pow(T-b,2),0)/o.length);i=b>0?x/b:null}let r={};for(let b of a){let x=new Date(b).toISOString().slice(0,10);r[x]=(r[x]||0)+1}let l=Object.values(r),c=0;if(l.length>=4){let b=l.reduce((T,$)=>T+$,0)/l.length,x=Math.sqrt(l.reduce((T,$)=>T+Math.pow($-b,2),0)/l.length),S=Math.max(...l);c=x>0?(S-b)/x:0}let d=null;if(l.length>=6){let b=l.reduce((T,$)=>T+$,0)/l.length,x=l.map(T=>T-b),S=x.reduce((T,$)=>T+$*$,0);S>0&&(d=x.slice(0,-1).reduce(($,P,M)=>$+P*x[M+1],0)/S)}let u=new Array(7).fill(0);for(let b of a)u[new Date(b).getUTCDay()]++;let p=bs(u),m=Math.log2(7),f=0;if(o.length>=10){let b=[...o].sort((T,$)=>T-$),x=b[Math.floor(b.length/2)];f=o.filter(T=>Math.abs(T-x)/x<.2).length/o.length}let v="normal",h=0;i!==null&&(i<.25?(h+=20,v="bot-pattern",n.push({sev:"warn",label:`Transaction intervals mechanically regular (CV=${i.toFixed(2)})`,detail:"The time gaps between transactions are too regular for human behavior (CV < 0.25). Organic wallets show irregular timing (CV 0.8\u20133.0). This pattern is a strong bot signature."})):i<.5?(h+=8,n.push({sev:"info",label:`Transaction timing somewhat regular (CV=${i.toFixed(2)})`,detail:"Interval regularity is below typical human variance. Could indicate scheduled automation."})):n.push({sev:"ok",label:`Transaction timing is irregular (CV=${i.toFixed(2)})`,detail:"Inter-transaction intervals show natural human-like variance."})),f>.55&&(h+=12,n.push({sev:"warn",label:`Strong periodicity detected (${(f*100).toFixed(0)}% of intervals near median)`,detail:"More than half of transaction intervals cluster around the same duration. This mechanical repetition is consistent with an automated script executing on a fixed schedule."})),c>3.5&&n.push({sev:"info",label:`Activity burst detected (peak day z-score=${c.toFixed(1)})`,detail:"One or more days had extreme transaction volume compared to baseline. Could indicate a coordinated pump event or account recovery sweep."}),d!==null&&d>.6&&(h+=6,n.push({sev:"info",label:`High day-to-day volume autocorrelation (\u03C1=${d.toFixed(2)})`,detail:"Transaction volume is strongly self-correlated \u2014 today's activity predicts tomorrow's. This is consistent with an automated routine that maintains a constant pace."}));let w=p/m;w<.7&&a.length>30&&(h+=6,n.push({sev:"info",label:`Day-of-week distribution concentrated (${(w*100).toFixed(0)}% of max entropy)`,detail:"Transactions cluster heavily on specific days. Automated systems often run every day (maximally flat) or skip weekends \u2014 both deviate from natural human patterns."})),n.length||n.push({sev:"ok",label:"No temporal anomalies detected",detail:"Transaction timing patterns are consistent with organic human activity."}),h>=20?v="bot-pattern":h>=8&&(v="elevated");let k=a.length>=2?Math.round((a[a.length-1]-a[0])/864e5):null;return{signals:n,verdict:v,riskPenalty:h,intervalCV:i,autocorrelation:d,burstScore:c,periodicityScore:f,dowEntropy:p,dowBins:u,dailyVolume:Object.entries(r).slice(-30),activeSpanDays:k,totalTimestamped:a.length}}function If(e,t){let s=[];if(e.length<20)return{signals:[{sev:"info",label:`Insufficient data for Granger causality analysis (need \u226520, found ${e.length})`,detail:"Granger causality requires enough temporal observations to test lead-lag relationships."}],verdict:"insufficient",riskPenalty:0,offerCancelCausality:null,inflowOutflowCausality:null};let o=12*3600*1e3,i=R=>R.date?Math.floor((R.date+946684800)*1e3/o):null,r={},l=R=>{r[R]||(r[R]={offerCreate:0,offerCancel:0,inflow:0,outflow:0,nftList:0,nftAccept:0})};for(let{tx:R,meta:F}of e){let W=i(R);if(W===null)continue;l(W);let E=r[W],z=R.TransactionType;z==="OfferCreate"?E.offerCreate++:z==="OfferCancel"&&E.offerCancel++,z==="NFTokenCreateOffer"?E.nftList++:z==="NFTokenAcceptOffer"&&E.nftAccept++;let Q=(F==null?void 0:F.delivered_amount)||R.Amount,ie=typeof Q=="string"?Number(Q)/1e6:0;ie>0&&(R.Destination===t?E.inflow+=ie:R.Account===t&&(E.outflow+=ie))}let c=Object.keys(r).map(Number).sort((R,F)=>R-F);if(c.length<6)return{signals:[{sev:"info",label:"Insufficient temporal windows for Granger test",detail:"Need activity spread across multiple time windows."}],verdict:"insufficient",riskPenalty:0,offerCancelCausality:null,inflowOutflowCausality:null};let d=R=>c.map(F=>r[F][R]||0),u=(R,F,W=4)=>{let E=R.length,z=R.reduce((fe,K)=>fe+K,0)/E,Q=F.reduce((fe,K)=>fe+K,0)/E,ie=R.map(fe=>fe-z),ce=F.map(fe=>fe-Q),de=Math.sqrt(ie.reduce((fe,K)=>fe+K*K,0)/E),se=Math.sqrt(ce.reduce((fe,K)=>fe+K*K,0)/E);return!de||!se?Array(W+1).fill(0):Array.from({length:W+1},(fe,K)=>{let xe=0,B=0;for(let J=0;J+K<E;J++)xe+=ie[J]*ce[J+K],B++;return B>0?xe/(B*de*se):0})},p="normal",m=0,f=d("offerCreate"),v=d("offerCancel"),h=u(f,v),w=h.indexOf(Math.max(...h)),k=Math.max(...h),b={ccf:h,maxCorr:k,maxLag:w};k>.55&&w<=2?(m+=18,p="causal-signal",s.push({sev:"warn",label:`OfferCreate \u2192 OfferCancel Granger signal (\u03C1=${k.toFixed(2)}, lag=${w} window${w===1?"":"s"})`,detail:`Offer creation strongly predicts subsequent cancellation at lag ${w} (${w*12}h). This causal pattern is the mechanical signature of wash trading: create offers to inflate visible book activity, then cancel them. A leading correlation this strong at such short lag is unlikely in organic market-making.`})):k>.35?(m+=6,s.push({sev:"info",label:`Mild offer-cancel lead relationship (\u03C1=${k.toFixed(2)}, lag=${w})`,detail:"Some temporal link between creating and cancelling offers. Worth monitoring alongside other signals."})):s.push({sev:"ok",label:"No Granger signal between offer creation and cancellation",detail:"Offer creation and cancellation timing appear independent \u2014 no evidence of systematic cancel-to-create cycles."});let x=d("inflow"),S=d("outflow"),T=u(x,S),$=T.indexOf(Math.max(...T)),P=Math.max(...T),M={ccf:T,maxCorr:P,maxLag:$};P>.65&&$===0?(m+=12,s.push({sev:"warn",label:`Inflow and outflow move in perfect lockstep (\u03C1=${P.toFixed(2)} at lag 0)`,detail:"Funds entering and leaving the wallet in the same time window with high correlation at zero lag is consistent with pass-through or round-trip self-trading: money comes in and immediately goes back out."})):P>.55&&$<=1?(m+=8,s.push({sev:"info",label:`Inflow leads outflow (\u03C1=${P.toFixed(2)}, lag=${$})`,detail:"Incoming funds reliably precede outgoing funds at short lag. Could indicate legitimate management, but in conjunction with other signals suggests fund cycling."})):s.push({sev:"ok",label:"No suspicious inflow\u2192outflow Granger pattern",detail:"Inflow and outflow timing are not predictably linked, consistent with independent organic transaction activity."});let N=d("nftList"),_=d("nftAccept"),X=N.reduce((R,F)=>R+F,0),I=_.reduce((R,F)=>R+F,0);if(X>3&&I>3){let R=u(N,_),F=Math.max(...R),W=R.indexOf(F);F>.6&&W<=1&&(m+=8,s.push({sev:"warn",label:`NFT listing causes rapid acceptance (\u03C1=${F.toFixed(2)}, lag=${W})`,detail:"NFT sell offer creation is closely followed by acceptance. Combined with the NFT trap detection module, this timing pattern can indicate coordinated offer traps with a controlled accepting address."}))}return s.some(R=>R.sev==="warn"||R.sev==="critical")||s.length||s.push({sev:"ok",label:"No Granger causality anomalies detected",detail:"Temporal relationships between transaction types show no suspicious lead-lag patterns."}),m>=18?p="causal-signal":m>=8&&(p="elevated"),{signals:s,verdict:p,riskPenalty:m,offerCancelCausality:b,inflowOutflowCausality:M,windowCount:c.length}}function Ff(e,t){let n=new Map;for(let{tx:o}of e){let i=[o.TakerGets,o.Amount];for(let r of i){if(!r||typeof r!="object")continue;let l=r.currency,c=Number(r.value||0),d=o.Account;if(!l||!d||c<=0||!Number.isFinite(c))continue;n.has(l)||n.set(l,{senders:new Set,vol:0,trades:0});let u=n.get(l);u.senders.add(d),u.vol+=c,u.trades++}}let s=[],a=[];for(let[o,i]of n.entries()){if(i.trades<8)continue;let r=i.senders.size;a.push({currency:o,uniqueActors:r,vol:i.vol,trades:i.trades}),r<5?s.push({sev:"critical",label:`${o}: ${r} wallet(s) driving all volume`,detail:`${i.trades} trades totalling ${i.vol.toFixed(2)} ${o} from only ${r} address(es). Fewer than 5 unique actors generating most volume is a wash trading red flag.`}):r<10&&s.push({sev:"warn",label:`${o}: low actor diversity (${r} wallets, ${i.trades} trades)`,detail:`Volume concentrated among only ${r} addresses. Organic markets typically have broader participation.`})}return a.length?s.length||s.push({sev:"ok",label:"Volume concentration normal",detail:`${a.length} token(s) analysed \u2014 all have \u226510 unique trading participants.`}):s.push({sev:"info",label:"No IOU/token volume data",detail:"No token-denominated transactions found in history (XRP-only activity)."}),{signals:s,concentrations:a}}function Bf(e,t,n,s){let a=[],o=!!(n&Xe.lsfDefaultRipple)||t.some(p=>p.account===e.Account),i=t.filter(p=>Number(p.balance)<0),r=i.reduce((p,m)=>p+Math.abs(Number(m.balance)),0);i.length>0&&a.push({sev:"info",label:`Token issuer: ${i.length} outstanding currency lines`,detail:`Total outstanding: ${D(r,2)} across ${i.length} holder(s).`});let l=t.filter(p=>p.freeze),c=t.filter(p=>p.freeze_peer);l.length&&a.push({sev:"warn",label:`${l.length} trustline(s) frozen by this account`,detail:"This account has frozen specific trustlines."}),c.length&&a.push({sev:"critical",label:`${c.length} of your trustline(s) frozen by issuer`,detail:`Frozen currencies: ${c.map(p=>p.currency).join(", ")}. You cannot transfer these tokens.`}),n&Xe.lsfGlobalFreeze&&a.push({sev:"critical",label:"Global Freeze \u2014 all token transfers suspended",detail:"No holders can transfer tokens issued by this account."}),n&Xe.lsfNoFreeze&&a.push({sev:"ok",label:"NoFreeze flag set \u2014 issuer cannot freeze balances",detail:"Token holders are protected against future freeze actions."});let d=Number(e.Balance||0)/1e6,u=10+Number(e.OwnerCount||0)*2;return i.length>0&&d<u+1&&a.push({sev:"warn",label:"Issuer balance near reserve \u2014 possible black hole",detail:"Issuer with outstanding tokens has almost no XRP above reserve. Tokens may be stranded."}),a.length===0&&a.push({sev:"ok",label:"No token issuer flags",detail:"This account does not appear to be a token issuer."}),{signals:a,isIssuer:o,obligationCount:i.length}}function Of(e,t,n,s=new Map){var m,f,v;let a=[],o=[],i=e.filter(h=>h.currency&&(h.currency.startsWith("03")||h.currency.length===40)),r=t.filter(({tx:h})=>h.TransactionType==="AMMDeposit"),l=t.filter(({tx:h})=>h.TransactionType==="AMMWithdraw"),c=t.filter(({tx:h})=>h.TransactionType==="AMMCreate"),d=t.filter(({tx:h})=>h.TransactionType==="AMMVote"),u=t.filter(({tx:h})=>h.TransactionType==="AMMBid");if(i.forEach(h=>{let w=Number(h.balance),k=Number(h.limit);o.push({currency:h.currency,issuer:h.account,balance:w,limit:k})}),o.length){a.push({sev:"info",label:`${o.length} LP token position(s)`,detail:`Active liquidity provider in ${o.length} AMM pool(s).`});for(let h of o){let w=s.get(h.currency);if(w){if(h.tvl=w.amount?Number(w.amount)/1e6:null,h.tvl2=(m=w.amount2)!=null&&m.value?Number(w.amount2.value):null,h.feeRate=w.trading_fee!=null?w.trading_fee/1e3:null,h.lpSupply=(f=w.lp_token)!=null&&f.value?Number(w.lp_token.value):null,h.lpSupply&&h.balance){let k=Math.abs(h.balance)/h.lpSupply*100;h.ownerPct=k,k>50&&a.push({sev:"warn",label:`Dominant AMM position: ${k.toFixed(0)}% of pool`,detail:`This account controls ${k.toFixed(0)}% of the LP token supply for pool ${U(h.currency)}. Withdrawing all at once would severely impact pool liquidity and anyone currently trading in it.`})}h.tvl!=null&&a.push({sev:"info",label:`Pool TVL: ${D(h.tvl,2)} XRP${h.tvl2?` + ${D(h.tvl2,2)} tokens`:""} \xB7 Fee: ${((v=h.feeRate)==null?void 0:v.toFixed(2))??"?"}%`,detail:`Actual pool context from amm_info. Your LP position represents ${h.ownerPct!=null?h.ownerPct.toFixed(1)+"% of the pool.":"an unknown share of the pool."}`})}}}return c.length&&a.push({sev:"info",label:`Created ${c.length} AMM pool(s)`,detail:"This account bootstrapped one or more liquidity pools."}),(r.length||l.length)&&a.push({sev:"info",label:`${r.length} deposit(s) \xB7 ${l.length} withdrawal(s)`,detail:"LP activity history."}),d.length&&a.push({sev:"info",label:`${d.length} AMM fee vote(s)`,detail:"This account has voted on AMM trading fee parameters."}),u.length&&a.push({sev:"info",label:`${u.length} continuous auction bid(s)`,detail:"Bid for the AMM auction slot (reduced fee trading window)."}),o.filter(h=>Math.abs(h.balance)>1e3).length&&a.push({sev:"warn",label:"Large LP positions \u2014 impermanent loss risk",detail:"Significant liquidity positions carry exposure to price divergence between pool assets."}),a.length===0&&a.push({sev:"ok",label:"No AMM positions",detail:"This account is not a liquidity provider."}),{signals:a,positions:o,deposits:r.length,withdrawals:l.length}}function Xf(e){let t=[],s=e.filter(({tx:p})=>p.Fee&&Number(p.Fee)>0);if(s.length<10)return{signals:[],verdict:"insufficient",riskPenalty:0,avgFeeMultiplier:null,spikeCount:0,topFeeHashes:[]};let a=s.map(({tx:p})=>Number(p.Fee)/12),o=a.reduce((p,m)=>p+m,0)/a.length,r=s.filter(({tx:p})=>Number(p.Fee)/12>100).length,l=r/s.length,c=0,d="normal",u=[...s].sort((p,m)=>Number(m.tx.Fee)-Number(p.tx.Fee)).slice(0,5).map(({tx:p})=>({hash:p.hash,mult:(Number(p.Fee)/12).toFixed(0),fee:Number(p.Fee)}));return l>.15&&r>=5?(c=10,d="elevated",t.push({sev:"warn",label:`Fee spike pattern: ${r} txs paid >100x base fee (${(l*100).toFixed(0)}% of history)`,detail:`Average fee multiplier: ${o.toFixed(0)}x. In XRPL, bots often pay elevated fees to guarantee same-ledger execution as a counterparty \u2014 a technique used in coordinated wash trading and sandwich attacks. Organic users rarely pay more than 2\u20135x the base fee. Top hashes: ${u.slice(0,3).map(p=>U(p.hash)).join(", ")}.`,hashes:u.map(p=>p.hash)})):o>20?(c=4,t.push({sev:"info",label:`Elevated average fee (${o.toFixed(0)}x base fee)`,detail:"This wallet consistently pays above-average fees. Could indicate priority execution requirements or automated trading."})):t.push({sev:"ok",label:`Fee levels normal (avg ${o.toFixed(1)}x base fee)`,detail:"Transaction fees are within typical organic ranges."}),{signals:t,verdict:d,riskPenalty:c,avgFeeMultiplier:+o.toFixed(2),spikeCount:r,topFeeHashes:u}}function Hf(e,t){let n=[],s=new Map;for(let{tx:r}of e){if(r.TransactionType!=="Payment"||r.Account!==t)continue;let l=r.Destination,c=r.DestinationTag;l&&(s.has(l)||s.set(l,new Set),c!=null&&s.get(l).add(c))}let a=[...s.entries()].filter(([r])=>{let l=Yn(r);return(l==null?void 0:l.type)==="exchange"}),o=0,i=[];for(let[r,l]of s.entries()){let c=Yn(r),d=(c==null?void 0:c.name)||U(r),u=l.size,p=e.filter(({tx:m})=>m.Account===t&&m.Destination===r).length;i.push({dest:r,name:d,uniqueTags:u,txCount:p,tags:[...l].slice(0,10)}),u===1&&p>=5&&(c==null?void 0:c.type)==="exchange"?n.push({sev:"info",label:`${d}: ${p} payments all using tag ${[...l][0]}`,detail:`Single destination tag used across all ${p} payments to ${d}. This is the normal pattern for one person funding their own exchange account.`}):u>10&&(c==null?void 0:c.type)==="exchange"?(o=Math.max(o,8),n.push({sev:"warn",label:`${d}: ${u} different destination tags used`,detail:`${p} payments to ${d} used ${u} different tags \u2014 each tag typically identifies a different customer account. Funding many exchange sub-accounts can indicate either a service (legitimate) or coordinated deposit layering where funds are spread across many exchange wallets to avoid detection.`})):u===0&&p>=2&&(c==null?void 0:c.type)==="exchange"&&n.push({sev:"warn",label:`${d}: ${p} payments with no destination tag`,detail:"Payments to exchange addresses without a destination tag may not be credited. Most exchanges require a tag to identify which customer account receives the funds."})}return n.length===0&&s.size>0?n.push({sev:"ok",label:"Destination tag patterns normal",detail:"Payment routing tags are consistent with regular outbound payments."}):s.size===0&&n.push({sev:"info",label:"No outbound payments to analyse for destination tags",detail:"No outbound Payment transactions found in history."}),{signals:n,riskPenalty:o,tagProfiles:i}}function zf(e,t){var c,d;let n=[],s=e.filter(({tx:u})=>u.TransactionType==="Payment"&&u.Account===t&&(Array.isArray(u.Paths)&&u.Paths.length>0||u.SendMax!=null));if(s.length===0)return{signals:[],riskPenalty:0,roundTripCount:0,deepHopCount:0,selfRoutedCount:0,noData:!0};let a=s.length<5?` (small sample: ${s.length} path payments found \u2014 patterns may not be statistically significant)`:"",o=s.filter(({tx:u})=>{let p=typeof u.Amount=="string",m=typeof u.SendMax=="string";return p&&m}),i=s.filter(({tx:u})=>Array.isArray(u.Paths)?u.Paths.some(p=>Array.isArray(p)&&p.length>=3):!1),r=s.filter(({tx:u})=>u.Destination===t),l=0;return o.length>=1&&(l+=12,n.push({sev:"warn",label:`${o.length} XRP\u2192IOU\u2192XRP round-trip path payments`,detail:`Sending XRP and receiving XRP via intermediate token pairs means the payment routes through the DEX and creates trading volume without changing economic position. ${o.length} occurrences suggests this is deliberate. This is the classic cross-currency wash-trading arb pattern on XRPL. Example hash: ${(d=(c=o[0])==null?void 0:c.tx)!=null&&d.hash?U(o[0].tx.hash):"N/A"}.`,hashes:o.slice(0,5).map(({tx:u})=>u.hash).filter(Boolean)})),i.length>=1&&(l+=6,n.push({sev:"info",label:`${i.length} path payments with \u22653 intermediate hops`,detail:"Deep routing chains (3+ hops) can indicate: legitimate arbitrage, liquidity optimization, or deliberate obfuscation of fund origin. Check each transaction for the intermediate issuers in the path."})),r.length>0&&(l+=15,n.push({sev:"critical",label:`${r.length} path payment(s) where sender = destination`,detail:`Money sent to your own address via a multi-hop path creates DEX trading volume with no net change in balance. This is a direct wash-trading technique: the path through the order book generates artificial volume on every intermediate pair. Hashes: ${r.slice(0,3).map(({tx:u})=>U(u.hash||"")).join(", ")}.`,hashes:r.slice(0,5).map(({tx:u})=>u.hash).filter(Boolean)})),n.length===0&&n.push({sev:"ok",label:`${s.length} path payment(s) \u2014 no suspicious routing patterns${a}`,detail:"No circular routing (XRP\u2192IOU\u2192XRP), self-routing, or unusual deep hop chains detected."}),{signals:n,riskPenalty:l,roundTripCount:o.length,deepHopCount:i.length,selfRoutedCount:r.length}}function Uf(e,t){var u;let n=new Map,s=[];for(let{tx:p,meta:m}of e){if(p.TransactionType!=="Payment"||p.Destination!==t)continue;let f=p.Account;if(!f||f===t)continue;let v=0,h=null,w=(m==null?void 0:m.delivered_amount)||p.Amount;typeof w=="string"?v=Number(w)/1e6:w!=null&&w.value&&(h={value:Number(w.value),currency:yn(w.currency),issuer:w.issuer});let k=Pt(p);s.push({src:f,amtXrp:v,amtToken:h,ts:k,hash:p.hash||"",destTag:p.DestinationTag}),n.has(f)||n.set(f,{addr:f,totalXrp:0,txCount:0,firstSeen:k,lastSeen:k,entity:Yn(f)||null});let b=n.get(f);b.totalXrp+=v,b.txCount++,b.lastSeen=Math.max(b.lastSeen,k),b.firstSeen=Math.min(b.firstSeen,k)}let a=[...n.values()].sort((p,m)=>m.totalXrp-p.totalXrp||m.txCount-p.txCount).slice(0,10),o=a.reduce((p,m)=>p+m.totalXrp,0),i=a.filter(p=>{var m;return((m=p.entity)==null?void 0:m.type)==="exchange"}),r={};for(let p of s){if(p.amtXrp<=0)continue;let m=Math.round(p.amtXrp/10)*10;r[m]=(r[m]||0)+1}let l=Object.entries(r).sort((p,m)=>m[1]-p[1])[0],c=l&&l[1]>=5&&l[1]/s.length>.4,d=[];if(i.length){let p=[...new Set(i.map(m=>m.entity.name))].join(", ");d.push({sev:"info",label:`Funding from ${i.length} known exchange(s): ${p}`,detail:`${D(i.reduce((m,f)=>m+f.totalXrp,0),2)} XRP received from exchange withdrawals \u2014 typical for a personal trading wallet.`})}if(c&&d.push({sev:"warn",label:`Structured inbound pattern: ${l[1]} payments near ~${l[0]} XRP`,detail:`Over 40% of inbound payments cluster around the same amount (~${l[0]} XRP). Structured deposits can indicate layering \u2014 deliberately splitting large amounts into smaller equal transfers to avoid detection.`}),n.size===1&&s.length>=5){let p=a[0];d.push({sev:"info",label:`Single funding source: all ${s.length} inbound payments from one address`,detail:`${((u=p.entity)==null?void 0:u.name)||U(p.addr)} is the sole funding source. This is normal for a personal wallet but notable for a wallet claiming broad community usage.`})}return!d.length&&s.length>0&&d.push({sev:"ok",label:`${s.length} inbound payment(s) from ${n.size} source(s)`,detail:`Total received: ${D(o,2)} XRP. No unusual inbound patterns.`}),s.length===0&&d.push({sev:"info",label:"No inbound payments found in analysed history",detail:"Wallet may be funded via DEX activity or in ledgers outside the analysed range."}),{signals:d,topSources:a,totalIn:o,uniqueSources:n.size,timeline:s.slice(-20).reverse(),exchangeSrcs:i,structuredFlag:!!c}}function Wf(e,t){var l,c;let n=[],s=[],a=[/airdrop/i,/claim.*reward/i,/free.*xrp/i,/verify.*wallet/i,/support.*team/i,/urgent/i,/suspended/i,/confirm.*seed/i,/your.*account.*hold/i,/unlock/i];for(let{tx:d}of e)if((l=d.Memos)!=null&&l.length)for(let u of d.Memos){let p=((c=u.Memo)==null?void 0:c.MemoData)||"";if(!p)continue;let m="";try{m=decodeURIComponent(p.replace(/../g,f=>"%"+f))}catch{m=p}if(!m||m===p)try{let f="";for(let v=0;v<p.length;v+=2){let h=parseInt(p.slice(v,v+2),16);h>=32&&h<127&&(f+=String.fromCharCode(h))}f.length>4&&(m=f)}catch{}s.push({tx:d.hash||"",type:d.TransactionType,sender:d.Account,text:m.slice(0,200),raw:p})}if(s.length===0)return{signals:[],allMemos:[],scamMemos:[],repeatedMemos:[]};let o=s.filter(d=>a.some(u=>u.test(d.text)));o.length&&n.push({sev:"critical",label:`${o.length} memo(s) match known scam patterns`,detail:`Memos containing phrases like "airdrop", "claim reward", "verify wallet", or "urgent" are used in social engineering attacks. These payments were likely sent to trick the recipient into taking action. Examples: ${o.slice(0,2).map(d=>'"'+d.text.slice(0,40)+'"').join(", ")}`});let i={};for(let d of s){let u=d.text.slice(0,50).trim().toLowerCase();u.length>3&&(i[u]=(i[u]||0)+1)}let r=Object.entries(i).filter(([,d])=>d>=3).sort((d,u)=>u[1]-d[1]);return r.length&&n.push({sev:"warn",label:`${r.length} memo text(s) repeated \u22653 times`,detail:`Identical memo text across multiple transactions suggests scripted or automated activity. Most repeated: "${r[0][0]}" (${r[0][1]}\xD7)`}),n.length||n.push({sev:"ok",label:`${s.length} memo(s) found \u2014 no suspicious patterns`,detail:"Memo content looks normal."}),{signals:n,allMemos:s,scamMemos:o,repeatedMemos:r.slice(0,5)}}function jf(e,t,n){let s=e.filter(u=>u.LedgerEntryType==="Escrow");if(!s.length)return{signals:[],escrows:[],hasThirdParty:!1};let a=[],o=Math.floor(Date.now()/1e3),i=946684800,r=s.map(u=>{let p=u.Account||null,m=u.Destination||null,f=Number(u.Amount||0)/1e6,v=u.FinishAfter?u.FinishAfter+i:null,h=u.CancelAfter?u.CancelAfter+i:null,w=p&&p!==n&&m===n,k=p===n&&m===n,b=v?Math.ceil((v-o)/86400):null;return{creator:p,dest:m,amtXrp:f,finishAfter:v,cancelAfter:h,isThirdParty:w,isSelfEscrow:k,daysToFinish:b,conditional:!!u.Condition}}),l=r.filter(u=>u.isThirdParty),c=r.reduce((u,p)=>u+p.amtXrp,0);l.length&&a.push({sev:"warn",label:`${l.length} escrow(s) created by external account(s) \u2014 funds locked to this address`,detail:`${D(l.reduce((u,p)=>u+p.amtXrp,0),2)} XRP in escrows that an outside party controls. The creator sets the conditions. Escrows created by attackers just before a drain attempt have been observed in some compromise patterns \u2014 verify who created these.`});let d=r.filter(u=>u.daysToFinish!=null&&u.daysToFinish>=0&&u.daysToFinish<=7);return d.length&&a.push({sev:"info",label:`${d.length} escrow(s) mature within 7 days`,detail:`${D(d.reduce((u,p)=>u+p.amtXrp,0),2)} XRP will become claimable soon. If these are third-party escrows, the creator can claim funds once the condition is met.`}),a.length||a.push({sev:"ok",label:`${s.length} self-escrow(s) \u2014 ${D(c,2)} XRP locked`,detail:"All escrows appear to be self-controlled time-locks. No third-party escrow risk."}),{signals:a,escrows:r,hasThirdParty:l.length>0,totalLocked:c}}function qf(e){let t=e.filter(l=>l.LedgerEntryType==="Check");if(!t.length)return{signals:[],checks:[]};let n=[],s=946684800,a=Math.floor(Date.now()/1e3),o=t.map(l=>{let c=typeof l.SendMax=="string"?Number(l.SendMax)/1e6:null,d=typeof l.SendMax=="object"?l.SendMax:null,u=l.Expiration?l.Expiration+s:null,p=(l.ledger_index,null),m=u&&u<a;return{sender:l.Account,dest:l.Destination,amtXrp:c,amtToken:d,expiry:u,expired:m,id:l.index||""}}),i=o.filter(l=>l.amtXrp&&l.amtXrp>100),r=o.filter(l=>l.expired);return i.length&&n.push({sev:"info",label:`${i.length} large uncashed check(s) \u2014 ${D(i.reduce((l,c)=>l+(c.amtXrp||0),0),2)} XRP pending`,detail:"Open checks can be cashed by the recipient at any time before expiry. Large uncashed checks represent a future outflow commitment."}),r.length&&n.push({sev:"info",label:`${r.length} expired check(s) \u2014 should be cancelled to reclaim reserve`,detail:"Expired checks still occupy owner reserve slots (2 XRP each). Cancelling them returns the reserved XRP."}),n.length||n.push({sev:"ok",label:`${t.length} check(s) found \u2014 no unusual patterns`,detail:"Check amounts are within normal range."}),{signals:n,checks:o}}function Vf(e,t){var m,f,v;if(!e||!((m=e.offers)!=null&&m.length))return{signals:[],hasData:!1};let{pair:n,offers:s}=e,a=[],o=new Map;for(let h of s){let w=h.Account,k=typeof h.TakerGets=="string"?Number(h.TakerGets)/1e6:Number(((f=h.TakerGets)==null?void 0:f.value)||0);o.set(w,(o.get(w)||0)+k)}let i=[...o.values()].reduce((h,w)=>h+w,0),r=o.get(t)||0,l=i>0?r/i:0,d=[...s].sort((h,w)=>{var x,S;let k=typeof h.TakerGets=="string"?Number(h.TakerGets)/1e6:Number(((x=h.TakerGets)==null?void 0:x.value)||0);return(typeof w.TakerGets=="string"?Number(w.TakerGets)/1e6:Number(((S=w.TakerGets)==null?void 0:S.value)||0))-k})[0],u=typeof(d==null?void 0:d.TakerGets)=="string"?Number(d.TakerGets)/1e6:Number(((v=d==null?void 0:d.TakerGets)==null?void 0:v.value)||0),p=i>0?u/i:0;return p>.4&&(d==null?void 0:d.Account)===t?a.push({sev:"critical",label:`Active wall order: this wallet controls ${(p*100).toFixed(0)}% of current book depth`,detail:`A single order from this address represents ${(p*100).toFixed(0)}% of the visible order book depth on pair ${n}. Large orders placed to make a market look deeper than it is \u2014 without intent to fill \u2014 is spoofing. This order is live right now.`}):p>.4&&a.push({sev:"warn",label:`Wall order present: ${(p*100).toFixed(0)}% of book depth in one order`,detail:`A single address controls ${(p*100).toFixed(0)}% of the current order book for pair ${n}. Wall orders dominate book depth and can be removed instantly \u2014 they create false liquidity signals.`}),l>.25&&a.push({sev:"info",label:`This wallet controls ${(l*100).toFixed(0)}% of current order book depth`,detail:`${D(r,2)} of ${D(i,2)} total book volume on pair ${n}.`}),a.length||a.push({sev:"ok",label:`Live order book looks normal (${s.length} orders, pair: ${n.split("\u2194").map(h=>h.split("+")[0]).join("\u2194")})`,detail:"No wall orders or unusual depth concentration detected in the current order book."}),{signals:a,hasData:!0,pair:n,offerCount:s.length,ourShare:l,wallShare:p}}function Gf(e,t,n,s,a,o,i,r,l,c,d,u,p,m){var v,h;return[{label:"Security",pts:Math.round((100-t.score)*.4),max:40,color:"#ff5555",icon:"\u{1F510}"},{label:"Drain Risk",pts:{low:0,medium:10,high:25,critical:35}[n.riskLevel]||0,max:35,color:"#ff5555",icon:"\u26A0\uFE0F"},{label:"Wash Trading",pts:Math.min(15,Math.round((a.score||0)*.15)),max:15,color:"#ffb86c",icon:"\u{1F4CA}"},{label:"NFT Risk",pts:Math.min(15,s.flags.filter(w=>w.sev==="critical").length*8+s.flags.filter(w=>w.sev==="warn").length*3),max:15,color:"#bd93f9",icon:"\u{1F3A8}"},{label:"Benford's",pts:(o==null?void 0:o.chiSq)>20.09?10:(o==null?void 0:o.chiSq)>15.51?5:0,max:10,color:"#f1fa8c",icon:"\u{1F4D0}"},{label:"Forensic Suite",pts:Math.min(20,Math.min(8,Math.round(((r==null?void 0:r.riskPenalty)||0)*.35))+Math.min(8,Math.round(((l==null?void 0:l.riskPenalty)||0)*.4))+Math.min(8,Math.round(((c==null?void 0:c.riskPenalty)||0)*.35))+Math.min(8,Math.round(((d==null?void 0:d.riskPenalty)||0)*.35))),max:20,color:"#00d4ff",icon:"\u{1F9EC}"},{label:"Vol Conc",pts:Math.min(10,(((v=i==null?void 0:i.signals)==null?void 0:v.filter(w=>w.sev==="critical").length)||0)*6+(((h=i==null?void 0:i.signals)==null?void 0:h.filter(w=>w.sev==="warn").length)||0)*3),max:10,color:"#ffb86c",icon:"\u{1FAE7}"},{label:"Fee Spikes",pts:Math.min(5,(u==null?void 0:u.riskPenalty)||0),max:5,color:"#ffb86c",icon:"\u{1F4B8}"}].filter(w=>w.pts>0)}function Kf(e,t,n,s,a,o,i,r,l,c,d=null){let u=0;u+=Math.round((100-e.score)*.4),u+={low:0,medium:10,high:25,critical:35}[t.riskLevel]||0;let m=n.flags.filter(v=>v.sev==="critical").length,f=n.flags.filter(v=>v.sev==="warn").length;if(u+=Math.min(15,m*8+f*3),u+=Math.min(15,Math.round(s.score*.15)),(a==null?void 0:a.chiSq)!=null&&(a.chiSq>20.09?u+=10:a.chiSq>15.51&&(u+=5)),o!=null&&o.signals){let v=o.signals.filter(w=>w.sev==="critical").length,h=o.signals.filter(w=>w.sev==="warn").length;u+=Math.min(10,v*6+h*3)}return i!=null&&i.riskPenalty&&(u+=Math.min(8,Math.round(i.riskPenalty*.35))),r!=null&&r.riskPenalty&&(u+=Math.min(8,Math.round(r.riskPenalty*.4))),l!=null&&l.riskPenalty&&(u+=Math.min(8,Math.round(l.riskPenalty*.35))),c!=null&&c.riskPenalty&&(u+=Math.min(8,Math.round(c.riskPenalty*.35))),d!=null&&d.riskPenalty&&(u+=Math.min(5,d.riskPenalty)),Math.min(100,u)}function Jf(e){var h;let t=document.getElementById("inspect-benfords-body");if(!t)return;let n={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},s=e.signals.map(w=>`
    <div class="finding finding--${w.sev}">
      <span class="finding-sev ${n[w.sev]||""}">${w.sev.toUpperCase()}</span>
      <div class="finding-body">
        <div class="finding-label">${g(w.label)}</div>
        <div class="finding-detail">${g(w.detail)}</div>
      </div>
    </div>`).join(""),a=(h=e.digitBreakdown)!=null&&h.length?`
    <div class="benford-grid">
      <div class="benford-grid-h">Digit</div>
      <div class="benford-grid-h">Observed</div>
      <div class="benford-grid-h">Expected</div>
      <div class="benford-grid-h">Bar</div>
      ${e.digitBreakdown.map(w=>{let k=parseFloat(w.obs),b=parseFloat(w.exp),x=k-b,S=Math.abs(x)>5?"#ff5555":Math.abs(x)>2.5?"#ffb86c":"#50fa7b",T=`<div style="height:6px;border-radius:3px;background:rgba(255,255,255,.08);overflow:hidden">
          <div style="height:100%;width:${Math.min(100,k*3.3).toFixed(0)}%;background:${S};border-radius:3px"></div>
        </div>`;return`<div class="mono" style="text-align:center">${w.digit}</div>
                <div class="mono" style="color:${S}">${w.obs}%</div>
                <div class="mono" style="opacity:.6">${w.exp}%</div>
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
    </p>`);let v=`
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
  `;t.innerHTML=s+o+a+v}function Yf(e){var o;let t=document.getElementById("inspect-volconc-body");if(!t)return;let n={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},s=e.signals.map(i=>`
    <div class="finding finding--${i.sev}">
      <span class="finding-sev ${n[i.sev]||""}">${i.sev.toUpperCase()}</span>
      <div class="finding-body">
        <div class="finding-label">${g(i.label)}</div>
        <div class="finding-detail">${g(i.detail)}</div>
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
          <td class="mono" style="padding:3px 0">${g(i.currency.slice(0,10))}</td>
          <td class="mono" style="text-align:center;color:${r}">${i.uniqueActors}</td>
          <td class="mono" style="text-align:center;opacity:.7">${i.trades}</td>
          <td style="font-size:11px;color:${r}">${l}</td>
        </tr>`}).join("")}
    </table>`:"";t.innerHTML=s+a}function pa(e,t,n){let s=document.getElementById(e);if(!s)return;let a={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},o=t.signals.map(i=>`
    <div class="finding finding--${i.sev}">
      <span class="finding-sev ${a[i.sev]||""}">${i.sev.toUpperCase()}</span>
      <div class="finding-body">
        <div class="finding-label">${g(i.label)}</div>
        <div class="finding-detail">${g(i.detail)}</div>
      </div>
    </div>`).join("");s.innerHTML=o+(n||"")}function Qf(e){let t=[["Sample size",e.sampleSize],["Amount entropy",e.amountEntropy!=null?e.amountEntropy.toFixed(2)+" bits":"\u2014",e.amountEntropy!=null&&e.amountEntropy<2?"risk-text-high":""],["Counterparty entropy",e.counterpartyEntropy!=null?e.counterpartyEntropy.toFixed(2)+" bits":"\u2014"],["Time-of-day entropy",e.timeEntropy!=null?e.timeEntropy.toFixed(2)+" bits":"\u2014"],["Unique counterparties",e.uniqueCounterparties],["Verdict",e.verdict,e.verdict==="anomalous"?"risk-text-high":e.verdict==="elevated"?"risk-text-med":""]];pa("inspect-entropy-body",e,'<div class="wash-stat-row" style="margin-top:10px"><span>Metric</span><span class="mono" style="opacity:.45">Value</span></div>'+t.map(([n,s,a])=>`<div class="wash-stat-row"><span>${n}</span><span class="mono ${a||""}">${s}</span></div>`).join(""))}function Zf(e){var s;let t=[["Unique counterparties",e.uniqueCounterparties],["Zipf exponent (s)",e.zipfExponent!=null?e.zipfExponent.toFixed(3):"\u2014",e.zipfExponent!=null&&(e.zipfExponent<.4||e.zipfExponent>2.2)?"risk-text-high":""],["Fit quality (R\xB2)",e.rSquared!=null?e.rSquared.toFixed(3):"\u2014",e.rSquared!=null&&e.rSquared<.55?"risk-text-high":""],["Natural range","s \u2248 0.8\u20131.3, R\xB2 > 0.55"],["Verdict",e.verdict,e.verdict==="anomalous"?"risk-text-high":e.verdict==="elevated"?"risk-text-med":""]],n=((s=e.freqTable)==null?void 0:s.slice(0,10).map((a,o)=>{let i=e.freqTable[0]||1,r=(a/i*100).toFixed(0),l=e.freqTable[0]?(e.freqTable[0]/Math.pow(o+1,e.zipfExponent||1)).toFixed(1):0;return`<div class="wash-stat-row">
      <span class="mono" style="min-width:28px">Rank ${o+1}</span>
      <div style="flex:1;height:6px;background:rgba(255,255,255,.06);border-radius:3px;overflow:hidden;margin:0 8px">
        <div style="height:100%;width:${r}%;background:var(--accent);border-radius:3px"></div>
      </div>
      <span class="mono" style="opacity:.6">${a}</span>
    </div>`}).join(""))||"";pa("inspect-zipf-body",e,t.map(([a,o,i])=>`<div class="wash-stat-row" style="margin-top:${a==="Unique counterparties"?10:0}px"><span>${a}</span><span class="mono ${i||""}">${o}</span></div>`).join("")+(n?`<div style="margin-top:14px;opacity:.75;font-size:.72rem;letter-spacing:.08em;color:rgba(255,255,255,.45);margin-bottom:6px">COUNTERPARTY RANK\u2013FREQUENCY</div>${n}`:""))}function eh(e){let t=[["Transactions timed",e.totalTimestamped||"\u2014"],["Active span",e.activeSpanDays!=null?e.activeSpanDays+" days":"\u2014"],["Interval CV",e.intervalCV!=null?e.intervalCV.toFixed(3):"\u2014",e.intervalCV!=null&&e.intervalCV<.5?"risk-text-high":""],["Periodicity score",e.periodicityScore!=null?(e.periodicityScore*100).toFixed(0)+"%":"\u2014",e.periodicityScore>.55?"risk-text-high":""],["Burst score (z)",e.burstScore!=null?e.burstScore.toFixed(2):"\u2014"],["Lag-1 autocorrelation",e.autocorrelation!=null?e.autocorrelation.toFixed(3):"\u2014",e.autocorrelation>.6?"risk-text-med":""],["Day-of-week entropy",e.dowEntropy!=null?e.dowEntropy.toFixed(2)+" bits":"\u2014"],["Verdict",e.verdict,e.verdict==="bot-pattern"?"risk-text-high":e.verdict==="elevated"?"risk-text-med":""]],n=["Sun","Mon","Tue","Wed","Thu","Fri","Sat"],s=e.dowBins?Math.max(...e.dowBins,1):1,a=e.dowBins?`
    <div style="margin-top:14px;opacity:.75;font-size:.72rem;letter-spacing:.08em;color:rgba(255,255,255,.45);margin-bottom:6px">DAY-OF-WEEK DISTRIBUTION</div>
    <div style="display:flex;gap:5px;align-items:flex-end;height:42px">
      ${e.dowBins.map((o,i)=>`
        <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:3px">
          <div style="width:100%;height:${(o/s*36).toFixed(0)}px;background:rgba(0,212,255,.35);border-radius:2px 2px 0 0;min-height:2px"></div>
          <div style="font-size:.6rem;opacity:.5">${n[i]}</div>
        </div>`).join("")}
    </div>`:"";pa("inspect-timeseries-body",e,t.map(([o,i,r])=>`<div class="wash-stat-row" style="margin-top:${o==="Transactions timed"?10:0}px"><span>${o}</span><span class="mono ${r||""}">${i}</span></div>`).join("")+a)}function th(e){let t=e.offerCancelCausality,n=e.inflowOutflowCausality,s=(o,i)=>{if(!(o!=null&&o.length))return"";let r=Math.max(.01,...o.map(Math.abs));return`<div style="margin-top:12px;opacity:.75;font-size:.72rem;letter-spacing:.08em;color:rgba(255,255,255,.45);margin-bottom:6px">${i}</div>
    <div style="display:flex;gap:4px;align-items:flex-end;height:40px">
      ${o.map((l,c)=>{let d=(Math.abs(l)/r*36).toFixed(0),u=l>.5?"rgba(255,85,85,.7)":l>.3?"rgba(255,184,108,.6)":"rgba(0,212,255,.3)";return`<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:3px">
          <div style="width:100%;height:${d}px;background:${u};border-radius:2px 2px 0 0;min-height:2px"></div>
          <div style="font-size:.6rem;opacity:.5">L${c}</div>
        </div>`}).join("")}
    </div>`},a=[["Time windows",e.windowCount||"\u2014"],["OfferCreate\u2192Cancel \u03C1",t?t.maxCorr.toFixed(3):"\u2014",t&&t.maxCorr>.55?"risk-text-high":""],["OC lag",t?`${t.maxLag} window${t.maxLag===1?"":"s"} (${t.maxLag*12}h)`:"\u2014"],["Inflow\u2192Outflow \u03C1",n?n.maxCorr.toFixed(3):"\u2014",n&&n.maxCorr>.65?"risk-text-high":""],["IO lag",n?`${n.maxLag} window${n.maxLag===1?"":"s"}`:"\u2014"],["Verdict",e.verdict,e.verdict==="causal-signal"?"risk-text-high":e.verdict==="elevated"?"risk-text-med":""]];pa("inspect-granger-body",e,a.map(([o,i,r])=>`<div class="wash-stat-row" style="margin-top:${o==="Time windows"?10:0}px"><span>${o}</span><span class="mono ${r||""}">${i}</span></div>`).join("")+s(t==null?void 0:t.ccf,"OFFER-CREATE \u2192 CANCEL CROSS-CORRELATION")+s(n==null?void 0:n.ccf,"INFLOW \u2192 OUTFLOW CROSS-CORRELATION"))}function nh(e,t,n,s,a){let o=document.getElementById("inspect-forensic-suite-body");if(!o)return;let i=(k,b=25)=>{if(!k||k.verdict==="insufficient")return null;if(k.chiSq!=null)return k.verdict==="high-deviation"?{val:b,cls:"risk-text-high",label:"HIGH DEVIATION"}:k.verdict==="moderate-deviation"?{val:Math.round(b*.5),cls:"risk-text-med",label:"MODERATE"}:{val:0,cls:"",label:"NORMAL"};let x=k.riskPenalty||0;return x>=18?{val:b,cls:"risk-text-high",label:"ANOMALOUS"}:x>=8?{val:Math.round(b*.5),cls:"risk-text-med",label:"ELEVATED"}:{val:0,cls:"",label:"NORMAL"}},r=[{name:"Benford's Law",icon:"\u{1F4D0}",desc:"First-digit digit distribution vs log-uniform expected",s:i(e)},{name:"Shannon's Entropy",icon:"\u{1F500}",desc:"Randomness of amounts, counterparties, time-of-day, tx types",s:i(t)},{name:"Zipf's Law",icon:"\u{1F4C8}",desc:"Counterparty rank-frequency power-law fit",s:i(n)},{name:"Time Series",icon:"\u{1F550}",desc:"Interval regularity, periodicity, burst detection, autocorrelation",s:i(s)},{name:"Granger Causality",icon:"\u{1F517}",desc:"Lead-lag temporal causality: create\u2192cancel, inflow\u2192outflow",s:i(a)}],l=r.some(k=>k.s&&k.s.val>0),c=r.filter(k=>{var b;return((b=k.s)==null?void 0:b.cls)==="risk-text-high"}).length,d=r.filter(k=>{var b;return((b=k.s)==null?void 0:b.cls)==="risk-text-med"}).length,u=r.filter(k=>!k.s).length,p,m,f;c>=3?(p="STRONG MANIPULATION SIGNALS \u2014 Multiple independent engines converging on anomalous patterns.",m="#ff5555",f="\u{1F6A8}"):c>=2||c>=1&&d>=2?(p="SIGNIFICANT ANOMALIES \u2014 At least two engines detect non-organic behavior. Cross-reference with Wash Trading and Drain Risk.",m="#ff5555",f="\u26A0\uFE0F"):c>=1||d>=2?(p="ELEVATED RISK \u2014 One or more engines flag behavioral anomalies. Investigate the specific modules for detail.",m="#ffb86c",f="\u26A0\uFE0F"):!l&&u<3?(p="NO ANOMALIES \u2014 All five engines return results consistent with organic financial activity.",m="#50fa7b",f="\u2705"):(p="INSUFFICIENT DATA \u2014 More transaction history needed for a reliable multi-engine assessment.",m="rgba(255,255,255,.4)",f="\u{1F4CA}");let v=r.map(k=>{let b=!k.s,x=b?"rgba(255,255,255,.25)":k.s.val===0?"#50fa7b":k.s.cls==="risk-text-high"?"#ff5555":"#ffb86c",S=b?"NO DATA":k.s.label,T=b?0:k.s.val===0?4:k.s.cls==="risk-text-high"?100:55;return`<div style="background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);border-radius:12px;padding:14px 14px 12px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span style="font-size:1.05rem">${k.icon}</span>
        <div style="flex:1">
          <div style="font-size:.82rem;font-weight:700;color:rgba(255,255,255,.85)">${k.name}</div>
          <div style="font-size:.7rem;color:rgba(255,255,255,.35);margin-top:1px;line-height:1.4">${k.desc}</div>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        <div style="flex:1;height:5px;background:rgba(255,255,255,.08);border-radius:3px;overflow:hidden">
          <div style="height:100%;width:${T}%;background:${x};border-radius:3px;transition:width .6s ease"></div>
        </div>
        <span style="font-size:.65rem;font-weight:800;color:${x};min-width:80px;text-align:right;letter-spacing:.06em">${S}</span>
      </div>
    </div>`}).join(""),h=r.filter(k=>k.s&&k.s.val>0),w="";h.length>=2?w=`<div style="background:rgba(255,184,108,.05);border:1px solid rgba(255,184,108,.2);border-radius:12px;padding:14px 16px;margin-top:14px">
      <div style="font-size:.68rem;font-weight:900;color:#ffb86c;letter-spacing:.12em;text-transform:uppercase;margin-bottom:8px">\u26A1 Convergence Analysis</div>
      <p style="font-size:.84rem;color:rgba(255,255,255,.65);line-height:1.7;margin:0">
        ${h.map(k=>k.name).join(" and ")} are all flagging behavioral anomalies.
        When multiple independent statistical methods converge on the same conclusion \u2014 each using
        different mathematical principles \u2014 the combined signal is substantially stronger than any
        single engine alone. This convergence reduces the probability that the findings are false positives
        from sample-specific artifacts or edge cases.
        ${c>=2?" The strength and breadth of these signals warrants serious investigation.":" Monitor alongside the Wash Trading and Security modules for a complete picture."}
      </p>
    </div>`:l?w=`<div style="background:rgba(0,212,255,.04);border:1px solid rgba(0,212,255,.12);border-radius:12px;padding:14px 16px;margin-top:14px">
      <p style="font-size:.84rem;color:rgba(255,255,255,.55);line-height:1.7;margin:0">
        Only one engine is currently flagging anomalies. A single-engine signal is a hypothesis, not a conclusion.
        Cross-reference with Wash Trading, Benford's Law, and Drain Risk modules to determine whether
        the pattern is isolated or part of a broader behavioral signature.
      </p>
    </div>`:w=`<div style="background:rgba(80,250,123,.04);border:1px solid rgba(80,250,123,.12);border-radius:12px;padding:14px 16px;margin-top:14px">
      <p style="font-size:.84rem;color:rgba(255,255,255,.55);line-height:1.7;margin:0">
        No engine in the forensic suite has flagged this account.
        The five methods use independent mathematical frameworks \u2014
        digit distribution (Benford), information theory (entropy), power laws (Zipf),
        temporal statistics (time series), and causal inference (Granger).
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
      ${v}
    </div>
    ${w}
    <div style="margin-top:16px;padding:12px 14px;background:rgba(255,255,255,.02);border-radius:10px;border:1px solid rgba(255,255,255,.05)">
      <div style="font-size:.68rem;font-weight:900;letter-spacing:.12em;color:rgba(255,255,255,.3);text-transform:uppercase;margin-bottom:6px">How to read this suite</div>
      <p style="font-size:.78rem;color:rgba(255,255,255,.4);line-height:1.7;margin:0">
        Each engine is mathematically independent. A single flag could be a false positive from small samples or edge-case data.
        Two or more flags converging is a meaningful signal. Three or more is strong evidence of non-organic behavior.
        None of these engines constitute legal proof \u2014 they are forensic intelligence to guide further investigation.
      </p>
    </div>`}function sh(e,t,n,s,a,o,i,r=null,l=null){let c=y("inspect-addr-badge");c&&(c.textContent=e.length>20?e.slice(0,10)+"\u2026"+e.slice(-8):e,c.title=e,c.dataset.fullAddr=e);let d=y("inspect-risk-score");d&&(d.textContent=i,d.className="irb-score-val "+To(i));let u=y("inspect-risk-label");u&&(u.textContent=i<20?"Low Risk":i<45?"Moderate":i<70?"High Risk":"Critical",u.className="irb-score-label "+To(i));let p=y("inspect-acct-grid");if(!p)return;let m=Math.max(0,n-s),f=Number(t.Flags||0),v=r!=null?r===0?"Created today":r===1?"1 day old":r<30?`${r} days old`:r<365?`${Math.floor(r/30)} months old`:`${(r/365).toFixed(1)} years old`:"\u2014",h=l?new Date(l).toLocaleDateString("en-US",{year:"numeric",month:"short",day:"numeric"}):null,w=nn(n),k=nn(m),b=[{label:"XRP Balance",value:`${D(n,6)} XRP${w}`,mono:!0},{label:"Spendable",value:`${D(m,6)} XRP${k}`,mono:!0,note:`${s} XRP reserved`},{label:"Wallet Age",value:v,note:h?`Created ${h}`:null,highlight:r!=null&&r<7?"new":null},{label:"Owner Count",value:a,note:`${a*2} XRP tied up`},{label:"Sequence",value:o,mono:!0},{label:"Regular Key",value:t.RegularKey?U(t.RegularKey):"None",warn:!!t.RegularKey,mono:!0},{label:"Master Key",value:f&Xe.lsfDisableMaster?"Disabled":"Active",warn:!!(f&Xe.lsfDisableMaster)}];p.innerHTML=b.map(x=>`
    <div class="acct-cell ${x.warn?"acct-cell--warn":""} ${x.highlight==="new"?"acct-cell--new":""}">
      <div class="acct-cell-label">${g(x.label)}</div>
      <div class="acct-cell-value ${x.mono?"mono":""}">${g(String(x.value))}</div>
      ${x.note?`<div class="acct-cell-note">${g(x.note)}</div>`:""}
      ${x.highlight==="new"?'<div class="acct-cell-new-badge">\u26A0 New wallet</div>':""}
    </div>`).join("")}function ah(e,t,n,s,a){let o=y("inspect-security-body");if(!o)return;let i=Object.entries(Xe).filter(([,r])=>n&r).map(([r])=>r.replace("lsf",""));o.innerHTML=`
    <div class="audit-items">
      ${e.findings.map(r=>wn(r)).join("")}
    </div>
    ${i.length?`
    <div class="audit-flags">
      <div class="audit-flags-label">Active Flags</div>
      <div class="audit-flags-pills">
        ${i.map(r=>`<span class="flag-pill">${g(r)}</span>`).join("")}
      </div>
    </div>`:""}
    ${s.length?`
    <div class="signer-list-block">
      <div class="signer-list-title">Signer List (Multisig)</div>
      ${s.map(r=>`
        <div class="signer-entries">
          ${(r.SignerEntries||[]).map(l=>{var c,d;return`
            <div class="signer-entry">
              <span class="signer-addr mono">${g(((c=l.SignerEntry)==null?void 0:c.Account)||"\u2014")}</span>
              <span class="signer-weight">weight ${((d=l.SignerEntry)==null?void 0:d.SignerWeight)||1}</span>
            </div>`}).join("")}
          <div class="signer-quorum">Quorum: ${r.SignerQuorum}</div>
        </div>`).join("")}
    </div>`:""}
    ${a.length?`
    <div class="audit-note">
      <span class="audit-note-label">DepositPreauth grants:</span>
      ${a.slice(0,8).map(r=>`<span class="mono">${U(r.Authorize||"")}</span>`).join(", ")}
      ${a.length>8?`+${a.length-8} more`:""}
    </div>`:""}
  `,ua("badge-security",e.findings)}function oh(e,t,n,s){let a=y("inspect-drain-body");if(!a)return;let o={low:"#50fa7b",medium:"#ffb86c",high:"#ff8c42",critical:"#ff5555"},i={low:"\u2713",medium:"\u26A0",high:"\u26A0",critical:"\u26D4"};a.innerHTML=`
    <div class="drain-level drain-level--${e.riskLevel}">
      <span class="drain-level-icon">${i[e.riskLevel]}</span>
      <span class="drain-level-text">Drain Risk: <strong>${e.riskLevel.toUpperCase()}</strong></span>
    </div>
    <div class="audit-items">
      ${e.signals.map(r=>wn(r)).join("")}
    </div>
    ${t.length?`
    <div class="drain-sub-section">
      <div class="drain-sub-title">Open Payment Channels</div>
      ${t.map(r=>`
        <div class="drain-channel-row">
          <span class="mono">${U(r.Destination)}</span>
          <span>${D(Number(r.Amount||0)/1e6,2)} XRP allocated</span>
          <span>${D(Number(r.Balance||0)/1e6,2)} XRP claimed</span>
        </div>`).join("")}
    </div>`:""}
    ${n.length?`
    <div class="drain-sub-section">
      <div class="drain-sub-title">Open Escrows</div>
      ${n.slice(0,5).map(r=>`
        <div class="drain-channel-row">
          <span>${r.Destination?U(r.Destination):"self"}</span>
          <span>${D(Number(r.Amount||0)/1e6,2)} XRP</span>
          <span class="mono">${r.Condition?"conditional":r.FinishAfter?"time-locked":""}</span>
        </div>`).join("")}
    </div>`:""}
  `,_h("badge-drain",e.riskLevel)}function ih(e,t){let n=y("inspect-nft-body");n&&(n.innerHTML=`
    <div class="audit-items">
      ${e.flags.map(s=>wn(s)).join("")}
    </div>
    ${t.length?`
    <div class="nft-grid">
      ${t.slice(0,12).map(s=>rh(s)).join("")}
    </div>
    ${t.length>12?`<div class="nft-more">+${t.length-12} more NFTs</div>`:""}
    `:""}
  `,ua("badge-nft",e.flags))}function rh(e){let t=Number(e.Flags||0),n=!!(t&kl.lsfTransferable),s=!!(t&kl.lsfBurnable),a=e.NFTokenTaxon||0,o=e.TransferFee?`${(e.TransferFee/1e3).toFixed(1)}%`:"0%";return`
    <div class="nft-card">
      <div class="nft-id mono">${e.NFTokenID?U(e.NFTokenID):"\u2014"}</div>
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
      ${e.Issuer&&e.Issuer!==e.Account?`<div class="nft-issuer mono">Issuer: ${U(e.Issuer)}</div>`:""}
    </div>`}function lh(e){let t=y("inspect-wash-body");if(!t)return;let n=e.verdict==="clean"||e.verdict==="low-risk"?"#50fa7b":e.verdict==="suspicious"?"#ffb86c":"#ff5555";t.innerHTML=`
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
      ${gs("Offer Creates",e.stats.creates)}
      ${gs("Offer Cancels",e.stats.cancels)}
      ${gs("Filled Offers",e.stats.fills)}
      ${gs("Payments",e.stats.payments)}
      ${gs("Round-trip Counterparties",e.stats.roundTrip)}
    </div>
    <div class="audit-items">
      ${e.signals.map(a=>wn(a)).join("")}
    </div>
  `;let s=y("badge-wash");if(s){let a=e.verdict==="clean"||e.verdict==="low-risk"?"ok":e.verdict==="suspicious"?"warn":"crit";s.textContent=e.verdict.replace("-"," "),s.className="section-badge section-badge--"+a}}function gs(e,t){return`<div class="wash-stat"><span class="wash-stat-label">${g(e)}</span><span class="wash-stat-val">${t}</span></div>`}function ch(e,t){let n=y("inspect-issuer-body");if(!n)return;let s=t.filter(a=>a.currency&&(a.currency.length===3||a.currency.length===40));n.innerHTML=`
    <div class="audit-items">
      ${e.signals.map(a=>wn(a)).join("")}
    </div>
    ${s.length?`
    <div class="trustline-list">
      ${s.slice(0,10).map(a=>`
        <div class="trustline-row">
          <span class="trustline-currency">${g(yn(a.currency))}</span>
          <span class="trustline-issuer mono">${U(a.account)}</span>
          <span class="trustline-balance ${Number(a.balance)<0?"trustline-owed":""} mono">
            ${Number(a.balance)<0?"\u25BC ":""}${D(Math.abs(Number(a.balance)),2)}
            ${a.freeze?'<span class="trustline-frozen">FROZEN</span>':""}
            ${a.freeze_peer?'<span class="trustline-frozen trustline-frozen--peer">FROZEN BY ISSUER</span>':""}
          </span>
        </div>`).join("")}
      ${s.length>10?`<div class="trustline-more">+${s.length-10} more trustlines</div>`:""}
    </div>`:""}
  `,ua("badge-issuer",e.signals)}function dh(e,t){let n=y("inspect-amm-body");n&&(n.innerHTML=`
    <div class="audit-items">
      ${e.signals.map(s=>wn(s)).join("")}
    </div>
    ${e.positions.length?`
    <div class="amm-positions">
      ${e.positions.map(s=>`
        <div class="amm-position-card">
          <div class="amm-position-currency mono">${U(s.currency)}</div>
          <div class="amm-position-meta">
            <span>Pool: ${U(s.issuer)}</span>
            <span class="amm-position-balance">${D(Math.abs(s.balance),4)} LP tokens</span>
          </div>
        </div>`).join("")}
    </div>`:""}
  `,ua("badge-amm",e.signals))}function ph(e){let t=y("trust-count-badge");t&&(t.textContent=e.length);let n=y("inspect-trust-body");n&&(n.innerHTML=e.length?e.map(s=>{let a=s.freeze?'<span class="trustline-frozen">Frozen</span>':"",o=s.freeze_peer?'<span class="trustline-frozen trustline-frozen--peer">Issuer Frozen</span>':"",i=s.no_ripple?'<span class="trustline-norip">NoRipple</span>':"";return`
          <div class="trustline-row">
            <span class="trustline-currency">${g(yn(s.currency))}</span>
            <span class="trustline-issuer mono">${U(s.account)}</span>
            <span class="trustline-balance mono">${g(s.balance)} / ${g(s.limit)}</span>
            <span class="trustline-flags">${a}${o}${i}</span>
          </div>`}).join(""):'<div class="inspect-empty-note">No trustlines found.</div>')}function uh(e,t){let n=y("inspect-tx-timeline");if(!n)return;let s=60,a=e.slice(0,s),o=y("badge-tx");if(o){let i=window._inspectMaxTx||5e3,r=e.length>=i;o.textContent=e.length.toLocaleString()+" tx"+(r?" (cap reached)":""),o.className="section-badge section-badge--neutral",r&&(o.title=`Fetched ${e.length.toLocaleString()} transactions \u2014 cap of ${i.toLocaleString()} reached. Set window._inspectMaxTx = 20000 in console to go deeper.`)}n.innerHTML=a.length?a.map(({tx:i,meta:r})=>{let l=i.TransactionType||"Unknown",c=(r==null?void 0:r.TransactionResult)==="tesSUCCESS",d=Sh(i,r,t),u=Pt(i),p=u?new Date(u*1e3).toLocaleString():"\u2014",m=Th(i,t),f=i.hash?i.hash.slice(0,8)+"\u2026"+i.hash.slice(-4):"",v=i.hash?`https://livenet.xrpl.org/transactions/${i.hash}`:null,h=i.hash?`https://xrpscan.com/tx/${i.hash}`:null;return`
          <div class="tx-row tx-row--${d}">
            <span class="tx-type-badge tx-type-badge--${Ch(l)}">${g(l)}</span>
            <span class="tx-brief">${m}</span>
            <span class="tx-result ${c?"tx-ok":"tx-fail"}">${c?"\u2713":"\u2717"}</span>
            <span class="tx-time">${p}</span>
            ${v?`<span class="tx-links">
              <a href="${v}" target="_blank" rel="noopener" class="tx-explorer-link" title="View on XRPL Livenet">\u{1F517}</a>
              <a href="${h}" target="_blank" rel="noopener" class="tx-explorer-link" title="View on XRPScan">\u{1F50D}</a>
            </span>`:""}
          </div>`}).join(""):'<div class="inspect-empty-note">No transactions found.</div>',e.length>s&&(n.innerHTML+=`<div class="tx-more">Showing ${s} of ${e.length} transactions</div>`)}function El(e,t,n){let s=Number((n==null?void 0:n.totalIn)||0),a=Number((t==null?void 0:t.totalOut)||0),o=Number(e||0);if(s<=0&&a<=0)return"";let i=new Set(((t==null?void 0:t.blackHoleDests)||[]).map(x=>x.addr)),r=new Set(((t==null?void 0:t.exchangeDests)||[]).map(x=>x.addr)),l=new Set(((t==null?void 0:t.newWalletDests)||[]).map(x=>x.addr)),c=0,d=0,u=0,p=0;for(let x of(t==null?void 0:t.destinations)||[])i.has(x.addr)?c+=x.totalXrp:r.has(x.addr)?d+=x.totalXrp:l.has(x.addr)?u+=x.totalXrp:p+=x.totalXrp;let m=Math.max(s,a,o,1),f=x=>(x>0?Math.max(1.5,x/m*100):0).toFixed(1),v=[{label:"Black hole",xrp:c,color:en.blackhole},{label:"Exchange",xrp:d,color:en.exchange},{label:"New wallet",xrp:u,color:en.newWallet},{label:"Other",xrp:p,color:en.other}].filter(x=>x.xrp>0),h=a>0?Math.max(1.5,a/m*100):0,w=v.map(x=>`<div style="width:${(a>0?x.xrp/a*100:0).toFixed(1)}%;background:${x.color};height:100%" title="${g(x.label)}: ${D(x.xrp,2)} XRP"></div>`).join(""),k=(x,S,T,$,P)=>`
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
      <div style="width:84px;font-size:.72rem;color:rgba(255,255,255,.55);flex-shrink:0">${x}</div>
      <div style="flex:1;height:16px;border-radius:5px;overflow:hidden;background:rgba(255,255,255,.05)">
        <div style="width:${T}%;height:100%;display:flex">${$||`<div style="width:100%;height:100%;background:${P}"></div>`}</div>
      </div>
      <div class="mono" style="width:92px;text-align:right;font-size:.75rem;color:rgba(255,255,255,.75);flex-shrink:0">${D(S,2)} XRP</div>
    </div>`,b=v.map(x=>`<span style="font-size:.66rem;color:${x.color};margin-right:12px">\u25CF ${g(x.label)} ${D(x.xrp,0)}</span>`).join("");return`
    <div style="margin-bottom:16px">
      <div style="font-size:.65rem;color:rgba(255,255,255,.35);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px">
        Fund Flow \u2014 Inbound vs Outbound vs Current Balance
      </div>
      ${k("Total In",s,f(s),null,"#50fa7b")}
      ${k("Total Out",a,h,v.length?w:null,"rgba(255,255,255,.3)")}
      ${k("Balance Now",o,f(o),null,"#00d4ff")}
      ${v.length?`<div style="margin-top:2px">${b}</div>`:""}
    </div>`}function mh(e,t,n){var l;let s=y("inspect-fundflow-body");if(!s)return;let a=y("badge-fundflow");if(!e.timeline.length&&!e.destinations.length){s.innerHTML='<div class="audit-row audit-row--ok"><span class="audit-icon">\u2713</span><div class="audit-text"><div class="audit-label">No outbound payments found in analysed transaction history</div></div></div>',a&&(a.textContent="Clear",a.className="section-badge section-badge--ok");return}let o=e.exchangeDests.length?`<div class="flow-alert flow-alert--exchange">\u{1F4B1} Funds reached ${e.exchangeDests.length} known exchange(s): ${e.exchangeDests.map(c=>c.entity.name).join(", ")}</div>`:"",i=e.blackHoleDests.length?'<div class="flow-alert flow-alert--blackhole">\u{1F573} Funds sent to black hole address \u2014 irrecoverable!</div>':"",r=(l=e.newWalletDests)!=null&&l.length?`<div class="flow-alert" style="background:rgba(255,85,85,.06);border:1px solid rgba(255,85,85,.25);color:#ff5555;border-radius:8px;padding:10px 14px;margin-bottom:8px">
        \u26A0\uFE0F <strong>${e.newWalletDests.length} destination(s) are brand-new wallets</strong> (Sequence &lt; 10) receiving large XRP amounts.
        New wallets receiving large transfers shortly after creation are a common pattern in drain attacks \u2014 the attacker creates a disposable wallet and drains funds there.
       </div>`:"";if(s.innerHTML=`
    ${El(t,e,n)}
    ${r}${o}${i}
    <div class="flow-summary">
      <div class="flow-stat"><span>Unique destinations</span><b>${e.uniqueDests}</b></div>
      <div class="flow-stat"><span>Total XRP out</span><b class="mono">${D(e.totalOut,2)}</b></div>
      <div class="flow-stat"><span>Path payments</span><b>${e.totalPathPay}</b></div>
      <div class="flow-stat"><span>Exchange dests</span><b>${e.exchangeDests.length}</b></div>
    </div>

    <div class="flow-section-h">\u{1F4CD} Top Destinations</div>
    <div class="flow-dest-list">
      ${e.destinations.map((c,d)=>{var v,h,w,k;let u=e.totalOut>0?c.totalXrp/e.totalOut*100:0,p=c.entity?`<span class="flow-entity-badge flow-entity--${c.entity.type}">${g(c.entity.name)}</span>`:"",m=c.pathCount>0?`<span class="flow-path-badge">${c.maxHops}-hop path \xD7${c.pathCount}</span>`:"",f=c.tokens.slice(0,2).map(b=>`<span class="flow-token-chip">${g(b.k.split(".")[0])}</span>`).join("");return`
          <div class="flow-dest-row">
            <div class="flow-dest-rank ${((v=c.entity)==null?void 0:v.type)==="exchange"?"flow-rank--exchange":((h=c.entity)==null?void 0:h.type)==="blackhole"?"flow-rank--blackhole":""}">${d+1}</div>
            <div class="flow-dest-info">
              <div class="flow-dest-top">
                <button class="addr-link mono cut flow-dest-addr" data-addr="${g(c.addr)}" title="${g(c.addr)}">${g(U(c.addr))}</button>
                <a href="https://xrpscan.com/account/${g(c.addr)}" target="_blank" rel="noopener" class="tx-explorer-link" title="View on XRPScan">\u{1F50D}</a>
                ${p}${m}${f}
              </div>
              <div class="flow-bar-row">
                <div class="flow-dest-bar"><div class="flow-dest-fill" style="width:${Math.min(100,u).toFixed(1)}%;background:${((w=c.entity)==null?void 0:w.type)==="exchange"?"#00d4ff":((k=c.entity)==null?void 0:k.type)==="blackhole"?"#ff5555":"rgba(80,250,123,.7)"}"></div></div>
                <span class="mono flow-dest-pct">${u.toFixed(0)}%</span>
              </div>
              <div class="flow-dest-meta">
                <span class="mono">${D(c.totalXrp,2)} XRP</span>
                <span class="flow-dest-cnt">${c.txCount} tx</span>
                ${c.txCount>1?`<span class="flow-dest-span">${Nl(c.firstSeen,c.lastSeen)}</span>`:""}
              </div>
            </div>
          </div>`}).join("")}
    </div>

    <div class="flow-section-h" style="margin-top:18px">\u23F1 Outflow Timeline</div>
    <div class="flow-timeline">
      ${e.timeline.map(c=>{let d=new Date(c.ts*1e3).toLocaleDateString(),u=new Date(c.ts*1e3).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"}),p=c.amtXrp>0?`${D(c.amtXrp,2)} XRP`:c.amtToken?`${D(c.amtToken.value,2)} ${c.amtToken.currency}`:"\u2014",m=Yn(c.dest),f=m?`<span class="flow-entity-badge flow-entity--${m.type}" style="font-size:.65rem">${g(m.name)}</span>`:"";return`
          <div class="flow-tx-row">
            <span class="flow-tx-date">${d} ${u}</span>
            <button class="addr-link mono cut flow-tx-dest" data-addr="${g(c.dest)}" title="${g(c.dest)}">${g(U(c.dest))}</button>
            ${f}
            <span class="flow-tx-amt mono">${p}</span>
            ${c.isPathPay?`<span class="flow-path-tag">${c.hopCount}-hop</span>`:""}
          </div>`}).join("")}
    </div>
  `,a){let c=e.blackHoleDests.length||e.exchangeDests.length>2;a.textContent=`${e.uniqueDests} dests`,a.className=`section-badge section-badge--${c?"crit":e.uniqueDests>0?"warn":"ok"}`}}function Nl(e,t){if(!e||!t)return"";let n=new Date(e*1e3).toLocaleDateString(),s=new Date(t*1e3).toLocaleDateString();return n===s?n:`${n} \u2013 ${s}`}function fh(e,t){let n=y("inspect-issuer-connections-body");if(!n)return;let s=e.totalIssued,a=y("badge-issuer-connections");if(n.innerHTML=`
    <div class="audit-items">
      ${e.signals.map(o=>wn(o)).join("")}
    </div>

    ${s>0?`
    <div class="conn-stats">
      <div class="conn-stat"><span>Total Supply</span><b class="mono">${D(s,0)}</b></div>
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
            <button class="addr-link mono cut conn-holder-addr" data-addr="${g(o.addr)}" title="${g(o.addr)}">${g(U(o.addr))}</button>
            <div class="conn-holder-bar-wrap">
              <div class="conn-holder-bar">
                <div class="conn-holder-fill" style="width:${Math.min(100,r).toFixed(1)}%;background:${l}"></div>
              </div>
              <span class="mono conn-holder-pct">${r.toFixed(1)}%</span>
            </div>
            <span class="mono conn-holder-amt">${D(o.balance,0)} ${g(o.currency.slice(0,8))}</span>
          </div>`}).join("")}
    </div>`:""}

    ${e.createdAccts.length?`
    <div class="conn-section-h">\u{1F195} Accounts Created by This Issuer</div>
    <div class="conn-created-list">
      ${e.createdAccts.slice(0,12).map(o=>`
        <button class="addr-chip mono" data-addr="${g(o)}" title="${g(o)}">${g(U(o))}</button>
      `).join("")}
      ${e.createdAccts.length>12?`<span style="opacity:.65;font-size:.78rem">+${e.createdAccts.length-12} more</span>`:""}
    </div>`:""}

    `:""}

    ${e.mirrorGroups.length?`
    <div class="conn-section-h">\u{1F501} Mirror Wallet Clusters</div>
    <div class="conn-mirror-list">
      ${e.mirrorGroups.map(o=>`
        <div class="conn-mirror-group">
          <div class="conn-mirror-h">~${D(o.approxAmt,0)} tokens \xB7 ${o.accounts.length} wallets</div>
          <div class="conn-mirror-addrs">
            ${o.accounts.slice(0,8).map(i=>`
              <button class="addr-chip mono" data-addr="${g(i.addr)}" title="${g(i.addr)}">${g(U(i.addr))}</button>
            `).join("")}
            ${o.accounts.length>8?`<span class="conn-mirror-more">+${o.accounts.length-8} more</span>`:""}
          </div>
        </div>
      `).join("")}
    </div>`:""}
  `,a){let o=e.signals.some(i=>i.sev==="critical")?"crit":e.signals.some(i=>i.sev==="warn")?"warn":e.signals.some(i=>i.sev==="info")?"neutral":"ok";a.className=`section-badge section-badge--${o}`,a.textContent=s>0?`${e.holderCount} holders`:"No issuance"}}function hh(e){var c;let t=document.getElementById("inspect-fee-analysis-body");if(!t||!e)return;let n={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},s=(e.signals||[]).map(d=>`
    <div class="finding finding--${d.sev}">
      <span class="finding-sev ${n[d.sev]||""}">${d.sev.toUpperCase()}</span>
      <div class="finding-body">
        <div class="finding-label">${g(d.label)}</div>
        <div class="finding-detail">${g(d.detail)}</div>
      </div>
    </div>`).join(""),a=e.avgFeeMultiplier!=null?`
    <div class="wash-stat-row" style="margin-top:10px">
      <span>Average fee multiplier</span><span class="mono">${e.avgFeeMultiplier}x base (12 drops)</span>
    </div>
    <div class="wash-stat-row">
      <span>High-fee transactions (>100x)</span><span class="mono ${e.spikeCount>5?"risk-text-high":""}">${e.spikeCount}</span>
    </div>`:"",o=(c=e.topFeeHashes)!=null&&c.length?`
    <div style="margin-top:12px;font-size:.72rem;color:rgba(255,255,255,.4);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">TOP FEE TRANSACTIONS</div>
    ${e.topFeeHashes.map(d=>`
      <div class="wash-stat-row">
        <a href="https://livenet.xrpl.org/transactions/${g(d.hash)}" target="_blank" rel="noopener"
           class="mono" style="font-size:.75rem;color:var(--accent);text-decoration:none">${U(d.hash)}</a>
        <span class="mono" style="color:#ffb86c">${d.mult}x base fee</span>
      </div>`).join("")}`:"",i=document.getElementById("section-fee-analysis");if(!(e.signals||[]).some(d=>d.sev==="warn"||d.sev==="critical")){i&&(i.style.display="none");return}i&&(i.style.display=""),t.innerHTML=s+a+o;let l=document.getElementById("badge-fee-analysis");l&&(l.textContent="Elevated",l.className="section-badge section-badge--warn")}function gh(e){var c,d;let t=document.getElementById("inspect-desttag-body");if(!t||!e)return;let n={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},s=(e.signals||[]).map(u=>`
    <div class="finding finding--${u.sev}">
      <span class="finding-sev ${n[u.sev]||""}">${u.sev.toUpperCase()}</span>
      <div class="finding-body">
        <div class="finding-label">${g(u.label)}</div>
        <div class="finding-detail">${g(u.detail)}</div>
      </div>
    </div>`).join(""),a=(c=e.tagProfiles)!=null&&c.length?`
    <div style="margin-top:12px;font-size:.72rem;color:rgba(255,255,255,.4);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">DESTINATION TAG SUMMARY</div>
    ${e.tagProfiles.slice(0,8).map(u=>`
      <div class="wash-stat-row">
        <span>${g(u.name)}</span>
        <span class="mono" style="opacity:.65">${u.txCount} tx \xB7 ${u.uniqueTags} unique tag${u.uniqueTags!==1?"s":""}</span>
      </div>`).join("")}`:"",o=document.getElementById("section-desttag"),i=(e.signals||[]).some(u=>u.sev==="warn"||u.sev==="critical"),r=((d=e.tagProfiles)==null?void 0:d.length)>0;if(!i&&!r){o&&(o.style.display="none");return}o&&(o.style.display=""),t.innerHTML=s+a;let l=document.getElementById("badge-desttag");l&&(l.textContent=i?"Check":"Normal",l.className=`section-badge section-badge--${i?"warn":"ok"}`)}function vh(e){var r;let t=document.getElementById("section-pathdepth"),n=document.getElementById("inspect-pathdepth-body"),s=document.getElementById("badge-pathdepth");if(!e||e.noData||!((r=e.signals)!=null&&r.length)){t&&(t.style.display="none");return}if(t&&(t.style.display=""),!n)return;let a={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},o=e.signals.map(l=>`
    <div class="finding finding--${l.sev}">
      <span class="finding-sev ${a[l.sev]||""}">${l.sev.toUpperCase()}</span>
      <div class="finding-body">
        <div class="finding-label">${g(l.label)}</div>
        <div class="finding-detail">${g(l.detail)}</div>
      </div>
    </div>`).join(""),i=`
    <div class="wash-stat-row" style="margin-top:10px">
      <span>Total path payments</span><span class="mono">${e.roundTripCount+e.deepHopCount+(e.selfRoutedCount||0)+(e.signals.filter(l=>l.sev==="ok").length>0?1:0)}</span>
    </div>
    ${e.roundTripCount?`<div class="wash-stat-row"><span>XRP\u2192IOU\u2192XRP round-trips</span><span class="mono ${e.roundTripCount>=3?"risk-text-high":"risk-text-med"}">${e.roundTripCount}</span></div>`:""}
    ${e.deepHopCount?`<div class="wash-stat-row"><span>Deep hop chains (\u22653 hops)</span><span class="mono">${e.deepHopCount}</span></div>`:""}
    ${e.selfRoutedCount?`<div class="wash-stat-row"><span>Self-routed payments</span><span class="mono risk-text-high">${e.selfRoutedCount}</span></div>`:""}`;if(n.innerHTML=o+i,s){let l=e.signals.some(d=>d.sev==="critical"),c=e.signals.some(d=>d.sev==="warn");s.textContent=l?"Critical":c?"Check":"Normal",s.className=`section-badge section-badge--${l?"crit":c?"warn":"ok"}`}}function bh(e){var r,l,c;let t=y("inspect-inbound-body");if(!t)return;let n={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},s=(e.signals||[]).map(d=>`
    <div class="finding finding--${d.sev}">
      <span class="finding-sev ${n[d.sev]||""}">${d.sev.toUpperCase()}</span>
      <div class="finding-body"><div class="finding-label">${g(d.label)}</div>
      <div class="finding-detail">${g(d.detail)}</div></div>
    </div>`).join(""),a=`
    <div class="flow-summary" style="margin-top:10px">
      <div class="flow-stat"><span>Inbound payments</span><b>${((r=e.timeline)==null?void 0:r.length)||0}</b></div>
      <div class="flow-stat"><span>Unique sources</span><b>${e.uniqueSources}</b></div>
      <div class="flow-stat"><span>Total XRP received</span><b class="mono">${D(e.totalIn,2)}</b></div>
      <div class="flow-stat"><span>Exchange sources</span><b>${((l=e.exchangeSrcs)==null?void 0:l.length)||0}</b></div>
    </div>`,o=(c=e.topSources)!=null&&c.length?`
    <div class="flow-section-h" style="margin-top:14px">\u{1F4E5} Top Funding Sources</div>
    <div class="flow-dest-list">
      ${e.topSources.map((d,u)=>{let p=e.totalIn>0?(d.totalXrp/e.totalIn*100).toFixed(0):0,m=d.entity,f=m?`<span class="flow-entity-badge flow-entity--${m.type}">${g(m.name)}</span>`:"";return`<div class="flow-dest-row">
          <div class="flow-dest-rank">${u+1}</div>
          <div class="flow-dest-info">
            <div class="flow-dest-top">
              <a href="https://xrpscan.com/account/${g(d.addr)}" target="_blank" rel="noopener" class="addr-link mono cut">${g(U(d.addr))}</a>
              ${f}
            </div>
            <div class="flow-bar-row">
              <div class="flow-dest-bar"><div class="flow-dest-fill" style="width:${Math.min(100,p)}%;background:${(m==null?void 0:m.type)==="exchange"?"#00d4ff":"rgba(80,250,123,.7)"}"></div></div>
              <span class="mono flow-dest-pct">${p}%</span>
            </div>
            <div class="flow-dest-meta">
              <span class="mono">${D(d.totalXrp,2)} XRP${nn(d.totalXrp)}</span>
              <span class="flow-dest-cnt">${d.txCount} tx</span>
            </div>
          </div>
        </div>`}).join("")}
    </div>`:"";t.innerHTML=s+a+o;let i=y("badge-inbound");if(i){let d=(e.signals||[]).some(u=>u.sev==="warn"||u.sev==="critical");i.textContent=`${e.uniqueSources} src${e.uniqueSources!==1?"s":""}`,i.className=`section-badge section-badge--${d?"warn":"neutral"}`}}function yh(e){var r;let t=y("section-memos"),n=y("inspect-memos-body");if(!e||!((r=e.allMemos)!=null&&r.length)){t&&(t.style.display="none");return}if(t&&(t.style.display=""),!n)return;let s={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},a=(e.signals||[]).map(l=>`
    <div class="finding finding--${l.sev}">
      <span class="finding-sev ${s[l.sev]||""}">${l.sev.toUpperCase()}</span>
      <div class="finding-body"><div class="finding-label">${g(l.label)}</div>
      <div class="finding-detail">${g(l.detail)}</div></div>
    </div>`).join(""),o=e.allMemos.slice(0,10).map(l=>`
    <div class="wash-stat-row" style="flex-direction:column;align-items:flex-start;gap:2px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.05)">
      <div style="font-size:.72rem;color:rgba(255,255,255,.35)">${g(l.type)} \xB7 <a href="https://livenet.xrpl.org/transactions/${g(l.tx)}" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none">${U(l.tx)}</a></div>
      <div style="font-size:.82rem;word-break:break-all;color:rgba(255,255,255,.75)">${g(l.text.slice(0,120))}${l.text.length>120?"\u2026":""}</div>
    </div>`).join("");n.innerHTML=a+`<div style="margin-top:10px;font-size:.72rem;color:rgba(255,255,255,.4);text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px">MEMO CONTENTS (${e.allMemos.length} found)</div>`+o;let i=y("badge-memos");if(i){let l=(e.signals||[]).some(d=>d.sev==="critical"),c=(e.signals||[]).some(d=>d.sev==="warn");i.textContent=l?"Scam text":c?"Patterns":"Normal",i.className=`section-badge section-badge--${l?"crit":c?"warn":"ok"}`}}function wh(e){var l;let t=y("section-escrow-depth"),n=y("inspect-escrow-depth-body");if(!e||!((l=e.escrows)!=null&&l.length)){t&&(t.style.display="none");return}if(t&&(t.style.display=""),!n)return;let s={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},a=(e.signals||[]).map(c=>`
    <div class="finding finding--${c.sev}">
      <span class="finding-sev ${s[c.sev]||""}">${c.sev.toUpperCase()}</span>
      <div class="finding-body"><div class="finding-label">${g(c.label)}</div>
      <div class="finding-detail">${g(c.detail)}</div></div>
    </div>`).join(""),o=946684800,i=e.escrows.map(c=>`
    <div class="wash-stat-row">
      <span>${c.isSelfEscrow?"Self-escrow":c.isThirdParty?'<span style="color:#ff5555">Third-party \u2192</span>':U(c.dest||"")}</span>
      <span class="mono">${D(c.amtXrp,2)} XRP${nn(c.amtXrp)}</span>
      <span style="font-size:.72rem;opacity:.55">${c.daysToFinish!=null?c.daysToFinish<0?"matured":c.daysToFinish+"d":c.conditional?"conditional":"\u2014"}</span>
    </div>`).join("");n.innerHTML=a+`<div style="margin-top:10px">${i}</div>`;let r=y("badge-escrow-depth");if(r){let c=e.hasThirdParty;r.textContent=`${e.escrows.length} escrow${e.escrows.length!==1?"s":""}`,r.className=`section-badge section-badge--${c?"warn":"neutral"}`}}function xh(e){var r;let t=y("section-checks"),n=y("inspect-checks-body");if(!e||!((r=e.checks)!=null&&r.length)){t&&(t.style.display="none");return}if(t&&(t.style.display=""),!n)return;let s={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},a=(e.signals||[]).map(l=>`
    <div class="finding finding--${l.sev}">
      <span class="finding-sev ${s[l.sev]||""}">${l.sev.toUpperCase()}</span>
      <div class="finding-body"><div class="finding-label">${g(l.label)}</div>
      <div class="finding-detail">${g(l.detail)}</div></div>
    </div>`).join(""),o=e.checks.map(l=>{var c,d;return`
    <div class="wash-stat-row">
      <span class="mono">${U(l.sender)} \u2192 ${U(l.dest||"")}</span>
      <span class="mono">${l.amtXrp!=null?D(l.amtXrp,2)+" XRP"+nn(l.amtXrp):(((c=l.amtToken)==null?void 0:c.value)||"?")+" "+((d=l.amtToken)==null?void 0:d.currency)}</span>
      <span style="font-size:.72rem;${l.expired?"color:#ff5555":"opacity:.55"}">${l.expired?"Expired":"Open"}</span>
    </div>`}).join("");n.innerHTML=a+`<div style="margin-top:10px">${o}</div>`;let i=y("badge-checks");i&&(i.textContent=`${e.checks.length} check${e.checks.length!==1?"s":""}`,i.className="section-badge section-badge--neutral")}function kh(e){let t=y("section-livebook"),n=y("inspect-livebook-body");if(!(e!=null&&e.hasData)){t&&(t.style.display="none");return}if(t&&(t.style.display=""),!n)return;let s={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},a=(e.signals||[]).map(r=>`
    <div class="finding finding--${r.sev}">
      <span class="finding-sev ${s[r.sev]||""}">${r.sev.toUpperCase()}</span>
      <div class="finding-body"><div class="finding-label">${g(r.label)}</div>
      <div class="finding-detail">${g(r.detail)}</div></div>
    </div>`).join(""),o=`
    <div class="wash-stat-row" style="margin-top:10px">
      <span>Pair</span><span class="mono">${g(e.pair.split("\u2194").map(r=>r.split("+")[0]).join(" \u2194 "))}</span>
    </div>
    <div class="wash-stat-row">
      <span>Live orders in book</span><span class="mono">${e.offerCount}</span>
    </div>
    ${e.ourShare>0?`<div class="wash-stat-row"><span>This wallet's book share</span><span class="mono ${e.ourShare>.25?"risk-text-high":""}">${(e.ourShare*100).toFixed(1)}%</span></div>`:""}
    ${e.wallShare>.3?`<div class="wash-stat-row"><span>Largest single order share</span><span class="mono ${e.wallShare>.4?"risk-text-high":"risk-text-med"}">${(e.wallShare*100).toFixed(1)}%</span></div>`:""}`;n.innerHTML=a+o;let i=y("badge-livebook");if(i){let r=(e.signals||[]).some(c=>c.sev==="critical"),l=(e.signals||[]).some(c=>c.sev==="warn");i.textContent=r?"Wall order":l?"Check":"Normal",i.className=`section-badge section-badge--${r?"crit":l?"warn":"ok"}`}}function $h(e,...t){let n=y("inspect-risk-breakdown");if(!n)return;let s=Gf(e,...t);if(!s.length){n.innerHTML="";return}let a=Math.max(1,s.reduce((o,i)=>o+i.pts,0));n.innerHTML=`
    <div style="margin-top:8px">
      <div style="font-size:.65rem;color:rgba(255,255,255,.35);text-transform:uppercase;letter-spacing:.1em;margin-bottom:5px">Score Breakdown</div>
      <div style="display:flex;height:8px;border-radius:4px;overflow:hidden;gap:1px">
        ${s.map(o=>`<div style="flex:${o.pts};background:${o.color};opacity:.85" title="${g(o.label)}: ${o.pts} pts"></div>`).join("")}
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px">
        ${s.map(o=>`<span style="font-size:.67rem;color:${o.color};opacity:.8">${o.icon} ${g(o.label)} ${o.pts}pts</span>`).join("")}
      </div>
    </div>`}function wn({sev:e,label:t,detail:n}){return`
    <div class="audit-row audit-row--${e}">
      <span class="audit-icon">${{ok:"\u2713",info:"\u2139",warn:"\u26A0",critical:"\u26D4"}[e]||"\u2139"}</span>
      <div class="audit-text">
        <div class="audit-label">${g(t)}</div>
        ${n?`<div class="audit-detail">${g(n)}</div>`:""}
      </div>
    </div>`}function To(e){return e<20?"risk-ok":e<45?"risk-medium":e<70?"risk-high":"risk-critical"}function Sh(e,t,n){if(ff.has(e.TransactionType))return"warn";if(e.TransactionType==="NFTokenCreateOffer"){let s=e.Amount;if(!s||typeof s=="string"&&Number(s)<1e6)return"critical"}return t!=null&&t.TransactionResult&&t.TransactionResult!=="tesSUCCESS"?"fail":"normal"}function Th(e,t){var s,a,o,i,r;let n=e.TransactionType;if(n==="Payment"){let l=e.Account===t?`\u2192 ${U(e.Destination)}`:`\u2190 ${U(e.Account)}`,c=typeof e.Amount=="string"?`${D(Number(e.Amount)/1e6,2)} XRP`:(s=e.Amount)!=null&&s.value?`${D(Number(e.Amount.value),2)} ${e.Amount.currency}`:"";return g(`${c} ${l}`)}if(n==="OfferCreate"){let l=typeof e.TakerPays=="string"?`${D(Number(e.TakerPays)/1e6,2)} XRP`:`${D(Number((a=e.TakerPays)==null?void 0:a.value),2)} ${(o=e.TakerPays)==null?void 0:o.currency}`,c=typeof e.TakerGets=="string"?`${D(Number(e.TakerGets)/1e6,2)} XRP`:`${D(Number((i=e.TakerGets)==null?void 0:i.value),2)} ${(r=e.TakerGets)==null?void 0:r.currency}`;return g(`${l} for ${c}`)}return n==="SetRegularKey"?g(`Key: ${e.RegularKey?U(e.RegularKey):"REMOVED"}`):n==="NFTokenMint"?g(`Taxon: ${e.NFTokenTaxon??"\u2014"}`):n==="NFTokenBurn"?g(`Token: ${e.NFTokenID?U(e.NFTokenID):"\u2014"}`):n==="AMMDeposit"?g("Pool deposit"):n==="AMMWithdraw"?g("LP withdrawal"):n==="EscrowCreate"?g(`${D(Number(e.Amount||0)/1e6,2)} XRP \u2192 ${U(e.Destination)}`):""}function Ch(e){return{Payment:"payment",OfferCreate:"offer",OfferCancel:"offer",NFTokenMint:"nft",NFTokenBurn:"nft",NFTokenCreateOffer:"nft",NFTokenAcceptOffer:"nft",SetRegularKey:"auth",SignerListSet:"auth",AccountSet:"auth",AccountDelete:"auth",TrustSet:"trust",AMMCreate:"amm",AMMDeposit:"amm",AMMWithdraw:"amm",AMMVote:"amm",AMMBid:"amm",EscrowCreate:"escrow",EscrowFinish:"escrow",EscrowCancel:"escrow",PaymentChannelCreate:"channel",PaymentChannelFund:"channel",PaymentChannelClaim:"channel"}[e]||"other"}function Pt(e){let t=(e==null?void 0:e.date)||(e==null?void 0:e.close_time)||(e==null?void 0:e.ledger_close_time);return t?Number(t)+gf:0}function yn(e){if(!e||e.length!==40)return e||"";try{let t="";for(let n=0;n<e.length;n+=2){let s=parseInt(e.slice(n,n+2),16);if(s!==0){if(s<32||s>126)return e;t+=String.fromCharCode(s)}}return t||e}catch{return e}}function Lh(e,t,n,s,a,o,i,r,l,c,d,u,p,m,f,v,h,w,k,b={}){var Ut,Hs,_i,Ri,Di,Ii,Fi,Bi,Oi,Xi,Hi,zi,Ui;let{feeAnalysis:x=null,destTagAnalysis:S=null,pathDepthAnalysis:T=null,gatewayBalances:$=null,inboundFlowAnalysis:P=null,memoAnalysis:M=null,escrowDepthAnalysis:N=null,checkAnalysis:_=null,liveBookAnalysis:X=null,walletAgeDays:I=null,walletCreatedTs:R=null}=b,F=946684800,W=new Date().toLocaleString(),E=e.slice(0,10)+"\u2026"+e.slice(-8),z=s<20?"LOW":s<45?"MODERATE":s<70?"HIGH":"CRITICAL",Q=s<20?"#50fa7b":s<45?"#ffb86c":s<70?"#ff8c42":"#ff5555",ie=f.filter(({tx:A})=>A.date!=null),ce=f.length.toLocaleString()+" transactions",de="",se=0;if(ie.length>=2){let A=ie[0].tx.date+F,Le=ie[ie.length-1].tx.date+F;se=Math.round((Le-A)/86400);let Wt=new Date(A*1e3).toLocaleDateString("en-US",{year:"numeric",month:"short",day:"numeric"}),Ye=new Date(Le*1e3).toLocaleDateString("en-US",{year:"numeric",month:"short",day:"numeric"});de=`${Wt} \u2013 ${Ye} (${se} days)`,ce=`${f.length.toLocaleString()} transactions from ${de}`}let fe=[],K=(A,Le,Wt,Ye,En)=>fe.push({module:A,sev:Le,headline:Wt,detail:Ye||"",hashes:En||[]});for(let A of a.findings||[])K("Security",A.sev,A.label,A.detail);K("Drain Risk",o.riskLevel==="low"?"ok":o.riskLevel==="medium"?"warn":"critical","Drain Risk Level: "+o.riskLevel.toUpperCase(),null);for(let A of o.signals||[])A.sev!=="ok"&&K("Drain Risk",A.sev,A.label,A.detail,A.hashes);for(let A of i.flags||[])A.sev!=="ok"&&K("NFT",A.sev,A.label,A.detail,A.hashes);r.verdict&&!["clean","low-risk"].includes(r.verdict)&&K("Wash Trading",r.score>=60?"critical":"warn",`Wash score ${r.score}/100 \u2014 ${r.verdict.replace("-"," ")}`,null);for(let A of r.signals||[])A.sev!=="ok"&&K("Wash Trading",A.sev,A.label,A.detail);for(let A of l.signals||[])A.sev!=="ok"&&K("Benford's Law",A.sev,A.label,A.detail);for(let A of c.signals||[])A.sev!=="ok"&&K("Volume Concentration",A.sev,A.label,A.detail);for(let A of(v==null?void 0:v.signals)||[])A.sev!=="ok"&&K("Shannon's Entropy",A.sev,A.label,A.detail);for(let A of(h==null?void 0:h.signals)||[])A.sev!=="ok"&&K("Zipf's Law",A.sev,A.label,A.detail);for(let A of(w==null?void 0:w.signals)||[])A.sev!=="ok"&&K("Time Series",A.sev,A.label,A.detail);for(let A of(k==null?void 0:k.signals)||[])A.sev!=="ok"&&K("Granger Causality",A.sev,A.label,A.detail);for(let A of d.signals||[])A.sev!=="ok"&&K("Token Issuer",A.sev,A.label,A.detail);for(let A of u.signals||[])A.sev!=="ok"&&K("AMM",A.sev,A.label,A.detail);(Ut=p.blackHoleDests)!=null&&Ut.length&&K("Fund Flow","critical",`Funds sent to ${p.blackHoleDests.length} black hole address(es)`,"These funds are permanently irrecoverable."),(Hs=p.exchangeDests)!=null&&Hs.length&&K("Fund Flow","warn",`${p.exchangeDests.length} known exchange(s) received funds`,p.exchangeDests.map(A=>A.entity.name).join(", ")),(_i=p.newWalletDests)!=null&&_i.length&&K("Fund Flow","critical",`${p.newWalletDests.length} brand-new wallet(s) received large XRP transfers`,"New wallets (Sequence < 10) receiving large amounts are a classic drain-mule pattern.");for(let A of m.signals||[])A.sev!=="ok"&&K("Issuer Connections",A.sev,A.label,A.detail);for(let A of(x==null?void 0:x.signals)||[])A.sev!=="ok"&&K("Fee Spikes",A.sev,A.label,A.detail,A.hashes);for(let A of(S==null?void 0:S.signals)||[])A.sev!=="ok"&&K("Destination Tags",A.sev,A.label,A.detail);for(let A of(T==null?void 0:T.signals)||[])A.sev!=="ok"&&K("Path Payments",A.sev,A.label,A.detail,A.hashes);for(let A of(P==null?void 0:P.signals)||[])A.sev!=="ok"&&K("Inbound Flow",A.sev,A.label,A.detail);for(let A of(M==null?void 0:M.signals)||[])A.sev!=="ok"&&K("Memo Analysis",A.sev,A.label,A.detail);for(let A of(N==null?void 0:N.signals)||[])A.sev!=="ok"&&K("Escrow Depth",A.sev,A.label,A.detail);for(let A of(X==null?void 0:X.signals)||[])A.sev!=="ok"&&K("Live Order Book",A.sev,A.label,A.detail);let xe=fe.filter(A=>A.sev==="critical"),B=fe.filter(A=>A.sev==="warn");window._lastAllFindings=fe;let J=A=>{let Le={critical:"background:rgba(255,85,85,.15);border:1px solid rgba(255,85,85,.35);color:#ff5555",warn:"background:rgba(255,184,108,.10);border:1px solid rgba(255,184,108,.30);color:#ffb86c",info:"background:rgba(120,180,255,.08);border:1px solid rgba(120,180,255,.18);color:rgba(120,180,255,.9)",ok:"background:rgba(80,250,123,.08);border:1px solid rgba(80,250,123,.22);color:#50fa7b"};return`<span style="padding:2px 8px;border-radius:999px;font-size:.68rem;font-weight:900;letter-spacing:.3px;text-transform:uppercase;${Le[A]||Le.info}">${A.toUpperCase()}</span>`};function re(){var Ye,En,rs,cn,Wi,ji,qi,Vi,Gi,Ki,Ji,Yi;let A=[];A.push(`<strong>Address ${E}</strong> was inspected on ${W}. The account holds <strong>${D(n,4)} XRP</strong>. This report analyzed <strong>${ce}</strong>, plus all open on-chain objects (escrows, payment channels, trustlines, NFTs, AMM positions). The overall risk score is <strong style="color:${Q}">${s}/100 \u2014 ${z}</strong>. <em style="opacity:.7">Risk scores reflect statistical patterns \u2014 not legal proof. A high score means unusual patterns were detected. Always verify before drawing conclusions.</em>`),xe.length&&A.push(`\u26A0\uFE0F The scan found <strong>${xe.length} critical issue${xe.length>1?"s":""}</strong> and <strong>${B.length} warning${B.length!==1?"s":""}</strong> \u2014 explained in plain English below.`);{let Me=o.riskLevel==="critical"||o.riskLevel==="high",rt=((Ye=p.newWalletDests)==null?void 0:Ye.length)>0,zs=((En=p.blackHoleDests)==null?void 0:En.length)>0,Us=r.score>=60,Xa=(x==null?void 0:x.verdict)==="elevated",Ha=[l.verdict==="high-deviation",(v==null?void 0:v.verdict)==="anomalous",(h==null?void 0:h.verdict)==="anomalous"||(h==null?void 0:h.verdict)==="elevated",(w==null?void 0:w.verdict)==="bot-pattern",(k==null?void 0:k.verdict)==="causal-signal"].filter(Boolean).length>=2,dn=null;if(Me&&rt)dn="The key change and the transfers to freshly-created wallets aren't separate concerns \u2014 together they're the specific sequence a drain follows: take control of signing, then move funds somewhere that isn't the attacker's known address.";else if(Me&&zs)dn="A compromised-looking key change followed by funds reaching an address nobody controls is consistent with a drain where the funds are gone rather than just moved.";else if(Us&&Xa)dn="The order-cancellation pattern and the fee spikes reinforce each other: overpaying fees to guarantee same-ledger execution is how the cancel-before-fill pattern gets coordinated with a counterparty.";else if(Us&&Ha)dn="This isn't just one statistical test disagreeing with the others \u2014 the wash-trading signal from actual order behavior and the independent mathematical tests are pointing at the same conclusion from two different directions.";else if(xe.length+B.length>=3){let za=[...new Set(xe.concat(B).map(gu=>gu.module))];dn=`${za.length} different analysis categories flagged this account (${za.slice(0,4).join(", ")}${za.length>4?", \u2026":""}) \u2014 any one alone could be circumstantial, but that many independent methods agreeing is the stronger signal here.`}dn&&A.push(`<strong>\u{1F9E9} How these findings fit together:</strong> ${dn}`)}if(o.riskLevel==="critical"?A.push(`<span style="color:#ff5555"><strong>\u{1F6A8} WALLET DRAIN RISK \u2014 CRITICAL</strong></span><br><strong>What was found:</strong> The account's security structure matches a known attack pattern \u2014 the master signing key has been disabled and replaced with a different key.<br><strong>What it means in plain English:</strong> If you did not personally do this, your wallet may have been taken over. An attacker who controls the replacement key can drain every XRP and token from the account.<br><strong>What to do right now:</strong> Stop sending any funds to this address. If it's your wallet, contact a security professional immediately.`):o.riskLevel==="high"&&A.push("<strong>\u26A0\uFE0F Elevated Drain Risk:</strong> Unusual security patterns found \u2014 possibly a key change followed by large outflows. See the Drain Risk section for exact transactions."),(rs=p.newWalletDests)!=null&&rs.length&&A.push(`<strong>\u{1F195} Brand-New Receiving Wallets:</strong> ${p.newWalletDests.length} of the top destinations are freshly-created wallets (fewer than 10 lifetime transactions) that received significant XRP. Creating a new disposable wallet to receive drained funds \u2014 then disappearing \u2014 is the most common drain attack pattern on XRPL.`),(cn=p.blackHoleDests)!=null&&cn.length&&A.push('<span style="color:#ff5555"><strong>\u{1F573} Funds Sent to Uncontrolled Address:</strong></span> Some XRP reached a "black hole" \u2014 an address nobody controls. <strong>These funds cannot be recovered by anyone.</strong>'),(Wi=p.exchangeDests)!=null&&Wi.length){let Me=[...new Set(p.exchangeDests.map(rt=>rt.entity.name))].join(", ");A.push(`<strong>\u{1F4B1} Exchange Activity:</strong> Funds reached known exchange(s): <strong>${Me}</strong>. Total outflow tracked: ${D(p.totalOut,2)} XRP to ${p.uniqueDests} destination(s). This is often normal \u2014 people cash out to exchanges. It becomes a concern when combined with the security or timing signals above.`)}else p.totalOut>0&&A.push(`<strong>Outbound payments:</strong> ${D(p.totalOut,2)} XRP sent to ${p.uniqueDests} destination(s). None matched known exchange addresses.`);if(r.score>=60){let Me=r.stats,rt=Me.creates>0?(Me.cancels/Me.creates*100).toFixed(0):0;A.push(`<strong>\u{1F4CA} Wash Trading Signals (Score: ${r.score}/100 \u2014 ${r.verdict.replace("-"," ").toUpperCase()}):</strong><br><strong>What was found:</strong> Out of ${Me.creates} DEX offers placed, ${Me.cancels} (${rt}%) were cancelled before filling. Only ${Me.fills} actually filled.`+(Me.selfTrades>0?` ${Me.selfTrades} payment(s) were sent from and back to the same address.`:"")+"<br><strong>What it means:</strong> Placing orders and cancelling them before they fill inflates a token's visible trading activity without any real buying or selling. It makes a thin market look active to attract other traders.<br><strong>Caveat:</strong> Legitimate market makers do cancel many orders as prices move. This finding is strongest when combined with the self-trade and fee-spike signals.")}else r.score>=30?A.push(`<strong>Moderate trading signals</strong> (score ${r.score}/100): Some DEX patterns look unusual but not conclusive alone. See Wash Trading section for specifics.`):A.push(`<strong>\u2705 DEX activity looks normal</strong> (wash score ${r.score}/100). Cancel ratios, fill rates, and trade sizes are within organic ranges.`);(T==null?void 0:T.selfRoutedCount)>0&&A.push(`<strong>\u{1F504} Self-Routing Path Payments:</strong> ${T.selfRoutedCount} payment(s) where the sender and destination are the same address. Routing XRP through the DEX back to yourself creates trading volume on every intermediate pair with no net economic transfer \u2014 a DEX-specific wash trading technique that's harder to detect than simple self-trades.`),(T==null?void 0:T.roundTripCount)>=3&&A.push(`<strong>XRP\u2192IOU\u2192XRP round-trips:</strong> ${T.roundTripCount} path payments paid and received XRP through intermediate token pairs \u2014 generating DEX volume without changing economic position.`),(x==null?void 0:x.verdict)==="elevated"&&A.push(`<strong>\u{1F4B8} Fee Spike Pattern:</strong> ${x.spikeCount} transaction(s) paid more than 100\xD7 the normal fee. Bots often overpay fees to guarantee same-ledger execution alongside a counterparty \u2014 a coordination technique used in wash trading and front-running. Organic users almost never need fees this high.`);let Le=[l.verdict==="high-deviation",(v==null?void 0:v.verdict)==="anomalous",(h==null?void 0:h.verdict)==="anomalous"||(h==null?void 0:h.verdict)==="elevated",(w==null?void 0:w.verdict)==="bot-pattern",(k==null?void 0:k.verdict)==="causal-signal"].filter(Boolean).length;if(Le>=3?A.push(`<strong>\u{1F52C} Statistical Analysis \u2014 Multiple Engines Agree:</strong><br>${Le} out of 5 independent mathematical tests found patterns inconsistent with human organic activity. These tests each use different mathematical approaches (number patterns, information theory, power laws, timing, causality) so they can't all be false alarms from the same data artifact.<br><strong>What it means:</strong> When unrelated statistical methods all flag the same account, the probability that all findings are coincidental false positives drops dramatically. This strongly suggests automated or coordinated activity, though it's not proof of fraud.`):Le>=2?A.push(`<strong>Statistical analysis:</strong> ${Le}/5 tests flagged unusual patterns. Multiple independent tests agreeing is a meaningful signal \u2014 see the Forensic Suite section.`):Le===1?A.push("<strong>Statistical analysis:</strong> 1/5 tests flagged an unusual pattern. A single flag is a hypothesis to investigate further, not a conclusion."):f.length>=30&&A.push(`<strong>\u2705 All statistical tests normal:</strong> Benford's Law, entropy, Zipf's Law, time series, and Granger causality all returned results consistent with organic activity across ${f.length} transactions.`),l.verdict==="high-deviation"&&l.chiSq!=null&&A.push(`<strong>Benford's Law detail (\u03C7\xB2=${l.chiSq.toFixed(1)}):</strong> In real financial data, "1" appears as the first digit ~30% of the time and "9" only ~4.6%. Computer-generated amounts break this pattern. This wallet's amounts deviate significantly (\u03C7\xB2=${l.chiSq.toFixed(1)} exceeds the 99% confidence threshold of 20.09).`),m.totalIssued>0){let Me=(ji=m.topHolders)==null?void 0:ji[0],rt=Me?(Me.balance/m.totalIssued*100).toFixed(0):null,zs=(qi=$==null?void 0:$.result)!=null&&qi.obligations?Object.values($.result.obligations).reduce((Xa,Ha)=>Xa+Number(Ha),0):null,Us=zs?` (verified via gateway_balances: ${D(zs,0)} total obligations)`:"";A.push(`<strong>\u{1FA99} Token Issuance:</strong> This account has issued tokens \u2014 <strong>${D(m.totalIssued,0)} outstanding</strong> across ${m.holderCount} holder(s)${Us}. `+(rt?`The largest single holder controls <strong>${rt}% of supply</strong>. `:"")+(rt&&Number(rt)>50?"Holding more than half the supply means one wallet could dump and collapse the token price. ":"")+((Vi=m.mirrorGroups)!=null&&Vi.length?`<strong>${m.mirrorGroups.length} cluster(s)</strong> of wallets each received identical token amounts \u2014 possible coordinated/insider wallets. `:"")+((Gi=m.createdAccts)!=null&&Gi.length?`This issuer also created ${m.createdAccts.length} wallet(s) \u2014 they may be controlled by the same entity. `:""))}let Wt=(i.flags||[]).filter(Me=>Me.sev==="critical");if(Wt.length&&A.push(`<strong>\u{1F3A8} NFT Risk:</strong> ${Wt.length} critical NFT issue(s) \u2014 most commonly a zero-price sell offer. The most common XRPL NFT scam: a malicious dApp tricks the wallet owner into signing a transaction that creates a sell offer for 0 XRP, making the NFT free for anyone to take.`),P!=null&&P.structuredFlag)A.push(`<strong>\u{1F4E5} Structured Inbound Pattern:</strong> ${P.uniqueSources} source(s) funded this wallet \u2014 many payments arrive at near-identical amounts. Structured deposits deliberately break large transfers into smaller equal amounts to reduce traceability.`);else if((Ki=P==null?void 0:P.exchangeSrcs)!=null&&Ki.length){let Me=[...new Set(P.exchangeSrcs.map(rt=>rt.entity.name))].join(", ");A.push(`<strong>\u{1F4E5} Funding Sources:</strong> Wallet received funds from ${P.uniqueSources} source(s) \u2014 ${Me} among them. Total inbound: ${D(P.totalIn,2)} XRP.`)}return(Ji=M==null?void 0:M.scamMemos)!=null&&Ji.length&&A.push(`<strong>\u{1F4DD} Scam Memo Content Detected:</strong> ${M.scamMemos.length} transaction memo(s) contain text matching known scam patterns (airdrop claims, wallet verification requests, urgency language). These payments were likely sent by attackers attempting social engineering.`),(Yi=X==null?void 0:X.signals)!=null&&Yi.some(Me=>Me.sev==="critical")&&A.push("<strong>\u{1F4D6} Active Spoofing Detected Right Now:</strong> This wallet currently has an order that controls over 40% of the visible order book depth. Large orders placed without intent to fill \u2014 then quickly cancelled when approached \u2014 is spoofing. This is happening in the live order book at time of inspection."),(S==null?void 0:S.riskPenalty)>0&&A.push("<strong>\u{1F3F7} Destination Tag Pattern:</strong> Payments to exchanges used an unusually wide variety of destination tags \u2014 each tag identifies a different customer account. This can indicate a service routing payments to many accounts, or deliberate spread of deposits across exchange accounts to reduce traceability."),xe.length===0&&B.length===0&&A.push(`<span style="color:#50fa7b"><strong>\u2705 No Elevated Signals Found</strong></span><br>All checks returned results within normal ranges across ${ce}. This does not guarantee the account is trustworthy \u2014 it means no identifiable red flags were found in the data analyzed.`),f.length<100&&A.push(`<em style="opacity:.6;font-size:.86em">Data coverage: ${ce}. Fewer than 100 transactions means some statistical tests above may not reach reliable conclusions \u2014 treat those specifically as weaker signal.</em>`),A}let pe={Security:{icon:"\u{1F510}",desc:"Keys, flags, multisig, auth changes"},"Drain Risk":{icon:"\u26A0\uFE0F",desc:"Auth changes \u2192 large outflows, external key injection"},"Fund Flow":{icon:"\u{1F30A}",desc:"Exchange flows, black holes, new-wallet recipients, path routing"},NFT:{icon:"\u{1F3A8}",desc:"Zero-value offers, no-metadata tokens, burns"},"Wash Trading":{icon:"\u{1F4CA}",desc:"Cancel ratios, self-trades, order uniformity, burst patterns"},"Benford's Law":{icon:"\u{1F4D0}",desc:"First-digit natural distribution test on all amounts"},"Volume Concentration":{icon:"\u{1FAE7}",desc:"How many wallets drive token trading volume"},"Shannon's Entropy":{icon:"\u{1F500}",desc:"Randomness of amounts, counterparties, timing, tx types"},"Zipf's Law":{icon:"\u{1F4C8}",desc:"Counterparty frequency power-law distribution"},"Time Series":{icon:"\u{1F550}",desc:"Interval regularity, periodicity \u2014 bot vs human timing"},"Granger Causality":{icon:"\u{1F517}",desc:"Create\u2192cancel cycles, inflow\u2192outflow cycling"},"Token Issuer":{icon:"\u{1FA99}",desc:"Supply, freeze state, concentration"},AMM:{icon:"\u{1F4A7}",desc:"LP positions, pool TVL, ownership share"},"Issuer Connections":{icon:"\u{1F578}",desc:"Distribution patterns, mirror wallets, account creation chains"},"Fee Spikes":{icon:"\u{1F4B8}",desc:"Elevated fee transactions \u2014 coordination signal"},"Destination Tags":{icon:"\u{1F3F7}",desc:"Exchange sub-account routing patterns"},"Path Payments":{icon:"\u{1F504}",desc:"Circular routing, self-routing, deep-hop obfuscation"},"Inbound Flow":{icon:"\u{1F4E5}",desc:"Funding sources, exchange deposits, structured inbound patterns"},"Memo Analysis":{icon:"\u{1F4DD}",desc:"Scam patterns, coordination text, hex-decoded memo data"},"Escrow Depth":{icon:"\u{1F512}",desc:"Third-party escrows, maturity dates, conditional locks"},"Live Order Book":{icon:"\u{1F4D6}",desc:"Current spoofing detection \u2014 wall orders, book depth concentration"}},Se=["Security","Drain Risk","Fund Flow","NFT","Wash Trading","Benford's Law","Volume Concentration","Shannon's Entropy","Zipf's Law","Time Series","Granger Causality","Token Issuer","AMM","Issuer Connections","Fee Spikes","Destination Tags","Path Payments"],ge={};for(let A of Se)ge[A]=fe.filter(Le=>Le.module===A&&Le.sev!=="ok"&&Le.sev!=="info");let ot=Se.filter(A=>ge[A].length>0).map(A=>{let Le=pe[A]||{icon:"\u{1F4CB}",desc:""},Wt=ge[A].map(Ye=>{var rs;let En=(rs=Ye.hashes)!=null&&rs.length?`
          <div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:6px">
            ${Ye.hashes.slice(0,5).map(cn=>`
              <a href="https://livenet.xrpl.org/transactions/${g(cn)}" target="_blank" rel="noopener"
                 style="font-size:.7rem;font-family:monospace;color:var(--accent);text-decoration:none;
                        background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.2);
                        border-radius:4px;padding:2px 6px" title="${g(cn)}">
                ${cn.slice(0,8)}\u2026${cn.slice(-4)} \u{1F517}
              </a>`).join("")}
          </div>`:"";return`
          <div class="report-finding-row">
            <div class="report-finding-top">
              ${J(Ye.sev)}
              <span class="report-finding-headline">${g(Ye.headline)}</span>
            </div>
            ${Ye.detail?`<div class="report-finding-detail">${g(Ye.detail)}</div>`:""}
            ${En}
          </div>`}).join("");return`
        <div class="report-module">
          <div class="report-module-h">
            <span style="margin-right:6px">${Le.icon}</span>${g(A)}
            <span style="font-size:.72rem;font-weight:400;opacity:.45;margin-left:8px">${g(Le.desc)}</span>
          </div>
          ${Wt}
        </div>`}).join(""),it=[{k:"Address",v:e,mono:!0},{k:"Balance",v:D(n,4)+" XRP"+nn(n),mono:!0},{k:"Wallet Age",v:I!=null?(I<1?"Created today":I+" days")+(R?" \u2014 created "+new Date(R).toLocaleDateString("en-US",{year:"numeric",month:"short",day:"numeric"}):""):"\u2014"},{k:"Risk Score",v:s+"/100 \u2014 "+z,color:Q},{k:"Transactions Analyzed",v:f.length+(de?" \xB7 "+de:"")},{k:"Activity Span",v:se>0?se+" days":"unknown"},{k:"Outbound Destinations",v:p.uniqueDests+" addresses received funds"},{k:"Total XRP Sent Out",v:D(p.totalOut,2)+" XRP",mono:!0},{k:"New-Wallet Recipients",v:(((Ri=p.newWalletDests)==null?void 0:Ri.length)||0)+((Di=p.newWalletDests)!=null&&Di.length?" \u26A0":" \u2014 none"),color:(Ii=p.newWalletDests)!=null&&Ii.length?"#ff5555":null},{k:"Wash Trading Score",v:(r.score||0)+"/100 \u2014 "+(r.verdict||"\u2014").replace("-"," ")+(r.score<25?" \u2713":r.score<50?" \u26A0 moderate":" \u{1F6A8} elevated")},{k:"Fee Spike Count (>100\xD7 base)",v:((x==null?void 0:x.spikeCount)??"N/A")+((x==null?void 0:x.spikeCount)>5?" \u26A0":""),mono:!0},{k:"Benford \u03C7\xB2 (normal \u2264 15.5)",v:l.chiSq!=null?l.chiSq.toFixed(2)+" \u2014 "+l.verdict.replace("-"," "):"insufficient data",mono:!0},{k:"Amount Entropy (natural 2.4\u20134.2)",v:(v==null?void 0:v.amountEntropy)!=null?v.amountEntropy.toFixed(2)+" bits":"N/A",mono:!0},{k:"Zipf Exponent (natural 0.8\u20131.3)",v:(h==null?void 0:h.zipfExponent)!=null?h.zipfExponent.toFixed(3)+"  R\xB2="+((Fi=h.rSquared)==null?void 0:Fi.toFixed(2)):"N/A",mono:!0},{k:"Timing Regularity CV (bot < 0.25)",v:(w==null?void 0:w.intervalCV)!=null?w.intervalCV.toFixed(3)+(w.intervalCV<.25?" \u26A0 bot-level":" \u2713"):"N/A",mono:!0},{k:"Granger OC Correlation",v:((Bi=k==null?void 0:k.offerCancelCausality)==null?void 0:Bi.maxCorr)!=null?k.offerCancelCausality.maxCorr.toFixed(3)+(k.offerCancelCausality.maxCorr>.55?" \u26A0":" \u2713"):"N/A",mono:!0},{k:"XRP\u2192IOU\u2192XRP Round-Trips",v:((T==null?void 0:T.roundTripCount)??0)+((T==null?void 0:T.roundTripCount)>=3?" \u26A0":""),mono:!0},{k:"Token Holders",v:m.holderCount>0?m.holderCount+" wallets hold tokens from this issuer":"Not a token issuer"},{k:"Critical Findings",v:xe.length+(xe.length===0?" \u2014 none":""),color:xe.length>0?"#ff5555":"#50fa7b"},{k:"Warnings",v:B.length+(B.length===0?" \u2014 none":""),color:B.length>0?"#ffb86c":"#50fa7b"}].map(A=>`
    <div class="report-stat-row">
      <span class="report-stat-k">${g(A.k)}</span>
      <span class="report-stat-v ${A.mono?"mono":""}" style="${A.color?"color:"+A.color:""}">${g(String(A.v))}</span>
    </div>`).join(""),Ce={critical:"rgba(255,85,85,.08)",warn:"rgba(255,184,108,.06)",info:"rgba(120,180,255,.05)",ok:"rgba(80,250,123,.05)"},ue={critical:"rgba(255,85,85,.25)",warn:"rgba(255,184,108,.20)",info:"rgba(120,180,255,.15)",ok:"rgba(80,250,123,.15)"},H=[];(o.riskLevel==="critical"||o.riskLevel==="high")&&H.push({icon:"\u{1F534}",sev:"critical",text:"If this is your wallet: stop sending funds here immediately. The account's security keys match a known drain attack pattern. Contact a security professional or the XRPL community before taking any action."}),(Oi=p.newWalletDests)!=null&&Oi.length&&H.push({icon:"\u26A0\uFE0F",sev:"critical",text:`${p.newWalletDests.length} brand-new wallet(s) received large XRP transfers. This is a classic drain pattern. If this was unexpected, the funds have likely already been moved further down the chain.`}),(Xi=p.blackHoleDests)!=null&&Xi.length&&H.push({icon:"\u26D4",sev:"critical",text:"Funds sent to black hole addresses are gone permanently. No exchange, no support team, and no legal action can retrieve them."}),(Hi=p.exchangeDests)!=null&&Hi.length&&H.push({icon:"\u{1F4B1}",sev:"warn",text:`If this was a drain: contact ${[...new Set(p.exchangeDests.map(A=>A.entity.name))].join(", ")} exchange support immediately with the transaction hashes from the Fund Flow section. Act within hours \u2014 exchanges can sometimes freeze funds quickly but not after they've been withdrawn.`}),r.score>=60&&H.push({icon:"\u{1F4CA}",sev:"warn",text:"Significant wash trading signals detected. If you're a market maker: high cancel ratios are normal for your role \u2014 review the self-trade and self-routing signals specifically. If you're a token holder or researcher: this pattern suggests the token's apparent volume may be artificial."}),(T==null?void 0:T.selfRoutedCount)>0&&H.push({icon:"\u{1F504}",sev:"warn",text:`${T.selfRoutedCount} path payment(s) routed XRP from and back to the same address through the DEX. This creates artificial trading volume on every intermediate pair. Check the Path Payments section for specific transaction hashes.`}),(zi=m.mirrorGroups)!=null&&zi.length&&H.push({icon:"\u{1F578}",sev:"warn",text:"Mirror wallet clusters found. If you are the issuer, determine whether these are genuine holders or insider accounts used to create the appearance of broader distribution. These wallets could coordinate a sell-off."}),(Ui=i.flags)!=null&&Ui.some(A=>A.sev==="critical")&&H.push({icon:"\u{1F3A8}",sev:"critical",text:"Zero-value NFT offer detected. If you didn't intentionally list your NFT for free: identify what website or app you used around the time this transaction was signed, and revoke any approvals it has."}),(x==null?void 0:x.verdict)==="elevated"&&H.push({icon:"\u{1F4B8}",sev:"info",text:`${x.spikeCount} transactions paid >100\xD7 normal fees. Check the Fee Spikes section to see if these align with moments of concentrated trading \u2014 elevated fees often mark coordinated activity windows.`}),H.length===0&&H.push({icon:"\u2705",sev:"ok",text:"No immediate actions required. The account shows no identifiable red flags. Continue monitoring as activity grows \u2014 some patterns only become statistically significant with more data."});let Y=H.map(A=>`
    <div style="background:${Ce[A.sev]||Ce.info};border:1px solid ${ue[A.sev]||ue.info};border-radius:10px;padding:12px 14px;margin-bottom:8px;display:flex;gap:12px;align-items:flex-start">
      <span style="font-size:1.15rem;flex-shrink:0;margin-top:1px">${A.icon}</span>
      <span style="font-size:.85rem;line-height:1.65;color:rgba(255,255,255,.78)">${A.text}</span>
    </div>`).join(""),De=`
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:8px;margin-top:10px">
      ${[["Benford's Law","In organic financial data, amounts starting with '1' appear ~30% of the time. Computer-generated amounts often break this law."],["Shannon's Entropy","Measures how 'predictable' transaction amounts and partners are. Bots repeat the same amounts; humans don't."],["Zipf's Law","Natural networks have a few heavy relationships and many light ones. Wash rings show unnaturally equal relationships."],["Time Series CV","Coefficient of Variation of gaps between transactions. Humans: >0.8 (irregular). Bots: <0.3 (clock-like)."],["Granger Causality","Tests if one event type systematically causes another \u2014 e.g., every offer creation is followed by a cancellation at a predictable lag."],["Interval CV","The regularity of timing between transactions. Very low = mechanical/automated. Very high = erratic/bursty."],["Gateway Balances","The XRPL API command that returns the true outstanding obligations of a token issuer \u2014 more accurate than just reading trustlines."],["Destination Tag","A number attached to a payment that identifies the recipient sub-account at an exchange. Like a bank account reference number."],["Path Payment","An XRPL payment that routes through intermediate DEX pairs. Can create trading volume on pairs the sender never intended to trade."],["XRP Round-Trip","A path payment that starts and ends in XRP, routed through IOU pairs. Creates DEX volume with no net economic transfer."],["Fee Multiplier","XRPL's base transaction fee is 12 drops (~$0.000001). Paying 100\xD7 means paying 1,200 drops \u2014 bots do this for guaranteed same-ledger execution."]].map(([A,Le])=>`
        <div style="background:rgba(255,255,255,.03);border-radius:8px;padding:10px 12px;border:1px solid rgba(255,255,255,.05)">
          <div style="font-size:.78rem;font-weight:700;color:rgba(255,255,255,.75);margin-bottom:4px">${g(A)}</div>
          <div style="font-size:.74rem;color:rgba(255,255,255,.42);line-height:1.5">${g(Le)}</div>
        </div>`).join("")}
    </div>`,Be=re();return`
    <div class="report-wrap">

      <!-- \u2500\u2500 Cover \u2500\u2500 -->
      <div class="report-cover">
        <div class="report-cover-left">
          <div class="report-logo">\u26A1 NaluXRP</div>
          <h2 class="report-title">Account Investigation Report</h2>
          <div class="report-addr mono">${g(e)}</div>
          <div class="report-ts">Generated ${W}</div>
          <div style="font-size:.75rem;color:rgba(255,255,255,.38);margin-top:4px">Coverage: ${g(ce)}</div>
        </div>
        <div class="report-score-circle" style="--score-color:${Q}">
          <div class="report-score-num" style="color:${Q}">${s}</div>
          <div class="report-score-den">/100</div>
          <div class="report-score-word" style="color:${Q}">${z}</div>
        </div>
      </div>

      <!-- \u2500\u2500 Executive Summary \u2500\u2500 -->
      <div class="report-section">
        <h3 class="report-section-h">\u{1F4CB} Executive Summary</h3>
        <div class="report-narrative">
          ${Be.map(A=>`<p style="margin-bottom:12px;line-height:1.7">${A}</p>`).join("")}
        </div>
      </div>

      <!-- \u2500\u2500 AI-Generated Explanation \u2500\u2500
           Deliberately its own section, clearly separate from the
           deterministic Executive Summary above \u2014 this is a real Claude
           call the reader should be able to tell apart from the template-
           generated narrative, not a drop-in replacement for it. On-demand
           (a button, not automatic) so opening the report never silently
           spends the reader's own Anthropic credits. -->
      <div class="report-section">
        <h3 class="report-section-h">\u{1F916} AI-Generated Explanation
          <span style="font-size:.68rem;font-weight:400;color:rgba(255,255,255,.4);margin-left:8px">via your own Claude API key</span>
        </h3>
        <div id="ai-explanation-body">
          <p style="font-size:.82rem;color:rgba(255,255,255,.45);margin-bottom:12px;line-height:1.6">
            Ask Claude to read this account's findings and write a plain-language explanation, distinct from the
            template-based summary above.
          </p>
          <button class="settings-btn settings-btn--primary" onclick="generateAiExplanation()">\u{1F916} Generate AI Explanation</button>
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
        <div style="margin-bottom:16px">${tg(f,e)}</div>
        ${El(n,p,P)}
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
        <div class="report-stats-grid">${it}</div>
      </div>

      <!-- \u2500\u2500 Findings by Module \u2500\u2500 -->
      ${ot?`
      <div class="report-section">
        <h3 class="report-section-h">\u{1F52C} Findings by Module
          <span class="report-counts">
            <span class="report-count report-count--crit">${xe.length} Critical</span>
            <span class="report-count report-count--warn">${B.length} Warnings</span>
          </span>
        </h3>
        <p style="font-size:.8rem;color:rgba(255,255,255,.4);margin-bottom:14px;line-height:1.6">
          Each module below used a different method to analyse the account.
          Findings include clickable transaction hash links so you can verify everything on-chain.
        </p>
        <div class="report-findings">${ot}</div>
      </div>`:`
      <div class="report-section">
        <h3 class="report-section-h">\u{1F52C} Findings</h3>
        <div class="report-clean-note">\u2705 No elevated findings across all ${Se.length} analysis modules.</div>
      </div>`}

      <!-- \u2500\u2500 Recommendations \u2500\u2500 -->
      <div class="report-section">
        <h3 class="report-section-h">\u{1F4A1} Recommended Actions</h3>
        ${Y}
      </div>

      <!-- \u2500\u2500 Glossary \u2500\u2500 -->
      <div class="report-section">
        <h3 class="report-section-h">\u{1F4D6} Understanding This Report</h3>
        <p style="font-size:.82rem;color:rgba(255,255,255,.45);line-height:1.65;margin-bottom:10px">
          Plain-English definitions for every technical term used in this report.
        </p>
        ${De}
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
  `}function Mh(e,...t){e.innerHTML=Lh(...t)}function Ph(){let e=document.getElementById("tab-inspector");e&&(e.querySelector("[data-inspector-v2]")||(e.innerHTML=`
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

      <div id="inspect-warn"    class="alert-warn"    style="display:none">\u26A1 Not connected \u2014 connect to an XRPL node first.</div>
      <div id="inspect-err"     class="alert-err"     style="display:none"></div>
      <div id="inspect-loading" class="inspect-loading-state" style="display:none">
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
              <span class="isd-section-title">My Wallets</span>
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
              <span class="isd-section-title">Recent Inspections</span>
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
              <span class="isd-section-title">Watchlist</span>
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
              <span class="isd-section-title">Notable XRPL Addresses</span>
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
              <span class="isd-section-title">What The Inspector Detects</span>
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
              <button class="irb-copy-btn" onclick="inspectorCopyAddr()" title="Copy address">\u{1F4CB}</button>
              <button id="watchlist-btn" class="irb-copy-btn" title="Add to watchlist">\u2606 Watch</button>
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:8px">
            <button id="analyst-mode-btn" onclick="toggleAnalystMode()"
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
          <div id="quick-verdict-body" style="opacity:.5;font-size:.82rem">Analysing\u2026</div>
        </div>

        <section class="widget-card inspector-section" id="section-overview">
          <header class="widget-header section-header">
            <span class="widget-title">\u{1F4CA} Account Overview</span>
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
          <header class="widget-header section-header">
            <span class="widget-title">\u{1F510} Security Audit</span>
            <span class="section-badge" id="badge-security"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-security-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-drain">
          <header class="widget-header section-header">
            <span class="widget-title">\u26A0 Drain Risk</span>
            <span class="section-badge" id="badge-drain"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-drain-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-fundflow">
          <header class="widget-header section-header">
            <span class="widget-title">\u{1F30A} Fund Flow Tracer</span>
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
          <header class="widget-header section-header">
            <span class="widget-title">\u{1F4E5} Inbound Flow Analysis</span>
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
          <header class="widget-header section-header">
            <span class="widget-title">\u{1F3A8} NFT Analysis</span>
            <span class="section-badge" id="badge-nft"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-nft-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-wash">
          <header class="widget-header section-header">
            <span class="widget-title">\u{1F4CA} Wash Trading</span>
            <span class="section-badge" id="badge-wash"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-wash-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-forensic-suite" style="border-color:rgba(0,212,255,.2)">
          <header class="widget-header section-header" style="background:rgba(0,212,255,.03)">
            <span class="widget-title">\u{1F9EC} Forensic Analytics Suite</span>
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
              <button class="forensic-tab-btn" onclick="_toggleForensicTab('benfords')" style="width:100%;justify-content:space-between">
                <span>\u{1F4D0} Benford's Law</span>
                <span style="display:flex;align-items:center;gap:8px"><span class="section-badge" id="badge-benfords"></span><span id="ftab-chevron-benfords" style="opacity:.5">\u25BE</span></span>
              </button>
              <div id="forensic-tab-benfords" class="forensic-tab-body" style="display:none"><div id="inspect-benfords-body" style="padding:8px 0"></div></div>
            </div>

            <div id="section-entropy" class="forensic-sub-section" style="margin-top:4px">
              <button class="forensic-tab-btn" onclick="_toggleForensicTab('entropy')" style="width:100%;justify-content:space-between">
                <span>\u{1F500} Shannon's Entropy</span>
                <span style="display:flex;align-items:center;gap:8px"><span class="section-badge" id="badge-entropy"></span><span id="ftab-chevron-entropy" style="opacity:.5">\u25BE</span></span>
              </button>
              <div id="forensic-tab-entropy" class="forensic-tab-body" style="display:none"><div id="inspect-entropy-body" style="padding:8px 0"></div></div>
            </div>

            <div id="section-zipf" class="forensic-sub-section" style="margin-top:4px">
              <button class="forensic-tab-btn" onclick="_toggleForensicTab('zipf')" style="width:100%;justify-content:space-between">
                <span>\u{1F4C8} Zipf's Law</span>
                <span style="display:flex;align-items:center;gap:8px"><span class="section-badge" id="badge-zipf"></span><span id="ftab-chevron-zipf" style="opacity:.5">\u25BE</span></span>
              </button>
              <div id="forensic-tab-zipf" class="forensic-tab-body" style="display:none"><div id="inspect-zipf-body" style="padding:8px 0"></div></div>
            </div>

            <div id="section-timeseries" class="forensic-sub-section" style="margin-top:4px">
              <button class="forensic-tab-btn" onclick="_toggleForensicTab('timeseries')" style="width:100%;justify-content:space-between">
                <span>\u{1F550} Time Series Analysis</span>
                <span style="display:flex;align-items:center;gap:8px"><span class="section-badge" id="badge-timeseries"></span><span id="ftab-chevron-timeseries" style="opacity:.5">\u25BE</span></span>
              </button>
              <div id="forensic-tab-timeseries" class="forensic-tab-body" style="display:none"><div id="inspect-timeseries-body" style="padding:8px 0"></div></div>
            </div>

            <div id="section-granger" class="forensic-sub-section" style="margin-top:4px">
              <button class="forensic-tab-btn" onclick="_toggleForensicTab('granger')" style="width:100%;justify-content:space-between">
                <span>\u{1F517} Granger Causality</span>
                <span style="display:flex;align-items:center;gap:8px"><span class="section-badge" id="badge-granger"></span><span id="ftab-chevron-granger" style="opacity:.5">\u25BE</span></span>
              </button>
              <div id="forensic-tab-granger" class="forensic-tab-body" style="display:none"><div id="inspect-granger-body" style="padding:8px 0"></div></div>
            </div>
          </div>
        </section>

        <section class="widget-card inspector-section" id="section-volconc">
          <header class="widget-header section-header">
            <span class="widget-title">\u{1FAE7} Volume Concentration</span>
            <span class="section-badge" id="badge-volconc"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-volconc-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-issuer">
          <header class="widget-header section-header">
            <span class="widget-title">\u{1FA99} Token Issuer</span>
            <span class="section-badge" id="badge-issuer"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-issuer-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-issuer-connections">
          <header class="widget-header section-header">
            <span class="widget-title">\u{1F578} Issuer Connection Graph</span>
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
          <header class="widget-header section-header">
            <span class="widget-title">\u{1F4A7} AMM / Liquidity</span>
            <span class="section-badge" id="badge-amm"></span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-amm-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-fee-analysis">
          <header class="widget-header section-header">
            <span class="widget-title">\u{1F4B8} Fee Spike Analysis</span>
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
          <header class="widget-header section-header">
            <span class="widget-title">\u{1F3F7} Destination Tag Patterns</span>
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
          <header class="widget-header section-header">
            <span class="widget-title">\u{1F504} Path Payment Depth</span>
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
          <header class="widget-header section-header">
            <span class="widget-title">\u{1F4DD} Memo Analysis</span>
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
          <header class="widget-header section-header">
            <span class="widget-title">\u{1F512} Escrow Depth</span>
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
          <header class="widget-header section-header">
            <span class="widget-title">\u{1F9FE} Open Checks</span>
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
          <header class="widget-header section-header">
            <span class="widget-title">\u{1F4D6} Live Order Book</span>
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
          <header class="widget-header section-header">
            <span class="widget-title">\u{1F517} Trustlines</span>
            <span class="section-badge section-badge--neutral" id="trust-count-badge">0</span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-trust-body"></div>
        </section>

        <section class="widget-card inspector-section" id="section-tx">
          <header class="widget-header section-header">
            <span class="widget-title">\u{1F4DC} Transaction History</span>
            <span class="section-badge section-badge--neutral" id="badge-tx">\u2014</span>
            <span class="section-chevron">\u25BE</span>
          </header>
          <div class="section-body" id="inspect-tx-timeline"></div>
        </section>

        <section class="widget-card inspector-section report-card" id="section-report">
          <header class="widget-header section-header">
            <span class="widget-title">\u{1F4C4} Full Investigation Report</span>
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
  `))}function Ah(){if(document.getElementById("inspector-nav"))return;let e=document.createElement("nav");e.id="inspector-nav",e.setAttribute("aria-label","Inspector navigation"),e.innerHTML=`
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
          <button class="in-btn" data-jump="granger"><span class="in-icon">\u{1F517}</span><span class="in-label">Granger</span></button>
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
  `;let t=document.getElementById("tab-inspector");t&&t.appendChild(e)}function Eh(){if(document.getElementById("inspector-howto"))return;let e=document.createElement("div");e.id="inspector-howto",e.className="howto-overlay",e.style.display="none",e.innerHTML=`
    <div class="howto-modal">
      <button class="howto-close" onclick="hideInspectorHowTo()">\u2715</button>

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
  `,e.addEventListener("click",t=>{t.target===e&&Co()}),document.addEventListener("keydown",t=>{t.key==="Escape"&&e.style.display!=="none"&&Co()}),document.body.appendChild(e)}function _l(e){Ie("#inspector-nav .in-btn[data-jump]").forEach(t=>t.classList.toggle("in-btn--active",t.dataset.jump===e))}function Nh(){var n;if(!document.body.classList.contains("inspector")||((n=y("inspect-result"))==null?void 0:n.style.display)==="none")return;let e=["security","drain","nft","wash","issuer","amm","trustlines","tx"],t=null;for(let s of e){let a=document.getElementById("section-"+s);a&&a.getBoundingClientRect().top<=150&&(t=s)}t&&_l(t)}function ua(e,t){let n=y(e);if(!n)return;let s=t.filter(o=>o.sev==="critical").length,a=t.filter(o=>o.sev==="warn").length;s?(n.textContent=s+" critical",n.className="section-badge section-badge--crit"):a?(n.textContent=a+" warn",n.className="section-badge section-badge--warn"):(n.textContent="OK",n.className="section-badge section-badge--ok")}function _h(e,t){let n=y(e);if(!n)return;let s={low:"ok",medium:"warn",high:"warn",critical:"crit"};n.textContent=t,n.className="section-badge section-badge--"+(s[t]||"ok")}window._toggleForensicTab=function(e){var a;let t=document.getElementById("forensic-tab-"+e);if(!t)return;let n=t.style.display!=="none";t.style.display=n?"none":"";let s=document.getElementById("ftab-chevron-"+e);s&&(s.textContent=n?"\u25BE":"\u25B4"),!n&&((a=t.querySelector('[id^="inspect-"]'))==null?void 0:a.innerHTML)===""&&(t.querySelector('[id^="inspect-"]').innerHTML='<div style="opacity:.45;font-size:.8rem;padding:8px 0">Run an inspection first.</div>')};function Rh(){var n,s;let e=y("inspect-addr-badge"),t=((n=e==null?void 0:e.dataset)==null?void 0:n.fullAddr)||(e==null?void 0:e.textContent);!t||t==="\u2014"||(s=navigator.clipboard)==null||s.writeText(t).then(()=>{let a=document.querySelector(".irb-copy-btn");a&&(a.textContent="\u2713",setTimeout(()=>a.textContent="\u{1F4CB}",1500))})}window.inspectorGoBack=function(){let e=y("inspect-result"),t=y("inspect-empty"),n=y("inspect-err"),s=y("inspect-addr");e&&(e.style.display="none"),n&&(n.style.display="none"),t&&(t.style.display=""),s&&(s.value=""),Po(),Ao(),window.scrollTo({top:0,behavior:"smooth"}),setTimeout(()=>s==null?void 0:s.focus(),300)};function Dh(){let e=document.getElementById("inspector-howto");e&&(e.style.display="",requestAnimationFrame(()=>e.classList.add("howto-visible")))}function Co(){let e=document.getElementById("inspector-howto");e&&(e.classList.remove("howto-visible"),setTimeout(()=>{e.classList.contains("howto-visible")||(e.style.display="none")},260))}var Mo="nalulf_inspect_history",Ih="nalulf_wallets",ys="nalulf_watchlist",Rl="nalulf_analyst_mode";var Fh=[{label:"SOLO Issuer",addr:"rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz",tag:"Token Issuer",icon:"\u{1FA99}",note:"200 trustlines \xB7 master disabled \xB7 liquidity provider",color:"#ffb86c"},{label:"Ripple Genesis",addr:"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",tag:"Genesis",icon:"\u{1F310}",note:"Original genesis wallet \xB7 100 billion XRP issued",color:"#50fa7b"},{label:"Bitstamp Hot",addr:"rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B",tag:"Exchange",icon:"\u{1F3E6}",note:"Major exchange hot wallet \xB7 high payment volume",color:"#8be9fd"},{label:"GateHub Hot",addr:"rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq",tag:"Exchange",icon:"\u{1F3E6}",note:"GateHub gateway \xB7 multi-currency issuance",color:"#8be9fd"},{label:"XAMAN Wallet",addr:"rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY",tag:"Wallet App",icon:"\u{1F4F1}",note:"XAMAN (XUMM) custodial wallet address",color:"#bd93f9"},{label:"DEX Market Maker",addr:"r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59",tag:"Market Maker",icon:"\u{1F4CA}",note:"High-volume DEX activity \xB7 offer patterns",color:"#ff79c6"}],Bh=[{icon:"\u{1F510}",title:"Security Audit",desc:"Decodes all account flags, checks master key status, regular key age, multisig signer lists, and suspicious auth changes.",color:"#50fa7b"},{icon:"\u26A0",title:"Drain Detection",desc:"Classic drain setup, external key injection (3rd party sets your key), large outflows within 48h of auth change, open payment channels.",color:"#ff5555"},{icon:"\u{1F3A8}",title:"NFT Risk",desc:"Zero-value sell offers (free NFT drain vector), no-URI spam tokens, unexpected burns, transfer fee exposure.",color:"#bd93f9"},{icon:"\u{1F4CA}",title:"Wash Trading",desc:"Five-signal scoring: cancel ratio, round-trip counterparties, single-pair concentration, fill rate, burst activity.",color:"#ffb86c"},{icon:"\u{1FA99}",title:"Token Issuer",desc:"Outstanding obligations, individual line freezes, global freeze, NoFreeze protection, black hole risk detection.",color:"#f1fa8c"},{icon:"\u{1F4A7}",title:"AMM & Liquidity",desc:"LP token positions, deposit/withdrawal history, fee votes, auction slot bids, impermanent loss warnings.",color:"#8be9fd"},{icon:"\u{1F30A}",title:"Fund Flow Tracer",desc:"Traces every outbound payment from a wallet \u2014 where funds went, which exchanges they reached, multi-hop path payment routes, and a full chronological drain timeline.",color:"#00d4ff"},{icon:"\u{1F578}",title:"Issuer Connection Graph",desc:"Token supply concentration, top holder %, accounts the issuer created/funded, and mirror-wallet clusters \u2014 groups of wallets receiving identical token amounts (sybil detection).",color:"#bd93f9"}];function Oh(){Xh(),Hh(),Po(),Ao(),xs(),zh(),Fl()}function Xh(){let e=document.getElementById("isd-notable-grid");e&&(e.innerHTML=Fh.map(t=>`
    <button class="isd-notable-card" onclick="inspectorLoadAddr('${t.addr}')" type="button">
      <div class="isd-notable-top">
        <span class="isd-notable-icon" style="color:${t.color}">${t.icon}</span>
        <span class="isd-notable-tag" style="border-color:${t.color}40;color:${t.color}">${g(t.tag)}</span>
      </div>
      <div class="isd-notable-label">${g(t.label)}</div>
      <div class="isd-notable-addr mono">${t.addr.slice(0,8)}\u2026${t.addr.slice(-6)}</div>
      <div class="isd-notable-note">${g(t.note)}</div>
    </button>
  `).join(""))}function Hh(){let e=document.getElementById("isd-cap-grid");e&&(e.innerHTML=Bh.map(t=>`
    <div class="isd-cap" style="--cap-color:${t.color}">
      <div class="isd-cap-icon-wrap"><span class="isd-cap-icon">${t.icon}</span></div>
      <div class="isd-cap-body">
        <div class="isd-cap-title">${g(t.title)}</div>
        <div class="isd-cap-desc">${g(t.desc)}</div>
      </div>
    </div>
  `).join(""))}function Po(){let e=document.getElementById("isd-wallets-section"),t=document.getElementById("isd-wallet-list");if(!e||!t)return;let n=ve(Z(Ih))||[];if(!n.length){e.style.display="none";return}e.style.display="",t.innerHTML=n.map(s=>{let a=s.color||"#50fa7b",o=s.emoji||"\u{1F48E}",i=s.label||"Wallet",r=s.address||"",l=r?r.slice(0,8)+"\u2026"+r.slice(-6):"\u2014",c=s.testnet?'<span class="isd-wallet-testnet">TESTNET</span>':"";return`
      <button class="isd-wallet-card" onclick="inspectorLoadAddr('${g(r)}')" type="button">
        <div class="isd-wallet-avatar" style="background:${a}20;border-color:${a}50">${o}</div>
        <div class="isd-wallet-info">
          <div class="isd-wallet-name">${g(i)} ${c}</div>
          <div class="isd-wallet-addr mono">${l}</div>
        </div>
        <div class="isd-wallet-inspect">Inspect \u2192</div>
      </button>
    `}).join("")}function Ao(){let e=document.getElementById("isd-recent-section"),t=document.getElementById("isd-recent-list");if(!e||!t)return;let n=ma();if(!n.length){e.style.display="none";return}e.style.display="",t.innerHTML=n.map((s,a)=>{let o=s.addr?s.addr.slice(0,10)+"\u2026"+s.addr.slice(-8):"\u2014",i=s.riskScore!=null?`<span class="isd-risk-pill isd-risk-pill--${Il(s.riskScore)}">${s.riskScore}</span>`:"";return`
      <button class="isd-recent-row" onclick="inspectorLoadAddr('${g(s.addr)}')" type="button">
        <span class="isd-recent-n">${a+1}</span>
        <span class="isd-recent-addr mono">${o}</span>
        <div class="isd-recent-right">
          ${i}
          <span class="isd-recent-time">${fa(s.ts)}</span>
        </div>
      </button>
    `}).join("")}function zh(){da(),window.addEventListener("xrpl-ledger",Uh),window.addEventListener("xrpl-connection",da)}function Uh(e){ca()&&da(e.detail)}var $o=null;function Wh(){return $o||($o={idx:document.getElementById("isd-ledger-idx"),age:document.getElementById("isd-ledger-age"),tps:document.getElementById("isd-tps"),tpsTrnd:document.getElementById("isd-tps-trend"),fee:document.getElementById("isd-fee"),feeLv:document.getElementById("isd-fee-level"),close:document.getElementById("isd-close-time"),dot:document.getElementById("isd-conn-dot"),connLbl:document.getElementById("isd-conn-label"),pill:document.getElementById("isd-conn-pill"),domTx:document.getElementById("isd-dom-tx"),domPct:document.getElementById("isd-dom-pct"),bar:document.getElementById("isd-fee-bar"),barLbl:document.getElementById("isd-fee-bar-label")})}function da(){let{idx:e,age:t,tps:n,tpsTrnd:s,fee:a,feeLv:o,close:i,dot:r,connLbl:l,pill:c,domTx:d,domPct:u,bar:p,barLbl:m}=Wh(),f=O.connectionState||"disconnected",v={connected:{label:"Connected",cls:"conn--live"},connecting:{label:"Connecting\u2026",cls:"conn--warn"},disconnected:{label:"Disconnected",cls:"conn--dead"}},h=v[f]||v.disconnected;r&&(r.className="isd-conn-dot"),l&&(l.textContent=h.label),c&&(c.className=`isd-conn-pill ${h.cls}`);let w=O.ledgerLog||[];if(w.length&&e){let T=w[0];if(e.textContent=Number(T.ledgerIndex||0).toLocaleString(),t&&(t.textContent=T.closeTimeSec!=="\u2014"?T.closeTimeSec+"s close":"\u2014"),i){let $=parseFloat(T.closeTimeSec);i.textContent=isNaN($)?"\u2014":$.toFixed(1)}}let k=O.tpsHistory||[];if(k.length&&n){let T=k.slice(-5),$=T.reduce((P,M)=>P+M,0)/T.length;if(n.textContent=$.toFixed(1),s&&k.length>=6){let P=k.slice(-10,-5),M=P.reduce((_,X)=>_+X,0)/P.length,N=$-M;s.textContent=N>.5?"\u2191 rising":N<-.5?"\u2193 falling":"\u2192 stable",s.className=`isd-metric-sub ${N>.5?"isd-up":N<-.5?"isd-down":""}`}}let b=O.feeHistory||[];if(b.length&&a){let T=b.slice(-5),$=T.reduce((N,_)=>N+_,0)/T.length,P=$/1e6;a.textContent=$<5e3?$.toFixed(0)+" drops":P.toFixed(5)+" XRP";let M=$<20?{lbl:"Low",cls:"fee-low",pct:10}:$<100?{lbl:"Normal",cls:"fee-normal",pct:28}:$<500?{lbl:"Elevated",cls:"fee-elevated",pct:60}:$<2e3?{lbl:"High",cls:"fee-high",pct:82}:{lbl:"Congested",cls:"fee-congest",pct:100};o&&(o.textContent=M.lbl,o.className=`isd-metric-sub ${M.cls}`),p&&(p.style.width=M.pct+"%",p.className=`isd-fee-bar-fill ${M.cls}`),m&&(m.textContent=M.lbl,m.className=`isd-fee-bar-level ${M.cls}`)}let x=O.txMixAccum||{},S=Object.entries(x).filter(([,T])=>T>0).sort(([,T],[,$])=>$-T);if(S.length&&d){let T=S.reduce((M,[,N])=>M+N,0),[$,P]=S[0];d.textContent=$,u&&(u.textContent=(P/T*100).toFixed(0)+"% of traffic")}}window.exportTxCSV=function(e){var l,c;if(!e||!e.length){alert("No transaction data to export. Run an inspection first.");return}let t=946684800,s=[["Hash","Date","Type","Account","Destination","Amount_XRP","Amount_Token","Currency","Fee_Drops","DestinationTag","Result","LedgerIndex"],...e.map(({tx:d,meta:u})=>{var w,k;let p=d.date?new Date((d.date+t)*1e3).toISOString():"",m=typeof d.Amount=="string"?(Number(d.Amount)/1e6).toFixed(6):"",f=(w=d.Amount)!=null&&w.value?d.Amount.value:"",v=((k=d.Amount)==null?void 0:k.currency)||(typeof d.Amount=="string"?"XRP":""),h=(u==null?void 0:u.TransactionResult)||"";return[d.hash||"",p,d.TransactionType||"",d.Account||"",d.Destination||"",m,f,v,d.Fee||"",d.DestinationTag??"",h,d.ledger_index||""]})].map(d=>d.map(u=>{let p=String(u);return p.includes(",")||p.includes('"')||p.includes(`
`)?'"'+p.replace(/"/g,'""')+'"':p}).join(",")).join(`
`),a=new Blob([s],{type:"text/csv;charset=utf-8;"}),o=URL.createObjectURL(a),i=document.createElement("a"),r=((c=(l=document.getElementById("inspect-addr-badge"))==null?void 0:l.dataset)==null?void 0:c.fullAddr)||"wallet";i.href=o,i.download=`naluxrp_${r.slice(0,10)}_${new Date().toISOString().slice(0,10)}.csv`,document.body.appendChild(i),i.click(),document.body.removeChild(i),URL.revokeObjectURL(o)};function jh(e,t){let s=ma().find(o=>o.addr===e);if(!s||s.riskScore==null||t==null)return null;let a=t-s.riskScore;return{prev:s.riskScore,curr:t,diff:a,ts:s.ts}}function qh(e,t){let n=jh(e,t);if(!n||Math.abs(n.diff)<2)return;let s=document.getElementById("inspect-risk-score");if(!s)return;let a=n.diff>0?`<span style="color:#ff5555;font-size:.7rem;font-weight:700"> \u2191${n.diff}</span>`:`<span style="color:#50fa7b;font-size:.7rem;font-weight:700"> \u2193${Math.abs(n.diff)}</span>`,o=fa(n.ts);s.insertAdjacentHTML("afterend",`<span class="risk-score-diff" title="Changed from ${n.prev} \u2192 ${n.curr} since ${o}">${a} vs ${o}</span>`)}window._inspectMaxTx||(window._inspectMaxTx=5e3);window.inspectorLoadAddr=function(e){let t=y("inspect-addr");t&&(t.value=e),Jn()};window.inspectWalletAddr=function(e){var n,s;window.inspectorLoadAddr(e);let t=document.querySelector('[data-tab="inspector"]');t&&((n=window.switchTab)==null||n.call(window,t,"inspector")),(s=window.showDashboard)==null||s.call(window)};window.printInspectorReport=function(){var s,a;let e=document.getElementById("inspect-report-body");if(!e)return;let t=((a=(s=document.getElementById("inspect-addr-badge"))==null?void 0:s.dataset)==null?void 0:a.fullAddr)||"wallet",n=window.open("","_blank","width=900,height=700");n.document.write(`<!DOCTYPE html><html><head>
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
  </body></html>`),n.document.close()};window.exportInspectorReport=function(){var n;let e=document.getElementById("inspect-report-body");if(!e)return;let t=e.innerText||e.textContent||"";(n=navigator.clipboard)==null||n.writeText(t).then(()=>{let s=document.getElementById("report-export-btn");s&&(s.textContent="\u2713 Copied!",setTimeout(()=>{s.textContent="\u{1F4CB} Copy Report"},2e3))}).catch(()=>{let s=document.createRange();s.selectNodeContents(e);let a=window.getSelection();a.removeAllRanges(),a.addRange(s)})};window.inspectorClearHistory=function(){lt(Mo);let e=document.getElementById("isd-recent-section");e&&(e.style.display="none")};window.inspectorClearWatchlist=function(){lt(ys),xs()};function ma(){return ve(Z(Mo))||[]}function Vh(e,t,n=[]){let s=ma();s=s.filter(o=>o.addr!==e);let a=n.filter(o=>o.sev==="critical"||o.sev==="warn").map(o=>o.module+":"+o.headline.slice(0,40)).sort().join("|");s.unshift({addr:e,riskScore:t,ts:Date.now(),fingerprint:a}),s=s.slice(0,12),te(Mo,JSON.stringify(s))}function ws(){return ve(Z(ys))||[]}function Gh(e,t){let n=ws().filter(s=>s.addr!==e);n.unshift({addr:e,label:t||U(e),addedTs:Date.now(),lastScore:null,lastTs:null}),te(ys,JSON.stringify(n.slice(0,50)))}function Dl(e){te(ys,JSON.stringify(ws().filter(t=>t.addr!==e)))}function Lo(e){return ws().some(t=>t.addr===e)}function Kh(e,t){let n=ws().map(s=>s.addr===e?{...s,lastScore:t,lastTs:Date.now()}:s);te(ys,JSON.stringify(n))}function fa(e){let t=Date.now()-e;return t<6e4?"just now":t<36e5?Math.floor(t/6e4)+"m ago":t<864e5?Math.floor(t/36e5)+"h ago":Math.floor(t/864e5)+"d ago"}function Il(e){return To(e).replace("risk-","")}var tn=!1;function Fl(){tn=localStorage.getItem(Rl)==="true",Eo()}function Eo(){let e=document.getElementById("inspect-result");if(!e)return;e.classList.toggle("mode-advanced",tn),e.classList.toggle("mode-simple",!tn);let t=document.getElementById("analyst-mode-btn");t&&(t.textContent=tn?"\u2697 Advanced":"\u{1F441} Simple",t.title=tn?"Switch to Simple view":"Switch to Advanced (analyst) view")}window.toggleAnalystMode=function(){tn=!tn,localStorage.setItem(Rl,tn),Eo()};var Jh=new Set(["section-overview","section-report"]),Yh=new Set(["section-security","section-drain","section-fundflow","section-inbound"]);function Qh(){let e=document.getElementById("inspect-result");if(!e)return;let t=[...e.querySelectorAll(".inspector-section")],n={crit:0,warn:1,neutral:2,ok:3,"":4},s=t.filter(i=>!Jh.has(i.id)&&!Yh.has(i.id));s.sort((i,r)=>{let l=c=>{let d=c.querySelector(".section-badge");if(!d)return"";let u=d.className;return u.includes("crit")?"crit":u.includes("warn")?"warn":u.includes("neutral")?"neutral":u.includes("ok")?"ok":""};return(n[l(i)]??4)-(n[l(r)]??4)});let a=document.getElementById("section-inbound")||document.getElementById("section-drain");if(!a)return;let o=a;for(let i of s)o.after(i),o=i}function Zh(e,t,n,s){let a=document.getElementById("quick-verdict-body");if(!a)return;let o=t.filter(u=>u.sev==="critical"),i=t.filter(u=>u.sev==="warn"),r=e<20?"#50fa7b":e<45?"#ffb86c":e<70?"#ff8c42":"#ff5555",l=e<20?"Low Risk":e<45?"Moderate":e<70?"High Risk":"Critical",c="",d="";if(o.length===0&&i.length===0)c=`No elevated signals found across ${s.toLocaleString()} transactions${n!=null?` and ${n} days of history`:""}.`,d="This wallet appears to operate within normal parameters.";else{let u=o.slice(0,2).map(m=>m.headline).join("; "),p=i.slice(0,2).map(m=>m.headline).join("; ");c=o.length?`${o.length} critical issue${o.length>1?"s":""}: ${u}.`:`${i.length} warning${i.length>1?"s":""}: ${p}.`,d=o.length?"Review the highlighted sections below. Scroll to the Report for full recommendations.":"Review the flagged sections below for context before drawing conclusions."}a.innerHTML=`
    <div style="display:flex;align-items:flex-start;gap:16px;flex-wrap:wrap">
      <div style="text-align:center;flex-shrink:0">
        <div style="font-size:2.2rem;font-weight:900;color:${r};line-height:1">${e}</div>
        <div style="font-size:.65rem;font-weight:800;color:${r};letter-spacing:.1em;text-transform:uppercase">${l}</div>
      </div>
      <div style="flex:1;min-width:200px">
        <div style="font-size:.92rem;color:rgba(255,255,255,.88);line-height:1.6;margin-bottom:6px">${g(c)}</div>
        <div style="font-size:.8rem;color:rgba(255,255,255,.45);line-height:1.5">${g(d)}</div>
        ${o.length||i.length?`
        <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
          ${o.length?`<span style="background:rgba(255,85,85,.12);border:1px solid rgba(255,85,85,.3);color:#ff5555;border-radius:999px;padding:2px 10px;font-size:.72rem;font-weight:700">${o.length} Critical</span>`:""}
          ${i.length?`<span style="background:rgba(255,184,108,.10);border:1px solid rgba(255,184,108,.25);color:#ffb86c;border-radius:999px;padding:2px 10px;font-size:.72rem;font-weight:700">${i.length} Warnings</span>`:""}
          <button onclick="document.getElementById('section-report')?.scrollIntoView({behavior:'smooth'})"
            style="background:rgba(0,212,255,.08);border:1px solid rgba(0,212,255,.2);color:var(--accent);border-radius:999px;padding:2px 10px;font-size:.72rem;cursor:pointer">Full Report \u2193</button>
        </div>`:""}
      </div>
    </div>`}function eg(e,t){let n=document.getElementById("change-banner");if(!n)return;n.style.display="none";let a=ma().find(u=>u.addr===e);if(!(a!=null&&a.fingerprint))return;let o=new Set(t.filter(u=>u.sev==="critical"||u.sev==="warn").map(u=>u.module+":"+u.headline.slice(0,40))),i=new Set((a.fingerprint||"").split("|").filter(Boolean)),r=[...o].filter(u=>!i.has(u)),l=[...i].filter(u=>!o.has(u));if(!r.length&&!l.length)return;let c=fa(a.ts),d=[];r.length&&d.push(`<span style="color:#ff5555">+${r.length} new finding${r.length>1?"s":""}</span>`),l.length&&d.push(`<span style="color:#50fa7b">${l.length} resolved</span>`),n.style.display="",n.innerHTML=`
    <div style="background:rgba(255,184,108,.07);border:1px solid rgba(255,184,108,.25);border-radius:10px;
                padding:10px 14px;margin-bottom:10px;display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <span style="font-size:1rem">\u{1F514}</span>
      <span style="font-size:.84rem;color:rgba(255,255,255,.75)">
        Since last inspection <strong>${c}</strong>: ${d.join(", ")}
        ${r.length?"\u2014 "+r.slice(0,2).map(u=>u.split(":")[1]).join("; "):""}
      </span>
      <button onclick="document.getElementById('change-banner').style.display='none'"
        style="margin-left:auto;background:none;border:none;color:rgba(255,255,255,.35);font-size:.9rem;cursor:pointer">\u2715</button>
    </div>`}function xs(){let e=document.getElementById("isd-watchlist-section"),t=document.getElementById("isd-watchlist-list");if(!e||!t)return;let n=ws();if(!n.length){e.style.display="none";return}e.style.display="",t.innerHTML=n.map(s=>{let a=s.addr.slice(0,8)+"\u2026"+s.addr.slice(-6),o=s.lastScore!=null?`<span class="isd-risk-pill isd-risk-pill--${Il(s.lastScore)}">${s.lastScore}</span>`:"",i=s.lastTs?fa(s.lastTs):"never checked";return`
      <div class="isd-recent-row" style="align-items:center">
        <button class="isd-recent-addr mono" style="flex:1;text-align:left;background:none;border:none;cursor:pointer;color:inherit"
          onclick="inspectorLoadAddr('${g(s.addr)}')">${g(s.label||a)} <span style="opacity:.45;font-size:.75em">${a}</span></button>
        <div style="display:flex;align-items:center;gap:8px">
          ${o}
          <span style="font-size:.72rem;opacity:.45">${i}</span>
          <button onclick="_removeFromWatchlistUI('${g(s.addr)}')"
            style="background:none;border:none;color:rgba(255,85,85,.6);font-size:.85rem;cursor:pointer;padding:2px 4px">\u2715</button>
        </div>
      </div>`}).join("")}window._removeFromWatchlistUI=function(e){Dl(e),xs()};function Bl(e){let t=document.getElementById("watchlist-btn");if(!t)return;let n=Lo(e);t.textContent=n?"\u2605 Watching":"\u2606 Watch",t.title=n?"Remove from watchlist":"Add to watchlist",t.style.color=n?"#ffb86c":"",t.onclick=()=>{Lo(e)?Dl(e):Gh(e,null),Bl(e),xs()}}function Tl(e,t="inspect-activity-chart"){let n=document.getElementById(t);if(!n||!e.length)return;let s=946684800,a={Payment:"#50fa7b",OfferCreate:"#00d4ff",OfferCancel:"#8be9fd",NFTokenMint:"#bd93f9",NFTokenCreateOffer:"#bd93f9",NFTokenAcceptOffer:"#ff79c6",AMMDeposit:"#ffb86c",AMMWithdraw:"#ffb86c",AMMCreate:"#ffb86c",SetRegularKey:"#ff5555",SignerListSet:"#ff5555",AccountSet:"#f1fa8c"},o="rgba(255,255,255,.25)",i={};for(let{tx:f}of e){if(!f.date)continue;let v=new Date((f.date+s)*1e3),h=new Date(v.getFullYear(),0,1),w=Math.ceil(((v-h)/864e5+h.getDay()+1)/7),k=`${v.getFullYear()}-${String(w).padStart(2,"0")}`;i[k]||(i[k]={count:0,types:{}}),i[k].count++;let b=f.TransactionType||"Other";i[k].types[b]=(i[k].types[b]||0)+1}let r=Object.entries(i).sort((f,v)=>f[0].localeCompare(v[0]));if(r.length<2){n.innerHTML='<div style="opacity:.4;font-size:.8rem;padding:10px 0">Not enough dated transactions for timeline.</div>';return}let l=Math.max(...r.map(([,f])=>f.count),1),c=Math.max(3,Math.min(16,Math.floor(600/r.length))),d=1,u=60,p=r.length*(c+d),m=r.map(([f,v])=>{var x;let h=Math.max(2,Math.round(v.count/l*u)),w=u-h,k=((x=Object.entries(v.types).sort((S,T)=>T[1]-S[1])[0])==null?void 0:x[0])||"Other",b=a[k]||o;return`<rect x="0" y="${w}" width="${c}" height="${h}" fill="${b}" opacity=".8" rx="1">
      <title>${f}: ${v.count} tx (dominant: ${k})</title></rect>`}).join("");n.innerHTML=`
    <div style="font-size:.65rem;color:rgba(255,255,255,.35);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">
      Activity Timeline \u2014 ${r.length} weeks \xB7 ${e.length.toLocaleString()} transactions
    </div>
    <div style="overflow-x:auto;padding-bottom:4px">
      <svg width="${p}" height="${u}" xmlns="http://www.w3.org/2000/svg" style="display:block;min-width:${p}px">
        ${r.map(([,f],v)=>{var x;let h=Math.max(2,Math.round(f.count/l*u)),w=u-h,k=((x=Object.entries(f.types).sort((S,T)=>T[1]-S[1])[0])==null?void 0:x[0])||"Other",b=a[k]||o;return`<rect x="${v*(c+d)}" y="${w}" width="${c}" height="${h}"
            fill="${b}" opacity=".8" rx="1">
            <title>${r[v][0]}: ${f.count} tx (${k})</title></rect>`}).join("")}
      </svg>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:5px">
      ${Object.entries(a).slice(0,8).map(([f,v])=>`<span style="font-size:.62rem;color:${v};opacity:.7">\u25CF ${f}</span>`).join("")}
    </div>`}function Ol(e,t){let n=new Map;for(let{tx:s,meta:a}of e){let o=s.Account===t,i=s.Destination===t;if(!o&&!i)continue;let r=o?s.Destination:s.Account;if(!r||r===t)continue;let l=Pt(s);n.has(r)||n.set(r,{cnt:0,xrpOut:0,xrpIn:0,entity:Yn(r),firstSeen:l,lastSeen:l});let c=n.get(r);c.cnt++,l&&(c.firstSeen=c.firstSeen?Math.min(c.firstSeen,l):l,c.lastSeen=Math.max(c.lastSeen,l));let d=(a==null?void 0:a.delivered_amount)||s.Amount,u=typeof d=="string"?Number(d)/1e6:0;o?c.xrpOut+=u:c.xrpIn+=u}return n}function tg(e,t,n=15){let s=Ol(e,t),a=[...s.entries()].sort((r,l)=>l[1].xrpOut+l[1].xrpIn-(r[1].xrpOut+r[1].xrpIn)||l[1].cnt-r[1].cnt).slice(0,n);if(!a.length)return"";let o=Math.max(...a.map(([,r])=>r.xrpOut+r.xrpIn),1),i=a.map(([r,l],c)=>{var w;let d=l.xrpOut+l.xrpIn,u=Math.max(1.5,d/o*100),p=en[(w=l.entity)==null?void 0:w.type]||en.other,m=d>0?l.xrpOut/d:.5,f=m>.65?"\u2192 out":m<.35?"\u2190 in":"\u21C4 both",v=l.entity?`<span style="font-size:.64rem;color:${p};border:1px solid ${p};border-radius:999px;padding:1px 7px;margin-left:6px">${g(l.entity.name)}</span>`:"",h=Nl(l.firstSeen,l.lastSeen);return`
      <div style="display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.05)">
        <div style="width:18px;text-align:center;font-size:.7rem;color:rgba(255,255,255,.35);flex-shrink:0">${c+1}</div>
        <div style="width:150px;flex-shrink:0;overflow:hidden">
          <div style="display:flex;align-items:center">
            <span class="mono" style="font-size:.76rem;color:rgba(255,255,255,.85)" title="${g(r)}">${g(U(r))}</span>
            ${v}
          </div>
          ${h?`<div style="font-size:.62rem;color:rgba(255,255,255,.35);margin-top:1px">${g(h)}</div>`:""}
        </div>
        <div style="flex:1;height:10px;border-radius:4px;overflow:hidden;background:rgba(255,255,255,.05)">
          <div style="width:${u.toFixed(1)}%;height:100%;background:${p}"></div>
        </div>
        <div style="width:46px;text-align:center;font-size:.66rem;color:rgba(255,255,255,.5);flex-shrink:0">${f}</div>
        <div class="mono" style="width:100px;text-align:right;font-size:.75rem;color:rgba(255,255,255,.8);flex-shrink:0">${D(d,2)} XRP</div>
        <div style="width:46px;text-align:right;font-size:.68rem;color:rgba(255,255,255,.4);flex-shrink:0">${l.cnt} tx</div>
      </div>`}).join("");return`
    <div style="font-size:.65rem;color:rgba(255,255,255,.35);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px">
      Top Counterparties \u2014 ${a.length} of ${s.size} addresses, ranked by volume
    </div>
    ${i}`}function ng(e,t,n,s,a="inspect-network-map"){let o=document.getElementById(a);if(!o)return;let r=[...Ol(e,t).entries()].sort(($,P)=>P[1].xrpOut+P[1].xrpIn-($[1].xrpOut+$[1].xrpIn)||P[1].cnt-$[1].cnt).slice(0,20);if(r.length<2){o.style.display="none";return}o.style.display="";let l=560,c=340,d=l/2,u=c/2,p=95,m=7,f=155,v=13,h=r[0][1].xrpOut+r[0][1].xrpIn||1,w=r[0][1].cnt||1,k=[{id:t,x:d,y:u,r:13,main:!0,label:U(t),color:"#00d4ff",xrpOut:0,xrpIn:0,cnt:0}];r.forEach(([$,P],M)=>{let N=M<m?p:f,_=M<m?m:v,I=(M<m?M:M-m)/_*2*Math.PI-Math.PI/2,R=P.xrpOut+P.xrpIn,F=Math.max(5,Math.min(14,4+R/h*10)),W=P.entity,E=en[W==null?void 0:W.type]||en.other,z=R>0?P.xrpOut/R:.5,Q=z>.65?"out":z<.35?"in":"both";k.push({id:$,x:d+N*Math.cos(I),y:u+N*Math.sin(I),r:F,color:E,label:(W==null?void 0:W.name)||U($),ent:W,xrpOut:P.xrpOut,xrpIn:P.xrpIn,cnt:P.cnt,dir:Q,vol:R,ring:N})});let b=`<defs>
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
  </defs>`,x=k.slice(1).map($=>{let P=$.vol/h,M=Math.max(.8,P*3),N=.12+P*.45,_=$.dir==="out"?"rgba(80,250,123,":$.dir==="in"?"rgba(0,212,255,":"rgba(255,184,108,",X=$.dir==="out"?`rgba(80,250,123,${N})`:$.dir==="in"?`rgba(0,212,255,${N})`:`rgba(255,184,108,${N})`,I=$.dir==="in"?"5,3":"none",R=`marker-end="url(#arrow-${$.dir})"`,F=$.x-d,W=$.y-u,E=Math.sqrt(F*F+W*W),z=($.r+2)/E,Q=d+F*(1-z),ie=u+W*(1-z),ce=`${$.xrpOut>0?"\u2192 "+D($.xrpOut,2)+" XRP out":""}${$.xrpIn>0?($.xrpOut>0?" / ":"")+"\u2190 "+D($.xrpIn,2)+" XRP in":""}, ${$.cnt} tx`;return`<line x1="${d}" y1="${u}" x2="${Q.toFixed(1)}" y2="${ie.toFixed(1)}"
      stroke="${X}" stroke-width="${M.toFixed(1)}" stroke-dasharray="${I}" ${R}>
      <title>${ce}</title></line>`}).join(""),S=k.map($=>{var W,E;if($.main){let z=U($.id);return`<g>
        <title>Inspected account: ${g($.id)}</title>
        <circle cx="${d}" cy="${u}" r="13" fill="rgba(0,212,255,.2)" stroke="#00d4ff" stroke-width="2"/>
        <circle cx="${d}" cy="${u}" r="13" fill="rgba(0,212,255,.15)"/>
        <text x="${d}" y="${u+4}" text-anchor="middle" font-size="6.5" fill="#00d4ff" font-weight="800">${g(z)}</text>
        <text x="${d}" y="${u+13+10}" text-anchor="middle" font-size="6"
          fill="rgba(255,255,255,.4)">Inspected account</text>
      </g>`}let P=((W=$.ent)==null?void 0:W.type)==="blackhole",M=((E=$.ent)==null?void 0:E.type)==="exchange",N=P?'filter="url(#glow-red)"':"",_=$.dir==="out"?"rgba(80,250,123,.5)":$.dir==="in"?"rgba(0,212,255,.5)":"rgba(255,184,108,.5)",X=1.5,I=$.label.length>14?$.label.slice(0,14)+"\u2026":$.label,R=$.vol>0?$.xrpOut>0&&$.xrpIn>0?`\u21C4 ${D($.vol,0)} XRP`:$.xrpOut>0?`\u2192 ${D($.xrpOut,0)} XRP`:`\u2190 ${D($.xrpIn,0)} XRP`:`${$.cnt} tx`,F=$.id+($.ent?" ("+$.ent.name+")":"")+" | "+($.xrpOut>0?"Sent: "+D($.xrpOut,2)+" XRP"+nn($.xrpOut)+" | ":"")+($.xrpIn>0?"Received: "+D($.xrpIn,2)+" XRP"+nn($.xrpIn)+" | ":"")+"Interactions: "+$.cnt;return`<g style="cursor:pointer" onclick="inspectorLoadAddr('${$.id}')">
      <title>${F}</title>
      ${P?`<circle cx="${$.x}" cy="${$.y}" r="${$.r+4}" fill="rgba(255,85,85,.1)" stroke="rgba(255,85,85,.4)" stroke-width="1" stroke-dasharray="3,2"/>`:""}
      <circle cx="${$.x}" cy="${$.y}" r="${$.r}" fill="${$.color}" opacity=".18" ${N}/>
      <circle cx="${$.x}" cy="${$.y}" r="${$.r}" fill="${$.color}" opacity=".1" stroke="${_}" stroke-width="${X}"/>
      <text x="${$.x}" y="${$.y+3.5}" text-anchor="middle" font-size="${$.ring===p?7.5:6.5}"
        fill="${$.color}" font-weight="700" opacity=".95">${g(I)}</text>
      <text x="${$.x}" y="${$.y+$.r+10}" text-anchor="middle" font-size="6"
        fill="rgba(255,255,255,.4)">${g(R)}</text>
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
        ${b}${T}${x}${S}
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
    </div>`}window.generateAiExplanation=async function(){let e=document.getElementById("ai-explanation-body");if(!e)return;if(!wl()){e.innerHTML=`<p style="font-size:.82rem;color:#ffb86c;line-height:1.6">
      AI explanations aren't set up yet. Add your Anthropic API key and proxy URL in
      <strong>Profile \u2192 Settings \u2192 AI Explanations</strong>, then come back and try again.
    </p>`;return}let t=window._lastInspectResult,n=window._lastAllFindings||[];if(!t){e.innerHTML='<p style="font-size:.82rem;color:#ff5555">Run an inspection first.</p>';return}e.innerHTML='<div style="font-size:.82rem;color:rgba(255,255,255,.5)">\u{1F916} Asking Claude\u2026</div>';let s=n.length?n.map(o=>`- [${o.sev.toUpperCase()}] ${o.module}: ${o.headline}${o.detail?" \u2014 "+o.detail:""}`).join(`
`):"(No elevated findings \u2014 all checks returned normal ranges.)",a=`Account: ${t.addr}
Risk score: ${t.riskScore}/100
Wallet age: ${t.walletAgeDays!=null?t.walletAgeDays+" days":"unknown"}
Transactions analyzed: ${t.txCount}

Automated findings from a rule-based XRPL forensics scan:
${s}

Write a clear, plain-English explanation of what this account's activity suggests, for someone who isn't a blockchain expert. Synthesize the findings above into a coherent read of the account rather than restating them one by one \u2014 call out which ones reinforce each other and which are weak signals on their own. Be direct about how concerning (or not) this looks, and note any real uncertainty rather than overstating confidence. Do not repeat the address or risk score back verbatim; the reader can already see those above your response.`;try{let o=await xl(a,{system:"You are a security analyst explaining automated blockchain forensics findings to a general audience. Be direct, calibrated, and skeptical of your own confidence where the evidence is thin."});e.innerHTML=`
      <div style="font-size:.85rem;line-height:1.7;white-space:pre-wrap">${g(o)}</div>
      <button class="settings-btn" style="margin-top:12px" onclick="generateAiExplanation()">\u21BB Regenerate</button>`}catch(o){e.innerHTML=`
      <p style="font-size:.82rem;color:#ff5555;line-height:1.6">${g(o.message||"AI request failed.")}</p>
      <button class="settings-btn" style="margin-top:8px" onclick="generateAiExplanation()">Try again</button>`}};window.exportInspectorJSON=function(){var o,i;let e=window._lastInspectResult;if(!e){alert("Run an inspection first.");return}let t=new Blob([JSON.stringify(e,null,2)],{type:"application/json"}),n=URL.createObjectURL(t),s=document.createElement("a"),a=((i=(o=document.getElementById("inspect-addr-badge"))==null?void 0:o.dataset)==null?void 0:i.fullAddr)||"wallet";s.href=n,s.download=`naluxrp_${a.slice(0,10)}_${new Date().toISOString().slice(0,10)}.json`,document.body.appendChild(s),s.click(),document.body.removeChild(s),URL.revokeObjectURL(n)};var sg=6e4,ag=1e4,og=12e4,ig=8e3,rg=12e4,lg=300,Ql="nalulf_net_baseline_v2",cg=80,dg=5,Ss="/api/v1/validatorregistry",Zl="/api/v1/validator";var pg=5*60*1e3,ec=10*60*1e3,Xl=1e4,tc=8e3,Ro=new Map,Do=new Map;var Xt={quorumTight:{w:3,label:"Quorum within 3 validators of failure threshold"},nUnlActive:{w:2,label:"Negative UNL active \u2014 validators currently being ignored"},amendVeto:{w:1,label:"Amendment veto clustering \u2014 protocol governance dispute"},feeSpike:{w:2,label:"Open ledger fee 10\xD7 minimum \u2014 DDoS / spam attack likely"},burnAnomaly:{w:2,label:"XRP burn rate z-score > 3\u03C3 \u2014 resource exhaustion pattern"},peerSaturate:{w:2,label:"Inbound peers > 80% of connections \u2014 Eclipse Attack risk"},eclipseRisk:{w:3,label:"Peer count < 6 \u2014 node highly vulnerable to isolation"},dexSpike:{w:1,label:"DEX volume > 3\xD7 AMM baseline \u2014 unusual event-driven flow"},reserveSpike:{w:1,label:"New account rate > 3\xD7 baseline \u2014 possible bot creation"},slowConverge:{w:2,label:"Consensus convergence > 6s \u2014 network agreement degraded"},lowProposers:{w:2,label:"Proposer count below quorum \u2014 validator participation low"},queuePressure:{w:2,label:"TX queue > 80% full \u2014 fee surge imminent"},spamLedger:{w:1,label:"Ledger > 2\xD7 expected size \u2014 ledger spam in progress"},ioStressed:{w:1,label:"Node IO latency > 5ms \u2014 storage or network I/O stress"},peerChurn:{w:1,label:"Elevated peer disconnect rate \u2014 DDoS or instability"},staleLedger:{w:3,label:"Ledger age > 10s \u2014 validation appears stalled"}},nc={MultiSign:{purpose:"Multi-signature authorization",intro:"rippled 0.31",desc:"Lets multiple keys jointly authorize one transaction. Essential for institutional custody and hardware-wallet setups.",impact:"New transaction: SignerListSet. All signers submit their signature; the last one broadcasts."},MultiSignReserve:{purpose:"Cheaper signer-list reserve",intro:"rippled 1.2",desc:"Cuts the owner reserve for SignerList objects from 5 owner-items (10 XRP) down to 1 owner-item (2 XRP).",impact:"Existing SignerLists do not gain the reduction automatically; delete and re-create the list."},DepositAuth:{purpose:"Block unsolicited incoming payments",intro:"rippled 0.90",desc:"An account can set lsfDepositAuth so it only receives payments explicitly pre-authorized via DepositPreauth.",impact:"Senders to un-authorized accounts receive tecNO_PERMISSION."},DeletableAccounts:{purpose:"Permanent account deletion + reserve reclaim",intro:"rippled 1.4",desc:"An account with no objects and sequence \u2265 (current ledger \u2212 256) can permanently delete itself and recover the base reserve.",impact:"New transaction: AccountDelete. Sends all XRP minus fees to a destination."},NegativeUNL:{purpose:"Fault-tolerant consensus during outages",intro:"rippled 1.6",desc:"When validators are persistently offline, the network may add them to the Negative UNL so they do not count against quorum.",impact:"Enables the network to survive planned outages of up to 20% of trusted validators."},Checks:{purpose:"Deferred, cancellable payments",intro:"rippled 1.0",desc:"The sender creates a Check; the recipient can later cash it up to the authorized amount or let it expire. The sender can cancel at any time.",impact:"New transactions: CheckCreate, CheckCash, CheckCancel. Each open Check uses one owner-reserve slot."},AMM:{purpose:"Native Automated Market Maker DEX",intro:"rippled 1.12",desc:"Adds a Constant-Product (x*y=k) AMM directly in the ledger. Anyone can deposit two assets to earn LP tokens and a share of swap fees.",impact:"New transactions: AMMCreate, AMMDeposit, AMMWithdraw, AMMVote, AMMBid, AMMDelete."},XChainBridge:{purpose:"Cross-chain bridge protocol",intro:"rippled 2.0",desc:"Lets assets move between XRPL Mainnet, sidechains, and EVM chains via a locking/minting bridge secured by Witness servers.",impact:"New ledger objects: Bridge, XChainOwnedCreateAccountClaimID, etc. Requires Witness infrastructure."},Clawback:{purpose:"Token-issuer recovery",intro:"rippled 1.12",desc:"Issuers who set lsfAllowTrustLineClawback before issuing tokens can claw back tokens from any holder.",impact:"Must be enabled on a fresh account before any trust lines are created."},NonFungibleTokensV1:{purpose:"Native NFT support",intro:"rippled 1.9",desc:"Adds NFTokenMint, NFTokenBurn, and offer-based transfer mechanics for non-fungible tokens stored in NFTokenPage objects.",impact:"Each NFTokenPage holds up to 32 tokens and costs one owner-reserve slot. Royalties up to 50%."},NonFungibleTokensV1_1:{purpose:"NFT V1 corrections",intro:"rippled 1.10",desc:"Fixes pagination bugs, transfer-fee edge cases, and minting with the URI field that were present in V1.",impact:"Breaking fix for some V1 edge cases. Wallets built for V1 should test V1_1 compatibility."},PayChan:{purpose:"Payment channels for streaming micropayments",intro:"rippled 0.33",desc:"Sender deposits XRP into a channel, then issues signed claims off-ledger. Recipient submits the highest claim at any time to settle on-ledger.",impact:"New transactions: PaymentChannelCreate, PaymentChannelFund, PaymentChannelClaim."},Escrow:{purpose:"Time-locked and condition-based XRP transfers",intro:"rippled 0.60",desc:"Lock XRP until a future time OR a cryptographic fulfillment (PREIMAGE-SHA-256) is revealed, enabling vesting schedules and atomic swaps.",impact:"New transactions: EscrowCreate, EscrowFinish, EscrowCancel. Locked XRP counts against reserves."},DisallowIncoming:{purpose:"Block unsolicited ledger-object creation",intro:"rippled 1.10",desc:"New account flags let you individually block incoming Trust Lines, Check objects, NFToken offers, and Payment Channels.",impact:"Four new AccountSet flags; existing incoming objects are unaffected."},ExpandedSignerList:{purpose:"Larger multi-sig signer lists",intro:"rippled 1.9.1",desc:"Increases the maximum signers per SignerList from 8 to 32, enabling more complex institutional multi-sig and DAO governance.",impact:"Reserve cost scales with signer count. Requires MultiSignReserve to be cost-effective."},OwnerPaysFee:{purpose:"Correct fee payer in PayChan",intro:"rippled 0.33",desc:"Fixes a spec inconsistency where the channel owner correctly pays the transaction fee when closing or expiring channels.",impact:"Purely a fee-accounting fix; no user-visible behavior changes."},fixMasterKeyAsRegularKey:{purpose:"Master-key mis-use bug fix",intro:"rippled 0.90",desc:"Prevents accounts from setting their master key as their regular key \u2014 an operation that could create an unusable account state.",impact:"No application changes needed; existing accounts are not affected."},TrustSetAuth:{purpose:"Authorized trust lines",intro:"rippled 0.30",desc:"Issuers can require explicit authorization before anyone can hold their token \u2014 a prerequisite for regulatory-grade stablecoins.",impact:"New flow: issuer sends TrustSet with tfSetfAuth to approve each holder."}},Hl=new Set(["xrpscan.com","xrpl.aesthetes.art","xrpkuwait.com","xrpgoat.com","xrp.vet","xrp.unic.ac.cy","xrp-validator.interledger.org","xpmarket.com","verum.eminence.im","validator.xrpl.robertswarthout.com","validator.xrpl-labs.com","validator.poli.usp.br","validator.gatehub.net","validator.aspired.nz","v2.xrpl-commons.org","tequ.dev","squidrouter.com","ripple.ittc.ku.edu","ripple.com","peersyst.cloud","onxrp.com","katczynski.net","jon-nilsen.no","ekiserrepe.es","cabbit.tech","bithomp.com","aureusox.com","arrington-xrp-capital.blockdaemon.com","anodos.finance","bitso.com","ripple.kenan-flagler.unc.edu","ripplevalidator.uwaterloo.ca","shadow.haas.berkeley.edu","www.bitrue.com","xrp-col.anu.edu.au"]),ug=new Set(["nHBu3iuq1SQ9Z686pYwWYVKpScSMDWfpUJHdNEQRxn5XyETui7Db","nHDwBbubxJswoweWQKEgWLNRJv2hNRCTR4GGApJmbtCcbtYNSpdB","nHU2FpRbPrvVcyQQpkqrAUDJDTRHZpjij8DpKeSC481PYY9ikYkb","nHUbmg8QNzEGjHzgnt99e9YE2scU3DZGH7FsF6MCcK5eiPt3AtaH","nHUxBD1UPb383SdWgJx62GGQ7W2WKvgpUtUXLjiGGRRcPb3nbSXd","nHUP6rfQfgzg6tKga3k9ziEvtjwn1PB32gcr5dLcamqzmitszYv2","nHBT58yHyDdPdJ6gzaBMT7gqwTMpj5ERji1s9SvfKKtfoZUS89WX","nHBxsUzx3Bbf6J4yJ3fLQ3VizPtdREVwTJ6mdqkuDTjLcVbggVbk","nHUeUNSn3zce2xQZWNghQvd9WRH6FWEnCBKYVJu2vAizMxnXegfJ","nHUCAdca6VoWWYVdBH1bwCUQggEX2e5acQSqxM3DwyuhsFknxmh3","nHDDiwQBqXhEL1CFoRHdMXD33x9K7rpYJfniXxL7kFavpPd21EGe","nHBipbbREjNEiCs4hpy3K2489dRf27MPnxdivTTWKSd8ZUhfRvn8","nHDDe5uAdiv6RA59MA1oM4JLDtVSYKNShgjEqq1KsdJXZiR47CQT","nHBbiP5ua5dUqCTz5i5vd3ia9jg3KJthohDjgKxnc7LxtmnauW7Z","nHBQ3CT3EWYZ4uzbnL3k6TRf9bBPhWRFVcK1F5NjtwCBksMEt5yy","nHU16DF2kq7TmbR1Y5z8yKNXiLEf3oHT19HVpVXv7unFLfxa17nT","nHUC23NnutZyYeQxQbAbPUpKoVGj5aisBxf2zzcZzJ43fcw5rc9z","nHUgdMvuchx7AWG4ATMQdNNuMryo1SFoNptLCEVt2Dn7wEc625mF","nHUhQVE93dajM3srxubsEj1mK1gzRwJob14QSrJefY1FdLs6r7WJ","nHUU8xBczYzW6kZ6Ei9DsggzTJXRFkN3wE3FP5H4SLYzhbodeYcG","nHUGqooyfGqFkyH6uskbaEi6y2MjXjdA7QdbmyZ6p9etL5isRKLT","nHDp1ZXxEn7eo5YaUtiagaxSLwXudnKZDx68C96p4tdVLGLLLUFn","nHBcLEB4S6moQGrhMjJo1jbp58WL5psHY9EMDWNAtdqykUYiA1rF","nHUAECq1v1cKwn3NsYVyD7v6BNbfqyXmNVSF3e4XCVxPgBHRWkvv","nHUif4sukXu9pJGyyBaeVMwmE8L1fJ5KJj4X4ksgTKhgjG6k96s2","nHUVJR7SeT3nn6JPTz46JHqYRf7vX2if1sdTxnceywmSBWa167pt","nHUEYz4TtTv7yebjhY3aDib5KYPHnKjnY5mPYK5y4QuKdocwS5tD","nHUN5n2S3nQ8bzKm7bqeFMiQeDijh1LMgEocyNyQbb4mREazVdZ5","nHUgchANqM3giYSSvY5HsafFW6qxmG5jJ3CvPiv7n8gjNQuNm8Uz","nHDUqGoM7KR1pgbdYBRgKpGKdFLhpnMzVbECs8RE73RGZm3Va6MJ","nHUVxTi8XfXjaaJppw7mLSrYDRpkDpf8H9ypzgVKxfSXShcWwAoK","nHBveTxA1NaBj5AayRAU91f6YopuFWt9rmxfGaEh77a32Q6ZzzHc"]),mg=new Set(["validator.pftperry.com","rip973.com","preaware.org","postfiat.org","pftmeech.xyz","pft.xbtseal.com","pft.wizbubba.xyz","pft.permanentupperclass.com","pft.g.money","pft.akirax.xyz","jollydinger.com","auri0x.io","app.w.ai"]);function sc(e,t){let n=(t||"").toLowerCase().replace(/^www\./,"");return ug.has(e)||mg.has(n)?{chain:"test",isUnl:!1}:Hl.has(n)||Hl.has("www."+n)?{chain:"main",isUnl:!0}:{chain:"main",isUnl:!1}}var Ho={"xrpscan.com":{label:"XRP Scan",domain:"xrpscan.com",chain:"main",category:"unl"},"xrpl.aesthetes.art":{label:"Aesthetes",domain:"xrpl.aesthetes.art",chain:"main",category:"unl"},"xrpkuwait.com":{label:"XRP Kuwait",domain:"xrpkuwait.com",chain:"main",category:"unl"},"xrpgoat.com":{label:"XRP Goat",domain:"xrpgoat.com",chain:"main",category:"unl"},"xrp.vet":{label:"XRP Vet",domain:"xrp.vet",chain:"main",category:"unl"},"xrp.unic.ac.cy":{label:"Univ. of Nicosia",domain:"xrp.unic.ac.cy",chain:"main",category:"unl"},"xrp-validator.interledger.org":{label:"Interledger",domain:"xrp-validator.interledger.org",chain:"main",category:"unl"},"xpmarket.com":{label:"XPMarket",domain:"xpmarket.com",chain:"main",category:"unl"},"verum.eminence.im":{label:"Eminence",domain:"verum.eminence.im",chain:"main",category:"unl"},"validator.xrpl.robertswarthout.com":{label:"R. Swarthout",domain:"validator.xrpl.robertswarthout.com",chain:"main",category:"unl"},"validator.xrpl-labs.com":{label:"XRPL Labs",domain:"validator.xrpl-labs.com",chain:"main",category:"unl"},"validator.poli.usp.br":{label:"USP",domain:"validator.poli.usp.br",chain:"main",category:"unl"},"validator.gatehub.net":{label:"Gatehub",domain:"validator.gatehub.net",chain:"main",category:"unl"},"validator.aspired.nz":{label:"Aspired NZ",domain:"validator.aspired.nz",chain:"main",category:"unl"},"v2.xrpl-commons.org":{label:"XRPL Commons",domain:"v2.xrpl-commons.org",chain:"main",category:"unl"},"tequ.dev":{label:"Tequ",domain:"tequ.dev",chain:"main",category:"unl"},"squidrouter.com":{label:"Squid Router",domain:"squidrouter.com",chain:"main",category:"unl"},"ripple.ittc.ku.edu":{label:"Univ. of Kansas",domain:"ripple.ittc.ku.edu",chain:"main",category:"unl"},"ripple.com":{label:"Ripple",domain:"ripple.com",chain:"main",category:"unl"},"peersyst.cloud":{label:"Peersyst",domain:"peersyst.cloud",chain:"main",category:"unl"},"onxrp.com":{label:"OnXRP",domain:"onxrp.com",chain:"main",category:"unl"},"katczynski.net":{label:"Katczynski",domain:"katczynski.net",chain:"main",category:"unl"},"jon-nilsen.no":{label:"Jon Nilsen",domain:"jon-nilsen.no",chain:"main",category:"unl"},"ekiserrepe.es":{label:"Ekiserrepe",domain:"ekiserrepe.es",chain:"main",category:"unl"},"cabbit.tech":{label:"Cabbit",domain:"cabbit.tech",chain:"main",category:"unl"},"bithomp.com":{label:"Bithomp",domain:"bithomp.com",chain:"main",category:"unl"},"aureusox.com":{label:"Aureus Ox",domain:"aureusox.com",chain:"main",category:"unl"},"arrington-xrp-capital.blockdaemon.com":{label:"Arrington / Blockdaemon",domain:"arrington-xrp-capital.blockdaemon.com",chain:"main",category:"unl"},"anodos.finance":{label:"Anodos Finance",domain:"anodos.finance",chain:"main",category:"unl"},"bitso.com":{label:"Bitso",domain:"bitso.com",chain:"main",category:"unl"},"ripple.kenan-flagler.unc.edu":{label:"UNC Kenan-Flagler",domain:"ripple.kenan-flagler.unc.edu",chain:"main",category:"unl"},"ripplevalidator.uwaterloo.ca":{label:"Univ. of Waterloo",domain:"ripplevalidator.uwaterloo.ca",chain:"main",category:"unl"},"shadow.haas.berkeley.edu":{label:"UC Berkeley Haas",domain:"shadow.haas.berkeley.edu",chain:"main",category:"unl"},"www.bitrue.com":{label:"Bitrue",domain:"www.bitrue.com",chain:"main",category:"unl"},"xrp-col.anu.edu.au":{label:"ANU",domain:"xrp-col.anu.edu.au",chain:"main",category:"unl"},"xrpval.rawsec.de":{label:"Rawsec",domain:"xrpval.rawsec.de",chain:"main",category:"other"},"xrplvl.carbonvibe.com":{label:"Carbon Vibe",domain:"xrplvl.carbonvibe.com",chain:"main",category:"other"},"xrplvalidator.alloy.ee":{label:"Alloy",domain:"xrplvalidator.alloy.ee",chain:"main",category:"other"},"xrpl.uni.lu":{label:"Univ. of Luxembourg",domain:"xrpl.uni.lu",chain:"main",category:"other"},"xrpl.to":{label:"XRPL.to",domain:"xrpl.to",chain:"main",category:"other"},"xrpl.su":{label:"XRPL.su",domain:"xrpl.su",chain:"main",category:"other"},"xrpl.sbivc.co.jp":{label:"SBI VC Trade",domain:"xrpl.sbivc.co.jp",chain:"main",category:"other"},"xrpl-verification.flare.network":{label:"Flare Network",domain:"xrpl-verification.flare.network",chain:"main",category:"other"},"xrpl-validator.7rev.dev":{label:"7Rev",domain:"xrpl-validator.7rev.dev",chain:"main",category:"other"},"xrp.teacopula.com":{label:"Teacopula",domain:"xrp.teacopula.com",chain:"main",category:"other"},"xrp.moneymindedapes.com":{label:"MoneyMindedApes",domain:"xrp.moneymindedapes.com",chain:"main",category:"other"},"xrp.hazza-systems.de":{label:"Hazza Systems",domain:"xrp.hazza-systems.de",chain:"main",category:"other"},"xrp.cs.uoregon.edu":{label:"Univ. of Oregon",domain:"xrp.cs.uoregon.edu",chain:"main",category:"other"},"xrp.bpsqn.com":{label:"BPSQN",domain:"xrp.bpsqn.com",chain:"main",category:"other"},"xrp-validator.grapedrop.xyz":{label:"Grapedrop",domain:"xrp-validator.grapedrop.xyz",chain:"main",category:"other"},"xaodao.io":{label:"XaoDAO",domain:"xaodao.io",chain:"main",category:"other"},"vl.xrpsalute.com":{label:"XRP Salute",domain:"vl.xrpsalute.com",chain:"main",category:"other"},"validator.xrpl.app":{label:"XRPL App",domain:"validator.xrpl.app",chain:"main",category:"other"},"validator.ukcbt.org":{label:"UKCBT",domain:"validator.ukcbt.org",chain:"main",category:"other"},"validator.sugarxrpl.com":{label:"SugarXRPL",domain:"validator.sugarxrpl.com",chain:"main",category:"other"},"validator.boscaern.digital":{label:"Boscaern",domain:"validator.boscaern.digital",chain:"main",category:"other"},"trimaera.tech":{label:"Trimaera",domain:"trimaera.tech",chain:"main",category:"other"},"textrp.io":{label:"TextRP",domain:"textrp.io",chain:"main",category:"other"},"tesbert.com":{label:"Tesbert",domain:"tesbert.com",chain:"main",category:"other"},"tachyon-xrpl-validator.github.io":{label:"Tachyon",domain:"tachyon-xrpl-validator.github.io",chain:"main",category:"other"},"solonation.io":{label:"SoloNation",domain:"solonation.io",chain:"main",category:"other"},"smokydrip.com":{label:"SmokyDrip",domain:"smokydrip.com",chain:"main",category:"other"},"rippled-validator.us":{label:"rippled-validator.us",domain:"rippled-validator.us",chain:"main",category:"other"},"rippleat.snt.uni.lu":{label:"Univ. Luxembourg (SNT)",domain:"rippleat.snt.uni.lu",chain:"main",category:"other"},"ripple.uni.lu":{label:"Univ. Luxembourg",domain:"ripple.uni.lu",chain:"main",category:"other"},"ripple.j2b.com":{label:"J2B",domain:"ripple.j2b.com",chain:"main",category:"other"},"rich-list.info":{label:"Rich List",domain:"rich-list.info",chain:"main",category:"other"},"proptoexchange.com":{label:"ProPtoExchange",domain:"proptoexchange.com",chain:"main",category:"other"},"printscierge.com":{label:"Printscierge",domain:"printscierge.com",chain:"main",category:"other"},"opulencex.io":{label:"OpulenceX",domain:"opulencex.io",chain:"main",category:"other"},"onledger.net":{label:"OnLedger",domain:"onledger.net",chain:"main",category:"other"},"oclost.art":{label:"Oclost",domain:"oclost.art",chain:"main",category:"other"},"managednetwork.us":{label:"ManagedNetwork",domain:"managednetwork.us",chain:"main",category:"other"},"joshuahamsa.com":{label:"Joshua Hamsa",domain:"joshuahamsa.com",chain:"main",category:"other"},"grimmsxrpflow.jwscott.net":{label:"Grimm XRP Flow",domain:"grimmsxrpflow.jwscott.net",chain:"main",category:"other"},"getlol.xyz":{label:"GetLol",domain:"getlol.xyz",chain:"main",category:"other"},"gen3labs.xyz":{label:"Gen3 Labs",domain:"gen3labs.xyz",chain:"main",category:"other"},"garveyvalid.com":{label:"Garvey",domain:"garveyvalid.com",chain:"main",category:"other"},"easynpl.kr":{label:"EasyNPL",domain:"easynpl.kr",chain:"main",category:"other"},"diseb.ewi.tudelft.nl":{label:"TU Delft",domain:"diseb.ewi.tudelft.nl",chain:"main",category:"other"},"datamossa.com":{label:"DataMossa",domain:"datamossa.com",chain:"main",category:"other"},"crypto.unibe.ch":{label:"Univ. of Bern",domain:"crypto.unibe.ch",chain:"main",category:"other"},"commonprefix.com":{label:"Common Prefix",domain:"commonprefix.com",chain:"main",category:"other"},"catalyze-research.com":{label:"Catalyze Research",domain:"catalyze-research.com",chain:"main",category:"other"},"catalog.org":{label:"Catalog",domain:"catalog.org",chain:"main",category:"other"},"blockchain.korea.ac.kr":{label:"Korea Univ.",domain:"blockchain.korea.ac.kr",chain:"main",category:"other"},"astatiumprotocol.com":{label:"Astatium Protocol",domain:"astatiumprotocol.com",chain:"main",category:"other"},"ladykxrpl.mywire.org":{label:"LadyK XRPL",domain:"LadyKXRPL.mywire.org",chain:"main",category:"other"},"eelap-p1201-xrp.abudhabi.nyu.edu":{label:"NYU Abu Dhabi",domain:"EELAP-P1201-XRP.ABUDHABI.NYU.EDU",chain:"main",category:"other"},"589.clouds.hspeed.ch":{label:"HSpeed",domain:"589.clouds.hspeed.ch",chain:"main",category:"other"},"validator.pftperry.com":{label:"PFT Perry",domain:"validator.pftperry.com",chain:"test",category:"other"},"rip973.com":{label:"rip973",domain:"rip973.com",chain:"test",category:"other"},"preaware.org":{label:"Preaware",domain:"preaware.org",chain:"test",category:"other"},"postfiat.org":{label:"PostFiat",domain:"postfiat.org",chain:"test",category:"other"},"pftmeech.xyz":{label:"PFT Meech",domain:"pftmeech.xyz",chain:"test",category:"other"},"pft.xbtseal.com":{label:"PFT XBT Seal",domain:"pft.xbtseal.com",chain:"test",category:"other"},"pft.wizbubba.xyz":{label:"PFT Wizbubba",domain:"pft.wizbubba.xyz",chain:"test",category:"other"},"pft.permanentupperclass.com":{label:"PFT Perm Upper Class",domain:"pft.permanentupperclass.com",chain:"test",category:"other"},"pft.g.money":{label:"PFT G.Money",domain:"pft.g.money",chain:"test",category:"other"},"pft.akirax.xyz":{label:"PFT Akirax",domain:"pft.akirax.xyz",chain:"test",category:"other"},"jollydinger.com":{label:"Jollydinger",domain:"jollydinger.com",chain:"test",category:"other"},"auri0x.io":{label:"Auri0x",domain:"auri0x.io",chain:"test",category:"other"},"app.w.ai":{label:"W.ai",domain:"app.w.ai",chain:"test",category:"other"}},wa={nHB8QMKGt9VB4Vg71VszjBVQnDW3v3QudM4436zXRZgiuUBBSWJe:{lat:37.77,lng:-122.42,city:"San Francisco",org:"Ripple"},nHUon2tpyJEHHYGmxqNd3h3oGNQwNyX8PNS3aHe3bNpCrNXZlHo:{lat:37.77,lng:-122.41,city:"San Francisco",org:"Ripple"},nHUpwrafS45zmi6eT72XS5ijpkW5JwfL5mLdPhEibrqUvtRcMAjU:{lat:37.78,lng:-122.4,city:"San Francisco",org:"Ripple"},nHUkp7WhouVMobBUKGrV5FNqjsdD9zKP5jpGnnLfQXCMNe4dkDqo:{lat:37.76,lng:-122.43,city:"San Francisco",org:"Ripple"},nHUryiyDqEtyWVtFG24AAhaYjMf9FRLietZGBWYwUTojmugMsx3o:{lat:37.79,lng:-122.38,city:"San Francisco",org:"Ripple"},nHUpcmNsxAw47yt2ADDoNoQrzLyTJPgnyq16u6Qx2kRPA17oUNHz:{lat:37.8,lng:-122.39,city:"San Francisco",org:"Ripple"},nHUnhRJK3csknycNK5SXRFi8jvDp3sKoWvS9wKWLq1ATBBGgPBjp:{lat:37.75,lng:-122.44,city:"San Francisco",org:"Ripple"},nHUq9tJvk5QTDkwurB7EzbzkZ2uuoHjS3GKjP6pZiU3DJGnobNYK:{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"AWS (Coil)"},nHUvcCcmoH1FJMMC6NtF9KKA4LpCWhjsxk2reCQidsp5AHQ7QY9H:{lat:49.45,lng:11.08,city:"Nuremberg",org:"Hetzner (Gatehub)"},nHDH7bQJpVfDhVSqdui3Z8GPvKEBQpo6AKHcnXe21zoD4nABA6xj:{lat:52.37,lng:4.9,city:"Amsterdam",org:"GCP (XRPL Labs)"},nHUED59jjpQ5QbNtesAbB6Es3uUPv3c9Ri5MNNgfMv5t5Lhb5ndW:{lat:19.43,lng:-99.13,city:"Mexico City",org:"AWS (Bitso)"},nHBidG3pZK11zqjeVos6hFxTDPGYuqfRFZ5gu9b7tQFdB8nPZujG:{lat:35.69,lng:139.69,city:"Tokyo",org:"NTT (Digital Garage)"},nHDB2PAPYqF86j9j3c6w1F1ZqwvQfiWcFShZ9Pokg9q4ohNDSkAz:{lat:47.61,lng:-122.33,city:"Seattle, WA",org:"Azure (Arrington)"},nHUdphn3LXa31w5sLd39MQdPEKQNrNYL3DQFByijVXiNQ3G6BYBZ:{lat:1.35,lng:103.82,city:"Singapore",org:"AWS (Tokenize)"},nHUFCyRCrUjvtZmKiLeF8ReopzKuSkVzdl1VsMCqm75aqyohLYEg:{lat:48.86,lng:2.35,city:"Paris",org:"OVH (XRPL Commons)"},nHULqGBkJtWeNFjhTzYeAsHA3qKKS7HoBh8CV3BAGTGMZuepEhWC:{lat:40.71,lng:-74.01,city:"New York",org:"Equinix (Blockchain LLC)"},nHBdXSF6YHAHSZUk7rvox6jwbvvyqBnsWGcewBtq8x1XuH6KXKXr:{lat:37.79,lng:-122.4,city:"San Francisco",org:"Cloudflare (XRP Scan)"}},zl={"xrpscan.com":{lat:51.51,lng:-.13,city:"London",org:"XRPScan"},"xrpl.aesthetes.art":{lat:52.37,lng:4.9,city:"Amsterdam",org:"Aesthetes"},"xrpkuwait.com":{lat:29.37,lng:47.98,city:"Kuwait City",org:"XRP Kuwait"},"xrpgoat.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"XRP Goat"},"xrp.vet":{lat:48.86,lng:2.35,city:"Paris",org:"XRP Vet"},"xrp.unic.ac.cy":{lat:35.17,lng:33.37,city:"Nicosia",org:"Univ. of Nicosia"},"xrp-validator.interledger.org":{lat:40.71,lng:-74.01,city:"New York",org:"Interledger Foundation"},"xpmarket.com":{lat:52.37,lng:4.9,city:"Amsterdam",org:"XPMarket"},"verum.eminence.im":{lat:51.51,lng:-.13,city:"London",org:"Eminence"},"validator.xrpl.robertswarthout.com":{lat:52.37,lng:4.9,city:"Amsterdam",org:"R. Swarthout"},"validator.xrpl-labs.com":{lat:52.37,lng:4.9,city:"Amsterdam",org:"XRPL Labs"},"validator.xrpl.app":{lat:52.37,lng:4.9,city:"Amsterdam",org:"XRPL App"},"validator.poli.usp.br":{lat:-23.55,lng:-46.63,city:"S\xE3o Paulo",org:"USP"},"validator.gatehub.net":{lat:46.05,lng:14.51,city:"Ljubljana",org:"Gatehub"},"validator.aspired.nz":{lat:-36.86,lng:174.76,city:"Auckland",org:"Aspired NZ"},"v2.xrpl-commons.org":{lat:48.86,lng:2.35,city:"Paris",org:"XRPL Commons"},"tequ.dev":{lat:60.17,lng:24.94,city:"Helsinki",org:"Tequ"},"squidrouter.com":{lat:37.77,lng:-122.42,city:"San Francisco",org:"Squid Router"},"ripple.ittc.ku.edu":{lat:38.97,lng:-95.24,city:"Lawrence, KS",org:"Univ. of Kansas"},"ripple.com":{lat:37.77,lng:-122.42,city:"San Francisco",org:"Ripple"},"peersyst.cloud":{lat:41.39,lng:2.15,city:"Barcelona",org:"Peersyst"},"onxrp.com":{lat:51.51,lng:-.13,city:"London",org:"OnXRP"},"katczynski.net":{lat:52.23,lng:21.01,city:"Warsaw",org:"Katczynski"},"jon-nilsen.no":{lat:59.91,lng:10.75,city:"Oslo",org:"Jon Nilsen"},"ekiserrepe.es":{lat:40.42,lng:-3.7,city:"Madrid",org:"Ekiserrepe"},"cabbit.tech":{lat:51.51,lng:-.13,city:"London",org:"Cabbit"},"bithomp.com":{lat:59.33,lng:18.07,city:"Stockholm",org:"Bithomp"},"aureusox.com":{lat:40.71,lng:-74.01,city:"New York",org:"Aureus Ox"},"arrington-xrp-capital.blockdaemon.com":{lat:40.71,lng:-74.01,city:"New York",org:"Blockdaemon"},"anodos.finance":{lat:37.98,lng:23.73,city:"Athens",org:"Anodos Finance"},"bitso.com":{lat:19.43,lng:-99.13,city:"Mexico City",org:"Bitso"},"ripple.kenan-flagler.unc.edu":{lat:35.9,lng:-79.05,city:"Chapel Hill, NC",org:"UNC Kenan-Flagler"},"ripplevalidator.uwaterloo.ca":{lat:43.47,lng:-80.54,city:"Waterloo, ON",org:"Univ. of Waterloo"},"shadow.haas.berkeley.edu":{lat:37.87,lng:-122.26,city:"Berkeley, CA",org:"UC Berkeley Haas"},"www.bitrue.com":{lat:1.35,lng:103.82,city:"Singapore",org:"Bitrue"},"xrp-col.anu.edu.au":{lat:-35.28,lng:149.13,city:"Canberra",org:"ANU"},"xrpval.rawsec.de":{lat:51.17,lng:10.45,city:"Germany",org:"Rawsec"},"xrplvl.carbonvibe.com":{lat:51.51,lng:-.13,city:"London",org:"Carbon Vibe"},"xrplvalidator.alloy.ee":{lat:59.44,lng:24.75,city:"Tallinn",org:"Alloy"},"xrpl.uni.lu":{lat:49.61,lng:6.13,city:"Luxembourg",org:"Univ. of Luxembourg"},"xrpl.to":{lat:48.86,lng:2.35,city:"Paris",org:"XRPL.to"},"xrpl.su":{lat:55.75,lng:37.62,city:"Moscow",org:"XRPL.su"},"xrpl.sbivc.co.jp":{lat:35.69,lng:139.69,city:"Tokyo",org:"SBI VC Trade"},"xrpl-verification.flare.network":{lat:51.51,lng:-.13,city:"London",org:"Flare Network"},"xrpl-validator.7rev.dev":{lat:52.52,lng:13.4,city:"Berlin",org:"7Rev"},"xrp.teacopula.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"Teacopula"},"xrp.moneymindedapes.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"MoneyMindedApes"},"xrp.hazza-systems.de":{lat:52.52,lng:13.4,city:"Berlin",org:"Hazza Systems"},"xrp.cs.uoregon.edu":{lat:44.05,lng:-123.08,city:"Eugene, OR",org:"Univ. of Oregon"},"xrp.bpsqn.com":{lat:37.77,lng:-122.42,city:"San Francisco",org:"BPSQN"},"xrp-validator.grapedrop.xyz":{lat:52.37,lng:4.9,city:"Amsterdam",org:"Grapedrop"},"xaodao.io":{lat:1.35,lng:103.82,city:"Singapore",org:"XaoDAO"},"vl.xrpsalute.com":{lat:40.71,lng:-74.01,city:"New York",org:"XRP Salute"},"validator.ukcbt.org":{lat:51.51,lng:-.13,city:"London",org:"UKCBT"},"validator.sugarxrpl.com":{lat:37.77,lng:-122.42,city:"San Francisco",org:"SugarXRPL"},"validator.boscaern.digital":{lat:53.33,lng:-6.25,city:"Dublin",org:"Boscaern"},"trimaera.tech":{lat:48.86,lng:2.35,city:"Paris",org:"Trimaera"},"textrp.io":{lat:1.35,lng:103.82,city:"Singapore",org:"TextRP"},"tesbert.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"Tesbert"},"tachyon-xrpl-validator.github.io":{lat:37.77,lng:-122.42,city:"San Francisco",org:"Tachyon"},"solonation.io":{lat:1.35,lng:103.82,city:"Singapore",org:"SoloNation"},"smokydrip.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"SmokyDrip"},"rippled-validator.us":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"rippled-validator.us"},"rippleat.snt.uni.lu":{lat:49.61,lng:6.13,city:"Luxembourg",org:"Univ. of Luxembourg"},"ripple.uni.lu":{lat:49.61,lng:6.13,city:"Luxembourg",org:"Univ. of Luxembourg"},"ripple.j2b.com":{lat:37.77,lng:-122.42,city:"San Francisco",org:"J2B"},"rich-list.info":{lat:51.51,lng:-.13,city:"London",org:"Rich List"},"proptoexchange.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"ProPtoExchange"},"printscierge.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"Printscierge"},"opulencex.io":{lat:1.35,lng:103.82,city:"Singapore",org:"OpulenceX"},"onledger.net":{lat:52.37,lng:4.9,city:"Amsterdam",org:"OnLedger"},"oclost.art":{lat:48.86,lng:2.35,city:"Paris",org:"Oclost"},"managednetwork.us":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"ManagedNetwork"},"joshuahamsa.com":{lat:37.77,lng:-122.42,city:"San Francisco",org:"Joshua Hamsa"},"grimmsxrpflow.jwscott.net":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"Grimm XRP Flow"},"getlol.xyz":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"GetLol"},"gen3labs.xyz":{lat:37.77,lng:-122.42,city:"San Francisco",org:"Gen3 Labs"},"garveyvalid.com":{lat:40.71,lng:-74.01,city:"New York",org:"Garvey"},"easynpl.kr":{lat:37.57,lng:126.98,city:"Seoul",org:"EasyNPL"},"diseb.ewi.tudelft.nl":{lat:52,lng:4.36,city:"Delft",org:"TU Delft"},"datamossa.com":{lat:48.86,lng:2.35,city:"Paris",org:"DataMossa"},"crypto.unibe.ch":{lat:46.95,lng:7.45,city:"Bern",org:"Univ. of Bern"},"commonprefix.com":{lat:37.98,lng:23.73,city:"Athens",org:"Common Prefix"},"catalyze-research.com":{lat:51.51,lng:-.13,city:"London",org:"Catalyze Research"},"catalog.org":{lat:37.77,lng:-122.42,city:"San Francisco",org:"Catalog"},"blockchain.korea.ac.kr":{lat:37.57,lng:126.98,city:"Seoul",org:"Korea Univ."},"astatiumprotocol.com":{lat:1.35,lng:103.82,city:"Singapore",org:"Astatium Protocol"},"ladykxrpl.mywire.org":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"LadyK XRPL"},"eelap-p1201-xrp.abudhabi.nyu.edu":{lat:24.47,lng:54.37,city:"Abu Dhabi",org:"NYU Abu Dhabi"},"589.clouds.hspeed.ch":{lat:47.38,lng:8.54,city:"Zurich",org:"HSpeed"},"www.payonline.financial":{lat:55.75,lng:37.62,city:"Moscow",org:"PayOnline"}};function zo(e){if(!e)return null;let t=e.toLowerCase().replace(/^www\./,"");return zl[t]??zl["www."+t]??null}var fg=[{lat:37.34,lng:-121.89,label:"s1.ripple.com",city:"San Jose, CA",org:"Ripple"},{lat:37.34,lng:-121.87,label:"s2.ripple.com",city:"San Jose, CA",org:"Ripple"},{lat:52.37,lng:4.91,label:"xrplcluster.com",city:"Amsterdam",org:"Cluster"},{lat:52.36,lng:4.89,label:"xrpl.ws",city:"Amsterdam",org:"Cluster"}],_e={nunl:{hex:"#ff5555",glow:"rgba(255,85,85,.4)",label:"Negative UNL"},both:{hex:"#50fa7b",glow:"rgba(80,250,123,.4)",label:"UNL + dUNL"},unl:{hex:"#00fff0",glow:"rgba(0,255,240,.35)",label:"UNL"},dunl:{hex:"#bd93f9",glow:"rgba(189,147,249,.4)",label:"dUNL only"},other:{hex:"#ffb86c",glow:"rgba(255,184,108,.4)",label:"Other"},pub:{hex:"#50fa7b",glow:"rgba(80,250,123,.4)",label:"Public Node"}},Io="https://api.xrpscan.com/api/v1/validatorregistry",$e=new Map,sn={},ba=0,$n=!1,an="fallback";function ac(){if(!$n){$e.clear();for(let[e,t]of Object.entries(Ho)){let n=t.domain??e,s=sc("",n),a=zo(n)??null;$e.set(e,{key:e,label:t.label,domain:n,domainVerified:!1,provider:t.provider??(a==null?void 0:a.org)??null,lists:t.lists??[],category:s.isUnl?"unl":"other",chain:s.chain,unl:s.isUnl,dunl:!1,geo:a,meta:{},agreement:{"1h":null,"24h":null,"30d":null}})}an="fallback",Uo({ok:!1,source:"fallback",error:"using hardcoded data \u2014 mount /api/v1 router"})}}var Fo=0,hg=5*60*1e3;function Ul(e,t){var s,a;let n=Array.isArray(e)?e:e.validators??e.data??[];if(!n.length)throw new Error("Empty validators array");$e.clear();for(let o of n){let i=o.key??o.validation_public_key??o.master_key??o.signing_key??null;if(!i)continue;let r=o.domain??null,l=r?r.toLowerCase().replace(/^www\./,""):null,c=o.unl===!0||o.unl===1||o.unl==="true",d=sc(i,l),u=c||d.isUnl,p=d.chain,m=u?"unl":"other",f=Object.values(Ho).find(b=>b.domain&&b.domain.toLowerCase().replace(/^www\./,"")===l),v=(f==null?void 0:f.label)??o.label??o.account_name??o.name??l??null??`${i.slice(0,8)}\u2026${i.slice(-6)}`,h=wa[i]??zo(l)??null,k=(((s=o.geo)==null?void 0:s.lat)!=null&&((a=o.geo)==null?void 0:a.lng)!=null?o.geo:null)??h;$e.set(i,{key:i,label:v,domain:r??null,domainVerified:!!(o.domainVerified??o.domain_verified),provider:o.provider??(k==null?void 0:k.org)??(f==null?void 0:f.provider)??null,lists:Array.isArray(o.lists)?o.lists:[],category:m,chain:p,unl:u,dunl:!1,geo:k,version:o.version??o.build_version??null,baseFee:o.base_fee_xrp??o.base_fee??null,ownerReserve:o.reserve_inc_xrp??o.owner_reserve??null,meta:o.meta??{},agreement:o.agreement??{"1h":No(o.agreement_1h??o.agr_1h),"24h":No(o.agreement_24h??o.agr_24h),"30d":No(o.agreement_30d??o.agr_30d)}})}sn=e.lists??{},ba=Date.now(),$n=!0,an=t,Fo=0,Uo({ok:!0,count:$e.size,lists:sn,source:t})}function No(e){if(!e)return null;let t=Number(e.total??e.ledgers??0),n=Number(e.missed??0),s=t-n,a=t>0?(s/t*100).toFixed(1):null;return{total:t,missed:n,hit:s,score:a?`${a}%`:null,scoreRaw:e.score??null}}async function va(e=!1){let t=Date.now();if(!e&&$n&&t-ba<pg)return!0;if(!e&&!$n&&t-Fo<hg)return!1;let n=typeof Ss=="string"&&Ss.startsWith("/api/"),s=location.protocol==="file:"||location.hostname==="127.0.0.1"||location.hostname==="localhost";if(!(n&&s))try{let a=new AbortController,o=setTimeout(()=>a.abort(),Xl),i=await fetch(Ss,{signal:a.signal,headers:{Accept:"application/json"}});if(clearTimeout(o),!i.ok)throw new Error(`HTTP ${i.status}`);let r=await i.json();return Ul(r,"proxy"),!0}catch(a){console.warn("[registry] tier 1 (proxy) failed:",a.message)}try{let a=new AbortController,o=setTimeout(()=>a.abort(),Xl),i=await fetch(Io,{signal:a.signal});if(clearTimeout(o),!i.ok)throw new Error(`HTTP ${i.status}`);let r=await i.text(),l=JSON.parse(r);return Ul(l,"xrpscan"),!0}catch(a){console.warn("[registry] tier 2 (xrpscan direct) failed:",a.message),(a.message.includes("Failed to fetch")||a.message.includes("CORS"))&&console.warn("[registry] CORS blocked \u2014 mount the backend proxy route (see validatorregistry.js)")}return console.warn("[registry] all sources failed \u2014 showing",Object.keys(Ho).length,"hardcoded validators"),Fo=Date.now(),$n||ac(),Uo({ok:!1,source:"fallback",error:"all sources failed \u2014 mount /api/v1 router"}),!1}window.debugRegistry=async function(){console.group("\u{1F50D} Registry debug"),console.log("Current source:",an),console.log("Validators loaded:",$e.size),console.log("Registry ok:",$n),console.log("Last fetch:",ba?new Date(ba).toLocaleTimeString():"never"),console.log(""),console.log("Testing proxy \u2192",Ss);try{let e=await fetch(Ss),t=await e.text();console.log("  Status:",e.status,"\u2014 body preview:",t.slice(0,300))}catch(e){console.warn("  Failed:",e.message)}console.log(""),console.log("Testing XRPScan direct \u2192",Io);try{let e=await fetch(Io),t=await e.text();console.log("  Status:",e.status,"\u2014 body preview:",t.slice(0,300))}catch(e){console.warn("  Failed:",e.message)}return console.groupEnd(),{source:an,size:$e.size,ok:$n}};function Ke(e){return $e.get(e)??{key:e,label:`${e.slice(0,10)}\u2026${e.slice(-6)}`,domain:null,provider:null,lists:[],category:"other",geo:wa[e]??null,meta:{}}}function on(e){var n;if(!e)return null;if(((n=e.geo)==null?void 0:n.lat)!=null)return e.geo;let t=wa[e.key];return t||zo(e.domain)}function oc(){return[...$e.values()].filter(e=>(e.category==="unl"||e.category==="both")&&e.chain!=="test").map(e=>e.key)}function gg(){return[...$e.values()].filter(e=>(e.category==="dunl"||e.category==="both")&&e.chain!=="test").map(e=>e.key)}function vg(){return[...$e.values()].filter(e=>e.category==="other"&&e.chain!=="test").map(e=>e.key)}function bg(){return[...$e.values()].filter(e=>e.chain==="test").map(e=>e.key)}function Uo({ok:e,count:t,lists:n,source:s,error:a}){let o=y("m1-registry-badge");if(o)if(e){let i=[...$e.values()].filter(c=>c.category==="unl").length,r=[...$e.values()].filter(c=>c.chain==="test").length,l=t-r;o.textContent=`${l} mainnet \xB7 ${i} UNL \xB7 ${r} testnet \xB7 live`,o.className="registry-badge registry-badge--ok"}else o.textContent=s==="fallback"?`Fallback data \xB7 ${$e.size} known \xB7 ${a??"endpoint unreachable"}`:"Refreshing\u2026",o.className="registry-badge registry-badge--warn"}var ya=null,Wl=!1,_o=!1,jl=0,ql=0,Vl=0,Gl=0,ic=!0,qe=null,kn=null,Ls=null,At=null,Fe={},ha=null,Bo={},je=null,Ot=[],ga=null,Oo={},ks="unl",tt={fees:[],burnDrops:[],dexOffers:[],ammSwaps:[],newAccounts:[],converge:[],proposers:[],peerCounts:[],peerDiscon:[]};function rc(){var t,n;if(Wl)return;Wl=!0,jg(),ac(),va(!0),zg(),Ug(),window.addEventListener("xrpl-connected",()=>{$s(),es()&&(Ts({force:!0}),Cs({force:!1}))}),window.addEventListener("xrpl-disconnected",()=>{cc(),uc(null)}),window.addEventListener("xrpl-ledger",s=>{Og(s.detail),es()&&Xg(s.detail)}),(t=y("btn-network-refresh"))==null||t.addEventListener("click",()=>{Ts({force:!0}),va(!0),Cs({force:!0})}),(n=document.querySelector('.dash-tab[data-tab="network"]'))==null||n.addEventListener("click",()=>{$s(),Ts({force:!0}),va(!1),Cs({force:!1})});let e=y("tab-network");e&&new MutationObserver($s).observe(e,{attributes:!0,attributeFilter:["style","class"]}),document.addEventListener("visibilitychange",$s)}function es(){let e=y("tab-network"),t=e?e.style.display!=="none":!1;return ic&&O.currentPage==="dashboard"&&O.currentTab==="network"&&t&&!document.hidden}function $s(){es()?yg():cc()}function lc(e){ic=!!e,$s()}function yg(){ya||(Ts({force:!1}),ya=setInterval(()=>{es()&&Ts({force:!1})},sg))}function cc(){clearInterval(ya),ya=null}async function Ts({force:e=!1}={}){var n;if(!es()&&!e)return;let t=Date.now();if(!(!e&&(t-jl<ag||_o||t<ql))){_o=!0,jl=t,Fe={},Kl(!0);try{await Promise.allSettled([va(!1),wg(),xg(),kg(),$g(),Sg()]),Tg(),Pg(),Ag(),Eg(),Fg(),uc({info:qe,fee:kn,vals:Ls}),qg()}catch(s){String((s==null?void 0:s.message)??"").toLowerCase().includes("too much load")&&(ql=Date.now()+og,(n=be)==null||n("Rate-limited \u2014 backing off 2 min."))}finally{Kl(!1),_o=!1}}}function Kl(e){var t;(t=y("btn-network-refresh"))==null||t.classList.toggle("spinning",e)}async function wg(){var n,s,a;let e=await Ne({command:"server_info"});if(qe=((n=e==null?void 0:e.result)==null?void 0:n.info)??null,!qe)return;Ge("converge",Number(((s=qe.last_close)==null?void 0:s.converge_time_s)??0)),Ge("proposers",Number(((a=qe.last_close)==null?void 0:a.proposers)??0)),Ge("peerCounts",Number(qe.peers??0));let t=Number(qe.peer_disconnects_resources??0);ha!==null&&t>ha&&Ge("peerDiscon",t-ha),ha=t}async function xg(){var t;let e=await Ne({command:"fee"});kn=(e==null?void 0:e.result)??null,((t=kn==null?void 0:kn.drops)==null?void 0:t.open_ledger_fee)!=null&&Ge("fees",Number(kn.drops.open_ledger_fee))}async function kg(){try{let e=await Ne({command:"validators"});Ls=(e==null?void 0:e.result)??null}catch{Ls=null}}async function $g(){var e;try{let t=await Ne({command:"peers"});At=Array.isArray((e=t==null?void 0:t.result)==null?void 0:e.peers)?t.result.peers:null}catch{At=null}}async function Sg(){var e;try{let t=await Ne({command:"feature"});(e=t==null?void 0:t.result)!=null&&e.features&&(Ng(t.result.features),pc(t.result.features))}catch{}}function Tg(){var M,N,_,X,I,R;let e=qe,t=Ls,n=(t==null?void 0:t.trusted_validator_keys)??[],s=oc(),a=gg(),o=n.length?n:s,i=a,r=Number((t==null?void 0:t.validation_quorum)??(e==null?void 0:e.validation_quorum)??0),l=o.length,c=l-r,d=l>0?r/l*100:0,u=o.filter(F=>$e.has(F)).length,p=l>0?Math.round(u/l*100):0,m=Number(((M=e==null?void 0:e.last_close)==null?void 0:M.converge_time_s)??0),f=Number(((N=e==null?void 0:e.last_close)==null?void 0:N.proposers)??0),v=r>0?Math.round(f/r*100):0,h=Array.isArray(e==null?void 0:e.negative_unl)?e.negative_unl:[],w=!!Ls;c>=0&&c<=3&&(Fe.quorumTight=!0),h.length>0&&(Fe.nUnlActive=!0),m>6&&(Fe.slowConverge=!0),f>0&&r>0&&f<r&&(Fe.lowProposers=!0),G("m1-active",w?l:"\u2014"),G("m1-quorum",r>0?r:"\u2014"),G("m1-margin",w?c>=0?c:`\u2212${Math.abs(c)}`:"\u2014"),G("m1-overlap",w?`${p}%`:"\u2014"),G("m1-known",w?`${u} / ${l} identified`:"\u2014 (validators cmd unavailable)"),G("m1-proposers",((_=e==null?void 0:e.last_close)==null?void 0:_.proposers)!=null?f:"\u2014"),G("m1-particip",r>0&&((X=e==null?void 0:e.last_close)==null?void 0:X.proposers)!=null?`${v}%`:"\u2014"),G("m1-converge",((I=e==null?void 0:e.last_close)==null?void 0:I.converge_time_s)!=null?`${m.toFixed(2)}s`:"\u2014"),G("m1-converge-avg",Ms("converge")>0?`avg ${Ms("converge").toFixed(2)}s`:"\u2014"),dt("m1-qbar",d,d>90?"bar-danger":d>80?"bar-warn":"bar-ok"),dt("m1-obar",p,p<40?"bar-danger":p<70?"bar-warn":"bar-ok"),dt("m1-pbar",v,v<80?"bar-danger":v<95?"bar-warn":"bar-ok"),dt("m1-cvgbar",Math.min(100,m/10*100),m>6?"bar-danger":m>4?"bar-warn":"bar-ok"),Mg({active:l,quorum:r,margin:c,nUnl:h,valsAvail:w});let k=(R=t==null?void 0:t.publisher_lists)==null?void 0:R[0],b=(sn==null?void 0:sn.ripple)??(sn==null?void 0:sn.xrplf)??null,x=(k==null?void 0:k.uri)??(b==null?void 0:b.uri)??"\u2014",S=(k==null?void 0:k.seq)??(b==null?void 0:b.seq)??"\u2014";if(G("m1-vl-uri",x),G("m1-vl-seq",S),k!=null&&k.expiration||b!=null&&b.expiration){let F=y("m1-vl-expiry");if(F){let W=(k==null?void 0:k.expiration)??(b==null?void 0:b.expiration),E=Math.floor((new Date(W)-Date.now())/864e5);F.textContent=E>0?`Expires ${E}d`:"\u26A0 EXPIRED",F.className=`expiry-pill ${E>30?"pill-ok":E>7?"pill-warn":"pill-bad"}`,F.style.display=""}}let T=y("m1-nunl-list");if(G("m1-nunl-count",h.length||"0"),T)if(!h.length)T.innerHTML='<div class="nunl-empty">\u2713 No validators on Negative UNL</div>';else{let F={};T.innerHTML=h.map(E=>{let z=Ke(E);return z.provider&&(F[z.provider]=(F[z.provider]||0)+1),`<div class="nunl-entry">
          <span class="nunl-dot"></span>
          <div class="nunl-info">
            <span class="nunl-label">${g(z.label)}</span>
            ${z.domain?`<span class="nunl-prov">${g(z.domain)}</span>`:""}
          </div>
          <span class="nunl-key" onclick="navigator.clipboard?.writeText('${g(E)}')">${E.slice(0,8)}...</span>
        </div>`}).join("");let W=Object.entries(F).sort((E,z)=>z[1]-E[1])[0];(W==null?void 0:W[1])>1&&(T.innerHTML+=`<div class="nunl-alert">\u26A0 ${W[1]} offline validators share <b>${g(W[0])}</b> \u2014 likely provider outage</div>`)}dc(o,i,r,h,w);let $=Number((qe==null?void 0:qe.peers)??0);G("wm-stat-val",w?`${l} validators`:`${$e.size} in registry`),G("wm-stat-nunl",`${h.length} on nUNL`),G("wm-stat-peers",`${At?At.length:$} peers`);let P=[...$e.keys()];Rg(o,i,h,At,!w)}function dc(e,t,n,s,a){let o=y("m1-val-grid");if(!o)return;let i=new Set(e),r=new Set(t),l=new Set(s),c=oc(),d=bg(),u=vg(),p=e.length?e:c,m=[...$e.keys()],f=m.filter(I=>{var R;return(((R=$e.get(I))==null?void 0:R.chain)??"main")==="main"}),v=d,h=u,w=p.filter(I=>!!Ke(I).domain),k=p.filter(I=>!Ke(I).domain),b=h.filter(I=>!!Ke(I).domain),x=h.filter(I=>!Ke(I).domain),S=m.filter(I=>!!on(Ke(I))),T=[{id:"unl",label:"UNL",count:p.length,dot:"unl"},{id:"others",label:"Others",count:h.length,dot:"other"},{id:"all",label:"All",count:f.length,dot:null},{id:"test",label:"Testnet",count:v.length,dot:null}],$={unl:"#00fff0",dunl:"#bd93f9",both:"#50fa7b",nunl:"#ff5555",other:"#ffb86c"},P='<div class="vg-tabs" role="tablist">'+T.map(I=>`<button class="vg-tab ${ks===I.id?"vg-tab--active":""}" data-vgtab="${I.id}">
        ${I.dot?`<span class="vg-tab-dot" style="background:${$[I.dot]}"></span>`:""}
        ${g(I.label)}
        <span class="vg-tab-count">${I.count}</span>
      </button>`).join("")+"</div>",M=[],N="";if(ks==="unl"){let I=p.filter(E=>l.has(E)),R=w.filter(E=>!l.has(E)),F=k.filter(E=>!l.has(E));I.length&&M.push({title:`\u26A0 Negative UNL (${I.length})`,keys:I,cls:"vgs-warn"}),M.push({title:`Named UNL validators \xB7 ${R.length}`,keys:R}),F.length&&M.push({title:`Key-only UNL validators \xB7 ${F.length}`,keys:F,collapsed:!0}),p.length||M.push({title:"No UNL data",keys:[],notice:"Registry not loaded yet"});let W=a?"live rippled":`registry (${an})`;N=`${p.length} trusted \xB7 quorum ${n} \xB7 ${s.length} on nUNL \xB7 source: ${W}`}else if(ks==="others")M.push({title:`Named mainnet (non-UNL) \xB7 ${b.length}`,keys:b}),x.length&&M.push({title:`Key-only mainnet \xB7 ${x.length}`,keys:x,collapsed:!0}),N=`${h.length} mainnet validators not on UNL \xB7 source: ${an}`;else if(ks==="test"){let I=v.filter(F=>!!Ke(F).domain),R=v.filter(F=>!Ke(F).domain);I.length&&M.push({title:`Named testnet \xB7 ${I.length}`,keys:I}),R.length&&M.push({title:`Key-only testnet \xB7 ${R.length}`,keys:R,collapsed:!0}),N=`${v.length} testnet validators`}else M.push({title:`\u2B50 UNL \xB7 ${p.length}`,keys:p}),M.push({title:`Other mainnet \xB7 ${h.length}`,keys:h,collapsed:!0}),v.length&&M.push({title:`Testnet \xB7 ${v.length}`,keys:v,collapsed:!0}),N=`${f.length} mainnet \xB7 ${v.length} testnet \xB7 ${S.length} geo-located \xB7 source: ${an}`;function _(I,R){var Se;let F=Ke(I),W=l.has(I),E=i.has(I),z=r.has(I),Q=F.chain==="test",ie,ce,de;W?(ie="vp-nunl",ce="nUNL",de=$.nunl):E&&z?(ie="vp-both",ce="UNL+dUNL",de=$.both):E?(ie="vp-unl",ce="UNL",de=$.unl):z?(ie="vp-dunl",ce="dUNL",de=$.dunl):(ie="vp-other",ce="Other",de=$.other);let se=on(F),fe=!!se,K=se?`\u{1F4CD} ${se.city??""}`:"",xe=F.domain?F.domain.replace(/^www\./,"").replace(/^validator\./,"").replace(/^xrp\./,""):null,B=`${I.slice(0,8)}\u2026${I.slice(-6)}`,J=E&&R!=null?`<span class="vg-num">${R+1}</span>`:"",re=(Se=F.agreement)==null?void 0:Se["24h"],pe=re!=null&&re.score?`<span class="vg-agr" style="color:${parseFloat(re.score)>=99?"#50fa7b":parseFloat(re.score)>=95?"#ffb86c":"#ff5555"}" title="24h agreement">${re.score}</span>`:"";return`<div class="vpill ${ie} ${fe?"vp-locatable":""}"
                 title="${g([F.label,F.domain,se==null?void 0:se.city,I].filter(Boolean).join(" \xB7 "))}"
                 onclick="window.focusValidator('${g(I)}')"
                 data-key="${g(I)}">
      ${J}
      <span class="vpdot" style="background:${de};box-shadow:0 0 5px ${de}55"></span>
      <div class="vptext">
        <span class="vplabel">${g(xe??F.label??B)}</span>
        ${K?`<span class="vpprov vp-geo">${g(K)}</span>`:""}
      </div>
      <div class="vpactions">
        ${pe}
        <span class="vntag vntag-cat" style="border-color:${de}44;color:${de}">${ce}</span>
        ${Q?'<span class="vntag" style="opacity:.5">test</span>':""}
      </div>
    </div>`}let X="";M.forEach(I=>{if(!I.keys.length)return;let R=I.keys.some(z=>i.has(z)),F=I.keys.map((z,Q)=>_(z,R?Q:null)).join(""),W=`vgs-${Math.random().toString(36).slice(2,8)}`,E=!I.collapsed;X+=`
      <div class="vg-section ${I.cls??""}">
        <button class="vg-section-hdr" onclick="
          const c=document.getElementById('${W}');
          const open=c.style.display!=='none';
          c.style.display=open?'none':'';
          this.querySelector('.vg-chevron').textContent=open?'\u25B6':'\u25BC';
        ">
          <span class="vg-chevron">${E?"\u25BC":"\u25B6"}</span>
          <span class="vg-sec-title">${g(I.title)}</span>
        </button>
        <div id="${W}" class="vg-section-body" style="display:${E?"":"none"}">
          ${F}
        </div>
      </div>`}),X||(X='<div class="nunl-empty">No validators in this view.</div>'),o.innerHTML=P+X,G("m1-val-summary",N),o.querySelectorAll(".vg-tab").forEach(I=>{I.addEventListener("click",R=>{R.stopPropagation();let F=I.getAttribute("data-vgtab");F&&(ks=F,dc(e,t,n,s,a))})})}async function Cg(e){let t=Ro.get(e);if(t&&Date.now()-t.cachedAt<ec)return t.data;try{let n=new AbortController,s=setTimeout(()=>n.abort(),tc),a=await fetch(`${Zl}/${encodeURIComponent(e)}`,{signal:n.signal});if(clearTimeout(s),!a.ok)throw new Error(`HTTP ${a.status}`);let o=await a.json();return Ro.set(e,{data:o,cachedAt:Date.now()}),o}catch{return null}}async function Lg(e){let t=Do.get(e);if(t&&Date.now()-t.cachedAt<ec)return t.data;try{let n=new AbortController,s=setTimeout(()=>n.abort(),tc),a=await fetch(`${Zl}/${encodeURIComponent(e)}/reports`,{signal:n.signal});if(clearTimeout(s),!a.ok)throw new Error(`HTTP ${a.status}`);let o=await a.json(),i=o.reports??o??[];return Do.set(e,{data:i,cachedAt:Date.now()}),i}catch{return[]}}window.focusValidator=async function(e){let t=Ke(e),n=on(t);document.querySelectorAll(".vpill").forEach(o=>o.classList.remove("vp-active"));let s=document.querySelector(`.vpill[data-key="${CSS.escape(e)}"]`);if(s&&(s.classList.add("vp-active"),s.scrollIntoView({behavior:"smooth",block:"nearest"})),Xo(e,t,null),Cg(e).then(o=>{o&&Xo(e,t,o)}),!n){let o=y("world-map-container");if(o){let i=o.querySelector(".wm-no-geo");i&&i.remove();let r=document.createElement("div");r.className="wm-no-geo",r.textContent=`\u{1F4CD} ${t.label} \u2014 geographic location unknown`,o.appendChild(r),setTimeout(()=>r.remove(),3500)}return}let a=y("world-map-container");a&&a.scrollIntoView({behavior:"smooth",block:"nearest"}),je&&(je.flyTo([n.lat,n.lng],6,{duration:1.2}),setTimeout(()=>{let o=Oo[e];o&&o.openPopup()},1300))};function Xo(e,t,n){var M,N,_,X,I;let s=y("amend-modal-overlay"),a=y("amend-modal-body");if(!s||!a)return;let o=n??{},i=t.label??o.label??o.account_name??e.slice(0,16)+"\u2026",r=t.domain??o.domain??null,l=t.chain??o.chain??"main",c=t.category??"other",d=_e[c]??_e.other,u=on(t),p=t.unl||c==="unl"||c==="both",m=t.dunl||c==="dunl"||c==="both",f=t.domainVerified||o.domain_verified?"\u2713 Verified":r?"Unverified":"\u2014",v=t.agreement??o.agreement??{},h=!n&&!((M=t.agreement)!=null&&M["24h"]);function w(R,F){if(!F||!F.total)return`<div class="adm-mi"><span class="adm-mk">${R}</span><span class="adm-mv" style="opacity:.5">\u2014</span></div>`;let W=parseFloat(F.score)||0,E=W>=99?"color:#50fa7b":W>=95?"color:#ffb86c":"color:#ff5555";return`<div class="adm-mi">
      <span class="adm-mk">${R}</span>
      <span class="adm-mv mono" style="${E}">${F.score??"\u2014"}
        <span style="opacity:.55;font-size:10px;font-weight:400"> \xB7 ${F.missed??0} missed / ${F.total??0}</span>
      </span>
    </div>`}function k(R,F,W=!1){return!F&&F!==0?"":`<div class="adm-mi"><span class="adm-mk">${R}</span><span class="adm-mv ${W?"mono":""}">${g(String(F))}</span></div>`}let b=Do.get(e),x=((N=b==null?void 0:b.data)==null?void 0:N.slice(-14))??[],S=x.length?`<div class="adm-section">
        <div class="adm-slbl">Ledger agreement \u2014 last ${x.length} days</div>
        <div style="display:flex;gap:2px;align-items:flex-end;height:32px;margin-top:6px;">
          ${x.map(R=>{let F=Number(R.missed??R.miss??0),W=Number(R.total??R.ledgers??1),E=W>0?(W-F)/W*100:100,z=Math.round(4+E/100*28),Q=E>=99?"#50fa7b":E>=95?"#ffb86c":"#ff5555";return`<div title="${R.date??""} \xB7 ${E.toFixed(1)}% (${F} missed)" style="flex:1;height:${z}px;background:${Q};border-radius:2px 2px 0 0;opacity:.85;transition:opacity .15s" onmouseover="this.style.opacity=1" onmouseout="this.style.opacity=.85"></div>`}).join("")}
        </div>
      </div>`:"",T=c==="unl"?"\u2B50 UNL":c==="both"?"\u2B50 UNL + dUNL":c==="nunl"?"\u26A0 Neg-UNL":c==="dunl"?"dUNL":"Non-UNL",$=c==="unl"||c==="both"?"background:rgba(0,255,240,.15);color:#00fff0;border-color:#00fff044":c==="nunl"?"background:rgba(255,85,85,.15);color:#ff5555;border-color:#ff555544":"background:rgba(255,184,108,.1);color:#ffb86c;border-color:#ffb86c44",P=r?`https://xrpscan.com/validator/${encodeURIComponent(r)}`:`https://xrpscan.com/validator/${encodeURIComponent(e)}`;a.innerHTML=`
    <div class="adm-header" style="border-bottom:1px solid rgba(255,255,255,.08);padding-bottom:12px;margin-bottom:12px;">
      <div class="adm-title-row" style="display:flex;align-items:flex-start;gap:10px;margin-bottom:6px;">
        <div style="flex:1">
          <h2 class="adm-title" style="color:${d.hex};margin:0;font-size:17px;font-weight:700">${g(i)}</h2>
          ${r?`<div style="font-size:12px;opacity:.65;margin-top:2px">${g(r)} <span style="opacity:.6">${g(f)}</span></div>`:""}
        </div>
        <span style="font-size:11px;padding:3px 8px;border-radius:10px;border:1px solid;flex-shrink:0;font-weight:600;${$}">${T}</span>
      </div>
      <div style="font-family:monospace;font-size:10px;opacity:.45;word-break:break-all;cursor:pointer" title="Click to copy" onclick="navigator.clipboard?.writeText('${g(e)}');this.style.opacity=.8;setTimeout(()=>this.style.opacity=.45,800)">${g(e)}</div>
    </div>

    <div class="adm-section">
      <div class="adm-slbl">Identity &amp; Status</div>
      ${k("Chain",l==="main"?"\u{1F310} Mainnet":"\u{1F9EA} Testnet")}
      ${k("UNL",p?"\u2B50 Yes \u2014 Ripple UNL":"No")}
      ${k("dUNL",m?"\u2713 Yes \u2014 XRPL Foundation UNL":"No")}
      ${u?k("Location",[u.city,u.country].filter(Boolean).join(", ")||"\u2014"):""}
      ${u!=null&&u.org?k("Provider",u.org):""}
      ${k("Version",t.version??o.version??o.build_version??null)}
      ${k("Base fee",t.baseFee??o.base_fee_xrp??o.baseFee??null)}
      ${k("Ledger",o.currentIndex?Number(o.currentIndex).toLocaleString():null,!0)}
    </div>

    <div class="adm-section">
      <div class="adm-slbl">Ledger Agreement ${h?'<span style="opacity:.4;font-size:10px;margin-left:6px">loading\u2026</span>':""}</div>
      ${w("1-hour",v["1h"]??((_=o.agreement)==null?void 0:_["1h"]))}
      ${w("24-hour",v["24h"]??((X=o.agreement)==null?void 0:X["24h"]))}
      ${w("30-day",v["30d"]??((I=o.agreement)==null?void 0:I["30d"]))}
    </div>

    ${S}

    <div class="adm-footer" style="display:flex;gap:10px;margin-top:12px;padding-top:10px;border-top:1px solid rgba(255,255,255,.07)">
      <a class="adm-link" href="${P}" target="_blank" rel="noopener noreferrer">\u2197 XRPScan</a>
      <button class="adm-link" style="background:none;border:none;cursor:pointer;color:inherit;padding:0" onclick="window._loadValidatorReports('${g(e)}')">\u{1F4CA} Load reports</button>
      ${(u==null?void 0:u.lat)!=null?`<button class="adm-link" style="background:none;border:none;cursor:pointer;color:inherit;padding:0" onclick="window.closeAmendModal();setTimeout(()=>window.focusValidator('${g(e)}'),200)">\u{1F4CD} Show on map</button>`:""}
    </div>`,s.style.display="flex",s.addEventListener("click",R=>{R.target===s&&window.closeAmendModal()},{once:!0})}window._loadValidatorReports=async function(e){var n;let t=Ke(e);await Lg(e),Xo(e,t,((n=Ro.get(e))==null?void 0:n.data)??null)};function Mg({active:e,quorum:t,margin:n,nUnl:s,valsAvail:a}){let o=y("m1-quorum-ring");if(!o)return;if(!a||!t||!e){o.innerHTML='<div style="opacity:.4;font-size:12px;text-align:center;padding:16px">Connect to view quorum</div>';return}let i=44,r=2*Math.PI*i,l=new Set(s),c=e-s.length,d=s.length,u=Math.max(0,e-t),p=t,m=n<=0?"#ff5555":n<=3?"#ffb86c":"#50fa7b",f=e>0?c/e:0,v=e>0?d/e:0,h=e>0?t/e:0,w=e>0?Math.max(0,n)/e:0,k=e>0?d/e:0;function b(x,S,T,$=8){if(S<=0)return"";let P=x*r,M=S*r;return`<circle r="${i}" cx="50" cy="50" fill="none"
      stroke="${T}" stroke-width="${$}" opacity=".85"
      stroke-dasharray="${M} ${r-M}"
      stroke-dashoffset="${r-P}"
      stroke-linecap="round"
      style="transform-origin:50px 50px;transform:rotate(-90deg)"/>`}o.innerHTML=`
    <div class="qr-wrap">
      <svg viewBox="0 0 100 100" width="100" height="100" style="overflow:visible">
        <!-- Background ring -->
        <circle r="${i}" cx="50" cy="50" fill="none" stroke="rgba(255,255,255,.06)" stroke-width="9"/>
        <!-- Quorum zone (required validators) -->
        ${b(0,h,"rgba(0,255,240,.25)",9)}
        <!-- Margin zone (extra validators) -->
        ${b(h,w,"#50fa7b",9)}
        <!-- Negative UNL (offline) -->
        ${k>0?b(h+w,k,"#ff5555",9):""}
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
    </div>`}function Pg(){var F,W,E;let e=qe,t=(e==null?void 0:e.server_state)??"unknown",n=(e==null?void 0:e.build_version)??"\u2014",s=Number((e==null?void 0:e.uptime)??0),a=e==null?void 0:e.network_id,o=Number((e==null?void 0:e.io_latency_ms)??0),i=String((e==null?void 0:e.jq_trans_overflow)??"0"),r=Number((e==null?void 0:e.peer_disconnects_resources)??0),l=Number((e==null?void 0:e.load_factor)??1),c=Number((e==null?void 0:e.load_factor_net)??1),d=Number((e==null?void 0:e.load_factor_server)??(e==null?void 0:e.load_factor_local)??1),u=Number(((F=e==null?void 0:e.validated_ledger)==null?void 0:F.age)??0),p=(W=e==null?void 0:e.validated_ledger)==null?void 0:W.seq,m=(e==null?void 0:e.complete_ledgers)??"",f=(e==null?void 0:e.state_accounting)??null;u>10&&(Fe.staleLedger=!0),o>5&&(Fe.ioStressed=!0),Ms("peerDiscon")>5&&(Fe.peerChurn=!0);let v=y("m2-state");if(v){v.textContent=t;let z=["full","proposing","validating"].includes(t),Q=["syncing","tracking","connected"].includes(t);v.className=`state-pill state-${z?"ok":Q?"warn":"bad"}`}G("m2-version",n),G("m2-uptime",Gg(s)),G("m2-netid",a===0?"0 (Mainnet)":a===1?"1 (Testnet)":a??"\u2014"),G("m2-ledger-seq",p!=null?Number(p).toLocaleString():"\u2014"),G("m2-ledger-age",u>0?`${u}s`:"< 1s"),G("m2-io-ms",o>0?`${o}ms`:"< 1ms"),G("m2-jq",i==="0"?"0 (clean)":`\u26A0 ${i}`),G("m2-discon",r.toLocaleString());let h=y("m2-ledger-age");h&&(h.className=`kv-v ${u>10?"text-danger":u>5?"text-warn":""}`);let w=Math.min(100,(l-1)/49*100);dt("m2-load-bar",w,l>5?"bar-danger":l>2?"bar-warn":"bar-ok"),G("m2-load-total",`${l.toFixed(2)}\xD7`),G("m2-load-net",`${c.toFixed(2)}\xD7`),G("m2-load-local",`${d.toFixed(2)}\xD7`);let k=d>c*1.5?"Local node stressed":c>d*1.5?"Network-wide stress":l>1.2?"Distributed":"Normal";G("m2-load-src",k);let b=O.tpsHistory.length?O.tpsHistory[O.tpsHistory.length-1]:null;G("m2-tps",b!=null?b.toFixed(1):"\u2014"),G("m2-txcount",((E=O.ledgerLog[0])==null?void 0:E.txCount)??"\u2014");let x=m==="entire ledger"||m.startsWith("32570"),S=x?100:Vg(m);if(G("m2-ledger-range",m||"\u2014"),G("m2-hist-type",x?"Full History Node":"Pruned / Partial"),G("m2-hist-score",`${S}%`),dt("m2-hist-bar",S,S<30?"bar-danger":S<70?"bar-warn":"bar-ok"),f){let z=y("m2-state-acct");if(z){let Q=["full","syncing","tracking","connected","disconnected"],ie=0,ce={};Q.forEach(de=>{var se;ce[de]=Number(((se=f[de])==null?void 0:se.duration_us)??0),ie+=ce[de]}),z.innerHTML=ie>0?Q.map(de=>{let se=Math.round(ce[de]/ie*100);return se?`<div class="sa-row"><span class="sa-lbl">${de}</span>
          <div class="bar-track sa-bar"><div class="bar-fill ${de==="full"?"bar-ok":de==="syncing"?"bar-warn":"bar-danger"}" style="width:${se}%"></div></div>
          <span class="sa-pct">${se}%</span></div>`:""}).join(""):'<span class="dim">No data</span>'}}let T=(e==null?void 0:e.peers)!=null?Number(e.peers):null,$=T!=null,P=0,M=0,N=!1;At&&(At.forEach(z=>{z.inbound===!0?P++:M++}),N=!0);let _=N&&P+M>0?Math.round(P/(P+M)*100):0,X=N?At.length:T??0,I=X<6?"HIGH":X<15?"MEDIUM":"LOW";X<6&&(Fe.eclipseRisk=!0),_>80&&(Fe.peerSaturate=!0),G("m2-peers",$?X:"\u2014"),G("m2-inbound",N?P:$?"\u2014 (cmd restricted)":"\u2014"),G("m2-outbound",N?M:$?"\u2014 (cmd restricted)":"\u2014"),G("m2-ib-pct",N?`${_}%`:"\u2014"),dt("m2-peer-bar",Math.min(100,X/21*100),X>18?"bar-danger":X>15?"bar-warn":"bar-ok"),dt("m2-ib-bar",_,_>80?"bar-danger":_>60?"bar-warn":"bar-ok");let R=y("m2-eclipse");R&&(R.textContent=I,R.className=`risk-badge risk-${I.toLowerCase()}`)}function Ag(){var M,N,_,X;let e=kn,t=Number(((M=e==null?void 0:e.drops)==null?void 0:M.minimum_fee)??10),n=Number(((N=e==null?void 0:e.drops)==null?void 0:N.open_ledger_fee)??10),s=Number(((_=e==null?void 0:e.drops)==null?void 0:_.median_fee)??10),a=Number(((X=e==null?void 0:e.drops)==null?void 0:X.base_fee)??10),o=Number((e==null?void 0:e.current_ledger_size)??0),i=Number((e==null?void 0:e.expected_ledger_size)??1),r=Number((e==null?void 0:e.current_queue_size)??0),l=Number((e==null?void 0:e.max_queue_size)??1),c=l>0?Math.round(r/l*100):0,d=i>0?o/i:1,u=Ms("fees"),p=u>0?Math.round((n-u)/u*100):0,m=Math.min(100,Math.round(Math.log2(Math.max(1,n/10))*14));n>t*10&&(Fe.feeSpike=!0),c>80&&(Fe.queuePressure=!0),d>2&&(Fe.spamLedger=!0);let f=tt.burnDrops.slice(-10),v=f.length?f.reduce((I,R)=>I+R,0)/f.length:0,h=Wg(tt.burnDrops),w=Ms("burnDrops"),k=h>0&&tt.burnDrops.length>5?((v-w)/h).toFixed(2):"0.00",b=Math.min(100,Math.abs(Number(k))*20);Math.abs(Number(k))>3&&(Fe.burnAnomaly=!0);let x=n>5e3?"Severe":n>500?"High":n>100?"Elevated":n>20?"Normal":"Minimal",T={Severe:"#ff5555",High:"#ff9955",Elevated:"#ffb86c",Normal:"#50fa7b",Minimal:"#6272a4"}[x]??"#50fa7b",$=y("m3-pressure");$&&($.textContent=x,$.className=`pressure-badge p-${x.toLowerCase()}`),G("m3-open",`${n} drops`),G("m3-med",`${s} drops`),G("m3-base",`${a} drops`),G("m3-devpct",`${p>0?"+":""}${p}% vs baseline`),G("m3-spam",`${m} / 100`),G("m3-qsize",`${r} / ${l}`),G("m3-qpct",`${c}%`),G("m3-szratio",`${d.toFixed(2)}\xD7`),G("m3-curledger",`${o} txs`),G("m3-expledger",`${i} expected`),G("m3-burn",v>0?`${(v/1e6).toFixed(4)} XRP / ledger`:"\u2014"),G("m3-burnz",`z = ${k}`),dt("m3-spam-bar",m,m>70?"bar-danger":m>40?"bar-warn":"bar-ok"),dt("m3-q-bar",c,c>80?"bar-danger":c>50?"bar-warn":"bar-ok"),dt("m3-sz-bar",Math.min(100,d*50),d>2?"bar-danger":d>1.5?"bar-warn":"bar-ok"),dt("m3-burn-bar",b,b>60?"bar-danger":b>30?"bar-warn":"bar-ok");let P=y("m3-congestion-summary");if(P){let I=[];d>2&&I.push({icon:"\u{1F6A8}",txt:`Ledger ${d.toFixed(1)}\xD7 normal size \u2014 possible spam burst`,col:"#ff5555"}),c>80&&I.push({icon:"\u26A0",txt:`TX queue ${c}% full \u2014 fee surge imminent`,col:"#ffb86c"}),m>70&&I.push({icon:"\u26A0",txt:`Spam index ${m}/100 \u2014 elevated DDoS risk`,col:"#ffb86c"}),Math.abs(Number(k))>3&&I.push({icon:"\u{1F4C9}",txt:`Burn rate z=${k} \u2014 resource exhaustion pattern`,col:"#ff9955"}),p>200&&I.push({icon:"\u{1F4B8}",txt:`Open fee ${p}% above baseline \u2014 network stress`,col:"#ffb86c"}),P.innerHTML=I.length?I.map(R=>`<div class="cong-line"><span>${R.icon}</span><span style="color:${R.col}">${g(R.txt)}</span></div>`).join(""):'<div class="cong-clear"><span style="color:#50fa7b">\u2713</span> No congestion signals \u2014 network traffic is normal</div>'}}function Eg(){var u,p;let e={},t=0;for(let m of $e.values()){if(m.chain==="test")continue;let f=m.version??"unknown";e[f]=(e[f]??0)+1,t++}let n={},s=0;if(Array.isArray(At))for(let m of At){let f=(m.version??"unknown").replace(/rippled-/i,"").split(" ")[0];n[f]=(n[f]??0)+1,s++}let a=y("m4-version-dist");if(a&&t>0){let m=Object.entries(e).sort((w,k)=>k[1]-w[1]),f=((u=m[0])==null?void 0:u[0])??"?",v=t>0?Math.round((((p=m[0])==null?void 0:p[1])??0)/t*100):0,h=["#00fff0","#50fa7b","#ffb86c","#bd93f9","#ff5555","#8be9fd"];a.innerHTML=m.slice(0,6).map(([w,k],b)=>{let x=Math.round(k/t*100),S=h[b%h.length],T=w.includes("beta")||w.includes("rc")||w.includes("RC");return`<div class="vd-row">
        <div class="vd-ver-label">
          <span style="color:${S};font-weight:600">${g(w)}</span>
          ${T?'<span class="vd-beta-tag">beta</span>':""}
        </div>
        <div class="vd-bar-wrap">
          <div class="vd-bar-fill" style="width:${x}%;background:${S};opacity:.75"></div>
        </div>
        <span class="vd-count">${k} <span style="opacity:.5">(${x}%)</span></span>
      </div>`}).join("")+`<div class="vd-summary">${t} validators \xB7 ${m.length} versions \xB7 ${v}% on latest (${g(f)})</div>`}let o={"North America":0,Europe:0,"Asia Pacific":0,"Middle East":0,"South America":0,Other:0};function i(m,f){return m>15&&f<-30?"North America":m>-60&&f<-30?"South America":m>35&&f>-30&&f<60?"Europe":m>10&&f>=60&&f<150||m>=-40&&f>=110?"Asia Pacific":m>10&&m<40&&f>=30&&f<70?"Middle East":"Other"}let r=0;for(let m of $e.values()){if(m.chain==="test")continue;let f=on(m);if(!(f!=null&&f.lat))continue;let v=i(f.lat,f.lng);o[v]=(o[v]??0)+1,r++}let l=y("m4-geo-dist");if(l&&r>0){let m={"North America":"#00fff0",Europe:"#50fa7b","Asia Pacific":"#bd93f9","Middle East":"#ffb86c","South America":"#8be9fd",Other:"#6272a4"},f=Object.entries(o).filter(([,k])=>k>0).sort((k,b)=>b[1]-k[1]),v=f.reduce((k,[,b])=>k+(b/r)**2,0),h=v>.4?"Concentrated":v>.25?"Moderate":"Distributed",w=v>.4?"#ff5555":v>.25?"#ffb86c":"#50fa7b";l.innerHTML=f.map(([k,b])=>{let x=Math.round(b/r*100),S=m[k]??"#6272a4";return`<div class="vd-row">
        <span class="vd-ver-label" style="color:${S};font-weight:600">${g(k)}</span>
        <div class="vd-bar-wrap">
          <div class="vd-bar-fill" style="width:${x}%;background:${S};opacity:.65"></div>
        </div>
        <span class="vd-count">${b} <span style="opacity:.5">(${x}%)</span></span>
      </div>`}).join("")+`<div class="vd-summary">${r} geo-located \xB7 <span style="color:${w}">${h}</span> (HHI ${v.toFixed(2)})</div>`}let c={};for(let m of $e.values()){if(m.chain==="test")continue;let f=on(m),v=m.provider??(f==null?void 0:f.org)??"Unknown",h=v.match(/AWS|Amazon/i)?"AWS":v.match(/Azure|Microsoft/i)?"Azure":v.match(/GCP|Google/i)?"GCP":v.match(/Hetzner/i)?"Hetzner":v.match(/OVH/i)?"OVH":v.match(/Cloudflare/i)?"Cloudflare":v.match(/Equinix/i)?"Equinix":v.match(/NTT/i)?"NTT":v.match(/Ripple/i)?"Ripple":"Other";c[h]=(c[h]??0)+1}let d=y("m4-provider-dist");if(d){let m=Object.values(c).reduce((f,v)=>f+v,0);if(m>0){let f=Object.entries(c).sort((h,w)=>w[1]-h[1]),v=["#ff5555","#ffb86c","#50fa7b","#00fff0","#bd93f9","#8be9fd","#6272a4"];d.innerHTML=f.slice(0,7).map(([h,w],k)=>{let b=Math.round(w/m*100),x=v[k%v.length],S=b>33?"\u26A0 ":"";return`<div class="vd-row">
          <span class="vd-ver-label" style="color:${x};font-weight:600">${S}${g(h)}</span>
          <div class="vd-bar-wrap">
            <div class="vd-bar-fill" style="width:${b}%;background:${x};opacity:.7;${b>33?"box-shadow:0 0 6px "+x+"88":""}"></div>
          </div>
          <span class="vd-count">${w} <span style="opacity:.5">(${b}%)</span></span>
        </div>`}).join("")}}}var Qn="pending";function pc(e){let t=y("amendment-list");if(!t)return;let n=y("amend-pipeline-header"),s=Object.entries(e).map(([d,u])=>({hash:d,...u})),a=s.filter(d=>d.enabled),o=s.filter(d=>!d.enabled&&!d.vetoed).sort((d,u)=>(u.count??0)-(d.count??0)),i=s.filter(d=>d.vetoed),r=o.filter(d=>d.majority),l=o.filter(d=>!d.majority&&(d.count??0)>=(d.threshold??28)*.8);if(o.some(d=>(d.count??0)<(d.threshold??28)*.5)&&(Fe.amendVeto=!0),n){let d=[{id:"pending",label:"Voting",count:o.length,color:"#8be9fd"},{id:"active",label:"Active",count:a.length,color:"#50fa7b"},{id:"vetoed",label:"Vetoed",count:i.length,color:"#ff5555"},{id:"all",label:"All",count:s.length,color:null}];n.innerHTML=`
      <div class="ap-tabs">
        ${d.map(u=>`
          <button class="ap-tab ${Qn===u.id?"ap-tab--active":""}" data-aptab="${u.id}">
            ${u.color?`<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:${u.color};margin-right:5px;vertical-align:middle"></span>`:""}
            ${u.label}
            <span class="ap-tab-count">${u.count}</span>
          </button>`).join("")}
      </div>
      ${r.length?`<div class="ap-alert-bar">\u23F3 ${r.length} amendment${r.length>1?"s":""} reached validator majority \u2014 activates in ~14 days if maintained</div>`:""}
      ${l.length?`<div class="ap-near-bar">\u{1F4C8} ${l.length} amendment${l.length>1?"s":""} approaching 80% threshold</div>`:""}`,n.querySelectorAll(".ap-tab").forEach(u=>{u.onclick=()=>{Qn=u.dataset.aptab,pc(e)}})}let c=Qn==="active"?a:Qn==="vetoed"?i:Qn==="all"?s.sort((d,u)=>d.enabled!==u.enabled?d.enabled?1:-1:d.vetoed!==u.vetoed?d.vetoed?1:-1:(u.count??0)-(d.count??0)):o;if(!c.length){t.innerHTML=`<div class="amend-empty">${Qn==="vetoed"?"No vetoed amendments":"No data"}</div>`;return}t.innerHTML=c.map(d=>{var $;let u=d.count??0,p=d.threshold??28,m=Math.min(100,Math.round(u/p*100)),f=d.name??`${d.hash.slice(0,10)}...`,v=!!d.enabled,h=!!d.vetoed,w=!!d.majority,k=nc[f]??{},b=($=tt.amendMomentum)==null?void 0:$[d.hash],x="";if(w&&!v&&d.majority){let P=Date.now()-new Date(d.majority).getTime(),M=P>0?Math.floor(P/864e5):0,N=Math.max(0,14-M),_=Math.min(100,Math.round(M/14*100));x=`<div class="ap-countdown">
        <span class="ap-countdown-lbl">Majority held ${M}d \xB7 activates in ~${N}d</span>
        <div class="ap-countdown-track"><div class="ap-countdown-fill" style="width:${_}%"></div></div>
      </div>`}let S=v?"#50fa7b":h?"#ff5555":w?"#ffb86c":m>=80?"#8be9fd":"rgba(255,255,255,.3)",T=v?"Active":h?"Vetoed":w?"Majority":m>=80?"Near":"Voting";return`<div class="ap-row" onclick="window.showAmendDetail('${g(d.hash)}')">
      <div class="ap-row-main">
        <div class="ap-row-top">
          <span class="ap-name">${g(f)}</span>
          <span class="ap-status-tag" style="border-color:${S}44;color:${S}">${T}</span>
        </div>
        ${k.purpose?`<div class="ap-purpose">${g(k.purpose)}</div>`:""}
        ${v?`<div class="ap-active-note">\u2713 Running on all ledgers${k.intro?" \xB7 since "+k.intro:""}</div>`:`<div class="ap-vote-row">
          <div class="ap-vote-track">
            <div class="ap-vote-fill" style="width:${m}%;background:${S};opacity:${v?1:.75}"></div>
            <div class="ap-vote-thresh" title="80% threshold"></div>
          </div>
          <span class="ap-vote-label">${u}/${p} <span style="opacity:.5">(${m}%)</span></span>
        </div>`}
        ${x}
      </div>
    </div>`}).join("")}function Ng(e){Bo={},Object.entries(e).forEach(([t,n])=>{Bo[t]={hash:t,...n}})}window.showAmendDetail=function(e){let t=Bo[e];if(!t)return;let n=t.name||`${e.slice(0,16)}...`,s=nc[n]||{},a=t.count??0,o=t.threshold??28,i=Math.min(100,Math.round(a/o*100)),r=t.enabled?"Active on Ledger":t.vetoed?"Vetoed":t.majority?"Majority Reached":"Voting in Progress",l=t.enabled?"adm-s-ok":t.vetoed?"adm-s-bad":t.majority?"adm-s-warn":"adm-s-info",c=t.enabled?"bar-ok":t.vetoed?"bar-danger":t.majority?"bar-warn":"bar-info",d=t.majority&&!t.enabled?`
    <div class="adm-note adm-note-warn">
      Majority reached. If maintained for 2 weeks this amendment will auto-activate.
      Majority since: ${g(String(t.majority))}
    </div>`:"",u=y("amend-modal-overlay"),p=y("amend-modal-body");!u||!p||(p.innerHTML=`
    <div class="adm-header">
      <div class="adm-title-row">
        <h2 class="adm-title">${g(n)}</h2>
        <span class="adm-status ${l}">${g(r)}</span>
      </div>
      <div class="adm-hash mono">${g(e)}</div>
    </div>
    ${s.purpose?`<div class="adm-purpose-row"><span class="adm-purpose-tag">Purpose</span>${g(s.purpose)}</div>`:""}
    ${s.desc?`<div class="adm-section"><div class="adm-slbl">What it does</div><div class="adm-sdesc">${g(s.desc)}</div></div>`:""}
    ${s.impact?`<div class="adm-section"><div class="adm-slbl">Technical Impact</div><div class="adm-sdesc">${g(s.impact)}</div></div>`:""}
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
      ${s.intro?`<div class="adm-mi"><span class="adm-mk">First available</span><span class="adm-mv">${g(s.intro)}</span></div>`:""}
    </div>
    <div class="adm-footer">
      <a class="adm-link" href="https://xrpl.org/known-amendments.html" target="_blank" rel="noopener noreferrer">Amendment Reference</a>
      <a class="adm-link" href="https://xrpl.org/consensus.html" target="_blank" rel="noopener noreferrer">Consensus Docs</a>
    </div>`,u.style.display="flex",u.addEventListener("click",m=>{m.target===u&&window.closeAmendModal()},{once:!0}))};window.closeAmendModal=function(){let e=y("amend-modal-overlay");e&&(e.style.display="none")};function _g(e){if(window.L){e();return}if(!document.querySelector("#leaflet-css")){let n=document.createElement("link");n.id="leaflet-css",n.rel="stylesheet",n.href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css",document.head.appendChild(n)}let t=document.createElement("script");t.src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js",t.onload=e,document.head.appendChild(t)}function Rg(e,t,n,s,a=!1){y("world-map-container")&&_g(()=>Dg(e,t,n,s,a))}function Dg(e,t,n,s,a=!1){let o=y("world-map-container");if(!o)return;let i=new Set(n||[]),r=new Set(e||[]),l=new Set(t||[]),c=O.currentNetwork||"xrpl-mainnet";if(je&&ga!==c&&(je.remove(),je=null,Ot=[],ga=null),!je){o.innerHTML="";let x=document.createElement("div");x.id="wm-leaflet",x.style.cssText="width:100%;height:440px;",o.appendChild(x),je=L.map("wm-leaflet",{center:[25,5],zoom:2,minZoom:1,maxZoom:12,zoomControl:!0,attributionControl:!0,worldCopyJump:!0}),L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",{attribution:'&copy; <a href="https://carto.com">CARTO</a> &copy; <a href="https://openstreetmap.org">OSM</a>',subdomains:"abcd",maxZoom:19}).addTo(je),ga=c}Ot.forEach(x=>{try{x.remove()}catch{}}),Ot=[];function d(x){return i.has(x)?"nunl":r.has(x)&&l.has(x)?"both":r.has(x)?"unl":l.has(x)?"dunl":"other"}Oo={};let u={};for(let[x,S]of $e){let T=on(S);if(!(T!=null&&T.lat)||!(T!=null&&T.lng))continue;let $=`${(Math.round(T.lat*2)/2).toFixed(1)},${(Math.round(T.lng*2)/2).toFixed(1)}`;u[$]||(u[$]={lat:T.lat,lng:T.lng,keys:[],city:T.city,org:T.org}),u[$].keys.push(x)}if(Object.values(u).forEach(x=>{let S=x.keys.length,T=x.keys.map(d),$=["nunl","both","unl","dunl","other"].find(X=>T.includes(X))||"other",P=_e[$],M=S>5?13:S>2?10:7,N=L.divIcon({html:`<div class="wm-lmarker wm-lmarker-val ${$==="nunl"?"wm-lmarker-nunl":""} ${a?"wm-lmarker-ref":""}"
                  style="--mc:${P.hex};--mg:${P.glow};"
                  title="${x.keys.map(X=>Ke(X).label).join(", ")}">
        <div class="wm-lring"></div>
        <div class="wm-ldot" style="width:${M*2}px;height:${M*2}px;">${S>1?`<span>${S}</span>`:""}</div>
      </div>`,className:"",iconSize:[(M+8)*2,(M+8)*2],iconAnchor:[M+8,M+8]}),_=L.marker([x.lat,x.lng],{icon:N}).bindPopup(Ig(x.keys,x.city,x.org,i,r,l,a),{maxWidth:380,className:"wm-popup-wrap"}).addTo(je);x.keys.forEach(X=>{Oo[X]=_}),Ot.push(_)}),a){let x=L.control({position:"bottomleft"});x.onAdd=()=>{let S=L.DomUtil.create("div","wm-ref-banner");return S.innerHTML="\u{1F4E1} Reference positions \xB7 live validator list unavailable from endpoint",S},x.addTo(je),Ot.push(x)}let p=[...$e.keys()].filter(x=>{var T;return((T=$e.get(x).geo)==null?void 0:T.lat)!=null||wa[x]}).length,m=$e.size-p;if(m>0){let x=L.control({position:"bottomright"});x.onAdd=()=>{let S=L.DomUtil.create("div","wm-unknown-ctrl");return S.innerHTML=`+ ${m} validators \xB7 location unknown`,S},x.addTo(je),Ot.push(x)}fg.forEach(x=>{let S=L.divIcon({html:`<div class="wm-lmarker wm-lmarker-pub">
        <div class="wm-lring"></div>
        <div class="wm-ldot" style="width:10px;height:10px;"></div>
      </div>`,className:"",iconSize:[20,20],iconAnchor:[10,10]}),T=L.marker([x.lat,x.lng],{icon:S}).bindPopup(`
        <div class="wm-popup-inner">
          <div class="wm-popup-badge wm-popup-badge-pub">Public Node</div>
          <div class="wm-popup-name">${g(x.label)}</div>
          <div class="wm-popup-row"><span class="wm-popup-key">Location</span><span>\u{1F4CD} ${g(x.city)}</span></div>
          <div class="wm-popup-row"><span class="wm-popup-key">Operator</span><span>${g(x.org)}</span></div>
          <div class="wm-popup-row"><span class="wm-popup-key">Type</span><span>Full history node</span></div>
        </div>`,{maxWidth:260,className:"wm-popup-wrap"}).addTo(je);Ot.push(T)});let f=Array.isArray(s)?s:[],v=f.filter(x=>x.inbound===!0).length,h=f.length-v,w=f.length>0?`${f.length} peers (${v}\u2193 ${h}\u2191)`:`${Number((qe==null?void 0:qe.peers)??0)} peers`,k=L.control({position:"topleft"});k.onAdd=()=>{let x=L.DomUtil.create("div","wm-legend-ctrl");return x.innerHTML=`
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${_e.unl.hex};box-shadow:0 0 5px ${_e.unl.glow}"></span>UNL Validator</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${_e.dunl.hex};box-shadow:0 0 5px ${_e.dunl.glow}"></span>dUNL only</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${_e.both.hex};box-shadow:0 0 5px ${_e.both.glow}"></span>UNL + dUNL</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${_e.other.hex};box-shadow:0 0 5px ${_e.other.glow}"></span>Other validator</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${_e.nunl.hex};box-shadow:0 0 5px ${_e.nunl.glow}"></span>Negative UNL</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${_e.pub.hex};box-shadow:0 0 5px ${_e.pub.glow}"></span>Public Node</div>
      <div class="wm-leg-row wm-leg-peers"><span class="wm-leg-dot" style="background:#8be9fd"></span>${w}</div>
      <div class="wm-leg-src" style="opacity:.55;font-size:10px;margin-top:4px;">
        Registry: ${an==="live"?"\u{1F7E2} live":"\u{1F7E1} fallback"}
      </div>`,x},k.addTo(je),Ot.push(k);let b=Ot.filter(x=>x&&typeof x.getLatLng=="function");if(b.length>=2)try{let x=L.latLngBounds(b.map(S=>S.getLatLng()));x.isValid()&&je.fitBounds(x.pad(.15),{maxZoom:6})}catch{}try{window.dispatchEvent(new CustomEvent("nalulf-network-map",{detail:{map:je,networkId:ga}}))}catch{}}function Ig(e,t,n,s,a,o,i=!1){let r=e.length>1,l=e.map(d=>{let u=Ke(d),p=s.has(d),m=a.has(d),f=o.has(d),v=d.slice(0,20)+"...",h,w;return p?(h=_e.nunl.hex,w="Negative UNL"):m&&f?(h=_e.both.hex,w="UNL + dUNL"):m?(h=_e.unl.hex,w="UNL"):f?(h=_e.dunl.hex,w="dUNL"):(h=_e.other.hex,w="Other"),`<div class="wm-popup-val-row">
      <span class="wm-popup-val-dot" style="background:${h};box-shadow:0 0 6px ${h}66"></span>
      <div class="wm-popup-val-info">
        <span class="wm-popup-val-name">${g(u.label)}</span>
        ${u.domain?`<span class="wm-popup-val-domain">${g(u.domain)}</span>`:""}
        <span class="wm-popup-val-key"
              onclick="navigator.clipboard?.writeText('${g(d)}');this.textContent='\u2713 Copied!';setTimeout(()=>this.textContent='${g(v)}',1400)"
              title="Click to copy full key">${g(v)}</span>
        <div class="wm-popup-val-tags">
          <span class="wm-popup-ok-tag" style="border-color:${h}66;color:${h}">${w}</span>
          ${u.provider?`<span class="wm-popup-prov">${g(u.provider)}</span>`:""}
        </div>
      </div>
    </div>`}).join(""),c=[...new Set(e.map(d=>{var p;let u=Ke(d);return u.provider??((p=on(u))==null?void 0:p.org)??null}).filter(Boolean))];return`<div class="wm-popup-inner">
    <div class="wm-popup-loc-row">
      <span class="wm-popup-loc-icon">\u{1F4CD}</span>
      <div>
        <div class="wm-popup-name">${g(t||"Unknown Location")}</div>
        ${c.map(d=>`<div class="wm-popup-org">${g(d)}</div>`).join("")}
      </div>
    </div>
    <div class="wm-popup-badges">
      ${r?`<div class="wm-popup-badge wm-popup-badge-cluster">${e.length} Validators at this location</div>`:""}
      ${i?'<div class="wm-popup-badge wm-popup-badge-ref">Reference data</div>':""}
    </div>
    <div class="wm-popup-divider"></div>
    <div class="wm-popup-vals">${l}</div>
  </div>`}var Zn=[];function Fg(){let e=Object.keys(Fe),t=e.reduce((r,l)=>{var c;return r+(((c=Xt[l])==null?void 0:c.w)??1)},0),n=t>=dg;for(e.forEach(r=>{var l,c;Zn.find(d=>d.key===r&&Date.now()-d.ts<3e5)||Zn.push({key:r,label:((l=Xt[r])==null?void 0:l.label)??r,ts:Date.now(),weight:((c=Xt[r])==null?void 0:c.w)??1})});Zn.length>20;)Zn.shift();let s=y("adversarial-alert");s&&(s.classList.toggle("adv-active",n),s.classList.toggle("adv-inactive",!n));let a=y("adversarial-score");if(a){let r=t===0?"All Clear":t<3?"Monitor":t<5?"Elevated":t<10?"High":"Critical",l=t===0?"#50fa7b":t<3?"#8be9fd":t<5?"#ffb86c":t<10?"#ff9955":"#ff5555";a.innerHTML=`<span style="color:${l};font-weight:700">${r}</span>
      <span style="opacity:.5;font-size:11px;margin-left:8px">threat score ${t}</span>`,a.className="adv-score"}let o=y("adversarial-signals");if(!o)return;if(!e.length)o.innerHTML=`<div class="adv-clear-card">
      <span class="adv-clear-icon">\u2713</span>
      <div>
        <div class="adv-clear-title">No Active Signals</div>
        <div class="adv-clear-sub">All ${Object.keys(Xt).length} threat indicators are nominal</div>
      </div>
    </div>`;else{let r=e.filter(u=>{var p;return(((p=Xt[u])==null?void 0:p.w)??1)>=3}),l=e.filter(u=>{var p;return(((p=Xt[u])==null?void 0:p.w)??1)===2}),c=e.filter(u=>{var p;return(((p=Xt[u])==null?void 0:p.w)??1)===1}),d=(u,p,m)=>p.length===0?"":`
      <div class="adv-group-title" style="color:${m}">${u} (${p.length})</div>
      ${p.map(f=>{let v=Xt[f]??{w:1,label:f},h=v.label.split(" \u2014 "),w=h[0],k=h[1]||"";return`<div class="adv-sig-card adv-sig-${v.w>=3?"critical":v.w>=2?"elevated":"monitor"}">
          <div class="adv-sig-top">
            <span class="adv-sig-dot" style="background:${m}"></span>
            <span class="adv-sig-title">${g(w)}</span>
            <span class="adv-sig-badge" style="border-color:${m}44;color:${m}">W${v.w}</span>
          </div>
          ${k?`<div class="adv-sig-detail">${g(k)}</div>`:""}
        </div>`}).join("")}`;o.innerHTML=d("Critical",r,"#ff5555")+d("Elevated",l,"#ffb86c")+d("Monitor",c,"#8be9fd")}let i=y("adversarial-history");if(i&&Zn.length){let r=Date.now();i.innerHTML=Zn.slice(-8).reverse().map(l=>{let c=Math.round((r-l.ts)/6e4),d=e.includes(l.key);return`<div class="adv-hist-row ${d?"adv-hist-active":"adv-hist-resolved"}">
        <span class="adv-hist-dot"></span>
        <span class="adv-hist-lbl">${g(l.label.split(" \u2014 ")[0].substring(0,40))}</span>
        <span class="adv-hist-time">${c<1?"now":`${c}m ago`} ${d?'<span class="adv-hist-tag-active">active</span>':'<span class="adv-hist-tag-res">resolved</span>'}</span>
      </div>`}).join("")}}function uc(e){var S,T,$,P;let t=y("nh-banner");if(!t)return;if(!e||O.connectionState!=="connected"){G("nh-score","\u2014"),G("nh-grade","Disconnected"),G("nh-sub","Connect to begin"),t.className="nh-banner nh-dead",Jl({}),Yl(null);return}let{info:n,fee:s,vals:a}=e,o=100,i=(n==null?void 0:n.server_state)??"unknown";["full","proposing","validating"].includes(i)||(o-=i==="syncing"?20:40);let r=Number((n==null?void 0:n.load_factor)??1);r>2&&(o-=10),r>5&&(o-=15),r>20&&(o-=20);let l=Number((n==null?void 0:n.peers)??0);l<6?o-=30:l<15&&(o-=10);let c=Number(((S=n==null?void 0:n.last_close)==null?void 0:S.converge_time_s)??0);c>6&&(o-=10),c>10&&(o-=15);let d=Number(((T=n==null?void 0:n.validated_ledger)==null?void 0:T.age)??0);d>5&&(o-=5),d>10&&(o-=15);let u=Number((($=s==null?void 0:s.drops)==null?void 0:$.open_ledger_fee)??10);u>500&&(o-=5),u>2e3&&(o-=10);let p=((P=a==null?void 0:a.trusted_validator_keys)==null?void 0:P.length)??0,m=(a==null?void 0:a.validation_quorum)??0;m>0&&p<m&&(o-=30);let f=((n==null?void 0:n.negative_unl)??[]).length;o-=Math.min(20,f*4);let v=Object.keys(Fe).reduce((M,N)=>{var _;return M+(((_=Xt[N])==null?void 0:_.w)??1)},0);o-=Math.min(25,v*3),o=Math.max(0,Math.min(100,Math.round(o)));let h=Object.keys(Fe).length,{grade:w,status:k,cls:b}=Bg(o);G("nh-score",k),G("nh-grade",w),G("nh-sub",`${new Date().toLocaleTimeString()} \xB7 ${h>0?h+" signal"+(h!==1?"s":"")+" active":"All signals clear"}`),t.className=`nh-banner nh-${b}`;let x=y("nh-ring");if(x){let M=2*Math.PI*28;x.style.strokeDasharray=M,x.style.strokeDashoffset=M*(1-o/100);let N=b==="great"?"#00fff0":b==="good"?"#50fa7b":b==="fair"?"#ffb86c":b==="warn"?"#ff9955":"#ff5555";x.style.stroke=N}Jl({st:i,pc:l,q:m,tc:p,lf:r,cvg:c,age:d,nc:f}),Yl({info:n,fee:s,vals:a})}function Bg(e){return e>=90?{grade:"All Systems Nominal",status:"Optimal",cls:"great"}:e>=70?{grade:"Operating Normally",status:"Good",cls:"good"}:e>=50?{grade:"Minor Issues Detected",status:"Watch",cls:"fair"}:e>=30?{grade:"Attention Required",status:"Warning",cls:"warn"}:{grade:"Critical Issues",status:"Critical",cls:"bad"}}function Jl(e){xn("nh-v-state",["full","proposing","validating"].includes(e.st)?"ok":e.st==="syncing"?"warn":"bad",e.st??"\u2014"),xn("nh-v-peers",(e.pc??0)>=15?"ok":(e.pc??0)>=6?"warn":"bad",e.pc!=null?`${e.pc} peers`:"\u2014"),xn("nh-v-cvg",(e.cvg??0)<4?"ok":(e.cvg??0)<7?"warn":"bad",e.cvg!=null?`${Number(e.cvg).toFixed(1)}s`:"\u2014"),xn("nh-v-age",(e.age??0)<3?"ok":(e.age??0)<8?"warn":"bad",e.age!=null?`${Number(e.age)}s ago`:"\u2014"),xn("nh-v-load",(e.lf??1)<2?"ok":(e.lf??1)<5?"warn":"bad",e.lf!=null?`${Number(e.lf).toFixed(2)}\xD7 load`:"\u2014"),xn("nh-v-nunl",(e.nc??0)===0?"ok":(e.nc??0)<=2?"warn":"bad",e.nc!=null?e.nc===0?"None offline":`${e.nc} offline`:"\u2014");let t=e.q??0,n=e.tc??0,s=n-t;xn("nh-v-quorum",s>3?"ok":s>0?"warn":"bad",t>0?`${t} required \xB7 margin ${s}`:"\u2014")}function xn(e,t,n){let s=y(e);s&&(s.textContent=n,s.className=`nh-vval nh-vval--${t}`)}function Yl(e){let t=y("nh-health-checks");if(!t)return;if(!e){t.innerHTML='<div class="hc-disconnected">Connect to an XRPL node to run health checks</div>';return}let{info:n,fee:s,vals:a}=e,i=[{label:"Node State",group:"consensus",icon:"\u2B21",check:()=>{let p=(n==null?void 0:n.server_state)||"unknown",m=["full","proposing","validating"].includes(p),f=p==="syncing"||p==="tracking";return{value:p,status:m?"ok":f?"watch":"alert",note:m?"Participating in consensus":f?"Catching up to network":"Not participating"}}},{label:"Quorum Margin",group:"consensus",icon:"\u2696",check:()=>{var v;let p=((v=a==null?void 0:a.trusted_validator_keys)==null?void 0:v.length)??0,m=(a==null?void 0:a.validation_quorum)??0,f=p-m;return m?{value:`${f} spare`,status:f>3?"ok":f>0?"watch":"alert",note:f>3?`${m} of ${p} needed \u2014 ${f} can go offline safely`:f>0?`Only ${f} validator(s) above quorum \u2014 very tight`:"Below quorum \u2014 consensus may stall"}:{value:"\u2014",status:"watch",note:"Validator data not available"}}},{label:"Negative UNL",group:"consensus",icon:"\u26D4",check:()=>{let p=((n==null?void 0:n.negative_unl)||[]).length;return{value:p===0?"None":`${p} listed`,status:p===0?"ok":p<=2?"watch":"alert",note:p===0?"All UNL validators are online":`${p} validator(s) temporarily excluded from consensus counting`}}},{label:"Ledger Age",group:"consensus",icon:"\u23F1",check:()=>{var m;let p=Number(((m=n==null?void 0:n.validated_ledger)==null?void 0:m.age)??0);return{value:p<2?"< 1s":`${p}s`,status:p<5?"ok":p<10?"watch":"alert",note:p<5?"Ledger closing on schedule (3\u20134s target)":p<10?"Slightly delayed \u2014 network may be busy":"Ledger stalled \u2014 consensus issue likely"}}},{label:"Convergence Time",group:"consensus",icon:"\u{1F504}",check:()=>{var m;let p=Number(((m=n==null?void 0:n.last_close)==null?void 0:m.converge_time_s)??0);return{value:p>0?`${p.toFixed(1)}s`:"\u2014",status:p<4?"ok":p<7?"watch":"alert",note:p<4?"Validators agreeing quickly":p<7?"Slightly slow \u2014 check for network latency":"Slow convergence \u2014 validator disagreement or network partition"}}},{label:"Peer Count",group:"infra",icon:"\u{1F517}",check:()=>{let p=Number((n==null?void 0:n.peers)??0);return{value:`${p} peers`,status:p>=15?"ok":p>=6?"watch":"alert",note:p>=15?"Well-connected to the network":p>=6?"Below recommended (15+) \u2014 consider adding peers":"Critically low \u2014 eclipse attack risk is high"}}},{label:"Load Factor",group:"infra",icon:"\u26A1",check:()=>{let p=Number((n==null?void 0:n.load_factor)??1);return{value:`${p.toFixed(2)}\xD7`,status:p<2?"ok":p<5?"watch":"alert",note:p<2?"Normal load \u2014 node processing freely":p<5?"Elevated load \u2014 fees increasing":"High load \u2014 this node is throttling transactions"}}},{label:"IO Latency",group:"infra",icon:"\u{1F4BE}",check:()=>{let p=Number((n==null?void 0:n.io_latency_ms)??0);return{value:p>0?`${p}ms`:"< 1ms",status:p<2?"ok":p<10?"watch":"alert",note:p<2?"Storage and network I/O responding well":p<10?"Moderate I/O latency \u2014 monitor disk/network":"High I/O latency \u2014 storage or network bottleneck"}}},{label:"Job Queue",group:"infra",icon:"\u{1F4CB}",check:()=>{let p=Number((n==null?void 0:n.jq_trans_overflow)??0);return{value:p===0?"Clear":`${p} overflow`,status:p===0?"ok":"alert",note:p===0?"No transaction job queue overflows":"Queue overflowing \u2014 node is overwhelmed, upgrade resources"}}},{label:"Fee Pressure",group:"ledger",icon:"\u{1F4B8}",check:()=>{var f;let p=Number(((f=s==null?void 0:s.drops)==null?void 0:f.open_ledger_fee)??10),m=p<100?"Minimal":p<500?"Elevated":p<5e3?"High":"Severe";return{value:`${p} drops`,status:p<100?"ok":p<500?"watch":"alert",note:p<100?"Normal transaction fees \u2014 network not congested":p<500?"Fees rising \u2014 moderate network congestion":"High fees \u2014 significant congestion or spam attack"}}},{label:"TX Queue Fill",group:"ledger",icon:"\u{1F5C2}",check:()=>{let p=Number((s==null?void 0:s.current_queue_size)??0),m=Number((s==null?void 0:s.max_queue_size)??1),f=m>0?Math.round(p/m*100):0;return{value:`${f}% (${p}/${m})`,status:f<50?"ok":f<80?"watch":"alert",note:f<50?`Queue at ${f}% \u2014 plenty of headroom`:f<80?`Queue ${f}% full \u2014 fee spike likely soon`:"Queue nearly full \u2014 transactions being dropped"}}}].map(p=>({...p,result:p.check()})),r=i.filter(p=>p.result.status==="ok").length,l=i.filter(p=>p.result.status==="watch").length,c=i.filter(p=>p.result.status==="alert").length,d=y("nh-health-summary");d&&(d.innerHTML=`
      <span class="hcs-count hcs-pass">${r}</span><span class="hcs-lbl">nominal</span>
      <span class="hcs-sep">\xB7</span>
      <span class="hcs-count hcs-warn">${l}</span><span class="hcs-lbl">watch</span>
      <span class="hcs-sep">\xB7</span>
      <span class="hcs-count hcs-fail">${c}</span><span class="hcs-lbl">alert</span>
      <span class="hcs-total">of ${i.length} checks</span>`);let u={consensus:"Consensus Health",infra:"Node Infrastructure",ledger:"Ledger & Fees"};t.innerHTML=Object.entries(u).map(([p,m])=>{let f=i.filter(b=>b.group===p),v=f.map(b=>{let x=b.result.status,S=x==="ok"?"hc-ok":x==="watch"?"hc-warn":"hc-fail",T="\u25CF";return`<div class="hc-item ${S}">
        <div class="hc-item-top">
          <span class="hc-dot" style="background:${x==="ok"?"#50fa7b":x==="watch"?"#ffb86c":"#ff5555"}"></span>
          <span class="hc-label">${g(b.icon)} ${g(b.label)}</span>
          <span class="hc-value">${g(b.result.value)}</span>
        </div>
        <div class="hc-note">${g(b.result.note)}</div>
      </div>`}).join(""),h=f.filter(b=>b.result.status==="ok").length;return`<div class="hc-group ${f.filter(b=>b.result.status==="alert").length>0?"hcg-alert":h===f.length?"hcg-ok":"hcg-watch"}">
      <div class="hc-group-title">${g(m)}
        <span class="hcg-badge">${h}/${f.length}</span>
      </div>
      <div class="hc-group-items">${v}</div>
    </div>`}).join("")}function Og(e){var t,n,s,a,o,i,r,l,c,d;e&&(Ge("burnDrops",(e.avgFee||0)*1e6*(e.txPerLedger??0)),Ge("dexOffers",((t=e.txTypes)==null?void 0:t.OfferCreate)??0),Ge("ammSwaps",(((n=e.txTypes)==null?void 0:n.AMMDeposit)??0)+(((s=e.txTypes)==null?void 0:s.AMMWithdraw)??0)+(((a=e.txTypes)==null?void 0:a.AMMBid)??0)),Ge("newAccounts",((o=e.txTypes)==null?void 0:o.AccountSet)??0),Ge("txPayment",((i=e.txTypes)==null?void 0:i.Payment)??0),Ge("txNFT",(((r=e.txTypes)==null?void 0:r.NFTokenMint)??0)+(((l=e.txTypes)==null?void 0:l.NFTokenBurn)??0)+(((c=e.txTypes)==null?void 0:c.NFTokenCreateOffer)??0)+(((d=e.txTypes)==null?void 0:d.NFTokenAcceptOffer)??0)),Ge("txLedger",e.txPerLedger??0),Ge("tps",e.tps??(e.txPerLedger??0)/3.5),Ge("closeTime",e.closeTime??3.5))}function Xg(e){let t=O.tpsHistory.length?O.tpsHistory[O.tpsHistory.length-1]:null;G("m2-tps",t!=null?t.toFixed(1):"\u2014"),G("m2-txcount",e.txPerLedger??"\u2014"),e.successRate!=null&&G("m2-success",`${e.successRate.toFixed(0)}%`)}async function Cs({force:e=!1}={}){if(!es()&&!e)return;let t=Date.now();if(!e&&t-Vl<rg)return;Vl=t;let n=y("latency-list");if(!n)return;let s=Qi[O.currentNetwork]??[],a=++Gl;n.innerHTML=s.map((o,i)=>`
    <div class="latency-row" id="lat-row-${i}">
      <div class="lat-ep">
        <span class="lat-name">${g(o.name)}</span>
        <span class="lat-url">${g(o.url)}</span>
      </div>
      <div class="lat-bwrap"><div class="lat-bfill" id="lat-bar-${i}" style="width:0%"></div></div>
      <span class="lat-val" id="lat-val-${i}">\u2014</span>
    </div>`).join("");for(let o=0;o<s.length;o++){if(a!==Gl)return;await Hg(s[o],o),await Kg(lg)}}async function Hg(e,t){var i;let n=y(`lat-val-${t}`),s=y(`lat-bar-${t}`),a=y(`lat-row-${t}`);n&&(n.textContent="...");let o=performance.now();try{let r=new WebSocket(e.url);await new Promise((d,u)=>{let p=setTimeout(()=>u(),ig);r.onopen=()=>{clearTimeout(p),d()},r.onerror=()=>{clearTimeout(p),u()}});let l=Math.round(performance.now()-o);try{r.close()}catch{}let c=l<100?"lat-fast":l<300?"lat-med":"lat-slow";n&&(n.textContent=`${l}ms`,n.className=`lat-val ${c}`),s&&(s.style.width=`${Math.min(100,l/600*100)}%`),a==null||a.classList.toggle("lat-active",((i=O.wsConn)==null?void 0:i.url)===e.url)}catch{n&&(n.textContent="timeout",n.className="lat-val lat-slow")}}function zg(){if(document.getElementById("vg-tab-styles"))return;let e=document.createElement("style");e.id="vg-tab-styles",e.textContent=`
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
  `,document.head.appendChild(e)}function Ug(){if(document.getElementById("m4-panel"))return;let e=[()=>document.querySelector('[data-section="fee-market"]'),()=>document.querySelector('[data-section="infrastructure"]'),()=>document.querySelector("#tab-network .section-grid"),()=>document.querySelector("#tab-network"),()=>document.body],t=null;for(let a of e)if(t=a(),t)break;if(!t)return;t.insertAdjacentHTML("beforeend",`
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
  `,document.getElementById("net-panel-styles")||document.head.appendChild(s)}function Ge(e,t){tt[e]||(tt[e]=[]),tt[e].push(Number(t)),tt[e].length>cg&&tt[e].shift()}function Ms(e){let t=tt[e]??[];return t.length?t.reduce((n,s)=>n+s,0)/t.length:0}function Wg(e){if(e.length<2)return 0;let t=e.reduce((n,s)=>n+s,0)/e.length;return Math.sqrt(e.reduce((n,s)=>n+(s-t)**2,0)/e.length)}function jg(){try{let e=localStorage.getItem(Ql);if(!e)return;let t=JSON.parse(e);Object.keys(tt).forEach(n=>{Array.isArray(t[n])&&(tt[n]=t[n])})}catch{}}function qg(){try{localStorage.setItem(Ql,JSON.stringify(tt))}catch{}}function G(e,t){let n=y(e);n&&(n.textContent=t??"\u2014")}function dt(e,t,n){let s=y(e);s&&(s.style.width=`${Math.min(100,Math.max(0,Number(t)||0))}%`,s.className=`bar-fill ${n??""}`)}function Vg(e){if(!e)return 0;let t=e.match(/(\d+)-(\d+)/);if(!t)return 10;let n=Number(t[2])-Number(t[1]);return n>1e7?95:n>1e6?70:n>1e5?40:15}function Gg(e){if(!e)return"\u2014";let t=Math.floor(e/86400),n=Math.floor(e%86400/3600),s=Math.floor(e%3600/60);return t>0?`${t}d ${n}h`:n>0?`${n}h ${s}m`:`${s}m`}function Kg(e){return new Promise(t=>setTimeout(t,e))}var Cc="nalulf_wallets",Lc="nalulf_profile",Mc="nalulf_social",Es="naluxrp_active_wallet",ln="nalulf_avatar_img",Ln="nalulf_banner_img",Jo="nalulf_activity_log",li="nalulf_balhist_",Jg="nalulf_addr_book",Yg="https://xrplcluster.com/",Qg="https://s2.ripple.com:51234/",Zg=[e=>`https://corsproxy.io/?${encodeURIComponent(e)}`,e=>`https://api.allorigins.win/raw?url=${encodeURIComponent(e)}`],Yo="claude-opus-5",ev=[{id:"claude-opus-5",label:"Claude Opus 5 \u2014 most capable, highest cost"},{id:"claude-sonnet-5",label:"Claude Sonnet 5 \u2014 strong, cheaper"},{id:"claude-haiku-4-5",label:"Claude Haiku 4.5 \u2014 fastest, cheapest"}],tv="https://api.xrpscan.com/api/v1/tokens",nv="https://api.coingecko.com/api/v3/coins/markets",sv="https://bithomp.com/api/v2/tokens",av="https://api.xrpl.to/api/tokens",ov=!1,Ta=10,Ca=2,iv=["\u{1F30A}","\u{1F40B}","\u{1F409}","\u{1F98B}","\u{1F981}","\u{1F43A}","\u{1F98A}","\u{1F43B}","\u{1F43C}","\u{1F985}","\u{1F42C}","\u{1F988}","\u{1F419}","\u{1F991}","\u{1F9FF}","\u{1F33A}","\u{1F338}","\u{1F340}","\u26A1","\u{1F525}","\u{1F48E}","\u{1F319}","\u2B50","\u{1F3AF}","\u{1F9E0}","\u{1F52E}","\u{1F6F8}","\u{1F5FA}","\u{1F3D4}","\u{1F3AD}","\u{1F3DB}"],rv=["\u{1F48E}","\u{1F3E6}","\u{1F510}","\u{1F511}","\u{1F4B0}","\u{1F30A}","\u26A1","\u{1F680}","\u{1F319}","\u2B50","\u{1F3F4}\u200D\u2620\uFE0F","\u{1F3AF}","\u{1F9E0}","\u{1F52E}"],lv=["#50fa7b","#00d4ff","#ffb86c","#bd93f9","#ff79c6","#f1fa8c","#ff5555","#00fff0","#ff6b6b","#a78bfa"],Ns=["banner-ocean","banner-neon","banner-gold","banner-cosmic","banner-sunset","banner-aurora"],as=[{id:"discord",label:"Discord",icon:"\u{1F4AC}",prefix:"https://discord.com/users/"},{id:"twitter",label:"X / Twitter",icon:"\u{1D54F}",prefix:"https://x.com/"},{id:"linkedin",label:"LinkedIn",icon:"in",prefix:"https://linkedin.com/in/"},{id:"github",label:"GitHub",icon:"\u2325",prefix:"https://github.com/"},{id:"telegram",label:"Telegram",icon:"\u2708",prefix:"https://t.me/"},{id:"facebook",label:"Facebook",icon:"f",prefix:"https://facebook.com/"},{id:"tiktok",label:"TikTok",icon:"\u266A",prefix:"https://tiktok.com/@"}],cv={tecNO_DST:"Destination account does not exist \u2014 fund it with 10 XRP first.",tecINSUF_RESERVE_LINE:"Insufficient reserve to add another trustline.",tecINSUF_RESERVE_OFFER:"Insufficient reserve to place a DEX order.",tecUNFUNDED_PAYMENT:"Insufficient balance (including reserve).",tecDST_TAG_NEEDED:"This destination requires a Destination Tag.",tecNO_PERMISSION:"Account has DepositAuth enabled \u2014 destination must preauthorize.",temBAD_AMOUNT:"Invalid amount.",temBAD_CURRENCY:"Invalid currency code.",temBAD_ISSUER:"Invalid issuer address.",tefPAST_SEQ:"Sequence number already used \u2014 please retry.",terQUEUED:"Transaction queued \u2014 will be included in a future ledger."},dv="https://cdn.jsdelivr.net/npm/xrpl@4.2.5/build/xrpl-latest-min.js",La=21e4,xa=null;function Wo(e){return btoa(String.fromCharCode(...e))}function jo(e){let t=atob(e),n=new Uint8Array(t.length);for(let s=0;s<t.length;s+=1)n[s]=t.charCodeAt(s);return n}async function Ea(){var e,t;return(e=window.xrpl)!=null&&e.Wallet?!0:(xa||(xa=new Promise((n,s)=>{let a=document.querySelector('script[data-xrpl-lib="1"]');if(a){a.addEventListener("load",()=>n(!0),{once:!0}),a.addEventListener("error",()=>s(new Error("Failed to load xrpl.js")),{once:!0});return}let o=document.createElement("script");o.src=dv,o.async=!0,o.defer=!0,o.dataset.xrplLib="1",o.onload=()=>n(!0),o.onerror=()=>s(new Error("Failed to load xrpl.js")),document.head.appendChild(o)}).finally(()=>{var n;(n=window.xrpl)!=null&&n.Wallet||(xa=null)})),await xa,!!((t=window.xrpl)!=null&&t.Wallet))}async function Pc(e,t,n=La){let s=new TextEncoder,a=await crypto.subtle.importKey("raw",s.encode(e),{name:"PBKDF2"},!1,["deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",hash:"SHA-256",salt:t,iterations:n},a,{name:"AES-GCM",length:256},!1,["encrypt","decrypt"])}async function Ac(e,t){let n=new TextEncoder,s=crypto.getRandomValues(new Uint8Array(16)),a=crypto.getRandomValues(new Uint8Array(12)),o=await Pc(t,s,La),i=await crypto.subtle.encrypt({name:"AES-GCM",iv:a},o,n.encode(e));return{v:1,kdf:"PBKDF2-SHA256",iter:La,alg:"AES-GCM-256",salt:Wo(s),iv:Wo(a),ct:Wo(new Uint8Array(i))}}async function pv(e,t){if(!(e!=null&&e.ct)||!(e!=null&&e.salt)||!(e!=null&&e.iv))throw new Error("Wallet seed blob is invalid.");let n=await Pc(t,jo(e.salt),e.iter||La),s=await crypto.subtle.decrypt({name:"AES-GCM",iv:jo(e.iv)},n,jo(e.ct));return new TextDecoder().decode(s)}async function uv(e,t){let n=(t||"").trim();if(n)return n;if(e!=null&&e.encSeed){let a=prompt("Enter your wallet password to decrypt and sign this transaction:");if(!a)throw new Error("Wallet password is required to sign.");try{return await pv(e.encSeed,a)}catch{throw new Error("Could not decrypt wallet seed. Check your wallet password and try again.")}}let s=prompt("Enter the wallet seed to sign this transaction (used once, not stored):");if(!s)throw new Error("Seed phrase is required to sign transactions.");return s.trim()}var le={displayName:"",handle:"",bio:"",location:"",website:"",avatar:"\u{1F30A}",banner:"banner-ocean",joinedDate:new Date().toISOString(),domain:""},oe=[],ze={},st=null,Ve={},ci={},di={},Ec={},pi={},Ps={},Nc={},Te={loading:!1,data:null,error:""},ut={loading:!1,items:[],error:""},mt={loading:!1,pools:[],error:""},xt={loading:!1,pools:[],error:""},Re={loading:!1,pool:null,error:""},C={pair:"BITSTAMP:XRPUSD",interval:"15",chartType:"candles",stats:null,loading:!1,error:"",comparePair:"",indicators:{sma20:!0,ema20:!1,wma20:!1,bb20:!1,vwap:!1,ichimoku:!1,macd:!1,rsi:!1,atr:!1,adx:!1,aroon:!1,cci:!1,williamsr:!1,mfi:!1,obv:!1,adline:!1,cmf:!1,stoch:!1,uo:!1,stdev:!1,donchian:!1,keltner:!1,supertrend:!1,pivots:!1,sar:!1,vortex:!1,elderRay:!1},tokenFocusKey:"",drawingTool:"none",drawings:[],alerts:[],indicatorMenuOpen:!1,moreMenuOpen:!1,indicatorQuery:"",indicatorSettings:{},settingsOpenFor:null,threeEnabled:!0,selectedIndicator:"sma20",selectedEducationTab:"indicator",educationCollapsed:!1,educationHint:"",chartMeta:{tokenKey:"XRP|",symbol:"XRP",source:"Coinbase + XRPL live",last:null,high:null,low:null,mode:"pair"}},j={loading:!1,tokens:[],filtered:[],trending:[],error:"",query:"",total:0,lastSyncAt:0,filters:{type:"all",minCap:0,minVol:0,hasDex:!1},selectedTokenKey:"",listLimit:240},wt={loading:!1,items:[],error:""},mc=new Map,ka=null,$a=null,fc=!1,hc=0,_c=0,qo=null,gc={xrplto:0},ee={chart:null,volumeSeries:null,activeSeries:null,compareSeries:null,indicatorSeries:[],indicatorPriceLines:[],priceLines:[],resizeObserver:null,chartType:"",configKey:"",legendEl:null,renderLegend:null,ichimokuData:null,indicatorLegendItems:[],alertPriceLines:[]},He={renderer:null,scene:null,camera:null,points:null,raf:0,host:null,resizeHandler:null},As=new Map,Sn=0,Vo="",mv="naluxrp_hist_v1_",Rc=60,Dc=25,fv=200,hv=e=>new Promise(t=>setTimeout(t,e)),Qo="naluxrp_seed_backed_up",Ic="naluxrp_token_watchlist",Zo="naluxrp_chart_layout",Fc="naluxrp_selected_token",ui="naluxrp_chart_3d",Bc="naluxrp_price_alerts";function Ma(){return O.currentPage==="profile"&&!document.hidden}var gv=[{symbol:"XRP",name:"XRP Ledger Native",marketCap:"$124.3B",source:"CoinGecko"},{symbol:"RLUSD",name:"Ripple USD",marketCap:"$312.0M",source:"Static sample"},{symbol:"SOLOGENIC",name:"Sologenic",marketCap:"$96.4M",source:"Static sample"}],Mn=[{id:"BITSTAMP:XRPUSD",label:"XRP / USD (Coinbase + XRPL)",source:"coinbase",ticker:"xrpusd",symbol:"XRP",coingeckoId:"ripple"},{id:"BINANCE:XRPUSDT",label:"XRP / USD (Coinbase mirror)",source:"coinbase",ticker:"XRPUSDT",symbol:"XRP",coingeckoId:"ripple"},{id:"BINANCE:ETHUSDT",label:"ETH / USD (Coinbase)",source:"coinbase",ticker:"ETHUSDT",symbol:"ETH",coingeckoId:"ethereum"},{id:"BINANCE:BTCUSDT",label:"BTC / USD (Coinbase)",source:"coinbase",ticker:"BTCUSDT",symbol:"BTC",coingeckoId:"bitcoin"},{id:"BINANCE:SOLUSDT",label:"SOL / USD (Coinbase)",source:"coinbase",ticker:"SOLUSDT",symbol:"SOL",coingeckoId:"solana"}],Oc=[{value:"1",label:"1m"},{value:"3",label:"3m"},{value:"5",label:"5m"},{value:"15",label:"15m"},{value:"30",label:"30m"},{value:"60",label:"1h"},{value:"120",label:"2h"},{value:"240",label:"4h"},{value:"D",label:"1D"},{value:"W",label:"1W"},{value:"M",label:"1M"}];var Xc=[{key:"none",label:"Cursor"},{key:"hline",label:"Horizontal Line"}],vv={trend:["sma20","ema20","wma20","ichimoku","adx","aroon","sar","supertrend","vortex","elderRay","macd"],momentum:["rsi","stoch","cci","williamsr","mfi","uo"],volume:["obv","adline","cmf","vwap"],volatility:["bb20","keltner","atr","donchian","stdev"],advanced:["pivots"]},Ht={sma20:{name:"SMA 20",what:"Simple average of closing prices over 20 periods.",purpose:"Baseline trend smoothing.",apply:"Use slope and price relation for trend confirmation.",mistake:"Assuming one crossover equals full trend reversal.",bias:"Check higher timeframe trend first."},ema20:{name:"EMA 20",what:"Weighted moving average that reacts faster.",purpose:"Track momentum shifts early.",apply:"Use with structure breaks for continuation entries.",mistake:"Overtrading every touch.",bias:"Wait for confirmation candle close."},wma20:{name:"WMA 20",what:"Linear weighted average favoring recent closes.",purpose:"Balance noise and reactivity.",apply:"Useful for dynamic pullback zones.",mistake:"Treating it as support in chop.",bias:"Confirm with volatility context."},ichimoku:{name:"Ichimoku Cloud",what:"Multi-line trend, momentum, and support/resistance framework.",purpose:"One-glance regime detection.",apply:"Favor trades aligned with cloud direction and conversion/base line confluence.",mistake:"Ignoring lagging span context.",bias:"Only take signals in clear trend phases."},macd:{name:"MACD",what:"Difference between fast and slow EMAs with signal line.",purpose:"Momentum and trend acceleration.",apply:"Use histogram contraction/expansion and line cross with structure.",mistake:"Late entries from isolated crosses.",bias:"Match cross direction with market structure."},rsi:{name:"RSI",what:"Relative strength oscillator from 0-100.",purpose:"Momentum strength and exhaustion.",apply:"40-80 bull range, 20-60 bear range is often more useful than 30/70 alone.",mistake:"Shorting every overbought reading in uptrends.",bias:"Use RSI with trend filters and divergence context."},stoch:{name:"Stochastic",what:"Close location relative to recent range.",purpose:"Short-term momentum turns.",apply:"Best in ranges or pullbacks within trend.",mistake:"Treating every cross as signal.",bias:"Require structure or support/resistance confluence."},cci:{name:"CCI",what:"Deviation from statistical mean.",purpose:"Identify cyclical overextensions.",apply:"Look for trend-aligned re-entry after reset.",mistake:"Using fixed thresholds in all regimes.",bias:"Adapt thresholds to volatility."},williamsr:{name:"Williams %R",what:"Inverse stochastic oscillator.",purpose:"Range extremes and momentum snapbacks.",apply:"Use with market regime filter.",mistake:"Fading trends blindly.",bias:"Avoid countertrend trades without invalidation levels."},mfi:{name:"MFI",what:"Volume-weighted RSI style oscillator.",purpose:"Money flow pressure.",apply:"Combine with volume spikes for conviction.",mistake:"Ignoring thin liquidity distortions.",bias:"Cross-check on multiple venues when possible."},uo:{name:"Ultimate Oscillator",what:"Weighted momentum across multiple windows.",purpose:"Reduce single-window false signals.",apply:"Divergences can be strong with structure breaks.",mistake:"Using without trend filter.",bias:"Require two independent confirmations."},obv:{name:"On Balance Volume",what:"Cumulative signed volume.",purpose:"Volume pressure trend.",apply:"Look for OBV breaks before price breaks.",mistake:"Trusting OBV in sparse data periods.",bias:"Check liquidity quality first."},adline:{name:"Accumulation/Distribution",what:"Volume flow using close location in candle.",purpose:"Detect stealth accumulation/distribution.",apply:"Use for divergence against price trend.",mistake:"Ignoring wick distortions.",bias:"Validate with average volume regime."},cmf:{name:"Chaikin Money Flow",what:"Normalized accumulation/distribution over window.",purpose:"Money flow bias.",apply:"Sustained above/below zero is more meaningful than single crosses.",mistake:"Reacting to one-bar flips.",bias:"Use persistence thresholds."},vwap:{name:"VWAP",what:"Volume weighted average price.",purpose:"Institutional execution benchmark.",apply:"Use as intraday mean reversion or trend continuation anchor.",mistake:"Ignoring session resets.",bias:"Define session context explicitly."},bb20:{name:"Bollinger Bands",what:"Moving average with standard deviation envelopes.",purpose:"Volatility expansion/contraction.",apply:"Squeezes can precede breakouts; walks indicate trend.",mistake:"Assuming every upper-band touch is sell.",bias:"Pair with trend and volume confirmation."},keltner:{name:"Keltner Channel",what:"EMA center with ATR-based envelopes.",purpose:"Trend-aware volatility channel.",apply:"Break/hold beyond band can mark trend strength.",mistake:"Using fixed ATR multiplier everywhere.",bias:"Tune per asset volatility."},atr:{name:"ATR",what:"Average true range.",purpose:"Position sizing and stop calibration.",apply:"Use ATR multiples for stops/targets.",mistake:"Using fixed pip stops in all regimes.",bias:"Normalize risk by volatility."},donchian:{name:"Donchian Channels",what:"Highest high / lowest low bands.",purpose:"Breakout systems.",apply:"Use channel breaks with trend filter.",mistake:"Ignoring false breakout environment.",bias:"Wait for close confirmation."},stdev:{name:"Standard Deviation",what:"Dispersion of price from mean.",purpose:"Volatility regime shifts.",apply:"Expand risk controls during high dispersion.",mistake:"Mistaking volatility for direction.",bias:"Separate volatility from trend."},adx:{name:"ADX",what:"Trend strength metric independent of direction.",purpose:"Regime filter.",apply:"Use +DI/-DI with ADX slope.",mistake:"Trading direction off ADX alone.",bias:"Combine with directional structure."},aroon:{name:"Aroon",what:"Time since highs/lows.",purpose:"Trend emergence detection.",apply:"Aroon up/down crosses near extremes can flag regime shifts.",mistake:"Using in high-noise micro ranges.",bias:"Require multi-candle confirmation."},pivots:{name:"Pivot Points",what:"Session-based support/resistance levels.",purpose:"Map likely reaction zones.",apply:"Use confluence with order flow and trend.",mistake:"Treating pivots as guaranteed reversal levels.",bias:"Plan invalidation before entry."},sar:{name:"Parabolic SAR",what:"Trailing stop indicator with acceleration factor.",purpose:"Trend trailing and stop logic.",apply:"Works best in persistent trends.",mistake:"Using in sideways chop.",bias:"Filter with ADX or structure."},supertrend:{name:"Supertrend",what:"ATR-based trend-following overlay.",purpose:"Trend direction and trailing stop.",apply:"Follow flips when volatility supports continuation.",mistake:"Chasing every flip in range.",bias:"Use higher timeframe confirmation."},vortex:{name:"Vortex",what:"Positive/negative trend movement lines.",purpose:"Trend turning points.",apply:"Crosses with expansion can mark trend shifts.",mistake:"Ignoring low-liquidity noise.",bias:"Confirm with volume and structure."},elderRay:{name:"Elder Ray",what:"Bull/Bear power versus EMA baseline.",purpose:"Pressure around trend mean.",apply:"Look for divergence and trend continuation.",mistake:"Using without baseline trend direction.",bias:"Anchor decisions to trend context."}},mi={sma20:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#f1c40f"}],ema20:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#ffb86c"}],wma20:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#bd93f9"}],vwap:[{id:"color",label:"Color",type:"color",default:"#80ffea"}],bb20:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Band Color",type:"color",default:"#ff79c6"}],ichimoku:[{id:"tenkanLen",label:"Tenkan Length",type:"number",default:9},{id:"kijunLen",label:"Kijun Length",type:"number",default:26},{id:"senkouBLen",label:"Senkou B Length",type:"number",default:52},{id:"tenkanColor",label:"Tenkan Color",type:"color",default:"#ffde59"},{id:"kijunColor",label:"Kijun Color",type:"color",default:"#6ecbff"},{id:"bullColor",label:"Cloud Bull Color",type:"color",default:"#46ffa0"},{id:"bearColor",label:"Cloud Bear Color",type:"color",default:"#ff7878"}],donchian:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#9cfb8c"}],keltner:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#7ee7ff"}],supertrend:[{id:"color",label:"Color",type:"color",default:"#8bffde"}],sar:[{id:"color",label:"Color",type:"color",default:"#ffaf7a"}],elderRay:[{id:"bullColor",label:"Bull Color",type:"color",default:"#5fff9d"},{id:"bearColor",label:"Bear Color",type:"color",default:"#ff9d9d"}],rsi:[{id:"length",label:"Length",type:"number",default:14},{id:"color",label:"Color",type:"color",default:"#a6ff4d"}],atr:[{id:"length",label:"Length",type:"number",default:14},{id:"color",label:"Color",type:"color",default:"#ffb86c"}],stdev:[{id:"color",label:"Color",type:"color",default:"#b2a3ff"}],stoch:[{id:"length",label:"Length",type:"number",default:14},{id:"kColor",label:"%K Color",type:"color",default:"#9ee8ff"},{id:"dColor",label:"%D Color",type:"color",default:"#ffd86b"}],macd:[{id:"fastLen",label:"Fast Length",type:"number",default:12},{id:"slowLen",label:"Slow Length",type:"number",default:26},{id:"signalLen",label:"Signal Length",type:"number",default:9},{id:"lineColor",label:"MACD Color",type:"color",default:"#8fd9ff"},{id:"signalColor",label:"Signal Color",type:"color",default:"#ffcf8e"}],obv:[{id:"color",label:"Color",type:"color",default:"#8cf9ff"}],adline:[{id:"color",label:"Color",type:"color",default:"#ffb7ff"}],cmf:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#f8ff87"}],williamsr:[{id:"length",label:"Length",type:"number",default:14},{id:"color",label:"Color",type:"color",default:"#ff9adf"}],cci:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#b8ff8e"}],mfi:[{id:"length",label:"Length",type:"number",default:14},{id:"color",label:"Color",type:"color",default:"#7bffd2"}],uo:[{id:"color",label:"Color",type:"color",default:"#ffd36f"}],adx:[{id:"length",label:"Length",type:"number",default:14},{id:"adxColor",label:"ADX Color",type:"color",default:"#9fd8ff"},{id:"plusColor",label:"+DI Color",type:"color",default:"#73ffc0"},{id:"minusColor",label:"-DI Color",type:"color",default:"#ff9797"}],aroon:[{id:"length",label:"Length",type:"number",default:14},{id:"upColor",label:"Up Color",type:"color",default:"#6cffb0"},{id:"downColor",label:"Down Color",type:"color",default:"#ff8f8f"}],vortex:[{id:"length",label:"Length",type:"number",default:14},{id:"plusColor",label:"VI+ Color",type:"color",default:"#d6a8ff"},{id:"minusColor",label:"VI- Color",type:"color",default:"#ffb0f3"}]},bv={sma20:{creator:"Early quantitative analysts (1900s tape reading era)",era:"Formalized in the early 20th century",math:"Arithmetic mean of the last N closes.",context:"Designed to smooth noisy tape data for trend direction visibility.",regime:"Best in directional trends, weaker in mean-reverting chop."},ema20:{creator:"Modern technical analysts adapting exponential smoothing",era:"Popularized in 1960s-1980s",math:"Recursive weighted mean with alpha = 2/(N+1).",context:"Improves responsiveness versus SMA while preserving trend structure.",regime:"Useful for pullback entries in trending environments."},ichimoku:{creator:"Goichi Hosoda",era:"Developed pre-WW2, published 1969",math:"Median-price lines (9/26/52) plus shifted cloud projections.",context:"Built as a full market regime system: trend, momentum, support/resistance in one frame.",regime:"Most reliable when cloud slope and price acceptance align."},macd:{creator:"Gerald Appel",era:"Late 1970s",math:"MACD = EMA(12)-EMA(26), signal=EMA(9) of MACD, histogram=spread.",context:"Tracks trend acceleration/deceleration, not just direction.",regime:"Strong in trend transitions, noisy in low-volatility ranges."},rsi:{creator:"J. Welles Wilder Jr.",era:"1978",math:"RSI = 100 - 100/(1+RS), RS = avg gain / avg loss.",context:"Measures internal momentum pressure rather than price level alone.",regime:"Range shifts (bull/bear RSI zones) matter more than static 30/70."},adx:{creator:"J. Welles Wilder Jr.",era:"1978",math:"Smoothed directional movement (+DI/-DI) transformed into trend-strength index.",context:"Separates trend strength from trend direction.",regime:"Filter trades: momentum systems improve when ADX slope rises."},aroon:{creator:"Tushar Chande",era:"1995",math:"Time since recent high/low scaled to 0-100.",context:"Focuses on trend freshness instead of pure magnitude.",regime:"Good at identifying emergent trend phases and late-trend fatigue."},cci:{creator:"Donald Lambert",era:"1980",math:"Deviation of typical price from moving average normalized by mean deviation.",context:"Originally commodity cycle tool for identifying statistical extremes.",regime:"Works better with volatility-aware thresholds than fixed +/-100."},williamsr:{creator:"Larry Williams",era:"1970s",math:"Position of close within rolling high-low range, scaled negative.",context:"Fast oscillator for short-horizon exhaustion and reversion timing.",regime:"Most effective in bounded ranges; trend filters prevent fade traps."},mfi:{creator:"Gene Quong and Avrum Soudack",era:"1989",math:"RSI-style transform using typical price * volume money flow.",context:"Adds participation/volume dimension to momentum analysis.",regime:"Useful where volume quality is high; weaker on fragmented liquidity."},obv:{creator:"Joseph Granville",era:"1963",math:"Cumulative signed volume based on close direction.",context:"Detects accumulation/distribution before obvious price moves.",regime:"Best when confirmed with structure breaks and volume regime shifts."},vwap:{creator:"Institutional execution desks",era:"1980s electronic execution era",math:"Cumulative price*volume divided by cumulative volume.",context:"Execution benchmark and intraday fair-value reference.",regime:"Most meaningful intraday and around session anchor resets."},bb20:{creator:"John Bollinger",era:"1980s",math:"SMA +/- k * standard deviation.",context:"Captures volatility contraction/expansion around a mean.",regime:"Band walks imply trend persistence; squeezes imply potential expansion."},atr:{creator:"J. Welles Wilder Jr.",era:"1978",math:"Smoothed average of true range components.",context:"Volatility unit for risk sizing and adaptive stops.",regime:"Risk engine input rather than directional signal."},donchian:{creator:"Richard Donchian",era:"1940s-1950s",math:"Rolling highest-high and lowest-low channels.",context:"Classic breakout trend-following framework.",regime:"Performs in sustained directional moves, whipsaws in compression."},supertrend:{creator:"Olivier Seban",era:"2009",math:"ATR envelope with trend-state switching logic.",context:"Simplifies trend-following and stop-trailing into one overlay.",regime:"Good in clean trends; combine with structure/ADX in chop."},vortex:{creator:"Etienne Botes and Douglas Siepman",era:"2010",math:"Normalized positive/negative movement vectors over rolling true range.",context:"Detects trend emergence and directional dominance shifts.",regime:"Improves when paired with volatility and liquidity filters."}},yv={hline:"Horizontal levels represent reaction zones. Respect zone width and liquidity sweeps."},wv=[{label:"XRP/USD (Bitstamp)",asset:{currency:"XRP"},asset2:{currency:"USD",issuer:"rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq"}},{label:"XRP/EUR (Bitstamp)",asset:{currency:"XRP"},asset2:{currency:"EUR",issuer:"rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq"}},{label:"XRP/USDC (Gatehub)",asset:{currency:"XRP"},asset2:{currency:"USDC",issuer:"rKveEyR1SrkWbJX214xcfH43ZsoGMb3PEv"}}],Hc="wallets",Tn=null,rn={},ts="",ft=1,we={algo:"ed25519",label:"",emoji:"\u{1F48E}",color:"#50fa7b",seed:"",address:"",passphrase:""},Cn=new Set,vc=60,xv={wallet_created:"\u{1F48E}",wallet_removed:"\u{1F5D1}",social_connected:"\u{1F517}",social_removed:"\u2715",profile_saved:"\u270F\uFE0F",trustline_added:"\u{1F517}",sent:"\u2B06",received:"\u2B07",vault_created:"\u{1F510}",backup_exported:"\u{1F4C2}",theme_changed:"\u{1F3A8}",wallet_imported:"\u{1F511}",watch_added:"\u{1F441}"};function zc(){ti(),oy(),Tv(),C.threeEnabled=Z(ui)!=="0",kv(),Ea().catch(()=>{be("Could not preload xrpl.js. Wallet generation/signing will require network access when used.")}),q(),ei("wallets"),Et(),uy(),Sv(),Ma()&&ns({silent:!0}),window.addEventListener("naluxrp:pagechange",e=>{var t;((t=e==null?void 0:e.detail)==null?void 0:t.pageId)==="profile"?ns({silent:!0}):He.raf&&Fs()}),document.addEventListener("click",e=>{var s;let t=document.querySelector(".xpd-indicator-menu-wrap");t&&!t.contains(e.target)&&C.indicatorMenuOpen&&(C.indicatorMenuOpen=!1,q());let n=document.querySelector(".xpd-more-menu-wrap");if(n&&!n.contains(e.target)&&C.moreMenuOpen&&(C.moreMenuOpen=!1,q()),C.settingsOpenFor){let a=(s=document.querySelector(".xpd-indicator-settings"))==null?void 0:s.closest(".xpd-indicator-chip-wrap");a&&!a.contains(e.target)&&(C.settingsOpenFor=null,q())}}),window.addEventListener("naluxrp:vault-ready",()=>{ti(),q(),ei(Hc),Et(),Kb(),ns({silent:!0,force:!0})}),window.addEventListener("naluxrp:vault-locked",()=>{q(),ns({silent:!0,force:!0})}),document.addEventListener("visibilitychange",()=>{if(Ma()&&!document.hidden&&oe.length){let e=oe.filter(t=>{let n=Ve[t.address];return!n||Date.now()-n.fetchedAt>3e5});e.length&&Promise.all(e.map(t=>Pn(t.address))).then(()=>{at(),Et()})}})}function kv(){let e=new URLSearchParams(window.location.search),t=e.get("pair")||"",n=e.get("tf")||"",s=e.get("token")||Z(Fc)||"",a=e.get("ind")||"";if(t&&Mn.some(o=>o.id===t)&&(C.pair=t),n&&Oc.some(o=>o.value===n)&&(C.interval=n),a){let o=new Set(a.split(",").map(i=>i.trim()).filter(Boolean));Object.keys(C.indicators).forEach(i=>{C.indicators[i]=o.has(i)})}s&&(C.tokenFocusKey=s,j.selectedTokenKey=s)}function $t(){let e=new URLSearchParams(window.location.search);e.set("pair",C.pair||"BITSTAMP:XRPUSD"),e.set("tf",C.interval||"15"),C.tokenFocusKey?e.set("token",C.tokenFocusKey):e.delete("token");let t=Object.entries(C.indicators).filter(([,s])=>!!s).map(([s])=>s).join(",");t?e.set("ind",t):e.delete("ind");let n=`${window.location.pathname}?${e.toString()}${window.location.hash||""}`;window.history.replaceState(null,"",n),C.tokenFocusKey&&te(Fc,C.tokenFocusKey)}function $v(){let e=document.getElementById("xpd-chart-section");e&&e.scrollIntoView({behavior:"smooth",block:"start"})}function Sv(){fc||(fc=!0,window.addEventListener("xrpl-ledger",()=>{let e=Date.now();e-hc<5e3||(hc=e,O.currentPage==="profile"&&document.querySelector("#profile-page .profile-wrap .xrpl-profile-dashboard")&&nd().then(()=>{if(Date.now()-_c>15e3)return;let n=document.activeElement;n&&/^(INPUT|TEXTAREA|SELECT)$/.test(n.tagName)||C.moreMenuOpen||C.indicatorMenuOpen||(As.clear(),q())}).catch(()=>{}))}))}function fi(e){Hc=e,Ie(".ptab-btn").forEach(t=>t.classList.toggle("active",t.dataset.tab===e)),ei(e)}function ei(e){try{switch(e){case"wallets":at();break;case"social":Fa();break;case"activity":$p();break;case"settings":zt();break;case"analytics":Lp();break;case"security":Ub();break}}catch(t){let n=y(`profile-tab-${e}`);n&&Uc(n,e,t),console.error(`Profile tab "${e}" error:`,t)}["wallets","social","activity","settings","analytics","security"].forEach(t=>{let n=y(`profile-tab-${t}`);n&&(n.style.display=t===e?"":"none")})}function Uc(e,t,n){e.innerHTML=`<div class="tab-error-card">
    <div class="tab-error-icon">\u26A0\uFE0F</div>
    <div class="tab-error-title">Something went wrong</div>
    <div class="tab-error-sub">${g((n==null?void 0:n.message)||"Unknown error")}</div>
    <button class="tab-error-btn" onclick="switchProfileTab('${t}')">Try Again</button>
  </div>`}function Tv(){document.addEventListener("keydown",e=>{if(e.key==="Escape")for(let t of["profile-editor-modal","wallet-creator-overlay","social-modal","send-modal-overlay","receive-modal-overlay","trustline-modal-overlay","import-address-modal","import-seed-modal","token-details-modal","pub-profile-overlay"]){let n=y(t)||document.getElementById(t);if(n!=null&&n.classList.contains("show")||(n==null?void 0:n.style.display)==="flex"){n.classList.remove("show"),n.style.display==="flex"&&(n.style.display="none");return}}e.key==="k"&&(e.ctrlKey||e.metaKey)&&(e.preventDefault(),$i())})}function ti(){var t,n;let e=ve(Z(Lc));e&&Object.assign(le,e),ze=ve(Z(Mc))||{},oe=ve(Z(Cc))||[],Nc=ve(Z(Jg))||{},C.alerts=ve(Z(Bc))||[],st=Z(Es)||((t=oe[0])==null?void 0:t.id)||null,!le.displayName&&((n=O.session)!=null&&n.name)&&(le.displayName=O.session.name,le.handle=O.session.name.toLowerCase().replace(/\s+/g,"_"),Wc())}function Wc(){te(Lc,JSON.stringify(le))}function _s(){te(Cc,JSON.stringify(oe))}function jc(){te(Mc,JSON.stringify(ze))}function hi(){te(Bc,JSON.stringify(C.alerts||[]))}function gt(e,t){let n=ve(Z(Jo))||[];n.unshift({type:e,detail:t,ts:Date.now()}),n.length>vc&&(n.length=vc),te(Jo,JSON.stringify(n))}function Cv(){return ve(Z(Jo))||[]}function qc(e){let t=(Date.now()-e)/1e3;return t<60?"just now":t<3600?`${Math.floor(t/60)}m ago`:t<86400?`${Math.floor(t/3600)}h ago`:`${Math.floor(t/86400)}d ago`}function St(){return oe.find(e=>e.id===st)||oe[0]||null}function Vc(e){oe.find(t=>t.id===e)&&(st=e,te(Es,e),at(),Et(),window.dispatchEvent(new CustomEvent("naluxrp:active-wallet-changed",{detail:St()})),ne("Active wallet switched"))}window.addEventListener("naluxrp:active-wallet-changed",e=>{let t=e.detail;if(!t)return;let n=y("inspect-addr");n&&!n.value&&(n.value=t.address),O.activeWalletAddress=t.address});function Et(){var o;let e=y("active-wallet-bar");if(!e)return;let t=St();if(!t){e.innerHTML='<div class="awb-empty">No wallet \u2014 <button class="awb-link" onclick="openWalletCreator()">create one</button></div>';return}let n=Ve[t.address],s=n?D(n.xrp,2)+" XRP":"\u2014 XRP",a=(o=n==null?void 0:n.tokens)!=null&&o.length?`\xB7 ${n.tokens.length} token${n.tokens.length>1?"s":""}`:"";e.innerHTML=`
    <div class="awb-left">
      <div class="awb-icon" style="background:${t.color}22;border-color:${t.color}55;color:${t.color}">${g(t.emoji)}</div>
      <div class="awb-info">
        <span class="awb-label">${g(t.label)}</span>
        <span class="awb-address mono">${g(t.address)}</span>
      </div>
      <span class="awb-balance">${s} ${a}</span>
    </div>
    <div class="awb-actions">
      <button class="awb-btn awb-btn--send"    onclick="openSendModal('${t.id}')">\u2B06 Send</button>
      <button class="awb-btn awb-btn--receive" onclick="openReceiveModal('${t.id}')">\u2B07 Receive</button>
      <button class="awb-btn awb-btn--trust"   onclick="openTrustlineModal('${t.id}')">\u{1F517} Trustlines</button>
      <button class="awb-btn awb-btn--inspect" onclick="inspectWalletAddr('${g(t.address)}')">\u{1F50D} Inspect</button>
    </div>`}function q(){var w,k;let e=document.querySelector("#profile-page .profile-wrap");if(!e)return;let t=document.getElementById("xpd-tv-widget"),n=!!(t&&ee.chart);t&&t.remove();let s=document.getElementById("xpd-chart-atmosphere"),a=!!(s&&He.renderer);s&&s.remove();let o=St(),i=(o==null?void 0:o.address)||"",r=Lv(),l=localStorage.getItem(ln),c=oe.some(b=>!b.watchOnly),d=Z(Qo)==="1",u=(w=Ve[i])==null?void 0:w.xrp,p=Object.values(Ve).reduce((b,x)=>b+((x==null?void 0:x.xrp)||0),0),m=(k=Te.data)!=null&&k.priceUsd?p*Te.data.priceUsd:0,f=Mn.map(b=>`<option value="${g(b.id)}" ${C.pair===b.id?"selected":""}>${g(b.label)}</option>`).join(""),v=Mn.map(b=>`<option value="${g(b.id)}" ${C.comparePair===b.id?"selected":""}>${g(b.label)}</option>`).join(""),h=Oc.map(b=>`<option value="${g(b.value)}" ${C.interval===b.value?"selected":""}>${g(b.label)}</option>`).join("");if(e.innerHTML=`
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
        </div>
      </header>

      <div class="xpd-layout-grid">
        <aside class="xpd-profile-card" aria-label="Profile identity">
          <div class="xpd-profile-top">
            <div class="xpd-avatar-shell" title="${g(le.displayName||"Anonymous")}" onclick="openProfileEditor()">
              ${l?`<img src="${l}" alt="Profile avatar" class="xpd-avatar-img" />`:`<span class="xpd-avatar-fallback">${g(le.avatar||(o==null?void 0:o.emoji)||"\u{1F30A}")}</span>`}
            </div>
            <div class="xpd-profile-meta">
              <h2 class="xpd-display-name">${g(le.displayName||"Anonymous")}</h2>
              <p class="xpd-bio">${g(le.bio||"No bio set. Click edit profile to add one.")}</p>
              <button class="xpd-action" onclick="openProfileEditor()">Edit profile</button>
            </div>
          </div>
          <div class="xpd-profile-list">
            <div class="xpd-item-row">
              <span class="xpd-item-label">Wallet</span>
              <div class="xpd-wallet-inline">
                ${i?`<span class="mono xpd-wallet-chip" title="${g(i)}">${i}</span><button class="xpd-mini-btn" onclick="copyToClipboard('${g(i)}')">Copy</button>`:'<span class="xpd-empty">No wallet selected</span>'}
              </div>
            </div>
            <div class="xpd-item-row">
              <span class="xpd-item-label">XRP Balance</span>
              <span class="xpd-item-value">${Number.isFinite(u)?`${D(u,4)} XRP`:"\u2014"}</span>
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
              <strong>${D(p,4)}</strong>
            </div>
            <div class="xpd-sidebar-snapshot-row">
              <span>Est. USD</span>
              <strong>${m?`$${D(m,2)}`:"\u2014"}</strong>
            </div>
            <div class="xpd-sidebar-snapshot-row">
              <span>Wallets</span>
              <strong>${oe.length}</strong>
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
                  <select class="xpd-input" onchange="setDexInterval(this.value)">${h}</select>
                  <select class="xpd-input" onchange="setDexChartType(this.value)">
                    <option value="candles" ${C.chartType==="candles"?"selected":""}>Candlestick</option>
                    <option value="line" ${C.chartType==="line"?"selected":""}>Line</option>
                    <option value="area" ${C.chartType==="area"?"selected":""}>Area</option>
                    <option value="bars" ${C.chartType==="bars"?"selected":""}>Bar</option>
                    <option value="heikin_ashi" ${C.chartType==="heikin_ashi"?"selected":""}>Heikin Ashi</option>
                    <option value="hollow_candles" ${C.chartType==="hollow_candles"?"selected":""}>Hollow Candle</option>
                  </select>
                  <select class="xpd-input" onchange="setComparePair(this.value)">
                    <option value="" ${C.comparePair?"":"selected"}>No Compare</option>
                    ${v}
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
                    ${Xc.map(b=>`<option value="${b.key}" ${C.drawingTool===b.key?"selected":""}>Draw: ${b.label}</option>`).join("")}
                  </select>
                  <button class="xpd-action xpd-action--icon" onclick="clearAllDrawings()" title="Clear Lines" aria-label="Clear Lines">\u{1F9F9}</button>
                  <button class="xpd-action xpd-action--icon" onclick="addPriceAlert()" title="Set Price Alert" aria-label="Set Price Alert">\u{1F514}</button>
                  ${Mv()}
                  <button class="xpd-action xpd-action--icon" onclick="exportChartPng()" title="Export PNG" aria-label="Export PNG">\u{1F5BC}\uFE0F</button>
                  <button class="xpd-action xpd-action--icon" onclick="copyChartLink()" title="Copy Chart Link" aria-label="Copy Chart Link">\u{1F517}</button>
                </div>
                <div class="xpd-toolbar-group xpd-more-menu-wrap">
                  <button class="xpd-action xpd-action--icon" onclick="event.stopPropagation(); toggleChartMoreMenu()" title="More settings" aria-label="More settings">\u22EF</button>
                  ${C.moreMenuOpen?`
                    <div class="xpd-more-menu" role="menu" aria-label="Chart preferences">
                      <button class="xpd-more-menu-item" onclick="toggleThreeEffects()"><span class="xai">\u{1F9CA}</span>${C.threeEnabled?"3D Background: On":"3D Background: Off"}</button>
                      <button class="xpd-more-menu-item" onclick="toggleTerminalTheme()"><span class="xai">\u{1F313}</span>Toggle Theme</button>
                      <button class="xpd-more-menu-item" onclick="saveChartLayoutPreset()"><span class="xai">\u{1F4BE}</span>Save Layout</button>
                      <button class="xpd-more-menu-item" onclick="loadChartLayoutPreset()"><span class="xai">\u{1F4C2}</span>Load Layout</button>
                    </div>
                  `:""}
                </div>
              </div>
            </div>
            ${Pv()}
          </section>

          <section class="xpd-section" aria-label="XRPL market data">
            <div class="xpd-section-head">
              <h2>XRPL Market Data</h2>
              <button class="xpd-action" onclick="refreshMarketData()"><span class="xai">\u27F3</span>Refresh market</button>
            </div>
            ${Ev()}
          </section>
        </div>
      </div>

      ${Av()}

      <section class="xpd-section" aria-label="Token discovery and watchlist">
        <div class="xpd-section-head">
          <h2>Token Discovery and Watchlists</h2>
          <button class="xpd-action" onclick="refreshTokenDiscovery()"><span class="xai">\u27F3</span>Refresh tokens</button>
        </div>
        ${Iv()}
      </section>

      <div class="xpd-dual-grid">
        <section class="xpd-section" aria-label="NFT gallery">
          <div class="xpd-section-head">
            <h2>NFT Gallery</h2>
            <button class="xpd-action" onclick="refreshNftGallery()"><span class="xai">\u27F3</span>Refresh NFTs</button>
          </div>
          ${Nv(i)}
        </section>

        <section class="xpd-section" aria-label="AMM pools and DEX liquidity">
          <div class="xpd-section-head">
            <h2>AMM, DEX, and Liquidity Pools</h2>
            <button class="xpd-action" onclick="refreshAmmPools()"><span class="xai">\u27F3</span>Refresh pools</button>
          </div>
          ${Rv(i)}
        </section>
      </div>

      <section class="xpd-section" aria-label="Portfolio and recent transactions">
        <div class="xpd-section-head">
          <h2>Portfolio and Recent Transactions</h2>
          <button class="xpd-action" onclick="refreshRecentTransactions()"><span class="xai">\u27F3</span>Refresh tx</button>
        </div>
        ${Fv(i)}
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
    </div>`,n){let b=document.getElementById("xpd-tv-widget");b&&b.replaceWith(t)}if(a){let b=document.getElementById("xpd-chart-atmosphere");b&&b.replaceWith(s)}Tb(),$p(),Lp(),Fa(),zt()}function Lv(){let e=String(O.currentNetwork||"").toLowerCase();return e.includes("testnet")?{label:"XRPL Testnet",kind:"testnet"}:e.includes("mainnet")?{label:"XRPL Mainnet",kind:"mainnet"}:e.includes("xahau")?{label:"Xahau Network",kind:"xahau"}:{label:`Network: ${g(O.currentNetwork||"Unknown")}`,kind:"unknown"}}function Mv(){let e=String(C.indicatorQuery||"").trim().toLowerCase(),t=[{key:"trend",label:"Trend",icon:"\u{1F4C8}"},{key:"momentum",label:"Momentum",icon:"\u26A1"},{key:"volume",label:"Volume",icon:"\u{1F4CA}"},{key:"volatility",label:"Volatility",icon:"\u{1F32A}\uFE0F"},{key:"advanced",label:"Custom",icon:"\u{1F9E0}"}];return`
    <div class="xpd-indicator-menu-wrap">
      <button class="xpd-action xpd-action--add" onclick="event.stopPropagation(); toggleIndicatorMenu()">+ Indicator</button>
      ${C.indicatorMenuOpen?`
        <div class="xpd-indicator-menu" role="menu" aria-label="Indicator menu">
          <input class="xpd-input xpd-indicator-search" placeholder="Search indicators..." value="${g(C.indicatorQuery||"")}" oninput="setIndicatorQuery(this.value)" />
          ${t.map(n=>{let s=(vv[n.key]||[]).filter(a=>{var i;return e?(((i=Ht[a])==null?void 0:i.name)||a).toLowerCase().includes(e):!0});return s.length?`
              <details class="xpd-indicator-group" open>
                <summary>${n.icon} ${n.label}</summary>
                <div class="xpd-indicator-items">
                  ${s.map(a=>{var o,i;return`<button class="xpd-indicator-item" title="${g(((o=Ht[a])==null?void 0:o.what)||"")}" onclick="addIndicatorFromMenu('${a}')">${g(((i=Ht[a])==null?void 0:i.name)||a)}</button>`}).join("")}
                </div>
              </details>`:""}).join("")}
        </div>
      `:""}
    </div>`}function Pv(){var m;let e=C.stats,t=((m=O.wsConn)==null?void 0:m.readyState)===1,n=C.chartMeta||{},s=Object.entries(C.indicators).filter(([,f])=>!!f).map(([f])=>f),a=String(C.tokenFocusKey||""),o=a.includes("|")?a.split("|")[0]:a,i=j.tokens.find(f=>ht(f)===a)||j.tokens.find(f=>String(f.symbol||"").toUpperCase()===String(o||"").toUpperCase())||null,r=!!i&&String(i.symbol||"").toUpperCase()!=="XRP"&&Number.isFinite(Number(i.price||0)),l=Number.isFinite(Number(n.last))?Number(n.last):r?Number(i.price||0):e==null?void 0:e.price,c=Number.isFinite(Number(n.high))?Number(n.high):e==null?void 0:e.high,d=Number.isFinite(Number(n.low))?Number(n.low):e==null?void 0:e.low,u=i?`${String(i.symbol||"").toUpperCase()}${i.issuer?` \xB7 ${i.issuer.slice(0,10)}...`:""}`:String(n.symbol||"XRP").toUpperCase(),p=String(n.source||(r?"Coinbase + token proxy":(e==null?void 0:e.source)||"Source pending"));return`
    ${C.error?`<div class="xpd-error">${g(C.error)}</div>`:""}
    <div class="xpd-chart-stats">
      <div class="xpd-pill" title="Current price">${l!=null?`$${D(l,r?6:4)}`:"Price \u2014"}</div>
      <div class="xpd-pill" title="24h change">${(e==null?void 0:e.changePct)!=null?`${e.changePct>=0?"+":""}${D(e.changePct,2)}%`:"24h \u2014"}</div>
      <div class="xpd-pill" title="24h high">${c!=null?`High $${D(c,r?6:4)}`:"High \u2014"}</div>
      <div class="xpd-pill" title="24h low">${d!=null?`Low $${D(d,r?6:4)}`:"Low \u2014"}</div>
      <div class="xpd-pill" title="XRPL orderbook spot">${r?`Token Spot $${D(Number((i==null?void 0:i.price)||0),6)}`:(e==null?void 0:e.xrplSpot)!=null?`XRPL Spot $${D(e.xrplSpot,4)}`:"XRPL Spot \u2014"}</div>
      <div class="xpd-pill" title="Chart source">${g(p)}</div>
      <div class="xpd-pill" title="Streaming status">${t?"\u25CF Live stream connected":"\u25CF Stream offline"}</div>
      ${i?`<div class="xpd-pill" title="Token focus">Token Focus: ${g(i.symbol)} ${i.price!=null?`($${D(i.price,6)})`:""}</div>`:""}
    </div>
    <div class="xpd-indicator-row">
      ${s.length?s.map(f=>{var v,h;return`<div class="xpd-indicator-chip-wrap"><div class="xpd-indicator-chip" title="${g(((v=Ht[f])==null?void 0:v.what)||"")}"><span>${g(((h=Ht[f])==null?void 0:h.name)||f)}</span><button class="xpd-mini-btn" onclick="event.stopPropagation(); openIndicatorSettings('${f}')">\u2699</button><button class="xpd-mini-btn" onclick="removeIndicator('${f}')">\u2715</button></div>${Cb(f)}</div>`}).join(""):'<span class="xpd-empty">No indicators enabled. Use + Indicator.</span>'}
    </div>
    ${(()=>{let f=_a(),v=(C.alerts||[]).filter(h=>h.tokenKey===f);return v.length?`
      <div class="xpd-indicator-row">
        ${v.map(h=>`
          <div class="xpd-indicator-chip" data-alert-id="${g(h.id)}" title="Notify when price crosses $${D(h.price,6)}">
            <span>\u{1F514} $${D(h.price,6)}</span>
            <button class="xpd-mini-btn" onclick="removePriceAlert('${h.id}')">\u2715</button>
          </div>`).join("")}
      </div>`:""})()}
    ${C.educationHint?`<div class="xpd-note">${g(C.educationHint)}</div>`:""}
    <div class="xpd-chart-wrap">
      <div class="xpd-chart-active-head">
        <div class="xpd-chart-active-left">
          <span class="xpd-chart-active-label">Active Chart Token</span>
          <strong class="xpd-chart-active-token" title="${g(u)}">${g(u)}</strong>
        </div>
        <div class="xpd-chart-active-right">
          <span class="xpd-chart-active-chip">Mode: ${g(n.mode||"pair")}</span>
          <span class="xpd-chart-active-chip" title="${g(p)}">Source: ${g(p)}</span>
        </div>
      </div>
      <div id="xpd-chart-atmosphere" class="xpd-chart-atmosphere" aria-hidden="true"></div>
      <div id="xpd-tv-widget" class="xpd-tv-widget"></div>
    </div>
    <p class="xpd-note">Professional chart controls: wheel zoom, hold-and-drag pan, horizontal price-line marking, and token-focused context ribbons for faster execution decisions.</p>`}function Av(){let e=C.selectedIndicator||"sma20",t=Ht[e]||Ht.sma20,n=bv[e]||null,s=C.educationCollapsed;return`
    <div class="xpd-edu-panel ${s?"collapsed":""}">
      <div class="xpd-edu-head">
        <h3>Indicator Intelligence and Bias Control</h3>
        <button class="xpd-mini-btn" onclick="toggleEducationPanel()">${s?"Expand":"Collapse"}</button>
      </div>
      ${s?"":`
        <div class="xpd-edu-tabs">
          <button class="xpd-mini-btn ${C.selectedEducationTab==="indicator"?"active":""}" onclick="selectEducationTab('indicator')">Indicator Guide</button>
          <button class="xpd-mini-btn ${C.selectedEducationTab==="psychology"?"active":""}" onclick="selectEducationTab('psychology')">Trading Psychology</button>
          <button class="xpd-mini-btn ${C.selectedEducationTab==="practice"?"active":""}" onclick="selectEducationTab('practice')">Best Practices</button>
        </div>
        ${C.selectedEducationTab==="indicator"?`
          <div class="xpd-edu-content">
            <h4 class="xpd-edu-title">${g(t.name)}</h4>
            ${nt("What it measures",t.what)}
            ${nt("Original purpose",t.purpose)}
            ${nt("How to apply",t.apply)}
            ${nt("Common mistake",t.mistake)}
            ${nt("Bias reduction tip",t.bias)}
            ${n?`
              ${nt("Created by / Era",`${n.creator} \xB7 ${n.era}`)}
              ${nt("Core math",n.math)}
              ${nt("Historical context",n.context)}
              ${nt("Best market regime",n.regime)}
            `:""}
          </div>
        `:""}
        ${C.selectedEducationTab==="psychology"?`
          <div class="xpd-edu-content">
            ${nt("Confirmation Bias","Require at least two independent signals before entering.")}
            ${nt("Anchoring","Do not anchor to entry price; respect invalidation and current structure.")}
            ${nt("Overfitting","More indicators is not better; build a repeatable checklist.")}
            ${nt("Risk Discipline","Position size by volatility and stop distance, not conviction.")}
          </div>
        `:""}
        ${C.selectedEducationTab==="practice"?`
          <ol class="xpd-edu-steps">
            <li>Start with trend context (higher timeframe).</li>
            <li>Add one momentum and one volatility indicator.</li>
            <li>Mark levels with drawings before taking a trade.</li>
            <li>Define entry, invalidation, and target before execution.</li>
            <li>Journal whether setup matched your rules.</li>
          </ol>
        `:""}
      `}
    </div>`}function nt(e,t){return`<div class="xpd-edu-row"><span class="xpd-edu-label">${g(e)}</span><span class="xpd-edu-value">${g(t)}</span></div>`}function Ev(){if(Te.loading)return'<div class="xpd-loading">Loading XRP market snapshot...</div>';if(Te.error)return`<div class="xpd-error">${g(Te.error)}</div>`;let e=Te.data;if(!e)return'<div class="xpd-empty">Market data is not available yet.</div>';let t=e.change24h>=0;return`
    <div class="xpd-market-grid">
      <article class="xpd-stat-card">
        <span class="xpd-stat-label">XRP Price</span>
        <strong class="xpd-stat-value">$${D(e.priceUsd,4)}</strong>
      </article>
      <article class="xpd-stat-card">
        <span class="xpd-stat-label">24h Change</span>
        <strong class="xpd-stat-value ${t?"up":"down"}">${t?"+":""}${D(e.change24h,2)}%</strong>
      </article>
      <article class="xpd-stat-card">
        <span class="xpd-stat-label">24h Volume</span>
        <strong class="xpd-stat-value">$${pt(e.volume24h)}</strong>
      </article>
      <article class="xpd-stat-card">
        <span class="xpd-stat-label">Market Cap</span>
        <strong class="xpd-stat-value">$${pt(e.marketCap)}</strong>
      </article>
    </div>
    <div class="xpd-token-strip">
      ${gv.map(n=>`<div class="xpd-token-pill" title="${g(`${n.symbol} ${n.name}`)}"><span class="sym xpd-pill-text">${n.symbol}</span><span class="xpd-pill-text">${g(n.name)}</span><span class="cap xpd-pill-text">${n.marketCap}</span></div>`).join("")}
    </div>
    <p class="xpd-note">Top XRPL token cards are static examples when direct DEX market-cap feeds are unavailable.</p>`}function Nv(e){return e?ut.loading?'<div class="xpd-loading">Loading account NFTs...</div>':ut.error?`<div class="xpd-error">${g(ut.error)}</div>`:ut.items.length?`<div class="xpd-nft-grid">${ut.items.map(_v).join("")}</div>`:'<div class="xpd-empty">No NFTs found for this wallet.</div>':'<div class="xpd-empty">Select or create a wallet to load NFTs.</div>'}function _v(e){let t=`${e.id.slice(0,12)}...${e.id.slice(-10)}`;return`<article class="xpd-nft-card">
    <div class="xpd-nft-media">
      ${e.image?`<img src="${g(e.image)}" alt="NFT ${g(t)}" loading="lazy" onerror="this.closest('.xpd-nft-media').innerHTML='<div class=&quot;xpd-nft-placeholder&quot;>NFT</div>'"/>`:'<div class="xpd-nft-placeholder">NFT</div>'}
    </div>
    <div class="xpd-nft-body">
      <div class="xpd-nft-id mono" title="${g(e.id)}">${g(t)}</div>
      <button class="xpd-action" onclick="sendNft('${g(e.id)}')">Send NFT</button>
    </div>
  </article>`}function Rv(e){let t=Bv(e),n=Ov(),s=Xv();return`<div class="xpd-amm-columns">${t}${n}${s}</div>`}function gi(){return(ve(Z(Ic))||[]).filter(Boolean)}function Gc(e){let t=[...new Set((e||[]).filter(Boolean))];te(Ic,JSON.stringify(t))}function Dv(e,t){return t.has(e)?t.get(e):j.tokens.find(s=>s.symbol===e)||null}function Iv(){let e=j.query||"",t=gi(),n=j.filtered.length?j.filtered:j.tokens,s=Math.max(120,Number(j.listLimit||240)),a=n.slice(0,s),o=j.trending.slice(0,14),i=new Map(j.tokens.map(c=>[ht(c),c])),r=i.get(j.selectedTokenKey)||null,l=j.filters||{type:"all",minCap:0,minVol:0,hasDex:!1};return`
    <div class="xpd-token-grid">
      <div class="xpd-token-col">
        <div class="xpd-search-row">
          <input class="xpd-input" list="xpd-token-suggest" placeholder="Search symbol, token, issuer" value="${g(e)}" oninput="searchTokens(this.value)" />
          <datalist id="xpd-token-suggest">${j.tokens.slice(0,80).map(c=>`<option value="${g(c.symbol)}">${g(c.name)}</option>`).join("")}</datalist>
          <div class="xpd-note">Loaded ${pt(j.total||n.length)} issued tokens \xB7 showing ${pt(a.length)} of ${pt(n.length)}${j.lastSyncAt?` \xB7 synced ${new Date(j.lastSyncAt).toLocaleTimeString()}`:""}</div>
          <div class="xpd-lookup-row" title="The search box above only finds tokens already in the loaded registry \u2014 use this to chart any XRPL issued currency directly by its currency code and issuer address.">
            <span class="xpd-lookup-label">Look up any issued asset</span>
            <div class="xpd-lookup-fields">
              <input id="xpd-lookup-currency" class="xpd-input" placeholder="Currency (e.g. SOLO)" maxlength="20" />
              <input id="xpd-lookup-issuer" class="xpd-input mono" placeholder="Issuer address (r...)" />
              <button class="xpd-action xpd-action--primary" onclick="lookupIssuedAsset()"><span class="xai">\u{1F50E}</span>Load</button>
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
        ${j.loading?'<div class="xpd-loading">Loading XRPL issued token registry...</div>':""}
        ${j.error?`<div class="xpd-error">${g(j.error)}</div>`:""}
        <div class="xpd-token-list">${a.map(c=>{let d=ht(c),u=encodeURIComponent(d),p=String(e||"").trim();return`
          <div class="xpd-token-row xpd-token-row--clickable" title="${g(`${c.symbol} ${c.name}`)}" onclick="openTokenOnChart(decodeURIComponent('${u}'))">
            <div class="xpd-token-main">
              <strong>${bc(c.symbol,p)}</strong>
              <span>${bc(c.name,p)}</span>
              ${c.issuer?`<span class="mono xpd-pill-text">${g(c.issuer)}</span>`:""}
            </div>
            <div class="xpd-token-actions">
              <span>${c.price!=null?`$${D(c.price,6)}`:"\u2014"}</span>
              ${Number.isFinite(c.holders)?`<span title="Holders">${pt(c.holders)} holders</span>`:""}
              <button class="xpd-mini-btn" onclick="event.stopPropagation(); addTokenToWatchlist(decodeURIComponent('${u}'))">Watch</button>
              <button class="xpd-mini-btn" onclick="event.stopPropagation(); openTokenOnChart(decodeURIComponent('${u}'))">Chart</button>
              <button class="xpd-mini-btn" onclick="event.stopPropagation(); selectTokenDetails(decodeURIComponent('${u}'))">Details</button>
            </div>
          </div>`}).join("")}</div>
      </div>
      <div class="xpd-token-col">
        ${r?`<div class="xpd-token-detail-card">
          <h3>${g(r.symbol)} \xB7 ${g(r.name)}</h3>
          <div class="pool-meta">Issuer: <span class="mono">${g(r.issuer||"Native XRP")}</span></div>
          <div class="pool-meta">Token ID: <span class="mono">${g(r.tokenId||"\u2014")}</span></div>
          <div class="pool-meta">Price: ${r.price!=null?`$${D(r.price,6)}`:"\u2014"} \xB7 24h Vol: ${r.volume24h!=null?`$${pt(r.volume24h)}`:"\u2014"}</div>
          <div class="pool-meta">Market Cap: ${r.marketCap!=null?`$${pt(r.marketCap)}`:"\u2014"} \xB7 Holders: ${r.holders!=null?pt(r.holders):"\u2014"}</div>
          <div class="xpd-row-actions">
            <button class="xpd-mini-btn" onclick="openTokenOnChart(decodeURIComponent('${encodeURIComponent(ht(r))}'))">Switch Main Chart</button>
            ${r.issuer?`<button class="xpd-mini-btn" onclick="window.open('https://xrpscan.com/account/${g(r.issuer)}','_blank')">View Issuer</button>`:""}
          </div>
        </div>`:""}
        <h3>Watchlist</h3>
        <div class="xpd-watchlist">${t.length?t.map(c=>{let d=Dv(c,i),u=d?`${d.symbol} \xB7 ${d.name}`:c,p=(d==null?void 0:d.price)!=null?`$${D(d.price,6)}`:"\u2014",m=encodeURIComponent(c);return`<div class="xpd-token-row xpd-token-row--clickable" onclick="openTokenOnChart(decodeURIComponent('${m}'))"><span>${g(u)}</span><div class="xpd-token-actions"><span>${p}</span><button class="xpd-mini-btn" onclick="event.stopPropagation(); openTokenOnChart(decodeURIComponent('${m}'))">Chart</button><button class="xpd-mini-btn" onclick="event.stopPropagation(); removeTokenFromWatchlist(decodeURIComponent('${m}'))">Remove</button></div></div>`}).join(""):'<div class="xpd-empty">No watchlist tokens yet.</div>'}</div>
        <h3>Trending</h3>
        <div class="xpd-watchlist">${o.length?o.map(c=>`<div class="xpd-token-row xpd-token-row--clickable" onclick="openTokenOnChart(decodeURIComponent('${encodeURIComponent(ht(c))}'))"><span>${g(c.symbol)} \xB7 ${g(c.name)}</span><span>${c.volume24h!=null?`$${pt(c.volume24h)} vol`:c.marketCap!=null?`$${pt(c.marketCap)} mcap`:"\u2014"}</span></div>`).join(""):'<div class="xpd-empty">No trending data.</div>'}</div>
      </div>
    </div>`}function bc(e,t){let n=String(e||""),s=String(t||"").trim();if(!s)return g(n);let a=n.toLowerCase().indexOf(s.toLowerCase());if(a<0)return g(n);let o=g(n.slice(0,a)),i=g(n.slice(a,a+s.length)),r=g(n.slice(a+s.length));return`${o}<mark class="xpd-hit">${i}</mark>${r}`}function Fv(e){var a,o;let t=Object.values(Ve).reduce((i,r)=>i+((r==null?void 0:r.xrp)||0),0),n=(a=Te.data)!=null&&a.priceUsd?t*Te.data.priceUsd:0,s=wt.items.slice(0,8);return`
    <div class="xpd-token-grid">
      <div class="xpd-token-col">
        <div class="xpd-market-grid">
          <article class="xpd-stat-card xpd-token-row--clickable" onclick="openTokenOnChart('XRP')"><span class="xpd-stat-label">Portfolio XRP</span><strong class="xpd-stat-value">${D(t,4)}</strong></article>
          <article class="xpd-stat-card"><span class="xpd-stat-label">Portfolio USD</span><strong class="xpd-stat-value">${n?`$${D(n,2)}`:"\u2014"}</strong></article>
          <article class="xpd-stat-card"><span class="xpd-stat-label">Wallets</span><strong class="xpd-stat-value">${oe.length}</strong></article>
          <article class="xpd-stat-card"><span class="xpd-stat-label">Network Stream</span><strong class="xpd-stat-value">${((o=O.wsConn)==null?void 0:o.readyState)===1?"Online":"Offline"}</strong></article>
        </div>
      </div>
      <div class="xpd-token-col">
        ${wt.loading?'<div class="xpd-loading">Loading recent transactions...</div>':""}
        ${wt.error?`<div class="xpd-error">${g(wt.error)}</div>`:""}
        <div class="xpd-watchlist">${e?s.length?s.map(i=>`<div class="xpd-token-row"><span class="mono">${g((i.hash||"").slice(0,12))}...</span><span>${g(i.TransactionType||"Unknown")}</span></div>`).join(""):'<div class="xpd-empty">No recent transactions.</div>':'<div class="xpd-empty">Select wallet to view transactions.</div>'}</div>
      </div>
    </div>`}function Bv(e){return e?mt.loading?'<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-loading">Loading account_objects and LP balances...</div></div>':mt.error?`<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-error">${g(mt.error)}</div></div>`:mt.pools.length?`<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-pool-list">${mt.pools.map(t=>`
    <div class="xpd-pool-item">
      <div class="pool-pair xpd-pill-text" title="${g(t.pair)}">${g(t.pair)}</div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">LP Balance</span><span class="xpd-pool-row-value" title="${g(t.lpBalance)}">${g(t.lpBalance)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Est. Value</span><span class="xpd-pool-row-value">${g(t.estimatedValue)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Trading Fee</span><span class="xpd-pool-row-value">${g(t.tradingFee||"\u2014")}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">TVL</span><span class="xpd-pool-row-value">${g(t.tvl||"Unavailable")}</span></div>
    </div>`).join("")}</div></div>`:'<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-empty">No AMM entries or LP-token balances detected for this wallet yet.</div></div>':'<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-empty">No active wallet.</div></div>'}function Ov(){return xt.loading?'<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-loading">Loading amm_info for known pools...</div></div>':xt.error?`<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-error">${g(xt.error)}</div></div>`:xt.pools.length?`<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-pool-list">${xt.pools.map(e=>`
    <div class="xpd-pool-item">
      <div class="pool-pair xpd-pill-text" title="${g(e.label)}">${g(e.label)}</div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Reserves</span><span class="xpd-pool-row-value">${g(e.reserveA)} / ${g(e.reserveB)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Trading Fee</span><span class="xpd-pool-row-value">${g(e.tradingFee)} bps</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Total LP</span><span class="xpd-pool-row-value mono" title="${g(e.totalLp)}">${g(e.totalLp)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">TVL</span><span class="xpd-pool-row-value">${g(e.tvl||"Unavailable")}</span></div>
    </div>`).join("")}</div></div>`:'<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-empty">No seeded pools returned on this network.</div></div>'}function Xv(){return`<div class="xpd-amm-card">
    <h3>Lookup custom pool</h3>
    <div class="xpd-form-grid">
      <input id="xpd-asset1-currency" class="xpd-input" placeholder="Asset 1 currency (e.g. XRP)" />
      <input id="xpd-asset1-issuer" class="xpd-input" placeholder="Asset 1 issuer (optional for XRP)" />
      <input id="xpd-asset2-currency" class="xpd-input" placeholder="Asset 2 currency (e.g. USD)" />
      <input id="xpd-asset2-issuer" class="xpd-input" placeholder="Asset 2 issuer" />
    </div>
    <div class="xpd-row-actions"><button class="xpd-action" onclick="loadCustomAmmPool()"><span class="xai">\u{1F50E}</span>Load pool</button><button class="xpd-action" onclick="refreshPoolExplorer()"><span class="xai">\u27F3</span>Refresh known pools</button></div>
    ${Re.loading?'<div class="xpd-loading">Loading pool...</div>':""}
    ${Re.error?`<div class="xpd-error">${g(Re.error)}</div>`:""}
    ${Re.pool?`<div class="xpd-pool-item">
      <div class="pool-pair xpd-pill-text" title="${g(Re.pool.label)}">${g(Re.pool.label)}</div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Reserves</span><span class="xpd-pool-row-value">${g(Re.pool.reserveA)} / ${g(Re.pool.reserveB)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Trading Fee</span><span class="xpd-pool-row-value">${g(Re.pool.tradingFee)} bps</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Total LP</span><span class="xpd-pool-row-value mono" title="${g(Re.pool.totalLp)}">${g(Re.pool.totalLp)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">TVL</span><span class="xpd-pool-row-value">${g(Re.pool.tvl||"Unavailable")}</span></div>
    </div>`:""}
  </div>`}function pt(e){return Number.isFinite(Number(e))?new Intl.NumberFormat("en-US",{notation:"compact",maximumFractionDigits:2}).format(Number(e)):"\u2014"}function ss(e){return typeof e=="string"?`${D(Number(e)/1e6,4)} XRP`:e&&typeof e=="object"?`${D(Number(e.value||0),4)} ${e.currency||"UNK"}`:"\u2014"}function Hv(e){if(!e||typeof e!="string")return"";try{let t=e.trim();if(!/^[0-9A-Fa-f]+$/.test(t)||t.length%2!==0)return t;let n=new Uint8Array(t.length/2);for(let s=0;s<t.length;s+=2)n[s/2]=parseInt(t.slice(s,s+2),16);return new TextDecoder().decode(n)}catch{return""}}function yc(e){return e?e.startsWith("ipfs://")?`https://ipfs.io/ipfs/${e.slice(7)}`:e.startsWith("ar://")?`https://arweave.net/${e.slice(5)}`:e:""}async function zv(e){let t=yc(Hv(e.URI||e.uri||""));if(!t)return"";if(/\.(png|jpg|jpeg|gif|webp|svg)$/i.test(t))return t;try{let n=await fetch(t,{method:"GET"});if(!n.ok)return"";let s=await n.json(),a=(s==null?void 0:s.image)||(s==null?void 0:s.image_url)||(s==null?void 0:s.thumbnail);return yc(a||"")}catch{return""}}async function kt(e,{timeoutMs:t=9e3,allowProxy:n=!0}={}){let s=async a=>{let o=typeof(AbortSignal==null?void 0:AbortSignal.timeout)=="function"?AbortSignal.timeout(t):void 0,i=await fetch(a,{method:"GET",mode:"cors",cache:"no-store",signal:o});if(!i.ok)throw new Error(`HTTP ${i.status}`);return await i.json()};try{return await s(e)}catch(a){if(!n)throw a;for(let o of Zg)try{return await s(o(e))}catch{}throw a}}async function Kc(){var e;Te.loading=!0,Te.error="",q();try{let t=await kt("https://api.exchange.coinbase.com/products/XRP-USD/ticker"),n=await kt("https://api.exchange.coinbase.com/products/XRP-USD/candles?granularity=86400"),s=Array.isArray(n)&&n.length?n[0]:null,a=Number((t==null?void 0:t.price)||0),o=s?Number(s[3]||0):a,i=s?Number(s[2]||a):a,r=s?Number(s[1]||a):a,l=s?Number(s[5]||0):0;Te.data={priceUsd:a,change24h:o?(a-o)/o*100:0,volume24h:l*a,marketCap:Number(((e=Te.data)==null?void 0:e.marketCap)||0),high24h:i,low24h:r}}catch(t){Te.error=(t==null?void 0:t.message)||"Could not load market data right now.",Te.data=null}finally{Te.loading=!1,q()}}async function Jc(e){if(ut.loading=!0,ut.error="",ut.items=[],q(),!e){ut.loading=!1,q();return}try{let t,n=[];do{let a=await Je({method:"account_nfts",params:[{account:e,limit:100,...t?{marker:t}:{}}]});n.push(...(a==null?void 0:a.account_nfts)||[]),t=a==null?void 0:a.marker}while(t);let s=await Promise.all(n.slice(0,80).map(async a=>({id:a.NFTokenID||a.nf_token_id||"Unknown",image:await zv(a)})));ut.items=s}catch(t){ut.error=(t==null?void 0:t.message)||"Could not load NFTs for this wallet."}finally{ut.loading=!1,q()}}async function Yc(e){if(mt.loading=!0,mt.error="",mt.pools=[],q(),!e){mt.loading=!1,q();return}try{let t=[],n;do{let o=await Je({method:"account_objects",params:[{account:e,type:"amm",limit:200,...n?{marker:n}:{}}]});((o==null?void 0:o.account_objects)||[]).forEach(r=>{let l=ss(r.Asset||r.amount),c=ss(r.Asset2||r.amount2),d=l.split(" ").pop()||"AssetA",u=c.split(" ").pop()||"AssetB";t.push({pair:`${d}/${u}`,lpBalance:r.LPTokenBalance?ss(r.LPTokenBalance):"Not reported",estimatedValue:"Estimate unavailable",tradingFee:r.TradingFee!=null?`${r.TradingFee} bps`:"\u2014",tvl:"Unavailable"})}),n=o==null?void 0:o.marker}while(n);let s=await Je({method:"account_lines",params:[{account:e,limit:200}]});((s==null?void 0:s.lines)||[]).filter(o=>typeof o.currency=="string"&&o.currency.length>=16&&Number(o.balance)>0).forEach(o=>{t.push({pair:`LP Token ${o.currency.slice(0,8)}...`,lpBalance:`${D(Number(o.balance),4)} ${o.currency.slice(0,8)}...`,estimatedValue:"Estimate unavailable",tradingFee:"\u2014",tvl:"Unavailable"})}),mt.pools=t}catch(t){mt.error=(t==null?void 0:t.message)||"Could not load account AMM objects."}finally{mt.loading=!1,q()}}async function Qc(e){try{let t=await Je({method:"amm_info",params:[{asset:e.asset,asset2:e.asset2}]}),n=t==null?void 0:t.amm;return n?{label:e.label,reserveA:ss(n.amount),reserveB:ss(n.amount2),tradingFee:String(n.trading_fee??"\u2014"),totalLp:ss(n.lp_token||n.lp_token_balance),tvl:Uv(n.amount,n.amount2)}:null}catch{return null}}function Uv(e,t){let n=a=>typeof a=="string"?Number(a)/1e6:a&&typeof a=="object"?Number(a.value||0):0,s=n(e)+n(t);return!Number.isFinite(s)||s<=0?"Unavailable":`${D(s,4)} (asset units)`}async function Zc(){xt.loading=!0,xt.error="",q();try{let e=await Promise.all(wv.map(Qc));xt.pools=e.filter(Boolean)}catch(e){xt.error=(e==null?void 0:e.message)||"Could not load AMM explorer data.",xt.pools=[]}finally{xt.loading=!1,q()}}async function ed(){var r,l,c,d;let e=(((r=document.getElementById("xpd-asset1-currency"))==null?void 0:r.value)||"").trim().toUpperCase(),t=(((l=document.getElementById("xpd-asset1-issuer"))==null?void 0:l.value)||"").trim(),n=(((c=document.getElementById("xpd-asset2-currency"))==null?void 0:c.value)||"").trim().toUpperCase(),s=(((d=document.getElementById("xpd-asset2-issuer"))==null?void 0:d.value)||"").trim();if(!e||!n){Re.error="Enter both asset currency codes first.",q();return}let a=e==="XRP"?{currency:"XRP"}:{currency:e,issuer:t},o=n==="XRP"?{currency:"XRP"}:{currency:n,issuer:s};if(e!=="XRP"&&!t||n!=="XRP"&&!s){Re.error="Issuer is required for non-XRP assets.",q();return}Re.loading=!0,Re.error="",Re.pool=null,q();let i=await Qc({label:`${e}/${n}`,asset:a,asset2:o});Re.loading=!1,i?Re.pool=i:Re.error="Pool not found or unavailable on this network.",q()}function Na(){return Mn.find(e=>e.id===C.pair)||Mn[0]}function vi(e){if(e==="D")return 1440;if(e==="W")return 10080;if(e==="M")return 43200;let t=Number(e);return Number.isFinite(t)&&t>0?t:60}function Wv(e){if(e==="M")return"W";if(e==="D"||e==="W")return e;let t=vi(e);for(let n of[5,15,60,240])if(t<=n)return String(n);return"D"}async function jv(e,t,n,s=200){var d;let a=t?`${e}.${t}`:e,o=Wv(n),i=Math.min(2e3,Math.max(20,Number(s)||200)),r=`https://api.onthedex.live/public/v1/ohlc?base=${encodeURIComponent(a)}&quote=XRP&interval=${o}&bars=${i}`,l=await kt(r,{timeoutMs:1e4});return(Array.isArray((d=l==null?void 0:l.data)==null?void 0:d.ohlc)?l.data.ohlc:[]).map(u=>({time:Number(u.t),open:Number(u.o),high:Number(u.h),low:Number(u.l),close:Number(u.c),volume:Number(u.vb||0)})).filter(u=>Number.isFinite(u.time)&&[u.open,u.high,u.low,u.close].every(Number.isFinite)).sort((u,p)=>u.time-p.time)}function td(e){return{xrpusd:"XRP-USD",XRPUSDT:"XRP-USD",ETHUSDT:"ETH-USD",BTCUSDT:"BTC-USD",SOLUSDT:"SOL-USD"}[e]||null}function qv(e){return{XRP:"XRP-USD",BTC:"BTC-USD",ETH:"ETH-USD",SOL:"SOL-USD",USDC:"USDC-USD"}[String(e||"").toUpperCase()]||null}var Go=new Map;async function Vv(e,t){if(!e)return null;let n=`${ht(e)}:${t}`,s=Go.get(n);if(s)return s;let a=Gv(e,t);Go.set(n,a);try{return await a}finally{Go.delete(n)}}async function Gv(e,t){var o,i;let n=String(e.symbol||"").toUpperCase();if(!n||n==="XRP")return null;let s=qv(n);if(s)try{let r=ad(t),l=r===86400?Rc:Dc,{candles:c,reachedStart:d}=await oi(s,r,l);if(c.length){let u=d?`${new Date(c[0].time*1e3).getUTCFullYear()}\u2013present`:`last ${c.length} bars`;return{candles:c,source:`Coinbase direct (${s}, ${u})`,mode:"token-direct"}}}catch{}let a=String(e.issuer||"").trim();if(a)try{let r=await jv(n,a,t,2e3);if(r.length){let l=Number(((o=C.stats)==null?void 0:o.xrplSpot)||((i=C.stats)==null?void 0:i.price)||0);return{candles:l>0?r.map(d=>({time:d.time,open:d.open*l,high:d.high*l,low:d.low*l,close:d.close*l,volume:d.volume})):r,source:`OnTheDex XRPL DEX (${n}/XRP)`,mode:"token-direct"}}}catch{}return null}function Kv(e,{mode:t="pair",source:n="Source pending",tokenKey:s=""}={}){let a=Array.isArray(e)?e:[];if(!a.length){C.chartMeta={tokenKey:s||C.tokenFocusKey||"XRP|",symbol:s&&s.split("|")[0]||"XRP",source:n,last:null,high:null,low:null,mode:t};return}let o=a[a.length-1],i=a.map(c=>Number(c.high)).filter(c=>Number.isFinite(c)),r=a.map(c=>Number(c.low)).filter(c=>Number.isFinite(c)),l=s||C.tokenFocusKey||"XRP|";C.chartMeta={tokenKey:l,symbol:l.split("|")[0]||"XRP",source:n,last:Number(o.close),high:i.length?Math.max(...i):Number(o.high),low:r.length?Math.min(...r):Number(o.low),mode:t}}async function Is(){var t;let e=Na();C.loading=!0,C.error="";try{let n=td(e.ticker);if(n){let s=await kt(`https://api.exchange.coinbase.com/products/${n}/ticker`),a=await kt(`https://api.exchange.coinbase.com/products/${n}/candles?granularity=86400`),o=Array.isArray(a)&&a.length?a[0]:null,i=Number(s.price||0),r=o?Number(o[3]):i;C.stats={price:i,high:o?Number(o[2]):i,low:o?Number(o[1]):i,changePct:r?(i-r)/r*100:0,baseSource:"Coinbase",source:"Coinbase"},await nd(),!Te.data&&C.stats.price&&(Te.data={priceUsd:C.stats.price,change24h:C.stats.changePct,volume24h:o?Number(o[5]||0)*C.stats.price:0,marketCap:Number(((t=Te.data)==null?void 0:t.marketCap)||0)});return}throw new Error("Chart stats unavailable for selected pair.")}catch(n){C.error=(n==null?void 0:n.message)||"DEX chart stats unavailable right now."}finally{C.loading=!1}}async function nd(){var e,t,n;try{let s=await Je({method:"book_offers",params:[{taker_gets:{currency:"USD",issuer:"rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq"},taker_pays:{currency:"XRP"},limit:1}]}),a=(e=s==null?void 0:s.offers)==null?void 0:e[0];if(!a)return;let o=Number(((t=a.TakerGets)==null?void 0:t.value)||0),i=typeof a.TakerPays=="string"?Number(a.TakerPays)/1e6:Number(((n=a.TakerPays)==null?void 0:n.value)||0);if(o>0&&i>0){let r=o/i;if(_c=Date.now(),C.stats||(C.stats={}),C.stats.xrplSpot=r,String(Na().symbol||"XRP").toUpperCase()==="XRP"){C.stats.price=r;let l=C.stats.baseSource||C.stats.source||"Market feed";C.stats.source=`${l} + XRPL live`,Te.data&&(Te.data.priceUsd=r)}}}catch{}}async function Jv(){var e,t;return(e=window.LightweightCharts)!=null&&e.createChart?!0:(ka||(ka=new Promise((n,s)=>{let a=document.querySelector('script[data-lw-chart="1"]');if(a){a.addEventListener("load",()=>n(!0),{once:!0}),a.addEventListener("error",()=>s(new Error("Chart library failed to load.")),{once:!0});return}let o=document.createElement("script");o.src="https://unpkg.com/lightweight-charts@4.2.2/dist/lightweight-charts.standalone.production.js",o.async=!0,o.defer=!0,o.dataset.lwChart="1",o.onload=()=>n(!0),o.onerror=()=>s(new Error("Chart library failed to load.")),document.head.appendChild(o)}).finally(()=>{var n;(n=window.LightweightCharts)!=null&&n.createChart||(ka=null)})),await ka,!!((t=window.LightweightCharts)!=null&&t.createChart))}async function Yv(){var e,t;return(e=window.THREE)!=null&&e.Scene?!0:($a||($a=new Promise((n,s)=>{let a=document.querySelector('script[data-three-chart="1"]');if(a){a.addEventListener("load",()=>n(!0),{once:!0}),a.addEventListener("error",()=>s(new Error("Three.js failed to load.")),{once:!0});return}let o=document.createElement("script");o.src="https://unpkg.com/three@0.166.1/build/three.min.js",o.async=!0,o.defer=!0,o.dataset.threeChart="1",o.onload=()=>n(!0),o.onerror=()=>s(new Error("Three.js failed to load.")),document.head.appendChild(o)}).finally(()=>{var n;(n=window.THREE)!=null&&n.Scene||($a=null)})),await $a,!!((t=window.THREE)!=null&&t.Scene))}function Fs(){var e,t;if(He.resizeHandler)try{window.removeEventListener("resize",He.resizeHandler)}catch{}if(He.raf&&cancelAnimationFrame(He.raf),(t=(e=He.renderer)==null?void 0:e.domElement)!=null&&t.parentElement)try{He.renderer.domElement.parentElement.removeChild(He.renderer.domElement)}catch{}if(He.renderer)try{He.renderer.dispose()}catch{}He={renderer:null,scene:null,camera:null,points:null,raf:0,host:null,resizeHandler:null}}async function Qv(){var t;let e=document.getElementById("xpd-chart-atmosphere");if(e&&!(He.renderer&&e.contains(He.renderer.domElement))&&!((navigator.hardwareConcurrency||4)<=3))try{if(await Yv(),!((t=window.THREE)!=null&&t.Scene))return;Fs();let n=window.THREE,s=Math.max(1,e.clientWidth||640),a=Math.max(1,e.clientHeight||460),o=new n.Scene,i=new n.PerspectiveCamera(52,s/a,.1,1e3);i.position.z=46;let r=new n.WebGLRenderer({alpha:!0,antialias:!0});r.setPixelRatio(Math.min(2,window.devicePixelRatio||1)),r.setSize(s,a),e.appendChild(r.domElement);let l=900,c=new Float32Array(l*3);for(let w=0;w<l;w+=1){let k=w*3;c[k]=(Math.random()-.5)*90,c[k+1]=(Math.random()-.5)*40,c[k+2]=(Math.random()-.5)*24}let d=new n.BufferGeometry;d.setAttribute("position",new n.BufferAttribute(c,3));let u=new n.PointsMaterial({color:5101823,size:.25,transparent:!0,opacity:.26,depthWrite:!1}),p=new n.Points(d,u);o.add(p);let m=0,f=0,v=()=>{var S;m+=1;let w=Number(((S=C.stats)==null?void 0:S.changePct)||0),k=Math.min(4,Math.max(.35,Math.abs(w)/2.2)),b=w>0?16758874:16739999;u.color.setHex(Math.abs(w)>1.5?b:5101823),p.rotation.y+=9e-4*k,p.rotation.x=Math.sin(m*.0015*k)*.08,p.position.y=Math.sin(m*.003*k)*.7,(!document.hidden||Date.now()-f>350)&&(r.render(o,i),f=Date.now()),He.raf=requestAnimationFrame(v)},h=()=>{let w=Math.max(1,e.clientWidth||640),k=Math.max(1,e.clientHeight||460);i.aspect=w/k,i.updateProjectionMatrix(),r.setSize(w,k)};window.addEventListener("resize",h,{passive:!0}),He={renderer:r,scene:o,camera:i,points:p,raf:0,host:e,resizeHandler:h},v()}catch{}}function sd(e){return vi(e)*60}function ad(e){let t=vi(e);return t<=1?60:t<=5?300:t<=15?900:t<=60?3600:t<=360?21600:86400}function od(){let e=String(C.tokenFocusKey||"");if(!e)return null;let t=e.includes("|")?e.split("|")[0]:e;return j.tokens.find(n=>ht(n)===e)||j.tokens.find(n=>String(n.symbol||"").toUpperCase()===String(t||"").toUpperCase())||null}function id(){var a,o;let e=od(),t=Number((e==null?void 0:e.price)||0);if(Number.isFinite(t)&&t>0)return t;let n=Number(((a=C.stats)==null?void 0:a.xrplSpot)||0);if(Number.isFinite(n)&&n>0)return n;let s=Number(((o=C.stats)==null?void 0:o.price)||0);return Number.isFinite(s)&&s>0?s:1}function rd(e,t=1,n=220){let s=Math.max(60,sd(e)),a=Math.floor(Date.now()/1e3),o=Math.floor(a/s)*s-n*s,i=Math.max(1e-6,Number(t)||1),r=[];for(let l=0;l<n;l+=1){let c=o+l*s,d=i,u=Math.sin((l+1)/9)*.004+Math.cos((l+3)/17)*.002;i=Math.max(1e-6,d*(1+u));let p=Math.max(d,i)*(1+Math.abs(u)*.55+.0015),m=Math.min(d,i)*Math.max(1e-6,1-(Math.abs(u)*.55+.0015));r.push({time:c,open:Number(d),high:Number(p),low:Number(m),close:Number(i),volume:Math.max(0,Math.round(Math.abs(u)*12e3+l%13*55))})}return r}function ni(e){if(!e.length)return e;let t=[];for(let n=0;n<e.length;n+=1){let s=e[n],a=(s.open+s.high+s.low+s.close)/4,o=t[n-1],i=o?(o.open+o.close)/2:(s.open+s.close)/2,r=Math.max(s.high,i,a),l=Math.min(s.low,i,a);t.push({...s,open:i,high:r,low:l,close:a})}return t}function si(e,t){let n=[],s=0;for(let a=0;a<e.length;a+=1)s+=e[a].close,a>=t&&(s-=e[a-t].close),a>=t-1&&n.push({time:e[a].time,value:s/t});return n}function Rs(e,t){let n=[];if(!e.length)return n;let s=2/(t+1),a=e[0].close;for(let o=0;o<e.length;o+=1)a=o===0?e[o].close:e[o].close*s+a*(1-s),o>=t-1&&n.push({time:e[o].time,value:a});return n}function Zv(e,t){let n=[],s=t*(t+1)/2;for(let a=t-1;a<e.length;a+=1){let o=0;for(let i=0;i<t;i+=1)o+=e[a-i].close*(t-i);n.push({time:e[a].time,value:o/s})}return n}function eb(e,t=20,n=2){let s=si(e,t),a=[],o=[];for(let i=t-1;i<e.length;i+=1){let r=e.slice(i-t+1,i+1),l=s[i-(t-1)].value,c=r.reduce((u,p)=>u+Math.pow(p.close-l,2),0)/t,d=Math.sqrt(c);a.push({time:e[i].time,value:l+d*n}),o.push({time:e[i].time,value:l-d*n})}return{upper:a,lower:o}}function tb(e){let t=[],n=0,s=0;for(let a=0;a<e.length;a+=1){let o=(e[a].high+e[a].low+e[a].close)/3;n+=o*(e[a].volume||0),s+=e[a].volume||0,s>0&&t.push({time:e[a].time,value:n/s})}return t}function nb(e,t=14){let n=[];if(e.length<=t)return n;let s=0,a=0;for(let r=1;r<=t;r+=1){let l=e[r].close-e[r-1].close;s+=l>0?l:0,a+=l<0?-l:0}let o=s/t,i=a/t;for(let r=t+1;r<e.length;r+=1){let l=e[r].close-e[r-1].close;o=(o*(t-1)+(l>0?l:0))/t,i=(i*(t-1)+(l<0?-l:0))/t;let c=i>0?o/i:100;n.push({time:e[r].time,value:100-100/(1+c)})}return n}function bi(e,t=14){let n=[];for(let o=0;o<e.length;o+=1){let i=o>0?e[o-1].close:e[o].close;n.push(Math.max(e[o].high-e[o].low,Math.abs(e[o].high-i),Math.abs(e[o].low-i)))}let s=[],a=n.slice(0,t).reduce((o,i)=>o+i,0)/Math.max(1,t);for(let o=t;o<e.length;o+=1)a=(a*(t-1)+n[o])/t,s.push({time:e[o].time,value:a});return s}function sb(e,t=14,n=3){let s=[];for(let o=t-1;o<e.length;o+=1){let i=e.slice(o-t+1,o+1),r=Math.max(...i.map(d=>d.high)),l=Math.min(...i.map(d=>d.low)),c=r!==l?(e[o].close-l)/(r-l)*100:50;s.push({time:e[o].time,value:c})}let a=[];for(let o=n-1;o<s.length;o+=1){let i=s.slice(o-n+1,o+1).reduce((r,l)=>r+l.value,0)/n;a.push({time:s[o].time,value:i})}return{k:s,d:a}}function ab(e,t=12,n=26,s=9){let a=Rs(e,t),o=Rs(e,n),i=new Map(o.map(u=>[u.time,u.value])),r=a.filter(u=>i.has(u.time)).map(u=>({time:u.time,value:u.value-i.get(u.time)})),l=[];if(r.length){let u=2/(s+1),p=r[0].value;for(let m=0;m<r.length;m+=1)p=m===0?r[m].value:r[m].value*u+p*(1-u),m>=s-1&&l.push({time:r[m].time,value:p})}let c=new Map(l.map(u=>[u.time,u.value])),d=r.filter(u=>c.has(u.time)).map(u=>({time:u.time,value:u.value-c.get(u.time)}));return{line:r,signal:l,hist:d}}function ld(e,t=9,n=26,s=52){let a=u=>{let p=[];for(let m=u-1;m<e.length;m+=1){let f=e.slice(m-u+1,m+1);p.push({time:e[m].time,value:(Math.max(...f.map(v=>v.high))+Math.min(...f.map(v=>v.low)))/2})}return p},o=a(t),i=a(n),r=new Map(i.map(u=>[u.time,u.value])),l=o.filter(u=>r.has(u.time)).map(u=>({time:u.time,value:(u.value+r.get(u.time))/2})),c=a(s),d=e.map(u=>({time:u.time,value:u.close}));return{tenkan:o,kijun:i,senkouA:l,senkouB:c,chikou:d}}function ob(e,t=20){let n=[],s=[],a=[];for(let o=t-1;o<e.length;o+=1){let i=e.slice(o-t+1,o+1),r=Math.max(...i.map(c=>c.high)),l=Math.min(...i.map(c=>c.low));n.push({time:e[o].time,value:r}),s.push({time:e[o].time,value:l}),a.push({time:e[o].time,value:(r+l)/2})}return{upper:n,lower:s,mid:a}}function ib(e,t=20,n=2){let s=Rs(e,t),a=bi(e,t),o=new Map(a.map(l=>[l.time,l.value])),i=[],r=[];return s.forEach(l=>{if(o.has(l.time)){let c=o.get(l.time)*n;i.push({time:l.time,value:l.value+c}),r.push({time:l.time,value:l.value-c})}}),{upper:i,lower:r,mid:s}}function rb(e){let t=[],n=[],s=0,a=0;for(let o=0;o<e.length;o+=1){if(o>0){let l=e[o-1];e[o].close>l.close&&(s+=e[o].volume||0),e[o].close<l.close&&(s-=e[o].volume||0)}let i=e[o].high-e[o].low||1,r=(e[o].close-e[o].low-(e[o].high-e[o].close))/i;a+=r*(e[o].volume||0),t.push({time:e[o].time,value:s}),n.push({time:e[o].time,value:a})}return{obv:t,adline:n}}function lb(e,t=14){if(e.length<t+2)return{adx:[],plusDi:[],minusDi:[]};let n=[],s=[],a=[];for(let p=1;p<e.length;p+=1){let m=e[p].high-e[p-1].high,f=e[p-1].low-e[p].low;s.push(m>f&&m>0?m:0),a.push(f>m&&f>0?f:0),n.push(Math.max(e[p].high-e[p].low,Math.abs(e[p].high-e[p-1].close),Math.abs(e[p].low-e[p-1].close)))}let o=n.slice(0,t).reduce((p,m)=>p+m,0),i=s.slice(0,t).reduce((p,m)=>p+m,0),r=a.slice(0,t).reduce((p,m)=>p+m,0),l=[],c=[],d=[];for(let p=t;p<n.length;p+=1){o=o-o/t+n[p],i=i-i/t+s[p],r=r-r/t+a[p];let m=o>0?100*i/o:0,f=o>0?100*r/o:0,v=m+f>0?100*Math.abs(m-f)/(m+f):0,h=e[p+1].time;l.push({time:h,value:m}),c.push({time:h,value:f}),d.push({time:h,value:v})}let u=[];if(d.length>=t){let p=d.slice(0,t).reduce((m,f)=>m+f.value,0)/t;for(let m=t;m<d.length;m+=1)p=(p*(t-1)+d[m].value)/t,u.push({time:d[m].time,value:p})}return{adx:u,plusDi:l,minusDi:c}}function cb(e,t=14){let n=[],s=[];for(let a=t-1;a<e.length;a+=1){let o=e.slice(a-t+1,a+1),i=0,r=0;for(let d=1;d<o.length;d+=1)o[d].high>=o[i].high&&(i=d),o[d].low<=o[r].low&&(r=d);let l=t-1-i,c=t-1-r;n.push({time:e[a].time,value:(t-l)/t*100}),s.push({time:e[a].time,value:(t-c)/t*100})}return{up:n,down:s}}function db(e,t=14){let n=[],s=[];if(e.length<t+2)return{plus:n,minus:s};for(let a=t;a<e.length;a+=1){let o=0,i=0,r=0;for(let l=a-t+1;l<=a;l+=1){let c=e[l-1],d=e[l];o+=Math.max(d.high-d.low,Math.abs(d.high-c.close),Math.abs(d.low-c.close)),i+=Math.abs(d.high-c.low),r+=Math.abs(d.low-c.high)}n.push({time:e[a].time,value:o>0?i/o:0}),s.push({time:e[a].time,value:o>0?r/o:0})}return{plus:n,minus:s}}function pb(e,t=10,n=3){let s=bi(e,t),a=new Map(s.map(c=>[c.time,c.value])),o=[],i=0,r=0,l=!0;return e.forEach((c,d)=>{if(d===0||!a.has(c.time))return;let u=(c.high+c.low)/2,p=a.get(c.time),m=u+n*p,f=u-n*p;d>1&&(m>i&&e[d-1].close<=i&&(m=i),f<r&&e[d-1].close>=r&&(f=r));let v=c.close>m?!0:c.close<f?!1:l,h=v?f:m;o.push({time:c.time,value:h,trendUp:v?1:0}),i=m,r=f,l=v}),o}function ub(e,t=14){let n=[];if(e.length<=t)return n;let s=e.map((a,o)=>{let i=(a.high+a.low+a.close)/3,r=o>0?(e[o-1].high+e[o-1].low+e[o-1].close)/3:i,l=i*(a.volume||0);return{time:a.time,pos:i>=r?l:0,neg:i<r?l:0}});for(let a=t;a<s.length;a+=1){let o=s.slice(a-t+1,a+1),i=o.reduce((c,d)=>c+d.pos,0),r=o.reduce((c,d)=>c+d.neg,0),l=r>0?i/r:100;n.push({time:s[a].time,value:100-100/(1+l)})}return n}function mb(e,t=14){let n=[];for(let s=t-1;s<e.length;s+=1){let a=e.slice(s-t+1,s+1),o=Math.max(...a.map(l=>l.high)),i=Math.min(...a.map(l=>l.low)),r=o!==i?(o-e[s].close)/(o-i)*-100:-50;n.push({time:e[s].time,value:r})}return n}function fb(e,t=20){let n=[],s=e.map(a=>({time:a.time,value:(a.high+a.low+a.close)/3}));for(let a=t-1;a<s.length;a+=1){let o=s.slice(a-t+1,a+1),i=o.reduce((c,d)=>c+d.value,0)/t,r=o.reduce((c,d)=>c+Math.abs(d.value-i),0)/t,l=r>0?(s[a].value-i)/(.015*r):0;n.push({time:s[a].time,value:l})}return n}function hb(e){if(e.length<30)return[];let t=[],n=[];for(let o=1;o<e.length;o+=1){let i=e[o-1].close,r=Math.min(e[o].low,i),l=Math.max(e[o].high,i);t.push({time:e[o].time,value:e[o].close-r}),n.push({time:e[o].time,value:l-r})}let s=(o,i,r)=>o.slice(i-r+1,i+1).reduce((l,c)=>l+c.value,0),a=[];for(let o=27;o<t.length;o+=1){let i=s(t,o,7)/Math.max(1e-9,s(n,o,7)),r=s(t,o,14)/Math.max(1e-9,s(n,o,14)),l=s(t,o,28)/Math.max(1e-9,s(n,o,28));a.push({time:t[o].time,value:100*(4*i+2*r+l)/7})}return a}function gb(e,t=20){let n=[],s=e.map(a=>{let o=a.high-a.low||1,i=(a.close-a.low-(a.high-a.close))/o;return{time:a.time,value:i*(a.volume||0),volume:a.volume||0}});for(let a=t-1;a<s.length;a+=1){let o=s.slice(a-t+1,a+1),i=o.reduce((l,c)=>l+c.value,0),r=o.reduce((l,c)=>l+c.volume,0);n.push({time:s[a].time,value:r>0?i/r:0})}return n}function vb(e){return(Array.isArray(e)?e:[]).map(t=>({time:Number(t[0]),low:Number(t[1]),high:Number(t[2]),open:Number(t[3]),close:Number(t[4]),volume:Number(t[5])})).filter(t=>Number.isFinite(t.time)&&[t.open,t.high,t.low,t.close].every(Number.isFinite))}function ai(e,t){let n=new Map;for(let s of e)n.set(s.time,s);for(let s of t)n.set(s.time,s);return Array.from(n.values()).sort((s,a)=>s.time-a.time)}async function oi(e,t,n){let s=[],a=Math.floor(Date.now()/1e3),o=!1;for(let i=0;i<n;i+=1){let r=a-t*300,l=`https://api.exchange.coinbase.com/products/${e}/candles?granularity=${t}&start=${new Date(r*1e3).toISOString()}&end=${new Date(a*1e3).toISOString()}`,c;try{c=await kt(l,{timeoutMs:1e4})}catch{break}let d=vb(c);if(!d.length){o=!0;break}s.push(...d),a=r,i<n-1&&await hv(fv)}return{candles:ai(s,[]),reachedStart:o}}async function bb(e,t,n){if(!e||!Number.isFinite(t)||!Number.isFinite(n)||n<=t)return[];try{let s=`https://api.coingecko.com/api/v3/coins/${e}/market_chart/range?vs_currency=usd&from=${t}&to=${n}`,a=await kt(s,{timeoutMs:15e3});return(Array.isArray(a==null?void 0:a.prices)?a.prices:[]).map(([i,r])=>({time:Math.floor(Number(i)/1e3/86400)*86400,open:Number(r),high:Number(r),low:Number(r),close:Number(r),volume:0})).filter(i=>Number.isFinite(i.time)&&Number.isFinite(i.close)&&i.close>0).sort((i,r)=>i.time-r.time)}catch{return[]}}async function yb(e,t,n){var u;let s=ad(n),a=s===86400,o=`${mv}${e.id}:${s}`,i=ve(Z(o));if((u=i==null?void 0:i.candles)!=null&&u.length&&i.reachedStart){let p=await oi(t,s,1),m=ai(i.candles,p.candles);return te(o,JSON.stringify({candles:m,reachedStart:!0,source:i.source,cachedAt:Date.now()})),{candles:m,source:i.source}}let l=await oi(t,s,a?Rc:Dc),c=l.candles,d=c.length?`Coinbase (${new Date(c[0].time*1e3).getUTCFullYear()}\u2013present, ${c.length} bars)`:"Coinbase";if(a&&l.reachedStart&&e.coingeckoId&&c.length){let p=c[0].time,m=await bb(e.coingeckoId,0,p);m.length&&(c=ai(m,c),d=`CoinGecko (${new Date(c[0].time*1e3).getUTCFullYear()}+) + Coinbase (${new Date(p*1e3).getUTCFullYear()}\u2013present)`)}else!a&&!l.reachedStart&&(d=`Coinbase (last ${c.length} bars \u2014 full inception history is daily/weekly/monthly only)`);return c.length&&te(o,JSON.stringify({candles:c,reachedStart:l.reachedStart,source:d,cachedAt:Date.now()})),{candles:c,source:d}}var Ko=new Map;async function cd(e,t){let n=`${e.id}:${t}`,s=As.get(n);if(s&&Date.now()-s.ts<6e4&&Array.isArray(s.data)&&s.data.length)return s.data;let a=Ko.get(n);if(a)return a;let o=(async()=>{let i=[],r="",l=td(e.ticker);if(l)try{let c=await yb(e,l,t);i=c.candles,r=c.source}catch{i=[]}if(!Array.isArray(i)||!i.length){let c=rd(t,id());return As.set(n,{ts:Date.now(),data:c,sourceLabel:""}),c}return As.set(n,{ts:Date.now(),data:i,sourceLabel:r}),i})();Ko.set(n,o);try{return await o}finally{Ko.delete(n)}}async function wb(){var u,p,m,f,v,h,w,k;let e=Na(),t=await cd(e,C.interval),s=((u=As.get(`${e.id}:${C.interval}`))==null?void 0:u.sourceLabel)||String(((p=C.stats)==null?void 0:p.source)||"Coinbase + XRPL live"),a="pair",o=od(),i=String((o==null?void 0:o.symbol)||"").toUpperCase(),r=o?ht(o):`${e.symbol||"XRP"}|`;if(o&&i&&i!=="XRP"){let b=await Vv(o,C.interval);(m=b==null?void 0:b.candles)!=null&&m.length&&(t=b.candles,s=b.source,a=b.mode)}let l=String(e.symbol||"XRP").toUpperCase()==="XRP",c=Number((l?(f=C.stats)==null?void 0:f.xrplSpot:null)??((v=C.stats)==null?void 0:v.price)??0);if(a==="pair"&&Number.isFinite(c)&&c>0&&t.length){let b=Math.max(60,sd(C.interval)),x=Math.floor(Date.now()/1e3),S=Math.floor(x/b)*b,T=t[t.length-1];T.time===S?(T.high=Math.max(T.high,c),T.low=Math.min(T.low,c),T.close=c):T.time<S&&t.push({time:S,open:T.close,high:Math.max(T.close,c),low:Math.min(T.close,c),close:c,volume:0})}let d=Number((o==null?void 0:o.price)||0);if(a==="pair"&&o&&i&&i!=="XRP"&&Number.isFinite(d)&&d>0&&t.length){let b=Number((l?(h=C.stats)==null?void 0:h.xrplSpot:null)??((w=C.stats)==null?void 0:w.price)??((k=t[t.length-1])==null?void 0:k.close)??0);if(Number.isFinite(b)&&b>0){let x=d/b;Number.isFinite(x)&&x>0&&(t=t.map(S=>({...S,open:S.open*x,high:S.high*x,low:S.low*x,close:S.close*x})),s="Coinbase pair + token spot proxy",a="token-proxy")}}return t.length||(t=rd(C.interval,id()),s=o&&i!=="XRP"?"Synthetic fallback (token-focused)":"Synthetic fallback",a="fallback"),o&&i!=="XRP"&&(a==="pair"||a==="fallback")?Vo!==r&&(Vo=r,be(`No market data found for ${o.symbol} yet \u2014 showing ${e.symbol||"XRP"} for reference.`)):r&&(Vo=""),C.chartType==="heikin_ashi"&&(t=ni(t)),Kv(t,{mode:a,source:s,tokenKey:r||"XRP|"}),t}function wc(e){if(!Array.isArray(e))return[];let t=e.map(s=>({time:Number(s.time),open:Number(s.open),high:Number(s.high),low:Number(s.low),close:Number(s.close),volume:Number(s.volume||0)})).filter(s=>Number.isFinite(s.time)&&Number.isFinite(s.open)&&Number.isFinite(s.high)&&Number.isFinite(s.low)&&Number.isFinite(s.close)&&s.time>0).sort((s,a)=>s.time-a.time),n=[];for(let s=0;s<t.length;s+=1){let a=t[s],o=n[n.length-1];o&&o.time===a.time?n[n.length-1]=a:n.push(a)}return n}function xb(e,t,n){var i;let s=Number(((i=e==null?void 0:e[e.length-1])==null?void 0:i.close)||0);if(!Number.isFinite(s)||s<=0)return 6;let o=Math.max(1e-12,Math.abs(Number(n)-Number(t)))/Math.max(1e-12,Math.abs(s));return s>=1e3?o<.01?4:2:s>=1?o<.01?6:4:s>=.01?o<.03?8:6:8}function kb(){if(ee.resizeObserver)try{ee.resizeObserver.disconnect()}catch{}ee.chart&&(ee.chart.remove(),ee={chart:null,volumeSeries:null,activeSeries:null,compareSeries:null,indicatorSeries:[],indicatorPriceLines:[],priceLines:[],resizeObserver:null,chartType:"",configKey:"",legendEl:null,renderLegend:null,ichimokuData:null,indicatorLegendItems:[],alertPriceLines:[]})}function xc(e,t){var d;let{addOverlay:n,addOsc:s,addOscHist:a,addPriceLevel:o}=t,i=(u,p)=>{var f,v;let m=Number((v=(f=C.indicatorSettings)==null?void 0:f[u])==null?void 0:v.length);return Number.isFinite(m)&&m>1?Math.min(500,Math.max(2,m)):p},r=(u,p,m)=>{var h,w;let f=(w=(h=C.indicatorSettings)==null?void 0:h[u])==null?void 0:w[p];if(f==null||f==="")return m;let v=(mi[u]||[]).find(k=>k.id===p);if((v==null?void 0:v.type)==="number"){let k=Number(f);return Number.isFinite(k)&&k>1?Math.min(500,Math.max(2,k)):m}return f},l=C.indicators;if(l.sma20&&n(si(e,i("sma20",20)),r("sma20","color","#f1c40f"),1.2,!1,"SMA"),l.ema20&&n(Rs(e,i("ema20",20)),r("ema20","color","#ffb86c"),1.2,!1,"EMA"),l.wma20&&n(Zv(e,i("wma20",20)),r("wma20","color","#bd93f9"),1.2,!1,"WMA"),l.vwap&&n(tb(e),r("vwap","color","#80ffea"),1.2,!1,"VWAP"),l.bb20){let u=r("bb20","color","#ff79c6"),p=eb(e,i("bb20",20),2);n(p.upper,u,1,!0,"BB Upper"),n(p.lower,u,1,!0,"BB Lower")}if(l.ichimoku){let u=ld(e,r("ichimoku","tenkanLen",9),r("ichimoku","kijunLen",26),r("ichimoku","senkouBLen",52));n(u.tenkan,r("ichimoku","tenkanColor","#ffde59"),1.2,!1,"Tenkan"),n(u.kijun,r("ichimoku","kijunColor","#6ecbff"),1.2,!1,"Kijun"),n(u.senkouA,"rgba(70,255,160,0.8)",1,!0,"Senkou A"),n(u.senkouB,"rgba(255,120,120,0.8)",1,!0,"Senkou B"),n(u.chikou,"rgba(220,220,255,0.6)",.9,!0,"Chikou")}if(l.donchian){let u=r("donchian","color","#9cfb8c"),p=ob(e,i("donchian",20));n(p.upper,u,1,!0,"Donchian Upper"),n(p.lower,u,1,!0,"Donchian Lower"),n(p.mid,"rgba(156,251,140,0.6)",1.2,!1,"Donchian Mid")}if(l.keltner){let u=r("keltner","color","#7ee7ff"),p=ib(e,i("keltner",20),2);n(p.upper,u,1,!0,"Keltner Upper"),n(p.lower,u,1,!0,"Keltner Lower"),n(p.mid,"rgba(126,231,255,0.66)",1.2,!1,"Keltner Mid")}if(l.pivots&&e.length>=2){let u=e[e.length-2],p=(u.high+u.low+u.close)/3,m=2*p-u.low,f=2*p-u.high,v=p+(u.high-u.low),h=p-(u.high-u.low);o(p,"#f6f6f6","P"),o(m,"#61ffb0","R1"),o(f,"#ff8f8f","S1"),o(v,"rgba(97,255,176,0.6)","R2"),o(h,"rgba(255,143,143,0.6)","S2")}if(l.supertrend||l.sar||l.elderRay){let u=Rs(e,14);if(l.supertrend&&n(pb(e,10,3),r("supertrend","color","#8bffde"),1.3,!1,"Supertrend"),l.sar&&n(u.map(p=>({time:p.time,value:p.value*.998})),r("sar","color","#ffaf7a"),1,!0,"SAR"),l.elderRay){let p=new Map(u.map(v=>[v.time,v.value])),m=e.filter(v=>p.has(v.time)).map(v=>({time:v.time,value:v.high-p.get(v.time)})),f=e.filter(v=>p.has(v.time)).map(v=>({time:v.time,value:v.low-p.get(v.time)}));s(m,r("elderRay","bullColor","#5fff9d"),"Elder Bull"),s(f,r("elderRay","bearColor","#ff9d9d"),"Elder Bear")}}if(l.rsi&&s(nb(e,i("rsi",14)),r("rsi","color","#a6ff4d"),"RSI"),l.atr&&s(bi(e,i("atr",14)),r("atr","color","#ffb86c"),"ATR"),l.stdev){let u=si(e,20),p=new Map(u.map(f=>[f.time,f.value])),m=e.filter(f=>p.has(f.time)).map(f=>({time:f.time,value:Math.abs(f.close-p.get(f.time))}));s(m,r("stdev","color","#b2a3ff"),"StdDev")}if(l.stoch){let u=sb(e,i("stoch",14),3);s(u.k,r("stoch","kColor","#9ee8ff"),"%K"),s(u.d,r("stoch","dColor","#ffd86b"),"%D")}if(l.macd){let u=ab(e,r("macd","fastLen",12),r("macd","slowLen",26),r("macd","signalLen",9));s(u.line,r("macd","lineColor","#8fd9ff"),"MACD"),s(u.signal,r("macd","signalColor","#ffcf8e"),"Signal"),(d=u.hist)!=null&&d.length&&a(u.hist)}let c=rb(e);if(l.obv&&s(c.obv,r("obv","color","#8cf9ff"),"OBV"),l.adline&&s(c.adline,r("adline","color","#ffb7ff"),"A/D"),l.cmf&&s(gb(e,i("cmf",20)),r("cmf","color","#f8ff87"),"CMF"),l.williamsr&&s(mb(e,i("williamsr",14)),r("williamsr","color","#ff9adf"),"Williams %R"),l.cci&&s(fb(e,i("cci",20)),r("cci","color","#b8ff8e"),"CCI"),l.mfi&&s(ub(e,i("mfi",14)),r("mfi","color","#7bffd2"),"MFI"),l.uo&&s(hb(e),r("uo","color","#ffd36f"),"UO"),l.adx){let u=lb(e,i("adx",14));s(u.adx,r("adx","adxColor","#9fd8ff"),"ADX"),s(u.plusDi,r("adx","plusColor","#73ffc0"),"+DI"),s(u.minusDi,r("adx","minusColor","#ff9797"),"-DI")}if(l.aroon){let u=cb(e,i("aroon",14));s(u.up,r("aroon","upColor","#6cffb0"),"Aroon Up"),s(u.down,r("aroon","downColor","#ff8f8f"),"Aroon Down")}if(l.vortex){let u=db(e,i("vortex",14));s(u.plus.map(p=>({time:p.time,value:p.value*100})),r("vortex","plusColor","#d6a8ff"),"VI+"),s(u.minus.map(p=>({time:p.time,value:p.value*100})),r("vortex","minusColor","#ffb0f3"),"VI-")}}function $b(e){let t=e.querySelector(":scope > svg.xpd-ichimoku-cloud-svg");return t||(t=document.createElementNS("http://www.w3.org/2000/svg","svg"),t.setAttribute("class","xpd-ichimoku-cloud-svg"),e.appendChild(t)),t}function Sb(e){var t;(t=e==null?void 0:e.querySelector(":scope > svg.xpd-ichimoku-cloud-svg"))==null||t.remove()}function dd(e,t,n,s,a){var h;if(!e||!t||!n)return;let o=n.clientWidth||0,i=n.clientHeight||0;if(!o||!i||!(s!=null&&s.length)||!(a!=null&&a.length))return;let r=$b(n);r.setAttribute("width",o),r.setAttribute("height",i),r.setAttribute("viewBox",`0 0 ${o} ${i}`);let l=((h=C.indicatorSettings)==null?void 0:h.ichimoku)||{},c=l.bullColor||"#46ffa0",d=l.bearColor||"#ff7878",u=new Map(a.map(w=>[w.time,w.value])),p=e.timeScale(),m=[];for(let w of s){let k=u.get(w.time);if(k==null)continue;let b=p.timeToCoordinate(w.time),x=t.priceToCoordinate(w.value),S=t.priceToCoordinate(k);b==null||x==null||S==null||m.push({x:b,ya:x,yb:S,bullish:w.value>=k})}let f="",v=0;for(let w=1;w<=m.length;w+=1){if(!(w===m.length||m[w].bullish!==m[v].bullish))continue;let b=m.slice(v,w);if(b.length>=2){let x=b.map($=>`${$.x.toFixed(1)},${$.ya.toFixed(1)}`).join(" "),S=b.slice().reverse().map($=>`${$.x.toFixed(1)},${$.yb.toFixed(1)}`).join(" "),T=b[0].bullish?c:d;f+=`<polygon points="${x} ${S}" fill="${g(T)}" opacity="0.22" />`}v=w}r.innerHTML=f}function kc(e,t,n,s){var i;if(!C.indicators.ichimoku){Sb(s),ee.ichimokuData=null;return}let a=((i=C.indicatorSettings)==null?void 0:i.ichimoku)||{},o=ld(e,Number(a.tenkanLen)||9,Number(a.kijunLen)||26,Number(a.senkouBLen)||52);ee.ichimokuData={senkouA:o.senkouA,senkouB:o.senkouB},dd(t,n,s,o.senkouA,o.senkouB)}function ii(){let e=ee.ichimokuData,t=document.getElementById("xpd-tv-widget");e&&ee.chart&&ee.activeSeries&&t&&dd(ee.chart,ee.activeSeries,t,e.senkouA,e.senkouB)}async function Tb(){var n,s,a,o;let e=++Sn,t=document.getElementById("xpd-tv-widget");if(t){ee.chart||(t.innerHTML='<div class="xpd-loading">Loading full price history\u2026</div>');try{C.threeEnabled?Qv():Fs();let i=await wb(),r=wc(i);if(e!==Sn)return;if(!r.length)throw new Error("No chart bars returned for selected pair/timeframe.");Lb(r);let l=JSON.stringify({pair:C.pair,interval:C.interval,chartType:C.chartType,comparePair:C.comparePair,indicators:C.indicators,indicatorSettings:C.indicatorSettings,threeEnabled:C.threeEnabled});if(!C.comparePair&&!(C.drawings||[]).length&&ee.chart&&ee.configKey===l){let B=C.chartType==="heikin_ashi"?ni(r):r;C.chartType==="line"||C.chartType==="area"?ee.activeSeries.setData(B.map(ue=>({time:ue.time,value:ue.close}))):ee.activeSeries.setData(B),ee.volumeSeries.setData(r.map(ue=>({time:ue.time,value:ue.volume||0,color:ue.close>=ue.open?"rgba(38,166,154,0.5)":"rgba(239,83,80,0.5)"})));let J=0,re=0,pe=[];xc(r,{addOverlay:(ue,H,Y,me,De)=>{let Be=ee.indicatorSeries[J++];ue!=null&&ue.length&&(Be==null||Be.setData(ue),De&&Be&&pe.push({label:De,color:H,series:Be,points:ue}))},addOsc:(ue,H,Y)=>{let me=ee.indicatorSeries[J++];ue!=null&&ue.length&&(me==null||me.setData(ue),Y&&me&&pe.push({label:Y,color:H,series:me,points:ue}))},addOscHist:ue=>{let H=ee.indicatorSeries[J++];ue!=null&&ue.length&&(H==null||H.setData(ue.map(Y=>({time:Y.time,value:Y.value,color:Y.value>=0?"rgba(99,255,157,0.45)":"rgba(255,126,126,0.45)"}))))},addPriceLevel:ue=>{let H=ee.indicatorPriceLines[re++];Number.isFinite(ue)&&(H==null||H.applyOptions({price:ue}))}}),ee.indicatorLegendItems=pe,kc(r,ee.chart,ee.activeSeries,t),$c(ee.activeSeries);let Ce=r[r.length-1];(n=ee.renderLegend)==null||n.call(ee,Ce.open,Ce.high,Ce.low,Ce.close,Ce.volume);return}if(!await Jv())throw new Error("Chart library failed to load.");if(e!==Sn)return;let d=document.getElementById("xpd-tv-widget");if(!d||e!==Sn)return;let u=null;try{u=((s=ee.chart)==null?void 0:s.timeScale().getVisibleLogicalRange())||null}catch{}kb(),d.innerHTML="";let p=window.LightweightCharts,m=Math.max(320,d.clientWidth||((a=d.parentElement)==null?void 0:a.clientWidth)||320),f=Math.max(360,d.clientHeight||460),v=r.map(B=>B.low),h=r.map(B=>B.high),w=xb(r,Math.min(...v),Math.max(...h)),k={type:"price",precision:w,minMove:Math.pow(10,-w)},b="#26a69a",x="#ef5350",S=p.createChart(d,{width:m,height:f,layout:{background:{type:p.ColorType.Solid,color:"#131722"},textColor:"#d1d4dc"},grid:{vertLines:{color:"#242832"},horzLines:{color:"#242832"}},rightPriceScale:{borderColor:"rgba(197,203,206,0.3)"},leftPriceScale:{visible:!1,borderColor:"rgba(197,203,206,0.3)"},timeScale:{borderColor:"rgba(197,203,206,0.3)",timeVisible:!0,secondsVisible:!1},crosshair:{mode:p.CrosshairMode.Normal},handleScroll:!0,handleScale:!0}),T=C.chartType==="heikin_ashi"?ni(r):r,$;if(C.chartType==="line")$=S.addLineSeries({color:"#2962ff",lineWidth:2,priceFormat:k}),$.setData(T.map(B=>({time:B.time,value:B.close})));else if(C.chartType==="area")$=S.addAreaSeries({lineColor:"#2962ff",topColor:"rgba(41,98,255,0.36)",bottomColor:"rgba(41,98,255,0.04)",lineWidth:2,priceFormat:k}),$.setData(T.map(B=>({time:B.time,value:B.close})));else if(C.chartType==="bars")$=S.addBarSeries({upColor:b,downColor:x,priceFormat:k}),$.setData(T);else{let B=C.chartType==="hollow_candles";$=S.addCandlestickSeries({upColor:B?"rgba(0,0,0,0)":b,downColor:x,borderUpColor:b,borderDownColor:x,wickUpColor:b,wickDownColor:x,borderVisible:!0,priceFormat:k}),$.setData(T)}let P=S.addHistogramSeries({priceFormat:{type:"volume"},priceScaleId:"vol"});S.priceScale("vol").applyOptions({scaleMargins:{top:.85,bottom:0}}),P.setData(r.map(B=>({time:B.time,value:B.volume||0,color:B.close>=B.open?"rgba(38,166,154,0.5)":"rgba(239,83,80,0.5)"})));let M=document.createElement("div");M.className="xpd-chart-legend",d.appendChild(M);let N=B=>Number.isFinite(B)?B.toFixed(w):"\u2014",_=(B,J,re,pe,Se,ge)=>{let ot=pe>=B,it=(ge||[]).map(Ce=>`<span style="color:${g(Ce.color)}">${g(Ce.label)} <b>${N(Ce.value)}</b></span>`).join("");M.innerHTML=`
        <span>O <b>${N(B)}</b></span>
        <span>H <b>${N(J)}</b></span>
        <span>L <b>${N(re)}</b></span>
        <span class="${ot?"xpd-legend-up":"xpd-legend-down"}">C <b>${N(pe)}</b></span>
        ${Se!=null?`<span>Vol <b>${pt(Se)}</b></span>`:""}
        ${it}
      `},X=T[T.length-1],I=(o=r[r.length-1])==null?void 0:o.volume,R=()=>{if(!X)return;let B=X.open??X.value,J=X.high??X.value,re=X.low??X.value,pe=X.close??X.value,Se=(ee.indicatorLegendItems||[]).map(ge=>{var ot,it;return{label:ge.label,color:ge.color,value:(it=(ot=ge.points)==null?void 0:ot[ge.points.length-1])==null?void 0:it.value}}).filter(ge=>Number.isFinite(ge.value));_(B,J,re,pe,I,Se)};R(),S.subscribeCrosshairMove(B=>{var Ce,ue;if(!B.time){R();return}let J=(Ce=B.seriesData)==null?void 0:Ce.get($);if(!J){R();return}let re=(ue=B.seriesData)==null?void 0:ue.get(P),pe=J.open??J.value,Se=J.high??J.value,ge=J.low??J.value,ot=J.close??J.value,it=(ee.indicatorLegendItems||[]).map(H=>{var Y,me;return{label:H.label,color:H.color,value:(me=(Y=B.seriesData)==null?void 0:Y.get(H.series))==null?void 0:me.value}}).filter(H=>Number.isFinite(H.value));_(pe,Se,ge,ot,re==null?void 0:re.value,it)});let F=!1,W=()=>{F||(F=!0,S.priceScale("osc").applyOptions({scaleMargins:{top:.65,bottom:.18}}))},E=[],z=[],Q=[];xc(r,{addOverlay:(B,J,re=1.2,pe=!1,Se="")=>{if(!(B!=null&&B.length))return;let ge=S.addLineSeries({color:J,lineWidth:re,lineStyle:pe?p.LineStyle.Dashed:p.LineStyle.Solid,priceLineVisible:!1,lastValueVisible:!1});ge.setData(B),E.push(ge),Se&&Q.push({label:Se,color:J,series:ge,points:B})},addOsc:(B,J,re="")=>{if(!(B!=null&&B.length))return;W();let pe=S.addLineSeries({color:J,lineWidth:1.2,priceScaleId:"osc",title:re,priceLineVisible:!1,lastValueVisible:!1});pe.setData(B),E.push(pe),re&&Q.push({label:re,color:J,series:pe,points:B})},addOscHist:B=>{if(!(B!=null&&B.length))return;W();let J=S.addHistogramSeries({priceScaleId:"osc",priceLineVisible:!1,lastValueVisible:!1});J.setData(B.map(re=>({time:re.time,value:re.value,color:re.value>=0?"rgba(99,255,157,0.45)":"rgba(255,126,126,0.45)"}))),E.push(J)},addPriceLevel:(B,J,re="")=>{Number.isFinite(B)&&z.push($.createPriceLine({price:B,color:J,lineWidth:1,lineStyle:p.LineStyle.Dashed,axisLabelVisible:!0,title:re}))}}),kc(r,S,$,d),S.timeScale().subscribeVisibleLogicalRangeChange(ii);let fe=null;if(C.comparePair){let B=Mn.find(J=>J.id===C.comparePair);if(B){let J=wc(await cd(B,C.interval));if(e===Sn&&J.length){let re=J[0].close||1;fe=S.addLineSeries({color:"#ffd166",lineWidth:1.4,priceScaleId:"left",priceLineVisible:!1,lastValueVisible:!0,priceFormat:{type:"custom",formatter:pe=>`${pe>=0?"+":""}${pe.toFixed(2)}%`,minMove:.01}}),S.priceScale("left").applyOptions({visible:!0,borderColor:"rgba(255,209,102,0.35)"}),fe.setData(J.map(pe=>({time:pe.time,value:(pe.close/re-1)*100})))}}}else S.priceScale("left").applyOptions({visible:!1});if(e!==Sn){try{S.remove()}catch{}return}let K=(C.drawings||[]).filter(B=>Number.isFinite(B==null?void 0:B.price)).map(B=>$.createPriceLine({price:B.price,color:"#78e5ff",lineWidth:2,lineStyle:p.LineStyle.Dashed,axisLabelVisible:!0,title:"Line"}));if(S.subscribeClick(B=>{if(C.drawingTool!=="hline"||!B.point)return;let J=$.coordinateToPrice(B.point.y);Number.isFinite(J)&&(C.drawings=[...C.drawings||[],{price:J}].slice(-50),K.push($.createPriceLine({price:J,color:"#78e5ff",lineWidth:2,lineStyle:p.LineStyle.Dashed,axisLabelVisible:!0,title:"Line"})))}),u&&Number.isFinite(u.from)&&Number.isFinite(u.to))try{S.timeScale().setVisibleLogicalRange(u)}catch{S.timeScale().fitContent()}else S.timeScale().fitContent();let xe=new ResizeObserver(()=>{S.applyOptions({width:Math.max(320,d.clientWidth||320)}),ii()});xe.observe(d),ee={chart:S,volumeSeries:P,activeSeries:$,compareSeries:fe,indicatorSeries:E,indicatorPriceLines:z,priceLines:K,resizeObserver:xe,chartType:C.chartType,configKey:l,legendEl:M,renderLegend:_,indicatorLegendItems:Q,alertPriceLines:[]},$c($)}catch(i){if(e!==Sn)return;if(C.error=(i==null?void 0:i.message)||"Could not initialize chart widget.",ee.chart){be(C.error);return}let r=document.getElementById("xpd-tv-widget");r&&(r.innerHTML=`<div class="xpd-error">${g(C.error)}</div>`)}}}function pd(){let e=Z(Qo)==="1"?"0":"1";te(Qo,e),q()}async function ud(e){Mn.some(t=>t.id===e)&&(C.pair=e,await Is(),$t(),q())}async function md(e){C.interval=e,await Is(),$t(),q()}function fd(e){C.chartType=e,$t(),q()}async function hd(){await Is(),q()}function gd(e,t){e in C.indicators&&(C.indicators[e]=!!t,t&&(C.selectedIndicator=e,C.selectedEducationTab="indicator"),$t(),q())}function vd(){C.indicatorMenuOpen=!C.indicatorMenuOpen,q()}function bd(){C.moreMenuOpen=!C.moreMenuOpen,q()}function yd(e){C.indicatorQuery=String(e||""),C.indicatorMenuOpen||(C.indicatorMenuOpen=!0),q()}function wd(e){let t=String(e||"").trim();t in C.indicators&&(C.indicators[t]=!0,C.selectedIndicator=t,C.selectedEducationTab="indicator",$t(),q())}function xd(e){let t=String(e||"").trim();t in C.indicators&&(C.indicators[t]=!1,$t(),q())}function Cb(e){var s,a;if(C.settingsOpenFor!==e)return"";let t=C.indicatorSettings[e]||{},n=mi[e]||[];return`
    <div class="xpd-indicator-settings" role="dialog" aria-label="${g(((s=Ht[e])==null?void 0:s.name)||e)} settings">
      <div class="xpd-indicator-settings-title">${g(((a=Ht[e])==null?void 0:a.name)||e)} settings</div>
      ${n.map(o=>{let i=t[o.id]??o.default;return o.type==="number"?`
            <label class="xpd-indicator-settings-field">
              <span>${g(o.label)}</span>
              <input id="xpd-ind-${o.id}-${e}" class="xpd-input" type="number" min="2" max="500" value="${i}" />
            </label>`:`
          <label class="xpd-indicator-settings-field">
            <span>${g(o.label)}</span>
            <input id="xpd-ind-${o.id}-${e}" class="xpd-indicator-color-input" type="color" value="${i}" />
          </label>`}).join("")}
      ${n.length?"":'<div class="xpd-note">This indicator has no adjustable settings yet.</div>'}
      <div class="xpd-indicator-settings-actions">
        <button class="xpd-mini-btn" onclick="resetIndicatorSettings('${e}')">Reset</button>
        <button class="xpd-mini-btn" onclick="closeIndicatorSettings()">Cancel</button>
        <button class="xpd-action xpd-action--primary" onclick="applyIndicatorSettings('${e}')">Save</button>
      </div>
    </div>`}function kd(e){let t=String(e||"").trim();t in C.indicators&&(C.settingsOpenFor=C.settingsOpenFor===t?null:t,q())}function $d(){C.settingsOpenFor=null,q()}function Sd(e){let t=String(e||"").trim();if(!(t in C.indicators))return;let n=C.indicatorSettings[t]||{},s={...n};for(let a of mi[t]||[]){let o=document.getElementById(`xpd-ind-${a.id}-${t}`);o&&(a.type==="number"?s[a.id]=Math.max(2,Math.min(500,Number(o.value)||n[a.id]||a.default)):s[a.id]=o.value)}C.indicatorSettings[t]=s,C.settingsOpenFor=null,q()}function Td(e){let t=String(e||"").trim();delete C.indicatorSettings[t],C.settingsOpenFor=null,q()}function Cd(){$t(),Li(window.location.href),ne("Chart link copied.")}function Ld(){C.threeEnabled=!C.threeEnabled,te(ui,C.threeEnabled?"1":"0"),C.threeEnabled||Fs(),q()}function Md(e){let t=!!e;C.threeEnabled!==t&&(C.threeEnabled=t,te(ui,C.threeEnabled?"1":"0"),C.threeEnabled||Fs(),q())}function Pd(e){C.comparePair=e||"",$t(),q()}function Ad(e){let t=String(e||"").trim();!t||!(t in C.indicators)||(C.indicators[t]=!0,C.selectedIndicator=t,q())}function Ed(e){let t=String(e||"none");Xc.some(n=>n.key===t)&&(C.drawingTool=t,C.educationHint=yv[t]||"",q())}function _a(){var e;return((e=C.chartMeta)==null?void 0:e.tokenKey)||C.tokenFocusKey||`${Na().symbol||"XRP"}|`}function Nd(){var s,a;let e=Number((s=C.chartMeta)==null?void 0:s.last),t=prompt(`Alert me when ${((a=C.chartMeta)==null?void 0:a.symbol)||"price"} crosses:`,Number.isFinite(e)?e.toFixed(6):"");if(t==null)return;let n=Number(t);if(!Number.isFinite(n)||n<=0){be("Enter a valid price.");return}C.alerts=[...C.alerts||[],{id:`alert_${Date.now()}`,tokenKey:_a(),price:n,createdAt:new Date().toISOString()}],hi(),q(),ne(`Alert set at $${D(n,6)}`)}function _d(e){C.alerts=(C.alerts||[]).filter(t=>t.id!==e),hi(),q()}function $c(e){if(!e)return;let t=window.LightweightCharts;for(let s of ee.alertPriceLines||[])try{e.removePriceLine(s)}catch{}let n=(C.alerts||[]).filter(s=>s.tokenKey===_a());ee.alertPriceLines=n.map(s=>{var a;return e.createPriceLine({price:s.price,color:"#ffb703",lineWidth:2,lineStyle:((a=t==null?void 0:t.LineStyle)==null?void 0:a.Dotted)??2,axisLabelVisible:!0,title:"\u{1F514} Alert"})})}function Lb(e){var r,l;if(e.length<2)return;let t=_a(),n=(C.alerts||[]).filter(c=>c.tokenKey===t);if(!n.length)return;let s=e[e.length-2].close,a=e[e.length-1].close,o=[],i=!1;for(let c of n){let d=s<c.price&&a>=c.price,u=s>c.price&&a<=c.price;d||u?(ne(`\u{1F514} ${((r=C.chartMeta)==null?void 0:r.symbol)||"Price"} crossed $${D(c.price,6)} (${d?"\u2191":"\u2193"} now $${D(a,6)})`),i=!0,(l=document.querySelector(`.xpd-indicator-chip[data-alert-id="${c.id}"]`))==null||l.remove()):o.push(c)}i&&(C.alerts=[...(C.alerts||[]).filter(c=>c.tokenKey!==t),...o],hi())}function Rd(){let e=ee.activeSeries;if(e)for(let t of ee.priceLines||[])try{e.removePriceLine(t)}catch{}ee.priceLines=[],C.drawings=[]}function Ra(e,t=0){var i;let n=(i=ee.chart)==null?void 0:i.timeScale();if(!n)return;let s=n.getVisibleLogicalRange();if(!s)return;let a=(s.to-s.from)*e,o=(s.to+s.from)/2+(s.to-s.from)*t;n.setVisibleLogicalRange({from:o-a/2,to:o+a/2})}function Dd(){Ra(.8)}function Id(){Ra(1.25)}function Fd(){Ra(1,-.2)}function Bd(){Ra(1,.2)}function Od(){C.educationCollapsed=!C.educationCollapsed,q()}function Xd(e){["indicator","psychology","practice"].includes(e)&&(C.selectedEducationTab=e,q())}function Hd(){let e=document.body.classList.contains("theme-gold");un(e?"cosmic":"gold"),q()}var Sc=!1;function Mb(){let e=document.getElementById("xpd-tv-widget");e&&ee.chart&&(ee.chart.applyOptions({width:Math.max(320,e.clientWidth||320),height:Math.max(320,e.clientHeight||460)}),ii())}function zd(){var t;let e=document.querySelector(".xpd-chart-wrap");e&&(Sc||(Sc=!0,document.addEventListener("fullscreenchange",()=>{requestAnimationFrame(()=>requestAnimationFrame(Mb))})),document.fullscreenElement?document.exitFullscreen():(t=e.requestFullscreen)==null||t.call(e))}function Ud(){let e=ee.chart;if(!e){be("Chart image is not ready yet.");return}let t=e.takeScreenshot(),n=document.createElement("a");n.download=`xrpl-chart-${Date.now()}.png`,n.href=t.toDataURL("image/png"),n.click()}function Wd(){return C.tokenFocusKey||C.pair||"default"}function jd(){var n;let e=ve(Z(Zo))||{},t=Wd();e[t]={interval:C.interval,chartType:C.chartType,comparePair:C.comparePair,indicators:C.indicators,indicatorSettings:C.indicatorSettings},te(Zo,JSON.stringify(e)),ne(`Chart layout saved for ${((n=C.chartMeta)==null?void 0:n.symbol)||t}.`)}function qd(){var s;let e=ve(Z(Zo))||{},t=Wd(),n=e[t];if(!n){be(`No saved layout for ${((s=C.chartMeta)==null?void 0:s.symbol)||t} yet.`);return}C.interval=n.interval||C.interval,C.chartType=n.chartType||C.chartType,C.comparePair=n.comparePair||"",C.indicators={...C.indicators,...n.indicators||{}},C.indicatorSettings={...C.indicatorSettings,...n.indicatorSettings||{}},$t(),q()}function Da(e){let t=String(e||"").trim();if(/^[0-9A-F]{40}$/i.test(t)){let n=t.replace(/(00)+$/g,"");if(/^[0-9A-F]+$/i.test(n)&&n.length%2===0)try{let s=new Uint8Array(n.length/2);for(let o=0;o<n.length;o+=2)s[o/2]=parseInt(n.slice(o,o+2),16);let a=new TextDecoder().decode(s).replace(/\0/g,"").trim();if(a)return a.toUpperCase()}catch{}}return t.toUpperCase()}function ht(e){return`${e.symbol}|${e.issuer||""}`}function Pb(e){var l,c,d,u,p,m,f,v,h,w;let t=Da(e.code||e.currency||""),n=String(e.issuer||((l=e.IssuingAccount)==null?void 0:l.account)||"").trim(),s=Number(e.price??((c=e.metrics)==null?void 0:c.price)??0),a=Number(e.marketcap??((d=e.metrics)==null?void 0:d.marketcap)??0),o=Number(((u=e.metrics)==null?void 0:u.volume_24h)??0),i=((m=(p=e.meta)==null?void 0:p.token)==null?void 0:m.name)||((f=e.IssuingAccount)==null?void 0:f.name)||t||"Unknown Token",r=Number(e.holders??((v=e.metrics)==null?void 0:v.holders)??((h=e.metrics)==null?void 0:h.trustlines)??0);return{symbol:t,name:i,issuer:n,tokenId:e.id||`${t}.${n}`,price:Number.isFinite(s)&&s>0?s:null,marketCap:Number.isFinite(a)&&a>0?a:null,volume24h:Number.isFinite(o)?o:null,holders:Number.isFinite(r)?r:null,change24h:null,verified:!!((w=e.IssuingAccount)!=null&&w.verified),score:Number(e.score||0)||null}}function Ab(e){let t=Da((e==null?void 0:e.symbol)||""),n=String((e==null?void 0:e.name)||t||"Unknown Token"),s=Number((e==null?void 0:e.current_price)||0),a=Number((e==null?void 0:e.market_cap)||0),o=Number((e==null?void 0:e.total_volume)||0),i=Number((e==null?void 0:e.price_change_percentage_24h)||0);return{symbol:t,name:n,issuer:"",tokenId:`cg:${(e==null?void 0:e.id)||t}`,price:Number.isFinite(s)&&s>0?s:null,marketCap:Number.isFinite(a)&&a>0?a:null,volume24h:Number.isFinite(o)&&o>0?o:null,holders:null,change24h:Number.isFinite(i)?i:null,verified:!1,score:null}}function Eb(e){var r;let t=Da((e==null?void 0:e.currency)||(e==null?void 0:e.token)||""),n=String((e==null?void 0:e.issuer)||(e==null?void 0:e.account)||"").trim(),s=String((e==null?void 0:e.name)||t||"Unknown Token"),a=Number((e==null?void 0:e.price)||((r=e==null?void 0:e.market)==null?void 0:r.price)||0),o=Number((e==null?void 0:e.marketcap)||(e==null?void 0:e.marketCap)||0),i=Number((e==null?void 0:e.volume24h)||(e==null?void 0:e.volume)||0);return{symbol:t,name:s,issuer:n,tokenId:`bithomp:${t}.${n||"na"}`,price:Number.isFinite(a)&&a>0?a:null,marketCap:Number.isFinite(o)&&o>0?o:null,volume24h:Number.isFinite(i)&&i>0?i:null,holders:Number.isFinite(Number((e==null?void 0:e.holders)||0))?Number((e==null?void 0:e.holders)||0):null,change24h:Number.isFinite(Number((e==null?void 0:e.change24h)||0))?Number((e==null?void 0:e.change24h)||0):null,verified:!!(e!=null&&e.verified),score:null}}function Nb(e){let t=Da((e==null?void 0:e.symbol)||(e==null?void 0:e.currency)||""),n=String((e==null?void 0:e.issuer)||(e==null?void 0:e.issuerAddress)||"").trim(),s=String((e==null?void 0:e.name)||t||"Unknown Token"),a=Number((e==null?void 0:e.price)||0),o=Number((e==null?void 0:e.volume24h)||0);return{symbol:t,name:s,issuer:n,tokenId:`xrplto:${t}.${n||"na"}`,price:Number.isFinite(a)&&a>0?a:null,marketCap:Number.isFinite(Number((e==null?void 0:e.marketCap)||0))?Number((e==null?void 0:e.marketCap)||0):null,volume24h:Number.isFinite(o)&&o>0?o:null,holders:Number.isFinite(Number((e==null?void 0:e.holders)||0))?Number((e==null?void 0:e.holders)||0):null,change24h:Number.isFinite(Number((e==null?void 0:e.change24h)||0))?Number((e==null?void 0:e.change24h)||0):null,verified:!!(e!=null&&e.verified),score:null}}async function Vd(){var e,t,n,s,a,o;if(Ma()){j.loading=!0,j.error="";try{let i=Date.now(),r=mc.get("tokens");if(r&&i-r.ts<6e4){j.tokens=r.data,j.total=r.total||r.data.length,j.lastSyncAt=r.ts,j.filtered=Pa(j.query,r.data),j.trending=Tc(r.data),j.loading=!1;return}let l=500,c=12,d=[];for(let T=1;T<=c;T+=1){let $=await kt(`${tv}?page=${T}&limit=${l}`,{allowProxy:!1,timeoutMs:12e3});if(!Array.isArray($)||!$.length||(d.push(...$),$.length<l))break}let u=d.map(Pb).filter(T=>!!T.symbol&&!!T.issuer),p=[kt(`${nv}?vs_currency=usd&order=market_cap_desc&per_page=250&page=1&sparkline=false`,{timeoutMs:12e3}).catch(()=>[]),Date.now()<(gc.xrplto||0)?Promise.resolve([]):kt(av,{timeoutMs:12e3,allowProxy:!1}).catch(T=>(String((T==null?void 0:T.message)||"").includes("429")&&(gc.xrplto=Date.now()+5*60*1e3),[]))];ov&&p.push(kt(sv,{timeoutMs:12e3,allowProxy:!1}).catch(()=>[]));let[m,f,v=[]]=await Promise.all(p),h=Array.isArray(m)?m.map(Ab).filter(T=>!!T.symbol):[],w=Array.isArray(v)?v.map(Eb).filter(T=>!!T.symbol):[],k=Array.isArray(f)?f.map(Nb).filter(T=>!!T.symbol):[],b={symbol:"XRP",name:"XRP Ledger Native",issuer:"",tokenId:"XRP",price:((e=Te.data)==null?void 0:e.priceUsd)||((t=C.stats)==null?void 0:t.price)||null,marketCap:((n=Te.data)==null?void 0:n.marketCap)||null,volume24h:((s=Te.data)==null?void 0:s.volume24h)||null,holders:null,change24h:((a=Te.data)==null?void 0:a.change24h)||((o=C.stats)==null?void 0:o.changePct)||null,verified:!0,score:1},x=new Map;[b,...u,...w,...k,...h].forEach(T=>{let $=ht(T);x.has($)||x.set($,T)});let S=[...x.values()];mc.set("tokens",{ts:i,data:S,total:S.length}),j.tokens=S,j.total=S.length,j.lastSyncAt=i,j.filtered=Pa(j.query,S),j.trending=Tc(S)}catch(i){j.error=(i==null?void 0:i.message)||"Could not load XRPL token discovery data."}finally{j.loading=!1}}}function Pa(e,t){let n=String(e||"").trim().toLowerCase(),s=j.filters||{type:"all",minCap:0,minVol:0,hasDex:!1};return t.filter(a=>{if(n&&!`${a.symbol} ${a.name} ${a.issuer} ${a.tokenId||""}`.toLowerCase().includes(n)||Number(s.minCap||0)>0&&Number(a.marketCap||0)<Number(s.minCap||0)||Number(s.minVol||0)>0&&Number(a.volume24h||0)<Number(s.minVol||0)||s.hasDex&&!(Number(a.volume24h||0)>0||Number(a.holders||0)>100))return!1;if(s.type&&s.type!=="all"){let o=String(a.symbol||"").toLowerCase(),i=String(a.name||"").toLowerCase(),r=/usd|usdc|usdt|rlusd|eur|gbp/.test(o)||/stable/.test(i),l=/meme|dog|cat|frog|shib|pepe/.test(o)||/meme/.test(i),c=/mpt/.test(o)||/multi-purpose/.test(i);if(s.type==="stablecoin"&&!r||s.type==="meme"&&!l||s.type==="mpt"&&!c||s.type==="standard"&&(r||l||c))return!1}return!0})}function Tc(e){return[...e].sort((t,n)=>{let s=Number(t.volume24h||0),a=Number(n.volume24h||0);if(a!==s)return a-s;let o=Number(t.marketCap||0);return Number(n.marketCap||0)-o}).slice(0,24)}async function Gd(e){if(wt.loading=!0,wt.error="",wt.items=[],!e){wt.loading=!1;return}try{let t=await ki(e,20);wt.items=t||[]}catch(t){wt.error=(t==null?void 0:t.message)||"Could not load recent transactions."}finally{wt.loading=!1}}function Kd(e){j.query=e,qo&&clearTimeout(qo),qo=setTimeout(()=>{j.listLimit=240,j.filtered=Pa(j.query,j.tokens),q()},300)}function Jd(e,t){j.filters={...j.filters,[e]:t},j.listLimit=240,j.filtered=Pa(j.query,j.tokens),q()}function Yd(){j.listLimit=Math.min(5e3,Number(j.listLimit||240)+240),q()}function Qd(){let e=j.filtered.length?j.filtered:j.tokens;j.listLimit=Math.min(5e3,Math.max(240,e.length)),q()}function Zd(){j.listLimit=240,q()}function ep(e){j.selectedTokenKey=e||"",q()}function tp(e){let t=String(e||"").trim();if(!t)return;let n=gi();n.includes(t)||n.push(t),Gc(n),q()}function np(e){let t=String(e||"").trim(),n=gi().filter(s=>s!==t);Gc(n),q()}async function Ia(e){let t=String(e||"").trim();if(!t)return;let n=String(t.includes("|")?t.split("|")[0]:t).toUpperCase(),s=t.includes("|")?j.tokens.find(o=>ht(o)===t):j.tokens.find(o=>String(o.symbol||"").toUpperCase()===String(n||"").toUpperCase());j.selectedTokenKey=s?ht(s):t.includes("|")?t:j.selectedTokenKey,C.tokenFocusKey=j.selectedTokenKey||t;let a={BTC:"BINANCE:BTCUSDT",ETH:"BINANCE:ETHUSDT",SOL:"BINANCE:SOLUSDT"};C.pair=a[n]||"BITSTAMP:XRPUSD",$t(),q(),setTimeout(()=>$v(),20),await Is(),$t(),q()}async function sp(e){return Ia(e)}async function ap(){await Vd(),q()}async function op(){let e=document.getElementById("xpd-lookup-currency"),t=document.getElementById("xpd-lookup-issuer"),n=String((e==null?void 0:e.value)||"").trim().toUpperCase(),s=String((t==null?void 0:t.value)||"").trim();if(!n){be("Enter a currency code first.");return}if(!s||!Ue(s)){be("Enter a valid XRPL issuer address.");return}let a=`${n}|${s}`,o=j.tokens.find(i=>ht(i)===a);o||(o={symbol:n,name:n,issuer:s,price:null,marketCap:null,volume24h:null,holders:null,tokenId:""},j.tokens=[...j.tokens,o]),j.selectedTokenKey=a,e&&(e.value=""),t&&(t.value=""),await Ia(a)}async function ip(){var t;let e=((t=St())==null?void 0:t.address)||"";await Gd(e),q()}async function ns({silent:e=!1,force:t=!1}={}){var s;if(!t&&!Ma())return;let n=((s=St())==null?void 0:s.address)||"";e||ne("Refreshing XRPL dashboard data..."),await Promise.allSettled([Is(),Kc(),Vd(),Gd(n),Jc(n),Yc(n),Zc()]),q()}function rp(){return Kc()}function lp(){var e;return Jc(((e=St())==null?void 0:e.address)||"")}function cp(){var e;return Yc(((e=St())==null?void 0:e.address)||"")}function dp(){return Zc()}function pp(e){ne(`NFT ${e.slice(0,12)}... selected. Send flow can be wired to NFTokenCreateOffer.`)}function Ds(){let e=y("profile-metrics-row");if(!e)return;let t=!1,n=Object.values(Ve).reduce((u,p)=>u+((p==null?void 0:p.xrp)||0),0),s=up(),a=Object.values(Ve).flatMap(u=>(u==null?void 0:u.tokens)||[]),o=St(),i=o?Ps[o.address]:null,r=(i==null?void 0:i.ownerCount)||0,l=Ta+r*Ca,c=o!=null&&o.createdAt?Rb(new Date(o.createdAt)):"\u2014",d=(i==null?void 0:i.sequence)!=null?i.sequence:"\u2014";e.innerHTML=`
    <div class="pmetric"><div class="pmetric-val">${t?"\u2022\u2022\u2022\u2022":D(n,2)}</div><div class="pmetric-label">Total XRP</div></div>
    <div class="pmetric pmetric-divider"></div>
    <div class="pmetric"><div class="pmetric-val ${s&&!t?"pmetric-usd":""}">
      ${t?"\u2022\u2022\u2022\u2022":s?"$"+D(n*s,2):"\u2014"}</div>
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
      <div class="pmetric-label">Reserved</div></div>`:""}`,o&&(!Ps[o.address]||Date.now()-Ps[o.address].fetchedAt>6e4)&&_b(o.address).then(()=>Ds())}async function _b(e){try{let t=await Je({method:"account_info",params:[{account:e,ledger_index:"validated"}]});t!=null&&t.account_data&&(Ps[e]={sequence:t.account_data.Sequence,ownerCount:t.account_data.OwnerCount||0,fetchedAt:Date.now()})}catch{}}function Rb(e){let t=Math.floor((Date.now()-e.getTime())/864e5);if(t<1)return"Today";if(t<30)return`${t}d`;if(t<365)return`${Math.floor(t/30)}mo`;let n=Math.floor(t/365),s=Math.floor(t%365/30);return s?`${n}y ${s}mo`:`${n}y`}function up(){var t;if(Array.isArray((t=window.__dashSeries)==null?void 0:t.marketPrice)){let n=window.__dashSeries.marketPrice.at(-1);if(n!=null&&Number.isFinite(n))return n}let e=document.getElementById("mkt-price");if(e){let n=parseFloat(e.textContent.replace("$",""));if(!isNaN(n))return n}return 0}function Db(){let e=oe.length>0,t=Object.values(ze).some(Boolean),n=!!le.bio,s=!!localStorage.getItem("naluxrp_last_backup_ts"),a=[e,t,n,s].filter(Boolean).length;return a===4?"":`
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
  </div>`}function Fa(){let e=y("profile-tab-social");if(!e)return;let t=Object.values(ze).filter(Boolean).length;e.innerHTML=`
    <div class="social-section-head">
      <div class="social-section-title">Social &amp; Community Links</div>
      <div class="social-section-sub">${t} of ${as.length} connected \xB7 stored locally only</div>
    </div>
    <div class="social-grid">
      ${as.map(n=>{let s=ze[n.id]||"",a=!!s;return`<div class="social-card ${a?"social-card--connected":""}" id="social-item-${n.id}">
          <div class="social-card-left">
            <div class="social-platform-badge social-platform-badge--${n.id}">${n.icon}</div>
            <div class="social-card-info">
              <div class="social-card-name">${g(n.label)}</div>
              <div class="social-card-handle ${a?"":"dim"}">${a?g("@"+s):"Not connected"}</div>
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
    </div>`:""}`,Aa("stat-socials-val",t)}function mp(e){let t=as.find(l=>l.id===e);if(!t)return;let n=y("social-modal");if(!n)return;let s=y("social-modal-icon"),a=y("social-modal-title"),o=y("social-modal-sub"),i=y("social-modal-input"),r=y("social-modal-delete");s&&(s.className=`social-platform-icon-lg social-icon ${t.id}`,s.textContent=t.icon),a&&(a.textContent=`Connect ${t.label}`),o&&(o.textContent=`Enter your ${t.label} ${t.id==="discord"?"user ID or username":"username"}.`),i&&(i.value=ze[e]||"",i.placeholder=`Your ${t.label} handle`),r&&(r.style.display=ze[e]?"":"none"),n.dataset.platform=e,n.classList.add("show"),setTimeout(()=>i==null?void 0:i.focus(),80)}function fp(){let e=y("social-modal"),t=e==null?void 0:e.dataset.platform,n=y("social-modal-input");if(!t||!n)return;let s=n.value.trim().replace(/^@/,"");s?ze[t]=s:delete ze[t],jc(),Fa(),os();let a=as.find(o=>o.id===t);fy(),gt("social_connected",`${(a==null?void 0:a.label)||t} @${s||"(removed)"}`),ne(`${a==null?void 0:a.label} updated`)}function hp(){var t;let e=(t=y("social-modal"))==null?void 0:t.dataset.platform;e&&(delete ze[e],jc(),Fa(),os(),gt("social_removed",e),ne("Social connection removed"))}function gp(e){let t=as.find(n=>n.id===e);t&&ze[e]&&window.open(`${t.prefix}${ze[e]}`,"_blank","noopener")}function os(){var e;(e=y("social-modal"))==null||e.classList.remove("show")}function at(){let e=y("profile-tab-wallets");if(!e)return;if(oe.length===0){e.innerHTML=Db()+`
      <div class="wallets-empty">
        <div class="wallets-empty-icon">\u{1F48E}</div>
        <div class="wallets-empty-title">No wallets yet</div>
        <div class="wallets-empty-sub">Generate your first XRPL wallet \u2014 your seed is encrypted with AES-256-GCM and never leaves this device.</div>
        <button class="btn-create-wallet-hero" onclick="openWalletCreator()">\u26A1 Generate XRPL Wallet</button>
      </div>`,Aa("stat-wallets-val",0);return}let t=oe.length>3?`
    <div class="wallet-filter-row">
      <input class="wallet-filter-input" id="wallet-filter-input" type="text"
        placeholder="\u{1F50D} Filter wallets\u2026" value="${g(ts)}"
        oninput="filterWallets(this.value)">
      ${ts?`<button class="wallet-filter-clear" onclick="filterWallets('')">\u2715</button>`:""}
    </div>`:"",n=oe.filter(a=>!ts||a.label.toLowerCase().includes(ts.toLowerCase())||a.address.toLowerCase().includes(ts.toLowerCase())),s=n.map((a,o)=>Ib(a,oe.indexOf(a))).join("");e.innerHTML=t+(n.length?s:`<div class="wcard-empty">No wallets match "${g(ts)}"</div>`)+`
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
    </div>`,Aa("stat-wallets-val",oe.length)}function Ib(e,t){let n=e.id===st,s=!!e.watchOnly,a=Ve[e.address],o=Ps[e.address],r=!0||s,l=(o==null?void 0:o.ownerCount)||0,c=Ta+l*Ca,d=r?a?D(a.xrp,2):"\u2014":"\u2022\u2022\u2022\u2022",u=a&&r?Math.max(0,a.xrp-c):null,p=(a==null?void 0:a.tokens)||[],m=a!=null&&a.fetchedAt?qc(a.fetchedAt):null,f=e.address.slice(0,8)+"\u2026"+e.address.slice(-6),v=xi(e.address);return`
  <div class="wcard ${n?"wcard--active":""} ${s?"wcard--watch":""}" id="wallet-item-${e.id}" style="--i:${t}">
    <div class="wcard-top">
      <div class="wcard-icon" style="background:${e.color}18;border-color:${e.color}44;color:${e.color}">${g(e.emoji||"\u{1F48E}")}</div>
      <div class="wcard-identity">
        <div class="wcard-name-row">
          <span class="wcard-name">${g(e.label||"Unnamed")}</span>
          ${n?'<span class="wcard-badge wcard-badge--active">\u25CF Active</span>':""}
          ${s?'<span class="wcard-badge wcard-badge--watch">\u{1F441} Watch</span>':""}
          ${e.testnet?'<span class="wcard-badge wcard-badge--testnet">Testnet</span>':'<span class="wcard-badge wcard-badge--mainnet">Mainnet</span>'}
        </div>
        <div class="wcard-address mono" title="${g(e.address)}" onclick="copyToClipboard('${g(e.address)}')">${f} <span class="wcard-copy-hint">\u29C9</span></div>
        <div class="wcard-algo-row">
          ${s?'<span class="wcard-enc">\u{1F50D} Read-only</span>':`<span class="wcard-algo">${g((e.algo||"ed25519").toUpperCase())}</span>
               <span class="wcard-enc">\u{1F510} AES-256-GCM</span>`}
        </div>
      </div>
      <div class="wcard-balance-col">
        ${v.length>=2?`<div class="wcard-sparkline">${Mp(v,70,22,e.color||"#00fff0")}</div>`:""}
        <div class="wcard-xrp ${r?"":"wcard-balance-locked"}">${d} <span class="wcard-xrp-label">XRP</span></div>
        ${u!==null&&r?`<div class="wcard-avail" title="${c} XRP reserved">${D(u,2)} avail.</div>`:""}
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
      ${p.slice(0,6).map(h=>{let w=h.currency.length>4?Pi(h.currency)||h.currency.slice(0,4)+"\u2026":h.currency;return`<div class="wcard-token-chip" onclick="openTokenDetailsModal('${g(h.currency)}','${g(h.issuer)}','${g(e.address)}')" title="${g(h.currency)}">
          <span class="wcard-token-cur">${g(w)}</span>
          <span class="wcard-token-bal">${D(parseFloat(h.balance||0),4)}</span>
        </div>`}).join("")}
      ${p.length>6?`<div class="wcard-token-chip wcard-token-more" onclick="openTokenDetailsModal('${g(p[6].currency)}','${g(p[6].issuer)}','${g(e.address)}')">+${p.length-6}</div>`:""}
    </div>`:""}

    <div class="wcard-actions">
      ${s?"":`<button class="wcard-btn wcard-btn--send" onclick="openSendModal('${e.id}')">\u2B06 Send</button>`}
      <button class="wcard-btn wcard-btn--receive" onclick="openReceiveModal('${e.id}')">\u2B07 Receive</button>
      ${s?"":`<button class="wcard-btn wcard-btn--trust" onclick="openTrustlineModal('${e.id}')">\u{1F517} Trust</button>`}
      <button class="wcard-btn wcard-btn--inspect" onclick="inspectWalletAddr('${g(e.address)}')">\u{1F50D} Inspect</button>
      ${n?"":`<button class="wcard-btn wcard-btn--setactive" onclick="setActiveWallet('${e.id}')">\u2605 Active</button>`}
      <button class="wcard-btn wcard-btn--expand ${Tn===e.id?"wcard-btn--expand-open":""}" onclick="toggleWalletDrawer('${e.id}')">${Tn===e.id?"\u25B2 Hide":"\u25BC Details"}</button>
      <button class="wcard-btn wcard-btn--remove" onclick="deleteWallet(${t})">\u2715</button>
    </div>

    ${Tn===e.id?`
    <div class="wcard-drawer" id="wcard-drawer-${e.id}">
      <div class="wcard-drawer-tabs">
        <button class="wdt-btn ${(rn[e.id]||"txns")==="txns"?"active":""}" onclick="switchWalletDrawerTab('${e.id}','txns')">\u{1F4CB} Transactions</button>
        <button class="wdt-btn ${(rn[e.id]||"txns")==="nfts"?"active":""}" onclick="switchWalletDrawerTab('${e.id}','nfts')">\u{1F3A8} NFTs</button>
        <button class="wdt-btn ${(rn[e.id]||"txns")==="orders"?"active":""}" onclick="switchWalletDrawerTab('${e.id}','orders')">\u{1F4CA} DEX</button>
        <button class="wdt-btn ${(rn[e.id]||"txns")==="amm"?"active":""}" onclick="switchWalletDrawerTab('${e.id}','amm')">\u{1F30A} AMM</button>
      </div>
      <div class="wcard-drawer-body" id="wcard-drawer-body-${e.id}">
        <div class="wdd-loading"><div class="spinner"></div> Loading\u2026</div>
      </div>
    </div>`:""}
  </div>`}function vp(e){var n;let t=oe[e];t&&(oe.splice(e,1),_s(),st===t.id&&(st=((n=oe[0])==null?void 0:n.id)||null,st&&te(Es,st)),at(),Et(),gt("wallet_removed",t.label),Fb(`Wallet "${t.label}" removed`,()=>{oe.splice(e,0,t),_s(),st||(st=t.id,te(Es,t.id)),at(),Et(),gt("wallet_created",t.label+" (restored)")},()=>{t.address&&lt(li+t.address)}))}function Fb(e,t,n){let s=document.getElementById("undo-toast");s&&s.remove();let a=document.createElement("div");a.id="undo-toast",a.className="undo-toast",a.innerHTML=`<span class="undo-msg">${g(e)}</span><button class="undo-btn">Undo</button>`,document.body.appendChild(a),requestAnimationFrame(()=>a.classList.add("show"));let o=setTimeout(()=>{a.classList.remove("show"),setTimeout(()=>a.remove(),300),n==null||n()},5e3);a.querySelector(".undo-btn").addEventListener("click",()=>{clearTimeout(o),t(),a.classList.remove("show"),setTimeout(()=>a.remove(),300),ne("Wallet restored")})}function bp(e){var n,s;let t=y("inspect-addr");t&&(t.value=e),(n=window.switchTab)==null||n.call(window,document.querySelector('[data-tab="inspector"]'),"inspector"),(s=window.showDashboard)==null||s.call(window)}function yp(e){Tn=Tn===e?null:e,Tn&&!rn[e]&&(rn[e]="txns"),at(),Tn&&setTimeout(()=>yi(e,rn[e]),60)}function wp(e,t){rn[e]=t;let n=document.getElementById(`wcard-drawer-${e}`);n&&(n.querySelectorAll(".wdt-btn").forEach(s=>s.classList.toggle("active",s.textContent.toLowerCase().includes(t==="txns"?"trans":t==="nfts"?"nft":t==="orders"?"dex":"amm"))),yi(e,t))}async function yi(e,t){var a,o,i;let n=oe.find(r=>r.id===e),s=document.getElementById(`wcard-drawer-body-${e}`);if(!(!n||!s)){s.innerHTML='<div class="wdd-loading"><div class="spinner"></div> Loading\u2026</div>';try{t==="txns"?s.innerHTML=Bb(((a=di[n.address])==null?void 0:a.txns)||await ki(n.address),n.address):t==="nfts"?s.innerHTML=Ob(((o=Ec[n.address])==null?void 0:o.nfts)||await Yb(n.address),n.address):t==="orders"?s.innerHTML=Xb(((i=pi[n.address])==null?void 0:i.offers)||await Qb(n.address),n.id,n.address):t==="amm"&&(s.innerHTML=await Hb(n.address))}catch(r){s.innerHTML=`<div class="wdd-error">\u26A0\uFE0F ${g(r.message)}</div>`}}}function xp(e){return{Payment:"\u{1F4B8}",OfferCreate:"\u{1F4CA}",OfferCancel:"\u2715",TrustSet:"\u{1F517}",NFTokenMint:"\u{1F3A8}",NFTokenBurn:"\u{1F525}",NFTokenCreateOffer:"\u{1F3AF}",NFTokenAcceptOffer:"\u2705",AMMCreate:"\u{1F30A}",AMMDeposit:"\u{1F4E5}",AMMWithdraw:"\u{1F4E4}",AMMVote:"\u{1F5F3}",AMMBid:"\u{1F4A1}",EscrowCreate:"\u23F3",EscrowFinish:"\u2705",EscrowCancel:"\u2715",AccountSet:"\u2699",SetRegularKey:"\u{1F511}",SignerListSet:"\u{1F4CB}"}[e]||"\u{1F4C4}"}function ri(e){return e?typeof e=="string"?`${D(Number(e)/1e6,4)} XRP`:`${D(parseFloat(e.value||0),4)} ${(e.currency||"?").length>4?e.currency.slice(0,4)+"\u2026":e.currency}`:"\u2014"}function Bb(e,t){return e!=null&&e.length?`<div class="wdd-tx-list">
    ${e.slice(0,25).map(n=>{var c,d;let s=n.TransactionType||"?",a=n.Account===t,o=!(((c=n.metaData)==null?void 0:c.TransactionResult)||((d=n.meta)==null?void 0:d.TransactionResult)||"").match(/^tec|^tem|^tef|^tel/),i=n.date?(n.date+946684800)*1e3:0,r=i?new Date(i).toLocaleDateString("en-US",{month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"}):"\u2014",l=n.hash||n.tx_hash||"";return`<div class="wdd-tx-row ${o?"":"wdd-tx-failed"}">
        <div class="wdd-tx-icon">${xp(s)}</div>
        <div class="wdd-tx-body">
          <div class="wdd-tx-type-row">
            <span class="wdd-tx-type">${s}</span>
            <span class="wdd-tx-dir ${a?"out":"in"}">${a?"\u2191 Out":"\u2193 In"}</span>
            ${o?"":'<span class="wdd-tx-fail-badge">Failed</span>'}
          </div>
          <div class="wdd-tx-detail">
            ${n.Amount?`<span class="wdd-tx-amount">${ri(n.Amount)}</span>`:""}
            ${n.Destination?`<span class="wdd-tx-dest mono">${Nc[n.Destination]||n.Destination.slice(0,8)+"\u2026"+n.Destination.slice(-5)}</span>`:""}
          </div>
        </div>
        <div class="wdd-tx-right">
          <div class="wdd-tx-date">${r}</div>
          ${l?`<a class="wdd-tx-hash" href="https://xrpscan.com/tx/${l}" target="_blank" rel="noopener">\u2B21 View</a>`:""}
        </div>
      </div>`}).join("")}
    <a class="wdd-view-more" href="https://xrpscan.com/account/${t}" target="_blank" rel="noopener">View full history on XRPScan \u2192</a>
  </div>`:'<div class="wdd-empty"><div class="wdd-empty-icon">\u{1F4CB}</div><div>No transactions yet.</div><div class="wdd-empty-sub">Fund with 10 XRP to activate.</div></div>'}function Ob(e,t){return e!=null&&e.length?`<div class="wdd-nft-header"><span>${e.length} NFT${e.length>1?"s":""}</span>
    <a class="wdd-view-more-inline" href="https://xrpscan.com/account/${t}#nfts" target="_blank">View on XRPScan \u2192</a></div>
    <div class="wdd-nft-grid">
      ${e.slice(0,24).map(n=>{var i;let s=n.nft_serial??((i=n.NFTokenID)==null?void 0:i.slice(-6))??"?",a=n.URI&&Pi(n.URI)||"",o=a.startsWith("ipfs://")?`https://cloudflare-ipfs.com/ipfs/${a.slice(7)}`:"";return`<div class="wdd-nft-card">
          <div class="wdd-nft-art">${o?`<img src="${g(o)}" class="wdd-nft-img" alt="NFT" onerror="this.parentNode.innerHTML='<span class=wdd-nft-placeholder>\u{1F3A8}</span>'" />`:'<span class="wdd-nft-placeholder">\u{1F3A8}</span>'}</div>
          <div class="wdd-nft-info"><div class="wdd-nft-id mono">#${s}</div></div>
        </div>`}).join("")}
    </div>
    ${e.length>24?`<div class="wdd-more-note">${e.length-24} more on XRPScan</div>`:""}`:'<div class="wdd-empty"><div class="wdd-empty-icon">\u{1F3A8}</div><div>No NFTs in this wallet.</div></div>'}function Xb(e,t,n){return e!=null&&e.length?`<div class="wdd-orders-header"><span>${e.length} open order${e.length>1?"s":""}</span></div>
    <div class="wdd-orders-list">
      ${e.map(s=>`<div class="wdd-order-row">
        <div class="wdd-order-dir ${s.flags&524288?"sell":"buy"}">${s.flags&524288?"SELL":"BUY"}</div>
        <div class="wdd-order-pair">
          <span class="wdd-order-gets">${ri(s.TakerGets)}</span>
          <span class="wdd-order-arrow">\u21C4</span>
          <span class="wdd-order-pays">${ri(s.TakerPays)}</span>
        </div>
        <div class="wdd-order-seq mono">Seq #${s.seq||"?"}</div>
        <button class="wdd-order-cancel" onclick="cancelOffer('${t}',${s.seq},this)">\u2715 Cancel</button>
      </div>`).join("")}
    </div>`:'<div class="wdd-empty"><div class="wdd-empty-icon">\u{1F4CA}</div><div>No open DEX orders.</div></div>'}async function Hb(e){try{let n=(ci[e]||[]).filter(s=>{var a;return((a=s.currency)==null?void 0:a.length)===40});return n.length?`<div class="wdd-amm-list">
      ${n.map(s=>{let a=s.currency,o=D(parseFloat(s.balance||0),6);return`<div class="wdd-amm-row">
          <div class="wdd-amm-icon">\u{1F30A}</div>
          <div class="wdd-amm-info">
            <div class="wdd-amm-pool mono">${a.slice(0,12)}\u2026</div>
            <div class="wdd-amm-bal">LP Tokens: ${o}</div>
            <div class="wdd-amm-issuer mono" style="opacity:.4;font-size:.7rem">${s.issuer.slice(0,14)}\u2026</div>
          </div>
          <a class="wdd-tx-hash" href="https://xrpscan.com/amm/${s.issuer}" target="_blank" rel="noopener">View AMM</a>
        </div>`}).join("")}
    </div>`:'<div class="wdd-empty"><div class="wdd-empty-icon">\u{1F30A}</div><div>No AMM LP positions.</div><div class="wdd-empty-sub">Deposit into an AMM pool to earn fees.</div></div>'}catch(t){return`<div class="wdd-error">\u26A0\uFE0F ${g(t.message)}</div>`}}async function kp(e,t,n){let s=prompt("Optional seed to cancel this order (leave blank to use wallet password):");n&&(n.disabled=!0,n.textContent="\u2026");try{let a=await ay(e,t,s);if(ty(a)){ne("Order cancelled \u2713");let o=oe.find(i=>i.id===e);o&&(delete pi[o.address],yi(e,"orders"))}else Nt("Cancel failed: "+ny(a)),n&&(n.disabled=!1,n.textContent="\u2715 Cancel")}catch(a){Nt(a.message),n&&(n.disabled=!1,n.textContent="\u2715 Cancel")}}function $p(){let e=y("profile-tab-activity");if(!e)return;let t=Cv(),n=St();e.innerHTML=`
    <div class="act-section-row">
      <div class="act-section">
        <div class="act-section-title">In-App Activity</div>
        <div class="act-section-sub">Your recent actions in NaluXRP</div>
        ${t.length?`<div class="act-timeline">${t.slice(0,20).map(s=>`
            <div class="act-entry">
              <div class="act-entry-icon">${xv[s.type]||"\u25CF"}</div>
              <div class="act-entry-body">
                <div class="act-entry-detail">${g(s.detail)}</div>
                <div class="act-entry-time">${qc(s.ts)}</div>
              </div>
            </div>`).join("")}</div>`:'<div class="act-empty-small">No activity yet.</div>'}
      </div>
      <div class="act-section">
        <div class="act-section-title">On-Chain Activity</div>
        <div class="act-section-sub">Full forensic analysis via Inspector</div>
        ${n?`<div class="act-redirect-card">
          <div class="act-rc-icon">\u{1F50D}</div>
          <div class="act-rc-body">
            <div class="act-rc-title">${g(n.label)}</div>
            <div class="act-rc-sub">Transaction history, wash trading signals, fund flow tracing, and a full investigation report.</div>
            <button class="act-inspect-btn-lg" onclick="inspectWalletAddr('${g(n.address)}')">Open Inspector \u2192</button>
          </div>
        </div>`:'<div class="act-empty-small">Create a wallet to inspect on-chain activity.</div>'}
      </div>
    </div>`}function zt(){var o,i;let e=y("profile-tab-settings");if(!e)return;let t=["gold","cosmic","starry","hawaiian"],n=Z("nalulf_pref_currency")||"XRP",s=Z("nalulf_pref_network")||"mainnet",a=Z("nalulf_pref_autolock")||"30";e.innerHTML=`<div class="settings-grid">

    <div class="settings-card">
      <div class="settings-card-hdr"><span class="settings-card-icon">\u{1F3A8}</span>
        <div><div class="settings-card-title">Appearance</div><div class="settings-card-sub">Theme and display preferences</div></div></div>
      <div class="settings-label">Theme</div>
      <div class="settings-theme-row">
        ${t.map(r=>`<button class="theme-pill ${r} ${O.currentTheme===r?"active":""}" onclick="prefSetTheme('${r}')">${r[0].toUpperCase()+r.slice(1)}</button>`).join("")}
      </div>
      <div style="margin-top:16px"><div class="settings-label">Display currency</div>
        <div class="settings-seg">
          <button class="settings-seg-btn ${n==="XRP"?"active":""}" onclick="setPrefCurrency('XRP')">XRP</button>
          <button class="settings-seg-btn ${n==="USD"?"active":""}" onclick="setPrefCurrency('USD')">USD</button>
        </div>
      </div>
      <div style="margin-top:16px"><div class="settings-label">3D immersive background</div>
        <div class="settings-seg">
          <button class="settings-seg-btn ${C.threeEnabled?"active":""}" onclick="setThreeEffects(true)">On</button>
          <button class="settings-seg-btn ${C.threeEnabled?"":"active"}" onclick="setThreeEffects(false)">Off</button>
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
        <div class="settings-kv"><span class="settings-k">Vault created</span><span class="settings-v">${g((i=(o=Ee.vault)==null?void 0:o.identity)!=null&&i.createdAt?new Date(Ee.vault.identity.createdAt).toLocaleDateString():"\u2014")}</span></div>
        <div class="settings-kv"><span class="settings-k">Server storage</span><span class="settings-v settings-v--good">None \xB7 local only</span></div>
        <div class="settings-kv"><span class="settings-k">Wallets</span><span class="settings-v">${oe.length} stored</span></div>
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

    ${zb()}

    <div class="settings-card settings-card--danger">
      <div class="settings-card-hdr"><span class="settings-card-icon">\u26A0\uFE0F</span>
        <div><div class="settings-card-title">Danger Zone</div><div class="settings-card-sub">Irreversible actions</div></div></div>
      <p class="settings-card-desc">Wiping removes all local data. Your wallets still exist on-chain and can be re-added with their seed phrases.</p>
      <button class="settings-btn settings-btn--danger" onclick="openAuth?.('forgot')">\u{1F5D1} Wipe Account Data</button>
    </div>
  </div>`}var wi=!1;function zb(){var s;let e=((s=Ee.vault)==null?void 0:s.ai)||{},t=!!e.apiKey;return wi||!t?`
    <div class="settings-card">
      <div class="settings-card-hdr"><span class="settings-card-icon">\u{1F916}</span>
        <div><div class="settings-card-title">AI Explanations</div><div class="settings-card-sub">Bring your own Anthropic API key</div></div></div>
      <p class="settings-card-desc">
        Requires a tiny stateless relay to work around Anthropic's browser CORS policy \u2014 it never sees or stores your key.
        <a href="https://github.com/anthropics" target="_blank" rel="noopener" style="color:var(--accent)">Deploy your own</a> or ask whoever runs this instance for the proxy URL.
      </p>
      <div class="settings-label">Anthropic API key</div>
      <input id="ai-settings-key" class="xrpl-input" type="password" placeholder="sk-ant-..." value="${g(e.apiKey||"")}" autocomplete="off" spellcheck="false" style="margin-bottom:10px" />
      <div class="settings-label">Proxy Worker URL</div>
      <input id="ai-settings-proxy" class="xrpl-input" type="text" placeholder="https://your-worker.workers.dev" value="${g(e.proxyUrl||"")}" autocomplete="off" spellcheck="false" style="margin-bottom:10px" />
      <div class="settings-label">Model <span style="opacity:.55;font-weight:400">\u2014 you're billed per request on your own key, so this is your cost/quality tradeoff</span></div>
      <select id="ai-settings-model" class="xrpl-input">
        ${ev.map(a=>`<option value="${a.id}" ${(e.model||Yo)===a.id?"selected":""}>${g(a.label)}</option>`).join("")}
      </select>
      <div class="settings-actions" style="margin-top:12px">
        <button class="settings-btn settings-btn--primary" onclick="saveAiSettings()">Save</button>
        ${t?'<button class="settings-btn" onclick="editAiSettings(false)">Cancel</button>':""}
      </div>
    </div>`:`
    <div class="settings-card">
      <div class="settings-card-hdr"><span class="settings-card-icon">\u{1F916}</span>
        <div><div class="settings-card-title">AI Explanations</div><div class="settings-card-sub">Claude-generated account analysis</div></div></div>
      <div class="settings-kv-list">
        <div class="settings-kv"><span class="settings-k">API key</span><span class="settings-v settings-v--good">\u2713 Configured</span></div>
        <div class="settings-kv"><span class="settings-k">Proxy</span><span class="settings-v mono" title="${g(e.proxyUrl||"")}">${g(shortAddr(e.proxyUrl||"")||"\u2014")}</span></div>
        <div class="settings-kv"><span class="settings-k">Model</span><span class="settings-v mono">${g(e.model||Yo)}</span></div>
      </div>
      <div class="settings-actions">
        <button class="settings-btn" onclick="editAiSettings()">Change</button>
        <button class="settings-btn settings-btn--danger" onclick="clearAiSettings()">Remove</button>
      </div>
    </div>`}function Sp(e=!0){wi=e,zt()}async function Tp(){var s,a,o;let e=(s=y("ai-settings-key"))==null?void 0:s.value.trim(),t=(a=y("ai-settings-proxy"))==null?void 0:a.value.trim(),n=((o=y("ai-settings-model"))==null?void 0:o.value.trim())||Yo;if(!e||!t){be("Enter both the API key and the proxy URL.");return}if(!/^https?:\/\//.test(t)){be("Proxy URL must start with http:// or https://");return}await Ee.update(i=>{i.ai={apiKey:e,proxyUrl:t,model:n}}),wi=!1,ne("AI settings saved."),zt()}async function Cp(){await Ee.update(e=>{delete e.ai}),ne("AI settings removed."),zt()}function Ub(){let e=y("profile-tab-security");e&&(e.innerHTML=`<div class="sec-grid">
    <div class="sec-card">
      <div class="sec-card-hdr"><span class="sec-card-icon">\u{1F510}</span>
        <div><div class="sec-card-title">Local Encrypted Vault</div><div class="sec-card-sub">AES-256-GCM \xB7 PBKDF2 150,000 iterations</div></div>
        <span class="sec-status-pill ${unlocked?"sec-status--open":"sec-status--locked"}">${unlocked?"Unlocked":"Locked"}</span>
      </div>
      <div class="sec-kv-grid">
        <div class="sec-kv"><span class="sec-k">Encryption</span><span class="sec-v mono">AES-256-GCM</span></div>
        <div class="sec-kv"><span class="sec-k">KDF</span><span class="sec-v mono">PBKDF2 \xB7 150k iterations \xB7 SHA-256</span></div>
        <div class="sec-kv"><span class="sec-k">Vault created</span><span class="sec-v">${createdAt}</span></div>
        <div class="sec-kv"><span class="sec-k">Server storage</span><span class="sec-v sec-v--good">None \u2014 local only</span></div>
        <div class="sec-kv"><span class="sec-k">Password stored</span><span class="sec-v sec-v--good">Never \u2014 key derivation only</span></div>
        <div class="sec-kv"><span class="sec-k">Signing</span><span class="sec-v sec-v--good">In-browser only, seed zero'd after use</span></div>
      </div>
      <div class="sec-card-actions">
        <button class="sec-btn sec-btn--primary" onclick="exportWalletAddresses()">\u2B07 Export Wallet Addresses</button>
      </div>
      <div class="sec-note"><span class="sec-note-icon">\u2139</span>Your backup is still encrypted. It cannot be read without your password.</div>
    </div>
    <div class="sec-card">
      <div class="sec-card-hdr"><span class="sec-card-icon">\u270D\uFE0F</span>
        <div><div class="sec-card-title">Seed Phrase Best Practices</div></div></div>
      <div class="sec-practices">
        ${[["Write it on paper now","Store in a fireproof box or safety deposit box. This is your only recovery option if you lose this device."],["Never store it digitally","No notes apps, emails, cloud drives, or screenshots. A hacked device means instant loss of funds."],["Never share it with anyone","No legitimate app or support team will ever ask. Anyone who asks is attempting theft."],["Use a strong unique password","Your password protects the encrypted vault on this device."],["Export your backup regularly","Use the Export Backup button after creating or modifying wallets. Keep the file offline."]].map(([t,n],s)=>`<div class="sec-practice">
          <div class="sec-practice-num">${s+1}</div>
          <div class="sec-practice-body"><strong>${t}.</strong> ${n}</div>
        </div>`).join("")}
      </div>
    </div>
    <div class="sec-card">
      <div class="sec-card-hdr"><span class="sec-card-icon">\u{1F4E1}</span>
        <div><div class="sec-card-title">XRPL Capabilities</div><div class="sec-card-sub">What your wallets can do in NaluXRP</div></div></div>
      <div class="sec-caps-grid">
        ${[["\u{1F4B8}","XRP & IOU Payments"],["\u{1F517}","Trustlines (TrustSet)"],["\u{1F4CA}","DEX Orders (CLOB)"],["\u{1F30A}","AMM Deposits & Swaps"],["\u{1F3A8}","NFT Mint & Transfer"],["\u{1F50D}","On-chain Forensic Inspect"],["\u{1F3E6}","Multi-wallet Management"],["\u{1F6E1}","Ed25519 & secp256k1"]].map(([t,n])=>`<div class="sec-cap"><span class="sec-cap-icon">${t}</span><span>${n}</span></div>`).join("")}
      </div>
    </div>
  </div>`)}async function Lp(){var t;let e=y("profile-tab-analytics");if(e){e.innerHTML='<div class="analytics-grid"><div class="skeleton-card analytics-card--wide" style="height:80px"></div><div class="skeleton-card" style="height:160px"></div><div class="skeleton-card" style="height:160px"></div></div>';try{let n=St(),s=Object.values(Ve).reduce((r,l)=>r+((l==null?void 0:l.xrp)||0),0),a=up(),o=Object.values(Ve).flatMap(r=>(r==null?void 0:r.tokens)||[]),i=[];if(n)try{i=((t=di[n.address])==null?void 0:t.txns)||await ki(n.address,100)}catch{}e.innerHTML=`<div class="analytics-grid">
      <div class="analytics-card analytics-card--wide">
        <div class="analytics-card-hdr"><span class="analytics-card-title">\u{1F4BC} Portfolio Summary</span>
          <span class="analytics-badge">${oe.length} wallet${oe.length!==1?"s":""}</span></div>
        <div class="portfolio-summary-row">
          ${oe.length?oe.map(r=>{let l=Ve[r.address],c=l?D(l.xrp,2):"\u2014",d=l&&a?`$${D(l.xrp*a,2)}`:"",u=xi(r.address);return`<div class="portfolio-wallet-row">
                <div class="pwr-icon" style="color:${r.color};background:${r.color}18;border-color:${r.color}33">${g(r.emoji||"\u{1F48E}")}</div>
                <div class="pwr-info"><div class="pwr-label">${g(r.label)}</div><div class="pwr-addr mono">${r.address.slice(0,8)}\u2026${r.address.slice(-5)}</div></div>
                <div class="pwr-sparkline">${Mp(u,80,28,r.color||"#00fff0")}</div>
                <div class="pwr-balance"><div class="pwr-xrp">${c} <span class="pwr-xrp-label">XRP</span></div>${d?`<div class="pwr-usd">${d}</div>`:""}</div>
              </div>`}).join(""):'<div class="analytics-empty">No wallets yet.</div>'}
        </div>
        <div class="portfolio-totals">
          <div class="ptotal"><span class="ptotal-label">Total XRP</span><span class="ptotal-val">${D(s,4)}</span></div>
          ${a?`<div class="ptotal"><span class="ptotal-label">Est. USD</span><span class="ptotal-val ptotal-usd">$${D(s*a,2)}</span></div>`:""}
          <div class="ptotal"><span class="ptotal-label">Tokens</span><span class="ptotal-val">${o.length}</span></div>
          <div class="ptotal"><span class="ptotal-label">Wallets</span><span class="ptotal-val">${oe.length}</span></div>
        </div>
      </div>

      ${n?`<div class="analytics-card analytics-card--wide">
        <div class="analytics-card-hdr"><span class="analytics-card-title">\u{1F4C8} Balance History</span>
          <span class="analytics-badge">${g(n.label)}</span></div>
        ${Wb(n.address)}
      </div>`:""}

      <div class="analytics-card analytics-card--wide">
        <div class="analytics-card-hdr"><span class="analytics-card-title">\u{1F4C5} On-Chain Activity</span>
          <span class="analytics-badge">${n?g(n.label):"No wallet"}</span></div>
        ${n?jb(i):'<div class="analytics-empty">Activate a wallet to see activity.</div>'}
      </div>

      ${i.length?`<div class="analytics-card">
        <div class="analytics-card-hdr"><span class="analytics-card-title">\u{1F4CA} TX Breakdown</span>
          <span class="analytics-badge">${i.length} recent</span></div>
        ${qb(i)}
      </div>`:""}

      ${n&&i.length?`<div class="analytics-card">
        <div class="analytics-card-hdr"><span class="analytics-card-title">\u{1F4B0} XRP Flow</span>
          <span class="analytics-badge">Est. net</span></div>
        ${Gb(i,n.address)}
      </div>`:""}

      ${o.length?`<div class="analytics-card">
        <div class="analytics-card-hdr"><span class="analytics-card-title">\u{1FA99} Token Holdings</span>
          <span class="analytics-badge">${o.length} assets</span></div>
        ${Vb(o)}
      </div>`:""}
    </div>`}catch(n){Uc(e,"analytics",n)}}}function Mp(e,t,n,s){if(e.length<2)return`<svg width="${t}" height="${n}"><line x1="0" y1="${n/2}" x2="${t}" y2="${n/2}" stroke="${s}" stroke-opacity=".2" stroke-width="1" stroke-dasharray="3 2"/></svg>`;let a=e.map(u=>u.xrp),o=Math.min(...a),i=Math.max(...a),r=i-o||1,l=a.map((u,p)=>`${3+p/(a.length-1)*(t-6)},${3+(1-(u-o)/r)*(n-6)}`),[c,d]=l[l.length-1].split(",");return`<svg width="${t}" height="${n}" viewBox="0 0 ${t} ${n}">
    <polyline points="${l.join(" ")}" fill="none" stroke="${s}" stroke-width="1.5" stroke-opacity=".8" stroke-linejoin="round" stroke-linecap="round"/>
    <circle cx="${c}" cy="${d}" r="2.5" fill="${s}" opacity=".9"/>
  </svg>`}function Wb(e){let t=xi(e);if(t.length<2)return`<div class="analytics-empty-chart"><div class="aec-icon">\u{1F4CA}</div><div>Balance history builds up as you refresh your wallet over time.</div><div class="aec-sub">${t.length} snapshot${t.length!==1?"s":""} recorded.</div></div>`;let n=560,s=130,a=52,o=12,i=14,r=30,l=t.map(_=>_.xrp),c=t.map(_=>_.ts),d=Math.min(...l),u=Math.max(...l),p=u-d||1,m=c[0],f=c[c.length-1],v=f-m||1,h=_=>a+(_-m)/v*(n-a-o),w=_=>i+(1-(_-d)/p)*(s-i-r),k=t.map(_=>`${h(_.ts).toFixed(1)},${w(_.xrp).toFixed(1)}`),b=h(c[0]),x=h(c[c.length-1]),S=l[l.length-1]-l[0],T=S>=0,$=l[0]?Math.abs(S/l[0]*100).toFixed(2):"0.00",P=T?"#00d4ff":"#ff5555",M=[d,(d+u)/2,u].map(_=>({v:_,y:w(_),l:D(_,2)})),N=[0,.5,1].map(_=>({x:a+_*(n-a-o),l:new Date(m+_*v).toLocaleDateString("en-US",{month:"short",day:"numeric"})}));return`
    <div class="balance-chart-meta">
      <div class="bcm-current">${D(l[l.length-1],4)} XRP</div>
      <div class="bcm-delta ${T?"bcm-up":"bcm-down"}">${T?"\u25B2":"\u25BC"} ${$}%</div>
      <div class="bcm-range">${t.length} snapshots</div>
    </div>
    <div class="balance-chart-wrap"><svg class="balance-chart-svg" viewBox="0 0 ${n} ${s}" preserveAspectRatio="none">
      <defs><linearGradient id="bg${e.slice(-4)}" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="${P}" stop-opacity=".22"/><stop offset="100%" stop-color="${P}" stop-opacity="0"/></linearGradient></defs>
      ${M.map(_=>`<line x1="${a}" y1="${_.y.toFixed(1)}" x2="${n-o}" y2="${_.y.toFixed(1)}" stroke="rgba(255,255,255,.06)" stroke-width="1"/>`).join("")}
      <path d="M${b.toFixed(1)},${s-r} L${k.join(" L")} L${x.toFixed(1)},${s-r} Z" fill="url(#bg${e.slice(-4)})"/>
      <polyline points="${k.join(" ")}" fill="none" stroke="${P}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      ${t.map(_=>`<circle cx="${h(_.ts).toFixed(1)}" cy="${w(_.xrp).toFixed(1)}" r="2" fill="${P}" opacity=".7"/>`).join("")}
      ${M.map(_=>`<text x="${a-5}" y="${(_.y+4).toFixed(1)}" text-anchor="end" fill="rgba(255,255,255,.38)" font-size="10" font-family="JetBrains Mono,monospace">${_.l}</text>`).join("")}
      ${N.map(_=>`<text x="${_.x.toFixed(1)}" y="${s-6}" text-anchor="middle" fill="rgba(255,255,255,.32)" font-size="10" font-family="JetBrains Mono,monospace">${_.l}</text>`).join("")}
    </svg></div>`}function jb(e){let t=new Map;e.forEach(f=>{f.date&&t.set(new Date((f.date+946684800)*1e3).toISOString().slice(0,10),(t.get(new Date((f.date+946684800)*1e3).toISOString().slice(0,10))||0)+1)});let n=26,s=12,a=2,o=new Date,i=Array.from({length:n*7},(f,v)=>{let h=new Date(o);return h.setDate(h.getDate()-(n*7-1-v)),h}),r=Array.from({length:n},(f,v)=>i.slice(v*7,v*7+7)),l=Math.max(1,...t.values()),c=n*(s+a)+30,d=7*(s+a)+28,u=f=>f===0?"rgba(255,255,255,.07)":`rgb(0,${Math.round(85+f*170)},${Math.round(119+f*121)})`,p=[],m=-1;return r.forEach((f,v)=>{var w;let h=(w=f[0])==null?void 0:w.getMonth();h!==m&&(m=h,p.push({wi:v,l:f[0].toLocaleDateString("en-US",{month:"short"})}))}),`<div class="heatmap-meta"><span>${e.length} tx \xB7 ${t.size} active days</span>
    <div class="heatmap-legend"><span>Less</span><div class="heatmap-legend-cells">${[0,.25,.5,.75,1].map(f=>`<div class="hm-leg-cell" style="background:${u(f)}"></div>`).join("")}</div><span>More</span></div>
  </div>
  <div class="heatmap-scroll"><svg class="heatmap-svg" viewBox="0 0 ${c} ${d}" width="${c}" height="${d}">
    ${p.map(({wi:f,l:v})=>`<text x="${26+f*(s+a)}" y="10" font-size="9" fill="rgba(255,255,255,.38)" font-family="Outfit,sans-serif">${v}</text>`).join("")}
    ${["","Mon","","Wed","","Fri",""].map((f,v)=>f?`<text x="0" y="${16+v*(s+a)+s/2+3}" font-size="9" fill="rgba(255,255,255,.3)" font-family="Outfit,sans-serif">${f}</text>`:"").join("")}
    ${r.map((f,v)=>f.map((h,w)=>{let k=h.toISOString().slice(0,10),b=t.get(k)||0;return`<rect x="${26+v*(s+a)}" y="${16+w*(s+a)}" width="${s}" height="${s}" rx="2" fill="${u(b/l)}" opacity="${b>0?.9:.25}"><title>${k}: ${b} tx</title></rect>`}).join("")).join("")}
  </svg></div>`}function qb(e){let t=new Map;e.forEach(a=>t.set(a.TransactionType||"?",(t.get(a.TransactionType||"?")||0)+1));let n=[...t.entries()].sort((a,o)=>o[1]-a[1]),s=e.length;return`<div class="tx-breakdown-list">${n.slice(0,8).map(([a,o])=>`<div class="txb-row"><div class="txb-icon">${xp(a)}</div><div class="txb-type">${a}</div><div class="txb-bar-wrap"><div class="txb-bar" style="width:${(o/s*100).toFixed(0)}%"></div></div><div class="txb-count">${o}</div></div>`).join("")}</div>`}function Vb(e){let t=new Map;e.forEach(o=>{let i=Math.abs(parseFloat(o.balance||0));t.set(o.currency,(t.get(o.currency)||0)+i)});let n=[...t.entries()].sort((o,i)=>i[1]-o[1]).slice(0,8),s=n.reduce((o,[,i])=>o+i,0)||1,a=["#00fff0","#00d4ff","#bd93f9","#50fa7b","#ffb86c","#ff79c6","#f1fa8c","#ff5555"];return`<div class="token-alloc-list">${n.map(([o,i],r)=>{let l=(i/s*100).toFixed(1),c=a[r%a.length],d=o.length>4?o.slice(0,4)+"\u2026":o;return`<div class="ta-row"><div class="ta-swatch" style="background:${c}"></div><div class="ta-cur mono">${d}</div><div class="ta-bar-wrap"><div class="ta-bar" style="width:${l}%;background:${c}20;border-color:${c}55"></div></div><div class="ta-pct">${l}%</div></div>`}).join("")}</div>`}function Gb(e,t){let n=0,s=0;e.forEach(i=>{var c,d;if(i.TransactionType!=="Payment"||!((((c=i.metaData)==null?void 0:c.TransactionResult)||((d=i.meta)==null?void 0:d.TransactionResult))==="tesSUCCESS")||typeof i.Amount!="string")return;let l=Number(i.Amount)/1e6;i.Destination===t&&(n+=l),i.Account===t&&(s+=l)});let a=n-s,o=a>=0;return`<div class="xrp-flow-grid">
    <div class="xrf-item xrf-in"><div class="xrf-label">\u2193 Inflow</div><div class="xrf-val">${D(n,4)} XRP</div></div>
    <div class="xrf-item xrf-out"><div class="xrf-label">\u2191 Outflow</div><div class="xrf-val">${D(s,4)} XRP</div></div>
    <div class="xrf-item ${o?"xrf-pos":"xrf-neg"}"><div class="xrf-label">Net</div><div class="xrf-val">${o?"+":""}${D(a,4)} XRP</div></div>
  </div>
  <div class="xrf-note">Based on ${e.length} fetched Payment TXs. Excludes fees and DEX fills.</div>`}async function Je(e){var n,s;try{if(((n=O.wsConn)==null?void 0:n.readyState)===1){let{wsSend:a}=await import("./xrpl-6AERZ5KD.js"),o={command:e==null?void 0:e.method,...((s=e==null?void 0:e.params)==null?void 0:s[0])||{}},i=await a(o);if((i==null?void 0:i.status)==="error")throw new Error(i.error_message||i.error||"XRPL RPC error");return(i==null?void 0:i.result)||null}}catch{}let t=async a=>{let o=await fetch(a,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(e),mode:"cors"});if(!o.ok)throw new Error(`HTTP ${o.status}`);return(await o.json()).result};try{return await t(Yg)}catch{return await t(Qg)}}async function Pn(e){var t;try{let n=[],s;do{let l=await Je({method:"account_lines",params:[{account:e,ledger_index:"current",limit:400,...s?{marker:s}:{}}]});if(!l||l.error)break;n.push(...l.lines||[]),s=l.marker}while(s);let a=await Je({method:"account_info",params:[{account:e,ledger_index:"current"}]});if(a!=null&&a.error)return null;let o=Number(a.account_data.Balance)/1e6,i=n.map(l=>({currency:l.currency,issuer:l.account,balance:l.balance,limit:l.limit}));Ve[e]={xrp:o,tokens:i,fetchedAt:Date.now()},ci[e]=i,Jb(e,o);let r=document.getElementById("awb-balance");return r&&e===((t=St())==null?void 0:t.address)&&hy(r.querySelector(".awb-xrp-num")||r,o,2,600),Ve[e]}catch{return null}}async function Kb(){await Promise.allSettled(oe.map(e=>Pn(e.address))),at(),Et(),Ds()}function Jb(e,t){let n=li+e,s=ve(Z(n))||[],a=Date.now();s.length&&a-s[s.length-1].ts<5*6e4?s[s.length-1]={xrp:t,ts:a}:s.push({xrp:t,ts:a}),s.length>90&&s.splice(0,s.length-90),te(n,JSON.stringify(s))}function xi(e){return ve(Z(li+e))||[]}async function ki(e,t=25){let n=await Je({method:"account_tx",params:[{account:e,limit:t,ledger_index_min:-1,ledger_index_max:-1}]}),s=((n==null?void 0:n.transactions)||[]).map(a=>a.tx||a.transaction||a);return di[e]={txns:s,fetchedAt:Date.now()},s}async function Yb(e){let t=await Je({method:"account_nfts",params:[{account:e,limit:50}]}),n=(t==null?void 0:t.account_nfts)||[];return Ec[e]={nfts:n,fetchedAt:Date.now()},n}async function Qb(e){let t=await Je({method:"account_offers",params:[{account:e,limit:50}]}),n=(t==null?void 0:t.offers)||[];return pi[e]={offers:n,fetchedAt:Date.now()},n}async function Zb(e){let t=await Je({method:"account_info",params:[{account:e,ledger_index:"current"}]});return(t==null?void 0:t.account_data)||null}async function ey(){let e=await Je({method:"ledger",params:[{ledger_index:"current"}]});return(e==null?void 0:e.ledger_current_index)||0}function ty(e){let t=(e==null?void 0:e.engine_result)||"";return t==="tesSUCCESS"||t.startsWith("tes")||(e==null?void 0:e.engine_result_code)===0}function ny(e){let t=(e==null?void 0:e.engine_result)||"";return cv[t]||(e==null?void 0:e.engine_result_message)||t||"Unknown error"}async function sy(e,t,n){if(await Ea(),!window.xrpl)throw new Error("xrpl.js library not loaded. Cannot sign transactions.");let s=oe.find(i=>i.id===e);if(!s)throw new Error("Wallet not found.");if(s.watchOnly)throw new Error("Watch-only wallets cannot sign transactions.");let a=await uv(s,n),o;try{o=window.xrpl.Wallet.fromSeed(a,{algorithm:s.algo==="secp256k1"?"secp256k1":"ed25519"})}catch(i){throw new Error("Invalid seed phrase: "+i.message)}if(o.classicAddress!==s.address)throw new Error("Seed does not match this wallet address.");try{let[i,r]=await Promise.all([Zb(s.address),ey()]);if(!i)throw new Error("Account not found on-chain. Fund with at least 10 XRP first (base reserve requirement).");let l={...t,Account:s.address,Fee:"12",Sequence:i.Sequence,LastLedgerSequence:r+20},{tx_blob:c,hash:d}=o.sign(l);return{...await Je({method:"submit",params:[{tx_blob:c}]}),tx_hash:d}}finally{}}async function ay(e,t,n){return sy(e,{TransactionType:"OfferCancel",OfferSequence:parseInt(t)},n)}function oy(){if(y("send-modal-overlay"))return;let e=document.createElement("div");e.innerHTML=`
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
  </div>`,document.body.appendChild(e),["send-modal-overlay","receive-modal-overlay","trustline-modal-overlay","import-address-modal","import-seed-modal","token-details-modal"].forEach(t=>{let n=document.getElementById(t);n==null||n.addEventListener("click",s=>{s.target===n&&(n.classList.remove("show"),n.style.display="")})})}function Pp(){var o;["displayName","handle","bio","location","website"].forEach(i=>{let r=y(`edit-${i}`);r&&(r.value=le[i]||"")});let e=y("editor-avatar-preview");if(e){let i=localStorage.getItem(ln);e.innerHTML=i?`<img src="${i}" class="profile-avatar-img"/>`:le.avatar||"\u{1F30A}"}let t=y("avatar-remove-btn");t&&(t.style.display=localStorage.getItem(ln)?"":"none");let n=y("editor-banner-preview");if(n){let i=localStorage.getItem(Ln);n.style.backgroundImage=i?`url(${i})`:"",n.style.backgroundSize="cover",n.style.backgroundPosition="center",Ns.forEach(r=>n.classList.remove(r)),i||n.classList.add(le.banner||"banner-ocean")}let s=y("avatar-picker-grid");s&&(s.innerHTML=iv.map(i=>`<div class="avatar-option ${le.avatar===i?"active":""}" onclick="selectAvatar('${i}')">${i}</div>`).join(""));let a=y("banner-picker-grid");a&&(a.innerHTML=Ns.map(i=>`<div class="banner-option ${i} ${le.banner===i?"active":""}" onclick="selectBanner('${i}')"></div>`).join("")),(o=y("profile-editor-modal"))==null||o.classList.add("show")}function Bs(){var e;(e=y("profile-editor-modal"))==null||e.classList.remove("show")}function Ap(){var e,t,n,s,a;le.displayName=((e=y("edit-displayName"))==null?void 0:e.value.trim())||le.displayName,le.handle=(((t=y("edit-handle"))==null?void 0:t.value.trim())||le.handle).replace(/^@/,"").replace(/\s+/g,"_").toLowerCase(),le.bio=((n=y("edit-bio"))==null?void 0:n.value.trim())||"",le.location=((s=y("edit-location"))==null?void 0:s.value.trim())||"",le.website=((a=y("edit-website"))==null?void 0:a.value.trim())||"",Wc(),gt("profile_saved","Profile details updated"),q(),Bs(),ne("Profile saved")}function Ep(e){localStorage.removeItem(ln),le.avatar=e,Ie(".avatar-option").forEach(s=>s.classList.toggle("active",s.textContent===e));let t=y("editor-avatar-preview");t&&(t.innerHTML=e);let n=y("avatar-remove-btn");n&&(n.style.display="none")}function Np(e){localStorage.removeItem(Ln),le.banner=e,Ie(".banner-option").forEach(n=>n.classList.toggle("active",n.classList.contains(e)));let t=y("editor-banner-preview");t&&(t.style.backgroundImage="",Ns.forEach(n=>t.classList.remove(n)),t.classList.add(e)),q()}function _p(e){var s;let t=(s=e==null?void 0:e.files)==null?void 0:s[0];if(!t)return;if(t.size>2*1024*1024){be("Image too large \u2014 max 2 MB");return}let n=new FileReader;n.onload=a=>{let o=new Image;o.onload=()=>{let i=document.createElement("canvas");i.width=i.height=200;let r=i.getContext("2d"),l=Math.min(o.width,o.height);r.drawImage(o,(o.width-l)/2,(o.height-l)/2,l,l,0,0,200,200);let c=i.toDataURL("image/jpeg",.85);localStorage.setItem(ln,c);let d=y("editor-avatar-preview");d&&(d.innerHTML=`<img src="${c}" class="profile-avatar-img"/>`);let u=y("avatar-remove-btn");u&&(u.style.display=""),q(),ne("Profile photo updated")},o.src=a.target.result},n.readAsDataURL(t),e.value=""}function Rp(){localStorage.removeItem(ln);let e=y("editor-avatar-preview");e&&(e.innerHTML=le.avatar||"\u{1F30A}");let t=y("avatar-remove-btn");t&&(t.style.display="none"),q()}function Dp(e){var s;let t=(s=e==null?void 0:e.files)==null?void 0:s[0];if(!t)return;if(t.size>5*1024*1024){be("Image too large \u2014 max 5 MB");return}let n=new FileReader;n.onload=a=>{let o=new Image;o.onload=()=>{let i=document.createElement("canvas");i.width=900,i.height=180;let r=i.getContext("2d"),l=Math.max(900/o.width,180/o.height);r.drawImage(o,(900-o.width*l)/2,(180-o.height*l)/2,o.width*l,o.height*l);let c=i.toDataURL("image/jpeg",.88);localStorage.setItem(Ln,c);let d=y("editor-banner-preview");d&&(d.style.backgroundImage=`url(${c})`,d.style.backgroundSize="cover",d.style.backgroundPosition="center",Ns.forEach(p=>d.classList.remove(p)));let u=y("banner-remove-btn");u&&(u.style.display=""),q(),ne("Banner updated")},o.src=a.target.result},n.readAsDataURL(t),e.value=""}function Ip(){localStorage.removeItem(Ln);let e=y("editor-banner-preview");e&&(e.style.backgroundImage="",Ns.forEach(n=>e.classList.remove(n)),e.classList.add(le.banner||"banner-ocean"));let t=y("banner-remove-btn");t&&(t.style.display="none"),q()}function iy(){let e=oe.map(({id:n,label:s,address:a,algo:o,emoji:i,color:r,testnet:l,watchOnly:c,createdAt:d})=>({id:n,label:s,address:a,algo:o,emoji:i,color:r,testnet:l,watchOnly:c,createdAt:d})),t=document.createElement("a");t.href="data:application/json;charset=utf-8,"+encodeURIComponent(JSON.stringify(e,null,2)),t.download=`nalulf-wallets-${new Date().toISOString().slice(0,10)}.json`,t.click(),gt("backup_exported","Wallet addresses exported"),ne("Wallet addresses exported")}function Fp(){iy()}function $i(){var e;ft=1,we={algo:"ed25519",label:"",emoji:"\u{1F48E}",color:"#50fa7b",seed:"",address:"",passphrase:""},Cn.clear(),Si(1),ly(),ry(),(e=y("wallet-creator-overlay"))==null||e.classList.add("show"),setTimeout(()=>{var t;return(t=y("wallet-label-input"))==null?void 0:t.focus()},80)}function Os(){var e;(e=y("wallet-creator-overlay"))==null||e.classList.remove("show"),we.seed=we.address=we.passphrase=""}function ry(){let e=y("wizard-security-banner");e&&(e.innerHTML=`<div class="wsb-icon">\u{1F510}</div>
    <div class="wsb-content">
      <div class="wsb-title">Your keys are encrypted on your device</div>
      <div class="wsb-body">Your wallet seed is encrypted with your password using AES-256-GCM before being saved to this device. <strong>It never leaves your browser.</strong></div>
      <div class="wsb-pills">
        <span class="wsb-pill wsb-pill--green">\u{1F512} Local only</span>
        <span class="wsb-pill wsb-pill--green">\u{1F6AB} Never sent to servers</span>
        <span class="wsb-pill wsb-pill--blue">\u26A1 AES-256-GCM</span>
      </div>
    </div>`)}async function Bp(){var e,t,n;if(ft===1){let s=(e=y("wallet-label-input"))==null?void 0:e.value.trim(),a=((t=y("wallet-pass-input"))==null?void 0:t.value)||"",o=((n=y("wallet-pass-confirm"))==null?void 0:n.value)||"";if(!s){be("Enter a wallet name.");return}if(a.length<10){be("Use a wallet password with at least 10 characters.");return}if(a!==o){be("Wallet password confirmation does not match.");return}if(we.label=s,we.passphrase=a,!cy())return;ft=2}else if(ft===2){if(Cn.size<4){be("Confirm all 4 security checkpoints first.");return}ft=3}else if(ft===3)try{await py(),ft=4}catch{return}Si(ft)}function Op(){if(ft<=1){Os();return}ft--,Si(ft)}function Si(e){var a;[1,2,3,4].forEach(o=>{let i=document.querySelector(`.step-${o}`);i&&(i.classList.toggle("active",o===e),i.classList.toggle("done",o<e))}),Ie(".wizard-panel").forEach(o=>o.classList.remove("active")),(a=y(`wizard-panel-${e}`))==null||a.classList.add("active");let t=y("wizard-back-btn"),n=y("wizard-next-btn"),s=y("wizard-finish-btn");t&&(t.style.display=e===4?"none":"",t.textContent=e===1?"Cancel":"\u2190 Back"),n&&(n.style.display=e>=3?"none":""),s&&(s.style.display=e===3?"":"none")}function ly(){let e=y("wallet-emoji-picker");e&&(e.innerHTML=rv.map(n=>`<div class="wallet-emoji-opt ${we.emoji===n?"active":""}" onclick="selectWalletEmoji('${n}')">${n}</div>`).join(""));let t=y("wallet-color-picker");t&&(t.innerHTML=lv.map(n=>`<div class="color-swatch ${we.color===n?"active":""}" style="background:${n}" onclick="selectWalletColor('${n}')"></div>`).join(""))}function cy(){var n;if(!((n=window.xrpl)!=null&&n.Wallet))return Nt("xrpl.js is not available yet. Please wait a moment and try again."),Ea().catch(()=>{}),!1;try{let s=window.xrpl.Wallet.generate(we.algo==="ed25519"?"ed25519":"secp256k1");we.seed=s.seed||"",we.address=s.classicAddress}catch(s){return Nt("Failed to generate a valid XRPL wallet: "+((s==null?void 0:s.message)||"Unknown error")),!1}let e=y("wizard-seed-value"),t=y("wizard-address-value");return e&&(e.textContent=we.seed),t&&(t.textContent=we.address),Cn.clear(),Ie(".security-check").forEach(s=>s.classList.remove("checked")),Ie(".check-box").forEach(s=>s.textContent=""),dy(),Wp(),e&&setTimeout(()=>e.classList.add("blur"),3e4),!0}function dy(){let e=y("security-checklist-dynamic");if(!e)return;let t=[{icon:"\u270D\uFE0F",title:"Write it on paper right now",body:"Copy your seed phrase onto paper and store it in a safe place. This is your ONLY recovery option if you lose access to this device."},{icon:"\u{1F6AB}",title:"Never store it digitally",body:"No notes apps, emails, screenshots, or cloud drives. A device with a digital copy that gets hacked means instant loss of funds."},{icon:"\u{1F92B}",title:"Never share it with anyone",body:"No legitimate app, exchange, or support team will ever ask for your seed. Anyone who asks is attempting to steal your funds."},{icon:"\u{1F510}",title:"Use a strong unique password",body:"Your password protects the encrypted seed on this device. Use one you don't use anywhere else."}];e.innerHTML=t.map((n,s)=>`
    <div class="security-check security-check-${s+1}" onclick="toggleSecurityCheck(${s+1})">
      <span class="check-box" id="check-box-${s+1}"></span>
      <div class="check-text"><strong>${n.icon} ${g(n.title)}</strong>${g(n.body)}</div>
    </div>`).join("")}async function py(){var n;let e=await Ac(we.seed,we.passphrase),t={id:crypto.randomUUID(),label:we.label,address:we.address,algo:we.algo,emoji:we.emoji,color:we.color,testnet:((n=y("wallet-testnet-check"))==null?void 0:n.checked)||!1,watchOnly:!1,encSeed:e,createdAt:new Date().toISOString()};oe.push(t),_s(),st||(st=t.id,te(Es,t.id)),at(),Et(),Aa("wallet-success-address",we.address),setTimeout(()=>{we.seed="",we.address="",we.passphrase=""},100),gt("wallet_created",we.label||"New XRPL Wallet"),ne("Wallet created and encrypted locally"),Pn(t.address).then(()=>at())}function Xp(e){we.algo=e,Ie(".algo-card").forEach(t=>t.classList.toggle("active",t.dataset.algo===e))}function Hp(e){we.emoji=e,Ie(".wallet-emoji-opt").forEach(t=>t.classList.toggle("active",t.textContent===e))}function zp(e){we.color=e,Ie(".color-swatch").forEach(t=>t.classList.toggle("active",t.style.background===e||t.dataset.color===e))}function Up(e){let t=document.querySelector(`.security-check-${e}`);if(!t)return;let n=t.querySelector(".check-box");Cn.has(e)?(Cn.delete(e),t.classList.remove("checked"),n&&(n.textContent="")):(Cn.add(e),t.classList.add("checked"),n&&(n.textContent="\u2713")),Wp()}function Wp(){let e=y("wizard-next-btn");e&&ft===2&&(e.disabled=Cn.size<4)}function jp(){var t;(t=y("wizard-seed-value"))==null||t.classList.remove("blur");let e=y("seed-reveal-hint");e&&(e.style.display="none"),setTimeout(()=>{var n;return(n=y("wizard-seed-value"))==null?void 0:n.classList.add("blur")},3e4)}function qp(){let e=y("wizard-seed-value");if(!e)return;Mi(e.textContent,3e4);let t=y("btn-copy-seed");t&&(t.textContent="Copied!",t.classList.add("copied"),setTimeout(()=>{t.textContent="Copy Seed",t.classList.remove("copied")},2e3))}function Vp(){let e=y("wizard-address-value")||y("wallet-success-address");if(!e)return;Mi(e.textContent);let t=y("btn-copy-addr");t&&(t.textContent="Copied!",t.classList.add("copied"),setTimeout(()=>{t.textContent="Copy",t.classList.remove("copied")},2e3))}function Gp(){let e=y("import-address-modal");if(!e)return;e.querySelector("#inp-import-address").value="",e.querySelector("#inp-import-label").value="";let t=e.querySelector("#import-address-error");t&&(t.textContent=""),e.classList.add("show"),setTimeout(()=>{var n;return(n=e.querySelector("#inp-import-address"))==null?void 0:n.focus()},80)}function Ti(){var e;(e=y("import-address-modal"))==null||e.classList.remove("show")}function Kp(){var s,a;let e=(((s=y("inp-import-address"))==null?void 0:s.value)||"").trim(),t=(((a=y("inp-import-label"))==null?void 0:a.value)||"").trim()||"Watch Wallet",n=y("import-address-error");if(!Ue(e)){n&&(n.textContent="Enter a valid XRPL address (starts with r\u2026)");return}if(oe.find(o=>o.address===e)){n&&(n.textContent="This address is already in your list.");return}oe.push({id:"watch_"+Date.now(),label:t,address:e,algo:"\u2014",emoji:"\u{1F441}",color:"#8be9fd",testnet:!1,createdAt:new Date().toISOString(),watchOnly:!0}),_s(),gt("watch_added",`${t} (${e.slice(0,8)}\u2026)`),Ti(),at(),Et(),Ds(),Pn(e).then(()=>{at(),Ds()}),ne(`\u{1F441} Watch-only wallet added: ${t}`)}function Jp(){let e=y("import-seed-modal");if(!e)return;e.querySelector("#inp-import-seed").value="",e.querySelector("#inp-import-seed-pass").value="",e.querySelector("#inp-import-seed-pass-confirm").value="",e.querySelector("#inp-import-seed-label").value="";let t=e.querySelector("#import-seed-error");t&&(t.textContent=""),e.classList.add("show"),setTimeout(()=>{var n;return(n=e.querySelector("#inp-import-seed"))==null?void 0:n.focus()},80)}function Ci(){var e;(e=y("import-seed-modal"))==null||e.classList.remove("show")}async function Yp(){var r,l,c,d,u;let e=(((r=y("inp-import-seed"))==null?void 0:r.value)||"").trim(),t=(((l=y("inp-import-seed-label"))==null?void 0:l.value)||"").trim()||"Imported Wallet",n=(((c=y("inp-import-seed-pass"))==null?void 0:c.value)||"").trim(),s=(((d=y("inp-import-seed-pass-confirm"))==null?void 0:d.value)||"").trim(),a=y("import-seed-error"),o=y("import-seed-btn"),i=p=>{a&&(a.textContent=p)};if(i(""),!e)return i("Enter your seed phrase.");if(n.length<10)return i("Use a wallet password with at least 10 characters.");if(n!==s)return i("Wallet password confirmation does not match.");if(await Ea(),!window.xrpl)return i("xrpl.js not loaded \u2014 cannot derive address from seed.");o&&(o.disabled=!0,o.textContent="Importing\u2026");try{let p=window.xrpl.Wallet.fromSeed(e),m=p.address,f=(u=p.algorithm)!=null&&u.toLowerCase().includes("ed")?"ed25519":"secp256k1";if(oe.find(b=>b.address===m))return i("This address is already in your vault.");let v="imp_"+Date.now(),h="\u{1F511}",w="#bd93f9",k=await Ac(e,n);oe.push({id:v,label:t,address:m,algo:f,emoji:h,color:w,testnet:!1,watchOnly:!1,encSeed:k,createdAt:new Date().toISOString()}),_s(),gt("wallet_imported",`${t} (${m.slice(0,8)}\u2026)`),Ci(),at(),Et(),Pn(m).then(()=>{at(),Ds()}),ne(`\u{1F511} Wallet imported: ${t}`)}catch(p){i("Invalid seed: "+(p.message||"Could not derive wallet."))}finally{o&&(o.disabled=!1,o.textContent="Import Wallet \u2192");let p=document.getElementById("inp-import-seed");p&&(p.value="");let m=document.getElementById("inp-import-seed-pass");m&&(m.value="");let f=document.getElementById("inp-import-seed-pass-confirm");f&&(f.value="")}}function Qp(e,t,n){var d;let s=y("token-details-modal");if(!s)return;let a=s.querySelector(".generic-modal");if(!a)return;let o=Ve[n],i=(d=o==null?void 0:o.tokens)==null?void 0:d.find(u=>u.currency===e&&u.issuer===t),r=i?D(parseFloat(i.balance||0),6):"\u2014",l=i!=null&&i.limit?D(parseFloat(i.limit),2):"Unlimited",c=e.length>4&&Pi(e)||e;a.innerHTML=`
    <div class="tdm-hdr">
      <div class="tdm-title"><span class="tdm-icon">\u{1FA99}</span><span class="tdm-cur">${g(c)}</span>
        ${c!==e?`<span class="tdm-hex mono">${g(e)}</span>`:""}</div>
      <button class="tdm-close" onclick="closeTokenDetailsModal()">\u2715</button>
    </div>
    <div class="tdm-grid">
      <div class="tdm-item"><div class="tdm-item-label">Balance</div><div class="tdm-item-val">${r}</div></div>
      <div class="tdm-item"><div class="tdm-item-label">Trust Limit</div><div class="tdm-item-val">${l}</div></div>
      <div class="tdm-item tdm-item--wide">
        <div class="tdm-item-label">Issuer</div>
        <div class="tdm-item-val tdm-issuer mono">${t.slice(0,14)}\u2026${t.slice(-6)}</div>
        <button class="tdm-copy-btn" onclick="copyToClipboard('${g(t)}')">\u29C9 Copy</button>
      </div>
    </div>
    <div class="tdm-links">
      <a class="tdm-link" href="https://xrpscan.com/account/${g(t)}" target="_blank" rel="noopener">\u{1F50D} View Issuer on XRPScan</a>
      <a class="tdm-link" href="https://xrpscan.com/account/${g(n)}#tokens" target="_blank" rel="noopener">\u{1F4CB} All My Tokens</a>
    </div>`,s.classList.add("show")}function Zp(){let e=y("token-details-modal");e&&(e.classList.remove("show"),e.style.display="")}function eu(){var s;(s=document.getElementById("pub-profile-overlay"))==null||s.remove();let e=localStorage.getItem(ln),t=as.filter(a=>ze[a.id]),n=document.createElement("div");n.id="pub-profile-overlay",n.className="pub-profile-overlay",n.innerHTML=`
    <div class="pub-profile-modal">
      <div class="pub-banner ${le.banner||"banner-ocean"}" ${localStorage.getItem(Ln)?`style="background-image:url(${localStorage.getItem(Ln)});background-size:cover;background-position:center;"`:""}>
      </div>
      <div class="pub-hdr">
        <div class="pub-avatar">${e?`<img src="${e}" alt="avatar"/>`:`<span>${g(le.avatar||"\u{1F30A}")}</span>`}</div>
        <div class="pub-info">
          <div class="pub-name">${g(le.displayName||"Anonymous")}</div>
          <div class="pub-handle">@${g(le.handle||"anonymous")}</div>
          ${le.bio?`<div class="pub-bio">${g(le.bio)}</div>`:""}
          <div class="vault-pill vault-pill--locked" style="font-size:.65rem;padding:3px 9px">\u{1F512} Self-custodied XRPL wallet</div>
        </div>
      </div>
      ${t.length?`<div class="pub-socials">${t.map(a=>`<span class="pub-social-badge"><span>${a.icon}</span><span>@${g(ze[a.id])}</span></span>`).join("")}</div>`:'<div style="padding:0 20px 16px;font-size:.82rem;color:rgba(255,255,255,.3)">No social accounts connected yet.</div>'}
      <div class="pub-close-row">
        <span style="font-size:.78rem;color:rgba(255,255,255,.32);flex:1">This is how others see your profile</span>
        <button class="pub-close-btn" onclick="document.getElementById('pub-profile-overlay').remove()">Close</button>
      </div>
    </div>`,document.body.appendChild(n),requestAnimationFrame(()=>requestAnimationFrame(()=>n.classList.add("show"))),n.addEventListener("click",a=>{a.target===n&&n.remove()})}function tu(e){un(e),zt(),gt("theme_changed",e)}function nu(e){te("nalulf_pref_currency",e),zt(),ne(`Display currency: ${e}`)}function su(e){te("nalulf_pref_network",e),zt(),ne(`Default network: ${e}`)}function au(e){te("nalulf_pref_autolock",e),zt(),ne(`Auto-lock: ${e} minutes`)}window._profileWipeAllData=()=>{confirm("Clear all profile, wallet list, social, and activity data? Encrypted wallet seeds saved on this device will be deleted.")&&(["nalulf_profile","nalulf_wallets","nalulf_social","nalulf_activity_log","nalulf_avatar_img","nalulf_banner_img","naluxrp_active_wallet"].forEach(e=>localStorage.removeItem(e)),oe=[],ze={},st=null,Ve={},ci={},ti(),q(),fi("wallets"),ne("Local data cleared"))};function uy(){var e,t,n;(e=y("profile-editor-modal"))==null||e.addEventListener("click",s=>{s.target===s.currentTarget&&Bs()}),(t=y("wallet-creator-overlay"))==null||t.addEventListener("click",s=>{s.target===s.currentTarget&&Os()}),(n=y("social-modal"))==null||n.addEventListener("click",s=>{s.target===s.currentTarget&&os()})}function my(){let e=[{done:!!le.displayName&&le.displayName!=="Anonymous",label:"Display name"},{done:!!le.bio,label:"Bio"},{done:le.avatar!=="\u{1F30A}"||!!localStorage.getItem(ln),label:"Custom avatar"},{done:!!localStorage.getItem(Ln),label:"Custom banner"},{done:oe.length>0,label:"Wallet added"},{done:Object.keys(ze).length>=1,label:"Social connected"},{done:!!le.location,label:"Location set"},{done:!!le.website,label:"Website added"}],t=e.filter(n=>n.done).length;return{pct:Math.round(t/e.length*100),done:t,total:e.length,checks:e}}function fy(){let e=document.getElementById("profile-completeness");if(!e)return;let{pct:t,checks:n}=my(),s=t===100?"#50fa7b":t>=60?"#00fff0":"#ffb86c",a=2*Math.PI*16,o=t/100*a,i=n.filter(r=>!r.done).map(r=>r.label);e.title=t===100?"Profile complete \u2713":`${t}% \u2014 Missing: ${i.join(", ")}`,e.innerHTML=`
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
    </div>`}function hy(e,t,n=2,s=700){if(!e)return;let a=performance.now(),o=parseFloat(e.textContent.replace(/[^0-9.]/g,""))||0;if(Math.abs(t-o)<.001){e.textContent=D(t,n);return}let i=r=>{let l=Math.min((r-a)/s,1),c=l<.5?2*l*l:-1+(4-2*l)*l;e.textContent=D(o+(t-o)*c,n),l<1?requestAnimationFrame(i):e.textContent=D(t,n)};requestAnimationFrame(i)}window._profileSetTokenSearch=e=>{let t=e.toLowerCase();document.querySelectorAll(".wdd-token-row").forEach(n=>{n.style.display=n.textContent.toLowerCase().includes(t)?"":"none"})};function Aa(e,t){let n=y(e);n&&(n.textContent=String(t))}function Li(e){Mi(e)}function Mi(e,t=0){var a;if(!!((a=navigator.clipboard)!=null&&a.writeText)&&document.hasFocus()){navigator.clipboard.writeText(e).then(()=>{ne("Copied to clipboard"),t&&setTimeout(()=>{var o;document.hasFocus()&&((o=navigator.clipboard)!=null&&o.writeText)&&navigator.clipboard.writeText("").catch(()=>{})},t)}).catch(()=>{let o=document.createElement("textarea");o.value=e,document.body.appendChild(o),o.select(),document.execCommand("copy"),o.remove(),ne("Copied")});return}let s=document.createElement("textarea");s.value=e,document.body.appendChild(s),s.select(),document.execCommand("copy"),s.remove(),ne("Copied")}function Pi(e){if(!/^[0-9A-Fa-f]+$/.test(e))return"";try{let t="";for(let n=0;n<e.length;n+=2)t+=String.fromCharCode(parseInt(e.slice(n,n+2),16));return t.replace(/\x00/g,"").trim()}catch{return""}}var gy={"xrpl-ledger":{title:"XRPL Ledger",subtitle:"What a ledger is, what validated means, and how to interpret ledger snapshots.",sections:[{heading:"In simple terms",paragraphs:["Think of the XRP Ledger (XRPL) as a public spreadsheet that the whole network agrees on.","A \u201Cledger version\u201D is one snapshot of that spreadsheet: balances, trustlines, offers, AMMs, and more.","When a ledger becomes \u201Cvalidated\u201D, it\u2019s final\u2014analytics based on validated ledgers reflect settled history."],bullets:["Ledger Index = the ledger number (sequence).","Ledger Hash = fingerprint of that ledger\u2019s contents.","Open \u2192 Closed \u2192 Validated = in-progress \u2192 proposed snapshot \u2192 final snapshot."]},{heading:"How NaluLF uses this",paragraphs:["NaluLF listens to validated ledger events, then summarizes what changed and what patterns are emerging.","You can quickly see dominant transaction types, fee pressure, DEX/AMM bursts, and concentration signals."],bullets:["Live stream cards summarize each ledger close.","Narratives turn raw changes into readable reporting.","Signals are heuristics (useful indicators, not proof)."]}],links:[{label:"XRPL Docs: Ledgers (overview)",url:"https://xrpl.org/docs/concepts/ledgers"},{label:"Open / Closed / Validated Ledgers",url:"https://xrpl.org/docs/concepts/ledgers/open-closed-validated-ledgers"},{label:"Ledger Structure",url:"https://xrpl.org/docs/concepts/ledgers/ledger-structure"},{label:"Ledger Header (hash/index basics)",url:"https://xrpl.org/docs/references/protocol/ledger-data/ledger-header"}],ctas:[{label:"Launch Dashboard \u2192",action:"auth:signup"},{label:"Close",action:"modal:close"}]},"accounts-trustlines":{title:"Accounts, Reserves, and Trustlines",subtitle:"How addresses work, why reserves exist, and what trustlines mean for tokens.",sections:[{heading:"In simple terms",paragraphs:["An XRPL account is a public address with a balance and settings (flags).","Reserves exist to prevent ledger spam: certain objects (offers, trustlines, signer lists) require reserved XRP.","Trustlines are \u201Cpermission slips\u201D that prevent you from receiving random issued tokens you didn\u2019t opt into."],bullets:["Reserves: base reserve + owner reserve for certain objects.","Trustlines: define limits and balances for issued tokens.","Flags/settings: control behaviors like Deposit Authorization."]},{heading:"Why this matters for investigations",paragraphs:["During compromises, account settings and objects can change quickly.","Trustlines and offers can reveal what tokens/markets are being targeted."],bullets:["Inspector helps you read balances, flags, and trustlines.","Reserve signals can hint at heavy offer/trustline usage."]}],links:[{label:"AccountRoot (ledger entry)",url:"https://xrpl.org/docs/references/protocol/ledger-data/ledger-entry-types/accountroot"},{label:"Reserves (why they exist)",url:"https://xrpl.org/docs/concepts/accounts/reserves"},{label:"Trust Line Tokens (concept)",url:"https://xrpl.org/docs/concepts/tokens/fungible-tokens/trust-line-tokens"},{label:"account_lines API (trustlines)",url:"https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_lines"},{label:"Deposit Authorization (DepositAuth)",url:"https://xrpl.org/docs/concepts/accounts/depositauth"},{label:"XRPL: Cryptographic Keys",url:"https://xrpl.org/docs/concepts/accounts/cryptographic-keys"}],ctas:[{label:"Inspect an Address \u2192",action:"auth:login"},{label:"Close",action:"modal:close"}]},"dex-amm":{title:"DEX, Offers, and AMMs",subtitle:"How trading works on XRPL and how AMM liquidity moves show up on-ledger.",sections:[{heading:"How XRPL trading works",paragraphs:["XRPL has a built-in decentralized exchange (DEX). People place \u201Coffers\u201D (limit orders) to trade between XRP and tokens, or token-to-token.","AMMs (Automated Market Makers) hold pools of two assets. Liquidity providers deposit/withdraw and traders swap against the pool."],bullets:["OfferCreate = place an order (limit order).","OfferCancel = remove an order (may still succeed even if nothing cancels).","AMMCreate/Deposit/Withdraw = liquidity lifecycle signals."]},{heading:"Manipulation signals (heuristics)",paragraphs:["On-ledger \u201Cspoofing\u201D isn\u2019t identical to centralized exchanges, but suspicious churn can still stand out.","Rapid OfferCreate/OfferCancel bursts, concentrated actors, and repeated short-lived behavior can indicate bot-driven or staged activity."],bullets:["Offer churn: creates vs cancels intensity.","Concentration: whether a small set of accounts dominates.","AMM bursts: sudden waves of deposits/withdraws."]}],links:[{label:"DEX (concept)",url:"https://xrpl.org/docs/concepts/tokens/decentralized-exchange"},{label:"Offers (concept)",url:"https://xrpl.org/docs/concepts/tokens/decentralized-exchange/offers"},{label:"OfferCreate (tx type)",url:"https://xrpl.org/docs/references/protocol/transactions/types/offercreate"},{label:"OfferCancel (tx type)",url:"https://xrpl.org/docs/references/protocol/transactions/types/offercancel"},{label:"AMMs (concept)",url:"https://xrpl.org/docs/concepts/tokens/decentralized-exchange/automated-market-makers"},{label:"book_offers API (order book)",url:"https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/path-and-order-book-methods/book_offers"}],ctas:[{label:"Launch Dashboard \u2192",action:"auth:signup"},{label:"Close",action:"modal:close"}]},"security-drains":{title:"Wallet Safety + Compromise Response (Defensive)",subtitle:"How to read suspicious patterns safely and what to watch for during incident response.",sections:[{heading:"What a \u201Cdrain\u201D usually means",paragraphs:["A wallet drain typically follows a compromise: stolen keys, malicious signing requests, phishing, or unsafe approvals.","NaluLF is designed for defensive investigation and monitoring\u2014NOT for unauthorized access or theft."],bullets:["Watch for sudden outbound bursts from a previously quiet account.","Look for new trustlines/offers right before the loss.","Check transaction result codes and whether actions are validated."]},{heading:"How NaluLF helps (defensive)",paragraphs:["Inspect the address, review counterparties, and watch for repeated interactions or suspicious churn.","Use narratives to communicate what changed and what to check next."],bullets:["Inspector: balances, trustlines, flags, reserve signals.","Breadcrumbs: repeating \u201Cwho touches who\u201D pairs.","Signals: concentration + churn + bot-like timing proxies."]}],links:[{label:"XRPL Learning: Security Best Practices",url:"https://learn.xrpl.org/lesson/security-best-practices-for-xrp/"},{label:"XRPL Learning: DeFi Security 101",url:"https://learn.xrpl.org/course/blockchain-for-business/lesson/defi-security-101-staying-safe-in-the-new-decentralized-world/"},{label:"XRPL: Secure Signing",url:"https://xrpl.org/docs/concepts/transactions/secure-signing"},{label:"Transaction Results",url:"https://xrpl.org/docs/references/protocol/transactions/transaction-results"},{label:"tesSUCCESS",url:"https://xrpl.org/docs/references/protocol/transactions/transaction-results/tes-success"}],ctas:[{label:"Inspect an Address \u2192",action:"auth:login"},{label:"Close",action:"modal:close"}]},"bots-data":{title:"Bots on the Data (Monitoring / Alerts)",subtitle:"How to build legit automation on top of public XRPL data.",sections:[{heading:"What to automate",paragraphs:["XRPL is public, so you can build monitoring bots for events: whale payments, DEX churn spikes, AMM liquidity changes, or sudden flag updates.","Good bots explain what they saw and provide confidence/validation steps."],bullets:["Use WebSocket subscriptions for live events.","Use API methods for snapshots (account_info, account_lines, book_offers).","Treat signals as indicators and confirm with multiple checks."]},{heading:"How NaluLF fits",paragraphs:["NaluLF is the \u201Chuman dashboard\u201D to validate what the bot flags.","You can click addresses (breadcrumbs/clusters) and open Inspector for context."],bullets:["Bots: alerting, reporting, research, and risk monitoring.","Not for unauthorized access."]}],links:[{label:"subscribe (WebSocket)",url:"https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/subscription-methods/subscribe"},{label:"Monitor Incoming Payments (tutorial)",url:"https://xrpl.org/docs/tutorials/http-websocket-apis/build-apps/monitor-incoming-payments-with-websocket"},{label:"account_info API",url:"https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_info"},{label:"account_lines API",url:"https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_lines"},{label:"book_offers API",url:"https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/path-and-order-book-methods/book_offers"}],ctas:[{label:"Launch Dashboard \u2192",action:"auth:signup"},{label:"Close",action:"modal:close"}]},"crypto-basics":{title:"Crypto Basics: Keys + Signing",subtitle:"Why keys matter, what signing does, and why validated actions are final.",sections:[{heading:"Key concepts",paragraphs:["Your private key proves ownership. If someone has it, they can sign actions as you.","A digital signature is a tamper-proof stamp: the network can verify it, but nobody can forge it without the private key.","This is why phishing is so dangerous: a valid signature is usually final once validated."],bullets:["Public key: shareable.","Private key: never share.","Hashing: detects tampering."]}],links:[{label:"XRPL: Cryptographic Keys",url:"https://xrpl.org/docs/concepts/accounts/cryptographic-keys"},{label:"XRPL: Secure Signing",url:"https://xrpl.org/docs/concepts/transactions/secure-signing"},{label:"Cloudflare: Public key cryptography",url:"https://www.cloudflare.com/learning/ssl/how-does-public-key-encryption-work/"},{label:"Cloudflare: What is a cryptographic key?",url:"https://www.cloudflare.com/learning/ssl/what-is-a-cryptographic-key/"}],ctas:[{label:"Close",action:"modal:close"}]},"about-naluxrp":{title:"What is NaluLF?",subtitle:"Client-only XRPL forensic & analytics suite: readable reporting + manipulation signals + investigation workflow.",sections:[{heading:"The goal",paragraphs:["NaluLF turns raw ledger firehose data into something you can understand quickly:","what happened, who seems involved, what changed, and what looks unusual."],bullets:["Live stream: what the network is doing right now.","Inspector: what\u2019s going on with this address.","Signals: what looks unusual or coordinated (heuristics)."]},{heading:"How it helps defenders",paragraphs:["When investigating suspicious activity (compromises, scams, wash-like churn), you need context fast.","NaluLF helps you gather data, pivot between entities, and produce a clear report of what the ledger shows."],bullets:["Pattern windows (repeat pairs, cluster-like co-activity).","DEX churn signals (OfferCreate/Cancel intensity + concentration).","AMM/LP bursts (deposit/withdraw waves)."]},{heading:"Ethics",paragraphs:["Designed for defensive monitoring, research, and investigations.","Not for stealing funds or unauthorized access."]}],links:[{label:"XRPL Docs: Transactions",url:"https://xrpl.org/docs/concepts/transactions"},{label:"XRPL Docs: DEX",url:"https://xrpl.org/docs/concepts/tokens/decentralized-exchange"},{label:"XRPL Docs: AMMs",url:"https://xrpl.org/docs/concepts/tokens/decentralized-exchange/automated-market-makers"},{label:"XRPL Learning: Scam safety checklist",url:"https://learn.xrpl.org/blog/safeguarding-your-crypto-wallet-your-essential-checklist-against-defi-scams/"}],ctas:[{label:"Launch Dashboard \u2192",action:"auth:signup"},{label:"Close",action:"modal:close"}]}},vy=[{icon:"\u{1F4D8}",title:"XRPL Ledgers",body:"Ledgers, validation, and indices.",topic:"xrpl-ledger"},{icon:"\u{1F464}",title:"Accounts",body:"Balances, reserves, flags, and keys.",topic:"accounts-trustlines"},{icon:"\u{1FA99}",title:"Trustlines",body:"Token safety model on XRPL.",topic:"accounts-trustlines"},{icon:"\u{1F501}",title:"DEX + Offers",body:"OfferCreate/Cancel + churn signals.",topic:"dex-amm"},{icon:"\u{1F4A7}",title:"AMMs / LPs",body:"Liquidity lifecycle and bursts.",topic:"dex-amm"},{icon:"\u{1F6E1}\uFE0F",title:"Security",body:"Defensive investigation workflow.",topic:"security-drains"}],by=[{icon:"\u{1F6E1}\uFE0F",title:"NaluLF Overview",desc:"What the app does, how it helps investigations, and what signals mean.",topic:"about-naluxrp"},{icon:"\u{1F4D8}",title:"XRPL Ledger",desc:"Ledgers, validated finality, and how to interpret snapshots.",topic:"xrpl-ledger"},{icon:"\u{1F464}",title:"Accounts + Trustlines",desc:"Reserves, flags, and trustline fundamentals for tokens.",topic:"accounts-trustlines"},{icon:"\u{1F501}",title:"DEX / Offers / AMMs",desc:"Trading primitives + what churn signals can indicate.",topic:"dex-amm"},{icon:"\u{1F9EF}",title:"Compromise Response",desc:"How to read suspicious flows defensively and safely.",topic:"security-drains"},{icon:"\u{1F916}",title:"Bots + Monitoring",desc:"Legit automation ideas using public XRPL data + validation steps.",topic:"bots-data"},{icon:"\u{1F510}",title:"Keys + Signing",desc:"Why signatures matter and how to stay safe.",topic:"crypto-basics"}],yy=[{num:1,title:"Learn the ecosystem with real sources",body:"Open learning cards with detailed explanations and trusted references.",topic:"xrpl-ledger"},{num:2,title:"Investigate suspicious wallet activity (defensive)",body:"Inspector + counterparties + patterns to build a clear timeline.",topic:"security-drains"},{num:3,title:"Monitor DEX/AMM churn for anomaly signals",body:"OfferCreate/Cancel bursts, concentration, and LP waves.",topic:"dex-amm"},{num:4,title:"Build monitoring bots on public data",body:"Subscriptions + APIs for alerts, reporting, and research.",topic:"bots-data"}],ou=!1;function wy(){if(document.getElementById("learnModalOverlay"))return;let e=document.createElement("div");e.id="learnModalOverlay",e.className="learn-modal-overlay",e.innerHTML=`
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
  `,document.body.appendChild(e),e.addEventListener("click",t=>{t.target===e&&Xs()}),document.addEventListener("keydown",t=>{t.key==="Escape"&&e.classList.contains("show")&&Xs()})}function xy(e){let t=gy[e];if(!t)return;wy();let n=document.getElementById("learnModalOverlay"),s=document.getElementById("learnModalTitle"),a=document.getElementById("learnModalSub"),o=document.getElementById("learnModalBody"),i=document.getElementById("learnModalLinks"),r=document.getElementById("learnModalCtas");!n||!s||!a||!o||!i||!r||(s.textContent=t.title,a.textContent=t.subtitle||"",o.innerHTML=(t.sections||[]).map(l=>`
    <section class="learn-sec">
      <h4>${g(l.heading||"")}</h4>
      ${(l.paragraphs||[]).map(c=>`<p>${g(c)}</p>`).join("")}
      ${l.bullets&&l.bullets.length?`<ul>${l.bullets.map(c=>`<li>${g(c)}</li>`).join("")}</ul>`:""}
    </section>
  `).join(""),i.innerHTML=(t.links||[]).map(l=>`
    <a class="learn-link" href="${g(l.url)}" target="_blank" rel="noopener noreferrer">
      ${g(l.label)}
      <span aria-hidden="true">\u2197</span>
    </a>
  `).join(""),r.innerHTML=(t.ctas||[]).map(l=>`
    <button class="learn-cta ${l.action==="auth:signup"?"primary":""}" type="button" data-action="${g(l.action)}">
      ${g(l.label)}
    </button>
  `).join(""),n.classList.add("show"),document.body.classList.add("modal-open"))}function Xs(){var e;(e=document.getElementById("learnModalOverlay"))==null||e.classList.remove("show"),document.body.classList.remove("modal-open")}function ky(e){var t,n,s;if(e==="modal:close")return Xs();if(e==="auth:signup"){Xs(),(t=window.openAuth)==null||t.call(window,"signup");return}if(e==="auth:login"){Xs(),(n=window.openAuth)==null||n.call(window,"login");return}if(e.startsWith("topic:"))return xy(e.split(":")[1]);if(e.startsWith("scroll:")){let a=e.split(":")[1];(s=document.getElementById(a))==null||s.scrollIntoView({behavior:"smooth",block:"start"})}}function $y(){ou||(ou=!0,document.addEventListener("click",e=>{var s,a;let t=(a=(s=e.target).closest)==null?void 0:a.call(s,"[data-action]");if(!t)return;let n=t.getAttribute("data-action")||"";n&&(e.preventDefault(),ky(n))}))}function iu(){var l,c,d,u,p;$y(),(l=document.querySelector(".landing-features"))==null||l.setAttribute("id","learn"),(c=document.querySelector(".landing-simple-value"))==null||c.setAttribute("id","use-cases"),(d=document.querySelector(".landing-cta"))==null||d.setAttribute("id","about"),(u=document.querySelector(".landing-tagline"))==null||u.classList.add("tagline-pill");let e=document.querySelector(".landing-stats-strip");e&&(e.classList.add("landing-learn-strip"),e.innerHTML=vy.map(m=>`
      <button class="learn-tile reveal" type="button" data-action="topic:${g(m.topic)}" aria-label="${g(m.title)}">
        <div class="learn-tile-ico">${m.icon}</div>
        <div class="learn-tile-t">${g(m.title)}</div>
        <div class="learn-tile-b">${g(m.body)}</div>
      </button>
    `).join(""));let t=y("features-grid");t&&(t.innerHTML=by.map(m=>`
      <div class="feature-card reveal">
        <span class="feature-icon">${m.icon}</span>
        <h3>${g(m.title)}</h3>
        <p>${g(m.desc)}</p>
        <button class="feature-cta" type="button" data-action="topic:${g(m.topic)}">
          Learn more \u2192
        </button>
      </div>
    `).join(""));let n=document.querySelector(".landing-simple-value"),s=n==null?void 0:n.querySelector("h2");s&&(s.textContent="What you can do with NaluLF");let a=y("value-grid");a&&(a.innerHTML=yy.map(m=>`
      <div class="value-card reveal">
        <div class="value-number">${m.num}</div>
        <h3>${g(m.title)}</h3>
        <p>${g(m.body)}</p>
        <div class="value-actions">
          <button class="value-cta" type="button" data-action="topic:${g(m.topic)}">Open guide \u2192</button>
          <button class="value-cta primary" type="button" data-action="auth:signup">Launch Dashboard \u2192</button>
        </div>
      </div>
    `).join(""));let o=document.querySelector(".landing-footer-bar .footer-brand");if(o){let m=((p=document.querySelector(".brand-glyph"))==null?void 0:p.getAttribute("src"))||"NaluLF/images/NLF-Shield-blue.jpg";o.innerHTML=`
      <img class="footer-icon" src="${g(m)}" alt="NaluLF shield" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline-flex';" />
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
    `)}function ru(){let e=new IntersectionObserver(t=>t.forEach(n=>{n.isIntersecting&&n.target.classList.add("visible")}),{threshold:.12});document.querySelectorAll(".reveal").forEach(t=>e.observe(t))}function lu(){let e=document.getElementById("particle-canvas");if(!e)return;let t=e.getContext("2d"),n,s,a=[],o=80,i=120;function r(){n=e.width=window.innerWidth,s=e.height=window.innerHeight}function l(){return{x:Math.random()*n,y:Math.random()*s,vx:(Math.random()-.5)*.4,vy:(Math.random()-.5)*.4,r:Math.random()*1.5+.5,alpha:Math.random()*.5+.1}}function c(){r(),a=Array.from({length:o},l)}function d(){return getComputedStyle(document.body).getPropertyValue("--accent-secondary").trim()||"#ffd700"}function u(){t.clearRect(0,0,n,s);let v=d();for(let h=0;h<a.length;h++)for(let w=h+1;w<a.length;w++){let k=a[h].x-a[w].x,b=a[h].y-a[w].y,x=Math.sqrt(k*k+b*b);x<i&&(t.beginPath(),t.moveTo(a[h].x,a[h].y),t.lineTo(a[w].x,a[w].y),t.strokeStyle=`rgba(255,255,255,${(1-x/i)*.06})`,t.lineWidth=1,t.stroke())}a.forEach(h=>{t.beginPath(),t.arc(h.x,h.y,h.r,0,Math.PI*2),t.fillStyle=`rgba(255,255,255,${h.alpha*.6})`,t.fill()})}function p(){a.forEach(v=>{v.x+=v.vx,v.y+=v.vy,(v.x<0||v.x>n)&&(v.vx*=-1),(v.y<0||v.y>s)&&(v.vy*=-1)})}let m;function f(){p(),u(),m=requestAnimationFrame(f)}c(),f(),document.addEventListener("visibilitychange",()=>{document.hidden?(m&&cancelAnimationFrame(m),m=null):m||f()}),window.addEventListener("resize",()=>{r(),a.forEach(v=>{v.x=Math.min(v.x,n),v.y=Math.min(v.y,s)})}),e.style.cssText=`
    position: fixed; inset: 0;
    width: 100%; height: 100%;
    pointer-events: none;
    z-index: 0; opacity: 0.4;
  `}var Ai=[{label:"\u{1F30A} Live Stream",hint:"Dashboard \u2192 Stream tab",action:()=>Nn(document.querySelector('[data-tab="stream"]'),"stream")},{label:"\u{1F50D} Inspector",hint:"Dashboard \u2192 Inspector tab",action:()=>Nn(document.querySelector('[data-tab="inspector"]'),"inspector")},{label:"\u{1F4E1} Network Health",hint:"Dashboard \u2192 Network tab",action:()=>Nn(document.querySelector('[data-tab="network"]'),"network")},{label:"\u{1F511} Sign In",hint:"Open auth",action:()=>{var e;return(e=window._openAuth)==null?void 0:e.call(window,"login")}},{label:"\u2728 Sign Up",hint:"Create account",action:()=>{var e;return(e=window._openAuth)==null?void 0:e.call(window,"signup")}},{label:"\u{1F3E0} Landing Page",hint:"Go home",action:()=>{var e;return(e=window._goHome)==null?void 0:e.call(window)}},{label:"\u{1F3A8} Cycle Theme",hint:"gold \u2192 cosmic \u2192 starry \u2192",action:()=>{var e;return(e=window._cycleTheme)==null?void 0:e.call(window)}}],An=0,Ba=[...Ai];function Ei(e=""){let t=y("cmdkOverlay"),n=y("cmdkInput");!t||!n||(t.classList.add("show"),n.value=e||"",pu(e),n.focus())}function is(){var e;(e=y("cmdkOverlay"))==null||e.classList.remove("show")}function du(){let e=y("cmdkOverlay"),t=y("cmdkInput");!e||!t||(t.addEventListener("input",()=>pu(t.value)),t.addEventListener("keydown",n=>{n.key==="ArrowDown"&&(n.preventDefault(),cu(1)),n.key==="ArrowUp"&&(n.preventDefault(),cu(-1)),n.key==="Enter"&&(n.preventDefault(),Sy()),n.key==="Escape"&&is()}),e.addEventListener("click",n=>{n.target===e&&is()}))}function pu(e=""){let t=y("cmdkList");if(!t)return;let n=e.toLowerCase().trim();Ba=n?Ai.filter(s=>s.label.toLowerCase().includes(n)||s.hint.toLowerCase().includes(n)):[...Ai],An=0,t.innerHTML=Ba.length?Ba.map((s,a)=>`
        <button class="cmdk-item${a===0?" is-active":""}" data-index="${a}">
          <span class="cmdk-label">${g(s.label)}</span>
          <span class="cmdk-hint2">${g(s.hint)}</span>
        </button>`).join(""):'<div class="cmdk-section-label">No results</div>',t.querySelectorAll(".cmdk-item").forEach(s=>{s.addEventListener("click",()=>uu(Number(s.dataset.index)))})}function cu(e){var n,s,a;let t=Ie("#cmdkList .cmdk-item");t.length&&((n=t[An])==null||n.classList.remove("is-active"),An=(An+e+t.length)%t.length,(s=t[An])==null||s.classList.add("is-active"),(a=t[An])==null||a.scrollIntoView({block:"nearest"}))}function uu(e){let t=Ba[e];t&&(is(),t.action())}function Sy(){uu(An)}var Oa=!1;function Ni(){let e=O.currentPage,t=O.currentTab,n=e==="dashboard"&&t==="stream",s=e==="dashboard"&&t==="inspector",a=e==="dashboard"&&t==="network";il(n),Ml(s),lc(a)}function mu(){Oa||(ol(),Ll(),rc(),zc(),Ni(),Oa=!0)}window.openAuth=e=>Qa(e);window.closeAuth=()=>qt();window.showAuthView=e=>jt(e);window.authKeydown=e=>br(e);window.submitSignIn=()=>eo();window.submitSignUp=()=>to();window.refreshCaptcha=()=>ar();window.showForgotView=()=>cr();window.forgotRestoreFromFile=()=>dr();window.forgotWipeConfirm=()=>pr();window.forgotWipeExecute=()=>ur();window.forgotBackToOptions=()=>mr();window.submitSyncImport=()=>no();window.exportVaultSyncCode=()=>fr();window.syncImportFromFile=()=>hr();window.signupNext=()=>Za();window.signupBack=()=>sr();window.logout=()=>gr();window.goHome=()=>mn();window.showLandingPage=()=>mn();window.showDashboard=()=>fn();window.showProfile=()=>qa();window.switchTab=(e,t)=>Nn(e,t);window.runInspect=()=>Jn();window.closeCommandPalette=()=>is();window.setTheme=e=>un(e);window.cycleTheme=()=>Wa();window.measureLatency=()=>Cs();window.switchProfileTab=e=>fi(e);window.openProfileEditor=()=>Pp();window.closeProfileEditor=()=>Bs();window.saveProfileEditor=()=>Ap();window.selectAvatar=e=>Ep(e);window.selectBanner=e=>Np(e);window.uploadAvatarImage=e=>_p(e);window.removeAvatarImage=()=>Rp();window.uploadBannerImage=e=>Dp(e);window.removeBannerImage=()=>Ip();window.prefSetTheme=e=>tu(e);window.setPrefCurrency=e=>nu(e);window.setPrefNetwork=e=>su(e);window.setPrefAutoLock=e=>au(e);window.openPublicProfilePreview=()=>eu();window.exportVaultBackup=()=>Fp();window.logActivity=(e,t)=>gt(e,t);window.toggleWalletDrawer=e=>yp(e);window.switchWalletDrawerTab=(e,t)=>wp(e,t);window.cancelOffer=(e,t,n)=>kp(e,t,n);window.fetchBalance=e=>Pn(e);window.setActiveWallet=e=>Vc(e);window.openImportAddressModal=()=>Gp();window.closeImportAddressModal=()=>Ti();window.importWatchOnlyWallet=()=>Kp();window.openImportSeedModal=()=>Jp();window.closeImportSeedModal=()=>Ci();window.executeImportFromSeed=()=>Yp();window.openTokenDetailsModal=(e,t,n)=>Qp(e,t,n);window.closeTokenDetailsModal=()=>Zp();window.refreshXrplDashboard=()=>ns();window.refreshMarketData=()=>rp();window.refreshNftGallery=()=>lp();window.refreshAmmPools=()=>cp();window.refreshPoolExplorer=()=>dp();window.loadCustomAmmPool=()=>ed();window.sendNft=e=>pp(e);window.toggleSeedBackupStatus=()=>pd();window.setDexPair=e=>ud(e);window.setDexInterval=e=>md(e);window.setDexChartType=e=>fd(e);window.refreshDexChart=()=>hd();window.setComparePair=e=>Pd(e);window.toggleIndicator=(e,t)=>gd(e,t);window.toggleTerminalTheme=()=>Hd();window.toggleChartFullscreen=()=>zd();window.exportChartPng=()=>Ud();window.saveChartLayoutPreset=()=>jd();window.loadChartLayoutPreset=()=>qd();window.setIndicatorFromDropdown=e=>Ad(e);window.toggleIndicatorMenu=()=>vd();window.toggleChartMoreMenu=()=>bd();window.setIndicatorQuery=e=>yd(e);window.addIndicatorFromMenu=e=>wd(e);window.removeIndicator=e=>xd(e);window.openIndicatorSettings=e=>kd(e);window.closeIndicatorSettings=()=>$d();window.applyIndicatorSettings=e=>Sd(e);window.resetIndicatorSettings=e=>Td(e);window.copyChartLink=()=>Cd();window.toggleThreeEffects=()=>Ld();window.setThreeEffects=e=>Md(e);window.editAiSettings=e=>Sp(e);window.saveAiSettings=()=>Tp();window.clearAiSettings=()=>Cp();window.setDrawingTool=e=>Ed(e);window.clearAllDrawings=()=>Rd();window.addPriceAlert=()=>Nd();window.removePriceAlert=e=>_d(e);window.zoomChartIn=()=>Dd();window.zoomChartOut=()=>Id();window.panChartLeft=()=>Fd();window.panChartRight=()=>Bd();window.toggleEducationPanel=()=>Od();window.selectEducationTab=e=>Xd(e);window.searchTokens=e=>Kd(e);window.lookupIssuedAsset=()=>op();window.addTokenToWatchlist=e=>tp(e);window.removeTokenFromWatchlist=e=>np(e);window.openTokenOnChart=e=>Ia(e);window.loadToken=e=>sp(e);window.refreshTokenDiscovery=()=>ap();window.refreshRecentTransactions=()=>ip();window.setTokenFilter=(e,t)=>Jd(e,t);window.selectTokenDetails=e=>ep(e);window.showMoreIssuedTokens=()=>Yd();window.showAllIssuedTokens=()=>Qd();window.resetIssuedTokenLimit=()=>Zd();window.openWalletCreator=()=>$i();window.closeWalletCreator=()=>Os();window.wizardNext=()=>Bp();window.wizardBack=()=>Op();window.selectAlgo=e=>Xp(e);window.selectWalletEmoji=e=>Hp(e);window.selectWalletColor=e=>zp(e);window.toggleSecurityCheck=e=>Up(e);window.revealSeed=()=>jp();window.copySeed=()=>qp();window.copyAddress=()=>Vp();window.copyToClipboard=e=>Li(e);window.deleteWallet=e=>vp(e);window.inspectWalletAddr=e=>bp(e);window.openSocialModal=e=>mp(e);window.closeSocialModal=()=>os();window.saveSocialModal=()=>fp();window.deleteSocial=()=>hp();window.viewSocial=e=>gp(e);window._openAuth=Qa;window._goHome=mn;window._cycleTheme=Wa;window._showProfile=qa;document.addEventListener("DOMContentLoaded",()=>{var e;console.log("\u{1F30A} NaluLF: booting\u2026"),er(),mn(),iu(),ru(),lu(),du(),Ty(),window.addEventListener("naluxrp:pagechange",t=>{var s;let n=(s=t==null?void 0:t.detail)==null?void 0:s.pageId;(n==="dashboard"||n==="inspector"||n==="profile")&&mu(),Oa&&Ni()}),window.addEventListener("naluxrp:tabchange",()=>{Oa&&Ni()}),document.addEventListener("keydown",t=>{var s;let n=["INPUT","TEXTAREA"].includes((s=document.activeElement)==null?void 0:s.tagName);if((t.ctrlKey||t.metaKey)&&t.key==="k"){t.preventDefault(),Ei();return}if(t.key==="/"&&!n){t.preventDefault(),Ei();return}t.key==="Escape"&&(is(),qt(),Bs(),Os(),os())}),(e=document.getElementById("auth-overlay"))==null||e.addEventListener("click",t=>{t.target===t.currentTarget&&qt()}),vr()&&(mu(),fn(),import("./xrpl-6AERZ5KD.js").then(({connectXRPL:t})=>t())),console.log("\u2705 NaluLF: ready")});function Ty(){hu(),setInterval(()=>{document.hidden||hu()},3e4)}async function fu(e){let t=[s=>`https://corsproxy.io/?${encodeURIComponent(s)}`,s=>`https://api.allorigins.win/raw?url=${encodeURIComponent(s)}`],n=async s=>{let a=typeof(AbortSignal==null?void 0:AbortSignal.timeout)=="function"?AbortSignal.timeout(7e3):void 0,o=await fetch(s,{mode:"cors",cache:"no-store",signal:a});if(!o.ok)throw new Error(`HTTP ${o.status}`);return await o.json()};try{return await n(e)}catch{for(let s of t)try{return await n(s(e))}catch{}throw new Error("Price feed unreachable")}}async function hu(){try{let e=await fu("https://api.exchange.coinbase.com/products/XRP-USD/ticker"),t=await fu("https://api.exchange.coinbase.com/products/XRP-USD/candles?granularity=86400");if(e!=null&&e.price){let n=Number(e.price),s=Array.isArray(t)&&t.length?t[0]:null,a=s?Number(s[3]||n):n,o=a?(n-a)/a*100:0,i=document.getElementById("xrpPrice"),r=document.getElementById("xrpChange");if(i&&(i.textContent=`$${Number(n).toFixed(3)}`),r){let l=o>=0;r.textContent=`${l?"+":""}${Number(o).toFixed(2)}%`,r.className=`xrp-price-change ${Math.abs(o)<.1?"flat":l?"up":"down"}`}}}catch{}}
