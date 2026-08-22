import{a as Xr,b as xo,c as Cn,d as It,e as w,f as Xe,g as y,h as He,i as _,j as z,k as Q,l as Z,m as bt,n as ge,o as ne,p as he,q as Wt,r as X,s as fa,v as Ee,w as Hr}from"./chunk-R7KFE7J7.js";function Pn(e){Cn.includes(e)||(e="gold"),X.currentTheme=e,Cn.forEach(t=>document.body.classList.remove(`theme-${t}`)),document.body.classList.add(`theme-${e}`),Z(xo,e)}function ko(){let e=Cn.indexOf(X.currentTheme);Pn(Cn[(e+1)%Cn.length])}function zr(){let e=Q(xo);Pn(Cn.includes(e)?e:"gold")}var jr={landing:"landing-page",dashboard:"dashboard",inspector:"inspector",profile:"dashboard"};function $o(e){document.body.classList.remove("modal-open"),Object.values(jr).forEach(i=>document.body.classList.remove(i)),document.body.classList.add(jr[e]||"dashboard");let t=w("landing"),n=w("dashboard"),s=w("profile-page");t&&(t.style.display=e==="landing"?"":"none"),n&&(n.style.display=e==="dashboard"?"":"none"),s&&(s.style.display=e==="profile"?"":"none");let a=e==="landing",o={landingActions:w("navbar-landing-actions"),dashActions:w("navbar-dash-actions"),navConn:w("navbar-conn"),cmdkHint:w("cmdk-hint"),helpBtn:w("help-trigger")};o.landingActions&&(o.landingActions.style.display=a?"":"none"),o.dashActions&&(o.dashActions.style.display=a?"none":""),o.navConn&&(o.navConn.style.display=a?"none":""),o.cmdkHint&&(o.cmdkHint.style.display=a?"none":""),o.helpBtn&&(o.helpBtn.style.display=a?"none":""),X.currentPage=e,window.scrollTo({top:0,behavior:"smooth"}),window.dispatchEvent(new CustomEvent("naluxrp:pagechange",{detail:{pageId:e}}))}function Mn(){$o("landing")}function Ln(){$o("dashboard")}function So(){$o("profile")}function An(e,t){Xe(".dash-tab").forEach(n=>{n.classList.toggle("active",n===e),n.setAttribute("aria-selected",String(n===e))}),["stream","inspector","network"].forEach(n=>{let s=w(`tab-${n}`);s&&(s.style.display=n===t?"":"none")}),t==="inspector"?(document.body.classList.remove("dashboard"),document.body.classList.add("inspector")):(document.body.classList.remove("inspector"),document.body.classList.add("dashboard")),X.currentTab=t,window.dispatchEvent(new CustomEvent("naluxrp:tabchange",{detail:{tabId:t}}))}var Ur="naluxrp_tour_seen",on=[{title:"Welcome to NaluLF \u{1F30A}",body:"A 20-second tour of the three things people miss most. Skip anytime."},{selector:"#cmdk-hint",title:"Jump anywhere, instantly",body:"Press <kbd>Ctrl</kbd>+<kbd>K</kbd> (or <kbd>/</kbd>) from any page. Paste an address in and it offers to inspect it directly \u2014 no need to navigate first."},{selector:"#dash-tab-inspector",title:"Inspect any wallet",body:"Full forensic suite \u2014 trust lines, fund flow, convergence signals, AI-assisted explanations \u2014 for any XRPL address, not just your own."},{selector:".user-chip",title:"Your Profile has more than wallets",body:"Portfolio analytics, activity history, and Project Intelligence \u2014 liquidity depth, holder concentration, and issuer-risk scoring for any token \u2014 all live there."}],st=0,Co=!1,Ps=null,Ft=null;function qr(){Q(Ur)||setTimeout(Po,700)}function Po(){Co||(Co=!0,st=0,Im(),Mo())}function Im(){if(w("tourOverlay"))return;let e=document.createElement("div");e.id="tourOverlay",e.className="tour-overlay",e.innerHTML='<div class="tour-card" id="tour-card"></div>',document.body.appendChild(e),e.addEventListener("click",t=>{t.target===e&&ha()})}function To(e){if(!e)return null;let t=document.querySelector(e);if(!t)return null;let n=t.getBoundingClientRect();return n.width>0||n.height>0?t:null}function Vr(){Ps==null||Ps.classList.remove("tour-highlight"),Ps=null}function Mo(){for(;st<on.length&&on[st].selector&&!To(on[st].selector);)st++;if(st>=on.length)return Lo();let e=on[st],t=w("tourOverlay"),n=w("tour-card");t.classList.add("show"),Vr();let s=To(e.selector);s&&(s.scrollIntoView({block:"center",behavior:"smooth"}),s.classList.add("tour-highlight"),Ps=s),n.innerHTML=`
    <div class="tour-step-count">${st+1} / ${on.length}</div>
    <div class="tour-title">${e.title}</div>
    <div class="tour-body">${e.body}</div>
    <div class="tour-actions">
      <button class="tour-btn tour-btn--ghost" onclick="tourSkip()">Skip tour</button>
      <div class="tour-actions-right">
        ${st>0?'<button class="tour-btn tour-btn--ghost" onclick="tourPrev()">Back</button>':""}
        <button class="tour-btn tour-btn--primary" onclick="tourNext()">${st===on.length-1?"Done":"Next"}</button>
      </div>
    </div>`,Wr(s,n),Ft&&(window.removeEventListener("resize",Ft),window.removeEventListener("scroll",Ft,!0)),Ft=()=>Wr(To(e.selector),n),window.addEventListener("resize",Ft),window.addEventListener("scroll",Ft,!0)}function Wr(e,t){if(!e){t.classList.add("tour-card--centered");return}t.classList.remove("tour-card--centered"),t.style.visibility="hidden",requestAnimationFrame(()=>{let n=e.getBoundingClientRect(),s=t.offsetWidth||320,a=t.offsetHeight||160,i=window.innerHeight-n.bottom>a+28?n.bottom+16:Math.max(16,n.top-a-16),r=n.left+n.width/2-s/2;r=Math.min(Math.max(16,r),window.innerWidth-s-16),t.style.top=`${i}px`,t.style.left=`${r}px`,t.style.visibility="visible"})}function Gr(){st++,st>=on.length?Lo():Mo()}function Kr(){st=Math.max(0,st-1),Mo()}function ha(){Lo()}function Lo(){var e;Co=!1,Z(Ur,"1"),Vr(),(e=w("tourOverlay"))==null||e.classList.remove("show"),Ft&&(window.removeEventListener("resize",Ft),window.removeEventListener("scroll",Ft,!0),Ft=null)}var Ot="naluxrp_vault_meta",Ut="naluxrp_vault_data",Qn="naluxrp_session",Eo="nalulf_used_names",No="nalulf_used_emails",Ro="nalulf_used_domains",Ao=15e4,ga="naluxrp_v2",Qe={_key:null,_vault:null,_lockTimer:null,AUTO_LOCK_MS:30*60*1e3,get isUnlocked(){return this._key!==null&&this._vault!==null},get vault(){return this._vault},hasVault(){return!!Q(Ot)&&!!Q(Ut)},async create(e,t,n,s){let a=crypto.getRandomValues(new Uint8Array(32));this._key=await this._deriveKey(e,a);let o=(s||t).toLowerCase().replace(/[^a-z0-9_]/g,"");return this._vault={checksum:ga,identity:{name:t,email:n,domain:o,createdAt:new Date().toISOString()},profile:{},wallets:[],social:{}},Z(Ot,JSON.stringify({salt:Array.from(a),iterations:Ao,version:ga})),await this._persist(),this._startLockTimer(),this._vault},async unlock(e){let t=ge(Q(Ot));if(!t)throw new Error("No account found. Create one first.");this._key=await this._deriveKey(e,new Uint8Array(t.salt));let n;try{let s=ge(Q(Ut));if(!s)throw new Error("missing");n=await this._decrypt(s)}catch{throw this._key=null,new Error("Incorrect password. Please try again.")}if((n==null?void 0:n.checksum)!==ga)throw this._key=null,new Error("Account data corrupted. Restore from backup.");return this._vault=n,this._startLockTimer(),this._vault},async update(e){if(!this.isUnlocked)throw new Error("Sign in to continue.");e(this._vault),await this._persist()},lock(){this._key=null,this._vault=null,clearTimeout(this._lockTimer),this._lockTimer=null},resetTimer(){this.isUnlocked&&this._startLockTimer()},async changePassword(e){if(!this.isUnlocked)throw new Error("Sign in first.");let t=crypto.getRandomValues(new Uint8Array(32));this._key=await this._deriveKey(e,t),Z(Ot,JSON.stringify({salt:Array.from(t),iterations:Ao,version:ga})),await this._persist()},async exportBlob(){if(!this.isUnlocked)throw new Error("Sign in before exporting.");let e={vault:ge(Q(Ut)),meta:ge(Q(Ot)),exportedAt:new Date().toISOString()},t=URL.createObjectURL(new Blob([JSON.stringify(e,null,2)],{type:"application/json"}));Object.assign(document.createElement("a"),{href:t,download:`naluxrp-backup-${Date.now()}.json`}).click(),URL.revokeObjectURL(t)},async _deriveKey(e,t){let n=new TextEncoder,s=await crypto.subtle.importKey("raw",n.encode(e),"PBKDF2",!1,["deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt:t,iterations:Ao,hash:"SHA-256"},s,{name:"AES-GCM",length:256},!1,["encrypt","decrypt"])},async _encrypt(e){let t=crypto.getRandomValues(new Uint8Array(12)),n=new TextEncoder,s=await crypto.subtle.encrypt({name:"AES-GCM",iv:t},this._key,n.encode(JSON.stringify(e)));return{iv:Array.from(t),cipher:Array.from(new Uint8Array(s))}},async _decrypt(e){let t=new TextDecoder,n=await crypto.subtle.decrypt({name:"AES-GCM",iv:new Uint8Array(e.iv)},this._key,new Uint8Array(e.cipher).buffer);return JSON.parse(t.decode(n))},async _persist(){!this._key||!this._vault||Z(Ut,JSON.stringify(await this._encrypt(this._vault)))},_startLockTimer(){clearTimeout(this._lockTimer),this._lockTimer=setTimeout(()=>{this.lock(),window.dispatchEvent(new CustomEvent("naluxrp:vault-locked"))},this.AUTO_LOCK_MS)}},lt=1;function Do(e){var t;Qe.hasVault()?rn(e||"login"):rn("welcome"),(t=w("auth-overlay"))==null||t.classList.add("show")}function ln(){var e;(e=w("auth-overlay"))==null||e.classList.remove("show"),cn(),lt=1,En(1)}function rn(e){var s,a,o,i,r;wa(".auth-view").forEach(l=>l.classList.remove("active")),(s=w(`auth-view-${e}`))==null||s.classList.add("active"),(a=w("auth-overlay"))==null||a.setAttribute("data-view",e);let t=["welcome","forgot","sync","celebrate","syncaware"].includes(e),n=w("auth-tab-row");n&&(n.style.display=t?"none":""),(o=w("tab-login-btn"))==null||o.classList.toggle("active",e==="login"),(i=w("tab-signup-btn"))==null||i.classList.toggle("active",e==="signup"),(r=w("tab-sync-btn"))==null||r.classList.toggle("active",e==="sync"),e==="signup"&&(lt=1,En(1),Jn()),cn()}function En(e){[1,2,3].forEach(s=>{let a=w(`signup-step-${s}`);a&&(a.style.display=s===e?"":"none");let o=w(`signup-dot-${s}`);o&&(o.classList.toggle("active",s===e),o.classList.toggle("done",s<e))});let t=["","Step 1 of 3 \u2014 Identity","Step 2 of 3 \u2014 Security","Step 3 of 3 \u2014 Sync setup"],n=w("signup-step-label");n&&(n.textContent=t[e]||"")}function Io(){var e,t,n,s,a,o;if(cn(),lt===1){let i=((e=w("inp-signup-name"))==null?void 0:e.value.trim())||"",r=((t=w("inp-signup-email"))==null?void 0:t.value.trim())||"",l=((n=w("inp-signup-domain"))==null?void 0:n.value.trim())||"";if(!i||i.length<3)return Ne("Display name must be at least 3 characters.");if(el(i))return Ne(`"${i}" is already in use on this device.`);if(!r||!r.includes("@"))return Ne("Enter a valid email address.");if(tl(r))return Ne("That email is already registered on this device.");if(l&&nl(l))return Ne(`@${l} is already taken on this device.`);if(l&&!/^[a-z0-9_]{2,30}$/.test(l))return Ne("Handle: 2-30 lowercase letters, numbers, underscores only.");lt=2,En(2),Jn(),setTimeout(()=>{var c;return(c=w("inp-signup-pass"))==null?void 0:c.focus()},80)}else if(lt===2){let i=((s=w("inp-signup-pass"))==null?void 0:s.value)||"",r=((a=w("inp-signup-confirm"))==null?void 0:a.value)||"";if(!i||i.length<8)return Ne("Password must be at least 8 characters.");if(!ml(i))return Ne("Add uppercase, lowercase, and a number.");if(i!==r)return Ne("Passwords do not match.");if(!Zr())return Jn(),Ne("Type the word from the image exactly.");lt=3,En(3);let l=w("syncaware-name"),c=((o=w("inp-signup-name"))==null?void 0:o.value.trim())||"there";l&&(l.textContent=c.split(" ")[0])}}function Yr(){lt>1&&(lt--,En(lt),cn(),lt===1&&setTimeout(()=>{var e;return(e=w("inp-signup-name"))==null?void 0:e.focus()},80))}var Jr=["XRPL","LEDGER","VAULT","CRYPTO","BLOCK","TOKEN","CHAIN","WAVE","ATLAS","FORGE","NEXUS","ORBIT","PRISM","DELTA","NOVA","SONIC","PIXEL","GHOST","FLARE","SPARK","TITAN","LUNAR","STORM","PROXY","CIPHER","RELAY","PULSE","SCOUT"],_o="";function Jn(){_o=Jr[Math.floor(Math.random()*Jr.length)];let e=document.getElementById("captcha-canvas"),t=w("inp-captcha");if(t&&(t.value=""),!e)return;let n=e.getContext("2d"),s=e.width,a=e.height;n.clearRect(0,0,s,a),n.fillStyle="#080f1e",n.fillRect(0,0,s,a),n.strokeStyle="rgba(0,255,240,.05)",n.lineWidth=1;for(let r=0;r<s;r+=18)n.beginPath(),n.moveTo(r,0),n.lineTo(r,a),n.stroke();for(let r=0;r<a;r+=18)n.beginPath(),n.moveTo(0,r),n.lineTo(s,r),n.stroke();for(let r=0;r<55;r++)n.fillStyle=`rgba(${Math.random()>.5?"0,255,240":"160,180,255"},${(Math.random()*.22+.05).toFixed(2)})`,n.beginPath(),n.arc(Math.random()*s,Math.random()*a,Math.random()*2+.5,0,Math.PI*2),n.fill();for(let r=0;r<4;r++)n.strokeStyle=`rgba(0,255,240,${(Math.random()*.1+.03).toFixed(2)})`,n.lineWidth=1,n.beginPath(),n.moveTo(0,Math.random()*a),n.bezierCurveTo(s*.3,Math.random()*a,s*.7,Math.random()*a,s,Math.random()*a),n.stroke();let o=_o.split(""),i=(s-o.length*26)/2+8;o.forEach((r,l)=>{let c=i+l*26+(Math.random()*8-4),u=a/2+8+(Math.random()*10-5);n.save(),n.translate(c,u),n.rotate(Math.random()*.35-.175),n.shadowColor="rgba(0,255,240,.5)",n.shadowBlur=8,n.fillStyle=`rgb(${Math.random()>.4?"180,255,240":"140,200,255"})`,n.font=`bold ${24+Math.random()*4}px 'JetBrains Mono','Courier New',monospace`,n.fillText(r,0,0),n.restore()})}function Qr(){Jn()}function Zr(){var e;return(((e=w("inp-captcha"))==null?void 0:e.value)||"").trim().toUpperCase()===_o}function el(e){return(ge(Q(Eo))||[]).some(t=>t.toLowerCase()===e.toLowerCase())}function tl(e){return(ge(Q(No))||[]).some(t=>t.toLowerCase()===e.toLowerCase())}function nl(e){return(ge(Q(Ro))||[]).some(t=>t.toLowerCase()===e.toLowerCase())}function Fm(e,t,n){let s=ge(Q(Eo))||[],a=ge(Q(No))||[],o=ge(Q(Ro))||[];s.includes(e.toLowerCase())||s.push(e.toLowerCase()),a.includes(t.toLowerCase())||a.push(t.toLowerCase()),n&&!o.includes(n.toLowerCase())&&o.push(n.toLowerCase()),Z(Eo,JSON.stringify(s)),Z(No,JSON.stringify(a)),Z(Ro,JSON.stringify(o))}async function Fo(){var s,a,o;if(qt)return;let e=((s=w("inp-login-email"))==null?void 0:s.value.trim())||"",t=((a=w("inp-login-pass"))==null?void 0:a.value)||"";if(cn(),!e)return Ne("Enter your email address.");if(!t)return Ne("Enter your password.");let n=w("signin-btn");qt=!0,Yn(n,!0,"Signing in\u2026");try{let i=await Qe.unlock(t);X.session={name:i.identity.name,email:i.identity.email,domain:i.identity.domain||""},Z(Qn,JSON.stringify(X.session)),ln(),ya(X.session),Ln(),fa(),window.dispatchEvent(new CustomEvent("naluxrp:vault-ready",{detail:Qe.vault})),Xm()}catch(i){Ne(i.message),(o=w("auth-modal-inner"))==null||o.classList.add("shake"),setTimeout(()=>{var r;return(r=w("auth-modal-inner"))==null?void 0:r.classList.remove("shake")},500)}finally{qt=!1,Yn(n,!1,"Sign In \u2192")}}async function Oo(){var i,r,l,c,u;if(qt)return;let e=((i=w("inp-signup-name"))==null?void 0:i.value.trim())||"",t=((r=w("inp-signup-email"))==null?void 0:r.value.trim())||"",n=((l=w("inp-signup-domain"))==null?void 0:l.value.trim())||e.toLowerCase().replace(/[^a-z0-9_]/g,"_"),s=((c=w("inp-signup-pass"))==null?void 0:c.value)||"",a=((u=w("inp-signup-confirm"))==null?void 0:u.value)||"";if(cn(),!s||s.length<8)return Ne("Password must be at least 8 characters.");if(!ml(s))return Ne("Add uppercase, lowercase, and a number.");if(s!==a)return Ne("Passwords do not match.");if(!Zr())return Jn(),lt=2,En(2),Ne("Type the word from the image exactly.");let o=w("signup-btn-create");qt=!0,Yn(o,!0,"Creating vault\u2026");try{await Qe.create(s,e,t,n),Fm(e,t,n),X.session={name:e,email:t,domain:n},Z(Qn,JSON.stringify(X.session)),ya(X.session),Om(e,()=>{ln(),Ln(),fa(),window.dispatchEvent(new CustomEvent("naluxrp:vault-ready",{detail:Qe.vault})),qr(),setTimeout(Hm,3500)})}catch(d){Ne(d.message),Jn(),lt=2,En(2)}finally{qt=!1,Yn(o,!1,"Create Account \u2192")}}function Om(e,t){rn("celebrate");let n=w("celebrate-name");n&&(n.textContent=e.split(" ")[0]);let s=setTimeout(t,2800),a=w("celebrate-continue-btn");a&&(a.onclick=()=>{clearTimeout(s),t()})}function sl(){rn("forgot"),wa(".forgot-step").forEach(t=>t.style.display="none");let e=w("forgot-step-options");e&&(e.style.display="")}function al(){let e=document.createElement("input");e.type="file",e.accept=".json,application/json",e.onchange=async t=>{let n=t.target.files[0];if(n)try{let s=await n.text(),a=JSON.parse(s);if(!(a!=null&&a.vault)||!(a!=null&&a.meta))throw new Error("Invalid backup file.");Z(Ut,JSON.stringify(a.vault)),Z(Ot,JSON.stringify(a.meta)),ne("Backup restored \u2014 sign in with your original password."),rn("login")}catch(s){Wt("Could not read backup: "+s.message)}},e.click()}function ol(){wa(".forgot-step").forEach(n=>n.style.display="none");let e=w("forgot-step-wipe");e&&(e.style.display="");let t=w("inp-wipe-confirm");t&&(t.value="")}function il(){var t;if((((t=w("inp-wipe-confirm"))==null?void 0:t.value.trim())||"")!=="DELETE")return Ne("Type DELETE exactly.");bt(Ot),bt(Ut),bt(Qn),Qe.lock(),X.session=null,ne("Account cleared. Create a new one."),ln(),rn("signup"),window.dispatchEvent(new Event("naluxrp:logout"))}function rl(){wa(".forgot-step").forEach(t=>t.style.display="none");let e=w("forgot-step-options");e&&(e.style.display=""),cn()}function ll(){let e=Q(Ut),t=Q(Ot);if(!e||!t){Wt("No vault to export.");return}let n=btoa(JSON.stringify({vault:JSON.parse(e),meta:JSON.parse(t)})),s=document.createElement("div");s.id="sync-code-overlay",s.style.cssText="position:fixed;inset:0;background:rgba(0,0,0,.92);backdrop-filter:blur(14px);z-index:99999;display:flex;align-items:center;justify-content:center;padding:20px;",s.innerHTML=`<div style="background:#0d1829;border:1.5px solid rgba(0,255,240,.22);border-radius:22px;padding:28px;max-width:500px;width:100%;box-shadow:0 28px 70px rgba(0,0,0,.95);"><div style="font-size:1rem;font-weight:900;margin-bottom:6px;color:#00fff0;">\u{1F4F1} Vault Sync Code</div><p style="font-size:.82rem;color:rgba(255,255,255,.55);margin-bottom:16px;line-height:1.6;">On your new device open NaluLF \u2192 <strong style="color:rgba(255,255,255,.8)">\u{1F4F1} New Device</strong> tab, paste this code and enter your password.</p><textarea readonly id="sync-code-output" style="width:100%;height:110px;background:#060e1a;border:1px solid rgba(255,255,255,.12);border-radius:10px;color:rgba(0,255,240,.85);font-family:monospace;font-size:.7rem;padding:10px;resize:none;box-sizing:border-box;" spellcheck="false">${n}</textarea><div style="display:flex;gap:10px;margin-top:14px;justify-content:flex-end;"><button onclick="document.getElementById('sync-code-overlay').remove()" style="padding:9px 16px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);border-radius:9px;color:rgba(255,255,255,.65);font-size:.85rem;font-weight:700;cursor:pointer;font-family:inherit;">Close</button><button onclick="navigator.clipboard.writeText(document.getElementById('sync-code-output').value).then(()=>{this.textContent='\u2713 Copied!';setTimeout(()=>this.textContent='Copy Code',2000)})" style="padding:9px 18px;background:linear-gradient(135deg,#00d4ff,#00fff0);border:none;border-radius:9px;color:#000;font-size:.85rem;font-weight:900;cursor:pointer;font-family:inherit;">Copy Code</button></div></div>`,document.body.appendChild(s),s.addEventListener("click",a=>{a.target===s&&s.remove()})}async function Bo(){var s,a;if(qt)return;let e=((s=w("inp-sync-code"))==null?void 0:s.value.trim())||"",t=((a=w("inp-sync-pass"))==null?void 0:a.value)||"";if(cn(),!e)return Ne("Paste your vault sync code or load a backup file first.");if(!t)return Ne("Enter the password from your original device.");let n=document.querySelector("#auth-view-sync .auth-submit-btn");qt=!0,Yn(n,!0,"Importing\u2026");try{let o;try{o=JSON.parse(atob(e))}catch{try{o=JSON.parse(e)}catch{throw new Error("Invalid sync code. Paste the full code from your other device.")}}if(!(o!=null&&o.vault)||!(o!=null&&o.meta))throw new Error("Invalid sync code format \u2014 make sure you copied the entire code.");Z(Ut,JSON.stringify(o.vault)),Z(Ot,JSON.stringify(o.meta));let i=await Qe.unlock(t);X.session={name:i.identity.name,email:i.identity.email,domain:i.identity.domain||""},Z(Qn,JSON.stringify(X.session)),ln(),ya(X.session),Ln(),fa(),window.dispatchEvent(new CustomEvent("naluxrp:vault-ready",{detail:Qe.vault})),ne("\u2705 Account imported to this device!")}catch(o){let i=o.message.includes("decrypt")||o.message.includes("Incorrect");Ne(i?"Wrong password \u2014 use the password from your original device.":"Could not import: "+o.message),bt(Ut),bt(Ot)}finally{qt=!1,Yn(n,!1,"Import & Sign In \u2192")}}function cl(){let e=document.createElement("input");e.type="file",e.accept=".json,application/json",e.onchange=async t=>{var s;let n=t.target.files[0];if(n)try{let a=await n.text(),o=JSON.parse(a);if(!(o!=null&&o.vault)||!(o!=null&&o.meta))throw new Error("Invalid backup file format.");let i=w("inp-sync-code");i&&(i.value=btoa(JSON.stringify({vault:o.vault,meta:o.meta})));let r=w("sync-file-feedback");r&&(r.textContent=`\u2713 File loaded: ${n.name}`,r.style.color="#50fa7b"),(s=w("inp-sync-pass"))==null||s.focus()}catch(a){Wt("Could not read backup: "+a.message)}},e.click()}function dl(){Qe.lock(),X.session=null,bt(Qn),Mn(),window.dispatchEvent(new Event("naluxrp:logout"))}function pl(){let e=ge(Q(Qn));return e!=null&&e.email&&Qe.hasVault()?(X.session=e,ya(e),!0):!1}function Bm(){if(w("vault-lock-banner"))return;let e=document.createElement("div");e.id="vault-lock-banner",e.className="vault-lock-banner",e.innerHTML=`<span class="vlb-icon">\u{1F512}</span><span class="vlb-text">Vault locked for security after 30 min of inactivity.</span><button class="vlb-btn" onclick="openAuth('login')">Unlock \u2192</button><button class="vlb-close" onclick="this.closest('.vault-lock-banner').remove()" title="Dismiss">\u2715</button>`,document.body.prepend(e),requestAnimationFrame(()=>e.classList.add("show"))}function Xm(){let e=w("vault-lock-banner");e&&(e.classList.remove("show"),setTimeout(()=>e.remove(),300))}function Hm(){if(w("backup-reminder-banner")||!Qe.hasVault())return;let e=document.createElement("div");e.id="backup-reminder-banner",e.className="backup-reminder-banner",e.innerHTML=`<span class="brb-icon">\u26A0\uFE0F</span><div class="brb-body"><strong>Back up your vault</strong> \u2014 you'll lose access if browser storage is cleared. <button class="brb-btn" onclick="window.exportVaultBackup?.()">Export Backup</button></div><button class="brb-close" onclick="this.closest('.backup-reminder-banner').remove()">\u2715</button>`;let t=document.getElementById("profile-page");t?t.prepend(e):document.body.prepend(e),requestAnimationFrame(()=>e.classList.add("show"))}function ul(e){var n;let t=((n=w("auth-overlay"))==null?void 0:n.getAttribute("data-view"))||"login";if(e.key==="Enter"&&(t==="login"&&Fo(),t==="signup"&&(lt<3?Io():Oo()),t==="sync"&&Bo()),e.key==="Tab"){let s=w("auth-modal-inner");if(!s)return;let a=Array.from(s.querySelectorAll("button:not([disabled]),input,textarea,select")).filter(r=>r.offsetParent!==null);if(!a.length)return;let o=a[0],i=a[a.length-1];e.shiftKey&&document.activeElement===o&&(e.preventDefault(),i.focus()),!e.shiftKey&&document.activeElement===i&&(e.preventDefault(),o.focus())}}function ba(e){let t=w(e);t==null||t.classList.add("valid"),t==null||t.classList.remove("invalid")}function Nn(e){let t=w(e);t==null||t.classList.add("invalid"),t==null||t.classList.remove("valid")}function va(e){let t=w(e);t==null||t.classList.remove("valid","invalid")}window.validateSignupName=()=>{var s;let e=((s=w("inp-signup-name"))==null?void 0:s.value.trim())||"",t=w("hint-signup-name");if(!e){va("inp-signup-name"),t&&(t.textContent="");return}if(e.length<3){Nn("inp-signup-name"),t&&(t.textContent="At least 3 characters");return}if(el(e)){Nn("inp-signup-name"),t&&(t.textContent="Already in use on this device");return}ba("inp-signup-name"),t&&(t.textContent="\u2713 Looks good!");let n=w("inp-signup-domain");n&&!n.dataset.manuallyEdited&&(n.value=e.toLowerCase().replace(/[^a-z0-9]/g,"_").replace(/_+/g,"_").replace(/^_|_$/g,""),window.validateSignupDomain())};window.validateSignupEmail=()=>{var n;let e=((n=w("inp-signup-email"))==null?void 0:n.value.trim())||"",t=w("hint-signup-email");if(!e){va("inp-signup-email"),t&&(t.textContent="");return}if(!e.includes("@")||!e.includes(".")){Nn("inp-signup-email"),t&&(t.textContent="Enter a valid email");return}if(tl(e)){Nn("inp-signup-email"),t&&(t.textContent="Already registered on this device");return}ba("inp-signup-email"),t&&(t.textContent="\u2713 Available")};window.validateSignupDomain=()=>{var s;let e=((s=w("inp-signup-domain"))==null?void 0:s.value.trim())||"",t=w("hint-signup-domain"),n=w("inp-signup-domain");if(!e){va("inp-signup-domain"),t&&(t.textContent="");return}if(!/^[a-z0-9_]{2,30}$/.test(e)){Nn("inp-signup-domain"),t&&(t.textContent="2-30 chars: a-z, 0-9, underscore only");return}if(nl(e)){Nn("inp-signup-domain"),t&&(t.textContent="Already taken on this device");return}ba("inp-signup-domain"),t&&(t.textContent=`\u2713 @${e}`),n&&(n.dataset.manuallyEdited="1")};window.validateLoginEmail=()=>{var t;let e=((t=w("inp-login-email"))==null?void 0:t.value.trim())||"";if(!e)return va("inp-login-email");e.includes("@")?ba("inp-login-email"):Nn("inp-login-email")};window.switchSyncMethod=function(e){var i,r;let t=e==="code";(i=document.getElementById("sync-method-code"))==null||i.classList.toggle("sync-method-card--active",t),(r=document.getElementById("sync-method-file"))==null||r.classList.toggle("sync-method-card--active",!t);let n=document.getElementById("sync-code-section"),s=document.getElementById("sync-file-section"),a=document.getElementById("sync-method-code-steps"),o=document.getElementById("sync-method-file-steps");n&&(n.style.display=t?"":"none"),s&&(s.style.display=t?"none":""),a&&(a.style.display=t?"":"none"),o&&(o.style.display=t?"none":"")};window.togglePwVisibility=function(e,t){let n=w(e);if(!n)return;let s=n.type==="password";n.type=s?"text":"password",t.textContent=s?"\u{1F648}":"\u{1F441}"};window.updatePwStrength=function(e){let t=w("pw-strength-fill"),n=w("pw-strength-label");if(!t||!n)return;let s=0;e.length>=8&&s++,/[A-Z]/.test(e)&&s++,/[a-z]/.test(e)&&s++,/[0-9]/.test(e)&&s++,/[^A-Za-z0-9]/.test(e)&&s++;let a=[{w:"0%",bg:"transparent",txt:""},{w:"20%",bg:"#ff5555",txt:"Very weak"},{w:"40%",bg:"#ff8c42",txt:"Weak"},{w:"60%",bg:"#ffb86c",txt:"Fair"},{w:"80%",bg:"#00d4ff",txt:"Good"},{w:"100%",bg:"#50fa7b",txt:"Strong \u2713"}],o=a[s]||a[0];t.style.width=o.w,t.style.background=o.bg,n.textContent=o.txt,n.style.color=o.bg};function ml(e){return/[A-Z]/.test(e)&&/[a-z]/.test(e)&&/[0-9]/.test(e)}function ya(e){let t=w("user-avatar"),n=w("user-name");t&&(t.textContent=e.name.charAt(0).toUpperCase()),n&&(n.textContent=e.name)}function Ne(e){let t=w("auth-error");t&&(t.textContent=e,t.style.display="")}function cn(){let e=w("auth-error");e&&(e.textContent="")}function Yn(e,t,n){e&&(e.disabled=t,e.textContent=n)}var qt=!1;function wa(e){return Array.from(document.querySelectorAll(e))}["click","keydown","mousemove","touchstart"].forEach(e=>document.addEventListener(e,()=>Qe.resetTimer(),{passive:!0}));window.addEventListener("naluxrp:vault-locked",()=>{X.vaultLocked=!0,Bm()});var zm="https://xrplcluster.com/",jm="https://s2.ripple.com:51234/";async function xa(e,t){var a;try{if(((a=X.wsConn)==null?void 0:a.readyState)===1){let o=await Ee({command:e,...t});if((o==null?void 0:o.status)==="error")throw new Error(o.error_message||o.error||"XRPL RPC error");return(o==null?void 0:o.result)||null}}catch{}let n=JSON.stringify({method:e,params:[t]}),s=async o=>{let i=await fetch(o,{method:"POST",headers:{"Content-Type":"application/json"},body:n,mode:"cors"});if(!i.ok)throw new Error(`HTTP ${i.status}`);return(await i.json()).result};try{return await s(zm)}catch{return await s(jm)}}function es(e){return typeof e=="string"?{value:Number(e)/1e6,isXrp:!0,currency:"XRP"}:e&&typeof e=="object"?{value:Number(e.value||0),isXrp:!1,currency:e.currency,issuer:e.issuer}:{value:0,isXrp:!0,currency:"XRP"}}function Wm(e){let t=String(e||"").trim().toUpperCase();if(t==="XRP"||/^[A-Z0-9?!@#$%^&*(){}[\]|]{3}$/i.test(t)||/^[0-9A-F]{40}$/.test(t))return t;let n=new TextEncoder().encode(t).slice(0,20),s=new Uint8Array(20);return s.set(n),Array.from(s).map(a=>a.toString(16).padStart(2,"0")).join("").toUpperCase()}var dn={lsfRequireAuth:262144,lsfDisableMaster:1048576,lsfNoFreeze:2097152,lsfGlobalFreeze:4194304,lsfDefaultRipple:8388608,lsfAllowTrustLineClawback:2147483648};async function Um(e,t){var n;try{let s=await xa("amm_info",{asset:{currency:"XRP"},asset2:{currency:e,issuer:t}}),a=s==null?void 0:s.amm;if(!a)return{exists:!1};let o=es(a.amount).value,i=es(a.amount2).value,r=es(a.lp_token||a.lp_token_balance).value,l=((n=a.lp_token||a.lp_token_balance)==null?void 0:n.currency)||null;return{exists:!0,account:a.account,xrpReserve:o,tokenReserve:i,lpSupply:r,lpCurrency:l,tradingFeePct:Number(a.trading_fee||0)/1e3,auctionSlot:a.auction_slot?{account:a.auction_slot.account,discountedFeePct:Number(a.auction_slot.discounted_fee||0)/1e3,priceXrp:es(a.auction_slot.price).value,expiration:a.auction_slot.expiration||null}:null,voteSlots:Array.isArray(a.vote_slots)?a.vote_slots.map(c=>({account:c.account,tradingFeePct:Number(c.trading_fee||0)/1e3,voteWeight:Number(c.vote_weight||0)/1e3})):[]}}catch{return{exists:!1,error:!0}}}async function qm(e){try{let t=await xa("account_info",{account:e,ledger_index:"validated"}),n=t==null?void 0:t.account_data;if(!n)return{exists:!1};let s=Number(n.Flags||0),a=o=>(s&o)===o;return{exists:!0,requireAuth:a(dn.lsfRequireAuth),globalFreeze:a(dn.lsfGlobalFreeze),noFreeze:a(dn.lsfNoFreeze),freezeCapable:!a(dn.lsfNoFreeze),defaultRipple:a(dn.lsfDefaultRipple),clawbackEnabled:a(dn.lsfAllowTrustLineClawback),blackholed:a(dn.lsfDisableMaster)&&!n.RegularKey,masterDisabled:a(dn.lsfDisableMaster),hasRegularKey:!!n.RegularKey}}catch{return{exists:!1,error:!0}}}async function bl(e,t,n=8){let s=[],a;for(let o=0;o<n;o++){let i=await xa("account_lines",{account:e,ledger_index:"validated",limit:400,...a?{marker:a}:{}});for(let r of(i==null?void 0:i.lines)||[]){if(r.currency!==t)continue;let l=-Number(r.balance||0);l>0&&s.push({address:r.account,balance:l})}if(a=i==null?void 0:i.marker,!a)break}return s}function vl(e){let t=[...e].sort((a,o)=>o.balance-a.balance),n=t.reduce((a,o)=>a+o.balance,0),s=a=>n>0?t.slice(0,a).reduce((o,i)=>o+i.balance,0)/n*100:0;return{holderCount:t.length,totalSampled:n,top1Pct:s(1),top5Pct:s(5),top10Pct:s(10),topHolders:t.slice(0,10)}}async function Vm(e,t){try{let n=await bl(e,t);return n.length?{exists:!0,...vl(n),sampleOnly:!0}:{exists:!1}}catch{return{exists:!1,error:!0}}}async function Gm(e,t){if(!e||!t)return{exists:!1};try{let n=await bl(e,t);return n.length?{exists:!0,...vl(n)}:{exists:!1}}catch{return{exists:!1,error:!0}}}var Km=[1,2,5,10,25];async function fl(e,t,n){let o=await xa("book_offers",{taker_gets:n==="buy"?{currency:e,issuer:t}:{currency:"XRP"},taker_pays:n==="buy"?{currency:"XRP"}:{currency:e,issuer:t},limit:200,ledger_index:"validated"});return((o==null?void 0:o.offers)||[]).map(r=>{let l=es(r.taker_gets_funded??r.TakerGets).value,c=es(r.taker_pays_funded??r.TakerPays).value;return l<=0||c<=0?null:{gets:l,pays:c,quality:c/l}}).filter(Boolean).sort((r,l)=>r.quality-l.quality)}function hl(e){if(!e.length)return{bestPrice:null,levels:[]};let t=e[0].quality,n=Km.map(s=>{let a=t*(1+s/100),o=0,i=0,r=!0;for(let l of e){if(l.quality>a){r=!1;break}o+=l.pays,i+=l.gets}return{pct:s,xrpAtOffer:o,tokenAtOffer:i,bookExhausted:r}});return{bestPrice:t,levels:n}}async function Jm(e,t){try{let[n,s]=await Promise.all([fl(e,t,"buy"),fl(e,t,"sell")]);if(!n.length&&!s.length)return{exists:!1};let a=hl(s.map(l=>({...l,gets:l.pays,pays:l.gets}))),o=hl(n),i=a.bestPrice?1/a.bestPrice:null,r=o.bestPrice&&i?(o.bestPrice-i)/i*100:null;return{exists:!0,buySideOfferCount:n.length,sellSideOfferCount:s.length,buyPriceXrp:o.bestPrice,sellPriceXrp:i,spreadPct:r,buyDepth:o.levels,sellDepth:a.levels}}catch{return{exists:!1,error:!0}}}var Xo={liquidity:31.25,distribution:18.75,marketQuality:18.75,lpStability:18.75,issuerRisk:12.5};function yl(e){return Math.max(0,Math.min(100,e))}function Zn(e,t,n){return n===t?0:yl((e-t)/(n-t)*100)}function Ym({amm:e,orderBook:t,holders:n,lp:s,issuer:a}){var p;let o={},i=e!=null&&e.exists?e.xrpReserve*2:0,r=t!=null&&t.exists&&((p=t.buyDepth.find(m=>m.pct===2))==null?void 0:p.xrpAtOffer)||0;o.liquidity={score:Math.round((Zn(i,0,1e5)+Zn(r,0,2e4))/2),inputs:{ammTvlXrp:i,depthTo2PctXrp:r,ammExists:!!(e!=null&&e.exists),orderBookExists:!!(t!=null&&t.exists)}},o.distribution={score:n!=null&&n.exists?Math.round(Zn(n.top10Pct,90,20)):0,inputs:{top1Pct:(n==null?void 0:n.top1Pct)??null,top5Pct:(n==null?void 0:n.top5Pct)??null,top10Pct:(n==null?void 0:n.top10Pct)??null,holderCount:(n==null?void 0:n.holderCount)??0,sampleOnly:(n==null?void 0:n.sampleOnly)??!0}};let l=t!=null&&t.exists?Math.abs(t.spreadPct??100):100;o.marketQuality={score:t!=null&&t.exists?Math.round(Zn(l,15,0)):0,inputs:{spreadPct:(t==null?void 0:t.spreadPct)??null,buySideOfferCount:(t==null?void 0:t.buySideOfferCount)??0,sellSideOfferCount:(t==null?void 0:t.sellSideOfferCount)??0}},o.lpStability={score:s!=null&&s.exists?Math.round((Zn(s.top1Pct,100,20)+Zn(s.holderCount,1,25))/2):0,inputs:{top1Pct:(s==null?void 0:s.top1Pct)??null,top5Pct:(s==null?void 0:s.top5Pct)??null,holderCount:(s==null?void 0:s.holderCount)??0}};let c=100,u={clawbackEnabled:!1,globalFreeze:!1,freezeCapable:!1,requireAuth:!1,blackholed:!1};a!=null&&a.exists?(u.clawbackEnabled=a.clawbackEnabled,u.globalFreeze=a.globalFreeze,u.freezeCapable=a.freezeCapable,u.requireAuth=a.requireAuth,u.blackholed=a.blackholed,a.clawbackEnabled&&(c-=30),a.globalFreeze&&(c-=25),a.freezeCapable&&(c-=10),a.requireAuth&&(c-=10),a.blackholed&&(c+=15)):c=0,o.issuerRisk={score:yl(Math.round(c)),inputs:u};let d=Object.entries(Xo).reduce((m,[f,g])=>m+o[f].score*g/100,0);return{overall:Math.round(d),subScores:o,weights:Xo,dimensionsLive:Object.keys(Xo),dimensionsDeferred:["networkActivity","treasuryHealth","transparency"]}}async function wl(e){let t=Wm(e.currency||e.symbol),n=e.issuer;if(!n)throw new Error("This token has no issuer address \u2014 Project Intelligence only applies to issued tokens, not XRP itself.");let[s,a,o,i]=await Promise.all([Um(t,n),qm(n),Vm(n,t),Jm(t,n)]),r=s.exists&&s.account&&s.lpCurrency?await Gm(s.account,s.lpCurrency):{exists:!1},l=Ym({amm:s,orderBook:i,holders:o,lp:r,issuer:a});return{token:{symbol:e.symbol,name:e.name,issuer:n,currency:t},amm:s,issuerRisk:a,holders:o,lp:r,orderBook:i,strength:l,fetchedAt:Date.now()}}var gl=10;function Ho(e){var f;let t=[],n=[],s=g=>(t.push(g),g.id),a=(g,v,h,b,x={})=>n.push({from:g,to:v,type:h,proven:!0,factLabel:b,...x}),{token:o,amm:i,issuerRisk:r,holders:l,lp:c}=e,u=s({id:"project",type:"project",label:o.name||o.symbol}),d=s({id:"token",type:"token",label:o.symbol,meta:{currency:o.currency,issuer:o.issuer}});a(u,d,"contains","Token record looked up for this project.");let p=s({id:"issuer",type:"issuer",label:"Issuer",address:o.issuer,meta:r!=null&&r.exists?{...r}:{exists:!1}});a(d,p,"issued-by",`account_info: ${o.issuer} is the issuing account of currency ${o.currency}.`);let m=null;if(i!=null&&i.exists){if(m=s({id:"amm",type:"amm",label:"AMM Pool",address:i.account,meta:{xrpReserve:i.xrpReserve,tokenReserve:i.tokenReserve,tradingFeePct:i.tradingFeePct,lpSupply:i.lpSupply}}),a(d,m,"pooled-in",`amm_info: XRP/${o.symbol} pool exists at account ${i.account}.`),(f=i.auctionSlot)!=null&&f.account){let g=s({id:"auction",type:"auction",label:"Auction Slot Holder",address:i.auctionSlot.account,meta:{discountedFeePct:i.auctionSlot.discountedFeePct,expiration:i.auctionSlot.expiration}});a(g,m,"auction-slot-holder","amm_info: auction_slot.account holds the discounted-fee slot on this pool.")}(i.voteSlots||[]).forEach((g,v)=>{if(!g.account)return;let h=s({id:`vote_${v}`,type:"vote",label:"Fee Voter",address:g.account,meta:{tradingFeePct:g.tradingFeePct,voteWeight:g.voteWeight}});a(h,m,"fee-voter",`amm_info: vote_slots[${v}].account cast a trading-fee vote weighted by its LP-token share.`)})}return((l==null?void 0:l.topHolders)||[]).slice(0,gl).forEach((g,v)=>{let h=l.totalSampled>0?g.balance/l.totalSampled*100:0,b=s({id:`whale_${v}`,type:"whale",label:`Holder #${v+1}`,address:g.address,meta:{balance:g.balance,pctOfSampled:h}});a(b,d,"holds",`account_lines: trustline balance of ${g.balance} (${h.toFixed(2)}% of the ${l.holderCount}-holder sample).`)}),m&&((c==null?void 0:c.topHolders)||[]).slice(0,gl).forEach((g,v)=>{let h=c.totalSampled>0?g.balance/c.totalSampled*100:0,b=s({id:`lp_${v}`,type:"lp",label:`LP Holder #${v+1}`,address:g.address,meta:{balance:g.balance,pctOfSampled:h}});a(b,m,"provides-liquidity",`account_lines (on the AMM account): LP-token balance of ${g.balance} (${h.toFixed(2)}% of sampled LP supply).`)}),{nodes:t,edges:n}}var Bl="nalulf_wallets",Xl="nalulf_profile",Hl="nalulf_social",Ns="naluxrp_active_wallet",un="nalulf_avatar_img",In="nalulf_banner_img",Ko="nalulf_activity_log",ii="nalulf_balhist_",Qm="nalulf_addr_book",Zm="https://xrplcluster.com/",ef="https://s2.ripple.com:51234/",tf=[e=>`https://corsproxy.io/?${encodeURIComponent(e)}`,e=>`https://api.allorigins.win/raw?url=${encodeURIComponent(e)}`],nf="https://api.xrpscan.com/api/v1/tokens",sf="https://api.coingecko.com/api/v3/coins/markets",af="https://bithomp.com/api/v2/tokens",of="https://api.xrpl.to/api/tokens",rf=!1,Pa=10,Ma=2,lf=["\u{1F30A}","\u{1F40B}","\u{1F409}","\u{1F98B}","\u{1F981}","\u{1F43A}","\u{1F98A}","\u{1F43B}","\u{1F43C}","\u{1F985}","\u{1F42C}","\u{1F988}","\u{1F419}","\u{1F991}","\u{1F9FF}","\u{1F33A}","\u{1F338}","\u{1F340}","\u26A1","\u{1F525}","\u{1F48E}","\u{1F319}","\u2B50","\u{1F3AF}","\u{1F9E0}","\u{1F52E}","\u{1F6F8}","\u{1F5FA}","\u{1F3D4}","\u{1F3AD}","\u{1F3DB}"],cf=["\u{1F48E}","\u{1F3E6}","\u{1F510}","\u{1F511}","\u{1F4B0}","\u{1F30A}","\u26A1","\u{1F680}","\u{1F319}","\u2B50","\u{1F3F4}\u200D\u2620\uFE0F","\u{1F3AF}","\u{1F9E0}","\u{1F52E}"],df=["#50fa7b","#00d4ff","#ffb86c","#bd93f9","#ff79c6","#f1fa8c","#ff5555","#00fff0","#ff6b6b","#a78bfa"],Rs=["banner-ocean","banner-neon","banner-gold","banner-cosmic","banner-sunset","banner-aurora"],as=[{id:"discord",label:"Discord",icon:"\u{1F4AC}",prefix:"https://discord.com/users/"},{id:"twitter",label:"X / Twitter",icon:"\u{1D54F}",prefix:"https://x.com/"},{id:"linkedin",label:"LinkedIn",icon:"in",prefix:"https://linkedin.com/in/"},{id:"github",label:"GitHub",icon:"\u2325",prefix:"https://github.com/"},{id:"telegram",label:"Telegram",icon:"\u2708",prefix:"https://t.me/"},{id:"facebook",label:"Facebook",icon:"f",prefix:"https://facebook.com/"},{id:"tiktok",label:"TikTok",icon:"\u266A",prefix:"https://tiktok.com/@"}],pf={tecNO_DST:"Destination account does not exist \u2014 fund it with 10 XRP first.",tecINSUF_RESERVE_LINE:"Insufficient reserve to add another trustline.",tecINSUF_RESERVE_OFFER:"Insufficient reserve to place a DEX order.",tecUNFUNDED_PAYMENT:"Insufficient balance (including reserve).",tecDST_TAG_NEEDED:"This destination requires a Destination Tag.",tecNO_PERMISSION:"Account has DepositAuth enabled \u2014 destination must preauthorize.",temBAD_AMOUNT:"Invalid amount.",temBAD_CURRENCY:"Invalid currency code.",temBAD_ISSUER:"Invalid issuer address.",tefPAST_SEQ:"Sequence number already used \u2014 please retry.",terQUEUED:"Transaction queued \u2014 will be included in a future ledger."},uf="https://cdn.jsdelivr.net/npm/xrpl@4.2.5/build/xrpl-latest-min.js",La=21e4,ka=null;function zo(e){return btoa(String.fromCharCode(...e))}function jo(e){let t=atob(e),n=new Uint8Array(t.length);for(let s=0;s<t.length;s+=1)n[s]=t.charCodeAt(s);return n}async function Na(){var e,t;return(e=window.xrpl)!=null&&e.Wallet?!0:(ka||(ka=new Promise((n,s)=>{let a=document.querySelector('script[data-xrpl-lib="1"]');if(a){a.addEventListener("load",()=>n(!0),{once:!0}),a.addEventListener("error",()=>s(new Error("Failed to load xrpl.js")),{once:!0});return}let o=document.createElement("script");o.src=uf,o.async=!0,o.defer=!0,o.dataset.xrplLib="1",o.onload=()=>n(!0),o.onerror=()=>s(new Error("Failed to load xrpl.js")),document.head.appendChild(o)}).finally(()=>{var n;(n=window.xrpl)!=null&&n.Wallet||(ka=null)})),await ka,!!((t=window.xrpl)!=null&&t.Wallet))}async function zl(e,t,n=La){let s=new TextEncoder,a=await crypto.subtle.importKey("raw",s.encode(e),{name:"PBKDF2"},!1,["deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",hash:"SHA-256",salt:t,iterations:n},a,{name:"AES-GCM",length:256},!1,["encrypt","decrypt"])}async function jl(e,t){let n=new TextEncoder,s=crypto.getRandomValues(new Uint8Array(16)),a=crypto.getRandomValues(new Uint8Array(12)),o=await zl(t,s,La),i=await crypto.subtle.encrypt({name:"AES-GCM",iv:a},o,n.encode(e));return{v:1,kdf:"PBKDF2-SHA256",iter:La,alg:"AES-GCM-256",salt:zo(s),iv:zo(a),ct:zo(new Uint8Array(i))}}async function mf(e,t){if(!(e!=null&&e.ct)||!(e!=null&&e.salt)||!(e!=null&&e.iv))throw new Error("Wallet seed blob is invalid.");let n=await zl(t,jo(e.salt),e.iter||La),s=await crypto.subtle.decrypt({name:"AES-GCM",iv:jo(e.iv)},n,jo(e.ct));return new TextDecoder().decode(s)}async function ff(e,t){let n=(t||"").trim();if(n)return n;if(e!=null&&e.encSeed){let a=prompt("Enter your wallet password to decrypt and sign this transaction:");if(!a)throw new Error("Wallet password is required to sign.");try{return await mf(e.encSeed,a)}catch{throw new Error("Could not decrypt wallet seed. Check your wallet password and try again.")}}let s=prompt("Enter the wallet seed to sign this transaction (used once, not stored):");if(!s)throw new Error("Seed phrase is required to sign transactions.");return s.trim()}var ce={displayName:"",handle:"",bio:"",location:"",website:"",avatar:"\u{1F30A}",banner:"banner-ocean",joinedDate:new Date().toISOString(),domain:""},oe=[],Je={},dt=null,Ze={},ri={},li={},Wl={},ci={},Ls={},Ul={},Te={loading:!0,data:null,error:""},vt={loading:!0,items:[],error:""},yt={loading:!0,pools:[],error:""},Mt={loading:!0,pools:[],error:""},Fe={loading:!1,pool:null,error:""},M={pair:"BITSTAMP:XRPUSD",interval:"15",chartType:"candles",stats:null,loading:!0,error:"",comparePair:"",indicators:{sma20:!0,ema20:!1,wma20:!1,bb20:!1,vwap:!1,ichimoku:!1,macd:!1,rsi:!1,atr:!1,adx:!1,aroon:!1,cci:!1,williamsr:!1,mfi:!1,obv:!1,adline:!1,cmf:!1,stoch:!1,uo:!1,stdev:!1,donchian:!1,keltner:!1,supertrend:!1,pivots:!1,sar:!1,vortex:!1,elderRay:!1},tokenFocusKey:"",drawingTool:"none",drawings:[],alerts:[],indicatorMenuOpen:!1,moreMenuOpen:!1,indicatorQuery:"",indicatorSettings:{},settingsOpenFor:null,threeEnabled:!0,selectedIndicator:"sma20",selectedEducationTab:"indicator",educationCollapsed:!1,educationHint:"",chartMeta:{tokenKey:"XRP|",symbol:"XRP",source:"Coinbase + XRPL live",last:null,high:null,low:null,mode:"pair"}},W={loading:!0,tokens:[],filtered:[],trending:[],error:"",query:"",total:0,lastSyncAt:0,filters:{type:"all",minCap:0,minVol:0,hasDex:!1},selectedTokenKey:"",listLimit:240},Pt={loading:!0,items:[],error:""},ze={loading:!1,error:"",data:null,tokenKey:"",expandedSubScore:"",graphView:"list"},xl=window.innerWidth>=768,kl=null;window.addEventListener("resize",()=>{clearTimeout(kl),kl=setTimeout(()=>{let e=window.innerWidth>=768;e!==xl&&(xl=e,ze.data&&U())},150)},{passive:!0});var $l=new Map,$a=null,Sa=null,Sl=!1,Tl=0,ql=0,As=null,Cl={xrplto:0},ee={chart:null,volumeSeries:null,activeSeries:null,compareSeries:null,indicatorSeries:[],indicatorPriceLines:[],priceLines:[],resizeObserver:null,chartType:"",configKey:"",legendEl:null,renderLegend:null,ichimokuData:null,indicatorLegendItems:[],alertPriceLines:[]},Ke={renderer:null,scene:null,camera:null,points:null,raf:0,host:null,resizeHandler:null},Es=new Map,Rn=0,Wo="",hf="naluxrp_hist_v1_",Vl=60,Gl=25,gf=200,bf=e=>new Promise(t=>setTimeout(t,e)),Jo="naluxrp_seed_backed_up",Kl="naluxrp_token_watchlist",Yo="naluxrp_chart_layout",Jl="naluxrp_selected_token",di="naluxrp_chart_3d",Yl="naluxrp_price_alerts";function Aa(){return X.currentPage==="profile"&&!document.hidden}var vf=[{symbol:"XRP",name:"XRP Ledger Native",marketCap:"$124.3B",source:"CoinGecko"},{symbol:"RLUSD",name:"Ripple USD",marketCap:"$312.0M",source:"Static sample"},{symbol:"SOLOGENIC",name:"Sologenic",marketCap:"$96.4M",source:"Static sample"}],Fn=[{id:"BITSTAMP:XRPUSD",label:"XRP / USD (Coinbase + XRPL)",source:"coinbase",ticker:"xrpusd",symbol:"XRP",coingeckoId:"ripple"},{id:"BINANCE:XRPUSDT",label:"XRP / USD (Coinbase mirror)",source:"coinbase",ticker:"XRPUSDT",symbol:"XRP",coingeckoId:"ripple"},{id:"BINANCE:ETHUSDT",label:"ETH / USD (Coinbase)",source:"coinbase",ticker:"ETHUSDT",symbol:"ETH",coingeckoId:"ethereum"},{id:"BINANCE:BTCUSDT",label:"BTC / USD (Coinbase)",source:"coinbase",ticker:"BTCUSDT",symbol:"BTC",coingeckoId:"bitcoin"},{id:"BINANCE:SOLUSDT",label:"SOL / USD (Coinbase)",source:"coinbase",ticker:"SOLUSDT",symbol:"SOL",coingeckoId:"solana"}],Ql=[{value:"1",label:"1m"},{value:"3",label:"3m"},{value:"5",label:"5m"},{value:"15",label:"15m"},{value:"30",label:"30m"},{value:"60",label:"1h"},{value:"120",label:"2h"},{value:"240",label:"4h"},{value:"D",label:"1D"},{value:"W",label:"1W"},{value:"M",label:"1M"}];var Zl=[{key:"none",label:"Cursor"},{key:"hline",label:"Horizontal Line"}],yf={trend:["sma20","ema20","wma20","ichimoku","adx","aroon","sar","supertrend","vortex","elderRay","macd"],momentum:["rsi","stoch","cci","williamsr","mfi","uo"],volume:["obv","adline","cmf","vwap"],volatility:["bb20","keltner","atr","donchian","stdev"],advanced:["pivots"]},Vt={sma20:{name:"SMA 20",what:"Simple average of closing prices over 20 periods.",purpose:"Baseline trend smoothing.",apply:"Use slope and price relation for trend confirmation.",mistake:"Assuming one crossover equals full trend reversal.",bias:"Check higher timeframe trend first."},ema20:{name:"EMA 20",what:"Weighted moving average that reacts faster.",purpose:"Track momentum shifts early.",apply:"Use with structure breaks for continuation entries.",mistake:"Overtrading every touch.",bias:"Wait for confirmation candle close."},wma20:{name:"WMA 20",what:"Linear weighted average favoring recent closes.",purpose:"Balance noise and reactivity.",apply:"Useful for dynamic pullback zones.",mistake:"Treating it as support in chop.",bias:"Confirm with volatility context."},ichimoku:{name:"Ichimoku Cloud",what:"Multi-line trend, momentum, and support/resistance framework.",purpose:"One-glance regime detection.",apply:"Favor trades aligned with cloud direction and conversion/base line confluence.",mistake:"Ignoring lagging span context.",bias:"Only take signals in clear trend phases."},macd:{name:"MACD",what:"Difference between fast and slow EMAs with signal line.",purpose:"Momentum and trend acceleration.",apply:"Use histogram contraction/expansion and line cross with structure.",mistake:"Late entries from isolated crosses.",bias:"Match cross direction with market structure."},rsi:{name:"RSI",what:"Relative strength oscillator from 0-100.",purpose:"Momentum strength and exhaustion.",apply:"40-80 bull range, 20-60 bear range is often more useful than 30/70 alone.",mistake:"Shorting every overbought reading in uptrends.",bias:"Use RSI with trend filters and divergence context."},stoch:{name:"Stochastic",what:"Close location relative to recent range.",purpose:"Short-term momentum turns.",apply:"Best in ranges or pullbacks within trend.",mistake:"Treating every cross as signal.",bias:"Require structure or support/resistance confluence."},cci:{name:"CCI",what:"Deviation from statistical mean.",purpose:"Identify cyclical overextensions.",apply:"Look for trend-aligned re-entry after reset.",mistake:"Using fixed thresholds in all regimes.",bias:"Adapt thresholds to volatility."},williamsr:{name:"Williams %R",what:"Inverse stochastic oscillator.",purpose:"Range extremes and momentum snapbacks.",apply:"Use with market regime filter.",mistake:"Fading trends blindly.",bias:"Avoid countertrend trades without invalidation levels."},mfi:{name:"MFI",what:"Volume-weighted RSI style oscillator.",purpose:"Money flow pressure.",apply:"Combine with volume spikes for conviction.",mistake:"Ignoring thin liquidity distortions.",bias:"Cross-check on multiple venues when possible."},uo:{name:"Ultimate Oscillator",what:"Weighted momentum across multiple windows.",purpose:"Reduce single-window false signals.",apply:"Divergences can be strong with structure breaks.",mistake:"Using without trend filter.",bias:"Require two independent confirmations."},obv:{name:"On Balance Volume",what:"Cumulative signed volume.",purpose:"Volume pressure trend.",apply:"Look for OBV breaks before price breaks.",mistake:"Trusting OBV in sparse data periods.",bias:"Check liquidity quality first."},adline:{name:"Accumulation/Distribution",what:"Volume flow using close location in candle.",purpose:"Detect stealth accumulation/distribution.",apply:"Use for divergence against price trend.",mistake:"Ignoring wick distortions.",bias:"Validate with average volume regime."},cmf:{name:"Chaikin Money Flow",what:"Normalized accumulation/distribution over window.",purpose:"Money flow bias.",apply:"Sustained above/below zero is more meaningful than single crosses.",mistake:"Reacting to one-bar flips.",bias:"Use persistence thresholds."},vwap:{name:"VWAP",what:"Volume weighted average price.",purpose:"Institutional execution benchmark.",apply:"Use as intraday mean reversion or trend continuation anchor.",mistake:"Ignoring session resets.",bias:"Define session context explicitly."},bb20:{name:"Bollinger Bands",what:"Moving average with standard deviation envelopes.",purpose:"Volatility expansion/contraction.",apply:"Squeezes can precede breakouts; walks indicate trend.",mistake:"Assuming every upper-band touch is sell.",bias:"Pair with trend and volume confirmation."},keltner:{name:"Keltner Channel",what:"EMA center with ATR-based envelopes.",purpose:"Trend-aware volatility channel.",apply:"Break/hold beyond band can mark trend strength.",mistake:"Using fixed ATR multiplier everywhere.",bias:"Tune per asset volatility."},atr:{name:"ATR",what:"Average true range.",purpose:"Position sizing and stop calibration.",apply:"Use ATR multiples for stops/targets.",mistake:"Using fixed pip stops in all regimes.",bias:"Normalize risk by volatility."},donchian:{name:"Donchian Channels",what:"Highest high / lowest low bands.",purpose:"Breakout systems.",apply:"Use channel breaks with trend filter.",mistake:"Ignoring false breakout environment.",bias:"Wait for close confirmation."},stdev:{name:"Standard Deviation",what:"Dispersion of price from mean.",purpose:"Volatility regime shifts.",apply:"Expand risk controls during high dispersion.",mistake:"Mistaking volatility for direction.",bias:"Separate volatility from trend."},adx:{name:"ADX",what:"Trend strength metric independent of direction.",purpose:"Regime filter.",apply:"Use +DI/-DI with ADX slope.",mistake:"Trading direction off ADX alone.",bias:"Combine with directional structure."},aroon:{name:"Aroon",what:"Time since highs/lows.",purpose:"Trend emergence detection.",apply:"Aroon up/down crosses near extremes can flag regime shifts.",mistake:"Using in high-noise micro ranges.",bias:"Require multi-candle confirmation."},pivots:{name:"Pivot Points",what:"Session-based support/resistance levels.",purpose:"Map likely reaction zones.",apply:"Use confluence with order flow and trend.",mistake:"Treating pivots as guaranteed reversal levels.",bias:"Plan invalidation before entry."},sar:{name:"Parabolic SAR",what:"Trailing stop indicator with acceleration factor.",purpose:"Trend trailing and stop logic.",apply:"Works best in persistent trends.",mistake:"Using in sideways chop.",bias:"Filter with ADX or structure."},supertrend:{name:"Supertrend",what:"ATR-based trend-following overlay.",purpose:"Trend direction and trailing stop.",apply:"Follow flips when volatility supports continuation.",mistake:"Chasing every flip in range.",bias:"Use higher timeframe confirmation."},vortex:{name:"Vortex",what:"Positive/negative trend movement lines.",purpose:"Trend turning points.",apply:"Crosses with expansion can mark trend shifts.",mistake:"Ignoring low-liquidity noise.",bias:"Confirm with volume and structure."},elderRay:{name:"Elder Ray",what:"Bull/Bear power versus EMA baseline.",purpose:"Pressure around trend mean.",apply:"Look for divergence and trend continuation.",mistake:"Using without baseline trend direction.",bias:"Anchor decisions to trend context."}},pi={sma20:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#f1c40f"}],ema20:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#ffb86c"}],wma20:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#bd93f9"}],vwap:[{id:"color",label:"Color",type:"color",default:"#80ffea"}],bb20:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Band Color",type:"color",default:"#ff79c6"}],ichimoku:[{id:"tenkanLen",label:"Tenkan Length",type:"number",default:9},{id:"kijunLen",label:"Kijun Length",type:"number",default:26},{id:"senkouBLen",label:"Senkou B Length",type:"number",default:52},{id:"tenkanColor",label:"Tenkan Color",type:"color",default:"#ffde59"},{id:"kijunColor",label:"Kijun Color",type:"color",default:"#6ecbff"},{id:"bullColor",label:"Cloud Bull Color",type:"color",default:"#46ffa0"},{id:"bearColor",label:"Cloud Bear Color",type:"color",default:"#ff7878"}],donchian:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#9cfb8c"}],keltner:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#7ee7ff"}],supertrend:[{id:"color",label:"Color",type:"color",default:"#8bffde"}],sar:[{id:"color",label:"Color",type:"color",default:"#ffaf7a"}],elderRay:[{id:"bullColor",label:"Bull Color",type:"color",default:"#5fff9d"},{id:"bearColor",label:"Bear Color",type:"color",default:"#ff9d9d"}],rsi:[{id:"length",label:"Length",type:"number",default:14},{id:"color",label:"Color",type:"color",default:"#a6ff4d"}],atr:[{id:"length",label:"Length",type:"number",default:14},{id:"color",label:"Color",type:"color",default:"#ffb86c"}],stdev:[{id:"color",label:"Color",type:"color",default:"#b2a3ff"}],stoch:[{id:"length",label:"Length",type:"number",default:14},{id:"kColor",label:"%K Color",type:"color",default:"#9ee8ff"},{id:"dColor",label:"%D Color",type:"color",default:"#ffd86b"}],macd:[{id:"fastLen",label:"Fast Length",type:"number",default:12},{id:"slowLen",label:"Slow Length",type:"number",default:26},{id:"signalLen",label:"Signal Length",type:"number",default:9},{id:"lineColor",label:"MACD Color",type:"color",default:"#8fd9ff"},{id:"signalColor",label:"Signal Color",type:"color",default:"#ffcf8e"}],obv:[{id:"color",label:"Color",type:"color",default:"#8cf9ff"}],adline:[{id:"color",label:"Color",type:"color",default:"#ffb7ff"}],cmf:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#f8ff87"}],williamsr:[{id:"length",label:"Length",type:"number",default:14},{id:"color",label:"Color",type:"color",default:"#ff9adf"}],cci:[{id:"length",label:"Length",type:"number",default:20},{id:"color",label:"Color",type:"color",default:"#b8ff8e"}],mfi:[{id:"length",label:"Length",type:"number",default:14},{id:"color",label:"Color",type:"color",default:"#7bffd2"}],uo:[{id:"color",label:"Color",type:"color",default:"#ffd36f"}],adx:[{id:"length",label:"Length",type:"number",default:14},{id:"adxColor",label:"ADX Color",type:"color",default:"#9fd8ff"},{id:"plusColor",label:"+DI Color",type:"color",default:"#73ffc0"},{id:"minusColor",label:"-DI Color",type:"color",default:"#ff9797"}],aroon:[{id:"length",label:"Length",type:"number",default:14},{id:"upColor",label:"Up Color",type:"color",default:"#6cffb0"},{id:"downColor",label:"Down Color",type:"color",default:"#ff8f8f"}],vortex:[{id:"length",label:"Length",type:"number",default:14},{id:"plusColor",label:"VI+ Color",type:"color",default:"#d6a8ff"},{id:"minusColor",label:"VI- Color",type:"color",default:"#ffb0f3"}]},wf={sma20:{creator:"Early quantitative analysts (1900s tape reading era)",era:"Formalized in the early 20th century",math:"Arithmetic mean of the last N closes.",context:"Designed to smooth noisy tape data for trend direction visibility.",regime:"Best in directional trends, weaker in mean-reverting chop."},ema20:{creator:"Modern technical analysts adapting exponential smoothing",era:"Popularized in 1960s-1980s",math:"Recursive weighted mean with alpha = 2/(N+1).",context:"Improves responsiveness versus SMA while preserving trend structure.",regime:"Useful for pullback entries in trending environments."},ichimoku:{creator:"Goichi Hosoda",era:"Developed pre-WW2, published 1969",math:"Median-price lines (9/26/52) plus shifted cloud projections.",context:"Built as a full market regime system: trend, momentum, support/resistance in one frame.",regime:"Most reliable when cloud slope and price acceptance align."},macd:{creator:"Gerald Appel",era:"Late 1970s",math:"MACD = EMA(12)-EMA(26), signal=EMA(9) of MACD, histogram=spread.",context:"Tracks trend acceleration/deceleration, not just direction.",regime:"Strong in trend transitions, noisy in low-volatility ranges."},rsi:{creator:"J. Welles Wilder Jr.",era:"1978",math:"RSI = 100 - 100/(1+RS), RS = avg gain / avg loss.",context:"Measures internal momentum pressure rather than price level alone.",regime:"Range shifts (bull/bear RSI zones) matter more than static 30/70."},adx:{creator:"J. Welles Wilder Jr.",era:"1978",math:"Smoothed directional movement (+DI/-DI) transformed into trend-strength index.",context:"Separates trend strength from trend direction.",regime:"Filter trades: momentum systems improve when ADX slope rises."},aroon:{creator:"Tushar Chande",era:"1995",math:"Time since recent high/low scaled to 0-100.",context:"Focuses on trend freshness instead of pure magnitude.",regime:"Good at identifying emergent trend phases and late-trend fatigue."},cci:{creator:"Donald Lambert",era:"1980",math:"Deviation of typical price from moving average normalized by mean deviation.",context:"Originally commodity cycle tool for identifying statistical extremes.",regime:"Works better with volatility-aware thresholds than fixed +/-100."},williamsr:{creator:"Larry Williams",era:"1970s",math:"Position of close within rolling high-low range, scaled negative.",context:"Fast oscillator for short-horizon exhaustion and reversion timing.",regime:"Most effective in bounded ranges; trend filters prevent fade traps."},mfi:{creator:"Gene Quong and Avrum Soudack",era:"1989",math:"RSI-style transform using typical price * volume money flow.",context:"Adds participation/volume dimension to momentum analysis.",regime:"Useful where volume quality is high; weaker on fragmented liquidity."},obv:{creator:"Joseph Granville",era:"1963",math:"Cumulative signed volume based on close direction.",context:"Detects accumulation/distribution before obvious price moves.",regime:"Best when confirmed with structure breaks and volume regime shifts."},vwap:{creator:"Institutional execution desks",era:"1980s electronic execution era",math:"Cumulative price*volume divided by cumulative volume.",context:"Execution benchmark and intraday fair-value reference.",regime:"Most meaningful intraday and around session anchor resets."},bb20:{creator:"John Bollinger",era:"1980s",math:"SMA +/- k * standard deviation.",context:"Captures volatility contraction/expansion around a mean.",regime:"Band walks imply trend persistence; squeezes imply potential expansion."},atr:{creator:"J. Welles Wilder Jr.",era:"1978",math:"Smoothed average of true range components.",context:"Volatility unit for risk sizing and adaptive stops.",regime:"Risk engine input rather than directional signal."},donchian:{creator:"Richard Donchian",era:"1940s-1950s",math:"Rolling highest-high and lowest-low channels.",context:"Classic breakout trend-following framework.",regime:"Performs in sustained directional moves, whipsaws in compression."},supertrend:{creator:"Olivier Seban",era:"2009",math:"ATR envelope with trend-state switching logic.",context:"Simplifies trend-following and stop-trailing into one overlay.",regime:"Good in clean trends; combine with structure/ADX in chop."},vortex:{creator:"Etienne Botes and Douglas Siepman",era:"2010",math:"Normalized positive/negative movement vectors over rolling true range.",context:"Detects trend emergence and directional dominance shifts.",regime:"Improves when paired with volatility and liquidity filters."}},xf={hline:"Horizontal levels represent reaction zones. Respect zone width and liquidity sweeps."},kf=[{label:"XRP/USD (Bitstamp)",asset:{currency:"XRP"},asset2:{currency:"USD",issuer:"rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq"}},{label:"XRP/EUR (Bitstamp)",asset:{currency:"XRP"},asset2:{currency:"EUR",issuer:"rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq"}},{label:"XRP/USDC (Gatehub)",asset:{currency:"XRP"},asset2:{currency:"USDC",issuer:"rKveEyR1SrkWbJX214xcfH43ZsoGMb3PEv"}}],_n=null,pn={},ts="",wt=1,ve={algo:"ed25519",label:"",emoji:"\u{1F48E}",color:"#50fa7b",seed:"",address:"",passphrase:""},Dn=new Set,Pl=60,$f={wallet_created:"\u{1F48E}",wallet_removed:"\u{1F5D1}",social_connected:"\u{1F517}",social_removed:"\u2715",profile_saved:"\u270F\uFE0F",trustline_added:"\u{1F517}",sent:"\u2B06",received:"\u2B07",vault_created:"\u{1F510}",backup_exported:"\u{1F4C2}",theme_changed:"\u{1F3A8}",wallet_imported:"\u{1F511}",watch_added:"\u{1F441}"};function ec(){Qo(),yg(),Mf(),M.threeEnabled=Q(di)!=="0",Sf(),Na().catch(()=>{he("Could not preload xrpl.js. Wallet generation/signing will require network access when used.")}),U(),Bt(),Cg(),Cf(),Aa()&&ns({silent:!0}),window.addEventListener("naluxrp:pagechange",e=>{var t;((t=e==null?void 0:e.detail)==null?void 0:t.pageId)==="profile"?ns({silent:!0}):Ke.raf&&Os()}),document.addEventListener("click",e=>{var s;let t=document.querySelector(".xpd-indicator-menu-wrap");t&&!t.contains(e.target)&&M.indicatorMenuOpen&&(M.indicatorMenuOpen=!1,U());let n=document.querySelector(".xpd-more-menu-wrap");if(n&&!n.contains(e.target)&&M.moreMenuOpen&&(M.moreMenuOpen=!1,U()),M.settingsOpenFor){let a=(s=document.querySelector(".xpd-indicator-settings"))==null?void 0:s.closest(".xpd-indicator-chip-wrap");a&&!a.contains(e.target)&&(M.settingsOpenFor=null,U())}}),window.addEventListener("naluxrp:vault-ready",()=>{Qo(),U(),Bt(),cg(),ns({silent:!0,force:!0})}),window.addEventListener("naluxrp:vault-locked",()=>{U(),ns({silent:!0,force:!0})}),document.addEventListener("visibilitychange",()=>{if(Aa()&&!document.hidden&&oe.length){let e=oe.filter(t=>{let n=Ze[t.address];return!n||Date.now()-n.fetchedAt>3e5});e.length&&Promise.all(e.map(t=>On(t.address))).then(()=>{$t(),Bt()})}})}function Sf(){let e=new URLSearchParams(window.location.search),t=e.get("pair")||"",n=e.get("tf")||"",s=e.get("token")||Q(Jl)||"",a=e.get("ind")||"";if(t&&Fn.some(o=>o.id===t)&&(M.pair=t),n&&Ql.some(o=>o.value===n)&&(M.interval=n),a){let o=new Set(a.split(",").map(i=>i.trim()).filter(Boolean));Object.keys(M.indicators).forEach(i=>{M.indicators[i]=o.has(i)})}s&&(M.tokenFocusKey=s,W.selectedTokenKey=s)}function At(){let e=new URLSearchParams(window.location.search);e.set("pair",M.pair||"BITSTAMP:XRPUSD"),e.set("tf",M.interval||"15"),M.tokenFocusKey?e.set("token",M.tokenFocusKey):e.delete("token");let t=Object.entries(M.indicators).filter(([,s])=>!!s).map(([s])=>s).join(",");t?e.set("ind",t):e.delete("ind");let n=`${window.location.pathname}?${e.toString()}${window.location.hash||""}`;window.history.replaceState(null,"",n),M.tokenFocusKey&&Z(Jl,M.tokenFocusKey)}function Tf(){let e=document.getElementById("xpd-chart-section");e&&e.scrollIntoView({behavior:"smooth",block:"start"})}function Cf(){Sl||(Sl=!0,window.addEventListener("xrpl-ledger",()=>{let e=Date.now();e-Tl<5e3||(Tl=e,X.currentPage==="profile"&&document.querySelector("#profile-page .profile-wrap .xrpl-profile-dashboard")&&Tc().then(()=>{if(Date.now()-ql>15e3)return;let n=document.activeElement;n&&/^(INPUT|TEXTAREA|SELECT)$/.test(n.tagName)||M.moreMenuOpen||M.indicatorMenuOpen||(Es.clear(),U())}).catch(()=>{}))}))}function ui(e){let t=w(`profile-tab-${e}`);t&&t.scrollIntoView({behavior:"smooth",block:"start"})}function Pf(e,t,n){e.innerHTML=`<div class="tab-error-card">
    <div class="tab-error-icon">\u26A0\uFE0F</div>
    <div class="tab-error-title">Something went wrong</div>
    <div class="tab-error-sub">${y((n==null?void 0:n.message)||"Unknown error")}</div>
    <button class="tab-error-btn" onclick="switchProfileTab('${t}')">Try Again</button>
  </div>`}function Mf(){document.addEventListener("keydown",e=>{if(e.key==="Escape")for(let t of["profile-editor-modal","wallet-creator-overlay","social-modal","send-modal-overlay","receive-modal-overlay","trustline-modal-overlay","import-address-modal","import-seed-modal","token-details-modal","pub-profile-overlay"]){let n=w(t)||document.getElementById(t);if(n!=null&&n.classList.contains("show")||(n==null?void 0:n.style.display)==="flex"){n.classList.remove("show"),n.style.display==="flex"&&(n.style.display="none");return}}e.key==="k"&&(e.ctrlKey||e.metaKey)&&(e.preventDefault(),$i())})}function Qo(){var t,n;let e=ge(Q(Xl));e&&Object.assign(ce,e),Je=ge(Q(Hl))||{},oe=ge(Q(Bl))||[],Ul=ge(Q(Qm))||{},M.alerts=ge(Q(Yl))||[],dt=Q(Ns)||((t=oe[0])==null?void 0:t.id)||null,!ce.displayName&&((n=X.session)!=null&&n.name)&&(ce.displayName=X.session.name,ce.handle=X.session.name.toLowerCase().replace(/\s+/g,"_"),tc())}function tc(){Z(Xl,JSON.stringify(ce))}function _s(){Z(Bl,JSON.stringify(oe))}function nc(){Z(Hl,JSON.stringify(Je))}function mi(){Z(Yl,JSON.stringify(M.alerts||[]))}function kt(e,t){let n=ge(Q(Ko))||[];n.unshift({type:e,detail:t,ts:Date.now()}),n.length>Pl&&(n.length=Pl),Z(Ko,JSON.stringify(n))}function Lf(){return ge(Q(Ko))||[]}function sc(e){let t=(Date.now()-e)/1e3;return t<60?"just now":t<3600?`${Math.floor(t/60)}m ago`:t<86400?`${Math.floor(t/3600)}h ago`:`${Math.floor(t/86400)}d ago`}function Et(){return oe.find(e=>e.id===dt)||oe[0]||null}function ac(e){oe.find(t=>t.id===e)&&(dt=e,Z(Ns,e),$t(),Bt(),window.dispatchEvent(new CustomEvent("naluxrp:active-wallet-changed",{detail:Et()})),ne("Active wallet switched"))}window.addEventListener("naluxrp:active-wallet-changed",e=>{let t=e.detail;if(!t)return;let n=w("inspect-addr");n&&!n.value&&(n.value=t.address),X.activeWalletAddress=t.address});function Bt(){var o;let e=w("active-wallet-bar");if(!e)return;let t=Et();if(!t){e.innerHTML='<div class="awb-empty">No wallet \u2014 <button class="awb-link" onclick="openWalletCreator()">create one</button></div>';return}let n=Ze[t.address],s=n?_(n.xrp,2)+" XRP":"\u2014 XRP",a=(o=n==null?void 0:n.tokens)!=null&&o.length?`\xB7 ${n.tokens.length} token${n.tokens.length>1?"s":""}`:"";e.innerHTML=`
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
    </div>`}function U(){var h,b;let e=document.querySelector("#profile-page .profile-wrap");if(!e)return;let t=document.getElementById("xpd-tv-widget"),n=!!(t&&ee.chart);t&&t.remove();let s=document.getElementById("xpd-chart-atmosphere"),a=!!(s&&Ke.renderer);s&&s.remove();let o=Et(),i=(o==null?void 0:o.address)||"",r=Af(),l=localStorage.getItem(un),c=oe.some(x=>!x.watchOnly),u=Q(Jo)==="1",d=(h=Ze[i])==null?void 0:h.xrp,p=Object.values(Ze).reduce((x,k)=>x+((k==null?void 0:k.xrp)||0),0),m=(b=Te.data)!=null&&b.priceUsd?p*Te.data.priceUsd:0,f=Fn.map(x=>`<option value="${y(x.id)}" ${M.pair===x.id?"selected":""}>${y(x.label)}</option>`).join(""),g=Fn.map(x=>`<option value="${y(x.id)}" ${M.comparePair===x.id?"selected":""}>${y(x.label)}</option>`).join(""),v=Ql.map(x=>`<option value="${y(x.value)}" ${M.interval===x.value?"selected":""}>${y(x.label)}</option>`).join("");if(e.innerHTML=`
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
            <div class="xpd-avatar-shell" title="${y(ce.displayName||"Anonymous")}" onclick="openProfileEditor()">
              ${l?`<img src="${l}" alt="Profile avatar" class="xpd-avatar-img" />`:`<span class="xpd-avatar-fallback">${y(ce.avatar||(o==null?void 0:o.emoji)||"\u{1F30A}")}</span>`}
            </div>
            <div class="xpd-profile-meta">
              <h2 class="xpd-display-name">${y(ce.displayName||"Anonymous")}</h2>
              <p class="xpd-bio">${y(ce.bio||"No bio set. Click edit profile to add one.")}</p>
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
              <span class="xpd-item-value">${Number.isFinite(d)?`${_(d,4)} XRP`:"\u2014"}</span>
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
              <button class="xpd-toggle ${u?"on":""}" onclick="toggleSeedBackupStatus()" aria-pressed="${u?"true":"false"}">${u?"Yes":"No"}</button>
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
                  <select class="xpd-input" onchange="setDexInterval(this.value)">${v}</select>
                  <select class="xpd-input" onchange="setDexChartType(this.value)">
                    <option value="candles" ${M.chartType==="candles"?"selected":""}>Candlestick</option>
                    <option value="line" ${M.chartType==="line"?"selected":""}>Line</option>
                    <option value="area" ${M.chartType==="area"?"selected":""}>Area</option>
                    <option value="bars" ${M.chartType==="bars"?"selected":""}>Bar</option>
                    <option value="heikin_ashi" ${M.chartType==="heikin_ashi"?"selected":""}>Heikin Ashi</option>
                    <option value="hollow_candles" ${M.chartType==="hollow_candles"?"selected":""}>Hollow Candle</option>
                  </select>
                  <select class="xpd-input" onchange="setComparePair(this.value)">
                    <option value="" ${M.comparePair?"":"selected"}>No Compare</option>
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
                    ${Zl.map(x=>`<option value="${x.key}" ${M.drawingTool===x.key?"selected":""}>Draw: ${x.label}</option>`).join("")}
                  </select>
                  <button class="xpd-action xpd-action--icon" onclick="clearAllDrawings()" title="Clear Lines" aria-label="Clear Lines">\u{1F9F9}</button>
                  <button class="xpd-action xpd-action--icon" onclick="addPriceAlert()" title="Set Price Alert" aria-label="Set Price Alert">\u{1F514}</button>
                  ${Ef()}
                  <button class="xpd-action xpd-action--icon" onclick="exportChartPng()" title="Export PNG" aria-label="Export PNG">\u{1F5BC}\uFE0F</button>
                  <button class="xpd-action xpd-action--icon" onclick="copyChartLink()" title="Copy Chart Link" aria-label="Copy Chart Link">\u{1F517}</button>
                </div>
                <div class="xpd-toolbar-group xpd-more-menu-wrap">
                  <button class="xpd-action xpd-action--icon" onclick="event.stopPropagation(); toggleChartMoreMenu()" title="More settings" aria-label="More settings">\u22EF</button>
                  ${M.moreMenuOpen?`
                    <div class="xpd-more-menu" role="menu" aria-label="Chart preferences">
                      <button class="xpd-more-menu-item" onclick="toggleThreeEffects()"><span class="xai">\u{1F9CA}</span>${M.threeEnabled?"3D Background: On":"3D Background: Off"}</button>
                      <button class="xpd-more-menu-item" onclick="toggleTerminalTheme()"><span class="xai">\u{1F313}</span>Toggle Theme</button>
                      <button class="xpd-more-menu-item" onclick="saveChartLayoutPreset()"><span class="xai">\u{1F4BE}</span>Save Layout</button>
                      <button class="xpd-more-menu-item" onclick="loadChartLayoutPreset()"><span class="xai">\u{1F4C2}</span>Load Layout</button>
                    </div>
                  `:""}
                </div>
              </div>
            </div>
            ${Nf()}
          </section>

          <section class="xpd-section" aria-label="XRPL market data">
            <div class="xpd-section-head">
              <h2>XRPL Market Data</h2>
              <button class="xpd-action" onclick="refreshMarketData()"><span class="xai">\u27F3</span>Refresh market</button>
            </div>
            ${_f()}
          </section>
        </div>
      </div>

      ${Rf()}

      <section class="xpd-section" aria-label="Token discovery and watchlist">
        <div class="xpd-section-head">
          <h2>Token Discovery and Watchlists</h2>
          <button class="xpd-action" onclick="refreshTokenDiscovery()"><span class="xai">\u27F3</span>Refresh tokens</button>
        </div>
        ${Bf()}
      </section>

      ${ze.loading||ze.error||ze.data?`
      <section class="xpd-section" aria-label="Project intelligence" id="xpd-project-intel-section">
        ${Hf()}
      </section>`:""}

      <div class="xpd-dual-grid">
        <section class="xpd-section" aria-label="NFT gallery">
          <div class="xpd-section-head">
            <h2>NFT Gallery</h2>
            <button class="xpd-action" onclick="refreshNftGallery()"><span class="xai">\u27F3</span>Refresh NFTs</button>
          </div>
          ${Df(i)}
        </section>

        <section class="xpd-section" aria-label="AMM pools and DEX liquidity">
          <div class="xpd-section-head">
            <h2>AMM, DEX, and Liquidity Pools</h2>
            <button class="xpd-action" onclick="refreshAmmPools()"><span class="xai">\u27F3</span>Refresh pools</button>
          </div>
          ${Ff(i)}
        </section>
      </div>

      <section class="xpd-section" aria-label="Portfolio and recent transactions">
        <div class="xpd-section-head">
          <h2>Portfolio and Recent Transactions</h2>
          <button class="xpd-action" onclick="refreshRecentTransactions()"><span class="xai">\u27F3</span>Refresh tx</button>
        </div>
        ${Yf(i)}
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
    </div>`,n){let x=document.getElementById("xpd-tv-widget");x&&x.replaceWith(t)}if(a){let x=document.getElementById("xpd-chart-atmosphere");x&&x.replaceWith(s)}Bh(),ng(),sg(),yi(),Bs()}function Af(){let e=String(X.currentNetwork||"").toLowerCase();return e.includes("testnet")?{label:"XRPL Testnet",kind:"testnet"}:e.includes("mainnet")?{label:"XRPL Mainnet",kind:"mainnet"}:e.includes("xahau")?{label:"Xahau Network",kind:"xahau"}:{label:`Network: ${y(X.currentNetwork||"Unknown")}`,kind:"unknown"}}function Ef(){let e=String(M.indicatorQuery||"").trim().toLowerCase(),t=[{key:"trend",label:"Trend",icon:"\u{1F4C8}"},{key:"momentum",label:"Momentum",icon:"\u26A1"},{key:"volume",label:"Volume",icon:"\u{1F4CA}"},{key:"volatility",label:"Volatility",icon:"\u{1F32A}\uFE0F"},{key:"advanced",label:"Custom",icon:"\u{1F9E0}"}];return`
    <div class="xpd-indicator-menu-wrap">
      <button class="xpd-action xpd-action--add" onclick="event.stopPropagation(); toggleIndicatorMenu()">+ Indicator</button>
      ${M.indicatorMenuOpen?`
        <div class="xpd-indicator-menu" role="menu" aria-label="Indicator menu">
          <input class="xpd-input xpd-indicator-search" placeholder="Search indicators..." value="${y(M.indicatorQuery||"")}" oninput="setIndicatorQuery(this.value)" />
          ${t.map(n=>{let s=(yf[n.key]||[]).filter(a=>{var i;return e?(((i=Vt[a])==null?void 0:i.name)||a).toLowerCase().includes(e):!0});return s.length?`
              <details class="xpd-indicator-group" open>
                <summary>${n.icon} ${n.label}</summary>
                <div class="xpd-indicator-items">
                  ${s.map(a=>{var o,i;return`<button class="xpd-indicator-item" title="${y(((o=Vt[a])==null?void 0:o.what)||"")}" onclick="addIndicatorFromMenu('${a}')">${y(((i=Vt[a])==null?void 0:i.name)||a)}</button>`}).join("")}
                </div>
              </details>`:""}).join("")}
        </div>
      `:""}
    </div>`}function Nf(){var m;let e=M.stats,t=((m=X.wsConn)==null?void 0:m.readyState)===1,n=M.chartMeta||{},s=Object.entries(M.indicators).filter(([,f])=>!!f).map(([f])=>f),a=String(M.tokenFocusKey||""),o=a.includes("|")?a.split("|")[0]:a,i=W.tokens.find(f=>Ve(f)===a)||W.tokens.find(f=>String(f.symbol||"").toUpperCase()===String(o||"").toUpperCase())||null,r=!!i&&String(i.symbol||"").toUpperCase()!=="XRP"&&Number.isFinite(Number(i.price||0)),l=Number.isFinite(Number(n.last))?Number(n.last):r?Number(i.price||0):e==null?void 0:e.price,c=Number.isFinite(Number(n.high))?Number(n.high):e==null?void 0:e.high,u=Number.isFinite(Number(n.low))?Number(n.low):e==null?void 0:e.low,d=i?`${String(i.symbol||"").toUpperCase()}${i.issuer?` \xB7 ${i.issuer.slice(0,10)}...`:""}`:String(n.symbol||"XRP").toUpperCase(),p=String(n.source||(r?"Coinbase + token proxy":(e==null?void 0:e.source)||"Source pending"));return`
    ${M.error?`<div class="xpd-error">${y(M.error)}</div>`:""}
    <div class="xpd-chart-stats">
      <div class="xpd-pill" title="Current price">${l!=null?`$${_(l,r?6:4)}`:"Price \u2014"}</div>
      <div class="xpd-pill" title="24h change">${(e==null?void 0:e.changePct)!=null?`${e.changePct>=0?"+":""}${_(e.changePct,2)}%`:"24h \u2014"}</div>
      <div class="xpd-pill" title="24h high">${c!=null?`High $${_(c,r?6:4)}`:"High \u2014"}</div>
      <div class="xpd-pill" title="24h low">${u!=null?`Low $${_(u,r?6:4)}`:"Low \u2014"}</div>
      <div class="xpd-pill" title="XRPL orderbook spot">${r?`Token Spot $${_(Number((i==null?void 0:i.price)||0),6)}`:(e==null?void 0:e.xrplSpot)!=null?`XRPL Spot $${_(e.xrplSpot,4)}`:"XRPL Spot \u2014"}</div>
      <div class="xpd-pill" title="Streaming status">${t?"\u25CF Live stream connected":"\u25CF Stream offline"}</div>
      ${i?`<div class="xpd-pill" title="Token focus">Token Focus: ${y(i.symbol)} ${i.price!=null?`($${_(i.price,6)})`:""}</div>`:""}
    </div>
    <div class="xpd-indicator-row">
      ${s.length?s.map(f=>{var g,v;return`<div class="xpd-indicator-chip-wrap"><div class="xpd-indicator-chip" title="${y(((g=Vt[f])==null?void 0:g.what)||"")}"><span>${y(((v=Vt[f])==null?void 0:v.name)||f)}</span><button class="xpd-mini-btn" onclick="event.stopPropagation(); openIndicatorSettings('${f}')">\u2699</button><button class="xpd-mini-btn" onclick="removeIndicator('${f}')">\u2715</button></div>${Xh(f)}</div>`}).join(""):'<span class="xpd-empty">No indicators enabled. Use + Indicator.</span>'}
    </div>
    ${(()=>{let f=Da(),g=(M.alerts||[]).filter(v=>v.tokenKey===f);return g.length?`
      <div class="xpd-indicator-row">
        ${g.map(v=>`
          <div class="xpd-indicator-chip" data-alert-id="${y(v.id)}" title="Notify when price crosses $${_(v.price,6)}">
            <span>\u{1F514} $${_(v.price,6)}</span>
            <button class="xpd-mini-btn" onclick="removePriceAlert('${v.id}')">\u2715</button>
          </div>`).join("")}
      </div>`:""})()}
    ${M.educationHint?`<div class="xpd-note">${y(M.educationHint)}</div>`:""}
    <div class="xpd-chart-wrap">
      <div class="xpd-chart-active-head">
        <div class="xpd-chart-active-left">
          <span class="xpd-chart-active-label">Active Chart Token</span>
          <strong class="xpd-chart-active-token" title="${y(d)}">${y(d)}</strong>
        </div>
        <div class="xpd-chart-active-right">
          <span class="xpd-chart-active-chip">Mode: ${y(n.mode||"pair")}</span>
          <span class="xpd-chart-active-chip" title="${y(p)}">Source: ${y(p)}</span>
        </div>
      </div>
      <div id="xpd-chart-atmosphere" class="xpd-chart-atmosphere" aria-hidden="true"></div>
      <div id="xpd-tv-widget" class="xpd-tv-widget"></div>
    </div>
    <p class="xpd-note">Professional chart controls: wheel zoom, hold-and-drag pan, horizontal price-line marking, and token-focused context ribbons for faster execution decisions.</p>`}function Rf(){let e=M.selectedIndicator||"sma20",t=Vt[e]||Vt.sma20,n=wf[e]||null,s=M.educationCollapsed;return`
    <div class="xpd-edu-panel ${s?"collapsed":""}">
      <div class="xpd-edu-head">
        <h3>Indicator Intelligence and Bias Control</h3>
        <button class="xpd-mini-btn" onclick="toggleEducationPanel()">${s?"Expand":"Collapse"}</button>
      </div>
      ${s?"":`
        <div class="xpd-edu-tabs">
          <button class="xpd-mini-btn ${M.selectedEducationTab==="indicator"?"active":""}" onclick="selectEducationTab('indicator')">Indicator Guide</button>
          <button class="xpd-mini-btn ${M.selectedEducationTab==="psychology"?"active":""}" onclick="selectEducationTab('psychology')">Trading Psychology</button>
          <button class="xpd-mini-btn ${M.selectedEducationTab==="practice"?"active":""}" onclick="selectEducationTab('practice')">Best Practices</button>
        </div>
        ${M.selectedEducationTab==="indicator"?`
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
        ${M.selectedEducationTab==="psychology"?`
          <div class="xpd-edu-content">
            ${ct("Confirmation Bias","Require at least two independent signals before entering.")}
            ${ct("Anchoring","Do not anchor to entry price; respect invalidation and current structure.")}
            ${ct("Overfitting","More indicators is not better; build a repeatable checklist.")}
            ${ct("Risk Discipline","Position size by volatility and stop distance, not conviction.")}
          </div>
        `:""}
        ${M.selectedEducationTab==="practice"?`
          <ol class="xpd-edu-steps">
            <li>Start with trend context (higher timeframe).</li>
            <li>Add one momentum and one volatility indicator.</li>
            <li>Mark levels with drawings before taking a trade.</li>
            <li>Define entry, invalidation, and target before execution.</li>
            <li>Journal whether setup matched your rules.</li>
          </ol>
        `:""}
      `}
    </div>`}function ct(e,t){return`<div class="xpd-edu-row"><span class="xpd-edu-label">${y(e)}</span><span class="xpd-edu-value">${y(t)}</span></div>`}function _f(){if(Te.loading)return'<div class="xpd-loading">Loading XRP market snapshot...</div>';if(Te.error)return`<div class="xpd-error">${y(Te.error)}</div>`;let e=Te.data;if(!e)return'<div class="xpd-empty">Market data is not available yet.</div>';let t=e.change24h>=0;return`
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
        <strong class="xpd-stat-value">$${qe(e.volume24h)}</strong>
      </article>
      <article class="xpd-stat-card">
        <span class="xpd-stat-label">Market Cap</span>
        <strong class="xpd-stat-value">$${qe(e.marketCap)}</strong>
      </article>
    </div>
    <div class="xpd-token-strip">
      ${vf.map(n=>`<div class="xpd-token-pill" title="${y(`${n.symbol} ${n.name}`)}"><span class="sym xpd-pill-text">${n.symbol}</span><span class="xpd-pill-text">${y(n.name)}</span><span class="cap xpd-pill-text">${n.marketCap}</span></div>`).join("")}
    </div>
    <p class="xpd-note">Top XRPL token cards are static examples when direct DEX market-cap feeds are unavailable.</p>`}function Df(e){return e?vt.loading?'<div class="xpd-loading">Loading account NFTs...</div>':vt.error?`<div class="xpd-error">${y(vt.error)}</div>`:vt.items.length?`<div class="xpd-nft-grid">${vt.items.map(If).join("")}</div>`:'<div class="xpd-empty">No NFTs found for this wallet.</div>':'<div class="xpd-empty">Select or create a wallet to load NFTs.</div>'}function If(e){let t=`${e.id.slice(0,12)}...${e.id.slice(-10)}`;return`<article class="xpd-nft-card">
    <div class="xpd-nft-media">
      ${e.image?`<img src="${y(e.image)}" alt="NFT ${y(t)}" loading="lazy" onerror="this.closest('.xpd-nft-media').innerHTML='<div class=&quot;xpd-nft-placeholder&quot;>NFT</div>'"/>`:'<div class="xpd-nft-placeholder">NFT</div>'}
    </div>
    <div class="xpd-nft-body">
      <div class="xpd-nft-id mono" title="${y(e.id)}">${y(t)}</div>
      <button class="xpd-action" onclick="sendNft('${y(e.id)}')">Send NFT</button>
    </div>
  </article>`}function Ff(e){let t=Qf(e),n=Zf(),s=eh();return`<div class="xpd-amm-columns">${t}${n}${s}</div>`}function fi(){return(ge(Q(Kl))||[]).filter(Boolean)}function oc(e){let t=[...new Set((e||[]).filter(Boolean))];Z(Kl,JSON.stringify(t))}function Of(e,t){return t.has(e)?t.get(e):W.tokens.find(s=>s.symbol===e)||null}function Bf(){let e=W.query||"",t=fi(),n=W.filtered,s=Math.max(120,Number(W.listLimit||240)),a=n.slice(0,s),o=W.trending.slice(0,14),i=new Map(W.tokens.map(c=>[Ve(c),c])),r=i.get(W.selectedTokenKey)||null,l=W.filters||{type:"all",minCap:0,minVol:0,hasDex:!1};return`
    <div class="xpd-token-grid">
      <div class="xpd-token-col">
        <div class="xpd-search-row">
          <input class="xpd-input" list="xpd-token-suggest" placeholder="Search symbol, token, issuer" value="${y(e)}" oninput="searchTokens(this.value)" />
          <datalist id="xpd-token-suggest">${W.tokens.slice(0,80).map(c=>`<option value="${y(c.symbol)}">${y(c.name)}</option>`).join("")}</datalist>
          <div class="xpd-note">Loaded ${qe(W.total||n.length)} issued tokens \xB7 showing ${qe(a.length)} of ${qe(n.length)}${W.lastSyncAt?` \xB7 synced ${new Date(W.lastSyncAt).toLocaleTimeString()}`:""}</div>
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
        ${W.loading?'<div class="xpd-loading">Loading XRPL issued token registry...</div>':""}
        ${W.error?`<div class="xpd-error">${y(W.error)}</div>`:""}
        ${!a.length&&!W.loading?`<div class="xpd-empty">No tokens match${e?` "${y(e)}"`:" the current filters"}. <button class="xpd-mini-btn" onclick="clearTokenFilters()">Clear search & filters</button></div>`:""}
        <div class="xpd-token-list">${a.map(c=>{let u=Ve(c),d=Ms(u),p=String(e||"").trim();return`
          <div class="xpd-token-row xpd-token-row--clickable" title="${y(`${c.symbol} ${c.name}`)}" onclick="openTokenOnChart(decodeURIComponent('${d}'))">
            <div class="xpd-token-main">
              <strong>${El(c.symbol,p)}</strong>
              <span>${El(c.name,p)}</span>
              ${c.issuer?`<span class="mono xpd-pill-text">${y(c.issuer)}</span>`:""}
            </div>
            <div class="xpd-token-actions">
              <span>${c.price!=null?`$${_(c.price,6)}`:"\u2014"}</span>
              ${Number.isFinite(c.holders)?`<span title="Holders">${qe(c.holders)} holders</span>`:""}
              <button class="xpd-mini-btn" onclick="event.stopPropagation(); addTokenToWatchlist(decodeURIComponent('${d}'))">Watch</button>
              <button class="xpd-mini-btn" onclick="event.stopPropagation(); openTokenOnChart(decodeURIComponent('${d}'))">Chart</button>
              <button class="xpd-mini-btn" onclick="event.stopPropagation(); selectTokenDetails(decodeURIComponent('${d}'))">Details</button>
              ${c.issuer?`<button class="xpd-mini-btn xpd-mini-btn--accent" onclick="event.stopPropagation(); openProjectIntel(decodeURIComponent('${d}'))" title="Project Strength \u2014 liquidity depth, holder/LP concentration, issuer risk">\u{1F52C} Strength</button>`:""}
            </div>
          </div>`}).join("")}</div>
      </div>
      <div class="xpd-token-col">
        ${r?`<div class="xpd-token-detail-card">
          <h3>${y(r.symbol)} \xB7 ${y(r.name)}</h3>
          <div class="pool-meta">Issuer: <span class="mono">${y(r.issuer||"Native XRP")}</span></div>
          <div class="pool-meta">Token ID: <span class="mono">${y(r.tokenId||"\u2014")}</span></div>
          <div class="pool-meta">Price: ${r.price!=null?`$${_(r.price,6)}`:"\u2014"} \xB7 24h Vol: ${r.volume24h!=null?`$${qe(r.volume24h)}`:"\u2014"}</div>
          <div class="pool-meta">Market Cap: ${r.marketCap!=null?`$${qe(r.marketCap)}`:"\u2014"} \xB7 Holders: ${r.holders!=null?qe(r.holders):"\u2014"}</div>
          <div class="xpd-row-actions">
            <button class="xpd-mini-btn" onclick="openTokenOnChart(decodeURIComponent('${Ms(Ve(r))}'))">Switch Main Chart</button>
            ${r.issuer?`<button class="xpd-mini-btn" onclick="window.open('https://xrpscan.com/account/${y(r.issuer)}','_blank')">View Issuer</button>`:""}
            ${r.issuer?`<button class="xpd-mini-btn xpd-mini-btn--accent" onclick="openProjectIntel(decodeURIComponent('${Ms(Ve(r))}'))">\u{1F52C} Project Strength</button>`:""}
          </div>
        </div>`:""}
        <h3>Watchlist</h3>
        <div class="xpd-watchlist">${t.length?t.map(c=>{let u=Of(c,i),d=u?`${u.symbol} \xB7 ${u.name}`:c,p=(u==null?void 0:u.price)!=null?`$${_(u.price,6)}`:"\u2014",m=Ms(c);return`<div class="xpd-token-row xpd-token-row--clickable" onclick="openTokenOnChart(decodeURIComponent('${m}'))"><span>${y(d)}</span><div class="xpd-token-actions"><span>${p}</span><button class="xpd-mini-btn" onclick="event.stopPropagation(); openTokenOnChart(decodeURIComponent('${m}'))">Chart</button><button class="xpd-mini-btn" onclick="event.stopPropagation(); removeTokenFromWatchlist(decodeURIComponent('${m}'))">Remove</button></div></div>`}).join(""):'<div class="xpd-empty">No watchlist tokens yet.</div>'}</div>
        <h3>Trending</h3>
        <div class="xpd-watchlist">${o.length?o.map(c=>`<div class="xpd-token-row xpd-token-row--clickable" onclick="openTokenOnChart(decodeURIComponent('${Ms(Ve(c))}'))"><span>${y(c.symbol)} \xB7 ${y(c.name)}</span><span>${c.volume24h!=null?`$${qe(c.volume24h)} vol`:c.marketCap!=null?`$${qe(c.marketCap)} mcap`:"\u2014"}</span></div>`).join(""):'<div class="xpd-empty">No trending data.</div>'}</div>
      </div>
    </div>`}function ic(){let e=document.getElementById("xpd-lookup-currency");if(!e){he("Token Discovery hasn't loaded yet \u2014 give it a moment and try again.");return}e.scrollIntoView({behavior:"smooth",block:"center"}),setTimeout(()=>e.focus(),350)}async function hi(e){let t=String(e||"").trim();if(!t)return;let n=t.includes("|")?W.tokens.find(s=>Ve(s)===t):W.tokens.find(s=>String(s.symbol||"").toUpperCase()===t.toUpperCase());if(!(n!=null&&n.issuer)){he("Project Intelligence needs a token with a known issuer.");return}ze={loading:!0,error:"",data:null,tokenKey:Ve(n),expandedSubScore:"",graphView:"list"},U(),setTimeout(()=>{var s;return(s=document.getElementById("xpd-project-intel-section"))==null?void 0:s.scrollIntoView({behavior:"smooth",block:"start"})},30);try{ze={loading:!1,error:"",data:await wl(n),tokenKey:Ve(n),expandedSubScore:"",graphView:"list"}}catch(s){ze={loading:!1,error:(s==null?void 0:s.message)||"Could not load project intelligence.",data:null,tokenKey:Ve(n),expandedSubScore:"",graphView:"list"}}U()}function rc(e){ze.expandedSubScore=ze.expandedSubScore===e?"":e,U()}var Xf=768;function lc(){return window.innerWidth>=Xf}function cc(e){e==="graph"&&!lc()||(ze.graphView=e==="graph"?"graph":"list",U())}function dc(){ze={loading:!1,error:"",data:null,tokenKey:"",expandedSubScore:"",graphView:"list"},U()}var pc={liquidity:{label:"Liquidity",icon:"\u{1F4A7}"},distribution:{label:"Distribution",icon:"\u{1F9EE}"},marketQuality:{label:"Market Quality",icon:"\u{1F4CA}"},lpStability:{label:"LP Stability",icon:"\u{1F3E6}"},issuerRisk:{label:"Issuer Risk",icon:"\u{1F6E1}"}};function Uo(e){return e>=75?"#50fa7b":e>=50?"#f1fa8c":e>=25?"#ffb86c":"#ff5555"}function uc(e){return e>=75?"STRONG":e>=50?"MODERATE":e>=25?"WEAK":"VERY WEAK"}function Hf(){if(ze.loading)return`<div class="xpd-section-head"><h2>\u{1F52C} Project Intelligence</h2></div>
      <div class="xpd-loading">Fetching AMM state, order-book depth, holder and LP concentration, and issuer flags\u2026</div>`;if(ze.error)return`<div class="xpd-section-head"><h2>\u{1F52C} Project Intelligence</h2>
      <button class="xpd-action" onclick="closeProjectIntel()">\u2715 Close</button></div>
      <div class="xpd-error">${y(ze.error)}</div>`;let e=ze.data;if(!e)return"";let t=e.strength,n=Uo(t.overall),s=t.dimensionsLive.map(a=>{let o=pc[a],i=t.subScores[a],r=ze.expandedSubScore===a;return`
      <div class="pi-subscore ${r?"pi-subscore--open":""}" onclick="toggleProjectIntelSubScore('${a}')">
        <div class="pi-subscore-row">
          <span class="pi-subscore-label">${o.icon} ${o.label}</span>
          <span class="pi-subscore-val" style="color:${Uo(i.score)}">${i.score}</span>
        </div>
        <div class="pi-subscore-bar"><div class="pi-subscore-fill" style="width:${i.score}%;background:${Uo(i.score)}"></div></div>
        ${r?`<div class="pi-subscore-detail">${Object.entries(i.inputs).map(([l,c])=>`
          <div class="pi-kv"><span>${y(Ra(l))}</span><span class="mono">${y(mc(c))}</span></div>
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
      <div class="pi-score-word" style="color:${n}">${uc(t.overall)}</div>
      <div class="pi-issuer-line mono">Issuer: ${y(e.token.issuer)}</div>
    </div>
    <div class="pi-subscore-grid">${s}</div>

    ${Uf(Ho(e))}

    <div class="pi-cards-grid">
      ${zf(e)}
      ${Ml("Holder Concentration",e.holders,"\u{1F465}")}
      ${Ml("LP Token Concentration",e.lp,"\u{1F3E6}")}
      ${jf(e.issuerRisk)}
    </div>`}function Ra(e){return e.replace(/([A-Z])/g," $1").replace(/^./,t=>t.toUpperCase()).trim()}function mc(e){return e==null?"\u2014":typeof e=="boolean"?e?"Yes":"No":typeof e=="number"?Number.isInteger(e)?String(e):_(e,2):String(e)}function zf(e){var i;let t=e.amm,n=e.orderBook,s=t!=null&&t.exists?`
    <div class="pi-kv"><span>XRP reserve</span><span class="mono">${_(t.xrpReserve,2)} XRP</span></div>
    <div class="pi-kv"><span>Token reserve</span><span class="mono">${_(t.tokenReserve,2)}</span></div>
    <div class="pi-kv"><span>LP token supply</span><span class="mono">${_(t.lpSupply,2)}</span></div>
    <div class="pi-kv"><span>Trading fee</span><span class="mono">${_(t.tradingFeePct,3)}%</span></div>
    ${t.auctionSlot?`<div class="pi-kv"><span>Auction slot discount</span><span class="mono">${_(t.auctionSlot.discountedFeePct,3)}%</span></div>`:""}
    ${(i=t.voteSlots)!=null&&i.length?`<div class="pi-kv"><span>Fee-vote participants</span><span class="mono">${t.voteSlots.length}</span></div>`:""}
  `:'<div class="inspect-empty-note">No AMM pool found for this pair.</div>',a=(r,l)=>r!=null&&r.length?`
    <div class="pi-depth-title">${l}</div>
    <table class="pi-depth-table"><thead><tr><th>Impact</th><th>XRP</th><th>Tokens</th></tr></thead><tbody>
    ${r.map(c=>`<tr><td>${c.pct}%</td><td class="mono">${_(c.xrpAtOffer,1)}</td><td class="mono">${qe(c.tokenAtOffer)}${c.bookExhausted?' <span title="Visible order book fully consumed before reaching this price-impact level \u2014 real depth may be less than shown, book is thin.">\u26A0</span>':""}</td></tr>`).join("")}
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
    </div>`}function Ml(e,t,n){if(!(t!=null&&t.exists))return`
    <div class="sec-card pi-card">
      <div class="sec-card-hdr"><span class="sec-card-icon">${n}</span><div><div class="sec-card-title">${y(e)}</div></div></div>
      <div class="inspect-empty-note">No holder data found.</div>
    </div>`;let s=(t.topHolders||[]).slice(0,8).map((a,o)=>`
    <div class="pi-holder-row">
      <span class="pi-holder-rank">${o+1}</span>
      <a href="https://xrpscan.com/account/${y(a.address)}" target="_blank" rel="noopener" class="mono pi-holder-addr">${y(a.address.slice(0,8))}\u2026${y(a.address.slice(-5))}</a>
      <span class="mono">${qe(a.balance)}</span>
      <span class="mono pi-holder-pct">${t.totalSampled>0?_(a.balance/t.totalSampled*100,1):"0.0"}%</span>
    </div>`).join("");return`
    <div class="sec-card pi-card">
      <div class="sec-card-hdr"><span class="sec-card-icon">${n}</span><div><div class="sec-card-title">${y(e)}</div><div class="sec-card-sub">${qe(t.holderCount)} holders${t.sampleOnly?" (sampled, capped)":""}</div></div></div>
      <div class="pi-kv"><span>Top 1</span><span class="mono">${_(t.top1Pct,1)}%</span></div>
      <div class="pi-kv"><span>Top 5</span><span class="mono">${_(t.top5Pct,1)}%</span></div>
      <div class="pi-kv"><span>Top 10</span><span class="mono">${_(t.top10Pct,1)}%</span></div>
      <hr class="pi-hr" />
      ${s}
    </div>`}var xt={clawbackEnabled:"The issuer has the technical capability to reclaim issued balances under XRPL's clawback mechanism. Consider the project's stated policy and use case.",globalFreeze:"The issuer has currently frozen all trustlines for this currency \u2014 holders cannot move balances until it's lifted.",freezeCapable:"The issuer retains the ability to freeze individual trustlines. Common and not inherently malicious, but a real capability worth knowing about.",requireAuth:"The issuer must approve each trustline before it can hold a balance \u2014 restricts who can hold this token.",blackholed:"The issuer has permanently disabled its master key and holds no regular key \u2014 issuer-side control of the account is no longer possible."};function jf(e){if(!(e!=null&&e.exists))return`
    <div class="sec-card pi-card">
      <div class="sec-card-hdr"><span class="sec-card-icon">\u{1F6E1}</span><div><div class="sec-card-title">Issuer Risk</div></div></div>
      <div class="inspect-empty-note">Could not load issuer account state.</div>
    </div>`;let t=(n,s,a)=>`
    <div class="finding finding--${s?a?"ok":"warn":"ok"}">
      <span class="finding-sev ${s?a?"sev-ok":"sev-warn":"sev-ok"}">${s?a?"YES":"\u26A0":"NO"}</span>
      <div class="finding-body">
        <div class="finding-label">${Ra(n)}</div>
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
    </div>`}var Zo={project:{icon:"\u{1F4C1}",color:"#8be9fd"},token:{icon:"\u{1FA99}",color:"#f1fa8c"},issuer:{icon:"\u{1F3DB}",color:"#ff79c6"},amm:{icon:"\u{1F4A7}",color:"#50fa7b"},auction:{icon:"\u{1F39F}",color:"#ffb86c"},vote:{icon:"\u{1F5F3}",color:"#bd93f9"},whale:{icon:"\u{1F40B}",color:"#6272a4"},lp:{icon:"\u{1F3E6}",color:"#69bff8"}};function Wf(e){return e?`${e.slice(0,8)}\u2026${e.slice(-5)}`:""}function Uf(e){let t=lc(),n=t&&ze.graphView==="graph";return`
    <div class="xpd-section-head pig-section-head">
      <h3 class="pig-heading">\u{1F578} Intelligence Graph <span class="pig-heading-sub">\u2014 proven on-ledger relationships only</span></h3>
      <div class="pig-view-toggle">
        <button class="pig-toggle-btn ${n?"":"pig-toggle-btn--active"}" onclick="setProjectGraphView('list')">\u2630 List</button>
        <button class="pig-toggle-btn ${n?"pig-toggle-btn--active":""} ${t?"":"pig-toggle-btn--disabled"}" ${t?`onclick="setProjectGraphView('graph')"`:'disabled title="The visual graph needs a wider screen to lay out its columns \u2014 switch to list view or widen your browser."'}>\u{1F578} Graph</button>
      </div>
    </div>
    ${n?Kf(e):qf(e)}`}function qf(e){let t=new Map(e.nodes.map(d=>[d.id,d])),n=d=>e.edges.filter(p=>p.from===d||p.to===d),s=d=>{let p=Zo[d.type]||{icon:"\u2022",color:"rgba(255,255,255,0.3)"},m=n(d.id).map(f=>`<div class="pig-fact"><span class="pig-fact-badge">PROVEN</span>${y(f.factLabel)}</div>`).join("");return`
      <div class="pig-node" style="border-left-color:${p.color}">
        <div class="pig-node-hdr">
          <span class="pig-node-icon">${p.icon}</span>
          <span class="pig-node-label">${y(d.label)}</span>
          ${d.address?`<a href="https://xrpscan.com/account/${y(d.address)}" target="_blank" rel="noopener" class="mono pig-node-addr">${y(Wf(d.address))}</a>`:""}
        </div>
        ${m}
      </div>`},a=t.get("token"),o=t.get("issuer"),i=t.get("amm"),r=t.get("auction"),l=e.nodes.filter(d=>d.type==="vote"),c=e.nodes.filter(d=>d.type==="whale"),u=e.nodes.filter(d=>d.type==="lp");return`
    <div class="pig-list">
      ${s(a)}
      ${s(o)}
      ${i?s(i):'<div class="inspect-empty-note">No AMM pool to graph.</div>'}
      ${r?s(r):""}
      ${l.length?`<div class="pig-list-subgroup"><div class="pig-list-subgroup-title">Fee Voters (${l.length})</div>${l.map(s).join("")}</div>`:""}
      ${c.length?`<div class="pig-list-subgroup"><div class="pig-list-subgroup-title">Top Holders (${c.length})</div>${c.map(s).join("")}</div>`:""}
      ${u.length?`<div class="pig-list-subgroup"><div class="pig-list-subgroup-title">Top LP Holders (${u.length})</div>${u.map(s).join("")}</div>`:""}
    </div>`}var fc={token:0,issuer:0,amm:1,auction:1,vote:1,whale:2,lp:2},hc=[20,270,520],qo=220,Ta=34,gc=46;function Vf(e,t){return e.length>t?e.slice(0,t-1)+"\u2026":e}function Gf(e){let t=[[],[],[]];e.nodes.forEach(s=>{s.type!=="project"&&t[fc[s.type]??1].push(s)});let n=[];return t.forEach((s,a)=>s.forEach((o,i)=>n.push({...o,x:hc[a],y:16+i*gc}))),n}function Kf(e){let t=Gf(e),n=new Map(t.map(c=>[c.id,c])),s=[0,1,2].map(c=>t.filter(u=>(fc[u.type]??1)===c).length),a=hc[2]+qo+20,o=32+Math.max(1,...s)*gc,i=e.edges.map(c=>{let u=n.get(c.from),d=n.get(c.to);if(!u||!d)return"";let p=u.x+qo,m=u.y+Ta/2,f=d.x,g=d.y+Ta/2,v=(p+f)/2;return`<path d="M${p},${m} C${v},${m} ${v},${g} ${f},${g}" stroke="rgba(255,255,255,0.25)" stroke-width="1.5" fill="none"/>`}).join(""),r=t.map(c=>{let u=Zo[c.type]||{icon:"\u2022",color:"rgba(255,255,255,0.3)"},d=`${u.icon} ${c.label}`;return`
      <g class="pig-svg-node">
        <rect x="${c.x}" y="${c.y}" width="${qo}" height="${Ta}" rx="7" fill="rgba(255,255,255,0.06)" stroke="${u.color}" stroke-width="1.5"></rect>
        <text x="${c.x+10}" y="${c.y+Ta/2+4}" font-size="11" fill="#fff">${y(Vf(d,26))}</text>
        <title>${y(c.label)}${c.address?" \u2014 "+y(c.address):""}</title>
      </g>`}).join(""),l=Object.entries(Zo).filter(([c])=>c!=="project").map(([c,u])=>`<span class="pig-legend-item"><span class="pig-legend-swatch" style="background:${u.color}"></span>${u.icon} ${Ra(c)}</span>`).join("");return`
    <div class="pig-svg-wrap"><svg viewBox="0 0 ${a} ${o}" width="${a}" height="${o}" class="pig-svg">${i}${r}</svg></div>
    <div class="pig-svg-legend">${l}</div>`}function bc(){let e=ze.data;e&&Ba(Jf(e))}function Ll(e,t){if(!(e!=null&&e.length))return"";let n=e.map(s=>`    ${s.pct}% impact: ${_(s.xrpAtOffer,1)} XRP / ${qe(s.tokenAtOffer)} tokens${s.bookExhausted?" (book exhausted before this level \u2014 real depth may be less than shown)":""}`).join(`
`);return`  ${t}:
${n}`}function Al(e,t){let n=[`${e}:`];return t!=null&&t.exists?(n.push(`  Holder count: ${t.holderCount}${t.sampleOnly?" (sampled, capped)":""}`),n.push(`  Top 1 holds: ${_(t.top1Pct,1)}%`),n.push(`  Top 5 hold: ${_(t.top5Pct,1)}%`),n.push(`  Top 10 hold: ${_(t.top10Pct,1)}%`),(t.topHolders||[]).slice(0,10).forEach((s,a)=>{let o=t.totalSampled>0?_(s.balance/t.totalSampled*100,2):"0.00";n.push(`    #${a+1} ${s.address}: ${qe(s.balance)} (${o}%)`)}),n.join(`
`)):(n.push("  No data found."),n.join(`
`))}function Jf(e){var l;let t=e.strength,n=e.amm,s=e.orderBook,a=e.issuerRisk,o=[];if(o.push(`XRPL TOKEN ANALYSIS \u2014 ${e.token.symbol}${e.token.name?` (${e.token.name})`:""}`),o.push(`Issuer: ${e.token.issuer}`),o.push(`Currency code: ${e.token.currency}`),o.push(`Snapshot taken: ${new Date(e.fetchedAt).toISOString()}`),o.push(""),o.push(`OVERALL STRENGTH SCORE: ${t.overall}/100 (${uc(t.overall)})`),o.push("Methodology note: this score covers only 5 point-in-time-computable dimensions (Liquidity, Distribution, Market Quality, LP Stability, Issuer Risk). Network Activity, Treasury Health, and Project Transparency are NOT included \u2014 they would require historical tracking this tool does not do."),o.push(""),o.push("SUB-SCORES:"),t.dimensionsLive.forEach(c=>{let u=pc[c],d=t.subScores[c];o.push(`- ${u.label}: ${d.score}/100`),Object.entries(d.inputs||{}).forEach(([p,m])=>{o.push(`    ${Ra(p)}: ${mc(m)}`)})}),o.push(""),o.push("LIQUIDITY \u2014 AMM POOL:"),n!=null&&n.exists?(o.push(`  XRP reserve: ${_(n.xrpReserve,2)}`),o.push(`  Token reserve: ${_(n.tokenReserve,2)}`),o.push(`  LP token supply: ${_(n.lpSupply,2)}`),o.push(`  Trading fee: ${_(n.tradingFeePct,3)}%`),n.auctionSlot&&o.push(`  Auction slot discounted fee: ${_(n.auctionSlot.discountedFeePct,3)}%`),(l=n.voteSlots)!=null&&l.length&&o.push(`  Fee-vote participants: ${n.voteSlots.length}`)):o.push("  No AMM pool found for this pair."),o.push(""),o.push("LIQUIDITY \u2014 LIVE ORDER BOOK (DEX):"),s!=null&&s.exists){o.push(`  Buy price: ${_(s.buyPriceXrp,6)} XRP`),o.push(`  Sell price: ${_(s.sellPriceXrp,6)} XRP`),o.push(`  Spread: ${s.spreadPct!=null?_(s.spreadPct,2)+"%":"\u2014"}`);let c=Ll(s.buyDepth,"Depth buying with XRP"),u=Ll(s.sellDepth,"Depth selling for XRP");c&&o.push(c),u&&o.push(u)}else o.push("  No live order book found for this pair.");o.push(""),o.push(Al("HOLDER CONCENTRATION",e.holders)),o.push(""),o.push(Al("LP TOKEN CONCENTRATION",e.lp)),o.push(""),o.push("ISSUER RISK FLAGS:"),a!=null&&a.exists?(o.push(`  Clawback enabled: ${a.clawbackEnabled?"YES":"No"} \u2014 ${xt.clawbackEnabled}`),o.push(`  Global freeze active: ${a.globalFreeze?"YES":"No"} \u2014 ${xt.globalFreeze}`),o.push(`  Freeze-capable: ${a.freezeCapable?"YES":"No"} \u2014 ${xt.freezeCapable}`),o.push(`  Requires auth to hold: ${a.requireAuth?"YES":"No"} \u2014 ${xt.requireAuth}`),o.push(`  Issuer blackholed: ${a.blackholed?"YES":"No"} \u2014 ${xt.blackholed}`)):o.push("  Could not load issuer account state."),o.push("");let i=Ho(e);o.push("PROVEN ON-LEDGER RELATIONSHIPS (Project Intelligence Graph):");let r=new Map(i.nodes.map(c=>[c.id,c]));return i.edges.forEach(c=>{let u=r.get(c.from),d=r.get(c.to);o.push(`  ${(u==null?void 0:u.label)||c.from} \u2192 ${(d==null?void 0:d.label)||c.to} [${c.type}]: ${c.factLabel}`)}),o.push(""),o.push("---"),o.push("Please analyze this XRPL token's on-chain data above. Explain in plain language what these metrics suggest about the token's liquidity health, holder/LP concentration risk, and issuer-side control risk. Point out anything that looks like a red flag or an unusually strong/weak signal, and note any limits in what this data can and can't tell me (e.g. it's a point-in-time snapshot, not history)."),o.join(`
`)}function El(e,t){let n=String(e||""),s=String(t||"").trim();if(!s)return y(n);let a=n.toLowerCase().indexOf(s.toLowerCase());if(a<0)return y(n);let o=y(n.slice(0,a)),i=y(n.slice(a,a+s.length)),r=y(n.slice(a+s.length));return`${o}<mark class="xpd-hit">${i}</mark>${r}`}function Yf(e){var a,o;let t=Object.values(Ze).reduce((i,r)=>i+((r==null?void 0:r.xrp)||0),0),n=(a=Te.data)!=null&&a.priceUsd?t*Te.data.priceUsd:0,s=Pt.items.slice(0,8);return`
    <div class="xpd-token-grid">
      <div class="xpd-token-col">
        <div class="xpd-market-grid">
          <article class="xpd-stat-card xpd-token-row--clickable" onclick="openTokenOnChart('XRP')"><span class="xpd-stat-label">Portfolio XRP</span><strong class="xpd-stat-value">${_(t,4)}</strong></article>
          <article class="xpd-stat-card"><span class="xpd-stat-label">Portfolio USD</span><strong class="xpd-stat-value">${n?`$${_(n,2)}`:"\u2014"}</strong></article>
          <article class="xpd-stat-card"><span class="xpd-stat-label">Wallets</span><strong class="xpd-stat-value">${oe.length}</strong></article>
          <article class="xpd-stat-card"><span class="xpd-stat-label">Network Stream</span><strong class="xpd-stat-value">${((o=X.wsConn)==null?void 0:o.readyState)===1?"Online":"Offline"}</strong></article>
        </div>
      </div>
      <div class="xpd-token-col">
        ${Pt.loading?'<div class="xpd-loading">Loading recent transactions...</div>':""}
        ${Pt.error?`<div class="xpd-error">${y(Pt.error)}</div>`:""}
        <div class="xpd-watchlist">${e?s.length?s.map(i=>`<div class="xpd-token-row"><span class="mono">${y((i.hash||"").slice(0,12))}...</span><span>${y(i.TransactionType||"Unknown")}</span></div>`).join(""):'<div class="xpd-empty">No recent transactions.</div>':'<div class="xpd-empty">Select wallet to view transactions.</div>'}</div>
      </div>
    </div>`}function Qf(e){return e?yt.loading?'<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-loading">Loading account_objects and LP balances...</div></div>':yt.error?`<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-error">${y(yt.error)}</div></div>`:yt.pools.length?`<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-pool-list">${yt.pools.map(t=>`
    <div class="xpd-pool-item">
      <div class="pool-pair xpd-pill-text" title="${y(t.pair)}">${y(t.pair)}</div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">LP Balance</span><span class="xpd-pool-row-value" title="${y(t.lpBalance)}">${y(t.lpBalance)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Est. Value</span><span class="xpd-pool-row-value">${y(t.estimatedValue)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Trading Fee</span><span class="xpd-pool-row-value">${y(t.tradingFee||"\u2014")}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">TVL</span><span class="xpd-pool-row-value">${y(t.tvl||"Unavailable")}</span></div>
    </div>`).join("")}</div></div>`:'<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-empty">No AMM entries or LP-token balances detected for this wallet yet.</div></div>':'<div class="xpd-amm-card"><h3>Your liquidity positions</h3><div class="xpd-empty">No active wallet.</div></div>'}function Zf(){return Mt.loading?'<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-loading">Loading amm_info for known pools...</div></div>':Mt.error?`<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-error">${y(Mt.error)}</div></div>`:Mt.pools.length?`<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-pool-list">${Mt.pools.map(e=>`
    <div class="xpd-pool-item">
      <div class="pool-pair xpd-pill-text" title="${y(e.label)}">${y(e.label)}</div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Reserves</span><span class="xpd-pool-row-value">${y(e.reserveA)} / ${y(e.reserveB)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Trading Fee</span><span class="xpd-pool-row-value">${y(e.tradingFee)} bps</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Total LP</span><span class="xpd-pool-row-value mono" title="${y(e.totalLp)}">${y(e.totalLp)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">TVL</span><span class="xpd-pool-row-value">${y(e.tvl||"Unavailable")}</span></div>
    </div>`).join("")}</div></div>`:'<div class="xpd-amm-card"><h3>General pool explorer</h3><div class="xpd-empty">No seeded pools returned on this network.</div></div>'}function eh(){return`<div class="xpd-amm-card">
    <h3>Lookup custom pool</h3>
    <div class="xpd-form-grid">
      <input id="xpd-asset1-currency" class="xpd-input" placeholder="Asset 1 currency (e.g. XRP)" />
      <input id="xpd-asset1-issuer" class="xpd-input" placeholder="Asset 1 issuer (optional for XRP)" />
      <input id="xpd-asset2-currency" class="xpd-input" placeholder="Asset 2 currency (e.g. USD)" />
      <input id="xpd-asset2-issuer" class="xpd-input" placeholder="Asset 2 issuer" />
    </div>
    <div class="xpd-row-actions"><button class="xpd-action" onclick="loadCustomAmmPool()"><span class="xai">\u{1F50E}</span>Load pool</button><button class="xpd-action" onclick="refreshPoolExplorer()"><span class="xai">\u27F3</span>Refresh known pools</button></div>
    ${Fe.loading?'<div class="xpd-loading">Loading pool...</div>':""}
    ${Fe.error?`<div class="xpd-error">${y(Fe.error)}</div>`:""}
    ${Fe.pool?`<div class="xpd-pool-item">
      <div class="pool-pair xpd-pill-text" title="${y(Fe.pool.label)}">${y(Fe.pool.label)}</div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Reserves</span><span class="xpd-pool-row-value">${y(Fe.pool.reserveA)} / ${y(Fe.pool.reserveB)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Trading Fee</span><span class="xpd-pool-row-value">${y(Fe.pool.tradingFee)} bps</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">Total LP</span><span class="xpd-pool-row-value mono" title="${y(Fe.pool.totalLp)}">${y(Fe.pool.totalLp)}</span></div>
      <div class="xpd-pool-row"><span class="xpd-pool-row-label">TVL</span><span class="xpd-pool-row-value">${y(Fe.pool.tvl||"Unavailable")}</span></div>
    </div>`:""}
  </div>`}function qe(e){return Number.isFinite(Number(e))?new Intl.NumberFormat("en-US",{notation:"compact",maximumFractionDigits:2}).format(Number(e)):"\u2014"}function ss(e){return typeof e=="string"?`${_(Number(e)/1e6,4)} XRP`:e&&typeof e=="object"?`${_(Number(e.value||0),4)} ${e.currency||"UNK"}`:"\u2014"}function th(e){if(!e||typeof e!="string")return"";try{let t=e.trim();if(!/^[0-9A-Fa-f]+$/.test(t)||t.length%2!==0)return t;let n=new Uint8Array(t.length/2);for(let s=0;s<t.length;s+=2)n[s/2]=parseInt(t.slice(s,s+2),16);return new TextDecoder().decode(n)}catch{return""}}function Nl(e){return e?e.startsWith("ipfs://")?`https://ipfs.io/ipfs/${e.slice(7)}`:e.startsWith("ar://")?`https://arweave.net/${e.slice(5)}`:e:""}async function nh(e){let t=Nl(th(e.URI||e.uri||""));if(!t)return"";if(/\.(png|jpg|jpeg|gif|webp|svg)$/i.test(t))return t;try{let n=await fetch(t,{method:"GET"});if(!n.ok)return"";let s=await n.json(),a=(s==null?void 0:s.image)||(s==null?void 0:s.image_url)||(s==null?void 0:s.thumbnail);return Nl(a||"")}catch{return""}}async function Lt(e,{timeoutMs:t=9e3,allowProxy:n=!0}={}){let s=async a=>{let o=typeof(AbortSignal==null?void 0:AbortSignal.timeout)=="function"?AbortSignal.timeout(t):void 0,i=await fetch(a,{method:"GET",mode:"cors",cache:"no-store",signal:o});if(!i.ok)throw new Error(`HTTP ${i.status}`);return await i.json()};try{return await s(e)}catch(a){if(!n)throw a;for(let o of tf)try{return await s(o(e))}catch{}throw a}}async function vc(){var e;Te.loading=!0,Te.error="",U();try{let t=await Lt("https://api.exchange.coinbase.com/products/XRP-USD/ticker"),n=await Lt("https://api.exchange.coinbase.com/products/XRP-USD/candles?granularity=86400"),s=Array.isArray(n)&&n.length?n[0]:null,a=Number((t==null?void 0:t.price)||0),o=s?Number(s[3]||0):a,i=s?Number(s[2]||a):a,r=s?Number(s[1]||a):a,l=s?Number(s[5]||0):0;Te.data={priceUsd:a,change24h:o?(a-o)/o*100:0,volume24h:l*a,marketCap:Number(((e=Te.data)==null?void 0:e.marketCap)||0),high24h:i,low24h:r}}catch(t){Te.error=(t==null?void 0:t.message)||"Could not load market data right now.",Te.data=null}finally{Te.loading=!1,U()}}async function yc(e){if(vt.loading=!0,vt.error="",vt.items=[],U(),!e){vt.loading=!1,U();return}try{let t,n=[];do{let a=await at({method:"account_nfts",params:[{account:e,limit:100,...t?{marker:t}:{}}]});n.push(...(a==null?void 0:a.account_nfts)||[]),t=a==null?void 0:a.marker}while(t);let s=await Promise.all(n.slice(0,80).map(async a=>({id:a.NFTokenID||a.nf_token_id||"Unknown",image:await nh(a)})));vt.items=s}catch(t){vt.error=(t==null?void 0:t.message)||"Could not load NFTs for this wallet."}finally{vt.loading=!1,U()}}async function wc(e){if(yt.loading=!0,yt.error="",yt.pools=[],U(),!e){yt.loading=!1,U();return}try{let t=[],n;do{let o=await at({method:"account_objects",params:[{account:e,type:"amm",limit:200,...n?{marker:n}:{}}]});((o==null?void 0:o.account_objects)||[]).forEach(r=>{let l=ss(r.Asset||r.amount),c=ss(r.Asset2||r.amount2),u=l.split(" ").pop()||"AssetA",d=c.split(" ").pop()||"AssetB";t.push({pair:`${u}/${d}`,lpBalance:r.LPTokenBalance?ss(r.LPTokenBalance):"Not reported",estimatedValue:"Estimate unavailable",tradingFee:r.TradingFee!=null?`${r.TradingFee} bps`:"\u2014",tvl:"Unavailable"})}),n=o==null?void 0:o.marker}while(n);let s=await at({method:"account_lines",params:[{account:e,limit:200}]});((s==null?void 0:s.lines)||[]).filter(o=>typeof o.currency=="string"&&o.currency.length>=16&&Number(o.balance)>0).forEach(o=>{t.push({pair:`LP Token ${o.currency.slice(0,8)}...`,lpBalance:`${_(Number(o.balance),4)} ${o.currency.slice(0,8)}...`,estimatedValue:"Estimate unavailable",tradingFee:"\u2014",tvl:"Unavailable"})}),yt.pools=t}catch(t){yt.error=(t==null?void 0:t.message)||"Could not load account AMM objects."}finally{yt.loading=!1,U()}}async function xc(e){try{let t=await at({method:"amm_info",params:[{asset:e.asset,asset2:e.asset2}]}),n=t==null?void 0:t.amm;return n?{label:e.label,reserveA:ss(n.amount),reserveB:ss(n.amount2),tradingFee:String(n.trading_fee??"\u2014"),totalLp:ss(n.lp_token||n.lp_token_balance),tvl:sh(n.amount,n.amount2)}:null}catch{return null}}function sh(e,t){let n=a=>typeof a=="string"?Number(a)/1e6:a&&typeof a=="object"?Number(a.value||0):0,s=n(e)+n(t);return!Number.isFinite(s)||s<=0?"Unavailable":`${_(s,4)} (asset units)`}async function kc(){Mt.loading=!0,Mt.error="",U();try{let e=await Promise.all(kf.map(xc));Mt.pools=e.filter(Boolean)}catch(e){Mt.error=(e==null?void 0:e.message)||"Could not load AMM explorer data.",Mt.pools=[]}finally{Mt.loading=!1,U()}}async function $c(){var r,l,c,u;let e=(((r=document.getElementById("xpd-asset1-currency"))==null?void 0:r.value)||"").trim().toUpperCase(),t=(((l=document.getElementById("xpd-asset1-issuer"))==null?void 0:l.value)||"").trim(),n=(((c=document.getElementById("xpd-asset2-currency"))==null?void 0:c.value)||"").trim().toUpperCase(),s=(((u=document.getElementById("xpd-asset2-issuer"))==null?void 0:u.value)||"").trim();if(!e||!n){Fe.error="Enter both asset currency codes first.",U();return}let a=e==="XRP"?{currency:"XRP"}:{currency:e,issuer:t},o=n==="XRP"?{currency:"XRP"}:{currency:n,issuer:s};if(e!=="XRP"&&!t||n!=="XRP"&&!s){Fe.error="Issuer is required for non-XRP assets.",U();return}Fe.loading=!0,Fe.error="",Fe.pool=null,U();let i=await xc({label:`${e}/${n}`,asset:a,asset2:o});Fe.loading=!1,i?Fe.pool=i:Fe.error="Pool not found or unavailable on this network.",U()}function _a(){return Fn.find(e=>e.id===M.pair)||Fn[0]}function gi(e){if(e==="D")return 1440;if(e==="W")return 10080;if(e==="M")return 43200;let t=Number(e);return Number.isFinite(t)&&t>0?t:60}function ah(e){if(e==="M")return"W";if(e==="D"||e==="W")return e;let t=gi(e);for(let n of[5,15,60,240])if(t<=n)return String(n);return"D"}async function oh(e,t,n,s=200){var u;let a=t?`${e}.${t}`:e,o=ah(n),i=Math.min(2e3,Math.max(20,Number(s)||200)),r=`https://api.onthedex.live/public/v1/ohlc?base=${encodeURIComponent(a)}&quote=XRP&interval=${o}&bars=${i}`,l=await Lt(r,{timeoutMs:1e4});return(Array.isArray((u=l==null?void 0:l.data)==null?void 0:u.ohlc)?l.data.ohlc:[]).map(d=>({time:Number(d.t),open:Number(d.o),high:Number(d.h),low:Number(d.l),close:Number(d.c),volume:Number(d.vb||0)})).filter(d=>Number.isFinite(d.time)&&[d.open,d.high,d.low,d.close].every(Number.isFinite)).sort((d,p)=>d.time-p.time)}function Sc(e){return{xrpusd:"XRP-USD",XRPUSDT:"XRP-USD",ETHUSDT:"ETH-USD",BTCUSDT:"BTC-USD",SOLUSDT:"SOL-USD"}[e]||null}function ih(e){return{XRP:"XRP-USD",BTC:"BTC-USD",ETH:"ETH-USD",SOL:"SOL-USD",USDC:"USDC-USD"}[String(e||"").toUpperCase()]||null}var Vo=new Map;async function rh(e,t){if(!e)return null;let n=`${Ve(e)}:${t}`,s=Vo.get(n);if(s)return s;let a=lh(e,t);Vo.set(n,a);try{return await a}finally{Vo.delete(n)}}async function lh(e,t){var o,i;let n=String(e.symbol||"").toUpperCase();if(!n||n==="XRP")return null;let s=ih(n);if(s)try{let r=Pc(t),l=r===86400?Vl:Gl,{candles:c,reachedStart:u}=await si(s,r,l);if(c.length){let d=u?`${new Date(c[0].time*1e3).getUTCFullYear()}\u2013present`:`last ${c.length} bars`;return{candles:c,source:`Coinbase direct (${s}, ${d})`,mode:"token-direct"}}}catch{}let a=String(e.issuer||"").trim();if(a)try{let r=await oh(n,a,t,2e3);if(r.length){let l=Number(((o=M.stats)==null?void 0:o.xrplSpot)||((i=M.stats)==null?void 0:i.price)||0);return{candles:l>0?r.map(u=>({time:u.time,open:u.open*l,high:u.high*l,low:u.low*l,close:u.close*l,volume:u.volume})):r,source:`OnTheDex XRPL DEX (${n}/XRP)`,mode:"token-direct"}}}catch{}return null}function ch(e,{mode:t="pair",source:n="Source pending",tokenKey:s=""}={}){let a=Array.isArray(e)?e:[];if(!a.length){M.chartMeta={tokenKey:s||M.tokenFocusKey||"XRP|",symbol:s&&s.split("|")[0]||"XRP",source:n,last:null,high:null,low:null,mode:t};return}let o=a[a.length-1],i=a.map(c=>Number(c.high)).filter(c=>Number.isFinite(c)),r=a.map(c=>Number(c.low)).filter(c=>Number.isFinite(c)),l=s||M.tokenFocusKey||"XRP|";M.chartMeta={tokenKey:l,symbol:l.split("|")[0]||"XRP",source:n,last:Number(o.close),high:i.length?Math.max(...i):Number(o.high),low:r.length?Math.min(...r):Number(o.low),mode:t}}async function Fs(){var t;let e=_a();M.loading=!0,M.error="";try{let n=Sc(e.ticker);if(n){let s=await Lt(`https://api.exchange.coinbase.com/products/${n}/ticker`),a=await Lt(`https://api.exchange.coinbase.com/products/${n}/candles?granularity=86400`),o=Array.isArray(a)&&a.length?a[0]:null,i=Number(s.price||0),r=o?Number(o[3]):i;M.stats={price:i,high:o?Number(o[2]):i,low:o?Number(o[1]):i,changePct:r?(i-r)/r*100:0,baseSource:"Coinbase",source:"Coinbase"},await Tc(),!Te.data&&M.stats.price&&(Te.data={priceUsd:M.stats.price,change24h:M.stats.changePct,volume24h:o?Number(o[5]||0)*M.stats.price:0,marketCap:Number(((t=Te.data)==null?void 0:t.marketCap)||0)});return}throw new Error("Chart stats unavailable for selected pair.")}catch(n){M.error=(n==null?void 0:n.message)||"DEX chart stats unavailable right now."}finally{M.loading=!1}}async function Tc(){var e,t,n;try{let s=await at({method:"book_offers",params:[{taker_gets:{currency:"USD",issuer:"rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq"},taker_pays:{currency:"XRP"},limit:1}]}),a=(e=s==null?void 0:s.offers)==null?void 0:e[0];if(!a)return;let o=Number(((t=a.TakerGets)==null?void 0:t.value)||0),i=typeof a.TakerPays=="string"?Number(a.TakerPays)/1e6:Number(((n=a.TakerPays)==null?void 0:n.value)||0);if(o>0&&i>0){let r=o/i;if(ql=Date.now(),M.stats||(M.stats={}),M.stats.xrplSpot=r,String(_a().symbol||"XRP").toUpperCase()==="XRP"){M.stats.price=r;let l=M.stats.baseSource||M.stats.source||"Market feed";M.stats.source=`${l} + XRPL live`,Te.data&&(Te.data.priceUsd=r)}}}catch{}}async function dh(){var e,t;return(e=window.LightweightCharts)!=null&&e.createChart?!0:($a||($a=new Promise((n,s)=>{let a=document.querySelector('script[data-lw-chart="1"]');if(a){a.addEventListener("load",()=>n(!0),{once:!0}),a.addEventListener("error",()=>s(new Error("Chart library failed to load.")),{once:!0});return}let o=document.createElement("script");o.src="https://unpkg.com/lightweight-charts@4.2.2/dist/lightweight-charts.standalone.production.js",o.async=!0,o.defer=!0,o.dataset.lwChart="1",o.onload=()=>n(!0),o.onerror=()=>s(new Error("Chart library failed to load.")),document.head.appendChild(o)}).finally(()=>{var n;(n=window.LightweightCharts)!=null&&n.createChart||($a=null)})),await $a,!!((t=window.LightweightCharts)!=null&&t.createChart))}async function ph(){var e,t;return(e=window.THREE)!=null&&e.Scene?!0:(Sa||(Sa=new Promise((n,s)=>{let a=document.querySelector('script[data-three-chart="1"]');if(a){a.addEventListener("load",()=>n(!0),{once:!0}),a.addEventListener("error",()=>s(new Error("Three.js failed to load.")),{once:!0});return}let o=document.createElement("script");o.src="https://unpkg.com/three@0.166.1/build/three.min.js",o.async=!0,o.defer=!0,o.dataset.threeChart="1",o.onload=()=>n(!0),o.onerror=()=>s(new Error("Three.js failed to load.")),document.head.appendChild(o)}).finally(()=>{var n;(n=window.THREE)!=null&&n.Scene||(Sa=null)})),await Sa,!!((t=window.THREE)!=null&&t.Scene))}function Os(){var e,t;if(Ke.resizeHandler)try{window.removeEventListener("resize",Ke.resizeHandler)}catch{}if(Ke.raf&&cancelAnimationFrame(Ke.raf),(t=(e=Ke.renderer)==null?void 0:e.domElement)!=null&&t.parentElement)try{Ke.renderer.domElement.parentElement.removeChild(Ke.renderer.domElement)}catch{}if(Ke.renderer)try{Ke.renderer.dispose()}catch{}Ke={renderer:null,scene:null,camera:null,points:null,raf:0,host:null,resizeHandler:null}}async function uh(){var t;let e=document.getElementById("xpd-chart-atmosphere");if(e&&!(Ke.renderer&&e.contains(Ke.renderer.domElement))&&!((navigator.hardwareConcurrency||4)<=3))try{if(await ph(),!((t=window.THREE)!=null&&t.Scene))return;Os();let n=window.THREE,s=Math.max(1,e.clientWidth||640),a=Math.max(1,e.clientHeight||460),o=new n.Scene,i=new n.PerspectiveCamera(52,s/a,.1,1e3);i.position.z=46;let r=new n.WebGLRenderer({alpha:!0,antialias:!0});r.setPixelRatio(Math.min(2,window.devicePixelRatio||1)),r.setSize(s,a),e.appendChild(r.domElement);let l=900,c=new Float32Array(l*3);for(let h=0;h<l;h+=1){let b=h*3;c[b]=(Math.random()-.5)*90,c[b+1]=(Math.random()-.5)*40,c[b+2]=(Math.random()-.5)*24}let u=new n.BufferGeometry;u.setAttribute("position",new n.BufferAttribute(c,3));let d=new n.PointsMaterial({color:5101823,size:.25,transparent:!0,opacity:.26,depthWrite:!1}),p=new n.Points(u,d);o.add(p);let m=0,f=0,g=()=>{var T;m+=1;let h=Number(((T=M.stats)==null?void 0:T.changePct)||0),b=Math.min(4,Math.max(.35,Math.abs(h)/2.2)),x=h>0?16758874:16739999;d.color.setHex(Math.abs(h)>1.5?x:5101823),p.rotation.y+=9e-4*b,p.rotation.x=Math.sin(m*.0015*b)*.08,p.position.y=Math.sin(m*.003*b)*.7,(!document.hidden||Date.now()-f>350)&&(r.render(o,i),f=Date.now()),Ke.raf=requestAnimationFrame(g)},v=()=>{let h=Math.max(1,e.clientWidth||640),b=Math.max(1,e.clientHeight||460);i.aspect=h/b,i.updateProjectionMatrix(),r.setSize(h,b)};window.addEventListener("resize",v,{passive:!0}),Ke={renderer:r,scene:o,camera:i,points:p,raf:0,host:e,resizeHandler:v},g()}catch{}}function Cc(e){return gi(e)*60}function Pc(e){let t=gi(e);return t<=1?60:t<=5?300:t<=15?900:t<=60?3600:t<=360?21600:86400}function Mc(){let e=String(M.tokenFocusKey||"");if(!e)return null;let t=e.includes("|")?e.split("|")[0]:e;return W.tokens.find(n=>Ve(n)===e)||W.tokens.find(n=>String(n.symbol||"").toUpperCase()===String(t||"").toUpperCase())||null}function Lc(){var a,o;let e=Mc(),t=Number((e==null?void 0:e.price)||0);if(Number.isFinite(t)&&t>0)return t;let n=Number(((a=M.stats)==null?void 0:a.xrplSpot)||0);if(Number.isFinite(n)&&n>0)return n;let s=Number(((o=M.stats)==null?void 0:o.price)||0);return Number.isFinite(s)&&s>0?s:1}function Ac(e,t=1,n=220){let s=Math.max(60,Cc(e)),a=Math.floor(Date.now()/1e3),o=Math.floor(a/s)*s-n*s,i=Math.max(1e-6,Number(t)||1),r=[];for(let l=0;l<n;l+=1){let c=o+l*s,u=i,d=Math.sin((l+1)/9)*.004+Math.cos((l+3)/17)*.002;i=Math.max(1e-6,u*(1+d));let p=Math.max(u,i)*(1+Math.abs(d)*.55+.0015),m=Math.min(u,i)*Math.max(1e-6,1-(Math.abs(d)*.55+.0015));r.push({time:c,open:Number(u),high:Number(p),low:Number(m),close:Number(i),volume:Math.max(0,Math.round(Math.abs(d)*12e3+l%13*55))})}return r}function ei(e){if(!e.length)return e;let t=[];for(let n=0;n<e.length;n+=1){let s=e[n],a=(s.open+s.high+s.low+s.close)/4,o=t[n-1],i=o?(o.open+o.close)/2:(s.open+s.close)/2,r=Math.max(s.high,i,a),l=Math.min(s.low,i,a);t.push({...s,open:i,high:r,low:l,close:a})}return t}function ti(e,t){let n=[],s=0;for(let a=0;a<e.length;a+=1)s+=e[a].close,a>=t&&(s-=e[a-t].close),a>=t-1&&n.push({time:e[a].time,value:s/t});return n}function Ds(e,t){let n=[];if(!e.length)return n;let s=2/(t+1),a=e[0].close;for(let o=0;o<e.length;o+=1)a=o===0?e[o].close:e[o].close*s+a*(1-s),o>=t-1&&n.push({time:e[o].time,value:a});return n}function mh(e,t){let n=[],s=t*(t+1)/2;for(let a=t-1;a<e.length;a+=1){let o=0;for(let i=0;i<t;i+=1)o+=e[a-i].close*(t-i);n.push({time:e[a].time,value:o/s})}return n}function fh(e,t=20,n=2){let s=ti(e,t),a=[],o=[];for(let i=t-1;i<e.length;i+=1){let r=e.slice(i-t+1,i+1),l=s[i-(t-1)].value,c=r.reduce((d,p)=>d+Math.pow(p.close-l,2),0)/t,u=Math.sqrt(c);a.push({time:e[i].time,value:l+u*n}),o.push({time:e[i].time,value:l-u*n})}return{upper:a,lower:o}}function hh(e){let t=[],n=0,s=0;for(let a=0;a<e.length;a+=1){let o=(e[a].high+e[a].low+e[a].close)/3;n+=o*(e[a].volume||0),s+=e[a].volume||0,s>0&&t.push({time:e[a].time,value:n/s})}return t}function gh(e,t=14){let n=[];if(e.length<=t)return n;let s=0,a=0;for(let r=1;r<=t;r+=1){let l=e[r].close-e[r-1].close;s+=l>0?l:0,a+=l<0?-l:0}let o=s/t,i=a/t;for(let r=t+1;r<e.length;r+=1){let l=e[r].close-e[r-1].close;o=(o*(t-1)+(l>0?l:0))/t,i=(i*(t-1)+(l<0?-l:0))/t;let c=i>0?o/i:100;n.push({time:e[r].time,value:100-100/(1+c)})}return n}function bi(e,t=14){let n=[];for(let o=0;o<e.length;o+=1){let i=o>0?e[o-1].close:e[o].close;n.push(Math.max(e[o].high-e[o].low,Math.abs(e[o].high-i),Math.abs(e[o].low-i)))}let s=[],a=n.slice(0,t).reduce((o,i)=>o+i,0)/Math.max(1,t);for(let o=t;o<e.length;o+=1)a=(a*(t-1)+n[o])/t,s.push({time:e[o].time,value:a});return s}function bh(e,t=14,n=3){let s=[];for(let o=t-1;o<e.length;o+=1){let i=e.slice(o-t+1,o+1),r=Math.max(...i.map(u=>u.high)),l=Math.min(...i.map(u=>u.low)),c=r!==l?(e[o].close-l)/(r-l)*100:50;s.push({time:e[o].time,value:c})}let a=[];for(let o=n-1;o<s.length;o+=1){let i=s.slice(o-n+1,o+1).reduce((r,l)=>r+l.value,0)/n;a.push({time:s[o].time,value:i})}return{k:s,d:a}}function vh(e,t=12,n=26,s=9){let a=Ds(e,t),o=Ds(e,n),i=new Map(o.map(d=>[d.time,d.value])),r=a.filter(d=>i.has(d.time)).map(d=>({time:d.time,value:d.value-i.get(d.time)})),l=[];if(r.length){let d=2/(s+1),p=r[0].value;for(let m=0;m<r.length;m+=1)p=m===0?r[m].value:r[m].value*d+p*(1-d),m>=s-1&&l.push({time:r[m].time,value:p})}let c=new Map(l.map(d=>[d.time,d.value])),u=r.filter(d=>c.has(d.time)).map(d=>({time:d.time,value:d.value-c.get(d.time)}));return{line:r,signal:l,hist:u}}function Ec(e,t=9,n=26,s=52){let a=d=>{let p=[];for(let m=d-1;m<e.length;m+=1){let f=e.slice(m-d+1,m+1);p.push({time:e[m].time,value:(Math.max(...f.map(g=>g.high))+Math.min(...f.map(g=>g.low)))/2})}return p},o=a(t),i=a(n),r=new Map(i.map(d=>[d.time,d.value])),l=o.filter(d=>r.has(d.time)).map(d=>({time:d.time,value:(d.value+r.get(d.time))/2})),c=a(s),u=e.map(d=>({time:d.time,value:d.close}));return{tenkan:o,kijun:i,senkouA:l,senkouB:c,chikou:u}}function yh(e,t=20){let n=[],s=[],a=[];for(let o=t-1;o<e.length;o+=1){let i=e.slice(o-t+1,o+1),r=Math.max(...i.map(c=>c.high)),l=Math.min(...i.map(c=>c.low));n.push({time:e[o].time,value:r}),s.push({time:e[o].time,value:l}),a.push({time:e[o].time,value:(r+l)/2})}return{upper:n,lower:s,mid:a}}function wh(e,t=20,n=2){let s=Ds(e,t),a=bi(e,t),o=new Map(a.map(l=>[l.time,l.value])),i=[],r=[];return s.forEach(l=>{if(o.has(l.time)){let c=o.get(l.time)*n;i.push({time:l.time,value:l.value+c}),r.push({time:l.time,value:l.value-c})}}),{upper:i,lower:r,mid:s}}function xh(e){let t=[],n=[],s=0,a=0;for(let o=0;o<e.length;o+=1){if(o>0){let l=e[o-1];e[o].close>l.close&&(s+=e[o].volume||0),e[o].close<l.close&&(s-=e[o].volume||0)}let i=e[o].high-e[o].low||1,r=(e[o].close-e[o].low-(e[o].high-e[o].close))/i;a+=r*(e[o].volume||0),t.push({time:e[o].time,value:s}),n.push({time:e[o].time,value:a})}return{obv:t,adline:n}}function kh(e,t=14){if(e.length<t+2)return{adx:[],plusDi:[],minusDi:[]};let n=[],s=[],a=[];for(let p=1;p<e.length;p+=1){let m=e[p].high-e[p-1].high,f=e[p-1].low-e[p].low;s.push(m>f&&m>0?m:0),a.push(f>m&&f>0?f:0),n.push(Math.max(e[p].high-e[p].low,Math.abs(e[p].high-e[p-1].close),Math.abs(e[p].low-e[p-1].close)))}let o=n.slice(0,t).reduce((p,m)=>p+m,0),i=s.slice(0,t).reduce((p,m)=>p+m,0),r=a.slice(0,t).reduce((p,m)=>p+m,0),l=[],c=[],u=[];for(let p=t;p<n.length;p+=1){o=o-o/t+n[p],i=i-i/t+s[p],r=r-r/t+a[p];let m=o>0?100*i/o:0,f=o>0?100*r/o:0,g=m+f>0?100*Math.abs(m-f)/(m+f):0,v=e[p+1].time;l.push({time:v,value:m}),c.push({time:v,value:f}),u.push({time:v,value:g})}let d=[];if(u.length>=t){let p=u.slice(0,t).reduce((m,f)=>m+f.value,0)/t;for(let m=t;m<u.length;m+=1)p=(p*(t-1)+u[m].value)/t,d.push({time:u[m].time,value:p})}return{adx:d,plusDi:l,minusDi:c}}function $h(e,t=14){let n=[],s=[];for(let a=t-1;a<e.length;a+=1){let o=e.slice(a-t+1,a+1),i=0,r=0;for(let u=1;u<o.length;u+=1)o[u].high>=o[i].high&&(i=u),o[u].low<=o[r].low&&(r=u);let l=t-1-i,c=t-1-r;n.push({time:e[a].time,value:(t-l)/t*100}),s.push({time:e[a].time,value:(t-c)/t*100})}return{up:n,down:s}}function Sh(e,t=14){let n=[],s=[];if(e.length<t+2)return{plus:n,minus:s};for(let a=t;a<e.length;a+=1){let o=0,i=0,r=0;for(let l=a-t+1;l<=a;l+=1){let c=e[l-1],u=e[l];o+=Math.max(u.high-u.low,Math.abs(u.high-c.close),Math.abs(u.low-c.close)),i+=Math.abs(u.high-c.low),r+=Math.abs(u.low-c.high)}n.push({time:e[a].time,value:o>0?i/o:0}),s.push({time:e[a].time,value:o>0?r/o:0})}return{plus:n,minus:s}}function Th(e,t=10,n=3){let s=bi(e,t),a=new Map(s.map(c=>[c.time,c.value])),o=[],i=0,r=0,l=!0;return e.forEach((c,u)=>{if(u===0||!a.has(c.time))return;let d=(c.high+c.low)/2,p=a.get(c.time),m=d+n*p,f=d-n*p;u>1&&(m>i&&e[u-1].close<=i&&(m=i),f<r&&e[u-1].close>=r&&(f=r));let g=c.close>m?!0:c.close<f?!1:l,v=g?f:m;o.push({time:c.time,value:v,trendUp:g?1:0}),i=m,r=f,l=g}),o}function Ch(e,t=14){let n=[];if(e.length<=t)return n;let s=e.map((a,o)=>{let i=(a.high+a.low+a.close)/3,r=o>0?(e[o-1].high+e[o-1].low+e[o-1].close)/3:i,l=i*(a.volume||0);return{time:a.time,pos:i>=r?l:0,neg:i<r?l:0}});for(let a=t;a<s.length;a+=1){let o=s.slice(a-t+1,a+1),i=o.reduce((c,u)=>c+u.pos,0),r=o.reduce((c,u)=>c+u.neg,0),l=r>0?i/r:100;n.push({time:s[a].time,value:100-100/(1+l)})}return n}function Ph(e,t=14){let n=[];for(let s=t-1;s<e.length;s+=1){let a=e.slice(s-t+1,s+1),o=Math.max(...a.map(l=>l.high)),i=Math.min(...a.map(l=>l.low)),r=o!==i?(o-e[s].close)/(o-i)*-100:-50;n.push({time:e[s].time,value:r})}return n}function Mh(e,t=20){let n=[],s=e.map(a=>({time:a.time,value:(a.high+a.low+a.close)/3}));for(let a=t-1;a<s.length;a+=1){let o=s.slice(a-t+1,a+1),i=o.reduce((c,u)=>c+u.value,0)/t,r=o.reduce((c,u)=>c+Math.abs(u.value-i),0)/t,l=r>0?(s[a].value-i)/(.015*r):0;n.push({time:s[a].time,value:l})}return n}function Lh(e){if(e.length<30)return[];let t=[],n=[];for(let o=1;o<e.length;o+=1){let i=e[o-1].close,r=Math.min(e[o].low,i),l=Math.max(e[o].high,i);t.push({time:e[o].time,value:e[o].close-r}),n.push({time:e[o].time,value:l-r})}let s=(o,i,r)=>o.slice(i-r+1,i+1).reduce((l,c)=>l+c.value,0),a=[];for(let o=27;o<t.length;o+=1){let i=s(t,o,7)/Math.max(1e-9,s(n,o,7)),r=s(t,o,14)/Math.max(1e-9,s(n,o,14)),l=s(t,o,28)/Math.max(1e-9,s(n,o,28));a.push({time:t[o].time,value:100*(4*i+2*r+l)/7})}return a}function Ah(e,t=20){let n=[],s=e.map(a=>{let o=a.high-a.low||1,i=(a.close-a.low-(a.high-a.close))/o;return{time:a.time,value:i*(a.volume||0),volume:a.volume||0}});for(let a=t-1;a<s.length;a+=1){let o=s.slice(a-t+1,a+1),i=o.reduce((l,c)=>l+c.value,0),r=o.reduce((l,c)=>l+c.volume,0);n.push({time:s[a].time,value:r>0?i/r:0})}return n}function Eh(e){return(Array.isArray(e)?e:[]).map(t=>({time:Number(t[0]),low:Number(t[1]),high:Number(t[2]),open:Number(t[3]),close:Number(t[4]),volume:Number(t[5])})).filter(t=>Number.isFinite(t.time)&&[t.open,t.high,t.low,t.close].every(Number.isFinite))}function ni(e,t){let n=new Map;for(let s of e)n.set(s.time,s);for(let s of t)n.set(s.time,s);return Array.from(n.values()).sort((s,a)=>s.time-a.time)}async function si(e,t,n){let s=[],a=Math.floor(Date.now()/1e3),o=!1;for(let i=0;i<n;i+=1){let r=a-t*300,l=`https://api.exchange.coinbase.com/products/${e}/candles?granularity=${t}&start=${new Date(r*1e3).toISOString()}&end=${new Date(a*1e3).toISOString()}`,c;try{c=await Lt(l,{timeoutMs:1e4})}catch{break}let u=Eh(c);if(!u.length){o=!0;break}s.push(...u),a=r,i<n-1&&await bf(gf)}return{candles:ni(s,[]),reachedStart:o}}async function Nh(e,t,n){if(!e||!Number.isFinite(t)||!Number.isFinite(n)||n<=t)return[];try{let s=`https://api.coingecko.com/api/v3/coins/${e}/market_chart/range?vs_currency=usd&from=${t}&to=${n}`,a=await Lt(s,{timeoutMs:15e3});return(Array.isArray(a==null?void 0:a.prices)?a.prices:[]).map(([i,r])=>({time:Math.floor(Number(i)/1e3/86400)*86400,open:Number(r),high:Number(r),low:Number(r),close:Number(r),volume:0})).filter(i=>Number.isFinite(i.time)&&Number.isFinite(i.close)&&i.close>0).sort((i,r)=>i.time-r.time)}catch{return[]}}async function Rh(e,t,n){var d;let s=Pc(n),a=s===86400,o=`${hf}${e.id}:${s}`,i=ge(Q(o));if((d=i==null?void 0:i.candles)!=null&&d.length&&i.reachedStart){let p=await si(t,s,1),m=ni(i.candles,p.candles);return Z(o,JSON.stringify({candles:m,reachedStart:!0,source:i.source,cachedAt:Date.now()})),{candles:m,source:i.source}}let l=await si(t,s,a?Vl:Gl),c=l.candles,u=c.length?`Coinbase (${new Date(c[0].time*1e3).getUTCFullYear()}\u2013present, ${c.length} bars)`:"Coinbase";if(a&&l.reachedStart&&e.coingeckoId&&c.length){let p=c[0].time,m=await Nh(e.coingeckoId,0,p);m.length&&(c=ni(m,c),u=`CoinGecko (${new Date(c[0].time*1e3).getUTCFullYear()}+) + Coinbase (${new Date(p*1e3).getUTCFullYear()}\u2013present)`)}else!a&&!l.reachedStart&&(u=`Coinbase (last ${c.length} bars \u2014 full inception history is daily/weekly/monthly only)`);return c.length&&Z(o,JSON.stringify({candles:c,reachedStart:l.reachedStart,source:u,cachedAt:Date.now()})),{candles:c,source:u}}var Go=new Map;async function Nc(e,t){let n=`${e.id}:${t}`,s=Es.get(n);if(s&&Date.now()-s.ts<6e4&&Array.isArray(s.data)&&s.data.length)return s.data;let a=Go.get(n);if(a)return a;let o=(async()=>{let i=[],r="",l=Sc(e.ticker);if(l)try{let c=await Rh(e,l,t);i=c.candles,r=c.source}catch{i=[]}if(!Array.isArray(i)||!i.length){let c=Ac(t,Lc());return Es.set(n,{ts:Date.now(),data:c,sourceLabel:""}),c}return Es.set(n,{ts:Date.now(),data:i,sourceLabel:r}),i})();Go.set(n,o);try{return await o}finally{Go.delete(n)}}async function _h(){var d,p,m,f,g,v,h,b;let e=_a(),t=await Nc(e,M.interval),s=((d=Es.get(`${e.id}:${M.interval}`))==null?void 0:d.sourceLabel)||String(((p=M.stats)==null?void 0:p.source)||"Coinbase + XRPL live"),a="pair",o=Mc(),i=String((o==null?void 0:o.symbol)||"").toUpperCase(),r=o?Ve(o):`${e.symbol||"XRP"}|`;if(o&&i&&i!=="XRP"){let x=await rh(o,M.interval);(m=x==null?void 0:x.candles)!=null&&m.length&&(t=x.candles,s=x.source,a=x.mode)}let l=String(e.symbol||"XRP").toUpperCase()==="XRP",c=Number((l?(f=M.stats)==null?void 0:f.xrplSpot:null)??((g=M.stats)==null?void 0:g.price)??0);if(a==="pair"&&Number.isFinite(c)&&c>0&&t.length){let x=Math.max(60,Cc(M.interval)),k=Math.floor(Date.now()/1e3),T=Math.floor(k/x)*x,S=t[t.length-1];S.time===T?(S.high=Math.max(S.high,c),S.low=Math.min(S.low,c),S.close=c):S.time<T&&t.push({time:T,open:S.close,high:Math.max(S.close,c),low:Math.min(S.close,c),close:c,volume:0})}let u=Number((o==null?void 0:o.price)||0);if(a==="pair"&&o&&i&&i!=="XRP"&&Number.isFinite(u)&&u>0&&t.length){let x=Number((l?(v=M.stats)==null?void 0:v.xrplSpot:null)??((h=M.stats)==null?void 0:h.price)??((b=t[t.length-1])==null?void 0:b.close)??0);if(Number.isFinite(x)&&x>0){let k=u/x;Number.isFinite(k)&&k>0&&(t=t.map(T=>({...T,open:T.open*k,high:T.high*k,low:T.low*k,close:T.close*k})),s="Coinbase pair + token spot proxy",a="token-proxy")}}return t.length||(t=Ac(M.interval,Lc()),s=o&&i!=="XRP"?"Synthetic fallback (token-focused)":"Synthetic fallback",a="fallback"),o&&i!=="XRP"&&(a==="pair"||a==="fallback")?Wo!==r&&(Wo=r,he(`No market data found for ${o.symbol} yet \u2014 showing ${e.symbol||"XRP"} for reference.`)):r&&(Wo=""),M.chartType==="heikin_ashi"&&(t=ei(t)),ch(t,{mode:a,source:s,tokenKey:r||"XRP|"}),t}function Rl(e){if(!Array.isArray(e))return[];let t=e.map(s=>({time:Number(s.time),open:Number(s.open),high:Number(s.high),low:Number(s.low),close:Number(s.close),volume:Number(s.volume||0)})).filter(s=>Number.isFinite(s.time)&&Number.isFinite(s.open)&&Number.isFinite(s.high)&&Number.isFinite(s.low)&&Number.isFinite(s.close)&&s.time>0).sort((s,a)=>s.time-a.time),n=[];for(let s=0;s<t.length;s+=1){let a=t[s],o=n[n.length-1];o&&o.time===a.time?n[n.length-1]=a:n.push(a)}return n}function Dh(e,t,n){var i;let s=Number(((i=e==null?void 0:e[e.length-1])==null?void 0:i.close)||0);if(!Number.isFinite(s)||s<=0)return 6;let o=Math.max(1e-12,Math.abs(Number(n)-Number(t)))/Math.max(1e-12,Math.abs(s));return s>=1e3?o<.01?4:2:s>=1?o<.01?6:4:s>=.01?o<.03?8:6:8}function Ih(){if(ee.resizeObserver)try{ee.resizeObserver.disconnect()}catch{}ee.chart&&(ee.chart.remove(),ee={chart:null,volumeSeries:null,activeSeries:null,compareSeries:null,indicatorSeries:[],indicatorPriceLines:[],priceLines:[],resizeObserver:null,chartType:"",configKey:"",legendEl:null,renderLegend:null,ichimokuData:null,indicatorLegendItems:[],alertPriceLines:[]})}function _l(e,t){var u;let{addOverlay:n,addOsc:s,addOscHist:a,addPriceLevel:o}=t,i=(d,p)=>{var f,g;let m=Number((g=(f=M.indicatorSettings)==null?void 0:f[d])==null?void 0:g.length);return Number.isFinite(m)&&m>1?Math.min(500,Math.max(2,m)):p},r=(d,p,m)=>{var v,h;let f=(h=(v=M.indicatorSettings)==null?void 0:v[d])==null?void 0:h[p];if(f==null||f==="")return m;let g=(pi[d]||[]).find(b=>b.id===p);if((g==null?void 0:g.type)==="number"){let b=Number(f);return Number.isFinite(b)&&b>1?Math.min(500,Math.max(2,b)):m}return f},l=M.indicators;if(l.sma20&&n(ti(e,i("sma20",20)),r("sma20","color","#f1c40f"),1.2,!1,"SMA"),l.ema20&&n(Ds(e,i("ema20",20)),r("ema20","color","#ffb86c"),1.2,!1,"EMA"),l.wma20&&n(mh(e,i("wma20",20)),r("wma20","color","#bd93f9"),1.2,!1,"WMA"),l.vwap&&n(hh(e),r("vwap","color","#80ffea"),1.2,!1,"VWAP"),l.bb20){let d=r("bb20","color","#ff79c6"),p=fh(e,i("bb20",20),2);n(p.upper,d,1,!0,"BB Upper"),n(p.lower,d,1,!0,"BB Lower")}if(l.ichimoku){let d=Ec(e,r("ichimoku","tenkanLen",9),r("ichimoku","kijunLen",26),r("ichimoku","senkouBLen",52));n(d.tenkan,r("ichimoku","tenkanColor","#ffde59"),1.2,!1,"Tenkan"),n(d.kijun,r("ichimoku","kijunColor","#6ecbff"),1.2,!1,"Kijun"),n(d.senkouA,"rgba(70,255,160,0.8)",1,!0,"Senkou A"),n(d.senkouB,"rgba(255,120,120,0.8)",1,!0,"Senkou B"),n(d.chikou,"rgba(220,220,255,0.6)",.9,!0,"Chikou")}if(l.donchian){let d=r("donchian","color","#9cfb8c"),p=yh(e,i("donchian",20));n(p.upper,d,1,!0,"Donchian Upper"),n(p.lower,d,1,!0,"Donchian Lower"),n(p.mid,"rgba(156,251,140,0.6)",1.2,!1,"Donchian Mid")}if(l.keltner){let d=r("keltner","color","#7ee7ff"),p=wh(e,i("keltner",20),2);n(p.upper,d,1,!0,"Keltner Upper"),n(p.lower,d,1,!0,"Keltner Lower"),n(p.mid,"rgba(126,231,255,0.66)",1.2,!1,"Keltner Mid")}if(l.pivots&&e.length>=2){let d=e[e.length-2],p=(d.high+d.low+d.close)/3,m=2*p-d.low,f=2*p-d.high,g=p+(d.high-d.low),v=p-(d.high-d.low);o(p,"#f6f6f6","P"),o(m,"#61ffb0","R1"),o(f,"#ff8f8f","S1"),o(g,"rgba(97,255,176,0.6)","R2"),o(v,"rgba(255,143,143,0.6)","S2")}if(l.supertrend||l.sar||l.elderRay){let d=Ds(e,14);if(l.supertrend&&n(Th(e,10,3),r("supertrend","color","#8bffde"),1.3,!1,"Supertrend"),l.sar&&n(d.map(p=>({time:p.time,value:p.value*.998})),r("sar","color","#ffaf7a"),1,!0,"SAR"),l.elderRay){let p=new Map(d.map(g=>[g.time,g.value])),m=e.filter(g=>p.has(g.time)).map(g=>({time:g.time,value:g.high-p.get(g.time)})),f=e.filter(g=>p.has(g.time)).map(g=>({time:g.time,value:g.low-p.get(g.time)}));s(m,r("elderRay","bullColor","#5fff9d"),"Elder Bull"),s(f,r("elderRay","bearColor","#ff9d9d"),"Elder Bear")}}if(l.rsi&&s(gh(e,i("rsi",14)),r("rsi","color","#a6ff4d"),"RSI"),l.atr&&s(bi(e,i("atr",14)),r("atr","color","#ffb86c"),"ATR"),l.stdev){let d=ti(e,20),p=new Map(d.map(f=>[f.time,f.value])),m=e.filter(f=>p.has(f.time)).map(f=>({time:f.time,value:Math.abs(f.close-p.get(f.time))}));s(m,r("stdev","color","#b2a3ff"),"StdDev")}if(l.stoch){let d=bh(e,i("stoch",14),3);s(d.k,r("stoch","kColor","#9ee8ff"),"%K"),s(d.d,r("stoch","dColor","#ffd86b"),"%D")}if(l.macd){let d=vh(e,r("macd","fastLen",12),r("macd","slowLen",26),r("macd","signalLen",9));s(d.line,r("macd","lineColor","#8fd9ff"),"MACD"),s(d.signal,r("macd","signalColor","#ffcf8e"),"Signal"),(u=d.hist)!=null&&u.length&&a(d.hist)}let c=xh(e);if(l.obv&&s(c.obv,r("obv","color","#8cf9ff"),"OBV"),l.adline&&s(c.adline,r("adline","color","#ffb7ff"),"A/D"),l.cmf&&s(Ah(e,i("cmf",20)),r("cmf","color","#f8ff87"),"CMF"),l.williamsr&&s(Ph(e,i("williamsr",14)),r("williamsr","color","#ff9adf"),"Williams %R"),l.cci&&s(Mh(e,i("cci",20)),r("cci","color","#b8ff8e"),"CCI"),l.mfi&&s(Ch(e,i("mfi",14)),r("mfi","color","#7bffd2"),"MFI"),l.uo&&s(Lh(e),r("uo","color","#ffd36f"),"UO"),l.adx){let d=kh(e,i("adx",14));s(d.adx,r("adx","adxColor","#9fd8ff"),"ADX"),s(d.plusDi,r("adx","plusColor","#73ffc0"),"+DI"),s(d.minusDi,r("adx","minusColor","#ff9797"),"-DI")}if(l.aroon){let d=$h(e,i("aroon",14));s(d.up,r("aroon","upColor","#6cffb0"),"Aroon Up"),s(d.down,r("aroon","downColor","#ff8f8f"),"Aroon Down")}if(l.vortex){let d=Sh(e,i("vortex",14));s(d.plus.map(p=>({time:p.time,value:p.value*100})),r("vortex","plusColor","#d6a8ff"),"VI+"),s(d.minus.map(p=>({time:p.time,value:p.value*100})),r("vortex","minusColor","#ffb0f3"),"VI-")}}function Fh(e){let t=e.querySelector(":scope > svg.xpd-ichimoku-cloud-svg");return t||(t=document.createElementNS("http://www.w3.org/2000/svg","svg"),t.setAttribute("class","xpd-ichimoku-cloud-svg"),e.appendChild(t)),t}function Oh(e){var t;(t=e==null?void 0:e.querySelector(":scope > svg.xpd-ichimoku-cloud-svg"))==null||t.remove()}function Rc(e,t,n,s,a){var v;if(!e||!t||!n)return;let o=n.clientWidth||0,i=n.clientHeight||0;if(!o||!i||!(s!=null&&s.length)||!(a!=null&&a.length))return;let r=Fh(n);r.setAttribute("width",o),r.setAttribute("height",i),r.setAttribute("viewBox",`0 0 ${o} ${i}`);let l=((v=M.indicatorSettings)==null?void 0:v.ichimoku)||{},c=l.bullColor||"#46ffa0",u=l.bearColor||"#ff7878",d=new Map(a.map(h=>[h.time,h.value])),p=e.timeScale(),m=[];for(let h of s){let b=d.get(h.time);if(b==null)continue;let x=p.timeToCoordinate(h.time),k=t.priceToCoordinate(h.value),T=t.priceToCoordinate(b);x==null||k==null||T==null||m.push({x,ya:k,yb:T,bullish:h.value>=b})}let f="",g=0;for(let h=1;h<=m.length;h+=1){if(!(h===m.length||m[h].bullish!==m[g].bullish))continue;let x=m.slice(g,h);if(x.length>=2){let k=x.map($=>`${$.x.toFixed(1)},${$.ya.toFixed(1)}`).join(" "),T=x.slice().reverse().map($=>`${$.x.toFixed(1)},${$.yb.toFixed(1)}`).join(" "),S=x[0].bullish?c:u;f+=`<polygon points="${k} ${T}" fill="${y(S)}" opacity="0.22" />`}g=h}r.innerHTML=f}function Dl(e,t,n,s){var i;if(!M.indicators.ichimoku){Oh(s),ee.ichimokuData=null;return}let a=((i=M.indicatorSettings)==null?void 0:i.ichimoku)||{},o=Ec(e,Number(a.tenkanLen)||9,Number(a.kijunLen)||26,Number(a.senkouBLen)||52);ee.ichimokuData={senkouA:o.senkouA,senkouB:o.senkouB},Rc(t,n,s,o.senkouA,o.senkouB)}function ai(){let e=ee.ichimokuData,t=document.getElementById("xpd-tv-widget");e&&ee.chart&&ee.activeSeries&&t&&Rc(ee.chart,ee.activeSeries,t,e.senkouA,e.senkouB)}async function Bh(){var n,s,a,o;let e=++Rn,t=document.getElementById("xpd-tv-widget");if(t){ee.chart||(t.innerHTML='<div class="xpd-loading">Loading full price history\u2026</div>');try{M.threeEnabled?uh():Os();let i=await _h(),r=Rl(i);if(e!==Rn)return;if(!r.length)throw new Error("No chart bars returned for selected pair/timeframe.");Hh(r);let l=JSON.stringify({pair:M.pair,interval:M.interval,chartType:M.chartType,comparePair:M.comparePair,indicators:M.indicators,indicatorSettings:M.indicatorSettings,threeEnabled:M.threeEnabled});if(!M.comparePair&&!(M.drawings||[]).length&&ee.chart&&ee.configKey===l){let B=M.chartType==="heikin_ashi"?ei(r):r;M.chartType==="line"||M.chartType==="area"?ee.activeSeries.setData(B.map(Y=>({time:Y.time,value:Y.close}))):ee.activeSeries.setData(B),ee.volumeSeries.setData(r.map(Y=>({time:Y.time,value:Y.volume||0,color:Y.close>=Y.open?"rgba(38,166,154,0.5)":"rgba(239,83,80,0.5)"})));let q=0,J=0,ue=[];_l(r,{addOverlay:(Y,Ce,Ye,$e,Ct)=>{let jt=ee.indicatorSeries[q++];Y!=null&&Y.length&&(jt==null||jt.setData(Y),Ct&&jt&&ue.push({label:Ct,color:Ce,series:jt,points:Y}))},addOsc:(Y,Ce,Ye)=>{let $e=ee.indicatorSeries[q++];Y!=null&&Y.length&&($e==null||$e.setData(Y),Ye&&$e&&ue.push({label:Ye,color:Ce,series:$e,points:Y}))},addOscHist:Y=>{let Ce=ee.indicatorSeries[q++];Y!=null&&Y.length&&(Ce==null||Ce.setData(Y.map(Ye=>({time:Ye.time,value:Ye.value,color:Ye.value>=0?"rgba(99,255,157,0.45)":"rgba(255,126,126,0.45)"}))))},addPriceLevel:Y=>{let Ce=ee.indicatorPriceLines[J++];Number.isFinite(Y)&&(Ce==null||Ce.applyOptions({price:Y}))}}),ee.indicatorLegendItems=ue,Dl(r,ee.chart,ee.activeSeries,t),Il(ee.activeSeries);let Ie=r[r.length-1];(n=ee.renderLegend)==null||n.call(ee,Ie.open,Ie.high,Ie.low,Ie.close,Ie.volume);return}if(!await dh())throw new Error("Chart library failed to load.");if(e!==Rn)return;let u=document.getElementById("xpd-tv-widget");if(!u||e!==Rn)return;let d=null;try{d=((s=ee.chart)==null?void 0:s.timeScale().getVisibleLogicalRange())||null}catch{}Ih(),u.innerHTML="";let p=window.LightweightCharts,m=Math.max(320,u.clientWidth||((a=u.parentElement)==null?void 0:a.clientWidth)||320),f=Math.max(360,u.clientHeight||460),g=r.map(B=>B.low),v=r.map(B=>B.high),h=Dh(r,Math.min(...g),Math.max(...v)),b={type:"price",precision:h,minMove:Math.pow(10,-h)},x="#26a69a",k="#ef5350",T=p.createChart(u,{width:m,height:f,layout:{background:{type:p.ColorType.Solid,color:"#131722"},textColor:"#d1d4dc"},grid:{vertLines:{color:"#242832"},horzLines:{color:"#242832"}},rightPriceScale:{borderColor:"rgba(197,203,206,0.3)"},leftPriceScale:{visible:!1,borderColor:"rgba(197,203,206,0.3)"},timeScale:{borderColor:"rgba(197,203,206,0.3)",timeVisible:!0,secondsVisible:!1},crosshair:{mode:p.CrosshairMode.Normal},handleScroll:!0,handleScale:!0}),S=M.chartType==="heikin_ashi"?ei(r):r,$;if(M.chartType==="line")$=T.addLineSeries({color:"#2962ff",lineWidth:2,priceFormat:b}),$.setData(S.map(B=>({time:B.time,value:B.close})));else if(M.chartType==="area")$=T.addAreaSeries({lineColor:"#2962ff",topColor:"rgba(41,98,255,0.36)",bottomColor:"rgba(41,98,255,0.04)",lineWidth:2,priceFormat:b}),$.setData(S.map(B=>({time:B.time,value:B.close})));else if(M.chartType==="bars")$=T.addBarSeries({upColor:x,downColor:k,priceFormat:b}),$.setData(S);else{let B=M.chartType==="hollow_candles";$=T.addCandlestickSeries({upColor:B?"rgba(0,0,0,0)":x,downColor:k,borderUpColor:x,borderDownColor:k,wickUpColor:x,wickDownColor:k,borderVisible:!0,priceFormat:b}),$.setData(S)}let E=T.addHistogramSeries({priceFormat:{type:"volume"},priceScaleId:"vol"});T.priceScale("vol").applyOptions({scaleMargins:{top:.85,bottom:0}}),E.setData(r.map(B=>({time:B.time,value:B.volume||0,color:B.close>=B.open?"rgba(38,166,154,0.5)":"rgba(239,83,80,0.5)"})));let C=document.createElement("div");C.className="xpd-chart-legend",u.appendChild(C);let P=B=>Number.isFinite(B)?B.toFixed(h):"\u2014",R=(B,q,J,ue,ke,Me)=>{let We=ue>=B,De=(Me||[]).map(Ie=>`<span style="color:${y(Ie.color)}">${y(Ie.label)} <b>${P(Ie.value)}</b></span>`).join("");C.innerHTML=`
        <span>O <b>${P(B)}</b></span>
        <span>H <b>${P(q)}</b></span>
        <span>L <b>${P(J)}</b></span>
        <span class="${We?"xpd-legend-up":"xpd-legend-down"}">C <b>${P(ue)}</b></span>
        ${ke!=null?`<span>Vol <b>${qe(ke)}</b></span>`:""}
        ${De}
      `},O=S[S.length-1],D=(o=r[r.length-1])==null?void 0:o.volume,I=()=>{if(!O)return;let B=O.open??O.value,q=O.high??O.value,J=O.low??O.value,ue=O.close??O.value,ke=(ee.indicatorLegendItems||[]).map(Me=>{var We,De;return{label:Me.label,color:Me.color,value:(De=(We=Me.points)==null?void 0:We[Me.points.length-1])==null?void 0:De.value}}).filter(Me=>Number.isFinite(Me.value));R(B,q,J,ue,D,ke)};I(),T.subscribeCrosshairMove(B=>{var Ie,Y;if(!B.time){I();return}let q=(Ie=B.seriesData)==null?void 0:Ie.get($);if(!q){I();return}let J=(Y=B.seriesData)==null?void 0:Y.get(E),ue=q.open??q.value,ke=q.high??q.value,Me=q.low??q.value,We=q.close??q.value,De=(ee.indicatorLegendItems||[]).map(Ce=>{var Ye,$e;return{label:Ce.label,color:Ce.color,value:($e=(Ye=B.seriesData)==null?void 0:Ye.get(Ce.series))==null?void 0:$e.value}}).filter(Ce=>Number.isFinite(Ce.value));R(ue,ke,Me,We,J==null?void 0:J.value,De)});let F=!1,H=()=>{F||(F=!0,T.priceScale("osc").applyOptions({scaleMargins:{top:.65,bottom:.18}}))},N=[],j=[],se=[];_l(r,{addOverlay:(B,q,J=1.2,ue=!1,ke="")=>{if(!(B!=null&&B.length))return;let Me=T.addLineSeries({color:q,lineWidth:J,lineStyle:ue?p.LineStyle.Dashed:p.LineStyle.Solid,priceLineVisible:!1,lastValueVisible:!1});Me.setData(B),N.push(Me),ke&&se.push({label:ke,color:q,series:Me,points:B})},addOsc:(B,q,J="")=>{if(!(B!=null&&B.length))return;H();let ue=T.addLineSeries({color:q,lineWidth:1.2,priceScaleId:"osc",title:J,priceLineVisible:!1,lastValueVisible:!1});ue.setData(B),N.push(ue),J&&se.push({label:J,color:q,series:ue,points:B})},addOscHist:B=>{if(!(B!=null&&B.length))return;H();let q=T.addHistogramSeries({priceScaleId:"osc",priceLineVisible:!1,lastValueVisible:!1});q.setData(B.map(J=>({time:J.time,value:J.value,color:J.value>=0?"rgba(99,255,157,0.45)":"rgba(255,126,126,0.45)"}))),N.push(q)},addPriceLevel:(B,q,J="")=>{Number.isFinite(B)&&j.push($.createPriceLine({price:B,color:q,lineWidth:1,lineStyle:p.LineStyle.Dashed,axisLabelVisible:!0,title:J}))}}),Dl(r,T,$,u),T.timeScale().subscribeVisibleLogicalRangeChange(ai);let de=null;if(M.comparePair){let B=Fn.find(q=>q.id===M.comparePair);if(B){let q=Rl(await Nc(B,M.interval));if(e===Rn&&q.length){let J=q[0].close||1;de=T.addLineSeries({color:"#ffd166",lineWidth:1.4,priceScaleId:"left",priceLineVisible:!1,lastValueVisible:!0,priceFormat:{type:"custom",formatter:ue=>`${ue>=0?"+":""}${ue.toFixed(2)}%`,minMove:.01}}),T.priceScale("left").applyOptions({visible:!0,borderColor:"rgba(255,209,102,0.35)"}),de.setData(q.map(ue=>({time:ue.time,value:(ue.close/J-1)*100})))}}}else T.priceScale("left").applyOptions({visible:!1});if(e!==Rn){try{T.remove()}catch{}return}let le=(M.drawings||[]).filter(B=>Number.isFinite(B==null?void 0:B.price)).map(B=>$.createPriceLine({price:B.price,color:"#78e5ff",lineWidth:2,lineStyle:p.LineStyle.Dashed,axisLabelVisible:!0,title:"Line"}));if(T.subscribeClick(B=>{if(M.drawingTool!=="hline"||!B.point)return;let q=$.coordinateToPrice(B.point.y);Number.isFinite(q)&&(M.drawings=[...M.drawings||[],{price:q}].slice(-50),le.push($.createPriceLine({price:q,color:"#78e5ff",lineWidth:2,lineStyle:p.LineStyle.Dashed,axisLabelVisible:!0,title:"Line"})))}),d&&Number.isFinite(d.from)&&Number.isFinite(d.to))try{T.timeScale().setVisibleLogicalRange(d)}catch{T.timeScale().fitContent()}else T.timeScale().fitContent();let Pe=new ResizeObserver(()=>{T.applyOptions({width:Math.max(320,u.clientWidth||320)}),ai()});Pe.observe(u),ee={chart:T,volumeSeries:E,activeSeries:$,compareSeries:de,indicatorSeries:N,indicatorPriceLines:j,priceLines:le,resizeObserver:Pe,chartType:M.chartType,configKey:l,legendEl:C,renderLegend:R,indicatorLegendItems:se,alertPriceLines:[]},Il($)}catch(i){if(e!==Rn)return;if(M.error=(i==null?void 0:i.message)||"Could not initialize chart widget.",ee.chart){he(M.error);return}let r=document.getElementById("xpd-tv-widget");r&&(r.innerHTML=`<div class="xpd-error">${y(M.error)}</div>`)}}}function _c(){let e=Q(Jo)==="1"?"0":"1";Z(Jo,e),U()}async function Dc(e){Fn.some(t=>t.id===e)&&(M.pair=e,await Fs(),At(),U())}async function Ic(e){M.interval=e,await Fs(),At(),U()}function Fc(e){M.chartType=e,At(),U()}async function Oc(){await Fs(),U()}function Bc(e,t){e in M.indicators&&(M.indicators[e]=!!t,t&&(M.selectedIndicator=e,M.selectedEducationTab="indicator"),At(),U())}function Xc(){M.indicatorMenuOpen=!M.indicatorMenuOpen,U()}function Hc(){M.moreMenuOpen=!M.moreMenuOpen,U()}function zc(e){M.indicatorQuery=String(e||""),M.indicatorMenuOpen||(M.indicatorMenuOpen=!0),U()}function jc(e){let t=String(e||"").trim();t in M.indicators&&(M.indicators[t]=!0,M.selectedIndicator=t,M.selectedEducationTab="indicator",At(),U())}function Wc(e){let t=String(e||"").trim();t in M.indicators&&(M.indicators[t]=!1,At(),U())}function Xh(e){var s,a;if(M.settingsOpenFor!==e)return"";let t=M.indicatorSettings[e]||{},n=pi[e]||[];return`
    <div class="xpd-indicator-settings" role="dialog" aria-label="${y(((s=Vt[e])==null?void 0:s.name)||e)} settings">
      <div class="xpd-indicator-settings-title">${y(((a=Vt[e])==null?void 0:a.name)||e)} settings</div>
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
    </div>`}function Uc(e){let t=String(e||"").trim();t in M.indicators&&(M.settingsOpenFor=M.settingsOpenFor===t?null:t,U())}function qc(){M.settingsOpenFor=null,U()}function Vc(e){let t=String(e||"").trim();if(!(t in M.indicators))return;let n=M.indicatorSettings[t]||{},s={...n};for(let a of pi[t]||[]){let o=document.getElementById(`xpd-ind-${a.id}-${t}`);o&&(a.type==="number"?s[a.id]=Math.max(2,Math.min(500,Number(o.value)||n[a.id]||a.default)):s[a.id]=o.value)}M.indicatorSettings[t]=s,M.settingsOpenFor=null,U()}function Gc(e){let t=String(e||"").trim();delete M.indicatorSettings[t],M.settingsOpenFor=null,U()}function Kc(){At(),zs(window.location.href),ne("Chart link copied.")}function Jc(){M.threeEnabled=!M.threeEnabled,Z(di,M.threeEnabled?"1":"0"),M.threeEnabled||Os(),U()}function Yc(e){let t=!!e;M.threeEnabled!==t&&(M.threeEnabled=t,Z(di,M.threeEnabled?"1":"0"),M.threeEnabled||Os(),U())}function Qc(e){M.comparePair=e||"",At(),U()}function Zc(e){let t=String(e||"").trim();!t||!(t in M.indicators)||(M.indicators[t]=!0,M.selectedIndicator=t,U())}function ed(e){let t=String(e||"none");Zl.some(n=>n.key===t)&&(M.drawingTool=t,M.educationHint=xf[t]||"",U())}function Da(){var e;return((e=M.chartMeta)==null?void 0:e.tokenKey)||M.tokenFocusKey||`${_a().symbol||"XRP"}|`}function td(){var s,a;let e=Number((s=M.chartMeta)==null?void 0:s.last),t=prompt(`Alert me when ${((a=M.chartMeta)==null?void 0:a.symbol)||"price"} crosses:`,Number.isFinite(e)?e.toFixed(6):"");if(t==null)return;let n=Number(t);if(!Number.isFinite(n)||n<=0){he("Enter a valid price.");return}M.alerts=[...M.alerts||[],{id:`alert_${Date.now()}`,tokenKey:Da(),price:n,createdAt:new Date().toISOString()}],mi(),U(),ne(`Alert set at $${_(n,6)}`)}function nd(e){M.alerts=(M.alerts||[]).filter(t=>t.id!==e),mi(),U()}function Il(e){if(!e)return;let t=window.LightweightCharts;for(let s of ee.alertPriceLines||[])try{e.removePriceLine(s)}catch{}let n=(M.alerts||[]).filter(s=>s.tokenKey===Da());ee.alertPriceLines=n.map(s=>{var a;return e.createPriceLine({price:s.price,color:"#ffb703",lineWidth:2,lineStyle:((a=t==null?void 0:t.LineStyle)==null?void 0:a.Dotted)??2,axisLabelVisible:!0,title:"\u{1F514} Alert"})})}function Hh(e){var r,l;if(e.length<2)return;let t=Da(),n=(M.alerts||[]).filter(c=>c.tokenKey===t);if(!n.length)return;let s=e[e.length-2].close,a=e[e.length-1].close,o=[],i=!1;for(let c of n){let u=s<c.price&&a>=c.price,d=s>c.price&&a<=c.price;u||d?(ne(`\u{1F514} ${((r=M.chartMeta)==null?void 0:r.symbol)||"Price"} crossed $${_(c.price,6)} (${u?"\u2191":"\u2193"} now $${_(a,6)})`),i=!0,(l=document.querySelector(`.xpd-indicator-chip[data-alert-id="${c.id}"]`))==null||l.remove()):o.push(c)}i&&(M.alerts=[...(M.alerts||[]).filter(c=>c.tokenKey!==t),...o],mi())}function sd(){let e=ee.activeSeries;if(e)for(let t of ee.priceLines||[])try{e.removePriceLine(t)}catch{}ee.priceLines=[],M.drawings=[]}function Ia(e,t=0){var i;let n=(i=ee.chart)==null?void 0:i.timeScale();if(!n)return;let s=n.getVisibleLogicalRange();if(!s)return;let a=(s.to-s.from)*e,o=(s.to+s.from)/2+(s.to-s.from)*t;n.setVisibleLogicalRange({from:o-a/2,to:o+a/2})}function ad(){Ia(.8)}function od(){Ia(1.25)}function id(){Ia(1,-.2)}function rd(){Ia(1,.2)}function ld(){M.educationCollapsed=!M.educationCollapsed,U()}function cd(e){["indicator","psychology","practice"].includes(e)&&(M.selectedEducationTab=e,U())}function dd(){let e=document.body.classList.contains("theme-gold");Pn(e?"cosmic":"gold"),U()}var Fl=!1;function zh(){let e=document.getElementById("xpd-tv-widget");e&&ee.chart&&(ee.chart.applyOptions({width:Math.max(320,e.clientWidth||320),height:Math.max(320,e.clientHeight||460)}),ai())}function pd(){var t;let e=document.querySelector(".xpd-chart-wrap");e&&(Fl||(Fl=!0,document.addEventListener("fullscreenchange",()=>{requestAnimationFrame(()=>requestAnimationFrame(zh))})),document.fullscreenElement?document.exitFullscreen():(t=e.requestFullscreen)==null||t.call(e))}function ud(){let e=ee.chart;if(!e){he("Chart image is not ready yet.");return}let t=e.takeScreenshot(),n=document.createElement("a");n.download=`xrpl-chart-${Date.now()}.png`,n.href=t.toDataURL("image/png"),n.click()}function md(){return M.tokenFocusKey||M.pair||"default"}function fd(){var n;let e=ge(Q(Yo))||{},t=md();e[t]={interval:M.interval,chartType:M.chartType,comparePair:M.comparePair,indicators:M.indicators,indicatorSettings:M.indicatorSettings},Z(Yo,JSON.stringify(e)),ne(`Chart layout saved for ${((n=M.chartMeta)==null?void 0:n.symbol)||t}.`)}function hd(){var s;let e=ge(Q(Yo))||{},t=md(),n=e[t];if(!n){he(`No saved layout for ${((s=M.chartMeta)==null?void 0:s.symbol)||t} yet.`);return}M.interval=n.interval||M.interval,M.chartType=n.chartType||M.chartType,M.comparePair=n.comparePair||"",M.indicators={...M.indicators,...n.indicators||{}},M.indicatorSettings={...M.indicatorSettings,...n.indicatorSettings||{}},At(),U()}function Fa(e){let t=String(e||"").trim();if(/^[0-9A-F]{40}$/i.test(t)){let n=t.replace(/(00)+$/g,"");if(/^[0-9A-F]+$/i.test(n)&&n.length%2===0)try{let s=new Uint8Array(n.length/2);for(let o=0;o<n.length;o+=2)s[o/2]=parseInt(n.slice(o,o+2),16);let a=new TextDecoder().decode(s).replace(/\0/g,"").trim();if(a)return a.toUpperCase()}catch{}}return t.toUpperCase()}function Ve(e){return`${e.symbol}|${e.issuer||""}`}function Ms(e){return encodeURIComponent(e).replace(/'/g,"%27")}function jh(e){var l,c,u,d,p,m,f,g,v,h;let t=Fa(e.code||e.currency||""),n=String(e.issuer||((l=e.IssuingAccount)==null?void 0:l.account)||"").trim(),s=Number(e.price??((c=e.metrics)==null?void 0:c.price)??0),a=Number(e.marketcap??((u=e.metrics)==null?void 0:u.marketcap)??0),o=Number(((d=e.metrics)==null?void 0:d.volume_24h)??0),i=((m=(p=e.meta)==null?void 0:p.token)==null?void 0:m.name)||((f=e.IssuingAccount)==null?void 0:f.name)||t||"Unknown Token",r=Number(e.holders??((g=e.metrics)==null?void 0:g.holders)??((v=e.metrics)==null?void 0:v.trustlines)??0);return{symbol:t,name:i,issuer:n,tokenId:e.id||`${t}.${n}`,price:Number.isFinite(s)&&s>0?s:null,marketCap:Number.isFinite(a)&&a>0?a:null,volume24h:Number.isFinite(o)?o:null,holders:Number.isFinite(r)?r:null,change24h:null,verified:!!((h=e.IssuingAccount)!=null&&h.verified),score:Number(e.score||0)||null}}function Wh(e){let t=Fa((e==null?void 0:e.symbol)||""),n=String((e==null?void 0:e.name)||t||"Unknown Token"),s=Number((e==null?void 0:e.current_price)||0),a=Number((e==null?void 0:e.market_cap)||0),o=Number((e==null?void 0:e.total_volume)||0),i=Number((e==null?void 0:e.price_change_percentage_24h)||0);return{symbol:t,name:n,issuer:"",tokenId:`cg:${(e==null?void 0:e.id)||t}`,price:Number.isFinite(s)&&s>0?s:null,marketCap:Number.isFinite(a)&&a>0?a:null,volume24h:Number.isFinite(o)&&o>0?o:null,holders:null,change24h:Number.isFinite(i)?i:null,verified:!1,score:null}}function Uh(e){var r;let t=Fa((e==null?void 0:e.currency)||(e==null?void 0:e.token)||""),n=String((e==null?void 0:e.issuer)||(e==null?void 0:e.account)||"").trim(),s=String((e==null?void 0:e.name)||t||"Unknown Token"),a=Number((e==null?void 0:e.price)||((r=e==null?void 0:e.market)==null?void 0:r.price)||0),o=Number((e==null?void 0:e.marketcap)||(e==null?void 0:e.marketCap)||0),i=Number((e==null?void 0:e.volume24h)||(e==null?void 0:e.volume)||0);return{symbol:t,name:s,issuer:n,tokenId:`bithomp:${t}.${n||"na"}`,price:Number.isFinite(a)&&a>0?a:null,marketCap:Number.isFinite(o)&&o>0?o:null,volume24h:Number.isFinite(i)&&i>0?i:null,holders:Number.isFinite(Number((e==null?void 0:e.holders)||0))?Number((e==null?void 0:e.holders)||0):null,change24h:Number.isFinite(Number((e==null?void 0:e.change24h)||0))?Number((e==null?void 0:e.change24h)||0):null,verified:!!(e!=null&&e.verified),score:null}}function qh(e){let t=Fa((e==null?void 0:e.symbol)||(e==null?void 0:e.currency)||""),n=String((e==null?void 0:e.issuer)||(e==null?void 0:e.issuerAddress)||"").trim(),s=String((e==null?void 0:e.name)||t||"Unknown Token"),a=Number((e==null?void 0:e.price)||0),o=Number((e==null?void 0:e.volume24h)||0);return{symbol:t,name:s,issuer:n,tokenId:`xrplto:${t}.${n||"na"}`,price:Number.isFinite(a)&&a>0?a:null,marketCap:Number.isFinite(Number((e==null?void 0:e.marketCap)||0))?Number((e==null?void 0:e.marketCap)||0):null,volume24h:Number.isFinite(o)&&o>0?o:null,holders:Number.isFinite(Number((e==null?void 0:e.holders)||0))?Number((e==null?void 0:e.holders)||0):null,change24h:Number.isFinite(Number((e==null?void 0:e.change24h)||0))?Number((e==null?void 0:e.change24h)||0):null,verified:!!(e!=null&&e.verified),score:null}}async function gd(){var e,t,n,s,a,o;if(Aa()){W.loading=!0,W.error="";try{let i=Date.now(),r=$l.get("tokens");if(r&&i-r.ts<6e4){W.tokens=r.data,W.total=r.total||r.data.length,W.lastSyncAt=r.ts,W.filtered=os(W.query,r.data),W.trending=Ol(r.data),W.loading=!1;return}let l=500,c=12,u=[];for(let S=1;S<=c;S+=1){let $=await Lt(`${nf}?page=${S}&limit=${l}`,{allowProxy:!1,timeoutMs:12e3});if(!Array.isArray($)||!$.length||(u.push(...$),$.length<l))break}let d=u.map(jh).filter(S=>!!S.symbol&&!!S.issuer),p=[Lt(`${sf}?vs_currency=usd&order=market_cap_desc&per_page=250&page=1&sparkline=false`,{timeoutMs:12e3}).catch(()=>[]),Date.now()<(Cl.xrplto||0)?Promise.resolve([]):Lt(of,{timeoutMs:12e3,allowProxy:!1}).catch(S=>(String((S==null?void 0:S.message)||"").includes("429")&&(Cl.xrplto=Date.now()+5*60*1e3),[]))];rf&&p.push(Lt(af,{timeoutMs:12e3,allowProxy:!1}).catch(()=>[]));let[m,f,g=[]]=await Promise.all(p),v=Array.isArray(m)?m.map(Wh).filter(S=>!!S.symbol):[],h=Array.isArray(g)?g.map(Uh).filter(S=>!!S.symbol):[],b=Array.isArray(f)?f.map(qh).filter(S=>!!S.symbol):[],x={symbol:"XRP",name:"XRP Ledger Native",issuer:"",tokenId:"XRP",price:((e=Te.data)==null?void 0:e.priceUsd)||((t=M.stats)==null?void 0:t.price)||null,marketCap:((n=Te.data)==null?void 0:n.marketCap)||null,volume24h:((s=Te.data)==null?void 0:s.volume24h)||null,holders:null,change24h:((a=Te.data)==null?void 0:a.change24h)||((o=M.stats)==null?void 0:o.changePct)||null,verified:!0,score:1},k=new Map;[x,...d,...h,...b,...v].forEach(S=>{let $=Ve(S);k.has($)||k.set($,S)});let T=[...k.values()];$l.set("tokens",{ts:i,data:T,total:T.length}),W.tokens=T,W.total=T.length,W.lastSyncAt=i,W.filtered=os(W.query,T),W.trending=Ol(T)}catch(i){W.error=(i==null?void 0:i.message)||"Could not load XRPL token discovery data."}finally{W.loading=!1}}}function os(e,t){let n=String(e||"").trim().toLowerCase(),s=W.filters||{type:"all",minCap:0,minVol:0,hasDex:!1};return t.filter(a=>{if(n&&!`${a.symbol} ${a.name} ${a.issuer} ${a.tokenId||""}`.toLowerCase().includes(n)||Number(s.minCap||0)>0&&Number(a.marketCap||0)<Number(s.minCap||0)||Number(s.minVol||0)>0&&Number(a.volume24h||0)<Number(s.minVol||0)||s.hasDex&&!(Number(a.volume24h||0)>0||Number(a.holders||0)>100))return!1;if(s.type&&s.type!=="all"){let o=String(a.symbol||"").toLowerCase(),i=String(a.name||"").toLowerCase(),r=/usd|usdc|usdt|rlusd|eur|gbp/.test(o)||/stable/.test(i),l=/meme|dog|cat|frog|shib|pepe/.test(o)||/meme/.test(i),c=/mpt/.test(o)||/multi-purpose/.test(i);if(s.type==="stablecoin"&&!r||s.type==="meme"&&!l||s.type==="mpt"&&!c||s.type==="standard"&&(r||l||c))return!1}return!0})}function Ol(e){return[...e].sort((t,n)=>{let s=Number(t.volume24h||0),a=Number(n.volume24h||0);if(a!==s)return a-s;let o=Number(t.marketCap||0);return Number(n.marketCap||0)-o}).slice(0,24)}async function bd(e){if(Pt.loading=!0,Pt.error="",Pt.items=[],!e){Pt.loading=!1;return}try{let t=await ki(e,20);Pt.items=t||[]}catch(t){Pt.error=(t==null?void 0:t.message)||"Could not load recent transactions."}finally{Pt.loading=!1}}function vd(e){W.query=e,As&&clearTimeout(As),As=setTimeout(()=>{W.listLimit=240,W.filtered=os(W.query,W.tokens),U()},300)}function yd(e,t){W.filters={...W.filters,[e]:t},W.listLimit=240,W.filtered=os(W.query,W.tokens),U()}function wd(){As&&clearTimeout(As),W.query="",W.filters={type:"all",minCap:0,minVol:0,hasDex:!1},W.listLimit=240,W.filtered=os("",W.tokens),U()}function xd(){W.listLimit=Math.min(5e3,Number(W.listLimit||240)+240),U()}function kd(){let e=W.filtered;W.listLimit=Math.min(5e3,Math.max(240,e.length)),U()}function $d(){W.listLimit=240,U()}function Sd(e){W.selectedTokenKey=e||"",U()}function Td(e){let t=String(e||"").trim();if(!t)return;let n=fi();n.includes(t)||n.push(t),oc(n),U()}function Cd(e){let t=String(e||"").trim(),n=fi().filter(s=>s!==t);oc(n),U()}async function Oa(e){let t=String(e||"").trim();if(!t)return;let n=String(t.includes("|")?t.split("|")[0]:t).toUpperCase(),s=t.includes("|")?W.tokens.find(o=>Ve(o)===t):W.tokens.find(o=>String(o.symbol||"").toUpperCase()===String(n||"").toUpperCase());W.selectedTokenKey=s?Ve(s):t.includes("|")?t:W.selectedTokenKey,M.tokenFocusKey=W.selectedTokenKey||t;let a={BTC:"BINANCE:BTCUSDT",ETH:"BINANCE:ETHUSDT",SOL:"BINANCE:SOLUSDT"};M.pair=a[n]||"BITSTAMP:XRPUSD",At(),U(),setTimeout(()=>Tf(),20),await Fs(),At(),U()}async function Pd(e){return Oa(e)}async function Md(){await gd(),U()}async function vi(){let e=document.getElementById("xpd-lookup-currency"),t=document.getElementById("xpd-lookup-issuer"),n=String((e==null?void 0:e.value)||"").trim().toUpperCase(),s=String((t==null?void 0:t.value)||"").trim();if(!n){he("Enter a currency code first.");return}if(!s||!He(s)){he("Enter a valid XRPL issuer address.");return}let a=`${n}|${s}`,o=W.tokens.find(i=>Ve(i)===a);o||(o={symbol:n,name:n,issuer:s,price:null,marketCap:null,volume24h:null,holders:null,tokenId:""},W.tokens=[...W.tokens,o],W.filtered=os(W.query,W.tokens)),W.selectedTokenKey=a,e&&(e.value=""),t&&(t.value=""),await Oa(a)}async function Ld(){var s,a;let e=String(((s=document.getElementById("xpd-lookup-currency"))==null?void 0:s.value)||"").trim().toUpperCase(),t=String(((a=document.getElementById("xpd-lookup-issuer"))==null?void 0:a.value)||"").trim();if(!e){he("Enter a currency code first.");return}if(!t||!He(t)){he("Enter a valid XRPL issuer address.");return}let n=`${e}|${t}`;await vi(),await hi(n)}async function Ad(){var t;let e=((t=Et())==null?void 0:t.address)||"";await bd(e),U()}async function ns({silent:e=!1,force:t=!1}={}){var s;if(!t&&!Aa())return;let n=((s=Et())==null?void 0:s.address)||"";e||ne("Refreshing XRPL dashboard data..."),await Promise.allSettled([Fs(),vc(),gd(),bd(n),yc(n),wc(n),kc()]),U()}function Ed(){return vc()}function Nd(){var e;return yc(((e=Et())==null?void 0:e.address)||"")}function Rd(){var e;return wc(((e=Et())==null?void 0:e.address)||"")}function _d(){return kc()}function Dd(e){ne(`NFT ${e.slice(0,12)}... selected. Send flow can be wired to NFTokenCreateOffer.`)}function Is(){let e=w("profile-metrics-row");if(!e)return;let t=!1,n=Object.values(Ze).reduce((d,p)=>d+((p==null?void 0:p.xrp)||0),0),s=Id(),a=Object.values(Ze).flatMap(d=>(d==null?void 0:d.tokens)||[]),o=Et(),i=o?Ls[o.address]:null,r=(i==null?void 0:i.ownerCount)||0,l=Pa+r*Ma,c=o!=null&&o.createdAt?Gh(new Date(o.createdAt)):"\u2014",u=(i==null?void 0:i.sequence)!=null?i.sequence:"\u2014";e.innerHTML=`
    <div class="pmetric"><div class="pmetric-val">${t?"\u2022\u2022\u2022\u2022":_(n,2)}</div><div class="pmetric-label">Total XRP</div></div>
    <div class="pmetric pmetric-divider"></div>
    <div class="pmetric"><div class="pmetric-val ${s&&!t?"pmetric-usd":""}">
      ${t?"\u2022\u2022\u2022\u2022":s?"$"+_(n*s,2):"\u2014"}</div>
      <div class="pmetric-label">Est. Value</div></div>
    <div class="pmetric pmetric-divider"></div>
    <div class="pmetric"><div class="pmetric-val">${u}</div><div class="pmetric-label">Transactions</div></div>
    <div class="pmetric pmetric-divider"></div>
    <div class="pmetric"><div class="pmetric-val">${c}</div><div class="pmetric-label">Wallet Age</div></div>
    <div class="pmetric pmetric-divider"></div>
    <div class="pmetric"><div class="pmetric-val">${a.length}</div><div class="pmetric-label">Tokens</div></div>
    ${i?`<div class="pmetric pmetric-divider"></div>
    <div class="pmetric pmetric-reserve" title="${r} owned objects \xD7 ${Ma} XRP + ${Pa} XRP base">
      <div class="pmetric-val pmetric-reserve-val">${l} XRP</div>
      <div class="pmetric-label">Reserved</div></div>`:""}`,o&&(!Ls[o.address]||Date.now()-Ls[o.address].fetchedAt>6e4)&&Vh(o.address).then(()=>Is())}async function Vh(e){try{let t=await at({method:"account_info",params:[{account:e,ledger_index:"validated"}]});t!=null&&t.account_data&&(Ls[e]={sequence:t.account_data.Sequence,ownerCount:t.account_data.OwnerCount||0,fetchedAt:Date.now()})}catch{}}function Gh(e){let t=Math.floor((Date.now()-e.getTime())/864e5);if(t<1)return"Today";if(t<30)return`${t}d`;if(t<365)return`${Math.floor(t/30)}mo`;let n=Math.floor(t/365),s=Math.floor(t%365/30);return s?`${n}y ${s}mo`:`${n}y`}function Id(){var t;if(Array.isArray((t=window.__dashSeries)==null?void 0:t.marketPrice)){let n=window.__dashSeries.marketPrice.at(-1);if(n!=null&&Number.isFinite(n))return n}let e=document.getElementById("mkt-price");if(e){let n=parseFloat(e.textContent.replace("$",""));if(!isNaN(n))return n}return 0}function Kh(){let e=oe.length>0,t=Object.values(Je).some(Boolean),n=!!ce.bio,s=!!localStorage.getItem("naluxrp_last_backup_ts"),a=[e,t,n,s].filter(Boolean).length;return a===4?"":`
    <div class="onboarding-card">
      <div class="onb-header">
        <div class="onb-title">\u2728 Complete your profile</div>
        <div class="onb-prog-wrap">
          <div class="onb-prog-bar"><div class="onb-prog-fill" style="width:${Math.round(a/4*100)}%"></div></div>
          <span class="onb-prog-label">${a}/4</span>
        </div>
      </div>
      <div class="onb-items">
        ${Ca("\u{1F48E}","Generate your first XRPL wallet","Encrypted with AES-256-GCM, never leaves this device.",e,"openWalletCreator()")}
        ${Ca("\u{1F517}","Connect a social account","Link Discord, X, GitHub, or any platform.",t,"switchProfileTab('social')")}
        ${Ca("\u270F\uFE0F","Add a bio","Tell people who you are.",n,"openProfileEditor()")}
        ${Ca("\u{1F4BE}","Export an encrypted backup","Protect against device loss.",s,"exportVaultBackup()")}
      </div>
    </div>`}function Ca(e,t,n,s,a){return`<div class="onb-item ${s?"onb-item--done":""}" ${s?"":` onclick="${a}"`}>
    <div class="onb-item-check">${s?"\u2713":e}</div>
    <div class="onb-item-body"><div class="onb-item-title">${t}</div><div class="onb-item-sub">${n}</div></div>
    ${s?"":'<span class="onb-item-arrow">\u2192</span>'}
  </div>`}function yi(){let e=w("profile-tab-social");if(!e)return;let t=Object.values(Je).filter(Boolean).length;e.innerHTML=`
    <div class="social-section-head">
      <div class="social-section-title">Social &amp; Community Links</div>
      <div class="social-section-sub">${t} of ${as.length} connected \xB7 stored locally only</div>
    </div>
    <div class="social-grid">
      ${as.map(n=>{let s=Je[n.id]||"",a=!!s;return`<div class="social-card ${a?"social-card--connected":""}" id="social-item-${n.id}">
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
    </div>`:""}`,Ea("stat-socials-val",t)}function Fd(e){let t=as.find(l=>l.id===e);if(!t)return;let n=w("social-modal");if(!n)return;let s=w("social-modal-icon"),a=w("social-modal-title"),o=w("social-modal-sub"),i=w("social-modal-input"),r=w("social-modal-delete");s&&(s.className=`social-platform-icon-lg social-icon ${t.id}`,s.textContent=t.icon),a&&(a.textContent=`Connect ${t.label}`),o&&(o.textContent=`Enter your ${t.label} ${t.id==="discord"?"user ID or username":"username"}.`),i&&(i.value=Je[e]||"",i.placeholder=`Your ${t.label} handle`),r&&(r.style.display=Je[e]?"":"none"),n.dataset.platform=e,n.classList.add("show"),setTimeout(()=>i==null?void 0:i.focus(),80)}function Od(){let e=w("social-modal"),t=e==null?void 0:e.dataset.platform,n=w("social-modal-input");if(!t||!n)return;let s=n.value.trim().replace(/^@/,"");s?Je[t]=s:delete Je[t],nc(),yi(),is();let a=as.find(o=>o.id===t);Mg(),kt("social_connected",`${(a==null?void 0:a.label)||t} @${s||"(removed)"}`),ne(`${a==null?void 0:a.label} updated`)}function Bd(){var t;let e=(t=w("social-modal"))==null?void 0:t.dataset.platform;e&&(delete Je[e],nc(),yi(),is(),kt("social_removed",e),ne("Social connection removed"))}function Xd(e){let t=as.find(n=>n.id===e);t&&Je[e]&&window.open(`${t.prefix}${Je[e]}`,"_blank","noopener")}function is(){var e;(e=w("social-modal"))==null||e.classList.remove("show")}function $t(){let e=w("profile-tab-wallets");if(!e)return;if(oe.length===0){e.innerHTML=Kh()+`
      <div class="wallets-empty">
        <div class="wallets-empty-icon">\u{1F48E}</div>
        <div class="wallets-empty-title">No wallets yet</div>
        <div class="wallets-empty-sub">Generate your first XRPL wallet \u2014 your seed is encrypted with AES-256-GCM and never leaves this device.</div>
        <button class="btn-create-wallet-hero" onclick="openWalletCreator()">\u26A1 Generate XRPL Wallet</button>
      </div>`,Ea("stat-wallets-val",0);return}let t=oe.length>3?`
    <div class="wallet-filter-row">
      <input class="wallet-filter-input" id="wallet-filter-input" type="text"
        placeholder="\u{1F50D} Filter wallets\u2026" value="${y(ts)}"
        oninput="filterWallets(this.value)">
      ${ts?`<button class="wallet-filter-clear" onclick="filterWallets('')">\u2715</button>`:""}
    </div>`:"",n=oe.filter(a=>!ts||a.label.toLowerCase().includes(ts.toLowerCase())||a.address.toLowerCase().includes(ts.toLowerCase())),s=n.map((a,o)=>Jh(a,oe.indexOf(a))).join("");e.innerHTML=t+(n.length?s:`<div class="wcard-empty">No wallets match "${y(ts)}"</div>`)+`
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
    </div>`,Ea("stat-wallets-val",oe.length)}function Jh(e,t){let n=e.id===dt,s=!!e.watchOnly,a=Ze[e.address],o=Ls[e.address],r=!0||s,l=(o==null?void 0:o.ownerCount)||0,c=Pa+l*Ma,u=r?a?_(a.xrp,2):"\u2014":"\u2022\u2022\u2022\u2022",d=a&&r?Math.max(0,a.xrp-c):null,p=(a==null?void 0:a.tokens)||[],m=a!=null&&a.fetchedAt?sc(a.fetchedAt):null,f=e.address.slice(0,8)+"\u2026"+e.address.slice(-6),g=xi(e.address);return`
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
        ${g.length>=2?`<div class="wcard-sparkline">${Vd(g,70,22,e.color||"#00fff0")}</div>`:""}
        <div class="wcard-xrp ${r?"":"wcard-balance-locked"}">${u} <span class="wcard-xrp-label">XRP</span></div>
        ${d!==null&&r?`<div class="wcard-avail" title="${c} XRP reserved">${_(d,2)} avail.</div>`:""}
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
      <span class="wcard-reserve-sub">${l} object${l!==1?"s":""} \xB7 base ${Pa} + ${l}\xD7${Ma}</span>
    </div>`:""}

    ${p.length&&r?`<div class="wcard-token-row">
      ${p.slice(0,6).map(v=>{let h=v.currency.length>4?Pi(v.currency)||v.currency.slice(0,4)+"\u2026":v.currency;return`<div class="wcard-token-chip" onclick="openTokenDetailsModal('${y(v.currency)}','${y(v.issuer)}','${y(e.address)}')" title="${y(v.currency)}">
          <span class="wcard-token-cur">${y(h)}</span>
          <span class="wcard-token-bal">${_(parseFloat(v.balance||0),4)}</span>
        </div>`}).join("")}
      ${p.length>6?`<div class="wcard-token-chip wcard-token-more" onclick="openTokenDetailsModal('${y(p[6].currency)}','${y(p[6].issuer)}','${y(e.address)}')">+${p.length-6}</div>`:""}
    </div>`:""}

    <div class="wcard-actions">
      ${s?"":`<button class="wcard-btn wcard-btn--send" onclick="openSendModal('${e.id}')">\u2B06 Send</button>`}
      <button class="wcard-btn wcard-btn--receive" onclick="openReceiveModal('${e.id}')">\u2B07 Receive</button>
      ${s?"":`<button class="wcard-btn wcard-btn--trust" onclick="openTrustlineModal('${e.id}')">\u{1F517} Trust</button>`}
      <button class="wcard-btn wcard-btn--inspect" onclick="inspectWalletAddr('${y(e.address)}')">\u{1F50D} Inspect</button>
      ${n?"":`<button class="wcard-btn wcard-btn--setactive" onclick="setActiveWallet('${e.id}')">\u2605 Active</button>`}
      <button class="wcard-btn wcard-btn--expand ${_n===e.id?"wcard-btn--expand-open":""}" onclick="toggleWalletDrawer('${e.id}')">${_n===e.id?"\u25B2 Hide":"\u25BC Details"}</button>
      <button class="wcard-btn wcard-btn--remove" onclick="deleteWallet(${t})">\u2715</button>
    </div>

    ${_n===e.id?`
    <div class="wcard-drawer" id="wcard-drawer-${e.id}">
      <div class="wcard-drawer-tabs">
        <button class="wdt-btn ${(pn[e.id]||"txns")==="txns"?"active":""}" onclick="switchWalletDrawerTab('${e.id}','txns')">\u{1F4CB} Transactions</button>
        <button class="wdt-btn ${(pn[e.id]||"txns")==="nfts"?"active":""}" onclick="switchWalletDrawerTab('${e.id}','nfts')">\u{1F3A8} NFTs</button>
        <button class="wdt-btn ${(pn[e.id]||"txns")==="orders"?"active":""}" onclick="switchWalletDrawerTab('${e.id}','orders')">\u{1F4CA} DEX</button>
        <button class="wdt-btn ${(pn[e.id]||"txns")==="amm"?"active":""}" onclick="switchWalletDrawerTab('${e.id}','amm')">\u{1F30A} AMM</button>
      </div>
      <div class="wcard-drawer-body" id="wcard-drawer-body-${e.id}">
        <div class="wdd-loading"><div class="spinner"></div> Loading\u2026</div>
      </div>
    </div>`:""}
  </div>`}function Hd(e){var n;let t=oe[e];t&&(oe.splice(e,1),_s(),dt===t.id&&(dt=((n=oe[0])==null?void 0:n.id)||null,dt&&Z(Ns,dt)),$t(),Bt(),kt("wallet_removed",t.label),Yh(`Wallet "${t.label}" removed`,()=>{oe.splice(e,0,t),_s(),dt||(dt=t.id,Z(Ns,t.id)),$t(),Bt(),kt("wallet_created",t.label+" (restored)")},()=>{t.address&&bt(ii+t.address)}))}function Yh(e,t,n){let s=document.getElementById("undo-toast");s&&s.remove();let a=document.createElement("div");a.id="undo-toast",a.className="undo-toast",a.innerHTML=`<span class="undo-msg">${y(e)}</span><button class="undo-btn">Undo</button>`,document.body.appendChild(a),requestAnimationFrame(()=>a.classList.add("show"));let o=setTimeout(()=>{a.classList.remove("show"),setTimeout(()=>a.remove(),300),n==null||n()},5e3);a.querySelector(".undo-btn").addEventListener("click",()=>{clearTimeout(o),t(),a.classList.remove("show"),setTimeout(()=>a.remove(),300),ne("Wallet restored")})}function zd(e){var n,s;let t=w("inspect-addr");t&&(t.value=e),(n=window.switchTab)==null||n.call(window,document.querySelector('[data-tab="inspector"]'),"inspector"),(s=window.showDashboard)==null||s.call(window)}function jd(e){_n=_n===e?null:e,_n&&!pn[e]&&(pn[e]="txns"),$t(),_n&&setTimeout(()=>wi(e,pn[e]),60)}function Wd(e,t){pn[e]=t;let n=document.getElementById(`wcard-drawer-${e}`);n&&(n.querySelectorAll(".wdt-btn").forEach(s=>s.classList.toggle("active",s.textContent.toLowerCase().includes(t==="txns"?"trans":t==="nfts"?"nft":t==="orders"?"dex":"amm"))),wi(e,t))}async function wi(e,t){var a,o,i;let n=oe.find(r=>r.id===e),s=document.getElementById(`wcard-drawer-body-${e}`);if(!(!n||!s)){s.innerHTML='<div class="wdd-loading"><div class="spinner"></div> Loading\u2026</div>';try{t==="txns"?s.innerHTML=Qh(((a=li[n.address])==null?void 0:a.txns)||await ki(n.address),n.address):t==="nfts"?s.innerHTML=Zh(((o=Wl[n.address])==null?void 0:o.nfts)||await pg(n.address),n.address):t==="orders"?s.innerHTML=eg(((i=ci[n.address])==null?void 0:i.offers)||await ug(n.address),n.id,n.address):t==="amm"&&(s.innerHTML=await tg(n.address))}catch(r){s.innerHTML=`<div class="wdd-error">\u26A0\uFE0F ${y(r.message)}</div>`}}}function Ud(e){return{Payment:"\u{1F4B8}",OfferCreate:"\u{1F4CA}",OfferCancel:"\u2715",TrustSet:"\u{1F517}",NFTokenMint:"\u{1F3A8}",NFTokenBurn:"\u{1F525}",NFTokenCreateOffer:"\u{1F3AF}",NFTokenAcceptOffer:"\u2705",AMMCreate:"\u{1F30A}",AMMDeposit:"\u{1F4E5}",AMMWithdraw:"\u{1F4E4}",AMMVote:"\u{1F5F3}",AMMBid:"\u{1F4A1}",EscrowCreate:"\u23F3",EscrowFinish:"\u2705",EscrowCancel:"\u2715",AccountSet:"\u2699",SetRegularKey:"\u{1F511}",SignerListSet:"\u{1F4CB}"}[e]||"\u{1F4C4}"}function oi(e){return e?typeof e=="string"?`${_(Number(e)/1e6,4)} XRP`:`${_(parseFloat(e.value||0),4)} ${(e.currency||"?").length>4?e.currency.slice(0,4)+"\u2026":e.currency}`:"\u2014"}function Qh(e,t){return e!=null&&e.length?`<div class="wdd-tx-list">
    ${e.slice(0,25).map(n=>{var c,u;let s=n.TransactionType||"?",a=n.Account===t,o=!(((c=n.metaData)==null?void 0:c.TransactionResult)||((u=n.meta)==null?void 0:u.TransactionResult)||"").match(/^tec|^tem|^tef|^tel/),i=n.date?(n.date+946684800)*1e3:0,r=i?new Date(i).toLocaleDateString("en-US",{month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"}):"\u2014",l=n.hash||n.tx_hash||"";return`<div class="wdd-tx-row ${o?"":"wdd-tx-failed"}">
        <div class="wdd-tx-icon">${Ud(s)}</div>
        <div class="wdd-tx-body">
          <div class="wdd-tx-type-row">
            <span class="wdd-tx-type">${s}</span>
            <span class="wdd-tx-dir ${a?"out":"in"}">${a?"\u2191 Out":"\u2193 In"}</span>
            ${o?"":'<span class="wdd-tx-fail-badge">Failed</span>'}
          </div>
          <div class="wdd-tx-detail">
            ${n.Amount?`<span class="wdd-tx-amount">${oi(n.Amount)}</span>`:""}
            ${n.Destination?`<span class="wdd-tx-dest mono">${Ul[n.Destination]||n.Destination.slice(0,8)+"\u2026"+n.Destination.slice(-5)}</span>`:""}
          </div>
        </div>
        <div class="wdd-tx-right">
          <div class="wdd-tx-date">${r}</div>
          ${l?`<a class="wdd-tx-hash" href="https://xrpscan.com/tx/${l}" target="_blank" rel="noopener">\u2B21 View</a>`:""}
        </div>
      </div>`}).join("")}
    <a class="wdd-view-more" href="https://xrpscan.com/account/${t}" target="_blank" rel="noopener">View full history on XRPScan \u2192</a>
  </div>`:'<div class="wdd-empty"><div class="wdd-empty-icon">\u{1F4CB}</div><div>No transactions yet.</div><div class="wdd-empty-sub">Fund with 10 XRP to activate.</div></div>'}function Zh(e,t){return e!=null&&e.length?`<div class="wdd-nft-header"><span>${e.length} NFT${e.length>1?"s":""}</span>
    <a class="wdd-view-more-inline" href="https://xrpscan.com/account/${t}#nfts" target="_blank">View on XRPScan \u2192</a></div>
    <div class="wdd-nft-grid">
      ${e.slice(0,24).map(n=>{var i;let s=n.nft_serial??((i=n.NFTokenID)==null?void 0:i.slice(-6))??"?",a=n.URI&&Pi(n.URI)||"",o=a.startsWith("ipfs://")?`https://cloudflare-ipfs.com/ipfs/${a.slice(7)}`:"";return`<div class="wdd-nft-card">
          <div class="wdd-nft-art">${o?`<img src="${y(o)}" class="wdd-nft-img" alt="NFT" onerror="this.parentNode.innerHTML='<span class=wdd-nft-placeholder>\u{1F3A8}</span>'" />`:'<span class="wdd-nft-placeholder">\u{1F3A8}</span>'}</div>
          <div class="wdd-nft-info"><div class="wdd-nft-id mono">#${s}</div></div>
        </div>`}).join("")}
    </div>
    ${e.length>24?`<div class="wdd-more-note">${e.length-24} more on XRPScan</div>`:""}`:'<div class="wdd-empty"><div class="wdd-empty-icon">\u{1F3A8}</div><div>No NFTs in this wallet.</div></div>'}function eg(e,t,n){return e!=null&&e.length?`<div class="wdd-orders-header"><span>${e.length} open order${e.length>1?"s":""}</span></div>
    <div class="wdd-orders-list">
      ${e.map(s=>`<div class="wdd-order-row">
        <div class="wdd-order-dir ${s.flags&524288?"sell":"buy"}">${s.flags&524288?"SELL":"BUY"}</div>
        <div class="wdd-order-pair">
          <span class="wdd-order-gets">${oi(s.TakerGets)}</span>
          <span class="wdd-order-arrow">\u21C4</span>
          <span class="wdd-order-pays">${oi(s.TakerPays)}</span>
        </div>
        <div class="wdd-order-seq mono">Seq #${s.seq||"?"}</div>
        <button class="wdd-order-cancel" onclick="cancelOffer('${t}',${s.seq},this)">\u2715 Cancel</button>
      </div>`).join("")}
    </div>`:'<div class="wdd-empty"><div class="wdd-empty-icon">\u{1F4CA}</div><div>No open DEX orders.</div></div>'}async function tg(e){try{let n=(ri[e]||[]).filter(s=>{var a;return((a=s.currency)==null?void 0:a.length)===40});return n.length?`<div class="wdd-amm-list">
      ${n.map(s=>{let a=s.currency,o=_(parseFloat(s.balance||0),6);return`<div class="wdd-amm-row">
          <div class="wdd-amm-icon">\u{1F30A}</div>
          <div class="wdd-amm-info">
            <div class="wdd-amm-pool mono">${a.slice(0,12)}\u2026</div>
            <div class="wdd-amm-bal">LP Tokens: ${o}</div>
            <div class="wdd-amm-issuer mono" style="opacity:.4;font-size:.7rem">${s.issuer.slice(0,14)}\u2026</div>
          </div>
          <a class="wdd-tx-hash" href="https://xrpscan.com/amm/${s.issuer}" target="_blank" rel="noopener">View AMM</a>
        </div>`}).join("")}
    </div>`:'<div class="wdd-empty"><div class="wdd-empty-icon">\u{1F30A}</div><div>No AMM LP positions.</div><div class="wdd-empty-sub">Deposit into an AMM pool to earn fees.</div></div>'}catch(t){return`<div class="wdd-error">\u26A0\uFE0F ${y(t.message)}</div>`}}async function qd(e,t,n){let s=prompt("Optional seed to cancel this order (leave blank to use wallet password):");if(s!==null){n&&(n.disabled=!0,n.textContent="\u2026");try{let a=await vg(e,t,s);if(hg(a)){ne("Order cancelled \u2713");let o=oe.find(i=>i.id===e);o&&(delete ci[o.address],wi(e,"orders"))}else Wt("Cancel failed: "+gg(a)),n&&(n.disabled=!1,n.textContent="\u2715 Cancel")}catch(a){Wt(a.message),n&&(n.disabled=!1,n.textContent="\u2715 Cancel")}}}function ng(){let e=w("profile-tab-activity");if(!e)return;let t=Lf(),n=Et();e.innerHTML=`
    <div class="act-section-row">
      <div class="act-section">
        <div class="act-section-title">In-App Activity</div>
        <div class="act-section-sub">Your recent actions in NaluXRP</div>
        ${t.length?`<div class="act-timeline">${t.slice(0,20).map(s=>`
            <div class="act-entry">
              <div class="act-entry-icon">${$f[s.type]||"\u25CF"}</div>
              <div class="act-entry-body">
                <div class="act-entry-detail">${y(s.detail)}</div>
                <div class="act-entry-time">${sc(s.ts)}</div>
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
    </div>`}function Bs(){var o,i;let e=w("profile-tab-settings");if(!e)return;let t=["gold","cosmic","starry","hawaiian"],n=Q("nalulf_pref_currency")||"XRP",s=Q("nalulf_pref_network")||"mainnet",a=Q("nalulf_pref_autolock")||"30";e.innerHTML=`<div class="settings-grid">

    <div class="settings-card">
      <div class="settings-card-hdr"><span class="settings-card-icon">\u{1F3A8}</span>
        <div><div class="settings-card-title">Appearance</div><div class="settings-card-sub">Theme and display preferences</div></div></div>
      <div class="settings-label">Theme</div>
      <div class="settings-theme-row">
        ${t.map(r=>`<button class="theme-pill ${r} ${X.currentTheme===r?"active":""}" onclick="prefSetTheme('${r}')">${r[0].toUpperCase()+r.slice(1)}</button>`).join("")}
      </div>
      <div style="margin-top:16px"><div class="settings-label">Display currency</div>
        <div class="settings-seg">
          <button class="settings-seg-btn ${n==="XRP"?"active":""}" onclick="setPrefCurrency('XRP')">XRP</button>
          <button class="settings-seg-btn ${n==="USD"?"active":""}" onclick="setPrefCurrency('USD')">USD</button>
        </div>
      </div>
      <div style="margin-top:16px"><div class="settings-label">3D immersive background</div>
        <div class="settings-seg">
          <button class="settings-seg-btn ${M.threeEnabled?"active":""}" onclick="setThreeEffects(true)">On</button>
          <button class="settings-seg-btn ${M.threeEnabled?"":"active"}" onclick="setThreeEffects(false)">Off</button>
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
        <div class="settings-kv"><span class="settings-k">Vault created</span><span class="settings-v">${y((i=(o=Qe.vault)==null?void 0:o.identity)!=null&&i.createdAt?new Date(Qe.vault.identity.createdAt).toLocaleDateString():"\u2014")}</span></div>
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

    <div class="settings-card settings-card--danger">
      <div class="settings-card-hdr"><span class="settings-card-icon">\u26A0\uFE0F</span>
        <div><div class="settings-card-title">Danger Zone</div><div class="settings-card-sub">Irreversible actions</div></div></div>
      <p class="settings-card-desc">Wiping removes all local data. Your wallets still exist on-chain and can be re-added with their seed phrases.</p>
      <button class="settings-btn settings-btn--danger" onclick="openAuth?.('forgot')">\u{1F5D1} Wipe Account Data</button>
    </div>
  </div>`}async function sg(){var t;let e=w("profile-tab-analytics");if(e){e.innerHTML='<div class="analytics-grid"><div class="skeleton-card analytics-card--wide" style="height:80px"></div><div class="skeleton-card" style="height:160px"></div><div class="skeleton-card" style="height:160px"></div></div>';try{let n=Et(),s=Object.values(Ze).reduce((r,l)=>r+((l==null?void 0:l.xrp)||0),0),a=Id(),o=Object.values(Ze).flatMap(r=>(r==null?void 0:r.tokens)||[]),i=[];if(n)try{i=((t=li[n.address])==null?void 0:t.txns)||await ki(n.address,100)}catch{}e.innerHTML=`<div class="analytics-grid">
      <div class="analytics-card analytics-card--wide">
        <div class="analytics-card-hdr"><span class="analytics-card-title">\u{1F4BC} Portfolio Summary</span>
          <span class="analytics-badge">${oe.length} wallet${oe.length!==1?"s":""}</span></div>
        <div class="portfolio-summary-row">
          ${oe.length?oe.map(r=>{let l=Ze[r.address],c=l?_(l.xrp,2):"\u2014",u=l&&a?`$${_(l.xrp*a,2)}`:"",d=xi(r.address);return`<div class="portfolio-wallet-row">
                <div class="pwr-icon" style="color:${r.color};background:${r.color}18;border-color:${r.color}33">${y(r.emoji||"\u{1F48E}")}</div>
                <div class="pwr-info"><div class="pwr-label">${y(r.label)}</div><div class="pwr-addr mono">${r.address.slice(0,8)}\u2026${r.address.slice(-5)}</div></div>
                <div class="pwr-sparkline">${Vd(d,80,28,r.color||"#00fff0")}</div>
                <div class="pwr-balance"><div class="pwr-xrp">${c} <span class="pwr-xrp-label">XRP</span></div>${u?`<div class="pwr-usd">${u}</div>`:""}</div>
              </div>`}).join(""):'<div class="analytics-empty">No wallets yet.</div>'}
        </div>
        <div class="portfolio-totals">
          <div class="ptotal"><span class="ptotal-label">Total XRP</span><span class="ptotal-val">${_(s,4)}</span></div>
          ${a?`<div class="ptotal"><span class="ptotal-label">Est. USD</span><span class="ptotal-val ptotal-usd">$${_(s*a,2)}</span></div>`:""}
          <div class="ptotal"><span class="ptotal-label">Tokens</span><span class="ptotal-val">${o.length}</span></div>
          <div class="ptotal"><span class="ptotal-label">Wallets</span><span class="ptotal-val">${oe.length}</span></div>
        </div>
      </div>

      ${n?`<div class="analytics-card analytics-card--wide">
        <div class="analytics-card-hdr"><span class="analytics-card-title">\u{1F4C8} Balance History</span>
          <span class="analytics-badge">${y(n.label)}</span></div>
        ${ag(n.address)}
      </div>`:""}

      <div class="analytics-card analytics-card--wide">
        <div class="analytics-card-hdr"><span class="analytics-card-title">\u{1F4C5} On-Chain Activity</span>
          <span class="analytics-badge">${n?y(n.label):"No wallet"}</span></div>
        ${n?og(i):'<div class="analytics-empty">Activate a wallet to see activity.</div>'}
      </div>

      <div class="analytics-card">
        <div class="analytics-card-hdr"><span class="analytics-card-title">\u{1F4CA} TX Breakdown</span>
          <span class="analytics-badge">${i.length} recent</span></div>
        ${i.length?ig(i):'<div class="analytics-empty-chart"><div class="aec-icon">\u{1F4CA}</div><div>Transaction breakdown builds up as this wallet transacts.</div></div>'}
      </div>

      <div class="analytics-card">
        <div class="analytics-card-hdr"><span class="analytics-card-title">\u{1F4B0} XRP Flow</span>
          <span class="analytics-badge">Est. net</span></div>
        ${n&&i.length?lg(i,n.address):`<div class="analytics-empty-chart"><div class="aec-icon">\u{1F4B0}</div><div>${n?"XRP flow needs at least one transaction to estimate.":"Activate a wallet to see XRP flow."}</div></div>`}
      </div>

      <div class="analytics-card">
        <div class="analytics-card-hdr"><span class="analytics-card-title">\u{1FA99} Token Holdings</span>
          <span class="analytics-badge">${o.length} assets</span></div>
        ${o.length?rg(o):'<div class="analytics-empty-chart"><div class="aec-icon">\u{1FA99}</div><div>No token trustlines held by any wallet yet.</div></div>'}
      </div>
    </div>`}catch(n){Pf(e,"analytics",n)}}}function Vd(e,t,n,s){if(e.length<2)return`<svg width="${t}" height="${n}"><line x1="0" y1="${n/2}" x2="${t}" y2="${n/2}" stroke="${s}" stroke-opacity=".2" stroke-width="1" stroke-dasharray="3 2"/></svg>`;let a=e.map(d=>d.xrp),o=Math.min(...a),i=Math.max(...a),r=i-o||1,l=a.map((d,p)=>`${3+p/(a.length-1)*(t-6)},${3+(1-(d-o)/r)*(n-6)}`),[c,u]=l[l.length-1].split(",");return`<svg width="${t}" height="${n}" viewBox="0 0 ${t} ${n}">
    <polyline points="${l.join(" ")}" fill="none" stroke="${s}" stroke-width="1.5" stroke-opacity=".8" stroke-linejoin="round" stroke-linecap="round"/>
    <circle cx="${c}" cy="${u}" r="2.5" fill="${s}" opacity=".9"/>
  </svg>`}function ag(e){let t=xi(e);if(t.length<2)return`<div class="analytics-empty-chart"><div class="aec-icon">\u{1F4CA}</div><div>Balance history builds up as you refresh your wallet over time.</div><div class="aec-sub">${t.length} snapshot${t.length!==1?"s":""} recorded.</div></div>`;let n=560,s=130,a=52,o=12,i=14,r=30,l=t.map(R=>R.xrp),c=t.map(R=>R.ts),u=Math.min(...l),d=Math.max(...l),p=d-u||1,m=c[0],f=c[c.length-1],g=f-m||1,v=R=>a+(R-m)/g*(n-a-o),h=R=>i+(1-(R-u)/p)*(s-i-r),b=t.map(R=>`${v(R.ts).toFixed(1)},${h(R.xrp).toFixed(1)}`),x=v(c[0]),k=v(c[c.length-1]),T=l[l.length-1]-l[0],S=T>=0,$=l[0]?Math.abs(T/l[0]*100).toFixed(2):"0.00",E=S?"#00d4ff":"#ff5555",C=[u,(u+d)/2,d].map(R=>({v:R,y:h(R),l:_(R,2)})),P=[0,.5,1].map(R=>({x:a+R*(n-a-o),l:new Date(m+R*g).toLocaleDateString("en-US",{month:"short",day:"numeric"})}));return`
    <div class="balance-chart-meta">
      <div class="bcm-current">${_(l[l.length-1],4)} XRP</div>
      <div class="bcm-delta ${S?"bcm-up":"bcm-down"}">${S?"\u25B2":"\u25BC"} ${$}%</div>
      <div class="bcm-range">${t.length} snapshots</div>
    </div>
    <div class="balance-chart-wrap"><svg class="balance-chart-svg" viewBox="0 0 ${n} ${s}" preserveAspectRatio="none">
      <defs><linearGradient id="bg${e.slice(-4)}" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="${E}" stop-opacity=".22"/><stop offset="100%" stop-color="${E}" stop-opacity="0"/></linearGradient></defs>
      ${C.map(R=>`<line x1="${a}" y1="${R.y.toFixed(1)}" x2="${n-o}" y2="${R.y.toFixed(1)}" stroke="rgba(255,255,255,.06)" stroke-width="1"/>`).join("")}
      <path d="M${x.toFixed(1)},${s-r} L${b.join(" L")} L${k.toFixed(1)},${s-r} Z" fill="url(#bg${e.slice(-4)})"/>
      <polyline points="${b.join(" ")}" fill="none" stroke="${E}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      ${t.map(R=>`<circle cx="${v(R.ts).toFixed(1)}" cy="${h(R.xrp).toFixed(1)}" r="2" fill="${E}" opacity=".7"/>`).join("")}
      ${C.map(R=>`<text x="${a-5}" y="${(R.y+4).toFixed(1)}" text-anchor="end" fill="rgba(255,255,255,.38)" font-size="10" font-family="JetBrains Mono,monospace">${R.l}</text>`).join("")}
      ${P.map(R=>`<text x="${R.x.toFixed(1)}" y="${s-6}" text-anchor="middle" fill="rgba(255,255,255,.32)" font-size="10" font-family="JetBrains Mono,monospace">${R.l}</text>`).join("")}
    </svg></div>`}function og(e){if(!e.length)return'<div class="analytics-empty-chart"><div class="aec-icon">\u{1F4C5}</div><div>Activity heatmap fills in as this wallet transacts.</div></div>';let t=new Map;e.forEach(f=>{f.date&&t.set(new Date((f.date+946684800)*1e3).toISOString().slice(0,10),(t.get(new Date((f.date+946684800)*1e3).toISOString().slice(0,10))||0)+1)});let n=26,s=12,a=2,o=new Date,i=Array.from({length:n*7},(f,g)=>{let v=new Date(o);return v.setDate(v.getDate()-(n*7-1-g)),v}),r=Array.from({length:n},(f,g)=>i.slice(g*7,g*7+7)),l=Math.max(1,...t.values()),c=n*(s+a)+30,u=7*(s+a)+28,d=f=>f===0?"rgba(255,255,255,.07)":`rgb(0,${Math.round(85+f*170)},${Math.round(119+f*121)})`,p=[],m=-1;return r.forEach((f,g)=>{var h;let v=(h=f[0])==null?void 0:h.getMonth();v!==m&&(m=v,p.push({wi:g,l:f[0].toLocaleDateString("en-US",{month:"short"})}))}),`<div class="heatmap-meta"><span>${e.length} tx \xB7 ${t.size} active days</span>
    <div class="heatmap-legend"><span>Less</span><div class="heatmap-legend-cells">${[0,.25,.5,.75,1].map(f=>`<div class="hm-leg-cell" style="background:${d(f)}"></div>`).join("")}</div><span>More</span></div>
  </div>
  <div class="heatmap-scroll"><svg class="heatmap-svg" viewBox="0 0 ${c} ${u}" width="${c}" height="${u}">
    ${p.map(({wi:f,l:g})=>`<text x="${26+f*(s+a)}" y="10" font-size="9" fill="rgba(255,255,255,.38)" font-family="Outfit,sans-serif">${g}</text>`).join("")}
    ${["","Mon","","Wed","","Fri",""].map((f,g)=>f?`<text x="0" y="${16+g*(s+a)+s/2+3}" font-size="9" fill="rgba(255,255,255,.3)" font-family="Outfit,sans-serif">${f}</text>`:"").join("")}
    ${r.map((f,g)=>f.map((v,h)=>{let b=v.toISOString().slice(0,10),x=t.get(b)||0;return`<rect x="${26+g*(s+a)}" y="${16+h*(s+a)}" width="${s}" height="${s}" rx="2" fill="${d(x/l)}" opacity="${x>0?.9:.25}"><title>${b}: ${x} tx</title></rect>`}).join("")).join("")}
  </svg></div>`}function ig(e){let t=new Map;e.forEach(a=>t.set(a.TransactionType||"?",(t.get(a.TransactionType||"?")||0)+1));let n=[...t.entries()].sort((a,o)=>o[1]-a[1]),s=e.length;return`<div class="tx-breakdown-list">${n.slice(0,8).map(([a,o])=>`<div class="txb-row"><div class="txb-icon">${Ud(a)}</div><div class="txb-type">${a}</div><div class="txb-bar-wrap"><div class="txb-bar" style="width:${(o/s*100).toFixed(0)}%"></div></div><div class="txb-count">${o}</div></div>`).join("")}</div>`}function rg(e){let t=new Map;e.forEach(o=>{let i=Math.abs(parseFloat(o.balance||0));t.set(o.currency,(t.get(o.currency)||0)+i)});let n=[...t.entries()].sort((o,i)=>i[1]-o[1]).slice(0,8),s=n.reduce((o,[,i])=>o+i,0)||1,a=["#00fff0","#00d4ff","#bd93f9","#50fa7b","#ffb86c","#ff79c6","#f1fa8c","#ff5555"];return`<div class="token-alloc-list">${n.map(([o,i],r)=>{let l=(i/s*100).toFixed(1),c=a[r%a.length],u=o.length>4?o.slice(0,4)+"\u2026":o;return`<div class="ta-row"><div class="ta-swatch" style="background:${c}"></div><div class="ta-cur mono">${u}</div><div class="ta-bar-wrap"><div class="ta-bar" style="width:${l}%;background:${c}20;border-color:${c}55"></div></div><div class="ta-pct">${l}%</div></div>`}).join("")}</div>`}function lg(e,t){let n=0,s=0;e.forEach(i=>{var c,u;if(i.TransactionType!=="Payment"||!((((c=i.metaData)==null?void 0:c.TransactionResult)||((u=i.meta)==null?void 0:u.TransactionResult))==="tesSUCCESS")||typeof i.Amount!="string")return;let l=Number(i.Amount)/1e6;i.Destination===t&&(n+=l),i.Account===t&&(s+=l)});let a=n-s,o=a>=0;return`<div class="xrp-flow-grid">
    <div class="xrf-item xrf-in"><div class="xrf-label">\u2193 Inflow</div><div class="xrf-val">${_(n,4)} XRP</div></div>
    <div class="xrf-item xrf-out"><div class="xrf-label">\u2191 Outflow</div><div class="xrf-val">${_(s,4)} XRP</div></div>
    <div class="xrf-item ${o?"xrf-pos":"xrf-neg"}"><div class="xrf-label">Net</div><div class="xrf-val">${o?"+":""}${_(a,4)} XRP</div></div>
  </div>
  <div class="xrf-note">Based on ${e.length} fetched Payment TXs. Excludes fees and DEX fills.</div>`}async function at(e){var n,s;try{if(((n=X.wsConn)==null?void 0:n.readyState)===1){let{wsSend:a}=await import("./xrpl-6AERZ5KD.js"),o={command:e==null?void 0:e.method,...((s=e==null?void 0:e.params)==null?void 0:s[0])||{}},i=await a(o);if((i==null?void 0:i.status)==="error")throw new Error(i.error_message||i.error||"XRPL RPC error");return(i==null?void 0:i.result)||null}}catch{}let t=async a=>{let o=await fetch(a,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(e),mode:"cors"});if(!o.ok)throw new Error(`HTTP ${o.status}`);return(await o.json()).result};try{return await t(Zm)}catch{return await t(ef)}}async function On(e){var t;try{let n=[],s;do{let l=await at({method:"account_lines",params:[{account:e,ledger_index:"current",limit:400,...s?{marker:s}:{}}]});if(!l||l.error)break;n.push(...l.lines||[]),s=l.marker}while(s);let a=await at({method:"account_info",params:[{account:e,ledger_index:"current"}]});if(a!=null&&a.error)return null;let o=Number(a.account_data.Balance)/1e6,i=n.map(l=>({currency:l.currency,issuer:l.account,balance:l.balance,limit:l.limit}));Ze[e]={xrp:o,tokens:i,fetchedAt:Date.now()},ri[e]=i,dg(e,o);let r=document.getElementById("awb-balance");return r&&e===((t=Et())==null?void 0:t.address)&&Lg(r.querySelector(".awb-xrp-num")||r,o,2,600),Ze[e]}catch{return null}}async function cg(){await Promise.allSettled(oe.map(e=>On(e.address))),$t(),Bt(),Is()}function dg(e,t){let n=ii+e,s=ge(Q(n))||[],a=Date.now();s.length&&a-s[s.length-1].ts<5*6e4?s[s.length-1]={xrp:t,ts:a}:s.push({xrp:t,ts:a}),s.length>90&&s.splice(0,s.length-90),Z(n,JSON.stringify(s))}function xi(e){return ge(Q(ii+e))||[]}async function ki(e,t=25){let n=await at({method:"account_tx",params:[{account:e,limit:t,ledger_index_min:-1,ledger_index_max:-1}]}),s=((n==null?void 0:n.transactions)||[]).map(a=>a.tx||a.transaction||a);return li[e]={txns:s,fetchedAt:Date.now()},s}async function pg(e){let t=await at({method:"account_nfts",params:[{account:e,limit:50}]}),n=(t==null?void 0:t.account_nfts)||[];return Wl[e]={nfts:n,fetchedAt:Date.now()},n}async function ug(e){let t=await at({method:"account_offers",params:[{account:e,limit:50}]}),n=(t==null?void 0:t.offers)||[];return ci[e]={offers:n,fetchedAt:Date.now()},n}async function mg(e){let t=await at({method:"account_info",params:[{account:e,ledger_index:"current"}]});return(t==null?void 0:t.account_data)||null}async function fg(){let e=await at({method:"ledger",params:[{ledger_index:"current"}]});return(e==null?void 0:e.ledger_current_index)||0}function hg(e){let t=(e==null?void 0:e.engine_result)||"";return t==="tesSUCCESS"||t.startsWith("tes")||(e==null?void 0:e.engine_result_code)===0}function gg(e){let t=(e==null?void 0:e.engine_result)||"";return pf[t]||(e==null?void 0:e.engine_result_message)||t||"Unknown error"}async function bg(e,t,n){if(await Na(),!window.xrpl)throw new Error("xrpl.js library not loaded. Cannot sign transactions.");let s=oe.find(i=>i.id===e);if(!s)throw new Error("Wallet not found.");if(s.watchOnly)throw new Error("Watch-only wallets cannot sign transactions.");let a=await ff(s,n),o;try{o=window.xrpl.Wallet.fromSeed(a,{algorithm:s.algo==="secp256k1"?"secp256k1":"ed25519"})}catch(i){throw new Error("Invalid seed phrase: "+i.message)}if(o.classicAddress!==s.address)throw new Error("Seed does not match this wallet address.");try{let[i,r]=await Promise.all([mg(s.address),fg()]);if(!i)throw new Error("Account not found on-chain. Fund with at least 10 XRP first (base reserve requirement).");let l={...t,Account:s.address,Fee:"12",Sequence:i.Sequence,LastLedgerSequence:r+20},{tx_blob:c,hash:u}=o.sign(l);return{...await at({method:"submit",params:[{tx_blob:c}]}),tx_hash:u}}finally{}}async function vg(e,t,n){return bg(e,{TransactionType:"OfferCancel",OfferSequence:parseInt(t)},n)}function yg(){if(w("send-modal-overlay"))return;let e=document.createElement("div");e.innerHTML=`
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
  </div>`,document.body.appendChild(e),["send-modal-overlay","receive-modal-overlay","trustline-modal-overlay","import-address-modal","import-seed-modal","token-details-modal"].forEach(t=>{let n=document.getElementById(t);n==null||n.addEventListener("click",s=>{s.target===n&&(n.classList.remove("show"),n.style.display="")})})}function Gd(){var o;["displayName","handle","bio","location","website"].forEach(i=>{let r=w(`edit-${i}`);r&&(r.value=ce[i]||"")});let e=w("editor-avatar-preview");if(e){let i=localStorage.getItem(un);e.innerHTML=i?`<img src="${i}" class="profile-avatar-img"/>`:ce.avatar||"\u{1F30A}"}let t=w("avatar-remove-btn");t&&(t.style.display=localStorage.getItem(un)?"":"none");let n=w("editor-banner-preview");if(n){let i=localStorage.getItem(In);n.style.backgroundImage=i?`url(${i})`:"",n.style.backgroundSize="cover",n.style.backgroundPosition="center",Rs.forEach(r=>n.classList.remove(r)),i||n.classList.add(ce.banner||"banner-ocean")}let s=w("avatar-picker-grid");s&&(s.innerHTML=lf.map(i=>`<div class="avatar-option ${ce.avatar===i?"active":""}" onclick="selectAvatar('${i}')">${i}</div>`).join(""));let a=w("banner-picker-grid");a&&(a.innerHTML=Rs.map(i=>`<div class="banner-option ${i} ${ce.banner===i?"active":""}" onclick="selectBanner('${i}')"></div>`).join("")),(o=w("profile-editor-modal"))==null||o.classList.add("show")}function Xs(){var e;(e=w("profile-editor-modal"))==null||e.classList.remove("show")}function Kd(){var e,t,n,s,a;ce.displayName=((e=w("edit-displayName"))==null?void 0:e.value.trim())||ce.displayName,ce.handle=(((t=w("edit-handle"))==null?void 0:t.value.trim())||ce.handle).replace(/^@/,"").replace(/\s+/g,"_").toLowerCase(),ce.bio=((n=w("edit-bio"))==null?void 0:n.value.trim())||"",ce.location=((s=w("edit-location"))==null?void 0:s.value.trim())||"",ce.website=((a=w("edit-website"))==null?void 0:a.value.trim())||"",tc(),kt("profile_saved","Profile details updated"),U(),Xs(),ne("Profile saved")}function Jd(e){localStorage.removeItem(un),ce.avatar=e,Xe(".avatar-option").forEach(s=>s.classList.toggle("active",s.textContent===e));let t=w("editor-avatar-preview");t&&(t.innerHTML=e);let n=w("avatar-remove-btn");n&&(n.style.display="none")}function Yd(e){localStorage.removeItem(In),ce.banner=e,Xe(".banner-option").forEach(n=>n.classList.toggle("active",n.classList.contains(e)));let t=w("editor-banner-preview");t&&(t.style.backgroundImage="",Rs.forEach(n=>t.classList.remove(n)),t.classList.add(e)),U()}function Qd(e){var s;let t=(s=e==null?void 0:e.files)==null?void 0:s[0];if(!t)return;if(t.size>2*1024*1024){he("Image too large \u2014 max 2 MB");return}let n=new FileReader;n.onload=a=>{let o=new Image;o.onload=()=>{let i=document.createElement("canvas");i.width=i.height=200;let r=i.getContext("2d"),l=Math.min(o.width,o.height);r.drawImage(o,(o.width-l)/2,(o.height-l)/2,l,l,0,0,200,200);let c=i.toDataURL("image/jpeg",.85);localStorage.setItem(un,c);let u=w("editor-avatar-preview");u&&(u.innerHTML=`<img src="${c}" class="profile-avatar-img"/>`);let d=w("avatar-remove-btn");d&&(d.style.display=""),U(),ne("Profile photo updated")},o.src=a.target.result},n.readAsDataURL(t),e.value=""}function Zd(){localStorage.removeItem(un);let e=w("editor-avatar-preview");e&&(e.innerHTML=ce.avatar||"\u{1F30A}");let t=w("avatar-remove-btn");t&&(t.style.display="none"),U()}function ep(e){var s;let t=(s=e==null?void 0:e.files)==null?void 0:s[0];if(!t)return;if(t.size>5*1024*1024){he("Image too large \u2014 max 5 MB");return}let n=new FileReader;n.onload=a=>{let o=new Image;o.onload=()=>{let i=document.createElement("canvas");i.width=900,i.height=180;let r=i.getContext("2d"),l=Math.max(900/o.width,180/o.height);r.drawImage(o,(900-o.width*l)/2,(180-o.height*l)/2,o.width*l,o.height*l);let c=i.toDataURL("image/jpeg",.88);localStorage.setItem(In,c);let u=w("editor-banner-preview");u&&(u.style.backgroundImage=`url(${c})`,u.style.backgroundSize="cover",u.style.backgroundPosition="center",Rs.forEach(p=>u.classList.remove(p)));let d=w("banner-remove-btn");d&&(d.style.display=""),U(),ne("Banner updated")},o.src=a.target.result},n.readAsDataURL(t),e.value=""}function tp(){localStorage.removeItem(In);let e=w("editor-banner-preview");e&&(e.style.backgroundImage="",Rs.forEach(n=>e.classList.remove(n)),e.classList.add(ce.banner||"banner-ocean"));let t=w("banner-remove-btn");t&&(t.style.display="none"),U()}function wg(){let e=oe.map(({id:n,label:s,address:a,algo:o,emoji:i,color:r,testnet:l,watchOnly:c,createdAt:u})=>({id:n,label:s,address:a,algo:o,emoji:i,color:r,testnet:l,watchOnly:c,createdAt:u})),t=document.createElement("a");t.href="data:application/json;charset=utf-8,"+encodeURIComponent(JSON.stringify(e,null,2)),t.download=`nalulf-wallets-${new Date().toISOString().slice(0,10)}.json`,t.click(),kt("backup_exported","Wallet addresses exported"),ne("Wallet addresses exported")}function np(){wg()}function $i(){var e;wt=1,ve={algo:"ed25519",label:"",emoji:"\u{1F48E}",color:"#50fa7b",seed:"",address:"",passphrase:""},Dn.clear(),Si(1),kg(),xg(),(e=w("wallet-creator-overlay"))==null||e.classList.add("show"),setTimeout(()=>{var t;return(t=w("wallet-label-input"))==null?void 0:t.focus()},80)}function Hs(){var e;(e=w("wallet-creator-overlay"))==null||e.classList.remove("show"),ve.seed=ve.address=ve.passphrase=""}function xg(){let e=w("wizard-security-banner");e&&(e.innerHTML=`<div class="wsb-icon">\u{1F510}</div>
    <div class="wsb-content">
      <div class="wsb-title">Your keys are encrypted on your device</div>
      <div class="wsb-body">Your wallet seed is encrypted with your password using AES-256-GCM before being saved to this device. <strong>It never leaves your browser.</strong></div>
      <div class="wsb-pills">
        <span class="wsb-pill wsb-pill--green">\u{1F512} Local only</span>
        <span class="wsb-pill wsb-pill--green">\u{1F6AB} Never sent to servers</span>
        <span class="wsb-pill wsb-pill--blue">\u26A1 AES-256-GCM</span>
      </div>
    </div>`)}async function sp(){var e,t,n;if(wt===1){let s=(e=w("wallet-label-input"))==null?void 0:e.value.trim(),a=((t=w("wallet-pass-input"))==null?void 0:t.value)||"",o=((n=w("wallet-pass-confirm"))==null?void 0:n.value)||"";if(!s){he("Enter a wallet name.");return}if(a.length<10){he("Use a wallet password with at least 10 characters.");return}if(a!==o){he("Wallet password confirmation does not match.");return}if(ve.label=s,ve.passphrase=a,!$g())return;wt=2}else if(wt===2){if(Dn.size<4){he("Confirm all 4 security checkpoints first.");return}wt=3}else if(wt===3)try{await Tg(),wt=4}catch{return}Si(wt)}function ap(){if(wt<=1){Hs();return}wt--,Si(wt)}function Si(e){var a;[1,2,3,4].forEach(o=>{let i=document.querySelector(`.step-${o}`);i&&(i.classList.toggle("active",o===e),i.classList.toggle("done",o<e))}),Xe(".wizard-panel").forEach(o=>o.classList.remove("active")),(a=w(`wizard-panel-${e}`))==null||a.classList.add("active");let t=w("wizard-back-btn"),n=w("wizard-next-btn"),s=w("wizard-finish-btn");t&&(t.style.display=e===4?"none":"",t.textContent=e===1?"Cancel":"\u2190 Back"),n&&(n.style.display=e>=3?"none":""),s&&(s.style.display=e===3?"":"none")}function kg(){let e=w("wallet-emoji-picker");e&&(e.innerHTML=cf.map(n=>`<div class="wallet-emoji-opt ${ve.emoji===n?"active":""}" onclick="selectWalletEmoji('${n}')">${n}</div>`).join(""));let t=w("wallet-color-picker");t&&(t.innerHTML=df.map(n=>`<div class="color-swatch ${ve.color===n?"active":""}" style="background:${n}" onclick="selectWalletColor('${n}')"></div>`).join(""))}function $g(){var n;if(!((n=window.xrpl)!=null&&n.Wallet))return Wt("xrpl.js is not available yet. Please wait a moment and try again."),Na().catch(()=>{}),!1;try{let s=window.xrpl.Wallet.generate(ve.algo==="ed25519"?"ed25519":"secp256k1");ve.seed=s.seed||"",ve.address=s.classicAddress}catch(s){return Wt("Failed to generate a valid XRPL wallet: "+((s==null?void 0:s.message)||"Unknown error")),!1}let e=w("wizard-seed-value"),t=w("wizard-address-value");return e&&(e.textContent=ve.seed),t&&(t.textContent=ve.address),Dn.clear(),Xe(".security-check").forEach(s=>s.classList.remove("checked")),Xe(".check-box").forEach(s=>s.textContent=""),Sg(),cp(),e&&setTimeout(()=>e.classList.add("blur"),3e4),!0}function Sg(){let e=w("security-checklist-dynamic");if(!e)return;let t=[{icon:"\u270D\uFE0F",title:"Write it on paper right now",body:"Copy your seed phrase onto paper and store it in a safe place. This is your ONLY recovery option if you lose access to this device."},{icon:"\u{1F6AB}",title:"Never store it digitally",body:"No notes apps, emails, screenshots, or cloud drives. A device with a digital copy that gets hacked means instant loss of funds."},{icon:"\u{1F92B}",title:"Never share it with anyone",body:"No legitimate app, exchange, or support team will ever ask for your seed. Anyone who asks is attempting to steal your funds."},{icon:"\u{1F510}",title:"Use a strong unique password",body:"Your password protects the encrypted seed on this device. Use one you don't use anywhere else."}];e.innerHTML=t.map((n,s)=>`
    <div class="security-check security-check-${s+1}" onclick="toggleSecurityCheck(${s+1})">
      <span class="check-box" id="check-box-${s+1}"></span>
      <div class="check-text"><strong>${n.icon} ${y(n.title)}</strong>${y(n.body)}</div>
    </div>`).join("")}async function Tg(){var n;let e=await jl(ve.seed,ve.passphrase),t={id:crypto.randomUUID(),label:ve.label,address:ve.address,algo:ve.algo,emoji:ve.emoji,color:ve.color,testnet:((n=w("wallet-testnet-check"))==null?void 0:n.checked)||!1,watchOnly:!1,encSeed:e,createdAt:new Date().toISOString()};oe.push(t),_s(),dt||(dt=t.id,Z(Ns,t.id)),$t(),Bt(),Ea("wallet-success-address",ve.address),setTimeout(()=>{ve.seed="",ve.address="",ve.passphrase=""},100),kt("wallet_created",ve.label||"New XRPL Wallet"),ne("Wallet created and encrypted locally"),On(t.address).then(()=>$t())}function op(e){ve.algo=e,Xe(".algo-card").forEach(t=>t.classList.toggle("active",t.dataset.algo===e))}function ip(e){ve.emoji=e,Xe(".wallet-emoji-opt").forEach(t=>t.classList.toggle("active",t.textContent===e))}function rp(e){ve.color=e,Xe(".color-swatch").forEach(t=>t.classList.toggle("active",t.style.background===e||t.dataset.color===e))}function lp(e){let t=document.querySelector(`.security-check-${e}`);if(!t)return;let n=t.querySelector(".check-box");Dn.has(e)?(Dn.delete(e),t.classList.remove("checked"),n&&(n.textContent="")):(Dn.add(e),t.classList.add("checked"),n&&(n.textContent="\u2713")),cp()}function cp(){let e=w("wizard-next-btn");e&&wt===2&&(e.disabled=Dn.size<4)}function dp(){var t;(t=w("wizard-seed-value"))==null||t.classList.remove("blur");let e=w("seed-reveal-hint");e&&(e.style.display="none"),setTimeout(()=>{var n;return(n=w("wizard-seed-value"))==null?void 0:n.classList.add("blur")},3e4)}function pp(){let e=w("wizard-seed-value");if(!e)return;Ba(e.textContent,3e4);let t=w("btn-copy-seed");t&&(t.textContent="Copied!",t.classList.add("copied"),setTimeout(()=>{t.textContent="Copy Seed",t.classList.remove("copied")},2e3))}function up(){let e=w("wizard-address-value")||w("wallet-success-address");if(!e)return;Ba(e.textContent);let t=w("btn-copy-addr");t&&(t.textContent="Copied!",t.classList.add("copied"),setTimeout(()=>{t.textContent="Copy",t.classList.remove("copied")},2e3))}function mp(){let e=w("import-address-modal");if(!e)return;e.querySelector("#inp-import-address").value="",e.querySelector("#inp-import-label").value="";let t=e.querySelector("#import-address-error");t&&(t.textContent=""),e.classList.add("show"),setTimeout(()=>{var n;return(n=e.querySelector("#inp-import-address"))==null?void 0:n.focus()},80)}function Ti(){var e;(e=w("import-address-modal"))==null||e.classList.remove("show")}function fp(){var s,a;let e=(((s=w("inp-import-address"))==null?void 0:s.value)||"").trim(),t=(((a=w("inp-import-label"))==null?void 0:a.value)||"").trim()||"Watch Wallet",n=w("import-address-error");if(!He(e)){n&&(n.textContent="Enter a valid XRPL address (starts with r\u2026)");return}if(oe.find(o=>o.address===e)){n&&(n.textContent="This address is already in your list.");return}oe.push({id:"watch_"+Date.now(),label:t,address:e,algo:"\u2014",emoji:"\u{1F441}",color:"#8be9fd",testnet:!1,createdAt:new Date().toISOString(),watchOnly:!0}),_s(),kt("watch_added",`${t} (${e.slice(0,8)}\u2026)`),Ti(),$t(),Bt(),Is(),On(e).then(()=>{$t(),Is()}),ne(`\u{1F441} Watch-only wallet added: ${t}`)}function hp(){let e=w("import-seed-modal");if(!e)return;e.querySelector("#inp-import-seed").value="",e.querySelector("#inp-import-seed-pass").value="",e.querySelector("#inp-import-seed-pass-confirm").value="",e.querySelector("#inp-import-seed-label").value="";let t=e.querySelector("#import-seed-error");t&&(t.textContent=""),e.classList.add("show"),setTimeout(()=>{var n;return(n=e.querySelector("#inp-import-seed"))==null?void 0:n.focus()},80)}function Ci(){var e;(e=w("import-seed-modal"))==null||e.classList.remove("show")}async function gp(){var r,l,c,u,d;let e=(((r=w("inp-import-seed"))==null?void 0:r.value)||"").trim(),t=(((l=w("inp-import-seed-label"))==null?void 0:l.value)||"").trim()||"Imported Wallet",n=(((c=w("inp-import-seed-pass"))==null?void 0:c.value)||"").trim(),s=(((u=w("inp-import-seed-pass-confirm"))==null?void 0:u.value)||"").trim(),a=w("import-seed-error"),o=w("import-seed-btn"),i=p=>{a&&(a.textContent=p)};if(i(""),!e)return i("Enter your seed phrase.");if(n.length<10)return i("Use a wallet password with at least 10 characters.");if(n!==s)return i("Wallet password confirmation does not match.");if(await Na(),!window.xrpl)return i("xrpl.js not loaded \u2014 cannot derive address from seed.");o&&(o.disabled=!0,o.textContent="Importing\u2026");try{let p=window.xrpl.Wallet.fromSeed(e),m=p.address,f=(d=p.algorithm)!=null&&d.toLowerCase().includes("ed")?"ed25519":"secp256k1";if(oe.find(x=>x.address===m))return i("This address is already in your vault.");let g="imp_"+Date.now(),v="\u{1F511}",h="#bd93f9",b=await jl(e,n);oe.push({id:g,label:t,address:m,algo:f,emoji:v,color:h,testnet:!1,watchOnly:!1,encSeed:b,createdAt:new Date().toISOString()}),_s(),kt("wallet_imported",`${t} (${m.slice(0,8)}\u2026)`),Ci(),$t(),Bt(),On(m).then(()=>{$t(),Is()}),ne(`\u{1F511} Wallet imported: ${t}`)}catch(p){i("Invalid seed: "+(p.message||"Could not derive wallet."))}finally{o&&(o.disabled=!1,o.textContent="Import Wallet \u2192");let p=document.getElementById("inp-import-seed");p&&(p.value="");let m=document.getElementById("inp-import-seed-pass");m&&(m.value="");let f=document.getElementById("inp-import-seed-pass-confirm");f&&(f.value="")}}function bp(e,t,n){var u;let s=w("token-details-modal");if(!s)return;let a=s.querySelector(".generic-modal");if(!a)return;let o=Ze[n],i=(u=o==null?void 0:o.tokens)==null?void 0:u.find(d=>d.currency===e&&d.issuer===t),r=i?_(parseFloat(i.balance||0),6):"\u2014",l=i!=null&&i.limit?_(parseFloat(i.limit),2):"Unlimited",c=e.length>4&&Pi(e)||e;a.innerHTML=`
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
    </div>`,s.classList.add("show")}function vp(){let e=w("token-details-modal");e&&(e.classList.remove("show"),e.style.display="")}function yp(){var s;(s=document.getElementById("pub-profile-overlay"))==null||s.remove();let e=localStorage.getItem(un),t=as.filter(a=>Je[a.id]),n=document.createElement("div");n.id="pub-profile-overlay",n.className="pub-profile-overlay",n.innerHTML=`
    <div class="pub-profile-modal">
      <div class="pub-banner ${ce.banner||"banner-ocean"}" ${localStorage.getItem(In)?`style="background-image:url(${localStorage.getItem(In)});background-size:cover;background-position:center;"`:""}>
      </div>
      <div class="pub-hdr">
        <div class="pub-avatar">${e?`<img src="${e}" alt="avatar"/>`:`<span>${y(ce.avatar||"\u{1F30A}")}</span>`}</div>
        <div class="pub-info">
          <div class="pub-name">${y(ce.displayName||"Anonymous")}</div>
          <div class="pub-handle">@${y(ce.handle||"anonymous")}</div>
          ${ce.bio?`<div class="pub-bio">${y(ce.bio)}</div>`:""}
          <div class="vault-pill vault-pill--locked" style="font-size:.65rem;padding:3px 9px">\u{1F512} Self-custodied XRPL wallet</div>
        </div>
      </div>
      ${t.length?`<div class="pub-socials">${t.map(a=>`<span class="pub-social-badge"><span>${a.icon}</span><span>@${y(Je[a.id])}</span></span>`).join("")}</div>`:'<div style="padding:0 20px 16px;font-size:.82rem;color:rgba(255,255,255,.3)">No social accounts connected yet.</div>'}
      <div class="pub-close-row">
        <span style="font-size:.78rem;color:rgba(255,255,255,.32);flex:1">This is how others see your profile</span>
        <button class="pub-close-btn" onclick="document.getElementById('pub-profile-overlay').remove()">Close</button>
      </div>
    </div>`,document.body.appendChild(n),requestAnimationFrame(()=>requestAnimationFrame(()=>n.classList.add("show"))),n.addEventListener("click",a=>{a.target===n&&n.remove()})}function wp(e){Pn(e),Bs(),kt("theme_changed",e)}function xp(e){Z("nalulf_pref_currency",e),Bs(),ne(`Display currency: ${e}`)}function kp(e){Z("nalulf_pref_network",e),Bs(),ne(`Default network: ${e}`)}function $p(e){Z("nalulf_pref_autolock",e),Bs(),ne(`Auto-lock: ${e} minutes`)}window._profileWipeAllData=()=>{confirm("Clear all profile, wallet list, social, and activity data? Encrypted wallet seeds saved on this device will be deleted.")&&(["nalulf_profile","nalulf_wallets","nalulf_social","nalulf_activity_log","nalulf_avatar_img","nalulf_banner_img","naluxrp_active_wallet"].forEach(e=>localStorage.removeItem(e)),oe=[],Je={},dt=null,Ze={},ri={},Qo(),U(),ui("wallets"),ne("Local data cleared"))};function Cg(){var e,t,n;(e=w("profile-editor-modal"))==null||e.addEventListener("click",s=>{s.target===s.currentTarget&&Xs()}),(t=w("wallet-creator-overlay"))==null||t.addEventListener("click",s=>{s.target===s.currentTarget&&Hs()}),(n=w("social-modal"))==null||n.addEventListener("click",s=>{s.target===s.currentTarget&&is()})}function Pg(){let e=[{done:!!ce.displayName&&ce.displayName!=="Anonymous",label:"Display name"},{done:!!ce.bio,label:"Bio"},{done:ce.avatar!=="\u{1F30A}"||!!localStorage.getItem(un),label:"Custom avatar"},{done:!!localStorage.getItem(In),label:"Custom banner"},{done:oe.length>0,label:"Wallet added"},{done:Object.keys(Je).length>=1,label:"Social connected"},{done:!!ce.location,label:"Location set"},{done:!!ce.website,label:"Website added"}],t=e.filter(n=>n.done).length;return{pct:Math.round(t/e.length*100),done:t,total:e.length,checks:e}}function Mg(){let e=document.getElementById("profile-completeness");if(!e)return;let{pct:t,checks:n}=Pg(),s=t===100?"#50fa7b":t>=60?"#00fff0":"#ffb86c",a=2*Math.PI*16,o=t/100*a,i=n.filter(r=>!r.done).map(r=>r.label);e.title=t===100?"Profile complete \u2713":`${t}% \u2014 Missing: ${i.join(", ")}`,e.innerHTML=`
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
    </div>`}function Lg(e,t,n=2,s=700){if(!e)return;let a=performance.now(),o=parseFloat(e.textContent.replace(/[^0-9.]/g,""))||0;if(Math.abs(t-o)<.001){e.textContent=_(t,n);return}let i=r=>{let l=Math.min((r-a)/s,1),c=l<.5?2*l*l:-1+(4-2*l)*l;e.textContent=_(o+(t-o)*c,n),l<1?requestAnimationFrame(i):e.textContent=_(t,n)};requestAnimationFrame(i)}window._profileSetTokenSearch=e=>{let t=e.toLowerCase();document.querySelectorAll(".wdd-token-row").forEach(n=>{n.style.display=n.textContent.toLowerCase().includes(t)?"":"none"})};function Ea(e,t){let n=w(e);n&&(n.textContent=String(t))}function zs(e){Ba(e)}function Ba(e,t=0){var a;if(!!((a=navigator.clipboard)!=null&&a.writeText)&&document.hasFocus()){navigator.clipboard.writeText(e).then(()=>{ne("Copied to clipboard"),t&&setTimeout(()=>{var o;document.hasFocus()&&((o=navigator.clipboard)!=null&&o.writeText)&&navigator.clipboard.writeText("").catch(()=>{})},t)}).catch(()=>{let o=document.createElement("textarea");o.value=e,document.body.appendChild(o),o.select(),document.execCommand("copy"),o.remove(),ne("Copied")});return}let s=document.createElement("textarea");s.value=e,document.body.appendChild(s),s.select(),document.execCommand("copy"),s.remove(),ne("Copied")}function Pi(e){if(!/^[0-9A-Fa-f]+$/.test(e))return"";try{let t="";for(let n=0;n<e.length;n+=2)t+=String.fromCharCode(parseInt(e.slice(n,n+2),16));return t.replace(/\x00/g,"").trim()}catch{return""}}var Ag=[{cat:"App",term:"Live Stream",body:"A real-time feed of the XRP Ledger as it closes \u2014 new ledgers, transaction volume, and network metrics as they happen. No refresh needed."},{cat:"App",term:"Inspector",body:"Full forensic analysis of any XRPL address, yours or anyone else's: trust lines, fund flow tracking, and a multi-engine Forensic Analytics Suite that looks for non-organic behavior patterns."},{cat:"App",term:"Network Health",body:"Live validator and node health \u2014 latency probing across public XRPL endpoints, so you can see which server is actually fastest to connect to right now."},{cat:"App",term:"Project Intelligence",body:"Token-level analysis for any issued asset: liquidity depth (AMM + live order book), holder concentration, LP token concentration, and issuer risk flags, rolled into one inspectable Strength score."},{cat:"App",term:"Portfolio Analytics",body:"Balance history, an activity heatmap, and fund-flow breakdowns for your own wallets \u2014 under Profile."},{cat:"App",term:"Command Palette (Ctrl+K)",body:"Press Ctrl+K (or /) from anywhere to jump to any page instantly. Paste in an XRPL address and it offers to inspect it directly, without navigating first."},{cat:"App",term:"Wallet Vault",body:"Your keys are encrypted client-side with AES-256-GCM (PBKDF2, 150,000 iterations) and never leave your device. There is no server that could be breached to expose them \u2014 which also means there's no password reset if you forget your vault password without a backup."},{cat:"On-Chain",term:"Trustline",body:"A trustline is what lets an account hold a token that isn't XRP. You must explicitly create one to a token's issuer before you can receive that token \u2014 this is an XRPL-specific safeguard against unwanted tokens landing in your wallet."},{cat:"On-Chain",term:"AMM / Liquidity Pool",body:"An Automated Market Maker pool holds reserves of two assets (e.g. XRP and a token) and prices trades algorithmically based on the ratio between them. Deeper reserves generally mean less price impact per trade."},{cat:"On-Chain",term:"Order Book Depth / Slippage",body:"How much of an asset is actually available to buy or sell at each price level on the live DEX order book. Thin depth means a modest-sized trade can move the price a lot \u2014 that price movement is slippage."},{cat:"On-Chain",term:"Holder Concentration",body:"What percentage of a token's total supply sits in the top 1, 5, or 10 wallets. High concentration means a small number of holders could crash the price by selling \u2014 a common signal used to spot rug-pull risk."},{cat:"On-Chain",term:"LP Token Concentration",body:`AMM pools issue their own "LP tokens" representing a share of the pool. If a handful of addresses hold most of the LP tokens, they can pull most of the pool's liquidity out at once, collapsing tradability.`},{cat:"On-Chain",term:"Issuer",body:`The XRPL account that created a token and controls certain settings on it (freeze, clawback, auth requirements). Every issued token has exactly one issuer address \u2014 it's effectively that token's "admin account."`},{cat:"On-Chain",term:"Clawback",body:xt.clawbackEnabled},{cat:"On-Chain",term:"Global Freeze",body:xt.globalFreeze},{cat:"On-Chain",term:"Freeze-Capable",body:xt.freezeCapable},{cat:"On-Chain",term:"Require Auth",body:xt.requireAuth},{cat:"On-Chain",term:"Blackholed / Black Hole Address",body:xt.blackholed},{cat:"On-Chain",term:"Fund Flow",body:"Where XRP actually goes after leaving a wallet \u2014 tracing outbound payments to their destinations, flagging known exchanges, black-hole addresses, and brand-new wallets receiving large transfers (a common drain-attack pattern)."},{cat:"On-Chain",term:"Convergence Signal",body:`The Forensic Analytics Suite runs several independent detection engines. When two or more flag the same address using unrelated methods, that agreement ("convergence") is a stronger signal than any single engine alone \u2014 a single flag can be a false positive, convergence usually isn't.`}],Xa="";function Sp(){let e=w("helpOverlay"),t=w("helpInput");!e||!t||(e.classList.add("show"),Xa="",t.value="",Cp(),t.focus())}function Ha(){var e;(e=w("helpOverlay"))==null||e.classList.remove("show")}function Mi(e){Xa=e,Cp()}function Tp(){let e=w("helpOverlay"),t=w("helpInput");!e||!t||(t.addEventListener("input",()=>Mi(t.value)),e.addEventListener("click",n=>{n.target===e&&Ha()}))}function Eg(e,t){return t?`${e.term} ${e.body}`.toLowerCase().includes(t):!0}function Cp(){let e=w("helpList");if(!e)return;let t=Xa.toLowerCase().trim(),n=Ag.filter(o=>Eg(o,t));if(!n.length){e.innerHTML=`<div class="help-empty">No matches for "${y(Xa)}".</div>`;return}let s=["App","On-Chain"],a={App:"App Features","On-Chain":"On-Chain & Forensic Concepts"};e.innerHTML=s.map(o=>{let i=n.filter(r=>r.cat===o);return i.length?`
      <div class="help-cat-label">${y(a[o])}</div>
      ${i.map(r=>`
        <div class="help-entry">
          <div class="help-term">${y(r.term)}</div>
          <div class="help-body">${y(r.body)}</div>
        </div>`).join("")}`:""}).join("")}var Ng=180,Qt=12,Pp=5,Mp="naluxrp_compact_mode",Rg=1e5,_g=18,Li=16,Dg=96,Lp=96,Ig=96,Fg=5*6e4,za=72,Ap=80,Og=1e4,Bg=20,Js=8,ou=3,iu=.7,Ri=.35,Va=12,gs=10,bs=2,ds=61e3,fn="NALU-SPAM-PROOF:",ru="naluxrp_spam_verified",lu="naluxrp_spam_allowlist",cu=new Set(["rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy","rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B","rrpNnNLKrartuEqfJGpqyDwPj1BBN1ih7","rN7n3473SaZBCG4dFL83w7PB9judJ7qdDo","rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh","rBKPS4oLSaV2KVVuHH8EpQqMGgGefGFQs7","rfk5bwaKCoNU84fTzdqWQowqnNaZorDmiV","rGFuMiw48HdbnrUbkRYDTvT5i9imC5fvv9","rwYHCs2EYBMBvRXFmxDrCUSorPsuqCck7t","rLHzPsX6oXkzU2qL12kHCH8G8cnZv1rBJh","ra5nK24KXen9AHvsdFTKHSANinZseWnPcX","rGWrZyax5eXbi5gs49MRZKkE9eKNL9p4B","rHsMUQFzBb7S6GnQFVgNirqvHRcLpAn5dU","rDsbeomae4FXwgQTJp9Rs64Qg9vDiTCdBv","rMQ98K56yXJbDGv49ZSmW51sLn94Xe1mu1","rKiCet8SdvWxPXnAgYarFUXMh1zCPz432Y","r9mhdcT2K7FdCGDEPqfbMJwVXsXCqEr5bP","r4GDFMLGJUKMjNEycBKPGnRSNXyNVLQLHi","rUA1S9qobBkxLqzdfGEzh5wm5KdLfbf8bx","rHtbQzmN4BDaEBnGSXp3AZaZAuZamNVsME","rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq","razqnFn6FqBaYBdNaGnVzmGaNE6XPRQ9bG","rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh","r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59","rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY","rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz"]),fe={dexPressure:[],nftMints:[],nftBurns:[],autoBridge:[],marketPrice:[],marketVol:[]},mn=null,Ai=0,Nt={acct:new Map},Us={window:[],totals:new Map,maxLedgers:12},Re={window:[],smoothCancelPerMin:null,smoothBurst:null},ie={byAddr:new Map,selectedAddr:null,selectedProof:null,allowList:new Set,verifiedCache:new Map},Ep=!1,Np=!1,Rp=!1,_i=!1,_p=!1,Dp=!1,Ip=!1,Fp=!1,Op=!1,Bp=!1,Xp=!1,Hp=!1,zp=!1,jp=!1,Wp=!1,Up=!1,qp=!1,Vp=!1,Bn=!1,Vs=!1,Di={};var Ii=new Map;function ja(e,t,n=2){let s=Ii.get(e)??-999;return Number(t)-s<n?!1:(Ii.set(e,Number(t)),!0)}var et={ledgersProcessed:0,startTime:Date.now(),totalTx:0,whaleCount:0,feeSpikes:0,botDetections:0,dexAlerts:0},_t=[],Xg=40,Xn={whaleTxXrp:1e5,feeSpikeMultiple:5,botCvThreshold:.2,dexCancelAlert:.75,clusterMinSize:5},du=0,Ja="naluxrp_widget_order",vs="naluxrp_widget_hidden",rs=null,Gt=!1,Gp=!1,pu=!0;function Yt(){return pu&&X.currentPage==="dashboard"&&X.currentTab==="stream"&&!document.hidden}var ps=[],Hg=30,zg=0;function uu(){Yg(),Zg(),zb(),Ub(),ab(),cb(),Rb(),_b(),ob(),qg(),Vg(),sv(),Db(),Ob(),Xb(),rv(),cv(),pv(),Yt()&&Za(),vv(),yv(),fv(),wv(),xv(),kv(),window.addEventListener("xrpl-connection",e=>{var n,s;let t=!!((n=e==null?void 0:e.detail)!=null&&n.connected);if(t&&mb(),((s=e==null?void 0:e.detail)==null?void 0:s.state)==="connecting"){Qa(!0,"Switching networks\u2026");let a=w("tx-mix");a&&(a.innerHTML='<div class="loading-row"><div class="spinner"></div> Accumulating\u2026</div>')}else t&&Qa(!1)}),window.addEventListener("xrpl-ledger",e=>{if(!Yt())return;let t=e.detail,n=Number(t.ledgerIndex||0);et.ledgersProcessed++,et.totalTx+=Number(t.txPerLedger||0),["risk-badge","risk-regime","risk-friction","risk-signalcount","landscape-badge","dexp-badge","dexP-badge","ab-badge","nft-badge","whale-badge","ss-badge","health-badge","pattern-badge"].forEach(a=>delete Di[a]),eb(t),ib(),sb(),rb(),hb(t.latestLedger),iv(t.recentTransactions||[],n);let s=yb(t);for(ps.push({li:n,friction:s.friction,regime:s.regime});ps.length>Hg;)ps.shift();Tu(),!Gt&&(ja("breadcrumbs",n,1)&&Ab(s.breadcrumbs),ja("clusters",n,2)&&Eb(s.clusters),ja("narratives",n,2)&&Nb(s.narratives),ja("landscape",n,3)&&Ib(s),av(t.txTypes,s.hhi),Bb(s.dexPatterns),Hb(s),Wb(s),Vb(s),uv(),n-du>=8&&mv(s,n))}),document.addEventListener("visibilitychange",()=>{Yt()?Za():ji()})}function mu(e){pu=!!e,Yt()?Za():ji()}function V(e,t){let n=w(e);n&&(n.textContent=String(t))}function we(e,t,n){return Math.max(t,Math.min(n,e))}function bn(e){return e!=null&&e.length?e.reduce((t,n)=>t+n,0)/e.length:null}function zi(e){if(!e||e.length<2)return null;let t=bn(e),n=bn(e.map(s=>(s-t)**2));return Math.sqrt(n)}function jg(e,t){return e!=null&&e.length?e.slice(Math.max(0,e.length-t)):[]}function Wg(e,t){let n=[];for(let s=0;s<e.length;s++){let a=Math.max(0,s-t+1);n.push(bn(e.slice(a,s+1)))}return n}function vn(e,t=0){return e==null||!Number.isFinite(e)?"\u2014":`${e>=0?"\u2191":"\u2193"}${Math.abs(e).toFixed(t)}%`}function ls(e,t=2){return e==null||!Number.isFinite(e)?"\u2014":Number(e).toFixed(t)}function hn(e){if(e==null||!Number.isFinite(e))return"\u2014";let t=Number(e);return t===0?"0 XRP":t>=1e3?`${t.toLocaleString(void 0,{maximumFractionDigits:2})} XRP`:t>=1?`${t.toFixed(4)} XRP`:t>=.01?`${t.toFixed(5)} XRP`:`${t.toFixed(6)} XRP`}function us(e,t=1){if(!e)return null;let n=we(Number(t),0,1),s=String(e).trim();if(s.startsWith("rgba("))return s;if(s.startsWith("rgb(")){let a=s.match(/^rgb\(\s*([0-9]+)\s*,\s*([0-9]+)\s*,\s*([0-9]+)\s*\)$/i);if(!a)return null;let o=we(Number(a[1]),0,255),i=we(Number(a[2]),0,255),r=we(Number(a[3]),0,255);return`rgba(${o},${i},${r},${n})`}if(s[0]==="#"){let a=s.slice(1);if(a.length===3&&(a=a.split("").map(l=>l+l).join("")),a.length!==6)return null;let o=parseInt(a.slice(0,2),16),i=parseInt(a.slice(2,4),16),r=parseInt(a.slice(4,6),16);return[o,i,r].every(Number.isFinite)?`rgba(${o},${i},${r},${n})`:null}return null}function Kp(e,t,n=.45){return t==null||!Number.isFinite(t)?e:e==null||!Number.isFinite(e)?t:e*(1-n)+t*n}async function Ug(e){if(typeof crypto<"u"&&crypto.subtle){let n=new TextEncoder().encode(e),s=await crypto.subtle.digest("SHA-512",n),a=new Uint8Array(s,0,32);return Array.from(a).map(o=>o.toString(16).padStart(2,"0")).join("")}let t=0x811c9dc5n;for(let n=0;n<e.length;n++)t^=BigInt(e.charCodeAt(n)),t=BigInt.asUintN(32,t*0x01000193n);return"FALLBACK-NON-CRYPTO-"+t.toString(16).padStart(8,"0").repeat(4).slice(0,44)}function qg(){var n,s;if(Hp||(Hp=!0,document.getElementById("acctPeekOverlay")))return;let e=document.createElement("div");e.id="acctPeekOverlay",e.className="acct-peek-overlay",e.style.display="none",e.innerHTML=`
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
  `,document.body.appendChild(e);let t=()=>{e.style.display="none",e.removeAttribute("data-addr"),document.body.classList.remove("modal-open"),Vs=!1,Rt=!1};e.addEventListener("click",a=>{a.target===e&&t()}),(n=w("acctPeekClose"))==null||n.addEventListener("click",t),(s=w("acctPeekInspect"))==null||s.addEventListener("click",async()=>{let a=e.getAttribute("data-addr");a&&await Jg(a),t()})}function Vg(){Xp||(Xp=!0,document.addEventListener("click",e=>{var s,a;let t=(a=(s=e.target).closest)==null?void 0:a.call(s,"[data-addr]");if(!t)return;let n=t.getAttribute("data-addr");n&&(e.preventDefault(),Kg(n))}))}function Jp(e){var r,l,c;if(!e||!((r=Re==null?void 0:Re.window)!=null&&r.length))return null;let t=0,n=0,s=0;for(let u of Re.window)s+=Number(u.total||0),t+=Number(((l=u.byActorCreate)==null?void 0:l.get(e))||0),n+=Number(((c=u.byActorCancel)==null?void 0:c.get(e))||0);let a=t+n;if(!a)return null;let o=a?n/a:0,i=s?a/s:null;return{create:t,cancel:n,total:a,cancelRatio:o,share:i}}function Gg(e){var o;let t=(o=Nt==null?void 0:Nt.acct)==null?void 0:o.get(e);if(!t||!t.intervals||t.intervals.length<6)return null;let n=bn(t.intervals),s=zi(t.intervals);return!n||s==null?null:{cv:s/n,total:t.total||0}}async function Kg(e){var i,r,l;if(!He(e))return;let t=document.getElementById("acctPeekOverlay");if(!t)return;t.style.display="flex",t.setAttribute("data-addr",e),document.body.classList.add("modal-open"),Vs=!0,Rt=!0,V("acctPeekAddr",e),V("acctPeekBal","\u2026"),V("acctPeekSeq","\u2026"),V("acctPeekOwner","\u2026"),V("acctPeekFlags","\u2026");let n=w("acctPeekNote"),s=w("acctPeekCtx");n&&(n.textContent="Fetching account_info\u2026"),s&&(s.textContent="Building context\u2026");let a=Nt.acct.get(e),o=((i=a==null?void 0:a.ledgers)==null?void 0:i.length)||0;try{if(!X.wsConn||X.wsConn.readyState!==1){n&&(n.textContent="Not connected to XRPL. Connect first.");return}let c=await Ee({command:"account_info",account:e,ledger_index:"validated",strict:!0}),u=(r=c==null?void 0:c.result)==null?void 0:r.account_data,d=Number((u==null?void 0:u.Balance)??NaN),p=Number.isFinite(d)?d/1e6:null;if(V("acctPeekBal",p==null?"\u2014":`${p.toLocaleString(void 0,{maximumFractionDigits:6})} XRP`),V("acctPeekSeq",(u==null?void 0:u.Sequence)??"\u2014"),V("acctPeekOwner",(u==null?void 0:u.OwnerCount)??"\u2014"),V("acctPeekFlags",(u==null?void 0:u.Flags)!=null?`0x${Number(u.Flags).toString(16)}`:"\u2014"),n){let m=[];p!=null&&p>=Rg&&m.push("Large balance (whale-sized).");let f=Gg(e);f&&f.cv<.35&&f.total>10&&m.push(`Bot-like timing signal (CV ${f.cv.toFixed(2)}).`);let g=Jp(e);if(g){let h=Math.round(g.cancelRatio*100),b=g.share!=null?Math.round(g.share*100):null;m.push(`DEX activity: ${g.total} offer tx in window.`),m.push(`Creates ${g.create}, cancels ${g.cancel} (${h}% cancels).`),b!=null&&m.push(`~${b}% of window activity.`)}let v=ie.byAddr.get(e);if(v){let h=Gs(v.level);m.push(`Spam-defense: score ${(v.score*100).toFixed(0)}% \xB7 level L${v.level} \xB7 bond ${h.toLocaleString()} XRP.`),v.verifiedLedger!=null&&m.push(`Credential verified at ledger #${Number(v.verifiedLedger).toLocaleString()}.`)}o>=6&&m.push(`Shows up often in recent ledgers (${o} times).`),m.length||m.push("No obvious red flags from this quick read."),n.textContent=m.join(" ")}if(s){let m=(l=a==null?void 0:a.ledgers)==null?void 0:l.at(-1),f=Jp(e),g=f?`DEX window: ${f.total} (creates ${f.create}, cancels ${f.cancel})`:null,v=_t.filter(k=>k.from===e||k.to===e).slice(0,3),h=v.length?`${v.length} whale tx in session (${v.map(k=>(k.amtXrp>=1e6?(k.amtXrp/1e6).toFixed(1)+"M":(k.amtXrp/1e3).toFixed(0)+"K")+" XRP").join(", ")})`:null,b=ie.byAddr.get(e),x=b?`Spam-defense: L${b.level} \xB7 score ${Math.round(b.score*100)}%`:null;s.textContent=[m?`Last seen around ledger #${Number(m).toLocaleString()}`:"Not in recent window.",g,h,x].filter(Boolean).join(" \xB7 ")}}catch(c){n&&(n.textContent=`Lookup failed: ${String((c==null?void 0:c.message)||c)}`),s&&(s.textContent="\u2014")}}async function Jg(e){if(!He(e))return;let t=document.querySelector('.dash-tab[data-tab="inspector"]'),n=document.getElementById("tab-inspector"),s=async()=>n&&n.style.display!=="none"?!0:(typeof window.switchTab=="function"&&t?window.switchTab(t,"inspector"):t==null||t.click(),await new Promise(o=>setTimeout(o,80)),n?n.style.display!=="none":!0);for(let o=0;o<6&&!await s();o++)await new Promise(r=>setTimeout(r,80));let a=document.getElementById("inspect-addr");a&&(a.value=e,a.focus()),await new Promise(o=>setTimeout(o,60)),typeof window.runInspect=="function"?window.runInspect():he("Inspector not ready yet.")}function Yg(){Xe(".net-btn[data-network]").forEach(e=>{e.addEventListener("click",()=>{let t=e.getAttribute("data-network");Xe(".net-btn").forEach(s=>{s.classList.toggle("active",s===e),s.setAttribute("aria-pressed",String(s===e))}),Nt.acct.clear(),Us.window=[],Us.totals=new Map,Re.window=[],Re.smoothCancelPerMin=null,Re.smoothBurst=null,Xt.length=0,Ka.clear(),Ge=0,Kt=0,pt=0,Ws=0,Jt=!0,Ya=0,Oi=!1,qs=null,Rt=!1,gn=0,ms=0,eo=!1;let n=w("ledgerStreamTrack");n&&(n.innerHTML="",n.style.transform="translateX(0px)"),vu(null,null),jb(),ie.byAddr.clear(),ie.selectedAddr=null,ie.selectedProof=null,Wi(),$u(),hs(null),Hr(t),Za({force:!0})})})}var Ga=[],Qg=8,Ei=null,Fi=0,js=null;function Zg(){let e=document.querySelector(".dashboard-metric-grid");if(!e)return;let t=e.closest(".dashboard-metrics")||e.parentElement;t&&t.classList.add("dashboard-sticky-strip"),e.innerHTML=`
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
  `}function eb(e){var g,v,h,b;let t=e.ledgerIndex?Number(e.ledgerIndex):null;V("d2-ledger-index",t?t.toLocaleString():"\u2014");let n=((g=e.latestLedger)==null?void 0:g.closeTimeSec)!=null?Number(e.latestLedger.closeTimeSec):null,s=w("d2-ledger-age");if(s&&(n!=null?(s.textContent=`${n<2?n.toFixed(2):n.toFixed(1)}s close`,s.style.color=n<=3?"#50fa7b":n<=6?"#ffb86c":"#ff6e6e"):(s.textContent="Waiting\u2026",s.style.color="")),n!=null&&(Ga.push(n),Ga.length>Qg&&Ga.shift(),tb()),Fi=Date.now(),nb(),e.tps!=null){let x=Number(e.tps),k=w("d2-tps");k&&(k.textContent=x.toFixed(1),k.style.color=x<10?"rgba(255,255,255,.65)":x<40?"#50fa7b":x<80?"#ffb86c":"#ff6e6e");let T=w("d2-tps-trend");if(T){let S=X.tpsHistory||[],$=S.length>2?(S.slice(-10).reduce((C,P)=>C+P,0)/Math.min(S.length,10)).toFixed(1):null,E=x<10?"Low":x<40?"Normal":x<80?"High":"Peak";T.textContent=$?`${E} \xB7 avg ${$}`:E,T.style.color=x<10?"rgba(255,255,255,.55)":x<40?"#50fa7b":x<80?"#ffb86c":"#ff6e6e"}}let a=(((v=e.latestLedger)==null?void 0:v.totalTx)??e.txPerLedger)||0,o=w("d2-tx-per-ledger");o&&(o.textContent=a>0?a.toLocaleString():"\u2014",o.style.color=a<10?"rgba(255,255,255,.65)":a<150?"#50fa7b":a<400?"#ffb86c":"#ff6e6e");let i=w("d2-tx-spread");i&&a>0&&(i.textContent=a<10?"Very light":a<50?"Light":a<150?"Normal":a<400?"High volume":"Very high volume",i.style.color=a<150?"":a<400?"#ffb86c":"#ff6e6e");let r=e.avgFee!=null?Number(e.avgFee):((h=e.latestLedger)==null?void 0:h.avgFee)!=null?Number(e.latestLedger.avgFee):null;if(r!=null){let x=Math.round(r*1e6),k=w("d2-fee-value");k&&(k.textContent=hn(r),k.style.color=x<=15?"#50fa7b":x<=50?"rgba(255,255,255,.9)":x<=200?"#ffb86c":"#ff6e6e");let T=w("d2-fee-delta");if(T)if(Ei!=null){let $=r/Ei;$>1.05?(T.textContent="\u2191",T.style.color="#ff6e6e",T.title=`+${(($-1)*100).toFixed(0)}% vs prev ledger`):$<.95?(T.textContent="\u2193",T.style.color="#50fa7b",T.title=`-${((1-$)*100).toFixed(0)}% vs prev ledger`):(T.textContent="\u2192",T.style.color="rgba(255,255,255,.35)",T.title="Stable vs prev ledger")}else T.textContent="";Ei=r;let S=w("d2-fee-pressure");if(S){let $=x<=15?"Base fee":x<=50?`${x} drops`:x<=200?`${x} drops \xB7 Elevated`:`${x} drops \xB7 Surge`;S.textContent=$,S.style.color=x<=50?"":x<=200?"#ffb86c":"#ff6e6e"}}let l=e.successRate!=null?Number(e.successRate):((b=e.latestLedger)==null?void 0:b.successRate)!=null?Number(e.latestLedger.successRate):null;if(l!=null){let x=w("d2-success-rate");x&&(x.textContent=`${l.toFixed(1)}%`,x.style.color=l>=90?"#50fa7b":l>=75?"#ffb86c":"#ff6e6e");let k=w("d2-success-note");if(k){let T=(100-l).toFixed(1);k.textContent=l>=90?`${T}% failed \xB7 Normal`:l>=75?`${T}% failed \xB7 Watch`:`${T}% failed \xB7 Alert`,k.style.color=l>=90?"":l>=75?"#ffb86c":"#ff6e6e"}}let c=a>0?Math.min(100,a/500*100):null,u=w("d2-network-capacity"),d=w("d2-capacity-note");c!=null&&(u&&(u.textContent=`${c.toFixed(1)}%`,u.style.color=c<20?"rgba(255,255,255,.65)":c<50?"#50fa7b":c<80?"#ffb86c":"#ff6e6e"),d&&(d.textContent=c<20?"Low usage":c<50?"Moderate":c<80?"Heavy":"Near capacity",d.style.color=c<50?"":c<80?"#ffb86c":"#ff6e6e"));let p=e.txTypes||{},m=Object.entries(p).sort(([,x],[,k])=>k-x);if(m.length){let[x,k]=m[0],T=m.reduce((P,[,R])=>P+R,0)||1,S=(k/T*100).toFixed(0),$=typeof It<"u"?It:{},E=w("d2-dominant-type");E&&(E.textContent=x,E.style.color=$[x]||"rgba(255,255,255,.9)");let C=w("d2-dominance-score");if(C){let P=m[1];C.textContent=P?`${S}% \xB7 2nd: ${P[0]}`:`${S}% of txs`}}let f=w("stream-loading");f&&(f.style.display="none")}function tb(){let e=w("d2-close-sparkline");if(!e||!e.getContext)return;let t=Ga;if(t.length<2)return;let n=e.width,s=e.height,a=e.getContext("2d");a.clearRect(0,0,n,s);let o=Math.max(...t,4),i=Math.floor((n-(t.length-1))/t.length),r=1;t.forEach((l,c)=>{let u=Math.max(3,Math.round(l/o*(s-2))),d=c*(i+r),p=s-u,m=l<=3?"rgba(80,250,123,.80)":l<=6?"rgba(255,184,108,.80)":"rgba(255,110,110,.85)";a.fillStyle=m;let f=Math.min(2,i/2);a.beginPath(),a.moveTo(d+f,p),a.lineTo(d+i-f,p),a.quadraticCurveTo(d+i,p,d+i,p+f),a.lineTo(d+i,s),a.lineTo(d,s),a.lineTo(d,p+f),a.quadraticCurveTo(d,p,d+f,p),a.closePath(),a.fill(),c===t.length-1&&(a.fillStyle="rgba(255,255,255,.18)",a.fillRect(d,p,i,Math.min(3,u)))})}function nb(){if(js&&cancelAnimationFrame(js),!Yt())return;let e=0,t=n=>{if(!Yt()){js=null;return}if(n-e>=120){e=n;let s=w("d2-ledger-age-timer");if(s&&Fi>0){let a=(Date.now()-Fi)/1e3;s.textContent=`${a.toFixed(1)}s ago`,s.style.color=a<4?"rgba(255,255,255,.55)":a<7?"#ffb86c":"#ff6e6e",s.style.opacity=a>=7?(.6+.4*Math.sin(Date.now()/300)).toFixed(2):"1"}}js=requestAnimationFrame(t)};js=requestAnimationFrame(t)}function sb(){let e=w("tx-mix");if(!e)return;let t=Object.entries(X.txMixAccum||{}).filter(([,s])=>s>0).sort(([,s],[,a])=>a-s).slice(0,10),n=t.reduce((s,[,a])=>s+a,0);n&&(e.innerHTML=t.map(([s,a])=>{let o=(a/n*100).toFixed(1),i=It[s]||"#6b7280";return`
      <div class="tx-mix-row">
        <span class="tx-mix-label">${y(s)}</span>
        <div class="tx-mix-bar">
          <div class="tx-mix-fill" style="width:${o}%;background:${i}"></div>
        </div>
        <span class="tx-mix-pct">${o}%</span>
      </div>`}).join(""))}var St=class{constructor(t,n="#00fff0",s="area"){this.canvasId=t,this.canvas=w(t),this.color=n,this.mode=s}_resolveCanvas(){return this.canvas||(this.canvas=w(this.canvasId)),this.canvas}draw(t){let n=this._resolveCanvas();if(!n||!(t!=null&&t.length))return;let s=n.getContext("2d");if(!s)return;let a=n.width=n.offsetWidth||300,o=n.height=n.offsetHeight||180;if(s.clearRect(0,0,a,o),t.length<2)return;let i=Math.min(...t)*.9,r=Math.max(...t)*1.05||1,l=v=>1-(v-i)/(r-i||1),c={l:10,r:10,t:10,b:12},u=a-c.l-c.r,d=o-c.t-c.b,p=u/(t.length-1),m=t.map((v,h)=>[c.l+h*p,c.t+l(v)*d]),f=bn(t);if(f!=null){let v=c.t+l(f)*d;s.beginPath(),s.moveTo(c.l,v),s.lineTo(c.l+u,v),s.strokeStyle="rgba(255,255,255,0.16)",s.lineWidth=1,s.stroke()}if(t.length>=Pp+2){let h=Wg(t,Pp).map((b,x)=>[c.l+x*p,c.t+l(b)*d]);s.beginPath(),h.forEach(([b,x],k)=>k===0?s.moveTo(b,x):s.lineTo(b,x)),s.strokeStyle="rgba(255,255,255,0.22)",s.lineWidth=1.5,s.stroke()}if(this.mode==="bar"){let v=Math.max(1,p-3);t.forEach((h,b)=>{let x=(1-l(h))*d,k=c.l+b*p-v/2,T=s.createLinearGradient(0,c.t,0,c.t+d);T.addColorStop(0,this.color),T.addColorStop(1,this.color+"33"),s.fillStyle=T,s.fillRect(k,c.t+d-x,v,x)});return}let g=s.createLinearGradient(0,c.t,0,c.t+d);g.addColorStop(0,this.color+"aa"),g.addColorStop(1,this.color+"11"),s.beginPath(),m.forEach(([v,h],b)=>b===0?s.moveTo(v,h):s.lineTo(v,h)),s.lineTo(m.at(-1)[0],c.t+d),s.lineTo(m[0][0],c.t+d),s.closePath(),s.fillStyle=g,s.fill(),s.beginPath(),m.forEach(([v,h],b)=>b===0?s.moveTo(v,h):s.lineTo(v,h)),s.strokeStyle=this.color,s.lineWidth=2,s.lineJoin="round",s.stroke()}},ye={};function ab(){ye.tps=new St("chart-tps","#50fa7b","area"),ye.fee=new St("chart-fee","#ffb86c","area"),ye.tps2=new St("chart-tps2","#50fa7b","bar"),ye.fee2=new St("chart-fee2","#ffb86c","area"),ye.dexPressure=new St("chart-dex-pressure","#00d4ff","bar"),ye.nftMints=new St("chart-nft-mints","#bd93f9","bar"),ye.nftBurns=new St("chart-nft-burns","#ff5555","bar"),ye.autoBridge=new St("chart-autobridge","#f1fa8c","bar"),ye.marketPrice=new St("chart-market-price","#50fa7b","area"),ye.marketVol=new St("chart-market-vol","#8be9fd","bar")}function Ht(e,t=Qt){let n=jg(e,t).filter(r=>Number.isFinite(r));if(!n.length)return{cur:null,avg:null,deltaPct:null,vol:null};let s=n.at(-1),a=bn(n),o=zi(n),i=a&&a!==0?(s-a)/a*100:null;return{cur:s,avg:a,deltaPct:i,vol:o}}function ob(){if(Rp)return;Rp=!0;let e=(t,n)=>{let s=w(t);if(!s)return;let a=s.closest(".widget-card"),o=a==null?void 0:a.querySelector(".widget-header");if(!o||document.getElementById(n))return;let i=document.createElement("div");i.className="trend-mini",i.id=n,i.innerHTML=`
      <div class="trend-mini-row">
        <div class="trend-mini-cell"><span class="trend-mini-k">Now</span><span class="trend-mini-v" data-k="now">\u2014</span></div>
        <div class="trend-mini-cell"><span class="trend-mini-k">Avg</span><span class="trend-mini-v" data-k="avg">\u2014</span></div>
      </div>
      <div class="trend-mini-row">
        <div class="trend-mini-cell"><span class="trend-mini-k">\u0394</span><span class="trend-mini-v" data-k="delta">\u2014</span></div>
        <div class="trend-mini-cell"><span class="trend-mini-k">\u03C3</span><span class="trend-mini-v" data-k="sigma">\u2014</span></div>
      </div>
    `,o.appendChild(i)};e("chart-tps","tpsTrendMini"),e("chart-fee","feeTrendMini"),e("chart-tps2","tpsTrendMini2"),e("chart-fee2","feeTrendMini2")}function Wa(e,t,n,s){let a=document.getElementById(e);if(!a)return;let o=(i,r)=>{let l=a.querySelector(`[data-k="${i}"]`);l&&(l.textContent=r)};if(t.cur==null){o("now","\u2014"),o("avg","\u2014"),o("delta","\u2014"),o("sigma","\u2014");return}o("now",`${Number(t.cur).toFixed(n)}${s}`),o("avg",t.avg!=null?`${Number(t.avg).toFixed(n)}${s}`:"\u2014"),o("delta",t.deltaPct==null?"\u2014":vn(t.deltaPct,0)),o("sigma",t.vol==null?"\u2014":`${Number(t.vol).toFixed(Math.max(0,n-1))}${s}`)}function ib(){var n,s,a,o,i,r,l,c,u,d;(n=ye.tps)==null||n.draw(X.tpsHistory),(s=ye.fee)==null||s.draw(X.feeHistory),(a=ye.tps2)==null||a.draw(X.tpsHistory),(o=ye.fee2)==null||o.draw(X.feeHistory);let e=Ht(X.tpsHistory,Qt),t=Ht(X.feeHistory,Qt);Wa("tpsTrendMini",e,2,""),Wa("tpsTrendMini2",e,2,""),Wa("feeTrendMini",t,0,"d"),Wa("feeTrendMini2",t,0,"d"),(i=ye.dexPressure)==null||i.draw(fe.dexPressure),(r=ye.nftMints)==null||r.draw(fe.nftMints),(l=ye.nftBurns)==null||l.draw(fe.nftBurns),(c=ye.autoBridge)==null||c.draw(fe.autoBridge),(u=ye.marketPrice)==null||u.draw(fe.marketPrice),(d=ye.marketVol)==null||d.draw(fe.marketVol)}function rb(){let e=w("ledger-log"),t=w("ledger-log-loading"),n=w("ledger-log-count");if(!e||!(X.ledgerLog||[]).length)return;t&&(t.style.display="none"),n&&(n.textContent=X.ledgerLog.length);let s=w("tab-network");!s||s.style.display==="none"||(e.innerHTML=`<div class="ledger-log-row log-head">
      <span>Ledger</span><span>TXs</span><span>TPS</span><span>Close</span><span>Time</span>
    </div>`+X.ledgerLog.slice(0,60).map(a=>`
      <div class="ledger-log-row">
        <span class="log-index">#${a.ledgerIndex.toLocaleString()}</span>
        <span class="log-tx">${a.txCount}</span>
        <span class="log-tps">${a.tps}</span>
        <span class="log-close">${a.closeTimeSec}s</span>
        <span class="log-time">${a.time}</span>
      </div>`).join(""))}var Xt=[],Ka=new Set,Ge=0,Ua=null,Ws=0,Kt=0,pt=0,Jt=!0,qa=0,Rt=!1,Ya=0,Oi=!1,qs=null,gn=0,ms=0,eo=!1,lb=.18;function cb(){db(),pb()}function db(){let e=w("ledgerStreamParticles");if(e){e.innerHTML="";for(let t=0;t<14;t++){let n=document.createElement("div");n.className="ledger-particle",n.style.left=Math.random()*100+"%",n.style.top=20+Math.random()*60+"%",n.style.animationDuration=6+Math.random()*8+"s",n.style.animationDelay=Math.random()*5+"s",e.appendChild(n)}}}function pb(){if(Ua)return;let e=w("ledgerStreamShell");e&&(e.addEventListener("mouseenter",()=>{Rt=!0}),e.addEventListener("mouseleave",()=>{Vs||(Rt=!1)}));let t=w("ledgerStreamTrack");t&&t.addEventListener("click",s=>{let a=s.target.closest("article.ledger-card");if(!a)return;let o=Number(a.dataset.ledgerIndex);Number.isFinite(o)&&(s.shiftKey?qs===o?(qs=null,Vs||(Rt=!1),Yp()):(qs=o,Rt=!0,Yp()):ub(o))});let n=s=>{Ws||(Ws=s);let a=Math.min(.05,(s-Ws)/1e3);Ws=s;let o=Yt()?w("ledgerStreamTrack"):null;if(o&&Ge>0){if(Jt){let i=o.scrollWidth||0;if(i>100)pt=Math.floor(i/2),Jt=!1,qa=0,Ge>0&&(gn=pt/Ge);else{qa++,qa>30&&(Jt=!1,qa=0),Ua=requestAnimationFrame(n);return}}if(pt>0&&!Rt&&eo){let i=Math.min(1,a/lb);Kt+=(ms-Kt)*i,Math.abs(ms-Kt)<.5&&(Kt=ms);let r=Kt%pt;o.style.transform=`translateX(${-r}px)`}if(!Rt&&Math.floor(s/250)!==Math.floor((s-a*1e3)/250)){let i=Date.now(),r=o.querySelectorAll("article.ledger-card[data-arrival-ts]"),l=12e4;r.forEach(c=>{let u=i-Number(c.dataset.arrivalTs||i),d=Math.max(.52,1-u/l*.48);c.style.opacity=d.toFixed(3)})}if(Ya>0){let i=Date.now()-Ya>Og;Qa(i)}}Ua=requestAnimationFrame(n)};Ua=requestAnimationFrame(n),window.addEventListener("resize",()=>{Jt=!0})}function fu(){if(gn<=0||pt<=0||Ge===0)return Kt;let e=w("ledgerStreamShell"),t=e&&e.offsetWidth||800,n=gn-14,a=(Ge-1)*gn+n-t+18;a=Math.max(0,a);let i=Math.floor(Kt/pt)*pt+a;return i<Kt-2&&(i+=pt),i}function Qa(e,t){if(e===Oi)return;Oi=e;let n=w("ledgerStreamShell");if(!n)return;let s=n.querySelector(".stream-stall-overlay");e?(s||(s=document.createElement("div"),s.className="stream-stall-overlay",n.appendChild(s)),s.innerHTML=`<span class="stream-stall-dot"></span> ${y(t||"Waiting for ledgers\u2026")}`):s==null||s.remove()}function Yp(){document.querySelectorAll(".ledger-card").forEach(e=>{let t=Number(e.dataset.ledgerIndex);e.classList.toggle("ledger-card--pinned",t===qs)})}function ub(e){let t=document.querySelector('.dash-tab[data-tab="inspector"]');typeof window.switchTab=="function"&&t?window.switchTab(t,"inspector"):t==null||t.click();let n=document.getElementById("inspect-addr");n&&(n.placeholder=`Ledger #${e.toLocaleString()} \u2014 paste an address`,n.focus())}function mb(){var t;let e=w("ledgerStreamShell");e&&(e.classList.remove("stream-reconnect-flash"),e.offsetWidth,e.classList.add("stream-reconnect-flash"),setTimeout(()=>e.classList.remove("stream-reconnect-flash"),1200),zg=((t=ps.at(-1))==null?void 0:t.li)??0,fb())}function fb(){let e=document.getElementById("reconnect-banner");if(!e){e=document.createElement("div"),e.id="reconnect-banner",e.className="reconnect-banner";let s=document.querySelector(".dashboard-col-main");s&&s.prepend(e)}e.style.display="",e.innerHTML=`
    <span class="reconnect-dot"></span>
    <span>Reconnected \u2014 rebuilding signal baseline (<span id="reconnect-countdown">3</span> ledgers)</span>
    <button onclick="document.getElementById('reconnect-banner').style.display='none'"
      style="margin-left:auto;background:none;border:none;color:inherit;opacity:.5;cursor:pointer;font-size:.9rem">\u2715</button>`;let t=3,n=setInterval(()=>{let s=document.getElementById("reconnect-countdown");if(s&&(s.textContent=t),t--,t<0){clearInterval(n);let a=document.getElementById("reconnect-banner");a&&(a.style.display="none")}},4e3)}function Qp(){let e=w("ledgerStreamTrack"),t=w("ledgerStreamShell"),n=w("stream-loading");if(!e||!t)return;if(n&&(n.style.display="none"),Xt.length===0){e.innerHTML='<div style="padding:40px;opacity:.6">Waiting for ledgers\u2026</div>',Ge=0,Jt=!0;return}let s=[...Xt].sort((o,i)=>o.ledgerIndex-i.ledgerIndex),a=s.map((o,i)=>gu(o,{prevIndex:i>0?s[i-1].ledgerIndex:null}));e.innerHTML=a.concat(a).join(""),Ge=s.length,Jt=!0,requestAnimationFrame(()=>{var i;let o=((i=w("ledgerStreamTrack"))==null?void 0:i.scrollWidth)||0;o>100&&(pt=Math.floor(o/2),gn=Ge>0?pt/Ge:0,ms=fu(),eo=!0,Jt=!1)})}function hb(e){var f,g;if(!e)return;let t=Number(e.ledgerIndex??NaN);if(!Number.isFinite(t)||Ka.has(t))return;Ka.add(t),Xt.push(e);let n=0;if(Xt.length>Ap){let v=Xt.splice(0,Xt.length-Ap);v.forEach(h=>Ka.delete(h.ledgerIndex)),n=v.length}Ya=Date.now(),Qa(!1),bb(e.avgFee!=null?Number(e.avgFee):null);let{auraClass:s,domColor:a}=vb(e);vu(s,a);let o=w("stream-loading");o&&(o.style.display="none");let i=w("ledgerStreamTrack");if(!i)return;if(Ge===0){Qp();return}let r=Xt.length>=2?Xt[Xt.length-2].ledgerIndex:0;if(t<r){Qp();return}let l=Ge,c=gu(e),u=document.createElement("template");u.innerHTML=c;let d=u.content.firstElementChild,p=i.children[l];p?i.insertBefore(d,p):i.appendChild(d);let m=document.createElement("template");if(m.innerHTML=c,i.appendChild(m.content.firstElementChild),Ge=l+1,n>0){for(let h=0;h<n;h++)(f=i.children[0])==null||f.remove();let v=Ge-n;for(let h=0;h<n;h++)(g=i.children[v])==null||g.remove();Ge-=n}Jt=!0,requestAnimationFrame(()=>{gn<=0&&pt>0&&Ge>0&&(gn=pt/Ge),ms=fu(),eo=!0})}var fs=[],gb=20;function bb(e){e==null||!Number.isFinite(e)||(fs.push(e),fs.length>gb&&fs.shift())}function hu(){return fs.length===0?null:fs.reduce((e,t)=>e+t,0)/fs.length}function gu(e,t={}){let{ledgerIndex:n,closeTimeSec:s,totalTx:a,txTypes:o,avgFee:i}=e,r=o||{},l=a??0,c=Object.entries(r).sort(([,D],[,I])=>I-D)[0],u=(c==null?void 0:c[0])||"Other",d=bu(u),p=typeof It<"u"?It:{},m=D=>p[D]||"#6b7280",f=m(u),g=us(f,.45)||f,v=us(f,.14)||f,h=s==null?"\u2014":s<2?`${Number(s).toFixed(2)}s`:`${Number(s).toFixed(1)}s`,b=l>0&&s>0?(l/s).toFixed(1):null,x=i!=null?Number(i):null,k=x!=null?hn(x):"\u2014",T=hu(),S=x!=null&&T!=null&&x>T*3,$=t.prevIndex!=null?Number(n)-t.prevIndex-1:0,E=$>0?`<div class="stream-gap-badge" title="${$} ledger(s) missing">\xB7\xB7\xB7&nbsp;${$} gap</div>`:"",C=D=>l>0?`${(D/l*100).toFixed(1)}%`:"0%",P=(D,I,F)=>I?`<div class="ledger-type-row">
      <span class="ledger-type-label cut">${y(D)}</span>
      <div class="ledger-type-bar"><div class="ledger-type-fill" style="width:${C(I)};background:${F}"></div></div>
      <span class="ledger-type-count">${I}</span>
    </div>`:"",R=(r.AMMCreate||0)+(r.AMMDeposit||0)+(r.AMMWithdraw||0)+(r.AMMVote||0),O=Date.now();return`${E}<article class="ledger-card ledger-card--${d} ledger-card--entry${S?" ledger-card--fee-spike":""}"
    data-ledger-index="${Number(n??0)}"
    data-arrival-ts="${O}"
    style="border-color:${g};box-shadow:0 0 22px ${v};flex-shrink:0">
    <div class="ledger-card-inner">
      <div class="ledger-card-header">
        <span class="ledger-id">#${(n||0).toLocaleString()}</span>
        <div class="ledger-meta">
          <span class="ledger-tag cut" style="border-color:${g};color:${f}">${y(u)}</span>
          ${S?'<span class="fee-spike-badge" title="Fee spike: 3\xD7 baseline">\u{1F525}</span>':""}
        </div>
      </div>
      <div class="ledger-main-row">
        <div class="ledger-main-stat"><span class="ledger-stat-label">TXs</span><span class="ledger-stat-value">${l}</span></div>
        <div class="ledger-main-stat"><span class="ledger-stat-label">Close</span><span class="ledger-stat-value">${h}</span></div>
        <div class="ledger-main-stat"><span class="ledger-stat-label">Avg Fee</span><span class="ledger-stat-value${S?" fee-spike-value":""}">${k}</span></div>
        ${b!=null?`<div class="ledger-main-stat"><span class="ledger-stat-label">TPS</span><span class="ledger-stat-value">${b}</span></div>`:""}
      </div>
      <div class="ledger-type-bars">
        ${P("Payment",r.Payment,m("Payment"))}
        ${P("OfferCreate",r.OfferCreate,m("OfferCreate"))}
        ${P("OfferCancel",r.OfferCancel,m("OfferCancel"))}
        ${P("TrustSet",r.TrustSet,m("TrustSet"))}
        ${P("NFT Mint",r.NFTokenMint,m("NFTokenMint"))}
        ${R?P("AMM",R,m("AMMCreate")):""}
        ${P("EscrowCreate",r.EscrowCreate,"#6b7280")}
        ${(r.Other||0)>0?P("Other",r.Other,"#6b7280"):""}
      </div>
    </div>
  </article>`}function bu(e){let t=String(e||"");return t==="Payment"?"payment":t.startsWith("Offer")?"offer":t.startsWith("NFToken")?"nft":t==="TrustSet"?"trust":t.startsWith("AMM")?"amm":"other"}function vb(e){var o;let n=((o=Object.entries(e.txTypes||{}).sort(([,i],[,r])=>r-i)[0])==null?void 0:o[0])||"Other",s=bu(n),a=It[n]||It.Other||"#6b7280";return{dominantTx:n,auraClass:s,domColor:a}}function vu(e,t){let n=w("ledgerStreamShell");if(!n)return;if(!e||!t){n.style.removeProperty("--streamTintStrong"),n.style.removeProperty("--streamTintSoft"),n.style.removeProperty("--streamTintBorder");return}let s=us(t,.16)||"rgba(0,255,240,0.14)",a=us(t,.06)||"rgba(0,255,240,0.06)",o=us(t,.22)||"rgba(0,255,240,0.22)";n.style.setProperty("--streamTintStrong",s),n.style.setProperty("--streamTintSoft",a),n.style.setProperty("--streamTintBorder",o),n.dataset.tint=e}function yb(e){var v,h;let t=Array.isArray(e.recentTransactions)?e.recentTransactions.slice(0,Ng):[],n=e.txTypes||{},s=Number(e.ledgerIndex||0),a=Object.values(n).reduce((b,x)=>b+x,0)||1,o=0;for(let b of Object.values(n)){let x=b/a;o+=x*x}let i=wb(t);xb(Us,i);let r=kb(Us.totals,i),l=$b(Us.totals),c=Sb(s,t),u=Tb(s,(v=e.latestLedger)==null?void 0:v.closeTimeSec,t),d=Cb({txs:t,txTypes:n,dexPatterns:u}),p=r.filter(b=>b.count>=2).length,m=Pb({hhi:o,repeats:p,dex:u,bots:((h=c.bots)==null?void 0:h.length)||0,advanced:d}),f=Mb({friction:m,tps:Ht(X.tpsHistory),fee:Ht(X.feeHistory)}),g=Lb({s:e,txTypes:n,hhi:o,dexPatterns:u,behavior:c,friction:m,regime:f,breadcrumbs:r,clusters:l,advanced:d});return{s:e,txs:t,txTypes:n,hhi:o,behavior:c,dexPatterns:u,friction:m,regime:f,breadcrumbs:r,clusters:l,narratives:g,advanced:d}}function wb(e){let t=new Map;for(let n of e){let s=n==null?void 0:n.account,a=n==null?void 0:n.destination;if(!s||!a)continue;let o=`${s}|${a}`;t.set(o,(t.get(o)||0)+1)}return t}function xb(e,t){e.window.unshift(t);for(let[n,s]of t.entries())e.totals.set(n,(e.totals.get(n)||0)+s);for(;e.window.length>e.maxLedgers;){let n=e.window.pop();for(let[s,a]of n.entries()){let o=(e.totals.get(s)||0)-a;o<=0?e.totals.delete(s):e.totals.set(s,o)}}}function kb(e,t){let s=[...e.entries()].map(([o,i])=>({k:o,c:i})).sort((o,i)=>i.c-o.c).filter(o=>o.c>=2);return(s.length?s:[...t.entries()].map(([o,i])=>({k:o,c:i}))).slice(0,10).map(({k:o,c:i})=>{let[r,l]=o.split("|");return{from:r,to:l,count:i}})}function $b(e){let t=[...e.entries()].filter(([,i])=>i>=2),n=t.length?t:[...e.entries()],s=new Map;for(let[i]of n){let[r,l]=i.split("|");!r||!l||(s.has(r)||s.set(r,new Set),s.has(l)||s.set(l,new Set),s.get(r).add(l),s.get(l).add(r))}let a=new Set,o=[];for(let i of s.keys()){if(a.has(i))continue;let r=[i],l=[];for(a.add(i);r.length;){let d=r.pop();l.push(d);for(let p of s.get(d)||[])a.has(p)||(a.add(p),r.push(p))}if(l.length<2)continue;let c=l[0],u=-1;for(let d of l){let p=(s.get(d)||new Set).size;p>u&&(u=p,c=d)}o.push({members:l,size:l.length,hub:c})}return o.sort((i,r)=>r.size-i.size),o.slice(0,6)}function Sb(e,t){let n=new Map;for(let a of t){let o=a==null?void 0:a.account;o&&n.set(o,(n.get(o)||0)+1)}for(let[a,o]of n.entries()){Nt.acct.has(a)||Nt.acct.set(a,{ledgers:[],intervals:[],total:0});let i=Nt.acct.get(a),r=i.ledgers.at(-1);i.ledgers.push(e),r!=null&&e>r&&i.intervals.push(e-r),i.ledgers.length>30&&i.ledgers.shift(),i.intervals.length>29&&i.intervals.shift(),i.total+=o}let s=[];for(let[a,o]of Nt.acct.entries()){if(o.intervals.length<6)continue;let i=bn(o.intervals),r=zi(o.intervals);if(!i||r==null)continue;let l=r/i;l<.35&&o.total>10&&s.push({acct:a,cv:l,total:o.total})}if(s.sort((a,o)=>a.cv-o.cv||o.total-a.total),e%50===0)for(let[a,o]of Nt.acct){let i=o.ledgers.at(-1)??e;e-i>1e3&&Nt.acct.delete(a)}return{bots:s.slice(0,6),uniqueActors:n.size}}function Tb(e,t,n){var E;let s=0,a=0,o=new Map,i=new Map,r=new Map;for(let C of n){let P=C==null?void 0:C.type,R=C==null?void 0:C.account;R&&(P==="OfferCreate"?(s+=1,o.set(R,(o.get(R)||0)+1),i.set(R,(i.get(R)||0)+1)):P==="OfferCancel"&&(a+=1,o.set(R,(o.get(R)||0)+1),r.set(R,(r.get(R)||0)+1)))}let l=s+a,c=l?a/l:0,u=t!=null&&Number(t)>0?a/Number(t)*60:null;for(Re.smoothCancelPerMin=Kp(Re.smoothCancelPerMin,u,.45),Re.window.unshift({li:e,closeTimeSec:t??null,create:s,cancel:a,total:l,cancelRatio:c,cancelsPerMin:Re.smoothCancelPerMin,byActor:o,byActorCreate:i,byActorCancel:r});Re.window.length>_g;)Re.window.pop();let d={create:0,cancel:0,total:0},p=new Map,m=new Map,f=new Map;for(let C of Re.window){d.create+=C.create,d.cancel+=C.cancel,d.total+=C.total;for(let[P,R]of C.byActor.entries())p.set(P,(p.get(P)||0)+R);for(let[P,R]of C.byActorCancel.entries())m.set(P,(m.get(P)||0)+R);for(let[P,R]of C.byActorCreate.entries())f.set(P,(f.get(P)||0)+R)}let g=Ni(p,5),v=Ni(m,5),h=Ni(f,5),b=d.total?(((E=g[0])==null?void 0:E.count)||0)/d.total:0,x=0;if(d.total)for(let C of p.values()){let P=C/d.total;x+=P*P}let k=Re.window.map(C=>C.total).filter(Number.isFinite),T=bn(k)||0,S=T>0?(l-T)/T*100:null;Re.smoothBurst=Kp(Re.smoothBurst,S,.4);let $=[];return d.total>=Li&&c>=.65&&$.push("Lots of cancels (looks like quote-stuffing/spam)"),d.total>=Li&&b>=.35&&$.push("One actor dominates DEX activity"),d.total>=Li&&(Re.smoothCancelPerMin||0)>=18&&$.push("Fast cancelling (high churn)"),Re.smoothBurst!=null&&Math.abs(Re.smoothBurst)>=45&&$.push("Sudden DEX burst"),{now:{li:e,create:s,cancel:a,total:l,cancelRatio:c,cancelsPerMin:Re.smoothCancelPerMin},window:{...d,cancelRatio:d.total?d.cancel/d.total:0},topShare:b,actorHHI:x,burstPct:Re.smoothBurst,topActor:g,topCanceller:v,topMaker:h,signals:$}}function Ni(e,t){return[...e.entries()].sort((n,s)=>s[1]-n[1]).slice(0,t).map(([n,s])=>({acct:n,count:s}))}function Cb({txs:e,txTypes:t,dexPatterns:n}){var H;let s=Number((t==null?void 0:t.OfferCreate)||0)+Number((t==null?void 0:t.OfferCancel)||0),a=Number((t==null?void 0:t.NFTokenMint)||0),o=Number((t==null?void 0:t.NFTokenBurn)||0),i=0,r=new Map,l=new Map;for(let N of e){if((N==null?void 0:N.type)!=="Payment")continue;let j=(N==null?void 0:N.paths)||(N==null?void 0:N.Paths),se=Array.isArray(j)&&j.length>0,re=(N==null?void 0:N.sendmax)!=null||(N==null?void 0:N.SendMax)!=null,pe=(N==null?void 0:N.delivermax)!=null||(N==null?void 0:N.DeliverMax)!=null;if(!(se||re||pe))continue;i+=1;let te=N==null?void 0:N.account,de=N==null?void 0:N.destination;if(te&&r.set(te,(r.get(te)||0)+1),te&&de){let le=`${te}|${de}`;l.set(le,(l.get(le)||0)+1)}}let c=[...r.entries()].sort((N,j)=>j[1]-N[1]).slice(0,5).map(([N,j])=>({acct:N,count:j})),u=[...l.entries()].sort((N,j)=>j[1]-N[1]).slice(0,5).map(([N,j])=>{let[se,re]=N.split("|");return{from:se,to:re,count:j}}),d=(H=n==null?void 0:n.now)!=null&&H.total?Math.round((n.now.cancelRatio||0)*100):0,p=(n==null?void 0:n.topShare)!=null?Math.round(n.topShare*100):0,m=e.filter(N=>(N==null?void 0:N.type)==="Payment").map(N=>typeof(N==null?void 0:N.amountXrp)=="number"?N.amountXrp:null).filter(N=>N!=null&&N>0&&Number.isFinite(N)),f=[100,1e3,1e4],g=m.filter(N=>f.some(j=>Math.abs(N%j)<1e-9&&N/j>=1)).length,v=m.length>=5?Math.round(g/m.length*100):null,h=e.filter(N=>(N==null?void 0:N.type)==="Payment"&&(N==null?void 0:N.account)&&(N==null?void 0:N.destination)&&N.account===N.destination).length,b=Number((t==null?void 0:t.AMMCreate)||0),x=Number((t==null?void 0:t.AMMDeposit)||0),k=Number((t==null?void 0:t.AMMWithdraw)||0),T=Number((t==null?void 0:t.AMMVote)||0),S=Number((t==null?void 0:t.AMMBid)||0),$=Number((t==null?void 0:t.AMMDelete)||0),E=b+x+k+T+S+$,C=x-k,P=x+k>0?Math.round(x/(x+k)*100):null,R=new Set;for(let N of e)["AMMCreate","AMMDeposit","AMMWithdraw","AMMVote","AMMBid"].includes(N==null?void 0:N.type)&&(N!=null&&N.account)&&R.add(N.account);let O=R.size,D=0,I=0;for(let N of e)(N==null?void 0:N.type)==="Payment"&&Array.isArray(N==null?void 0:N.paths)&&N.paths.length>0&&(D+=N.paths.length,I++);let F=I>0?(D/I).toFixed(1):null;return{offerTotal:s,dexCancelPct:d,dexTopSharePct:p,mints:a,burns:o,pathPays:i,topPathActors:c,topPathPairs:u,roundnessIdx:v,selfTradeCount:h,ammCreate:b,ammDeposit:x,ammWithdraw:k,ammVote:T,ammBid:S,ammDelete:$,lpTotal:E,lpNetFlow:C,lpRatio:P,lpUniqueActors:O,avgPathDepth:F}}function Pb({hhi:e,repeats:t,dex:n,bots:s,advanced:a}){var h,b;let o=we((e-.22)/.25,0,1)*22,i=we((t-2)/6,0,1)*12,r=((h=n==null?void 0:n.window)==null?void 0:h.cancelRatio)??0,l=(n==null?void 0:n.topShare)??0,c=((b=n==null?void 0:n.now)==null?void 0:b.cancelsPerMin)??0,u=we((r-.5)/.5,0,1)*18,d=we((l-.25)/.5,0,1)*18,p=we(c/25,0,1)*10,m=we(s/6,0,1)*10,f=(a==null?void 0:a.roundnessIdx)!=null?we((a.roundnessIdx-30)/40,0,1)*8:0,g=(a==null?void 0:a.selfTradeCount)>0?Math.min(8,a.selfTradeCount*4):0,v=(a==null?void 0:a.pathPays)!=null?we(a.pathPays/30,0,1)*6:0;return Math.round(o+i+u+d+p+m+f+g+v)}function Mb({friction:e,tps:t,fee:n}){let s=(n==null?void 0:n.deltaPct)!=null&&Math.abs(n.deltaPct)>=35,a=(t==null?void 0:t.deltaPct)!=null&&Math.abs(t.deltaPct)>=25;return e>=75?"Manipulated":s||a?"Stressed":((t==null?void 0:t.cur)??0)>=12||((t==null?void 0:t.avg)??0)>=10?"Active":"Quiet"}function Lb({s:e,txTypes:t,hhi:n,dexPatterns:s,behavior:a,friction:o,regime:i,breadcrumbs:r,clusters:l,advanced:c}){var h,b,x,k,T;let u=[],d=Ht(X.tpsHistory,Qt),p=Ht(X.feeHistory,Qt),m=((h=Object.entries(t||{}).sort(([,S],[,$])=>$-S)[0])==null?void 0:h[0])||"\u2014",f=Number(e.txPerLedger||0);u.push({sentiment:i==="Manipulated"||i==="Stressed"?"warn":i==="Active"?"up":"ok",title:`Overall: ${i} \xB7 Risk score ${o}/100`,detail:"Heuristic score from concentration, repeats, DEX churn, bot-like timing, and routing indicators. It's a signal, not proof."}),u.push({sentiment:"ok",title:`Ledger snapshot: #${Number(e.ledgerIndex||0).toLocaleString()} \xB7 ${f} tx \xB7 most common: ${m}`,detail:`TPS ${ls(d.cur,2)} (avg ${ls(d.avg,2)} \xB7 ${vn(d.deltaPct,0)}). Fee ${p.cur!=null?hn(p.cur):"\u2014"} (avg ${p.avg!=null?hn(p.avg):"\u2014"} \xB7 ${vn(p.deltaPct,0)}).`});let g=n>=.35?"high":n>=.25?"medium":"low";if(u.push({sentiment:n>=.35?"warn":"ok",title:`Transaction mix: ${g} concentration (HHI ${n.toFixed(2)})`,detail:n>=.35?"A few tx types dominate. Patterns look \u201Cstronger,\u201D but can be misleading.":"Mix is broad. Strong signals usually come from behavior, not just tx type."}),s.window.total){let S=Math.round(s.window.cancelRatio*100),$=Math.round(s.topShare*100);u.push({sentiment:s.signals.length?"warn":"ok",title:`DEX monitor: ${s.window.total} offer tx (window) \xB7 cancels ${S}% \xB7 top actor ~${$}%`,detail:s.signals.length?`Signals: ${s.signals.join(" \xB7 ")}`:"No strong DEX-pattern signals right now.",addr:((b=s.topActor[0])==null?void 0:b.acct)||null})}let v=r.filter(S=>S.count>=2).length;if(v>=2&&u.push({sentiment:"new",title:`Repeating counterparties: ${v} recurring pair(s)`,detail:"Repeated interactions can be routing loops, bots, or coordinated flows. Click addresses for a quick read."}),l!=null&&l.length&&((x=l[0])==null?void 0:x.size)>=3&&u.push({sentiment:"new",title:`Cluster forming: ${l[0].size} wallets \xB7 hub ${z(l[0].hub)}`,detail:"Clusters are co-activity groups (not identity proof). Use as \u201Clikely related behavior.\u201D",addr:l[0].hub}),(k=a.bots)!=null&&k.length){let S=a.bots[0];u.push({sentiment:"warn",title:`Bot-like timing: ${a.bots.length} candidate(s)`,detail:`Low variance in repeated appearances. Top: ${z(S.acct)} (CV ${S.cv.toFixed(2)}).`,addr:S.acct})}if(c!=null&&c.pathPays){let S=(T=c.topPathActors)==null?void 0:T[0];u.push({sentiment:c.pathPays>=18?"warn":"ok",title:`Autobridge-ish routing: ${c.pathPays} path payments (ledger sample)`,detail:S?`Most active routing wallet: ${z(S.acct)} (${S.count}).`:"Paths/SendMax/DeliverMax appear frequently in the sample.",addr:(S==null?void 0:S.acct)||null})}return c!=null&&c.selfTradeCount&&u.push({sentiment:"warn",title:`Self-transfer signal: ${c.selfTradeCount} payment(s) where sender = receiver`,detail:"Self-transfers can be benign (housekeeping) or used to fake activity. Treat as a watch signal."}),((c==null?void 0:c.roundnessIdx)??0)>=45&&u.push({sentiment:"warn",title:`Round-number bias: ${c.roundnessIdx}% of payments are exact multiples of 100/1,000/10,000`,detail:"Round-number bias often shows scripted behavior (bots) rather than human payments."}),u.slice(0,12)}function Ab(e){let t=w("d2-breadcrumb-list"),n=w("d2-breadcrumb-meta");if(!t)return;if(!e.length){t.innerHTML='<div class="gateway-item" style="opacity:.6">Watching for repeated interactions\u2026</div>',n&&(n.textContent="\u2014");return}let s=e.filter(a=>a.count>=2).length;n&&(n.textContent=s?`${s} repeats`:"Top interactions"),t.innerHTML=e.slice(0,10).map(a=>`
    <div class="gateway-item gateway-row">
      <div class="gateway-left mono cut">
        <button class="addr-link mono cut gw-from" data-addr="${y(a.from)}">${y(z(a.from))}</button>
        <span class="gw-arrow">\u2192</span>
        <button class="addr-link mono cut gw-to" data-addr="${y(a.to)}">${y(z(a.to))}</button>
      </div>
      <span class="gw-count">${a.count}\xD7</span>
    </div>`).join("")}function Eb(e){let t=w("d2-cluster-list"),n=w("d2-cluster-persistence");if(t){if(!e.length){t.innerHTML='<div class="gateway-item" style="opacity:.6">Building clusters\u2026 (needs repeated activity)</div>',n&&(n.textContent="\u2014");return}n&&(n.textContent=`${e.length} group${e.length!==1?"s":""}`),t.innerHTML=e.slice(0,6).map((s,a)=>{let i=`hsl(${(a*67+120)%360},70%,60%)`,r=s.members.slice(0,4);return`
      <div class="gateway-item cluster-item">
        <div class="cluster-head">
          <span class="cluster-title" style="color:${i}">Group ${a+1}</span>
          <span class="cluster-meta">${s.size} wallets</span>
        </div>
        <div class="cluster-preview">
          <span class="cluster-chip-h">Hub:</span>
          <button class="addr-chip mono" data-addr="${y(s.hub)}">${y(z(s.hub))}</button>
        </div>
        <div class="cluster-preview">
          <span class="cluster-chip-h">Members:</span>
          ${r.map(l=>`<button class="addr-chip mono" data-addr="${y(l)}">${y(z(l))}</button>`).join("")}
          ${s.members.length>r.length?`<span class="cluster-more">+${s.members.length-r.length}</span>`:""}
        </div>
      </div>`}).join("")}}function Nb(e){let t=w("d2-delta-narratives");if(!t)return;if(!e.length){t.innerHTML='<div class="gateway-item" style="opacity:.6">Building baseline \u2014 narratives appear after 1\u20132 ledgers\u2026</div>';return}let n={up:"#50fa7b",down:"#ff5555",new:"#00d4ff",warn:"#ffb86c",ok:"rgba(255,255,255,.85)"};t.innerHTML=e.map(s=>{let a=n[s.sentiment]||"rgba(255,255,255,.85)",o=s.addr&&He(s.addr)?`<button class="addr-link narrative-addr" data-addr="${y(s.addr)}">Peek</button>`:"";return`
      <details class="gateway-item narrative-item">
        <summary style="color:${a}">
          <span class="narrative-title">${y(s.title||s.text||"")}</span>
          ${o}
        </summary>
        <div class="narrative-detail">${y(s.detail||"")}</div>
      </details>`}).join("")}function Rb(){if(Ep)return;Ep=!0;let e=new Map([["Pattern detection","Quick \u201Cat a glance\u201D read. If one thing dominates, patterns are easier to spot (but can be noisy)."],["Live ledger stream","Each card is a validated ledger. Glow color shows what activity dominated that ledger. Click a card to jump to inspector."],["Wallet breadcrumbs","Shows who repeatedly interacts with who. Click an address for an account peek."],["Cluster inference","Groups wallets that move together. Not identity proof. Use it as \u201Clikely related behavior.\u201D"],["Delta narratives","Plain-English summary of what changed: load, fees, DEX churn, repeats, bot-like timing."]]);document.querySelectorAll("section.widget-card[aria-label], div.widget-card[aria-label]").forEach(t=>{let n=t.getAttribute("aria-label")||"",s=e.get(n);if(!s)return;let a=t.querySelector(".widget-header");if(!a||t.querySelector(".widget-help"))return;let o=document.createElement("p");o.className="widget-help",o.textContent=s,a.insertAdjacentElement("afterend",o)})}function _b(){if(Np)return;Np=!0;let e=document.querySelector(".ledger-stream-card");if(!e||e.querySelector(".ledger-legend"))return;let t=e.querySelector(".widget-help"),n=e.querySelector(".widget-header"),s=document.createElement("div");s.className="ledger-legend",s.setAttribute("aria-label","Ledger glow legend"),s.innerHTML=`
    <span class="legend-label">Glow key:</span>
    <span class="legend-chip payment">Payment</span>
    <span class="legend-chip offer">DEX</span>
    <span class="legend-chip nft">NFT</span>
    <span class="legend-chip trust">Trust</span>
    <span class="legend-chip amm">AMM</span>
    <span class="legend-chip other">Other</span>
  `,t?t.insertAdjacentElement("afterend",s):n?n.insertAdjacentElement("afterend",s):e.prepend(s)}function Db(){if(_p)return;_p=!0;let e=document.querySelector(".dashboard-col-main");if(!e)return;let t=document.createElement("section");t.className="widget-card",t.id="landscape-card",t.setAttribute("aria-label","Landscape brief"),t.innerHTML=`
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
  `,e.prepend(t)}function Ib(e){var b,x,k,T,S,$,E,C,P,R,O,D,I,F,H;let t=w("landscape-badge");t&&(t.textContent=`${e.regime} \xB7 Risk ${e.friction}/100`);let n=e.s,s=e.txTypes||{},a=((b=Object.entries(s).sort(([,N],[,j])=>j-N)[0])==null?void 0:b[0])||"\u2014",o=Ht(X.tpsHistory,Qt),i=Ht(X.feeHistory,Qt),r=e.dexPatterns,l=(x=r==null?void 0:r.window)!=null&&x.total?Math.round(r.window.cancelRatio*100):0,c=w("landscape-text");if(c){let N=Number(n.ledgerIndex||0).toLocaleString(),j=Number(n.txPerLedger||0),se=((k=n.latestLedger)==null?void 0:k.closeTimeSec)!=null?Number(n.latestLedger.closeTimeSec).toFixed(2)+"s":"\u2014",re=o.cur!=null?`${ls(o.cur,2)} TPS`:"\u2014",pe=i.cur!=null?`${hn(i.cur)} fee`:"\u2014",ae=n.successRate!=null?`${Number(n.successRate).toFixed(1)}% success`:"\u2014",te=(T=r==null?void 0:r.window)!=null&&T.total?`DEX offers are <b>${r.window.total}</b> (window), with <b>${l}% cancels</b>.`:"DEX offers look quiet right now.";c.innerHTML=`
      <b>Right now:</b> Ledger <b>#${N}</b> closed in <b>${se}</b> with <b>${j}</b> transactions.
      Network is at <b>${re}</b>, with <b>${pe}</b>, and <b>${ae}</b>.
      Most common activity was <b>${y(a)}</b>. ${te}
    `}let u=w("landscape-why"),d=w("landscape-watchlist"),p=w("landscape-now"),m=w("landscape-watch"),f=[],g=[],v=[];if(e.regime==="Manipulated"?v.push("Risk score is very high. Patterns like churn, loops, or single-actor dominance often correlate with manipulated activity."):e.regime==="Stressed"?v.push("The network is behaving \u201Cabnormally\u201D (spikes in TPS or fees). This can be organic bursts or bots pushing volume."):e.regime==="Active"?v.push("The network is busy. Patterns are easier to detect because there\u2019s more data per minute."):v.push("The network is quiet. Signals are weaker; a few bots can dominate a small sample."),(S=r==null?void 0:r.signals)!=null&&S.length&&v.push(`DEX churn signals: <b>${y(r.signals.join(" \xB7 "))}</b>. Heavy OfferCreate/Cancel churn can indicate quote-stuffing/spoofing-like behavior.`),(($=e.advanced)==null?void 0:$.selfTradeCount)>0&&v.push(`Detected <b>${e.advanced.selfTradeCount}</b> self-transfer payment(s) in the sample. Can be benign, but can also be used to fake activity.`),(((E=e.advanced)==null?void 0:E.roundnessIdx)??0)>=45&&v.push(`Round-number bias is high (<b>${e.advanced.roundnessIdx}%</b>). That often indicates automation rather than human behavior.`),((C=e.advanced)==null?void 0:C.pathPays)>=18&&v.push(`Path payments are heavy (<b>${e.advanced.pathPays}</b> in sample). Lots of routing can mean arbitrage bots or automated bridge traffic.`),u&&(u.innerHTML=v.map(N=>`<div class="landscape-row">${N}</div>`).join("")),f.push(`Overall mode: <b>${y(e.regime)}</b> (risk score <b>${e.friction}/100</b>).`),f.push(`Traffic: <b>${ls(o.cur,2)}</b> TPS (avg ${ls(o.avg,2)} \xB7 ${vn(o.deltaPct,0)}).`),f.push(`Fees: <b>${i.cur!=null?hn(i.cur):"\u2014"}</b> (avg ${i.avg!=null?hn(i.avg):"\u2014"} \xB7 ${vn(i.deltaPct,0)}).`),(P=r==null?void 0:r.window)!=null&&P.total){let N=(R=r.topActor)==null?void 0:R[0];f.push(`DEX activity: <b>${r.window.total}</b> offer tx (window) \xB7 cancels <b>${l}%</b> \xB7 churn <b>${ls(r.now.cancelsPerMin,1)}</b>/min.`),N&&f.push(`Most active DEX wallet: <button class="addr-link mono" data-addr="${y(N.acct)}">${y(z(N.acct))}</button> (${N.count}).`)}else f.push("DEX activity: <b>quiet</b> (few OfferCreate/OfferCancel).");let h=e.breadcrumbs.filter(N=>N.count>=2).length;if(h&&g.push(`Repeating interactions: <b>${h}</b> pair(s) keep showing up.`),(D=(O=e.behavior)==null?void 0:O.bots)!=null&&D.length){let N=e.behavior.bots[0];g.push(`Bot-like timing: top candidate <button class="addr-link mono" data-addr="${y(N.acct)}">${y(z(N.acct))}</button> (CV ${N.cv.toFixed(2)}).`)}if((I=r==null?void 0:r.signals)!=null&&I.length&&g.push(`DEX signals: <b>${y(r.signals.join(" \xB7 "))}</b>`),(F=e.clusters)!=null&&F.length&&g.push(`Largest cluster: <b>${e.clusters[0].size}</b> wallets \xB7 hub <button class="addr-link mono" data-addr="${y(e.clusters[0].hub)}">${y(z(e.clusters[0].hub))}</button>.`),(H=e.advanced)!=null&&H.pathPays&&g.push(`Autobridge/path flow: <b>${e.advanced.pathPays}</b> path payments detected in sample.`),g.length||g.push("Nothing urgent stands out in the current window."),p&&(p.innerHTML=f.map(N=>`<div class="landscape-row">${N}</div>`).join("")),m&&(m.innerHTML=g.map(N=>`<div class="landscape-row">${N}</div>`).join("")),d){let N=Fb(e);d.innerHTML=N.length?N.map(j=>`
        <div class="landscape-watchitem">
          <button class="addr-link mono cut" data-addr="${y(j.addr)}">${y(z(j.addr))}</button>
          <div class="landscape-watchwhy">${j.why}</div>
        </div>
      `).join(""):'<div style="opacity:.75">No clear \u201Ctop suspect\u201D yet \u2014 need a few more ledgers to build a baseline.</div>'}}function Fb(e){var i,r,l,c,u,d,p,m;let t=[],n=(f,g)=>{!f||!He(f)||t.some(v=>v.addr===f)||t.push({addr:f,why:g})};if((r=(i=e.behavior)==null?void 0:i.bots)!=null&&r.length){let f=e.behavior.bots[0];n(f.acct,`Bot-like timing (CV <span class="mono">${f.cv.toFixed(2)}</span>). High regularity is common in spam & automation.`)}let s=e.dexPatterns;if((l=s==null?void 0:s.topActor)!=null&&l.length){let f=s.topActor[0],g=s.topShare!=null?Math.round(s.topShare*100):null,v=((c=s.now)==null?void 0:c.cancelsPerMin)!=null?s.now.cancelsPerMin.toFixed(1):"\u2014";g!=null&&g>=25&&n(f.acct,`Dominates DEX activity (~<span class="mono">${g}%</span> share). Cancels/min <span class="mono">${v}</span> \u2014 watch for quote-stuffing/spoofing.`)}if((u=s==null?void 0:s.topCanceller)!=null&&u.length){let f=s.topCanceller[0];f.count>=6&&n(f.acct,`Top canceller (<span class="mono">${f.count}</span>). Heavy cancels can be a manipulation signal.`)}let a=e.breadcrumbs||[],o=a[0];if(o!=null&&o.from&&(o!=null&&o.to)){let f=a.find(g=>g.from===o.to&&g.to===o.from);f&&f.count>=3&&o.count>=3?(n(o.from,`Ping\u2011pong loop with ${z(o.to)} (<span class="mono">${o.count}\xD7</span> / <span class="mono">${f.count}\xD7</span>). Can be wash-like routing.`),n(o.to,`Ping\u2011pong loop with ${z(o.from)} (<span class="mono">${f.count}\xD7</span> / <span class="mono">${o.count}\xD7</span>).`)):o.count>=10&&n(o.from,`Repeated counterparty flow to ${z(o.to)} (<span class="mono">${o.count}\xD7</span>). Persistent repetition often indicates automation.`)}if((d=e.clusters)!=null&&d.length&&e.clusters[0].size>=3&&n(e.clusters[0].hub,`Cluster hub of <span class="mono">${e.clusters[0].size}</span> wallets. Coordination is a common feature of wash/loop tactics.`),(m=(p=e.advanced)==null?void 0:p.topPathActors)!=null&&m.length){let f=e.advanced.topPathActors[0];f.count>=6&&n(f.acct,`Heavy path\u2011payment routing (<span class="mono">${f.count}</span>). Often correlates with arbitrage bots.`)}return t.slice(0,6)}function Ob(){if(Dp)return;Dp=!0;let e=document.querySelector(".dashboard-col-side");if(!e)return;let t=document.createElement("section");t.className="widget-card",t.id="dex-pattern-card",t.setAttribute("aria-label","DEX pattern monitor"),t.innerHTML=`
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
  `,e.prepend(t)}function Bb(e){var p,m;if(!document.getElementById("dex-pattern-card"))return;let t=e.window.total||0,n=t?Math.round(e.window.cancelRatio*100):0,s=t?Math.round(e.topShare*100):0;V("dexp-badge",t?`${t} offer tx \xB7 ${n}% cancels`:"Quiet");let a=w("dexp-cancel-bar");a&&(a.style.width=`${we(n,0,100)}%`),V("dexp-cancel-val",t?`${n}%`:"\u2014");let o=w("dexp-topshare-bar");o&&(o.style.width=`${we(s,0,100)}%`),V("dexp-topshare-val",t?`${s}%`:"\u2014");let i=e.burstPct,r=i==null?0:Math.min(100,Math.abs(i)),l=w("dexp-burst-bar");l&&(l.style.width=`${r}%`),V("dexp-burst-val",i==null?"\u2014":vn(i,0)),V("dexp-cpm",e.now.cancelsPerMin==null?"\u2014":e.now.cancelsPerMin.toFixed(1)),V("dexp-hhi",t?e.actorHHI.toFixed(2):"\u2014"),V("dexp-totalwin",t?`${t}`:"\u2014");let c=w("dexp-signals");c&&(c.innerHTML=e.signals.length?e.signals.map(f=>`<span class="sig-pill warn">${y(f)}</span>`).join(""):'<span class="sig-pill ok">No strong DEX signals</span>');let u=w("dexp-cancellers");u&&(u.innerHTML=(p=e.topCanceller)!=null&&p.length?e.topCanceller.slice(0,5).map(f=>`
        <div class="dex-rowline">
          <button class="addr-link mono cut" data-addr="${y(f.acct)}">${y(z(f.acct))}</button>
          <span class="mono">${f.count}</span>
        </div>`).join(""):'<div style="opacity:.7">\u2014</div>');let d=w("dexp-makers");d&&(d.innerHTML=(m=e.topMaker)!=null&&m.length?e.topMaker.slice(0,5).map(f=>`
        <div class="dex-rowline">
          <button class="addr-link mono cut" data-addr="${y(f.acct)}">${y(z(f.acct))}</button>
          <span class="mono">${f.count}</span>
        </div>`).join(""):'<div style="opacity:.7">\u2014</div>')}function Xb(){if(Ip)return;Ip=!0;let e=document.querySelector(".dashboard-col-main");if(!e)return;let t=document.createElement("section");t.className="widget-card",t.id="risk-card",t.setAttribute("aria-label","Risk panel"),t.innerHTML=`
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
  `,t.querySelectorAll(".risk-box-toggle").forEach(n=>{var a;n.addEventListener("click",()=>{let o=n.getAttribute("data-target"),i=document.getElementById(o);if(!i)return;let r=n.getAttribute("aria-expanded")!=="false";n.setAttribute("aria-expanded",r?"false":"true"),i.classList.toggle("risk-collapsed",r),n.querySelector(".risk-box-chevron").textContent=r?"\u25B8":"\u25BE";try{localStorage.setItem("risk_collapsed_"+o,r?"1":"0")}catch{}});let s=n.getAttribute("data-target");try{localStorage.getItem("risk_collapsed_"+s)==="1"&&(n.setAttribute("aria-expanded","false"),(a=document.getElementById(s))==null||a.classList.add("risk-collapsed"),n.querySelector(".risk-box-chevron").textContent="\u25B8")}catch{}}),e.appendChild(t)}function Hb(e){var r,l,c,u,d,p,m,f,g,v;if(!document.getElementById("risk-card"))return;V("risk-badge",`Risk ${e.friction}/100`),V("risk-regime",e.regime),V("risk-friction",`${e.friction}/100`);let t=[];e.hhi>=.35&&t.push({cls:"warn",t:"High concentration"}),e.breadcrumbs.filter(h=>h.count>=2).length>=3&&t.push({cls:"new",t:"Repeating counterparties"}),(l=(r=e.behavior)==null?void 0:r.bots)!=null&&l.length&&t.push({cls:"warn",t:"Bot-like timing"}),(u=(c=e.dexPatterns)==null?void 0:c.signals)!=null&&u.length&&t.push({cls:"warn",t:"DEX churn signals"}),((d=e.advanced)==null?void 0:d.selfTradeCount)>0&&t.push({cls:"warn",t:`Self-transfer: ${e.advanced.selfTradeCount}`}),(((p=e.advanced)==null?void 0:p.roundnessIdx)??0)>=45&&t.push({cls:"warn",t:`Round-number bias ${e.advanced.roundnessIdx}%`}),((m=e.advanced)==null?void 0:m.pathPays)>0&&t.push({cls:"warn",t:`Path flow: ${e.advanced.pathPays}`}),V("risk-signalcount",`${t.length}`);let n=w("risk-pills");n&&(n.innerHTML=t.length?t.map(h=>`<span class="sig-pill ${h.cls}">${y(h.t)}</span>`).join(""):'<span class="sig-pill ok">No elevated signals</span>');let s=w("risk-bots");if(s){let h=((f=e.behavior)==null?void 0:f.bots)||[];if(h.length){let b={};for(let k of h){let T=k.botType||"Periodic";b[T]||(b[T]=[]),b[T].push(k)}let x=["Market Maker","Arbitrage","Flood / Spam","Periodic"];s.innerHTML=x.filter(k=>b[k]).map(k=>{let T=b[k];return`<div class="bot-type-group">
          <div class="bot-type-label" style="color:${T[0].botTypeColor||"rgba(255,255,255,.8)"}">${k}</div>
          ${T.map($=>`
            <div class="risk-row bot-row">
              <button class="addr-link mono cut" data-addr="${y($.acct)}" title="${y($.acct)}">${y(z($.acct))}</button>
              <div class="bot-row-meta">
                <span class="mono bot-cv" style="color:${$.cv<.1?"#ff5555":$.cv<.2?"#ffb86c":"rgba(255,255,255,.65)"}">CV ${$.cv.toFixed(2)}</span>
                <span class="bot-total mono">${$.total}tx</span>
              </div>
            </div>
            ${$.botDesc?`<div class="bot-desc">${y($.botDesc)}</div>`:""}
          `).join("")}
        </div>`}).join("")}else s.innerHTML='<div style="opacity:.7;font-size:.84rem">No periodic bots detected yet</div>'}let a=w("risk-amm");if(a){let h=e.advanced||{},{ammCreate:b=0,ammDeposit:x=0,ammWithdraw:k=0,ammVote:T=0,ammBid:S=0,lpTotal:$=0,lpNetFlow:E=0,lpRatio:C,lpUniqueActors:P=0}=h;if($===0)a.innerHTML='<div style="opacity:.6;font-size:.84rem">No AMM activity in this ledger</div>';else{let R=E>0?"#50fa7b":E<0?"#ff5555":"rgba(255,255,255,.5)";a.innerHTML=`
        <div class="amm-chips">
          ${b?`<span class="amm-chip amm-create">\u{1F195} Create \xD7${b}</span>`:""}
          ${x?`<span class="amm-chip amm-dep">\u2193 Deposit \xD7${x}</span>`:""}
          ${k?`<span class="amm-chip amm-wd">\u2191 Withdraw \xD7${k}</span>`:""}
          ${T?`<span class="amm-chip amm-vote">\u{1F5F3} Vote \xD7${T}</span>`:""}
          ${S?`<span class="amm-chip amm-bid">\u{1F4E3} Bid \xD7${S}</span>`:""}
        </div>
        <div class="risk-row" style="margin-top:8px"><span>Net LP flow</span>
          <span class="mono" style="color:${R}">${E>0?"+"+E+" (adding LP)":E<0?E+" (removing LP)":"0 (balanced)"}</span></div>
        ${C!=null?`<div class="risk-row"><span>Deposit ratio</span><span class="mono">${C}% depositing</span></div>`:""}
        <div class="risk-row"><span>Unique LP actors</span><span class="mono">${P||"\u2014"}</span></div>
        <div class="risk-row"><span>Total LP ops</span><span class="mono">${$}</span></div>`}}let o=w("risk-path");if(o){let h=e.advanced||{},b=(g=h.topPathActors)==null?void 0:g[0],x=(v=h.topPathActors)==null?void 0:v[1],k=h.selfTradeCount>0?"#ff5555":"rgba(255,255,255,.5)",T=(h.roundnessIdx??0)>=45?"#ff5555":(h.roundnessIdx??0)>=25?"#ffb86c":"rgba(255,255,255,.5)";o.innerHTML=`
      <div class="risk-row"><span>Path payments</span><span class="mono">${h.pathPays??"\u2014"}</span></div>
      ${h.avgPathDepth!=null?`<div class="risk-row"><span>Avg path depth</span><span class="mono">${h.avgPathDepth} hops</span></div>`:""}
      ${b?`<div class="risk-row"><span>Top router</span>
        <button class="addr-link mono cut" data-addr="${y(b.acct)}">${y(z(b.acct))}</button></div>
        <div class="risk-row" style="opacity:.75"><span style="padding-left:8px">\u21B3 count</span><span class="mono">${b.count}</span></div>`:""}
      ${x?`<div class="risk-row" style="opacity:.7"><span>2nd router</span>
        <button class="addr-link mono cut" data-addr="${y(x.acct)}">${y(z(x.acct))}</button></div>`:""}
      <div class="risk-row" style="margin-top:4px;border-top:1px solid rgba(255,255,255,.05);padding-top:8px">
        <span>Round-number %</span><span class="mono" style="color:${T}">${h.roundnessIdx!=null?h.roundnessIdx+"%":"\u2014"}</span></div>
      <div class="risk-row"><span>Self-transfers</span><span class="mono" style="color:${k}">${h.selfTradeCount??0}</span></div>`}let i=w("risk-notes");i&&(i.innerHTML=`
    <div style="opacity:.85">Signals are not proof. Use them to choose what to inspect.</div>
    <div style="opacity:.85">DEX monitor uses OfferCreate/OfferCancel only \u2014 no orderbook polling.</div>
    <div style="opacity:.85">Click any address to peek, then "Open in Inspector".</div>`)}function zb(){if(zp)return;zp=!0;let e=document.querySelector(".dashboard-col-side");if(e){if(!document.getElementById("dex-pressure-card")){let t=document.createElement("section");t.className="widget-card",t.id="dex-pressure-card",t.setAttribute("aria-label","DEX pressure"),t.innerHTML=`
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
    `,e.prepend(t)}}}function jb(){fe.dexPressure=[],fe.nftMints=[],fe.nftBurns=[],fe.autoBridge=[],Ii.clear(),Object.keys(Di).forEach(e=>delete Di[e]),yu({offerTotal:null,dexCancelPct:null,dexTopSharePct:null,mints:null,burns:null,pathPays:null,topPathActors:[],topPathPairs:[]})}function cs(e,t,n){for(e.push(Number(t||0));e.length>n;)e.shift()}function Wb(e){var n,s,a,o;let t=e==null?void 0:e.advanced;t&&(cs(fe.dexPressure,t.offerTotal,Dg),cs(fe.nftMints,t.mints,Lp),cs(fe.nftBurns,t.burns,Lp),cs(fe.autoBridge,t.pathPays,Ig),yu(t),(n=ye.dexPressure)==null||n.draw(fe.dexPressure),(s=ye.nftMints)==null||s.draw(fe.nftMints),(a=ye.nftBurns)==null||a.draw(fe.nftBurns),(o=ye.autoBridge)==null||o.draw(fe.autoBridge))}function yu(e){var t,n,s;if(document.getElementById("dex-pressure-card")&&(V("dexP-badge",e.offerTotal==null?"Waiting\u2026":`${e.offerTotal} offer tx`),V("dexP-now",e.offerTotal==null?"\u2014":e.offerTotal),V("dexP-cancel",e.dexCancelPct==null?"\u2014":`${e.dexCancelPct}%`),V("dexP-share",e.dexTopSharePct==null?"\u2014":`${e.dexTopSharePct}%`)),document.getElementById("autobridge-card")){V("ab-badge",e.pathPays==null?"Waiting\u2026":`${e.pathPays} path pays`),V("ab-now",e.pathPays==null?"\u2014":e.pathPays);let a=(t=e.topPathActors)==null?void 0:t[0];V("ab-top-actor",a?z(a.acct):"\u2014"),V("ab-pairs",(n=e.topPathPairs)!=null&&n.length?e.topPathPairs.length:"\u2014");let o=w("ab-top-pairs");o&&(o.innerHTML=(s=e.topPathPairs)!=null&&s.length?e.topPathPairs.map(i=>`
          <div class="dex-rowline">
            <span class="mono cut">${y(z(i.from))}</span>
            <span style="opacity:.7">\u2192</span>
            <span class="mono cut">${y(z(i.to))}</span>
            <span class="mono">${i.count}</span>
          </div>`).join(""):'<div style="opacity:.7">\u2014</div>')}if(document.getElementById("nft-mint-card")){let a=Number(e.mints||0)-Number(e.burns||0);V("nft-badge",e.mints==null&&e.burns==null?"Waiting\u2026":`${e.mints||0} mints \xB7 ${e.burns||0} burns`),V("nft-mints-now",e.mints==null?"\u2014":e.mints),V("nft-burns-now",e.burns==null?"\u2014":e.burns),V("nft-net-now",`${a}`)}}function Za({force:e=!1}={}){if(!Yt()){ji();return}mn&&!e||(mn&&(clearInterval(mn),mn=null),Zp(),mn=setInterval(()=>{Yt()&&Zp()},Fg))}function ji(){mn&&(clearInterval(mn),mn=null)}async function Zp(){var t,n,s,a,o,i,r,l,c,u;let e=++Ai;V("mkt-badge","Loading\u2026");try{let p=await fetch("https://api.exchange.coinbase.com/products/XRP-USD/candles?granularity=3600",{cache:"no-store"});if(!p.ok)throw new Error("market history failed");let m=await p.json();if(!Array.isArray(m)||m.length<10)throw new Error("no history");if(e!==Ai)return;let f=[...m].sort((k,T)=>Number(k[0])-Number(T[0])),g=f.map(k=>Number(k[4])).filter(Number.isFinite),v=f.map(k=>Number(k[5])).filter(Number.isFinite);fe.marketPrice=g.slice(-za),fe.marketVol=v.slice(-za);let h=fe.marketPrice.at(-1),b=fe.marketPrice.length>24?fe.marketPrice.at(-25):fe.marketPrice.at(0),x=b&&h?(h-b)/b*100:null;V("mkt-badge",h?`$${h.toFixed(4)}`:"\u2014"),V("mkt-price",h?`$${h.toFixed(4)}`:"\u2014"),V("mkt-chg",x==null?"\u2014":vn(x,2)),V("mkt-upd",new Date().toLocaleTimeString()),(t=ye.marketPrice)==null||t.draw(fe.marketPrice),(n=ye.marketVol)==null||n.draw(fe.marketVol);return}catch{}try{let d=await fetch("https://api.coinpaprika.com/v1/tickers/xrp-xrp",{cache:"no-store"});if(!d.ok)throw new Error("tick failed");let p=await d.json();if(e!==Ai)return;let m=Number((a=(s=p==null?void 0:p.quotes)==null?void 0:s.USD)==null?void 0:a.price),f=Number((i=(o=p==null?void 0:p.quotes)==null?void 0:o.USD)==null?void 0:i.volume_24h),g=Number((l=(r=p==null?void 0:p.quotes)==null?void 0:r.USD)==null?void 0:l.percent_change_24h);Number.isFinite(m)&&(cs(fe.marketPrice,m,za),Number.isFinite(f)&&cs(fe.marketVol,f,za)),V("mkt-badge",Number.isFinite(m)?`$${m.toFixed(4)}`:"\u2014"),V("mkt-price",Number.isFinite(m)?`$${m.toFixed(4)}`:"\u2014"),V("mkt-chg",Number.isFinite(g)?`${g>=0?"\u2191":"\u2193"}${Math.abs(g).toFixed(2)}%`:"\u2014"),V("mkt-upd",new Date().toLocaleTimeString()),(c=ye.marketPrice)==null||c.draw(fe.marketPrice),(u=ye.marketVol)==null||u.draw(fe.marketVol)}catch{V("mkt-badge","Unavailable")}}function Ub(){var n,s,a,o;if(jp)return;jp=!0;let e=document.querySelector(".dashboard-fullwidth");if(!e){e=document.createElement("div"),e.className="dashboard-fullwidth";let i=document.querySelector(".dashboard-columns");i?i.insertAdjacentElement("afterend",e):(n=document.querySelector(".dashboard-page"))==null||n.appendChild(e)}if(document.getElementById("spam-defense-card"))return;let t=document.createElement("section");t.className="widget-card",t.id="spam-defense-card",t.setAttribute("aria-label","Spam defense"),Wi(),$u(),t.innerHTML=`
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
          <input type="range" id="sim-base" min="1" max="500" step="1" value="${gs}"
            oninput="_renderBondSim()" style="width:100%;margin-top:4px">
          <span id="sim-base-val" class="mono" style="font-size:.72rem">${gs} XRP</span>
        </label>
        <label style="font-size:.78rem;opacity:.7">
          Growth factor
          <input type="range" id="sim-growth" min="1.2" max="4" step="0.1" value="${bs}"
            oninput="_renderBondSim()" style="width:100%;margin-top:4px">
          <span id="sim-growth-val" class="mono" style="font-size:.72rem">${bs}\xD7</span>
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
  `,e.appendChild(t),(s=w("spam-copy-hash"))==null||s.addEventListener("click",()=>{var i;return eu(((i=w("spam-proof-hash"))==null?void 0:i.textContent)||"")}),(a=w("spam-copy-json"))==null||a.addEventListener("click",()=>{var i;return eu(((i=w("spam-proof-json"))==null?void 0:i.textContent)||"")}),(o=w("spam-print-proof"))==null||o.addEventListener("click",nv),_renderBondSim()}window._toggleBondSim=function(){let e=w("spam-sim-panel");if(!e)return;let t=e.style.display!=="none";e.style.display=t?"none":"";let n=w("spam-sim-toggle");n&&(n.style.color=t?"":"#00d4ff")};window._renderBondSim=function(){let e=document.getElementById("sim-base"),t=document.getElementById("sim-growth"),n=document.getElementById("sim-table");if(!n)return;let s=Number((e==null?void 0:e.value)||gs),a=Number((t==null?void 0:t.value)||bs),o=fe.marketPrice.at(-1)??null;document.getElementById("sim-base-val")&&(document.getElementById("sim-base-val").textContent=s+" XRP"),document.getElementById("sim-growth-val")&&(document.getElementById("sim-growth-val").textContent=a+"\xD7");let i="";for(let r=0;r<=Js;r++){let l=Math.round(s*a**r),c=o?"$"+(l*o).toLocaleString(void 0,{maximumFractionDigits:0}):"",u=r<3?"#50fa7b":r<6?"#ffb86c":"#ff5555";i+=`<div style="padding:5px;border-radius:6px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07)">
      <div style="font-size:.65rem;opacity:.5">L${r}</div>
      <div style="color:${u};font-weight:800">${l>=1e3?(l/1e3).toFixed(1)+"k":l}</div>
      ${c?`<div style="font-size:.62rem;opacity:.45">${c}</div>`:""}
    </div>`}n.innerHTML=i};async function eu(e){try{await navigator.clipboard.writeText(String(e||"")),ne("Copied")}catch{he("Copy failed (browser blocked clipboard).")}}function Gs(e){let t=we(Number(e)||0,0,Js);return Math.round(gs*bs**t)}function Wi(){try{let e=JSON.parse(localStorage.getItem(lu)||"[]");ie.allowList=new Set(e)}catch{ie.allowList=new Set}}function wu(){try{localStorage.setItem(lu,JSON.stringify([...ie.allowList]))}catch{}}function xu(e){He(e)&&(ie.allowList.add(e),wu(),ie.byAddr.delete(e),ne(`${z(e)} added to allow-list \u2014 will no longer be flagged`))}window._spamAllowAddr=xu;function ku(){try{return JSON.parse(localStorage.getItem(ru)||"{}")}catch{return{}}}function qb(e){try{localStorage.setItem(ru,JSON.stringify(e))}catch{}}function $u(){let e=ku();for(let[t,n]of Object.entries(e))ie.verifiedCache.set(t,n)}window.exportSpamReputation=function(){let e=[...ie.byAddr.entries()].map(([o,i])=>({addr:o,level:i.level,strikes:i.strikes,score:+(i.score||0).toFixed(4),threatType:i.threatType||"Unknown",verified:!!i.verifiedLedger,verifiedLedger:i.verifiedLedger??null,lastSeen:i.lastSeenLedger??null})),t={v:2,network:X.currentNetwork||"xrpl-mainnet",exportedAt:new Date().toISOString(),allowList:[...ie.allowList],suspects:e,policy:{bondBaseXrp:gs,bondGrowth:bs,ratchetMax:Js}},n=new Blob([JSON.stringify(t,null,2)],{type:"application/json"}),s=URL.createObjectURL(n),a=document.createElement("a");a.href=s,a.download=`naluxrp_reputation_${new Date().toISOString().slice(0,10)}.json`,document.body.appendChild(a),a.click(),document.body.removeChild(a),URL.revokeObjectURL(s),ne("Reputation list exported")};window.importSpamReputation=function(e){if(!e)return;let t=new FileReader;t.onload=n=>{var s;try{let a=JSON.parse(n.target.result);if(!a.suspects)throw new Error("Invalid format");let o=0;for(let i of a.suspects){if(!He(i.addr))continue;let r=ie.byAddr.get(i.addr)||{};ie.byAddr.set(i.addr,{...r,level:i.level??0,strikes:i.strikes??0,score:i.score??0,threatType:i.threatType??"Unknown",verifiedLedger:i.verifiedLedger??null,lastSeenLedger:i.lastSeen??null,scoreHistory:[],signalBreakdown:{}}),o++}if((s=a.allowList)!=null&&s.length){for(let i of a.allowList)He(i)&&ie.allowList.add(i);wu()}ne(`Imported ${o} reputation entries`)}catch(a){he("Import failed: "+a.message)}},t.readAsText(e)};function Vb(e){var l,c;if(!document.getElementById("spam-defense-card"))return;let t=Yb(e),n=t.reduce((u,d)=>Math.max(u,d.level),0),s=t.filter(u=>u.verified).length,a=fe.marketPrice.at(-1)??null,o=t.reduce((u,d)=>u+Gs(d.level),0),i=a?`~$${(o*a).toLocaleString(void 0,{maximumFractionDigits:0})}`:`${o} XRP`;V("spam-count",t.length),V("spam-maxlvl",`L${n}`),V("spam-verified",s),V("spam-allowcount",ie.allowList.size),V("spam-bondusd",i),V("spam-badge",t.length?`${t.length} tracked \xB7 max L${n}`:"Quiet");let r=w("spam-list");if(r&&(t.length?r.innerHTML=t.map(u=>{let d=Gs(u.level),p=a?` (~$${(d*a).toFixed(0)})`:"",m=u.level>=6?"#ff5555":u.level>=3?"#ffb86c":"#50fa7b",f=u.score>=.7?"#ff5555":u.score>=.4?"#ffb86c":"#50fa7b",g={"Payment Flooder":"#ff5555","Quote Stuffer":"#ff5555","Wash Trader":"#ff5555","DEX Bot":"#ffb86c","Arb Router":"#00d4ff","Periodic Bot":"#bd93f9"}[u.threatType]||"rgba(255,255,255,.6)",v=u.verified?`<span class="spam-cred-chip">\u2714 L${u.level} verified</span>`:"",h=Gb(u.scoreHistory||[]);return`
          <div class="spam-card" data-spam-addr="${y(u.addr)}">
            <div class="spam-card-top">
              <button class="addr-link mono spam-card-addr" data-addr="${y(u.addr)}">${y(z(u.addr))}</button>
              <div class="spam-card-actions">
                <button class="spam-btn" data-action="expand"  data-spam-addr="${y(u.addr)}">\u25BE Detail</button>
                <button class="spam-btn" data-action="proof"   data-spam-addr="${y(u.addr)}">Proof</button>
                <button class="spam-btn" data-action="allow"   data-spam-addr="${y(u.addr)}" title="Trust this address permanently">\u2713 Allow</button>
                <button class="spam-btn spam-btn-clear" data-action="clear" data-spam-addr="${y(u.addr)}">\u2715</button>
              </div>
            </div>
            <div class="spam-card-meta">
              <span class="spam-meta-chip">Level <b style="color:${m}">L${u.level}</b></span>
              <span class="spam-meta-chip">Score <b style="color:${f}">${Math.round(u.score*100)}%</b></span>
              <span class="spam-meta-chip" style="color:${g}">${y(u.threatType)}</span>
              <span class="spam-meta-chip">Bond <b>${d>=1e3?(d/1e3).toFixed(1)+"k":d} XRP${p}</b></span>
              ${v}
              <span title="Score trend \u2014 last ${(u.scoreHistory||[]).length} ledgers" style="margin-left:auto">${h}</span>
            </div>
            <!-- Expandable signal breakdown (hidden by default) -->
            <div class="spam-breakdown" id="spam-bd-${y(u.addr.slice(0,10))}" style="display:none">
              ${Kb(u.breakdown,u.strikes)}
            </div>
          </div>`}).join(""):r.innerHTML=`<div class="spam-empty">No suspects flagged \u2014 allow-list has ${cu.size} known-good entities.</div>`),Bi||Jb(),ie.selectedAddr){let u=ie.byAddr.get(ie.selectedAddr);u?Ui(ie.selectedAddr,u,e.s.ledgerIndex).then(d=>hs(d)):hs(null)}((l=document.getElementById("spam-sim-panel"))==null?void 0:l.style.display)!=="none"&&((c=window._renderBondSim)==null||c.call(window))}function Gb(e){if(!(e!=null&&e.length))return"";let t=42,n=14,s=1,a=t/Math.max(1,e.length-1),o=e.map((l,c)=>`${(c*a).toFixed(1)},${(n-2-l/s*(n-4)).toFixed(1)}`).join(" "),i=e.at(-1)??0,r=i>=.7?"#ff5555":i>=.4?"#ffb86c":"#50fa7b";return`<svg width="${t}" height="${n}" xmlns="http://www.w3.org/2000/svg" style="overflow:visible">
    <polyline points="${o}" fill="none" stroke="${r}" stroke-width="1.5" stroke-linejoin="round"/>
    <circle cx="${((e.length-1)*a).toFixed(1)}" cy="${(n-2-i/s*(n-4)).toFixed(1)}"
      r="2" fill="${r}"/>
  </svg>`}function Kb(e={},t=0){let n=[{label:"Bot timing",val:e.bot??0,desc:e.botType?`Type: ${e.botType}`:"Low variance in repeated ledger appearances"},{label:"DEX dominance",val:e.dexDom??0,desc:"Share of offer tx window controlled by this address"},{label:"Cancel pattern",val:e.cancelPat??0,desc:"Heavy OfferCancel activity relative to creates"},{label:"Ping-pong loop",val:e.pingPong??0,desc:"Bidirectional repeated payments between two addresses"},{label:"Path routing",val:e.pathRoute??0,desc:"High path-payment count \u2014 common in arb bots"},{label:"Self-transfer",val:e.selfTrade??0,desc:"Payments where sender = receiver"},{label:"Round-number pay",val:e.roundPay??0,desc:"Unusual bias toward exact round-number payment amounts"}].filter(s=>s.val>.001);return n.length?`
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
    </div>`:'<div style="opacity:.5;font-size:.78rem;padding:6px 0">No significant signal breakdown available yet.</div>'}var Bi=!1;function Jb(){Bi||(Bi=!0,document.addEventListener("click",e=>{var a,o,i,r;let t=(o=(a=e.target).closest)==null?void 0:o.call(a,"button[data-action][data-spam-addr]");if(!t)return;let n=t.getAttribute("data-action"),s=t.getAttribute("data-spam-addr");if(s){if(n==="proof"){let l=ie.byAddr.get(s);if(!l)return;ie.selectedAddr=s;let c=w("spam-proof");if(c){c.style.display="";let u=w("spam-proof-hash");u&&(u.textContent="Computing SHA-512Half\u2026")}Ui(s,l,((r=(i=X.ledgerLog)==null?void 0:i[0])==null?void 0:r.ledgerIndex)||null).then(u=>{ie.selectedProof=u,hs(u)}).catch(u=>he("Proof build failed: "+u.message));return}if(n==="clear"){ie.byAddr.delete(s),ie.selectedAddr===s&&hs(null),ne("Cleared from session");return}if(n==="allow"){xu(s),ie.byAddr.delete(s),ie.selectedAddr===s&&hs(null);return}if(n==="expand"){let l=s.slice(0,10),c=document.getElementById("spam-bd-"+l);if(!c)return;let u=c.style.display!=="none";c.style.display=u?"none":"",t.textContent=u?"\u25BE Detail":"\u25B4 Hide";return}}}))}function hs(e){let t=w("spam-proof");if(!t)return;if(!e){t.style.display="none";return}t.style.display="",V("spam-proof-hash",e.hash);let n=w("spam-proof-json");n&&(n.textContent=e.canonicalJson);let s=w("spam-cred-step");s&&(s.innerHTML=`
      <div style="opacity:.9">
        To \u201Ccredential\u201D this address at level <b>L${e.level}</b>, do:
      </div>
      <ul style="margin:8px 0 0 18px;opacity:.9">
        <li><b>EscrowCreate</b> locking <b>${e.policy.bondRequiredXrp} XRP</b> to <b>itself</b> for ~24h (strong bond; funds are locked).</li>
        <li>Include a Memo that starts with <span class="mono">${fn}</span> and then the proof hash.</li>
        <li>Alternatively (cheap): send a 1-drop self-payment with <b>DestinationTag=${ds+e.level}</b> and the same memo.</li>
      </ul>
      <div style="opacity:.75;margin-top:8px">
        This dashboard will mark it verified once it sees a matching on-ledger tx in the stream.
      </div>
    `)}function Yb(e){var o,i,r,l,c;ie.allowList.size||Wi();let t=new Set;(((o=e.behavior)==null?void 0:o.bots)||[]).forEach(u=>t.add(u.acct)),(((i=e.dexPatterns)==null?void 0:i.topActor)||[]).forEach(u=>t.add(u.acct)),(((r=e.dexPatterns)==null?void 0:r.topCanceller)||[]).forEach(u=>t.add(u.acct)),(((l=e.dexPatterns)==null?void 0:l.topMaker)||[]).forEach(u=>t.add(u.acct)),(e.breadcrumbs||[]).forEach(u=>{t.add(u.from),t.add(u.to)}),(e.clusters||[]).forEach(u=>{t.add(u.hub),(u.members||[]).forEach(d=>t.add(d))}),(((c=e.advanced)==null?void 0:c.topPathActors)||[]).forEach(u=>t.add(u.acct));let n=Number(e.s.ledgerIndex||0)||null,s=e.txs||[],a=[];if(n&&n%50===0){let u=Va*24;for(let[d,p]of ie.byAddr)n-(p.lastSeenLedger||0)>u&&ie.byAddr.delete(d)}for(let u of t){if(!He(u)||cu.has(u)||ie.allowList.has(u))continue;let{score:d,breakdown:p}=Zb(u,e),m=Qb(p),f=ie.byAddr.get(u)||{strikes:0,level:0,score:0,verifiedLedger:null,lastSeenLedger:null,scoreHistory:[],threatType:"Unknown",signalBreakdown:{}},g=f.strikes||0;d>=iu?g+=1:d<=Ri&&(g=Math.max(0,g-1));let v=f.lastSeenLedger||n,h=n?n-v:0;if(h>Va&&d<Ri){let $=Math.floor(h/Va);g=Math.max(0,g-$)}let b=we(Math.floor(g/ou),0,Js),x=[...f.scoreHistory||[],d].slice(-10),k=ie.verifiedCache.get(u),T=f.verifiedLedger??(k==null?void 0:k.ledgerIndex)??null;T||(T=ev(u,b,s,n),T&&tv(u,b,n));let S={score:d,strikes:g,level:b,verifiedLedger:T,lastSeenLedger:n,scoreHistory:x,threatType:m,signalBreakdown:p};ie.byAddr.set(u,S),a.push({addr:u,score:d,strikes:g,level:b,verified:!!T,verifiedLedger:T,scoreHistory:x,threatType:m,breakdown:p})}return a.sort((u,d)=>d.level-u.level||d.score-u.score),a.slice(0,Bg)}function Qb(e){let{bot:t=0,dexDom:n=0,cancelPat:s=0,pingPong:a=0,pathRoute:o=0,selfTrade:i=0,roundPay:r=0}=e,l=n+s;return t>.25&&(e.botType==="Flood / Spam"||r>.05)?"Payment Flooder":t>.2&&l>.15?"DEX Bot":l>.3&&s>.1?"Quote Stuffer":a>.1?"Wash Trader":o>.1?"Arb Router":t>.2?"Periodic Bot":"Multi-Signal"}function Zb(e,t){var m,f,g,v,h;let n={bot:0,botType:null,dexDom:0,cancelPat:0,pingPong:0,pathRoute:0,selfTrade:0,roundPay:0},s=(((m=t.behavior)==null?void 0:m.bots)||[]).find(b=>b.acct===e);if(s){let b=we((.35-s.cv)/.35,0,1);n.bot=+(.4*(.5+.5*b)).toFixed(3),n.botType=s.botType||"Periodic"}let a=t.dexPatterns,o=((g=(f=a==null?void 0:a.topActor)==null?void 0:f[0])==null?void 0:g.acct)===e&&a.topShare||0;o>0&&(n.dexDom=+(.3*we((o-.2)/.4,0,1)).toFixed(3));let i=((a==null?void 0:a.topCanceller)||[]).find(b=>b.acct===e);i&&(n.cancelPat=+(.2*we(i.count/20,0,1)).toFixed(3));let r=t.breadcrumbs||[],l=r.find(b=>b.from===e&&b.to===e);l&&(n.selfTrade=+(.2*we(l.count/20,0,1)).toFixed(3));let c=r[0];if(c&&(c.from===e||c.to===e)){let b=r.find(x=>x.from===c.to&&x.to===c.from);b&&b.count>=3&&c.count>=3&&(n.pingPong=.15)}let u=(((v=t.advanced)==null?void 0:v.topPathActors)||[]).find(b=>b.acct===e);u&&(n.pathRoute=+(.15*we(u.count/25,0,1)).toFixed(3));let d=(h=t.advanced)==null?void 0:h.roundnessIdx;return d!=null&&d>=45&&(u||s)&&(n.roundPay=+(.1*we((d-45)/35,0,1)).toFixed(3)),{score:we(n.bot+n.dexDom+n.cancelPat+n.pingPong+n.pathRoute+n.selfTrade+n.roundPay,0,1),breakdown:n}}function ev(e,t,n,s){if(!(n!=null&&n.length))return null;let a=ds+t;for(let o of n)if((o==null?void 0:o.account)===e){if(o.type==="EscrowCreate"&&o.destination===e){let i=typeof o.amountXrp=="number"?o.amountXrp:null,r=Gs(t);if(i!=null&&i>=r&&Xi(o.memos).startsWith(fn))return s}if(o.type==="Payment"&&o.destination===e&&Number(o.destinationTag)===a&&Xi(o.memos).startsWith(fn))return s}return null}async function tv(e,t,n){var a;let s=ie.byAddr.get(e);if(s)try{let o=await Ui(e,s,n),i=fn+o.hash;if((((a=X.ledgerLog)==null?void 0:a.flatMap(c=>c.transactions||[]))||[]).some(c=>(c==null?void 0:c.account)!==e?!1:Xi(c.memos).startsWith(i))){let c=ku();c[e]={ledgerIndex:n,hash:o.hash,level:t},qb(c),ie.verifiedCache.set(e,{ledgerIndex:n,hash:o.hash}),ne(`\u2714 Credential verified for ${z(e)} at L${t}`)}}catch{}}function Xi(e){if(!Array.isArray(e))return"";let t=[];for(let n of e){let s=(n==null?void 0:n.Memo)||(n==null?void 0:n.memo)||null;if(!s)continue;let a=s.MemoData||s.memo_data||"";try{if(typeof a=="string"&&/^[0-9A-Fa-f]+$/.test(a)&&a.length%2===0){let o=Uint8Array.from(a.match(/../g),i=>parseInt(i,16));t.push(new TextDecoder().decode(o))}else typeof a=="string"&&t.push(a)}catch{}}return t.join(" ")}async function Ui(e,t,n){let s=t.level||0,a=Gs(s),o=fe.marketPrice.at(-1)??null,i=o?(a*o).toFixed(2):null,r={hashAlgorithm:"SHA-512Half",ratchetMax:Js,strikesToLevel:ou,strikeUp:iu,strikeDown:Ri,decayLedgers:Va,bondBaseXrp:gs,bondGrowthFactor:bs,bondRequiredXrp:a,bondRequiredUsd:i,credTagBase:ds,memoPrefix:fn,credentialTag:ds+s},l={v:2,hashAlg:"SHA-512Half",network:X.currentNetwork||"xrpl-mainnet",address:e,ledgerIndex:n!=null?Number(n):null,level:s,threatType:t.threatType||"Unknown",score:Number((t.score||0).toFixed(4)),strikes:Number(t.strikes||0),signalBreakdown:t.signalBreakdown||{},credential:{destinationTag:ds+s,memoFormat:fn+"<SHA-512Half-of-this-proof>",verifiedLedger:t.verifiedLedger??null},policy:r,note:"Generated by NaluXRP Spam Defense POC. Hash uses XRPL-native SHA-512Half (first 256 bits of SHA-512). A gateway or relayer policy can require the indicated bond/credential before providing service to this address.",generatedAt:new Date().toISOString()},c=JSON.stringify(l,Object.keys(l).sort(),0),u=await Ug(c);l.credential.memoFormat=fn+u;let d=JSON.stringify(l,null,2);return{hash:u,canonicalJson:d,level:s,policy:r,threatType:t.threatType}}function nv(){let e=ie.selectedProof;if(!e){he("Generate a proof first using the Proof button.");return}let t=ie.selectedAddr||"\u2014",n=fe.marketPrice.at(-1)??null,s=e.policy.bondRequiredXrp,a=n?` (~$${(s*n).toFixed(0)} USD)`:"",o=e.hash.startsWith("FALLBACK")?'<div style="padding:8px 12px;background:#fff3cd;border:1px solid #f0ad4e;border-radius:4px;margin-bottom:12px">\u26A0 Hash is non-cryptographic (SubtleCrypto unavailable). Do NOT use for enforcement.</div>':"",i=window.open("","_blank","width=760,height=660");i.document.write(`<!DOCTYPE html><html><head>
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
        ${s.toLocaleString()} XRP, finish ~25,000 ledgers from now, memo = <code>${fn}${e.hash}</code></p>
      <p style="font-size:.85rem"><b>Option B (1-drop payment):</b> Payment of 1 drop to itself,
        DestinationTag = ${ds+e.level}, same memo.</p>
    </div>
    <div class="section">
      <div class="section-h">Canonical Proof JSON (v2)</div>
      <pre>${e.canonicalJson.replace(/</g,"&lt;").replace(/>/g,"&gt;")}</pre>
    </div>
    </body></html>`),i.document.close()}var Su=null;function sv(){if(_i)return;_i=!0;let e=document.querySelector('[aria-label="Pattern detection"]');if(!e){e=document.createElement("section"),e.className="widget-card",e.setAttribute("aria-label","Pattern detection");let t=document.querySelector(".dashboard-col-main");if(!t)return;let n=t.querySelector(".dashboard-metrics");n?n.insertAdjacentElement("afterend",e):t.prepend(e)}e.innerHTML=`
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
    </div>`,Su=document.getElementById("pattern-donut-canvas")}function av(e,t){if(!_i)return;let n=typeof It<"u"?It:{},s=Object.entries(e||{}).filter(([,m])=>m>0).sort(([,m],[,f])=>f-m);if(!s.length)return;let a=s.reduce((m,[,f])=>m+f,0)||1,[o,i]=s[0],r=Math.round(i/a*100),l=s[1],c=w("pattern-badge");c&&(c.textContent=o+" \xB7 "+r+"%");let u=w("pattern-dom-type");if(u&&(u.textContent=o,u.style.color=n[o]||"rgba(255,255,255,.9)"),V("pattern-dom-pct",r+"% of ledger"),l){let m=Math.round(l[1]/a*100),f=w("pattern-2nd-type");f&&(f.textContent=l[0]+" ("+m+"%)",f.style.color=n[l[0]]||"rgba(255,255,255,.7)")}else V("pattern-2nd-type","\u2014");let d=w("pattern-hhi");d&&t!=null&&(d.textContent=t.toFixed(3),d.style.color=t>=.35?"#ff5555":t>=.25?"#ffb86c":"#50fa7b");let p=w("pattern-donut-center");p&&(p.innerHTML='<span style="color:'+(n[o]||"#fff")+';font-size:1.15rem">'+r+"%</span>"),ov(s,a,n)}function ov(e,t,n){let s=Su||w("pattern-donut-canvas");if(!(s!=null&&s.getContext))return;let a=s.getContext("2d"),o=s.width/2,i=s.height/2,r=Math.min(s.width,s.height)/2-6,l=r*.56;a.clearRect(0,0,s.width,s.height);let c=e.slice(0,7),u=e.slice(7).reduce((m,[,f])=>m+f,0),d=u>0?[...c,["Other",u]]:[...c],p=-Math.PI/2;for(let[m,f]of d){let g=f/t*Math.PI*2,v=us(n[m]||"#6b7280",.88)||"#6b7280";a.beginPath(),a.moveTo(o+Math.cos(p)*l,i+Math.sin(p)*l),a.arc(o,i,r,p,p+g),a.arc(o,i,l,p+g,p,!0),a.closePath(),a.fillStyle=v,a.fill(),a.strokeStyle="rgba(0,8,20,0.85)",a.lineWidth=2,a.stroke(),p+=g}a.beginPath(),a.arc(o,i,l-1,0,Math.PI*2),a.fillStyle="rgba(0,21,36,0.94)",a.fill()}function iv(e,t){let n=!1;for(let s of e){if((s==null?void 0:s.type)!=="Payment")continue;let a=typeof(s==null?void 0:s.amountXrp)=="number"?s.amountXrp:null;a==null||a<Xn.whaleTxXrp||(_t.unshift({ts:Date.now(),ledgerIndex:t,from:s.account||"\u2014",to:s.destination||"\u2014",amtXrp:a,hash:s.hash||""}),et.whaleCount++,n=!0)}if(n){for(;_t.length>Xg;)_t.pop();lv()}}function rv(){if(Wp)return;Wp=!0;let e=document.querySelector(".dashboard-col-side");if(!e)return;let t=document.createElement("section");t.className="widget-card",t.id="whale-feed-card",t.setAttribute("aria-label","Whale alert feed"),t.innerHTML=`
    <div class="widget-header">
      <span class="widget-title">\u{1F40B} Whale Alert Feed</span>
      <span class="widget-tag mono cut" id="whale-badge">Watching\u2026</span>
    </div>
    <p class="widget-help">Payments \u2265 ${Xn.whaleTxXrp.toLocaleString()} XRP from the live stream. Click address to peek.</p>
    <div id="whale-feed-list" style="max-height:260px;overflow-y:auto">
      <div style="opacity:.5;font-size:.82rem;padding:8px 0">Watching for large transfers\u2026</div>
    </div>`,e.prepend(t)}function lv(){let e=w("whale-feed-list");if(!e)return;let t=w("whale-badge");if(t&&(t.textContent=_t.length?`${_t.length} alerts`:"Watching\u2026"),!_t.length){e.innerHTML='<div style="opacity:.5;font-size:.82rem;padding:8px 0">No whale transactions yet.</div>';return}e.innerHTML=_t.slice(0,20).map(n=>{let s=n.amtXrp>=1e6?`${(n.amtXrp/1e6).toFixed(2)}M`:n.amtXrp>=1e3?`${(n.amtXrp/1e3).toFixed(0)}K`:n.amtXrp.toFixed(0),a=Math.floor((Date.now()-n.ts)/1e3),o=a<60?`${a}s`:a<3600?`${Math.floor(a/60)}m`:`${Math.floor(a/3600)}h`;return`<div style="border-bottom:1px solid rgba(255,255,255,.05);padding:7px 0">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">
        <span>\u{1F40B}</span><span style="font-size:.95rem;font-weight:700;color:#50fa7b">${s} XRP</span>
        <span style="font-size:.7rem;opacity:.45;margin-left:auto">${o} \xB7 #${n.ledgerIndex.toLocaleString()}</span>
      </div>
      <div style="display:flex;gap:4px;align-items:center;font-size:.74rem">
        <button class="addr-link mono cut" data-addr="${y(n.from)}" style="max-width:100px">${y(z(n.from))}</button>
        <span style="opacity:.5">\u2192</span>
        <button class="addr-link mono cut" data-addr="${y(n.to)}" style="max-width:100px">${y(z(n.to))}</button>
        ${n.hash?`<a href="https://livenet.xrpl.org/transactions/${y(n.hash)}" target="_blank" rel="noopener" style="margin-left:auto;color:var(--accent,#00d4ff);font-size:.7rem;text-decoration:none">\u{1F517}</a>`:""}
      </div>
    </div>`}).join("")}function cv(){if(Up)return;Up=!0;let e=document.querySelector(".dashboard-col-main");if(!e)return;let t=document.createElement("section");t.className="widget-card",t.id="network-health-card",t.setAttribute("aria-label","Network health"),t.innerHTML=`
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
    </div>`;let n=document.getElementById("landscape-card");n?e.insertBefore(t,n):e.prepend(t)}function dv(e){var g;if(!document.getElementById("network-health-card"))return;let t=Ht(X.tpsHistory,Qt),n=Ht(X.feeHistory,Qt),s=e.successRate!=null?Number(e.successRate):null,a=((g=e.latestLedger)==null?void 0:g.closeTimeSec)!=null?Number(e.latestLedger.closeTimeSec):null,o=t.cur!=null?we(Math.round(Math.min(t.cur,50)/50*25),0,25):12,i=n.deltaPct!=null?we(Math.round(25-Math.abs(n.deltaPct)/100*25),0,25):12,r=s!=null?we(Math.round(s/100*25),0,25):12,l=a!=null?we(Math.round(25-Math.max(0,(a-3)/7)*25),0,25):12,c=o+i+r+l,u=c>=75?"#50fa7b":c>=50?"#ffb86c":"#ff5555",d=c>=75?"Healthy":c>=50?"Degraded":"Stressed",p=w("health-score");p&&(p.textContent=c,p.style.color=u);let m=w("health-badge");m&&(m.textContent=d,m.style.color=u);let f=w("health-bars");f&&(f.innerHTML=[{label:"TPS",score:o,note:t.cur!=null?`${t.cur.toFixed(1)} tx/s`:"\u2014"},{label:"Fee Stable",score:i,note:n.deltaPct!=null?vn(n.deltaPct,0)+" vs avg":"\u2014"},{label:"Success",score:r,note:s!=null?`${s.toFixed(1)}%`:"\u2014"},{label:"Close Time",score:l,note:a!=null?`${a.toFixed(1)}s`:"\u2014"}].map(v=>{let h=v.score/25*100,b=v.score>=20?"#50fa7b":v.score>=12?"#ffb86c":"#ff5555";return`<div style="display:flex;align-items:center;gap:8px">
        <span style="font-size:.7rem;min-width:68px;opacity:.7">${v.label}</span>
        <div style="flex:1;height:5px;background:rgba(255,255,255,.08);border-radius:3px;overflow:hidden">
          <div style="height:100%;width:${h}%;background:${b};border-radius:3px"></div></div>
        <span style="font-size:.7rem;min-width:48px;text-align:right;opacity:.65">${v.note}</span>
      </div>`}).join(""))}function pv(){if(qp)return;qp=!0;let e=document.querySelector(".dashboard-col-side");if(!e)return;let t=document.createElement("section");t.className="widget-card",t.id="session-stats-card",t.setAttribute("aria-label","Session stats"),t.innerHTML=`
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
    </div>`,e.appendChild(t)}function uv(){if(!document.getElementById("session-stats-card"))return;let e=Math.floor((Date.now()-et.startTime)/6e4);V("ss-ledgers",et.ledgersProcessed.toLocaleString()),V("ss-tx",et.totalTx.toLocaleString()),V("ss-whales",et.whaleCount),V("ss-feespikes",et.feeSpikes),V("ss-bots",et.botDetections),V("ss-dexalerts",et.dexAlerts),V("ss-time",`${e}m`),V("ss-badge",`${et.ledgersProcessed} ledgers`)}function mv(e,t){var o,i,r,l,c,u,d,p;if(du=t,_t.length&&_t[0].ledgerIndex===t){let m=_t[0],f=m.amtXrp>=1e6?`${(m.amtXrp/1e6).toFixed(1)}M`:`${(m.amtXrp/1e3).toFixed(0)}K`;ne(`\u{1F40B} Whale: ${f} XRP  ${z(m.from)} \u2192 ${z(m.to)}`)}let n=hu(),s=(o=X.feeHistory)==null?void 0:o.at(-1);s&&n&&s>n*Xn.feeSpikeMultiple&&(et.feeSpikes++,he(`\u{1F525} Fee spike: ${hn(s)} (${Math.round(s/n)}\xD7 baseline)`));let a=(((i=e.behavior)==null?void 0:i.bots)||[]).filter(m=>m.cv<Xn.botCvThreshold&&m.total>8);a.length&&(et.botDetections=Math.max(et.botDetections,a.length),a[0].botType==="Flood / Spam"&&he(`\u{1F916} Spam bot: ${z(a[0].acct)} (CV ${a[0].cv.toFixed(2)})`)),((l=(r=e.dexPatterns)==null?void 0:r.window)==null?void 0:l.cancelRatio)>=Xn.dexCancelAlert&&((u=(c=e.dexPatterns)==null?void 0:c.window)==null?void 0:u.total)>=20&&(et.dexAlerts++,he(`\u{1F9E0} DEX: ${Math.round(e.dexPatterns.window.cancelRatio*100)}% cancel ratio \u2014 possible quote-stuffing`)),((p=(d=e.clusters)==null?void 0:d[0])==null?void 0:p.size)>=Xn.clusterMinSize&&ne(`\u{1F578} Cluster: ${e.clusters[0].size} wallets around ${z(e.clusters[0].hub)}`),e.friction>=75&&e.regime==="Manipulated"&&he(`\u26A0\uFE0F Risk score: ${e.friction}/100 \u2014 ${e.regime} regime`),dv(e.s)}function fv(){var n,s,a,o;if(Vp)return;Vp=!0;let e=document.createElement("button");e.id="customize-btn",e.className="customize-btn",e.setAttribute("aria-pressed","false"),e.innerHTML="\u2699 Customize",(n=document.querySelector(".dashboard-header"))==null||n.appendChild(e);let t=document.createElement("div");t.id="customize-panel",t.className="customize-panel",t.setAttribute("aria-label","Dashboard customizer"),t.innerHTML=`
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
    </div>`,document.body.appendChild(t),e.addEventListener("click",()=>tu()),(s=document.getElementById("customize-close"))==null||s.addEventListener("click",()=>tu(!1)),(a=document.getElementById("customize-reset"))==null||a.addEventListener("click",()=>{try{localStorage.removeItem(Ja),localStorage.removeItem(vs)}catch{}nu(),Hi(),qi()}),(o=document.getElementById("customize-export"))==null||o.addEventListener("click",()=>{var i;try{let r={order:JSON.parse(localStorage.getItem(Ja)||"[]"),hidden:JSON.parse(localStorage.getItem(vs)||"[]"),alertConfig:Xn};(i=navigator.clipboard)==null||i.writeText(JSON.stringify(r,null,2)),ne("Config copied to clipboard")}catch{he("Export failed")}}),nu(),Hi()}function tu(e){var s;let t=document.getElementById("customize-panel"),n=document.getElementById("customize-btn");!t||!n||(Bn=e??!Bn,t.classList.toggle("customize-panel--open",Bn),n.setAttribute("aria-pressed",String(Bn)),n.textContent=Bn?"\u2715 Close":"\u2699 Customize",Bn&&qi(),(s=document.querySelector(".dashboard-col-side"))==null||s.classList.toggle("customize-mode",Bn))}function Ks(){var e;return[...((e=document.querySelector(".dashboard-col-side"))==null?void 0:e.querySelectorAll(":scope > .widget-card"))||[]]}function ys(e){return e.id||e.getAttribute("aria-label")||""}function hv(e){var t,n;return((n=(t=e.querySelector(".widget-title"))==null?void 0:t.textContent)==null?void 0:n.trim())||ys(e)}function nu(){let e=document.querySelector(".dashboard-col-side");if(!e)return;let t;try{t=JSON.parse(localStorage.getItem(Ja)||"null")}catch{t=null}if(!Array.isArray(t)||!t.length)return;let n=new Map(Ks().map(s=>[ys(s),s]));t.forEach(s=>{let a=n.get(s);a&&e.appendChild(a)})}function Hi(){let e;try{e=JSON.parse(localStorage.getItem(vs)||"[]")}catch{e=[]}Ks().forEach(t=>t.classList.toggle("widget-hidden",e.includes(ys(t))))}function gv(){try{localStorage.setItem(Ja,JSON.stringify(Ks().map(e=>ys(e))))}catch{}}function bv(e){let t;try{t=JSON.parse(localStorage.getItem(vs)||"[]")}catch{t=[]}t=t.includes(e)?t.filter(n=>n!==e):[...t,e];try{localStorage.setItem(vs,JSON.stringify(t))}catch{}Hi(),qi()}function qi(){let e=document.getElementById("customize-list");if(!e)return;let t;try{t=JSON.parse(localStorage.getItem(vs)||"[]")}catch{t=[]}e.innerHTML="",Ks().forEach(n=>{var r;let s=ys(n),a=hv(n),o=!t.includes(s),i=document.createElement("div");i.className="customize-row",i.setAttribute("draggable","true"),i.dataset.widgetId=s,i.innerHTML=`
      <span class="customize-drag-handle" title="Drag to reorder">\u283F</span>
      <span class="customize-row-title">${y(a)}</span>
      <button class="customize-vis-btn ${o?"vis-on":"vis-off"}" data-id="${y(s)}">${o?"\u{1F441} Visible":"\u{1F6AB} Hidden"}</button>`,i.addEventListener("dragstart",l=>{rs=i,l.dataTransfer.effectAllowed="move",i.classList.add("customize-dragging")}),i.addEventListener("dragend",()=>{i.classList.remove("customize-dragging"),e.querySelectorAll(".customize-row").forEach(u=>u.classList.remove("customize-over"));let l=[...e.querySelectorAll(".customize-row")].map(u=>u.dataset.widgetId),c=document.querySelector(".dashboard-col-side");if(c){let u=new Map(Ks().map(d=>[ys(d),d]));l.forEach(d=>{let p=u.get(d);p&&c.appendChild(p)})}gv()}),i.addEventListener("dragover",l=>{if(l.preventDefault(),l.dataTransfer.dropEffect="move",rs&&rs!==i){e.querySelectorAll(".customize-row").forEach(u=>u.classList.remove("customize-over")),i.classList.add("customize-over");let c=[...e.querySelectorAll(".customize-row")];c.indexOf(rs)<c.indexOf(i)?e.insertBefore(rs,i.nextSibling):e.insertBefore(rs,i)}}),i.addEventListener("dragleave",()=>i.classList.remove("customize-over")),i.addEventListener("drop",l=>l.preventDefault()),(r=i.querySelector(".customize-vis-btn"))==null||r.addEventListener("click",()=>bv(s)),e.appendChild(i)})}function vv(){if(Gp)return;Gp=!0;let e=document.querySelector(".dashboard-header");if(!e||document.getElementById("global-pause-btn"))return;let t=document.createElement("button");t.id="global-pause-btn",t.className="global-pause-btn",t.setAttribute("aria-pressed","false"),t.title="Pause all updates \u2014 numbers stop changing so you can read",t.innerHTML="\u23F8 Live",t.addEventListener("click",()=>{Gt=!Gt,t.setAttribute("aria-pressed",String(Gt)),t.innerHTML=Gt?"\u25B6 Paused":"\u23F8 Live",t.classList.toggle("global-pause-btn--paused",Gt),Rt=Gt&&!Vs?Gt:Rt;let s=document.querySelector(".dashboard-sticky-strip");s&&s.classList.toggle("metrics-paused",Gt)});let n=document.getElementById("customize-btn");n?e.insertBefore(t,n):e.appendChild(t)}var su=!1;function yv(){if(su)return;su=!0;let e=(t=0)=>{let n=document.querySelector("#risk-card .widget-header"),s=document.querySelector("#landscape-card .widget-header");if(!n&&!s&&t<20){setTimeout(()=>e(t+1),300);return}if(n&&!n.querySelector(".friction-sparkline-wrap")){let a=document.createElement("div");a.className="friction-sparkline-wrap",a.title="Risk score \u2014 last 30 ledgers",a.innerHTML='<canvas id="friction-sparkline-canvas" width="80" height="22"></canvas>',n.appendChild(a)}if(s&&!s.querySelector(".friction-sparkline-wrap")){let a=document.createElement("div");a.className="friction-sparkline-wrap",a.title="Risk score history",a.innerHTML='<canvas id="friction-sparkline-canvas-2" width="60" height="18"></canvas>',s.appendChild(a)}Tu()};e()}function Tu(){ps.length&&(au("friction-sparkline-canvas",80,22),au("friction-sparkline-canvas-2",60,18))}function au(e,t,n){let s=document.getElementById(e);if(!(s!=null&&s.getContext))return;let a=s.getContext("2d");a.clearRect(0,0,t,n);let o=ps;if(o.length<2)return;let i=100,r=t/(o.length-1),l=o.map((g,v)=>[v*r,n-2-g.friction/i*(n-4)]),c=n-2-60/i*(n-4);a.fillStyle="rgba(255,85,85,.07)",a.fillRect(0,0,t,c);let u=a.createLinearGradient(0,0,0,n);u.addColorStop(0,"rgba(255,184,108,.35)"),u.addColorStop(1,"rgba(255,184,108,.05)"),a.beginPath(),l.forEach(([g,v],h)=>h===0?a.moveTo(g,v):a.lineTo(g,v)),a.lineTo(l.at(-1)[0],n),a.lineTo(0,n),a.closePath(),a.fillStyle=u,a.fill();let d=o.at(-1).friction,p=d<26?"#50fa7b":d<61?"#ffb86c":"#ff5555";a.beginPath(),l.forEach(([g,v],h)=>h===0?a.moveTo(g,v):a.lineTo(g,v)),a.strokeStyle=p,a.lineWidth=1.5,a.lineJoin="round",a.stroke();let[m,f]=l.at(-1);a.beginPath(),a.arc(m,f,2.5,0,Math.PI*2),a.fillStyle=p,a.fill()}window.printLandscapeReport=function(){var i,r,l,c;if(!document.getElementById("landscape-card"))return;let t=((i=document.getElementById("d2-ledger-index"))==null?void 0:i.textContent)||"\u2014",n=((r=document.getElementById("landscape-badge"))==null?void 0:r.textContent)||"",s=new Date().toLocaleString(),a=window.open("","_blank","width=860,height=700");a.document.write(`<!DOCTYPE html><html><head>
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
  <div class="meta">Ledger #${t} \xB7 ${n} \xB7 Generated ${s}</div>`);let o=[{id:"landscape-text",label:"Situation Summary"},{id:"landscape-why",label:"Why It Matters"},{id:"landscape-now",label:"What Is Happening"},{id:"landscape-watch",label:"What To Watch Next"},{id:"landscape-watchlist",label:"Who To Watch"}];for(let{id:u,label:d}of o){let p=document.getElementById(u);if(!(!p||!p.textContent.trim())){if(a.document.write(`<div class="section"><div class="section-h">${d}</div>`),u==="landscape-watchlist"){let m=p.querySelectorAll(".landscape-watchitem");if(m.length)for(let f of m){let g=((l=f.querySelector(".addr-link"))==null?void 0:l.textContent)||"\u2014",v=((c=f.querySelector(".landscape-watchwhy"))==null?void 0:c.textContent)||"";a.document.write(`<div class="watchitem"><b>${g}</b><p>${v}</p></div>`)}else a.document.write(`<div class="row">${p.textContent.trim()}</div>`)}else{let m=p.querySelectorAll(".landscape-row");if(m.length)for(let f of m)a.document.write(`<div class="row">${f.innerHTML}</div>`);else a.document.write(`<div class="row">${p.innerHTML}</div>`)}a.document.write("</div>")}}a.document.write("</body></html>"),a.document.close()};function wv(){if(Fp||(Fp=!0,document.getElementById("dash-bottom-nav")))return;let e=document.createElement("nav");e.id="dash-bottom-nav",e.setAttribute("aria-label","Quick nav"),e.innerHTML=`
    <button data-go="stream" class="bn-btn"><span>\u{1F30A}</span><small>Stream</small></button>
    <button data-go="inspector" class="bn-btn"><span>\u{1F50D}</span><small>Inspect</small></button>
    <button data-go="network" class="bn-btn"><span>\u{1F4E1}</span><small>Health</small></button>
    <button data-go="dex" class="bn-btn"><span>\u{1F9E0}</span><small>DEX</small></button>
    <button data-go="risk" class="bn-btn"><span>\u26A0\uFE0F</span><small>Risk</small></button>
    <button data-go="profile" class="bn-btn"><span>\u{1F464}</span><small>Profile</small></button>
  `,document.body.appendChild(e);let t=s=>{var a;return(a=document.querySelector(`.dash-tab[data-tab="${s}"]`))==null?void 0:a.click()};e.addEventListener("click",s=>{let a=s.target.closest("button[data-go]");if(!a)return;let o=a.dataset.go;if(o==="profile"){typeof window.showProfile=="function"&&window.showProfile();return}if(X.currentPage!=="dashboard"&&typeof window.showDashboard=="function"&&window.showDashboard(),o==="stream"||o==="inspector"||o==="network"){t(o);return}t("stream"),setTimeout(()=>{var r;let i=o==="dex"?"dex-pattern-card":"risk-card";(r=document.getElementById(i))==null||r.scrollIntoView({behavior:"smooth",block:"start"})},80)});let n=()=>{let s=X.currentPage==="profile",a=X.currentPage==="landing";e.style.display=a?"none":"",e.querySelectorAll(".bn-btn").forEach(o=>{let i=o.dataset.go,r=s?i==="profile":i===X.currentTab;o.classList.toggle("bn-btn--active",r)})};window.addEventListener("naluxrp:pagechange",n),window.addEventListener("naluxrp:tabchange",n),n()}function xv(){var a,o;if(Op)return;Op=!0;let e=document.querySelector(".dashboard-header");if(!e||document.getElementById("compactToggleBtn"))return;let t=document.createElement("button");t.id="compactToggleBtn",t.type="button",t.className="dash-accordion-toggle",t.textContent="Compact: OFF",e.appendChild(t);let n=(i,r=!0)=>{if(document.body.classList.toggle("dash-accordion",i),t.textContent=i?"Compact: ON":"Compact: OFF",r)try{localStorage.setItem(Mp,i?"1":"0")}catch{}if(i){let l=document.querySelector(".dashboard-col-side .widget-card");l&&l.classList.add("is-open")}else document.querySelectorAll(".dashboard-col-side .widget-card.is-open").forEach(l=>l.classList.remove("is-open"))},s=null;try{s=localStorage.getItem(Mp)}catch{}n(s==="1"?!0:s==="0"?!1:((o=(a=window.matchMedia)==null?void 0:a.call(window,"(max-width: 600px)"))==null?void 0:o.matches)??!1,!1),t.addEventListener("click",()=>n(!document.body.classList.contains("dash-accordion"),!0))}function kv(){if(Bp)return;Bp=!0;let e=document.querySelector(".dashboard-col-side");e&&e.addEventListener("click",t=>{var o,i;if(!document.body.classList.contains("dash-accordion"))return;let n=t.target;if((o=n==null?void 0:n.closest)!=null&&o.call(n,"button, a, input, textarea, select, kbd"))return;let s=(i=n==null?void 0:n.closest)==null?void 0:i.call(n,".widget-card");if(!s)return;let a=s.classList.contains("is-open");e.querySelectorAll(".widget-card.is-open").forEach(r=>{r!==s&&r.classList.remove("is-open")}),s.classList.toggle("is-open",!a)})}var _e={lsfPasswordSpent:65536,lsfRequireDestTag:131072,lsfRequireAuth:262144,lsfDisallowXRP:524288,lsfDisableMaster:1048576,lsfNoFreeze:2097152,lsfGlobalFreeze:4194304,lsfDefaultRipple:8388608,lsfDepositAuth:16777216},Cu={lsfBurnable:1,lsfOnlyXRP:2,lsfTrustLine:4,lsfTransferable:8},$v=new Set(["SetRegularKey","SignerListSet","AccountSet","AccountDelete","EscrowCreate","PaymentChannelCreate","DepositPreauth"]),yn={blackhole:"#ff5555",exchange:"#00d4ff",newWallet:"#ff79c6",issuer:"#ffb86c",wallet:"#bd93f9",other:"#8be9fd"},Sv=.55,Tv=.15,tr=20,Eu=946684800;function Se({module:e,category:t=null,sev:n,confidence:s=null,headline:a,detail:o="",observed:i=[],alternativeExplanations:r=[],evidenceAgainstBenign:l=[],classification:c=null,hashes:u=[]}={}){return{module:e,category:t,sev:n,confidence:s,headline:a,label:a,detail:o,observed:i,alternativeExplanations:r,evidenceAgainstBenign:l,classification:c,hashes:u}}var Cv=new Map([["rPVMhWBsfF9iMXYj3aAzJVkPDTFNSyWdKy",{name:"Bitstamp",type:"exchange"}],["rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B",{name:"Bitstamp",type:"exchange"}],["rrpNnNLKrartuEqfJGpqyDwPj1BBN1ih7",{name:"Bitstamp",type:"exchange"}],["rN7n3473SaZBCG4dFL83w7PB9judJ7qdDo",{name:"Binance",type:"exchange"}],["rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh",{name:"Binance",type:"exchange"}],["rBKPS4oLSaV2KVVuHH8EpQqMGgGefGFQs7",{name:"Bitso",type:"exchange"}],["rfk5bwaKCoNU84fTzdqWQowqnNaZorDmiV",{name:"Gate.io",type:"exchange"}],["rGFuMiw48HdbnrUbkRYDTvT5i9imC5fvv9",{name:"Gate.io",type:"exchange"}],["rwYHCs2EYBMBvRXFmxDrCUSorPsuqCck7t",{name:"Kraken",type:"exchange"}],["rLHzPsX6oXkzU2qL12kHCH8G8cnZv1rBJh",{name:"Kraken",type:"exchange"}],["ra5nK24KXen9AHvsdFTKHSANinZseWnPcX",{name:"Uphold",type:"exchange"}],["rGWrZyax5eXbi5gs49MRZKkE9eKNL9p4B",{name:"Bittrex",type:"exchange"}],["rDsbeomae4FXwgQTJp9Rs64Qg9vDiTCdBv",{name:"Coinone",type:"exchange"}],["rHsMUQFzBb7S6GnQFVgNirqvHRcLpAn5dU",{name:"Bithumb",type:"exchange"}],["rMQ98K56yXJbDGv49ZSmW51sLn94Xe1mu1",{name:"Huobi",type:"exchange"}],["rHcFoo6a9qT5NHiVn1THwX3B4QF2VQKWZ",{name:"Huobi",type:"exchange"}],["rKiCet8SdvWxPXnAgYarFUXMh1zCPz432Y",{name:"Coinbase",type:"exchange"}],["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",{name:"Coinbase",type:"exchange"}],["r9mhdcT2K7FdCGDEPqfbMJwVXsXCqEr5bP",{name:"OKX",type:"exchange"}],["r32U8WFxhqEAVkKcTb1GGRR1VH2oaFdexN",{name:"OKX",type:"exchange"}],["r4GDFMLGJUKMjNEycBKPGnRSNXyNVLQLHi",{name:"Bybit",type:"exchange"}],["rBETszU65yYoFcYdRkiGqFaYmhZpHWC7sj",{name:"Bybit",type:"exchange"}],["rMWUykAmNQDaM9poSes8VLDZDDkEoutilities",{name:"KuCoin",type:"exchange"}],["rUA1S9qobBkxLqzdfGEzh5wm5KdLfbf8bx",{name:"KuCoin",type:"exchange"}],["rHtbQzmN4BDaEBnGSXp3AZaZAuZamNVsME",{name:"MEXC",type:"exchange"}],["rDN1gPWW3XQFXVJFQSiJxPHGZiRLMVSi7K",{name:"MEXC",type:"exchange"}],["rB3gZey7VWHoDokMt3tCiXBSRmaZi5xJi9",{name:"Crypto.com",type:"exchange"}],["rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq",{name:"GateHub",type:"exchange"}],["razqnFn6FqBaYBdNaGnVzmGaNE6XPRQ9bG",{name:"GateHub",type:"exchange"}],["rGQdkxNBQeQC1WTQDQ2F2QoGBZxYcMxBBg",{name:"GateHub",type:"exchange"}],["rpXTzCuXtjiPDFysxq8uNmtZBe9Xo97JbW",{name:"Bitbank",type:"exchange"}],["rsuUjfWxrACCAwGQDsNeZUhpzXf1n1NK5Z",{name:"Bitbank",type:"exchange"}],["r9oxUGJqMfMEhGBxrMJnmNvVh1LKkMv7fz",{name:"Coincheck",type:"exchange"}],["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",{name:"Genesis (Black Hole)",type:"blackhole"}],["r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59",{name:"Black Hole #2",type:"blackhole"}],["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",{name:"Genesis Wallet",type:"ripple"}],["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",{name:"Ripple Labs Ops",type:"ripple"}],["rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY",{name:"XAMAN (XUMM)",type:"wallet"}],["rBj4eVRWn6mCELVTNkVFDfGNByE9VFTM3R",{name:"XAMAN",type:"wallet"}],["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",{name:"XRPL AMM Engine",type:"dex"}],["rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz",{name:"SOLO Issuer",type:"issuer"}],["rcoreNywaoz2ZCVt2sc3JiEi7G7MpZxZgm",{name:"CORE Token",type:"issuer"}],["rhXo4TcWbLY4GqTSmscMpgZ1KMXFBi9V55",{name:"XRPL DeFi Pool",type:"issuer"}],["rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",{name:"UNL Validator Set",type:"validator"}]]);function zn(e){return Cv.get(e)||null}var Pv=null,ut=!1;var ws=null,Pu=!1,Ki=!0;function no(){return Ki&&X.currentPage==="dashboard"&&X.currentTab==="inspector"&&!document.hidden}async function Mv(e){let t=[s=>`https://corsproxy.io/?${encodeURIComponent(s)}`,s=>`https://api.allorigins.win/raw?url=${encodeURIComponent(s)}`],n=async s=>{let a=typeof(AbortSignal==null?void 0:AbortSignal.timeout)=="function"?AbortSignal.timeout(6e3):void 0,o=await fetch(s,{mode:"cors",cache:"no-store",signal:a});if(!o.ok)throw new Error(`HTTP ${o.status}`);return await o.json()};try{return await n(e)}catch{for(let s of t)try{return await n(s(e))}catch{}throw new Error("Price feed unavailable")}}async function Lv(){if(Pu)return ws;Pu=!0;try{let e=await Mv("https://api.exchange.coinbase.com/products/XRP-USD/ticker");ws=Number((e==null?void 0:e.price)||0)||null}catch{ws=null}return ws}function wn(e){if(!ws||!e)return"";let t=e*ws;return t>=1e6?` (~$${(t/1e6).toFixed(2)}M)`:t>=1e3?` (~$${(t/1e3).toFixed(1)}K)`:` (~$${t.toFixed(2)})`}var Qs=null;function Nu(){return Qs||(Qs={input:()=>document.getElementById("inspect-addr"),err:document.getElementById("inspect-err"),result:document.getElementById("inspect-result"),empty:document.getElementById("inspect-empty"),loading:document.getElementById("inspect-loading"),loadMsg:document.getElementById("inspect-loading-msg"),warn:document.getElementById("inspect-warn"),badge:document.getElementById("inspect-addr-badge"),score:document.getElementById("inspect-risk-score"),label:document.getElementById("inspect-risk-label")},Qs)}function Av(){Qs=null,Nu()}function Ru(){var n,s,a,o,i;r0(),l0(),c0(),(n=w("inspect-addr"))==null||n.addEventListener("keydown",r=>{r.key==="Enter"&&xs()}),(s=w("inspect-addr"))==null||s.addEventListener("paste",()=>{setTimeout(()=>{var l;let r=(l=w("inspect-addr"))==null?void 0:l.value.trim();r&&He(r)&&xs()},60)});let e=r=>{let l=r==null?void 0:r.closest(".inspector-section");if(!l)return;let c=l.classList.toggle("collapsed");r.setAttribute("aria-expanded",String(!c))};(a=document.getElementById("tab-inspector"))==null||a.addEventListener("click",r=>{if(r.target.closest("button"))return;let l=r.target.closest(".section-header");l&&e(l)}),(o=document.getElementById("tab-inspector"))==null||o.addEventListener("keydown",r=>{var c,u;if(r.key!=="Enter"&&r.key!==" ")return;let l=(u=(c=r.target).closest)==null?void 0:u.call(c,".section-header");l&&(r.preventDefault(),e(l))}),(i=document.getElementById("inspector-nav"))==null||i.addEventListener("click",r=>{var u;let l=r.target.closest("[data-jump]");if(!l)return;let c=document.getElementById("section-"+l.dataset.jump);c&&(c.classList.remove("collapsed"),(u=c.querySelector(".section-header"))==null||u.setAttribute("aria-expanded","true"),c.scrollIntoView({behavior:"smooth",block:"start"})),Vu(l.dataset.jump)});let t=!1;window.addEventListener("scroll",()=>{no()&&(t||(t=!0,requestAnimationFrame(()=>{d0(),t=!1})))},{passive:!0}),window.runInspect=xs,window.inspectorCopyAddr=u0,window.showInspectorHowTo=m0,window.hideInspectorHowTo=Zi,Av(),b0(),window.addEventListener("naluxrp:tabchange",r=>{var l;((l=r.detail)==null?void 0:l.tabId)==="inspector"&&no()&&(ar(),or(),na(),so())})}function _u(e){Ki=!!e,Ki||(ut=!0)}async function xs(){var a,o,i,r,l,c,u,d,p,m,f,g,v,h,b;if(!no())return;let e=Nu(),t=((a=e.input())==null?void 0:a.value.trim())||"";if([e.err,e.result,e.empty,e.warn].forEach(x=>x&&(x.style.display="none")),ut=!0,!t){e.empty&&(e.empty.style.display="");return}if(!He(t)){e.err&&(e.err.textContent=`\u26A0 Invalid address: ${y(t)}`,e.err.style.display="");return}if(X.connectionState!=="connected"){e.warn&&(e.warn.style.display="");return}Pv=t,ut=!1;let n=x=>{e.loading&&(e.loading.style.display="",e.loadMsg&&(e.loadMsg.textContent=x))};n("Fetching account data\u2026");let s=x=>new Promise(k=>setTimeout(k,x));try{n("Fetching account data\u2026");let[x,k,T]=await Promise.all([Ee({command:"account_info",account:t,ledger_index:"validated"}),Ee({command:"account_offers",account:t,ledger_index:"validated"}),Ee({command:"account_nfts",account:t,ledger_index:"validated"}).catch(()=>null)]);if(ut)return;let S=((o=x==null?void 0:x.result)==null?void 0:o.account_data)||{},$=((i=k==null?void 0:k.result)==null?void 0:i.offers)||[],E=((r=T==null?void 0:T.result)==null?void 0:r.account_nfts)||[];n("Fetching trustlines\u2026");let C=[],P,R=0;do{R++;let G={command:"account_lines",account:t,ledger_index:"validated",limit:400};P&&(G.marker=P);let me=await Ee(G).catch(()=>null);if(ut)return;let be=((l=me==null?void 0:me.result)==null?void 0:l.lines)||[];C.push(...be),P=((c=me==null?void 0:me.result)==null?void 0:c.marker)||null,R>1&&await s(50)}while(P&&C.length<4e3);n("Fetching account objects\u2026");let O=[],D,I=0;do{I++;let G={command:"account_objects",account:t,ledger_index:"validated",limit:400};D&&(G.marker=D);let me=await Ee(G).catch(()=>null);if(ut)return;let be=((u=me==null?void 0:me.result)==null?void 0:u.account_objects)||[];O.push(...be),D=((d=me==null?void 0:me.result)==null?void 0:d.marker)||null,I>1&&await s(50)}while(D&&O.length<2e3);n("Fetching token supply, AMM data & price\u2026");let F=15,H=C.filter(G=>G.currency&&Number(G.balance)!==0&&G.currency.startsWith("03")&&G.currency.length===40),[N,,...j]=await Promise.all([Ee({command:"gateway_balances",account:t,ledger_index:"validated"}).catch(()=>null),Lv(),...H.slice(0,F).map(G=>Ee({command:"amm_info",amm_account:G.account,ledger_index:"validated"}).catch(()=>null))]);if(ut)return;let se=(N==null?void 0:N.result)||null,re=new Map;H.slice(0,F).forEach((G,me)=>{var be,Ue;(Ue=(be=j[me])==null?void 0:be.result)!=null&&Ue.amm&&re.set(G.currency,j[me].result.amm)});let pe=400,ae=250,te=window._inspectMaxTx||5e3,de=Math.ceil(te/pe),le=[],Pe=new Set,B=G=>{var me,be;for(let Ue of G||[]){let ft=((me=Ue.tx_json)==null?void 0:me.hash)||((be=Ue.tx)==null?void 0:be.hash)||Ue.hash||null;ft&&Pe.has(ft)||(ft&&Pe.add(ft),le.push(Ue))}},q={newestToOldestComplete:!1,oldestToNewestFetched:!1,hitTxCap:!1,hitPageCap:!1,fetchErrorOccurred:!1},J,ue=0;for(let G=1;G<=de&&le.length<te;G++){if(ue=G,ut)return;n(`Fetching transactions \u2014 page ${G} (${le.length.toLocaleString()} so far)\u2026`);let me={command:"account_tx",account:t,limit:pe,ledger_index_min:-1,ledger_index_max:-1,forward:!1};J&&(me.marker=J);let be=await Ee(me).catch(()=>null);if(ut)return;if(be==null&&(q.fetchErrorOccurred=!0),B((p=be==null?void 0:be.result)==null?void 0:p.transactions),J=((m=be==null?void 0:be.result)==null?void 0:m.marker)||null,!J)break;G<de&&le.length<te&&await s(ae)}if(q.hitTxCap=le.length>=te,q.hitPageCap=!!J&&ue>=de,q.newestToOldestComplete=!J,le.length<te){if(ut)return;n("Fetching oldest transactions (anchoring history start)\u2026");let G=await Ee({command:"account_tx",account:t,limit:pe,ledger_index_min:-1,ledger_index_max:-1,forward:!0}).catch(()=>null);if(ut)return;G==null&&(q.fetchErrorOccurred=!0),B((f=G==null?void 0:G.result)==null?void 0:f.transactions),q.oldestToNewestFetched=G!=null&&!((g=G==null?void 0:G.result)!=null&&g.marker),await s(ae)}e.loading&&(e.loading.style.display="none");let ke=Ev(le).sort((G,me)=>(G.tx.date??0)-(me.tx.date??0)),Me=946684800,We=null,De=null,Ie=q.newestToOldestComplete||q.oldestToNewestFetched;if(ke.length>0){let G=ke[0].tx;G!=null&&G.date&&(De=(G.date+Me)*1e3,We=Math.floor((Date.now()-De)/864e5))}let Y=new Map;for(let{tx:G}of ke){if(G.TransactionType!=="OfferCreate"||!G.TakerPays||!G.TakerGets)continue;let me=Ue=>typeof Ue=="string"?"XRP":`${Ue.currency}+${Ue.issuer||""}`,be=[me(G.TakerPays),me(G.TakerGets)].sort().join("\u2194");Y.set(be,(Y.get(be)||0)+1)}let Ce=null;if(Y.size>0){let G=[...Y.entries()].sort((sn,pa)=>pa[1]-sn[1])[0][0],[me,be]=G.split("\u2194"),Ue=sn=>sn==="XRP"?{currency:"XRP"}:{currency:sn.split("+")[0],issuer:sn.split("+")[1]},ft=await Ee({command:"book_offers",taker_pays:Ue(me),taker_gets:Ue(be),limit:20,ledger_index:"validated"}).catch(()=>null);(h=(v=ft==null?void 0:ft.result)==null?void 0:v.offers)!=null&&h.length&&(Ce={pair:G,offers:ft.result.offers})}let Ye=[...new Set(ke.filter(({tx:G})=>G.TransactionType==="Payment"&&G.Account===t&&G.Destination).map(({tx:G})=>G.Destination))].slice(0,6),$e=new Map;for(let G of Ye){if(ut)return;let me=await Ee({command:"account_info",account:G,ledger_index:"validated"}).catch(()=>null),be=(b=me==null?void 0:me.result)==null?void 0:b.account_data;be&&$e.set(G,{sequence:be.Sequence||0,balance:Number(be.Balance||0)/1e6}),await s(80)}Iv(t,S,C,$,E,O,ke,{gatewayBalances:se,ammInfoMap:re,destAgeMap:$e,walletAgeDays:We,walletCreatedTs:De,walletAgeVerified:Ie,historyCoverage:q,liveOrderBook:Ce}),e.result&&(e.result.style.display="",ir());let Ct=e.score?Number(e.score.textContent):null;S0(t,isNaN(Ct)?null:Ct);let jt=window._lastAllFindings||[];T0(t,isNaN(Ct)?null:Ct,jt),R0(t,jt),er(t)&&P0(t,isNaN(Ct)?null:Ct),A0()}catch(x){if(ut)return;e.loading&&(e.loading.style.display="none"),e.err&&(e.err.textContent=`Error: ${y(x.message)}`,e.err.style.display="")}}function Ev(e){return e.map(t=>{let n=t.tx_json||t.tx||t.transaction||{},s=t.metadata||t.meta||{};return n.date==null&&t.date!=null&&(n.date=t.date),!n.hash&&t.hash&&(n.hash=t.hash),{tx:n,meta:s}})}function Zt(e){if(e==null)return null;if(typeof e=="string")return Number(e)/1e6;let t=Number(e.value);return Number.isFinite(t)?t:null}function Ji(e){return typeof e=="string"?"XRP":(e==null?void 0:e.currency)||null}function Du(e){return typeof e=="string"&&e.length===40&&e.startsWith("03")}function nr(e,t,n){var a,o,i,r,l,c,u,d,p,m,f,g;let s={xrpDelta:0,tokenDeltas:[],tokenDeltaMap:new Map,lpDeltas:[],lpDeltaMap:new Map};if(!((a=t==null?void 0:t.AffectedNodes)!=null&&a.length))return s;for(let v of t.AffectedNodes){let h=v.CreatedNode,b=v.ModifiedNode,x=v.DeletedNode,k=h||b||x;if(k){if(k.LedgerEntryType==="AccountRoot"){if((((o=k.FinalFields)==null?void 0:o.Account)||((i=k.NewFields)==null?void 0:i.Account))!==n)continue;let S=Number(((r=k.FinalFields||k.NewFields)==null?void 0:r.Balance)??0),$=h?0:Number(((l=k.PreviousFields)==null?void 0:l.Balance)??S),E=(S-$)/1e6;E&&(s.xrpDelta+=E);continue}if(k.LedgerEntryType==="RippleState"){let T=k.FinalFields||k.NewFields,S=(c=T==null?void 0:T.LowLimit)==null?void 0:c.issuer,$=(u=T==null?void 0:T.HighLimit)==null?void 0:u.issuer,E=S===n;if(!E&&!($===n))continue;let P=E?1:-1,R=E?$:S,O=(d=T==null?void 0:T.Balance)==null?void 0:d.currency,D=x?0:Number(((p=T==null?void 0:T.Balance)==null?void 0:p.value)??0),I=h?0:Number(((f=(m=k.PreviousFields)==null?void 0:m.Balance)==null?void 0:f.value)??(x?((g=T==null?void 0:T.Balance)==null?void 0:g.value)??0:D)),F=(D-I)*P;if(!F||!O)continue;let H=Du(O)?s.lpDeltaMap:s.tokenDeltaMap,N=`${O}.${R}`,j=H.get(N)||{currency:O,issuer:R,delta:0};j.delta+=F,H.set(N,j)}}}return s.tokenDeltas=[...s.tokenDeltaMap.values()],s.lpDeltas=[...s.lpDeltaMap.values()],delete s.tokenDeltaMap,delete s.lpDeltaMap,s}function Iu(e,t){return e.map(({tx:n,meta:s})=>{let a=nr(n,s,t);return{txHash:n.hash,date:n.date,type:n.TransactionType,result:(s==null?void 0:s.TransactionResult)||null,xrpDelta:a.xrpDelta,tokenDeltas:a.tokenDeltas,lpDeltas:a.lpDeltas}})}function Fu(e,t,n){let s=Iu(e,t),a=n,o=new Array(s.length);for(let i=s.length-1;i>=0;i--){let r=a;a-=s[i].xrpDelta,o[i]={...s[i],balanceBefore:a,balanceAfter:r}}return o}var Nv=[86400,3*86400],Rv=.5,_v=10;function Ou(e,t,n,s={}){var u;let a=[],o=e.length,i=t.filter(({tx:d})=>["SetRegularKey","SignerListSet"].includes(d.TransactionType)).map(({tx:d})=>d.date).filter(d=>d!=null);for(let d of Nv)for(let p=0;p<o;p++){let m=e[p];if(m.date==null||m.balanceBefore<=0)continue;let f=0,g=p,v=[];for(;g<o&&e[g].date!=null&&e[g].date-m.date<=d;)e[g].xrpDelta<0&&(f+=-e[g].xrpDelta,v.push(e[g])),g++;let h=m.balanceBefore>0?f/m.balanceBefore:0;h>=Rv&&f>_v&&a.push({windowSec:d,startDate:m.date,endDate:((u=e[Math.min(g,o)-1])==null?void 0:u.date)??m.date,balanceAtStart:m.balanceBefore,totalOutflowXrp:f,pctOfBalanceMoved:h,startIdx:p,endIdx:Math.min(g,o)-1,triggeredByAuthChange:i.some(b=>b<=m.date&&m.date-b<=d)})}let r=300;a.sort((d,p)=>p.pctOfBalanceMoved-d.pctOfBalanceMoved);let l=[];for(let d of a)l.some(m=>m.windowSec===d.windowSec&&d.startDate<=m.endDate+r&&d.endDate>=m.startDate-r)||l.push(d);l.sort((d,p)=>d.startDate-p.startDate);let c=s.fetchErrorOccurred?"possibly-incomplete":"complete";return l.map(d=>({...d,dataCompleteness:c}))}function Dv(e,t,n,s){let a=t.slice(e.startIdx,e.endIdx+1).filter(C=>C.xrpDelta<0),o=new Set(a.map(C=>C.txHash)),i=n.filter(({tx:C})=>o.has(C.hash)&&C.TransactionType==="Payment"),r=new Set(n.filter(({tx:C})=>C.TransactionType==="Payment"&&C.Account===s&&C.date<e.startDate).map(({tx:C})=>C.Destination).filter(Boolean)),l=[...new Set(i.map(({tx:C})=>C.Destination).filter(Boolean))],c=l.filter(C=>!r.has(C)),u=l.length?c.length/l.length:null,d=new Map;for(let{tx:C}of i){let P=typeof C.Amount=="string"?Number(C.Amount)/1e6:0;d.set(C.Destination,(d.get(C.Destination)||0)+P)}let p=[...d.entries()].sort((C,P)=>P[1]-C[1]),m=e.totalOutflowXrp>0&&p[0]?p[0][1]/e.totalOutflowXrp:null,f=p.map(([C,P])=>({addr:C,xrp:P,entity:zn(C)})),g=n.filter(({tx:C})=>C.TransactionType==="Payment"&&C.Account===s&&(C.date<e.startDate||C.date>e.endDate)&&typeof C.Amount=="string").map(({tx:C})=>Number(C.Amount)/1e6).filter(C=>C>0),v=C=>{let P=[...C].sort((R,O)=>R-O);return P.length?P[Math.floor(P.length/2)]:null},h=v(g),b=i.map(({tx:C})=>Number(C.Amount)/1e6).filter(C=>C>0),x=v(b),k=h&&x?x/h>=5:!1,T=new Map;for(let C of t.slice(e.startIdx,e.endIdx+1))for(let P of C.tokenDeltas){if(P.delta>=0)continue;let R=`${P.currency}.${P.issuer}`;T.set(R,(T.get(R)||0)+-P.delta)}let S=[...T.entries()].map(([C,P])=>({key:C,amount:P})),E=t.filter(C=>C.date!=null&&C.date<e.startDate&&e.startDate-C.date<=172800).some(C=>C.xrpDelta>0&&C.tokenDeltas.some(P=>P.delta<0));return{...e,newRecipientPct:u,newDestCount:c.length,episodeDestCount:l.length,topDestShare:m,destinations:f.slice(0,5),transferSizeAnomaly:k,historicalMedianXrp:h,episodeMedianXrp:x,trustlineLiquidations:S,dexConversionPrecedingWithdrawal:E}}function Iv(e,t,n,s,a,o,i,r={}){let{gatewayBalances:l=null,ammInfoMap:c=new Map,destAgeMap:u=new Map,walletAgeDays:d=null,walletCreatedTs:p=null,walletAgeVerified:m=!1,historyCoverage:f=null,liveOrderBook:g=null}=r,v=Number(t.Balance||0)/1e6,h=Number(t.OwnerCount||0),b=10+h*2,x=Number(t.Flags||0),k=t.Sequence??"\u2014",T=o.filter(Y=>Y.LedgerEntryType==="SignerList"),S=o.filter(Y=>Y.LedgerEntryType==="Escrow"),$=o.filter(Y=>Y.LedgerEntryType==="PayChannel"),E=o.filter(Y=>Y.LedgerEntryType==="DepositPreauth"),C=o.filter(Y=>Y.LedgerEntryType==="Check"),P=Hv(t,x,T,i,f),R=zu(t,x,T,i,$,S,e,v,f),O=Wv(a,i,e),D=xy(g,e),I=ju(i,e,f||{}),F=qv(I,e),H=Yv(i,e,n,I,F,D),N=uy(t,n,x,i),j=my(n,i,o,c,e),se=ny(i),re=py(i,e),pe=sy(i,e),ae=ay(i,e),te=oy(i),de=iy(i,e),le=Fv(i,e,u),Pe=fy(i),B=hy(i,e),q=gy(i,e),J=Ov(i,e,n,l),ue=by(i,e),ke=vy(i,e),Me=yy(o,i,e),We=wy(o),De=Py(P,R,O,H,se,re,pe,ae,te,de,Pe);Dy(e,t,v,b,h,k,De,d,p,m),Iy(P,t,x,T,E),Fy(R,$,S,C),Uy(le,v,ue),Oy(O,a),Xy(H),My(se),Ly(re),Ay(pe),Ey(ae),Ny(te),Ry(de),_y(se,pe,ae,te,de),Hy(N,n),qy(J,n),Vy(Pe),Gy(B),Ky(q),zy(j,n),Jy(ue),Yy(ke),Qy(Me),Zy(We),e0(D),t0(De,P,R,O,H,se,re,pe,ae,te,de,Pe,ue,ke),jy(n),Wy(i,e),Au(i),D0(i,e,le,ue),window._lastTxList=i,window._lastBalXrp=v,window._lastHistoryCoverage=f;let Ie=w("inspect-report-body");Ie&&(i0(Ie,e,t,v,De,P,R,O,H,se,re,N,j,le,J,i,pe,ae,te,de,{feeAnalysis:Pe,destTagAnalysis:B,pathDepthAnalysis:q,gatewayBalances:l,inboundFlowAnalysis:ue,memoAnalysis:ke,escrowDepthAnalysis:Me,checkAnalysis:We,liveBookAnalysis:D,walletAgeDays:d,walletCreatedTs:p,walletAgeVerified:m,historyCoverage:f}),Au(i,"inspect-report-activity-chart"),N0(De,window._lastAllFindings||[],d,i.length,window._lastCategoryRisk||{},m,f),window._lastInspectResult={addr:e,riskScore:De,walletAgeDays:d,walletAgeVerified:m,historyCoverage:f,txCount:i.length,findings:window._lastAllFindings||[],timestamp:new Date().toISOString()},Yu(),Qu(e))}function Fv(e,t,n=new Map){let s=new Map,a=[];for(let{tx:p,meta:m}of e){if(p.TransactionType!=="Payment"||p.Account!==t)continue;let f=p.Destination;if(!f)continue;let g=0,v=null,h=p.Amount;typeof h=="string"?g=Number(h)/1e6:h!=null&&h.value&&(v={value:Number(h.value),currency:Hn(h.currency),issuer:h.issuer});let b=Array.isArray(p.Paths)&&p.Paths.length>0,x=p.SendMax!=null,k=b||x,T=b?p.Paths.reduce((C,P)=>Math.max(C,(P||[]).length+1),1):k?2:1,S=Wn(p),$={dest:f,amtXrp:g,amtToken:v,ts:S,isPathPay:k,hopCount:T,hash:p.hash||p.Hash||"",ledger:p.ledger_index||p.LedgerIndex||0,destTag:p.DestinationTag};a.push($),s.has(f)||s.set(f,{addr:f,totalXrp:0,txCount:0,firstSeen:S,lastSeen:S,entity:zn(f)||null,pathCount:0,maxHops:1,tokens:new Map});let E=s.get(f);if(E.totalXrp+=g,E.txCount++,E.lastSeen=Math.max(E.lastSeen,S),E.firstSeen=Math.min(E.firstSeen,S),k&&(E.pathCount++,E.maxHops=Math.max(E.maxHops,T)),v){let C=`${v.currency}.${z(v.issuer||"")}`;E.tokens.set(C,(E.tokens.get(C)||0)+v.value)}}let o=[...s.values()].sort((p,m)=>m.totalXrp-p.totalXrp||m.txCount-p.txCount).slice(0,10).map(p=>({...p,tokens:[...p.tokens.entries()].map(([m,f])=>({k:m,v:f}))})),i=o.reduce((p,m)=>p+m.totalXrp,0),r=a.filter(p=>p.isPathPay).length,l=o.filter(p=>{let m=n.get(p.addr);return m&&m.sequence<10&&p.totalXrp>10}),c=o.filter(p=>{var m;return((m=p.entity)==null?void 0:m.type)==="exchange"}),u=o.filter(p=>{var m;return((m=p.entity)==null?void 0:m.type)==="blackhole"});return{timeline:[...a].filter(p=>p.amtXrp>.01||p.amtToken).sort((p,m)=>p.ts-m.ts).slice(0,30),destinations:o,totalOut:i,totalPathPay:r,uniqueDests:s.size,exchangeDests:c,blackHoleDests:u,newWalletDests:l}}function Ov(e,t,n,s=null){var E,C;let a=null;if(s!=null&&s.obligations){let P=Object.values(s.obligations);P.length===1?a=Number(P[0])||null:P.length>1&&(a=null)}let o=[],i=new Map,r=new Map,l=new Set,c=new Set(n.filter(P=>Number(P.balance)<0).map(P=>Hn(P.currency)));for(let{tx:P,meta:R}of e)if(P.Account===t&&P.TransactionType==="Payment"){((C=(E=R==null?void 0:R.AffectedNodes)==null?void 0:E.some)==null?void 0:C.call(E,I=>{var F,H,N;return((F=I.CreatedNode)==null?void 0:F.LedgerEntryType)==="AccountRoot"&&((N=(H=I.CreatedNode)==null?void 0:H.NewFields)==null?void 0:N.Account)===P.Destination}))&&P.Destination&&l.add(P.Destination);let D=P.Amount;if(typeof D=="object"&&(D!=null&&D.value)&&(D!=null&&D.currency)){let I=Hn(D.currency);if(c.has(I)){let F=Number(D.value),H=P.Destination;i.has(H)||(i.set(H,0),r.set(H,Wn(P))),i.set(H,i.get(H)+F)}}}let u=[...i.entries()].sort((P,R)=>R[1]-P[1]),d=[];if(u.length>=3){let P=new Map;for(let[R,O]of u){if(O<=0)continue;let D=Math.pow(10,Math.floor(Math.log10(O))),F=(Math.round(O/D/.1)*.1*D).toPrecision(2);P.has(F)||P.set(F,[]),P.get(F).push({addr:R,amt:O})}for(let[,R]of P.entries())if(R.length>=3){let O=R.reduce((D,I)=>D+I.amt,0)/R.length;d.push({approxAmt:O,accounts:R}),o.push({sev:"warn",label:`${R.length} accounts each received ~${_(O,0)} tokens`,detail:"Highly similar token amounts suggest coordinated wallets, pre-arranged airdrop clusters, or sybil accounts."})}}let p=[...r.values()].sort();if(p.length>=5){let P=p[p.length-1]-p[0];P<3600&&p.length>=10&&o.push({sev:"warn",label:`${p.length} accounts funded within ${Math.ceil(P/60)} minutes`,detail:"Rapid token distribution to many wallets in a narrow time window. Matches pre-sale airdrop or coordinated distribution for wash trading."})}l.size>0&&o.push({sev:l.size>10?"warn":"info",label:`${l.size} account(s) created by this address`,detail:"This issuer funded the activation of these accounts. They may be controlled by the same entity."});let m=n.filter(P=>Number(P.balance)<0),f=a,g=m.reduce((P,R)=>P+Math.abs(Number(R.balance)),0),v=f??g,h=f==null&&m.length>0,b=h?` (based on ${m.length} visible trustlines \u2014 actual total supply may be higher if there are more holders)`:"",x=m.map(P=>({addr:P.account,balance:Math.abs(Number(P.balance)),currency:Hn(P.currency)})).sort((P,R)=>R.balance-P.balance).slice(0,10),k=new Set;for(let{tx:P}of e){if(P.TransactionType!=="Payment")continue;let R=P.Amount;typeof R!="object"||!(R!=null&&R.currency)||(P.Account===t&&P.Destination&&k.add(P.Destination),P.Destination===t&&P.Account&&k.add(P.Account))}x.forEach(P=>{P.activeWithIssuer=k.has(P.addr)});let T=x.filter(P=>P.activeWithIssuer).length;x.length>=3&&o.push(Se({module:"Issuer Connections",category:"issuer",sev:"info",confidence:.35,headline:`${T} of top ${x.length} holders have transacted directly with the issuer`,detail:`${x.length-T} show no direct payment activity with this issuer in the fetched history.`,observed:[`Direct-contact holders: ${T}/${x.length}`,"Measures direct issuer contact only \u2014 holders active via DEX trades or peer-to-peer transfers are not visible from this account's own history alone"],classification:"This distinguishes holders who have engaged with the issuer directly from those who haven't \u2014 it is not a general on-chain activity/dormancy check."}));let S=f??g,$=S>0&&(f!=null||m.length>=50);if(x.length>=2&&$){let P=x[0].balance/S*100,R=f!=null?"":" (of visible sample)";P>50?o.push({sev:"critical",label:`Top holder controls ${P.toFixed(0)}%${R} of supply`,detail:`${z(x[0].addr)} holds ${_(x[0].balance,0)} of ${_(S,0)} total${b}. `+(f!=null?"Extreme dump risk \u2014 one wallet could sell everything.":"Check gateway_balances or a block explorer to confirm the full supply picture.")}):P>25&&o.push({sev:"warn",label:`Top holder controls ${P.toFixed(0)}%${R} of supply`,detail:`Large single-holder concentration${b}. Monitor for coordinated sell events.`});let D=x.slice(0,5).reduce((I,F)=>I+F.balance,0)/S*100;D>75&&o.push({sev:"warn",label:`Top 5 holders own ${D.toFixed(0)}%${R} of supply`,detail:`Supply heavily concentrated in a few wallets${b}. This pattern is common in pre-launch setups or tokens with limited real distribution.`})}else m.length>0&&!$&&o.push({sev:"info",label:`${m.length} trustline holder(s) visible \u2014 supply data limited`,detail:`Only ${m.length} trustlines returned by account_lines. The true holder count and total supply cannot be determined from this data alone. Use a block explorer (XRPScan, Bithomp) for a complete holder distribution.`});return o.length===0&&v===0&&o.push({sev:"info",label:"No token issuance detected",detail:"This account does not appear to be an active token issuer."}),{signals:o,totalIssued:v,holderCount:m.length,topHolders:x,mirrorGroups:d,createdAccts:[...l],distributions:u.slice(0,10),isSampleOnly:h}}var Bv=new Set(["rrrrrrrrrrrrrrrrrrrrrhoLvTp","rrrrrrrrrrrrrrrrrrrrBZbvji","rrrrrrrrrrrrrrrrrNAMEtxvNvQ","rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh","r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59"]);function Bu(e){return!!e&&Bv.has(e)}function Xu(e,t,n=[],s=[]){let a=!!(t&_e.lsfDisableMaster),o=(e==null?void 0:e.RegularKey)||"",i=Array.isArray(n)&&n.length>0,r=Bu(o);return!!(a&&r&&!i)}function Hu(e,t,n=[]){let s=!!(t&_e.lsfDefaultRipple),a=!!(t&_e.lsfRequireAuth),o=!!(t&_e.lsfGlobalFreeze),i=!!(t&_e.lsfNoFreeze),r=n.filter(({tx:c})=>c.TransactionType==="TrustSet").length,l=n.filter(({tx:c})=>{var u;return c.TransactionType==="Payment"&&typeof c.Amount=="object"&&((u=c.Amount)==null?void 0:u.currency)}).length;return s||a||o||i||r>=3||l>=5}var Be={NORMAL:"Normal",REGULAR_KEY:"Regular-Key Controlled",MULTISIG:"Multisig Controlled",BLACKHOLED:"Blackholed",RECOVERABLE:"Recoverable",MISCONFIGURED:"Potentially Misconfigured",UNKNOWN:"Unknown"},Vi=4;function Xv(e,t,n,s,a={}){let o=!!(t&_e.lsfDisableMaster),i=!!e.RegularKey,r=n.length>0,l=Bu(e.RegularKey),c=s.filter(({tx:g})=>g.TransactionType==="AccountSet"&&g.Account===e.Account&&(g.SetFlag===Vi||g.ClearFlag===Vi)).map(({tx:g})=>({date:g.date,hash:g.hash,action:g.SetFlag===Vi?"disabled":"enabled"})).sort((g,v)=>(g.date??0)-(v.date??0)),u=c.some((g,v)=>g.action==="enabled"&&c.slice(0,v).some(h=>h.action==="disabled")),d=n.filter(g=>(g.SignerEntries||[]).reduce((b,x)=>{var k;return b+Number(((k=x.SignerEntry)==null?void 0:k.SignerWeight)||0)},0)<Number(g.SignerQuorum||1)),p,m,f;return d.length?(p=Be.MISCONFIGURED,m="blocked \u2014 quorum exceeds total signer weight, unreachable as configured",f=.9):r?(p=Be.MULTISIG,m="controlled by signer quorum",f=.85):o&&i&&l?(p=Be.BLACKHOLED,m="none \u2014 regular key points to a provably unusable address",f=.85):o&&!i?(p=Be.BLACKHOLED,m="none \u2014 no working key exists",f=.75):o&&i&&u?(p=Be.RECOVERABLE,m="proven historically \u2014 master key has been re-enabled from this state before",f=.7):o&&i?(p=Be.REGULAR_KEY,m="possible \u2014 whoever holds the regular key can re-enable the master key or act directly",f=.6):o?(p=Be.UNKNOWN,m="undetermined",f=.3):(p=Be.NORMAL,m="full \u2014 master key is active",f=.9),a!=null&&a.fetchErrorOccurred&&!(a!=null&&a.newestToOldestComplete)&&(f=Math.min(f,.5)),{state:p,reversibility:m,confidence:f,masterDisabled:o,hasRegularKey:i,hasSignerList:r,masterKeyHistory:c,wasEverReenabled:u,misconfiguredSignerListCount:d.length}}function Hv(e,t,n,s,a={}){let o=[],i=100,r=!!(t&_e.lsfDisableMaster),l=!!e.RegularKey,c=n.length>0,u=Xu(e,t,n,s),d=Hu(e,t,s),p=Xv(e,t,n,s,a);{let f={[Be.BLACKHOLED]:"info",[Be.MISCONFIGURED]:"critical",[Be.REGULAR_KEY]:"info",[Be.MULTISIG]:"info",[Be.RECOVERABLE]:"info",[Be.NORMAL]:"ok",[Be.UNKNOWN]:"warn"};o.push(Se({module:"Security",category:"security",sev:f[p.state]||"info",confidence:p.confidence,headline:`Account Control State: ${p.state}`,detail:`Reversibility: ${p.reversibility}`,observed:[`Master key: ${p.masterDisabled?"disabled":"active"}`,`Regular key: ${p.hasRegularKey?e.RegularKey:"not set"}`,`Signer list: ${p.hasSignerList?`${n.length} list(s)`:"none"}`,p.wasEverReenabled?"Master key has been re-enabled from a disabled state at least once in fetched history":null].filter(Boolean),classification:p.state===Be.MISCONFIGURED?"Signer quorum cannot be reached with the current signer weights as configured \u2014 this account may be functionally stuck regardless of anyone's intent.":p.state===Be.REGULAR_KEY?"A disabled master key with an active regular key is not the same as a locked/irreversible account \u2014 the regular key holder retains full control, including the ability to re-enable the master key.":null})),p.state===Be.BLACKHOLED&&(i-=40),p.state===Be.MISCONFIGURED&&(i-=30),u&&d&&o.push({sev:"warn",label:"Blackholed issuer caution",detail:"This account appears issuer-like and intentionally blackholed. Sending issued tokens back here may make them unrecoverable or effectively burn them."})}if(l){let f=s.find(({tx:v})=>v.TransactionType==="SetRegularKey"),g=f&&Date.now()/1e3-Wn(f.tx)<86400*30;u?o.push({sev:"info",label:"Regular key points to blackhole address",detail:e.RegularKey}):g?(o.push({sev:"warn",label:"Regular key set recently",detail:`Key: ${e.RegularKey} \u2014 changed within 30 days. Verify you intended this.`}),i-=15):o.push({sev:"info",label:"Regular key active",detail:e.RegularKey})}n.forEach(f=>{let g=f.SignerEntries||[],v=f.SignerQuorum||1;o.push({sev:"info",label:`Multisig: ${g.length} signers, quorum ${v}`,detail:g.map(h=>{var b;return z(((b=h.SignerEntry)==null?void 0:b.Account)||"")}).join(", ")})}),t&_e.lsfGlobalFreeze&&(o.push({sev:"warn",label:"Global Freeze active",detail:"This issuer has frozen all token balances."}),i-=10),t&_e.lsfDepositAuth&&o.push({sev:"ok",label:"Deposit Authorization enabled",detail:"Only pre-authorized senders can deposit."}),t&_e.lsfDefaultRipple&&o.push({sev:"info",label:"Default Ripple enabled",detail:"Balances can ripple through this account (issuer behaviour)."});let m=s.filter(({tx:f})=>f.TransactionType==="AccountDelete");return m.length&&(o.push({sev:"warn",label:`${m.length} AccountDelete attempt(s)`,detail:"Account deletion was attempted."}),i-=5),t&_e.lsfRequireAuth&&o.push({sev:"info",label:"Require Auth enabled",detail:"This account must individually approve each trustline before it can hold a balance \u2014 restricts who can hold what it issues."}),t&_e.lsfNoFreeze&&o.push({sev:"info",label:"No Freeze enabled",detail:"This account has permanently given up the ability to freeze trustlines \u2014 an irreversible choice, typically made to reassure holders."}),t&_e.lsfRequireDestTag&&o.push({sev:"info",label:"Require Destination Tag enabled",detail:"Payments to this account must include a destination tag \u2014 common for exchange/custodial deposit accounts."}),t&_e.lsfDisallowXRP&&o.push({sev:"info",label:"Disallow XRP flag set",detail:"A client-side hint requesting senders avoid sending XRP to this account. Not enforced by the protocol \u2014 XRP can still be sent."}),t&_e.lsfPasswordSpent&&o.push({sev:"info",label:"Password Spent flag set",detail:"This account has already used its one free SetRegularKey transaction; further regular-key changes will cost the standard transaction fee."}),o.length===0&&o.push({sev:"ok",label:"No security issues detected",detail:"Master key active, no regular key or signer list overrides, no risky flags set."}),{findings:o,score:Math.max(0,i),controlState:p}}function zv(e,t,n,s,a,o){let i=[],r="low",l=!!(t&_e.lsfDisableMaster),c=Xu(e,t,n,s),u=Hu(e,t,s);c?(i.push({sev:"info",label:"Intentional blackhole detected",detail:`Master key is disabled and regular key ${e.RegularKey} is a known blackhole address. This is typical for a permanently locked issuer/account, not a classic drain setup.`}),u&&i.push({sev:"warn",label:"Caution: sending assets back may burn them",detail:"Because this account appears to be an intentionally blackholed issuer, sending issued tokens back to it may strand or effectively burn those tokens."})):l&&e.RegularKey&&(i.push({sev:"critical",label:"Classic drain setup detected",detail:`Master key disabled. Regular key ${e.RegularKey} controls the account. If this key was set by an attacker, funds are at risk.`}),r="critical");let d=s.filter(({tx:m})=>m.TransactionType==="SetRegularKey"&&m.Account!==e.Account);if(!c&&d.length&&(i.push({sev:"critical",label:"Regular key set by external account",detail:`${d.length} key change(s) where sender \u2260 account owner. This is unusual.`}),r="critical"),a.length){let m=a.reduce((f,g)=>f+Number(g.Amount||0)/1e6,0);i.push({sev:"warn",label:`${a.length} open payment channel(s) \u2014 ${_(m,2)} XRP locked`,detail:`Destination(s): ${a.map(f=>z(f.Destination)).join(", ")}`}),r==="low"&&(r="medium")}if(o.length){let m=o.reduce((f,g)=>f+Number(g.Amount||0)/1e6,0);i.push({sev:"info",label:`${o.length} open escrow(s) \u2014 ${_(m,2)} XRP escrowed`,detail:`Escrow(s): ${o.map(f=>f.Destination?z(f.Destination):"self-escrow").join(", ")}`})}let p=s.filter(({tx:m})=>m.TransactionType==="DepositPreauth"&&m.Authorize);return p.length>5&&(i.push({sev:"warn",label:`${p.length} DepositPreauth grants issued`,detail:"Account pre-authorized many senders. Review if all are trusted."}),r==="low"&&(r="medium")),i.length===0&&i.push({sev:"ok",label:"No compromise-risk patterns detected",detail:"Auth structure looks intact."}),{signals:i,riskLevel:r}}function jv(e,t,n,s={}){let a=Fu(e,t,n),i=Ou(a,e,t,s).map(c=>Dv(c,a,e,t)),r=[],l="none";for(let c of i){let u=c.windowSec===86400?"24h":`${Math.round(c.windowSec/86400)}d`,d=[`${_(c.totalOutflowXrp,2)} XRP moved out (${(c.pctOfBalanceMoved*100).toFixed(0)}% of the ${_(c.balanceAtStart,2)} XRP balance at window start) within ${u}`,c.newRecipientPct!=null?`${(c.newRecipientPct*100).toFixed(0)}% of destinations (${c.newDestCount}/${c.episodeDestCount}) were first-time recipients`:null,c.topDestShare!=null?`${(c.topDestShare*100).toFixed(0)}% of the outflow went to a single destination`:null,c.transferSizeAnomaly?`Transfer sizes in this window are ${(c.episodeMedianXrp/c.historicalMedianXrp).toFixed(1)}x this account's own historical median`:null,c.trustlineLiquidations.length?`${c.trustlineLiquidations.length} token position(s) liquidated shortly before/during this window`:null,c.dexConversionPrecedingWithdrawal?"A token\u2192XRP conversion occurred in the 48h before this outflow began":null,c.triggeredByAuthChange?"A regular-key or signer-list change occurred immediately before this window":null].filter(Boolean),p=[];c.newRecipientPct!=null&&c.newRecipientPct>.7&&p.push("Nearly all destinations are first-time recipients, not established counterparties"),c.triggeredByAuthChange&&p.push("Outflow immediately follows an authorization change \u2014 the classic compromise-then-drain sequence"),c.dexConversionPrecedingWithdrawal&&c.trustlineLiquidations.length&&p.push("Assets were converted to XRP shortly before leaving, consistent with liquidating a position specifically to withdraw everything");let m=c.destinations.some(g=>g.entity),f=c.triggeredByAuthChange||c.pctOfBalanceMoved>=.9?"critical":"warn";f==="critical"?l="critical":l!=="critical"&&(l=l==="none"||l==="low"?"high":l),r.push(Se({module:"Asset Drain Behavior",category:"security",sev:f,confidence:c.triggeredByAuthChange?.75:.5,headline:`${_(c.totalOutflowXrp,2)} XRP (${(c.pctOfBalanceMoved*100).toFixed(0)}% of balance) moved out within ${u}`,detail:"Sliding-window balance reconstruction flagged this as an unusually large, fast depletion.",observed:d,alternativeExplanations:["A planned, deliberate transfer by the account's own owner (exchange withdrawal, consolidation, moving to a new wallet)",m?"Destination is a known exchange or labeled entity, consistent with a routine cash-out":"Destination(s) not in the known-entity registry \u2014 inconclusive either way"],evidenceAgainstBenign:p,classification:c.triggeredByAuthChange?"Outflow following an authorization change is a strong compromise-and-drain signal, but ledger data alone cannot distinguish an attacker from an owner who changed their own key and then withdrew funds themselves.":"Large, fast depletion observed. This describes behavior, not intent \u2014 see Account Compromise Risk above for whether the account's access controls show separate signs of being compromised."}))}return r.length||r.push(Se({module:"Asset Drain Behavior",category:"security",sev:"ok",headline:"No abnormal depletion detected",detail:"No window scanned showed a large, fast balance drop relative to this account's own history."})),{episodes:i,findings:r,severity:l}}var Mu={low:0,medium:1,high:2,critical:3,none:-1};function zu(e,t,n,s,a,o,i,r,l){let c=zv(e,t,n,s,a,o),u=jv(s,i,r,l),d=u.severity==="none"?"low":u.severity==="high"?"critical":u.severity,p=Mu[d]>Mu[c.riskLevel]?d:c.riskLevel;return{signals:[...c.signals,...u.findings],riskLevel:p,compromiseRiskLevel:c.riskLevel,assetDrainSeverity:u.severity,episodes:u.episodes}}function Wv(e,t,n){let s=[],a=new Map(e.map(m=>[m.NFTokenID,m])),i=t.filter(({tx:m})=>m.TransactionType==="NFTokenCreateOffer"&&m.Account===n).filter(({tx:m})=>{let f=m.Amount;return f?typeof f=="string"?Number(f)<1e6:!1:!0});i.length&&s.push({sev:"critical",label:`${i.length} NFT offer(s) created for \u22641 XRP`,detail:"You created sell offers at near-zero price. This is a common NFT drain vector \u2014 attackers trick victims into listing their NFTs for free."});let r=t.filter(({tx:m})=>m.TransactionType==="NFTokenAcceptOffer"&&m.Account===n);r.length&&s.push({sev:"warn",label:`${r.length} NFT offer(s) accepted`,detail:"Review these transactions to confirm they were intentional sales/purchases."});let l=t.filter(({tx:m})=>m.TransactionType==="NFTokenBurn"&&m.Account===n);l.length&&s.push({sev:"warn",label:`${l.length} NFT(s) burned`,detail:"Burned NFTs cannot be recovered. Confirm these were intentional."});let c=t.filter(({tx:m})=>m.TransactionType==="NFTokenMint"&&m.Account===n),u=t.filter(({tx:m})=>m.TransactionType==="NFTokenCreateOffer"||m.TransactionType==="NFTokenAcceptOffer");c.length>0&&u.length>0&&s.push({sev:"info",label:`${c.length} NFT(s) minted \xB7 ${u.length} transfer event(s)`,detail:"This account has minting activity."});let d=e.filter(m=>m.TransferFee&&m.TransferFee>0);if(d.length){let m=d.reduce((f,g)=>f+g.TransferFee,0)/d.length;s.push({sev:"info",label:`${d.length} NFT(s) carry transfer fees (avg ${(m/1e3).toFixed(1)}%)`,detail:"These NFTs pay royalties on each transfer."})}let p=e.filter(m=>!m.URI);return p.length>2&&s.push({sev:"warn",label:`${p.length} NFT(s) have no URI / metadata`,detail:"NFTs without a URI may be spam or placeholder tokens used in scams."}),s.length===0&&e.length===0?s.push({sev:"ok",label:"No NFT activity detected",detail:"This account holds no NFTs."}):s.length===0&&s.push({sev:"ok",label:`${e.length} NFT(s) held \u2014 no risk signals`,detail:"NFT posture looks normal."}),{flags:s,nftCount:e.length,mintCount:c.length}}var to={tfPassive:65536,tfImmediateOrCancel:131072,tfFillOrKill:262144,tfSell:524288};function Uv(e,t){var n;for(let s of(e==null?void 0:e.AffectedNodes)||[]){let a=s.CreatedNode;if((a==null?void 0:a.LedgerEntryType)==="Offer"&&((n=a.NewFields)==null?void 0:n.Account)===t)return a}return null}function ju(e,t,n={}){var r,l,c,u,d,p,m;let s=new Map,a=[],o=n.newestToOldestComplete||n.oldestToNewestFetched?"complete":"possibly-truncated";e.forEach((f,g)=>{var P,R,O,D,I;let{tx:v,meta:h}=f;if(v.TransactionType!=="OfferCreate"||v.Account!==t||(h==null?void 0:h.TransactionResult)!=="tesSUCCESS")return;let b={currency:Ji(v.TakerGets),issuer:typeof v.TakerGets=="object"?v.TakerGets.issuer:null,value:Zt(v.TakerGets)},x={currency:Ji(v.TakerPays),issuer:typeof v.TakerPays=="object"?v.TakerPays.issuer:null,value:Zt(v.TakerPays)},k=Uv(h,t),T=k?{gets:Zt((P=k.NewFields)==null?void 0:P.TakerGets),pays:Zt((R=k.NewFields)==null?void 0:R.TakerPays)}:null,S={gets:Math.max(0,(b.value??0)-((T==null?void 0:T.gets)??0)),pays:Math.max(0,(x.value??0)-((T==null?void 0:T.pays)??0))},$=[];for(let F of h.AffectedNodes||[]){let H=F.DeletedNode||F.ModifiedNode;if(!H||H.LedgerEntryType!=="Offer")continue;let N=(O=H.FinalFields)==null?void 0:O.Account;!N||N===t||$.push({account:N,gets:Zt((D=H.FinalFields)==null?void 0:D.TakerGets),pays:Zt((I=H.FinalFields)==null?void 0:I.TakerPays)})}let E=Number(v.Flags||0),C={offerId:`${t}:${v.Sequence}`,createHash:v.hash,createDate:v.date,createLedgerIndex:(k==null?void 0:k.LedgerIndex)||null,takerGetsOriginal:b,takerPaysOriginal:x,offerSequence:v.Sequence,replacesOfferSeq:v.OfferSequence||null,flags:{passive:!!(E&to.tfPassive),immediateOrCancel:!!(E&to.tfImmediateOrCancel),fillOrKill:!!(E&to.tfFillOrKill),sell:!!(E&to.tfSell)},expiration:v.Expiration||null,crossedAtCreation:S,counterpartiesAtCreation:$,restingAmount:T,status:k?"resting":"filled-immediately",consumedEvents:[],cancelHash:null,cancelDate:null,timeRestingSeconds:null,realizedFillPct:null,expiryUncertain:!1,dataCompleteness:o,_createIdx:g};s.set(C.offerId,C),a.push(C)});for(let f of a){if(!f.createLedgerIndex)continue;for(let h=f._createIdx+1;h<e.length;h++){let{tx:b,meta:x}=e[h];if((x==null?void 0:x.TransactionResult)!=="tesSUCCESS"&&(x==null?void 0:x.TransactionResult)!=="tecKILLED"&&!((r=x==null?void 0:x.AffectedNodes)!=null&&r.length))continue;let k=null;for(let T of(x==null?void 0:x.AffectedNodes)||[]){let S=T.CreatedNode,$=T.ModifiedNode,E=T.DeletedNode,C=S||$||E;if(!(!C||C.LedgerEntryType!=="Offer")&&C.LedgerIndex===f.createLedgerIndex){k={node:C,kind:E?"deleted":$?"modified":"created"};break}}if(k){if(k.kind==="deleted"){let T=b.Account===t&&b.TransactionType==="OfferCancel"&&b.OfferSequence===f.offerSequence,S=b.Account===t&&b.TransactionType==="OfferCreate"&&b.OfferSequence===f.offerSequence;if(T||S)f.status="cancelled",f.cancelHash=b.hash,f.cancelDate=b.date;else{let $=nr(b,x,t);$.xrpDelta!==0||$.tokenDeltas.some(C=>C.delta!==0)?(f.status="consumed-later",f.consumedEvents.push({hash:b.hash,date:b.date,counterpartyAccount:b.Account!==t?b.Account:null})):(f.status="expired",f.expiryUncertain=!0)}f.timeRestingSeconds=(b.date??f.createDate)-f.createDate,f.dataCompleteness=f.dataCompleteness;break}if(k.kind==="modified"){let T=Zt((l=k.node.FinalFields)==null?void 0:l.TakerGets),S=Zt((c=k.node.FinalFields)==null?void 0:c.TakerPays);f.consumedEvents.push({hash:b.hash,date:b.date,counterpartyAccount:b.Account!==t?b.Account:null,gets:Math.max(0,(((u=f.restingAmount)==null?void 0:u.gets)??0)-(T??0)),pays:Math.max(0,(((d=f.restingAmount)==null?void 0:d.pays)??0)-(S??0))}),f.restingAmount={gets:T,pays:S},f.status="partially-filled-then-resting"}}}if(f.status==="resting"||f.status==="partially-filled-then-resting"){let h=Math.floor(Date.now()/1e3)-Eu,b=((m=(p=e[e.length-1])==null?void 0:p.tx)==null?void 0:m.date)??h;f.expiration!=null&&f.expiration<=b?(f.status="expired",f.expiryUncertain=!0):f.status="unknown-open",f.timeRestingSeconds=b-f.createDate,f.dataCompleteness}let g=f.consumedEvents.reduce((h,b)=>h+(b.gets||0),0),v=f.crossedAtCreation.gets+g;f.realizedFillPct=f.takerGetsOriginal.value?Math.min(100,v/f.takerGetsOriginal.value*100):null,delete f._createIdx}let i={total:a.length,filledImmediately:a.filter(f=>f.status==="filled-immediately").length,cancelled:a.filter(f=>f.status==="cancelled").length,consumedLater:a.filter(f=>f.status==="consumed-later").length,partiallyFilled:a.filter(f=>f.status==="partially-filled-then-resting").length,expired:a.filter(f=>f.status==="expired").length,unknownOpen:a.filter(f=>f.status==="unknown-open").length};return{byOfferId:s,list:a,stats:i}}function qv(e,t){let n=e.list,s=n.length,a=n.filter(b=>b.status==="filled-immediately").length,o=n.filter(b=>b.status==="resting"||b.status==="partially-filled-then-resting"||b.status==="unknown-open").length,i=n.filter(b=>b.status==="consumed-later").length,r=n.filter(b=>b.status==="cancelled").length,l=n.filter(b=>b.status==="expired").length,c=n.filter(b=>b.status==="unknown-open").length,u=n.map(b=>b.timeRestingSeconds).filter(b=>b!=null),d=u.length?u.reduce((b,x)=>b+x,0)/u.length:null,p=[...u].sort((b,x)=>b-x),m=p.length?p[Math.floor(p.length/2)]:null,f=n.map(b=>b.realizedFillPct).filter(b=>b!=null),g=f.length?f.reduce((b,x)=>b+x,0)/f.length:null,v=new Map;for(let b of n){let x=[b.takerGetsOriginal.currency||"?",b.takerPaysOriginal.currency||"?"].sort().join("\u2194"),k=v.get(x)||{created:0,filled:0,cancelled:0,fillPctSum:0,fillPctCount:0};k.created++,(b.status==="filled-immediately"||b.status==="consumed-later")&&k.filled++,b.status==="cancelled"&&k.cancelled++,b.realizedFillPct!=null&&(k.fillPctSum+=b.realizedFillPct,k.fillPctCount++),v.set(x,k)}for(let b of v.values())b.avgFillPct=b.fillPctCount?b.fillPctSum/b.fillPctCount:null;let h=[];if(s>=10){let b=r/s;g!=null&&g<5&&b>.5?h.push(Se({module:"Offer Fill Rate",category:"liquidity",sev:"warn",confidence:.6,headline:`Low realized fill rate: ${g.toFixed(1)}% across ${s} offers`,detail:`${r} of ${s} offers were cancelled, most with minimal execution before cancellation.`,observed:[`${r} cancelled (${(b*100).toFixed(0)}%)`,`${i} consumed by a counterparty after resting`,`${l} expired/removed unfunded`,`${c} still open as of the last analyzed transaction`,`Average time resting before resolution: ${d!=null?d.toFixed(0)+"s":"unknown"}`],alternativeExplanations:["Active order management \u2014 repricing as the market moves","Automated market-making that requeues orders frequently"],evidenceAgainstBenign:g<1?["Realized fill percentage is near zero, not just below average"]:[],classification:"A low fill rate is observed. On its own this does not establish intent \u2014 see the Spoofing and Market-Maker Automation scores for further context."})):h.push(Se({module:"Offer Fill Rate",category:"liquidity",sev:"ok",confidence:.7,headline:`${g!=null?g.toFixed(1)+"%":"Normal"} realized fill rate across ${s} offers`,detail:`${a} filled immediately, ${i} consumed after resting, ${r} cancelled, ${l} expired.`}))}else h.push(Se({module:"Offer Fill Rate",category:"liquidity",sev:"info",headline:`Only ${s} offer(s) placed \u2014 insufficient sample for fill-rate analysis`,detail:"Need at least 10 OfferCreate transactions for a meaningful fill-rate read."}));return{createdCount:s,immediateFillCount:a,restingCount:o,laterConsumedCount:i,cancelledCount:r,expiredCount:l,unknownOpenCount:c,avgTimeRestingSeconds:d,medianTimeRestingSeconds:m,realizedFillPctOverall:g,byPair:v,findings:h}}function Vv(e,t,n){let s=e.list,a=s.map(h=>h.createDate).filter(h=>h!=null).sort((h,b)=>h-b),o=h=>{if(!a.length)return 0;let b=1;for(let x=0;x<a.length;x++){let k=1;for(let T=x+1;T<a.length&&a[T]-a[x]<=h;T++)k++;b=Math.max(b,k)}return b},i={thirtySec:o(30),oneHour:o(3600)},r=s.map(h=>h.takerGetsOriginal.value).filter(h=>h!=null&&h>0),l=null;if(r.length>=tr){let h=r.reduce((x,k)=>x+k,0)/r.length,b=Math.sqrt(r.reduce((x,k)=>x+(k-h)**2,0)/r.length);l=h>0?b/h:null}let c=[100,1e3,1e4,1e5],u=r.filter(h=>c.some(b=>Math.abs(h%b)<1e-6&&h/b>=1)).length,d=r.length?u/r.length:0,p=new Map;s.forEach(h=>{let b=[h.takerGetsOriginal.currency||"?",h.takerPaysOriginal.currency||"?"].sort().join("\u2194");p.set(b,(p.get(b)||0)+1)});let m=[...p.entries()].sort((h,b)=>b[1]-h[1])[0]||null,f=m&&s.length?m[1]/s.length:0,g=s.length?s.filter(h=>h.status==="cancelled").length/s.length:0,v=s.map(h=>h.timeRestingSeconds).filter(h=>h!=null);return{burstWindows:i,sizeCV:l,roundNumberPct:d,pairConcentration:f,dominantPair:m,cancelRatio:g,restingTimes:v,createdCount:s.length}}function Gv(e,t,n,s){let a=[],o=0,i=n.filter(({tx:d})=>d.TransactionType==="Payment"),r=new Set(i.filter(({tx:d})=>d.Account===s&&d.Destination).map(({tx:d})=>d.Destination)),l=new Set(i.filter(({tx:d})=>d.Destination===s&&d.Account).map(({tx:d})=>d.Account)),c=[...r].filter(d=>l.has(d));if(c.length>0&&i.length>=tr){let d=c.length/r.size;if(d>Tv){let p=new Set;for(let f of t.list){for(let g of f.counterpartiesAtCreation)p.add(g.account);for(let g of f.consumedEvents)g.counterpartyAccount&&p.add(g.counterpartyAccount)}let m=c.filter(f=>p.has(f));a.push(Se({module:"Wash Execution",category:"market-integrity",sev:"warn",confidence:m.length?.55:.4,headline:`${c.length} round-trip payment counterpart(s) detected`,detail:`${(d*100).toFixed(1)}% of payment recipients also sent back to this account.`,observed:[`${c.length} of ${r.size} outbound recipients also sent payments back`,m.length?`${m.length} of those also traded directly on the DEX with this account`:"No overlap found with DEX trading counterparties"],alternativeExplanations:["Ordinary reciprocal business/personal payments","Exchange deposit/withdrawal cycling through the same account"],evidenceAgainstBenign:m.length?["Payment round-trip AND direct DEX trading with the same counterparty(ies)"]:[],classification:"Round-trip payment pattern observed. Cannot confirm circular multi-account flow (A\u2192B\u2192C\u2192A) from this account's history alone \u2014 that would require the counterparties' own transaction histories."})),o+=m.length?25:15}}let u=i.filter(({tx:d})=>d.Account===s&&d.Destination===s);return u.length>0&&(a.push(Se({module:"Wash Execution",category:"market-integrity",sev:"critical",confidence:.85,headline:`${u.length} self-payment(s): sender = receiver`,detail:"Payments where origin and destination are the same address.",observed:[`${u.length} Payment transaction(s) with Account === Destination`],alternativeExplanations:["A no-op transaction used to mark an account active, or to test a memo/path"],evidenceAgainstBenign:u.length>2?["Repeated, not a single isolated instance"]:[],classification:"Confirmed self-payment. Creates recorded volume with zero net economic transfer \u2014 this is a fact about the transaction, not an inference."})),o+=30),a.length||a.push(Se({module:"Wash Execution",category:"market-integrity",sev:"ok",headline:"No wash-execution signals",detail:`${t.list.length} offers, ${u.length} self-payments \u2014 patterns look normal.`})),{score:Math.min(100,o),findings:a,stats:{roundTrip:c.length,selfTrades:u.length}}}function Kv(e,t,n,s,a){var d;let o=[],i=0,r=t.list,l=t.byOfferId,c=0,u=0;for(let p of r){if(!p.replacesOfferSeq)continue;let m=l.get(`${s}:${p.replacesOfferSeq}`);if(!m)continue;c++;let f=m.takerPaysOriginal.value&&m.takerGetsOriginal.value?m.takerPaysOriginal.value/m.takerGetsOriginal.value:null,g=p.takerPaysOriginal.value&&p.takerGetsOriginal.value?p.takerPaysOriginal.value/p.takerGetsOriginal.value:null;f&&g&&Math.abs(g-f)/f<.02&&u++}if(c>=5&&u/c>.6&&(o.push(Se({module:"Spoofing",category:"market-integrity",sev:"warn",confidence:.45,headline:`${u} of ${c} order replacements kept nearly the same price`,detail:"Cancel-and-immediately-recreate at a near-identical price, repeated \u2014 a quote-management pattern worth a closer look.",observed:[`${c} create-and-replace chains found`,`${u} replaced within 2% of the prior price`],alternativeExplanations:["Routine order refresh/repricing by an active trader or market maker","Bumping sequence to avoid an unrelated conflict"],classification:"Replacement pattern observed. On its own this is common in both legitimate quote maintenance and layering \u2014 see Market-Maker Automation for the explanatory read."})),i+=15),r.length>=10){let p=r.filter(m=>m.takerGetsOriginal.currency==="XRP"&&m.takerGetsOriginal.value!=null);if(p.length>=10){let m=p.map(b=>b.takerGetsOriginal.value).sort((b,x)=>x-b),f=m[Math.floor(m.length*.05)]||0,g=p.filter(b=>b.takerGetsOriginal.value>=f),v=g.filter(b=>b.status==="cancelled"||b.status==="expired"),h=g.length>=5?v.length/g.length:0;h>=.95&&(o.push(Se({module:"Spoofing",category:"market-integrity",sev:"warn",confidence:.3,headline:`${(h*100).toFixed(0)}% of this wallet's largest orders were cancelled without meaningful fill (own-history proxy)`,detail:`${v.length} of ${g.length} top-5%-by-this-wallet's-own-size orders cancelled or expired.`,observed:["Sizing is relative to this wallet's own order history, not current book depth",`${v.length}/${g.length} cancelled or expired without fill`],alternativeExplanations:["A large order sized appropriately for a genuinely deep, liquid market","Cancelled for unrelated reasons (funding change, strategy shift)"],classification:"Own-history size proxy only \u2014 true book-depth-relative sizing and price-distance-from-executable checks need historical order-book state this app cannot reliably obtain from public XRPL nodes. Treat as a weaker signal than a book-relative measurement would be."})),i+=10)}}if((d=a==null?void 0:a.signals)!=null&&d.length)for(let p of a.signals)(p.sev==="critical"||p.sev==="warn")&&(o.push(p),i+=p.sev==="critical"?20:10);return o.length||o.push(Se({module:"Spoofing",category:"market-integrity",sev:"ok",headline:"No spoofing signals",detail:"No large-order cancel pattern, replacement pattern, or live book wall detected."})),{score:Math.min(100,i),findings:o}}function Jv(e,t,n,s,a){let o=[],i=!1,r=e.cancelRatio>Sv,l=e.sizeCV!=null&&e.sizeCV<.2,c=e.burstWindows.thirtySec>=8||e.burstWindows.oneHour>100,u=(a==null?void 0:a.realizedFillPctOverall)!=null&&a.realizedFillPctOverall>=5;return e.createdCount>=tr&&r&&(l||c)?(i=!0,o.push(Se({module:"Market-Maker Automation",category:"automation",sev:"info",confidence:u?.6:.4,headline:"Behavior consistent with automated market-making / quote maintenance",detail:`${(e.cancelRatio*100).toFixed(0)}% cancel ratio, ${e.sizeCV!=null?"CV "+e.sizeCV.toFixed(2):"no size-uniformity read"}, max ${e.burstWindows.thirtySec} offers/30s.`,observed:[`Cancel ratio: ${(e.cancelRatio*100).toFixed(0)}%`,e.sizeCV!=null?`Order-size coefficient of variation: ${e.sizeCV.toFixed(2)}`:null,`Burst: up to ${e.burstWindows.thirtySec} offers in 30s, ${e.burstWindows.oneHour} in 1h`,u?`Realized fill rate: ${a.realizedFillPctOverall.toFixed(1)}% \u2014 not zero, consistent with a working market-making strategy`:"Realized fill rate is low or unknown"].filter(Boolean),alternativeExplanations:["Spoofing/layering dressed up with uniform sizing to look automated"],evidenceAgainstBenign:u?[]:["Fill rate is low despite the high order volume \u2014 automation alone does not explain that combination"],classification:u?"High cancel/burst/uniformity plus a non-trivial realized fill rate is the expected signature of legitimate automated market-making. This explanation should reduce confidence in Wash Execution and Spoofing findings above, not add to them.":"High cancel/burst/uniformity WITHOUT meaningful fills is less consistent with genuine market-making \u2014 weigh the Spoofing and Wash Execution findings above accordingly."}))):o.push(Se({module:"Market-Maker Automation",category:"automation",sev:"ok",headline:"No strong automation signature",detail:"Order behavior does not show the high-cancel/tight-sizing/burst pattern typical of automated market-making."})),{automationLikely:i,findings:o}}function Yv(e,t,n,s,a,o){let i=Vv(s,e,t),r=Gv(i,s,e,t),l=Kv(i,s,e,t,o),c=Jv(i,s,e,t,a),u=[...r.findings,...l.findings,...c.findings,...(a==null?void 0:a.findings)||[]],d=Math.min(100,r.score+l.score),p=d===0?"clean":d<25?"low-risk":d<50?"suspicious":"high-risk";return{signals:u,score:d,verdict:p,executionScore:r.score,spoofingScore:l.score,automationLikely:c.automationLikely,stats:{creates:s.list.length,cancels:s.list.filter(m=>m.status==="cancelled").length,fills:(a==null?void 0:a.immediateFillCount)??0,payments:e.filter(({tx:m})=>m.TransactionType==="Payment").length,roundTrip:r.stats.roundTrip,selfTrades:r.stats.selfTrades}}}var Qv=[0,.301,.176,.125,.097,.079,.067,.058,.051,.046];function Zv(e){let t=new Map;for(let{tx:n}of e){let s=n.TransactionType==="Payment"?"Payment":n.TransactionType==="OfferCreate"||n.TransactionType==="OfferCancel"?"Offer":null;if(!s)continue;let a=[n.Amount,n.TakerGets,n.TakerPays,n.SendMax,n.DeliverMin];for(let o of a){let i=Ji(o),r=Zt(o);if(r==null||r<=0||!Number.isFinite(r)||!i)continue;let l=`${i}|${s}`;t.has(l)||t.set(l,{currency:i,txClass:s,values:[]}),t.get(l).values.push(r)}}return t}function ey(e){let t=e.length,n=[];if(t<50)return{level:"LOW",reasons:[`Only ${t} observations in this group (need \u226550)`],n:t};let s=[...e].sort((d,p)=>d-p),a=s[0],o=s[s.length-1],i=a>0?Math.log10(o/a):0,r=[100,1e3,1e4,1e5],c=e.filter(d=>r.some(p=>Math.abs(d%p)<1e-6&&d/p>=1)).length/t,u="HIGH";return i<1?(u="LOW",n.push(`Values span only ${i.toFixed(1)} orders of magnitude \u2014 Benford needs a wide spread to be meaningful`)):i<2&&(u="MEDIUM",n.push(`Narrow magnitude spread (${i.toFixed(1)} orders of magnitude)`)),c>.5?(u="LOW",n.push(`${(c*100).toFixed(0)}% round-number amounts \u2014 suggests fixed lot sizes or tick constraints, not organically-generated values`)):c>.25&&u==="HIGH"&&(u="MEDIUM",n.push(`${(c*100).toFixed(0)}% round-number amounts`)),t<100&&u==="HIGH"&&(u="MEDIUM",n.push(`Sample size (${t}) clears the minimum but is still modest`)),n.length||n.push("Sufficient sample size, wide magnitude spread, low round-number concentration"),{level:u,reasons:n,magnitudeSpread:i,roundPct:c,n:t}}function ty(e){let t=e.length,n=new Array(10).fill(0);for(let o of e){let i=o.toFixed(6).replace(/^0+\.?0*/,""),r=parseInt(i[0],10);r>=1&&r<=9&&n[r]++}let s=0,a=[];for(let o=1;o<=9;o++){let i=n[o]/t,r=Qv[o];s+=t*Math.pow(i-r,2)/r,a.push({digit:o,obs:(i*100).toFixed(1),exp:(r*100).toFixed(1),delta:((i-r)*100).toFixed(1)})}return{chiSq:s,digitBreakdown:a,n:t}}function Wu(e){if((e==null?void 0:e.chiSq)==null)return 0;let t={HIGH:1,MEDIUM:.5,LOW:.15}[e.overallApplicability]??.15;return Math.min(10,e.chiSq/20.09*10)*t}function ny(e){let t=Zv(e),n=[];for(let[i,r]of t){if(r.values.length<50)continue;let l=ey(r.values),c=ty(r.values);n.push({key:i,currency:r.currency,txClass:r.txClass,...c,applicability:l})}if(n.sort((i,r)=>r.n-i.n),!n.length)return{signals:[{sev:"info",label:"Insufficient data for Benford's Law",detail:"No single currency/transaction-class group reached the 50-observation minimum \u2014 amounts are too fragmented across assets to test any one distribution meaningfully."}],results:[],overallApplicability:"LOW",chiSq:null,verdict:"insufficient",digitBreakdown:[],sampleSize:0};let s=n.map(i=>Se({module:"Benford's Law",category:"market-integrity",sev:i.applicability.level==="LOW"?"info":i.chiSq>20.09?"warn":"ok",confidence:{HIGH:.7,MEDIUM:.4,LOW:.15}[i.applicability.level],headline:`${i.currency==="XRP"?"XRP":z(i.currency)} ${i.txClass} amounts: \u03C7\xB2=${i.chiSq.toFixed(1)}, Applicability ${i.applicability.level}`,detail:`n=${i.n} observations`,observed:[`Benford Applicability: ${i.applicability.level}`,...i.applicability.reasons,`Chi-square statistic: ${i.chiSq.toFixed(2)} (critical values: 15.51 at p<0.05, 20.09 at p<0.01)`],classification:i.applicability.level==="LOW"?"Benford's Law is not reliably applicable to this group (narrow magnitude spread and/or high round-number concentration) \u2014 a deviation here says nothing about whether amounts were fabricated.":i.chiSq>20.09?"Amount-generation pattern is non-natural under this model. This describes the shape of the distribution, not a conclusion about intent \u2014 fixed pricing tiers, algorithmic strategies, and token denomination conventions are common legitimate causes of Benford deviation.":"First-digit distribution is consistent with organic, unconstrained amount generation."})),a=n[0],o=n.some(i=>i.applicability.level==="HIGH")?"HIGH":n.some(i=>i.applicability.level==="MEDIUM")?"MEDIUM":"LOW";return{signals:s,results:n,overallApplicability:o,chiSq:a.chiSq,verdict:a.chiSq>20.09?"high-deviation":a.chiSq>15.51?"moderate-deviation":"normal",digitBreakdown:a.digitBreakdown,sampleSize:a.n}}function sy(e,t){let s=[],a=[];for(let{tx:v}of e){let h=[v.Amount,v.TakerGets,v.TakerPays];for(let b of h){let x=typeof b=="string"?Number(b)/1e6:b!=null&&b.value?Number(b.value):null;x&&x>0&&Number.isFinite(x)&&a.push(x)}}let o=a.length>=30?(()=>{let v=new Array(12).fill(0);for(let h of a){let b=Math.min(11,Math.max(0,Math.floor(Math.log10(h+1)*2)));v[b]++}return Zs(v)})():null,i={};for(let{tx:v}of e){let h=v.Account===t?v.Destination:v.Account;h&&h!==t&&(i[h]=(i[h]||0)+1)}let r=Object.values(i),l=r.length>=3?Zs(r):null,c=new Array(24).fill(0),u=!1;for(let{tx:v}of e)if(v.date){let b=new Date((v.date+946684800)*1e3).getUTCHours();c[b]++,u=!0}let d=u&&e.length>=30?Zs(c):null,p={};for(let{tx:v}of e)p[v.TransactionType]=(p[v.TransactionType]||0)+1;let m=Zs(Object.values(p)),f="normal",g=0;if(o!==null&&(o<1.5?(f="low-entropy",g+=18,s.push({sev:"warn",label:`Amount entropy critically low (H=${o.toFixed(2)} bits)`,detail:"Transaction amounts are highly repetitive. A bot or scripted actor tends to reuse the same values. Organic wallets show entropy \u22652.4 bits across amount magnitudes."})):o<2.2?(g+=8,s.push({sev:"info",label:`Amount entropy below natural range (H=${o.toFixed(2)} bits)`,detail:"Some amount repetition detected. Could indicate automated activity mixed with organic transactions."})):o>4.5?(g+=10,s.push({sev:"info",label:`Amount entropy abnormally high (H=${o.toFixed(2)} bits)`,detail:"Transaction amounts are maximally varied \u2014 more than organic activity typically shows. This can indicate amounts were artificially randomized to evade Benford detection."})):s.push({sev:"ok",label:`Amount entropy normal (H=${o.toFixed(2)} bits)`,detail:"Transaction amount diversity is consistent with organic financial activity."})),l!==null&&(l<1&&r.length<4?(g+=14,s.push({sev:"warn",label:`Counterparty entropy very low (H=${l.toFixed(2)} bits)`,detail:"This wallet transacts with very few unique addresses and with high repetition \u2014 a structural signature of round-trip wash trading rings."})):l<2?(g+=5,s.push({sev:"info",label:`Counterparty entropy low (H=${l.toFixed(2)} bits)`,detail:"Most interactions are concentrated among a small set of counterparties."})):s.push({sev:"ok",label:`Counterparty diversity healthy (H=${l.toFixed(2)} bits)`,detail:"Counterparty distribution reflects diverse interaction patterns."})),d!==null){let v=Math.log2(24),h=d/v;h<.45?(g+=10,s.push({sev:"warn",label:`Time-of-day entropy low (H=${d.toFixed(2)} bits, ${(h*100).toFixed(0)}% of max)`,detail:"Transactions cluster heavily in a few hours of the day. Bots typically run at fixed UTC hours; organic users spread activity across the day."})):s.push({sev:"ok",label:`Time-of-day distribution natural (H=${d.toFixed(2)} bits)`,detail:"Transaction timing is distributed across hours in a pattern consistent with human activity."})}return s.length||s.push({sev:"info",label:"Insufficient data for entropy analysis",detail:`Need \u226530 transactions. Found ${e.length}.`}),g>=18?f="anomalous":g>=8&&(f="elevated"),{signals:s,verdict:f,riskPenalty:g,amountEntropy:o,counterpartyEntropy:l,timeEntropy:d,typeEntropy:m,uniqueCounterparties:r.length,sampleSize:e.length}}function Zs(e){let t=e.reduce((n,s)=>n+s,0);return t?-e.reduce((n,s)=>{if(!s)return n;let a=s/t;return n+a*Math.log2(a)},0):0}function ay(e,t){let s=[],a={};for(let{tx:C}of e){let P=C.Account===t?C.Destination:C.Account;P&&P!==t&&(a[P]=(a[P]||0)+1)}let o=Object.values(a).sort((C,P)=>P-C);if(o.length<8)return{signals:[{sev:"info",label:`Insufficient counterparties for Zipf's Law (need \u22658, found ${o.length})`,detail:"Zipf analysis becomes meaningful with a broader counterparty network."}],verdict:"insufficient",zipfExponent:null,riskPenalty:0,freqTable:[],uniqueCounterparties:o.length};let i=o.length,r=0,l=0,c=0,u=0,d=o.map((C,P)=>({rank:P+1,freq:C,lx:Math.log(P+1),ly:Math.log(C)}));for(let{lx:C,ly:P}of d)r+=C,l+=P,c+=C*P,u+=C*C;let p=i*u-r*r,m=p!==0?(i*c-r*l)/p:null,f=m!==null?Math.abs(m):null,g=l/i,v=0,h=0,b=(l-m*r)/i;for(let{lx:C,ly:P}of d)v+=Math.pow(P-g,2),h+=Math.pow(P-(m*C+b),2);let x=v>0?1-h/v:0,k="normal",T=0;f!==null&&(x<.55?(T+=12,s.push({sev:"warn",label:`Counterparty distribution doesn't follow Zipf's Law (R\xB2=${x.toFixed(2)})`,detail:`Natural networks follow a power-law rank-frequency relationship. This wallet's counterparty network has poor Zipf fit (R\xB2=${x.toFixed(2)}), suggesting artificial or script-driven interaction structure.`}),k="anomalous"):f<.4?(T+=15,s.push({sev:"warn",label:`Zipf exponent too flat (s=${f.toFixed(2)}, expected 0.8\u20131.3)`,detail:"A very flat Zipf exponent means counterparties are used with surprisingly equal frequency. In organic networks, you transact far more often with a few key addresses. Flat distribution is consistent with round-trip wash trading rings."}),k="anomalous"):f>2.2?(T+=10,s.push({sev:"warn",label:`Zipf exponent hyper-concentrated (s=${f.toFixed(2)}, expected 0.8\u20131.3)`,detail:"Extreme concentration on one or two counterparties with steep dropoff. While not unusual for simple wallets, combined with other signals this suggests coordinated narrow-ring activity."}),k="elevated"):s.push({sev:"ok",label:`Counterparty network follows Zipf's Law (s=${f.toFixed(2)}, R\xB2=${x.toFixed(2)})`,detail:"The rank-frequency distribution of counterparties follows the expected natural power-law pattern. This is consistent with organic wallet activity."}));let S={};for(let{tx:C}of e){let P=typeof C.Amount=="string"?Math.round(Number(C.Amount)/1e4)*10:null;P&&P>0&&(S[P]=(S[P]||0)+1)}let $=Object.values(S).sort((C,P)=>P-C),E=$.length?$[0]/$.reduce((C,P)=>C+P,0):0;return E>.45&&(T+=8,s.push({sev:"warn",label:`Single amount dominates ${(E*100).toFixed(0)}% of transactions`,detail:"One transaction amount value accounts for nearly half of all payments. Round-number dominance is a hallmark of scripted or wash-trading activity."})),s.length||s.push({sev:"info",label:"Zipf analysis: no anomalies detected",detail:"Counterparty distribution consistent with natural activity."}),{signals:s,verdict:k,riskPenalty:T,zipfExponent:f,rSquared:x,freqTable:o.slice(0,12),uniqueCounterparties:o.length}}function oy(e){if(e.length<20)return{signals:[{sev:"info",label:`Insufficient transactions for time series analysis (need \u226520, found ${e.length})`,detail:"Time series analysis requires a longer transaction history."}],verdict:"insufficient",riskPenalty:0,intervalCV:null,autocorrelation:null,burstScore:null,periodicityScore:null};let s=e.filter(({tx:S})=>S.date!=null).map(({tx:S})=>(S.date+946684800)*1e3).sort((S,$)=>S-$);if(s.length<20)return{signals:[{sev:"info",label:"No timestamp data available",detail:"Time series requires date-stamped transactions."}],verdict:"insufficient",riskPenalty:0,intervalCV:null,autocorrelation:null,burstScore:null,periodicityScore:null};let a=[];for(let S=1;S<s.length;S++){let $=(s[S]-s[S-1])/1e3;$>0&&$<86400*30&&a.push($)}let o=null;if(a.length>=5){let S=a.reduce((E,C)=>E+C,0)/a.length,$=Math.sqrt(a.reduce((E,C)=>E+Math.pow(C-S,2),0)/a.length);o=S>0?$/S:null}let i={};for(let S of s){let $=new Date(S).toISOString().slice(0,10);i[$]=(i[$]||0)+1}let r=Object.values(i),l=0;if(r.length>=4){let S=r.reduce((C,P)=>C+P,0)/r.length,$=Math.sqrt(r.reduce((C,P)=>C+Math.pow(P-S,2),0)/r.length),E=Math.max(...r);l=$>0?(E-S)/$:0}let c=null;if(r.length>=6){let S=r.reduce((C,P)=>C+P,0)/r.length,$=r.map(C=>C-S),E=$.reduce((C,P)=>C+P*P,0);E>0&&(c=$.slice(0,-1).reduce((P,R,O)=>P+R*$[O+1],0)/E)}let u=new Array(7).fill(0);for(let S of s)u[new Date(S).getUTCDay()]++;let d=Zs(u),p=Math.log2(7),m=0;if(a.length>=10){let S=[...a].sort((C,P)=>C-P),$=S[Math.floor(S.length/2)];m=a.filter(C=>Math.abs(C-$)/$<.2).length/a.length}let f=Object.entries(i).sort((S,$)=>S[0].localeCompare($[0])),g=null;if(f.length>=8){let S=Math.floor(f.length/2),$=f.slice(0,S),E=f.slice(S),C=D=>D.reduce((I,[,F])=>I+F,0)/D.length,P=C($),R=C(E),O=P>0&&R>0?Math.max(P,R)/Math.min(P,R):null;O!=null&&O>=3&&(g={transitionDate:E[0][0],beforeRate:P,afterRate:R,ratio:O,direction:R>P?"increase":"decrease"})}let v=0;o!==null&&(v+=Math.max(0,(.6-o)/.6)*60),v+=m*40,v=Math.min(100,Math.round(v));let h=[],b="normal",x=0;if(v>=60?(h.push({sev:"info",label:`Automation Probability: ${v}% (interval CV=${o!=null?o.toFixed(2):"\u2014"}, periodicity=${(m*100).toFixed(0)}%)`,detail:"Transaction timing is consistent with scripted/automated execution. This describes HOW the account operates, not whether it's risky \u2014 automation alone is common and legitimate (market makers, subscription payments, scheduled treasury operations)."}),x+=6):v>=30?h.push({sev:"ok",label:`Automation Probability: ${v}%`,detail:"Some timing regularity, within a range common to both scheduled tools and habitual human usage."}):h.push({sev:"ok",label:`Automation Probability: ${v}%`,detail:"Transaction timing shows natural, human-like variance."}),g&&(x+=4,h.push({sev:"info",label:`Regime Change detected around ${g.transitionDate}`,detail:`Daily transaction rate ${g.direction}d roughly ${g.ratio.toFixed(1)}x (${g.beforeRate.toFixed(1)} \u2192 ${g.afterRate.toFixed(1)} tx/day). A simple split-half comparison, not a formal changepoint test \u2014 treat the transition date as approximate.`})),l>3.5){let S=f.length?f.reduce(($,E)=>E[1]>$[1]?E:$)[0]:null;h.push({sev:"info",label:`Burst Event: peak day z-score ${l.toFixed(1)}${S?` (${S})`:""}`,detail:"One day had extreme transaction volume relative to this account's own baseline. Consistent with a coordinated event, an account-recovery sweep, or simply a busy day \u2014 timing and other signals (Fund Flow, Fee Spikes) provide the context this alone can't."})}c!==null&&c>.6&&(x+=4,h.push({sev:"info",label:`Volume Autocorrelation: HIGH (\u03C1=${c.toFixed(2)})`,detail:"Day-to-day transaction volume is strongly self-correlated \u2014 consistent with a routine that maintains a steady pace, not inherently risky on its own."}));let k=d/p;k<.7&&s.length>30&&h.push({sev:"info",label:`Unusual Relative to Account Baseline: day-of-week activity concentrated (${(k*100).toFixed(0)}% of max entropy)`,detail:"Transactions cluster on specific days of the week relative to this account's own history. Both maximally-flat (every day) and business-hours-only patterns can produce this \u2014 direction matters more than the raw number."}),h.length<=1&&v<30&&h.push({sev:"ok",label:"No temporal anomalies detected",detail:"Transaction timing patterns are consistent with organic human activity."}),x>=10&&(b="elevated");let T=s.length>=2?Math.round((s[s.length-1]-s[0])/864e5):null;return{signals:h,verdict:b,riskPenalty:x,intervalCV:o,autocorrelation:c,burstScore:l,periodicityScore:m,automationProbability:v,regimeChange:g,dowEntropy:d,dowBins:u,dailyVolume:Object.entries(i).slice(-30),activeSpanDays:T,totalTimestamped:s.length}}function iy(e,t){let s=[];if(e.length<20)return{signals:[{sev:"info",label:`Insufficient data for offer/flow coupling analysis (need \u226520, found ${e.length})`,detail:"Testing for lead-lag correlation requires enough temporal observations."}],verdict:"insufficient",riskPenalty:0,offerCancelCausality:null,inflowOutflowCausality:null};let o=12*3600*1e3,i=I=>I.date?Math.floor((I.date+946684800)*1e3/o):null,r={},l=I=>{r[I]||(r[I]={offerCreate:0,offerCancel:0,inflow:0,outflow:0,nftList:0,nftAccept:0})};for(let{tx:I,meta:F}of e){let H=i(I);if(H===null)continue;l(H);let N=r[H],j=I.TransactionType;j==="OfferCreate"?N.offerCreate++:j==="OfferCancel"&&N.offerCancel++,j==="NFTokenCreateOffer"?N.nftList++:j==="NFTokenAcceptOffer"&&N.nftAccept++;let se=(F==null?void 0:F.delivered_amount)||I.Amount,re=typeof se=="string"?Number(se)/1e6:0;re>0&&(I.Destination===t?N.inflow+=re:I.Account===t&&(N.outflow+=re))}let c=Object.keys(r).map(Number).sort((I,F)=>I-F);if(c.length<6)return{signals:[{sev:"info",label:"Insufficient temporal windows for coupling analysis",detail:"Need activity spread across multiple time windows."}],verdict:"insufficient",riskPenalty:0,offerCancelCausality:null,inflowOutflowCausality:null};let u=I=>c.map(F=>r[F][I]||0),d=(I,F,H=4)=>{let N=I.length,j=I.reduce((de,le)=>de+le,0)/N,se=F.reduce((de,le)=>de+le,0)/N,re=I.map(de=>de-j),pe=F.map(de=>de-se),ae=Math.sqrt(re.reduce((de,le)=>de+le*le,0)/N),te=Math.sqrt(pe.reduce((de,le)=>de+le*le,0)/N);return!ae||!te?Array(H+1).fill(0):Array.from({length:H+1},(de,le)=>{let Pe=0,B=0;for(let q=0;q+le<N;q++)Pe+=re[q]*pe[q+le],B++;return B>0?Pe/(B*ae*te):0})},p="normal",m=0,f=u("offerCreate"),g=u("offerCancel"),v=d(f,g),h=v.indexOf(Math.max(...v)),b=Math.max(...v),x={ccf:v,maxCorr:b,maxLag:h};b>.55&&h<=2?(m+=18,p="strong-coupling",s.push(Se({module:"Offer Coupling",category:"market-integrity",sev:"warn",confidence:.4,headline:`Offer Creation/Cancellation Coupling: HIGH (\u03C1=${b.toFixed(2)}, lag=${h} window${h===1?"":"s"})`,detail:`Offer creation and cancellation are strongly correlated ${h} window(s) apart (${h*12}h).`,observed:[`Cross-correlation \u03C1=${b.toFixed(2)} at a ${h}-window lag`,"Correlation, not a causality test \u2014 no autoregressive model or significance test was run"],alternativeExplanations:["Active order management/repricing that naturally pairs creates with cancels","A market maker's normal quote-refresh cycle"],classification:"Statistical coupling observed between offer creation and cancellation timing. This is the kind of pattern wash trading can produce, but correlation at a lag is not proof of it \u2014 see Wash Execution and Spoofing for behavior-level evidence."}))):b>.35?(m+=6,s.push(Se({module:"Offer Coupling",category:"market-integrity",sev:"info",confidence:.25,headline:`Offer Creation/Cancellation Coupling: MODERATE (\u03C1=${b.toFixed(2)}, lag=${h})`,detail:"A mild temporal link between creating and cancelling offers."}))):s.push({sev:"ok",label:"Offer Creation/Cancellation Coupling: LOW",detail:"Offer creation and cancellation timing appear independent."});let k=u("inflow"),T=u("outflow"),S=d(k,T),$=S.indexOf(Math.max(...S)),E=Math.max(...S),C={ccf:S,maxCorr:E,maxLag:$};E>.65&&$===0?(m+=12,s.push(Se({module:"Offer Coupling",category:"market-integrity",sev:"warn",confidence:.4,headline:`Inflow/Outflow Contemporaneous Correlation: HIGH (\u03C1=${E.toFixed(2)})`,detail:"Funds entering and leaving the wallet in the same 12h window are strongly correlated.",observed:[`Zero-lag correlation \u03C1=${E.toFixed(2)} \u2014 same-window co-movement, not a lead-lag relationship`,"A lag-0 result cannot show which direction (if either) leads the other"],alternativeExplanations:["Pass-through/consolidation behavior (an intermediary account by design)","Routine deposit-then-forward operational pattern"],classification:"Same-window co-movement between inflow and outflow, not a demonstrated lead-lag pattern. Consistent with pass-through/round-trip activity, but zero lag means the data alone cannot establish which value moved first."}))):E>.55&&$<=1?(m+=8,s.push(Se({module:"Offer Coupling",category:"market-integrity",sev:"info",confidence:.3,headline:`Inflow/Outflow Coupling: MODERATE (\u03C1=${E.toFixed(2)}, lag=${$})`,detail:"Incoming funds are correlated with outgoing funds at a short lag."}))):s.push({sev:"ok",label:"Inflow/Outflow Coupling: LOW",detail:"Inflow and outflow timing are not predictably linked."});let P=u("nftList"),R=u("nftAccept"),O=P.reduce((I,F)=>I+F,0),D=R.reduce((I,F)=>I+F,0);if(O>3&&D>3){let I=d(P,R),F=Math.max(...I),H=I.indexOf(F);F>.6&&H<=1&&(m+=8,s.push(Se({module:"Offer Coupling",category:"market-integrity",sev:"warn",confidence:.3,headline:`NFT Listing/Acceptance Coupling: HIGH (\u03C1=${F.toFixed(2)}, lag=${H})`,detail:"NFT sell-offer creation is closely correlated with acceptance timing.",alternativeExplanations:["A pre-arranged legitimate sale between known parties"],classification:"Timing coupling only \u2014 combined with the NFT trap detection module's own evidence, this can support (but does not by itself prove) a coordinated-acceptance pattern."})))}return s.some(I=>I.sev==="warn"||I.sev==="critical")||s.length||s.push({sev:"ok",label:"No coupling anomalies detected",detail:"Temporal relationships between transaction types show no notable lead-lag or contemporaneous correlation."}),m>=18?p="strong-coupling":m>=8&&(p="elevated"),{signals:s,verdict:p,riskPenalty:m,offerCancelCausality:x,inflowOutflowCausality:C,windowCount:c.length}}function ry(e){if(!e)return"";try{let t="";for(let n=0;n<e.length;n+=2){let s=parseInt(e.slice(n,n+2),16);s>=32&&s<127&&(t+=String.fromCharCode(s))}return t.length>4?t.toLowerCase().trim():""}catch{return""}}function ly(e){let t=Array.from({length:e},(a,o)=>o),n=a=>t[a]===a?a:t[a]=n(t[a]);return{find:n,union:(a,o)=>{let i=n(a),r=n(o);i!==r&&(t[i]=r)}}}function cy(e){let t=e.length,{find:n,union:s}=ly(t);for(let o=0;o<t;o++)for(let i=o+1;i<t;i++){let r=e[o],l=e[i];if(r.memos.size&&[...r.memos].some(p=>l.memos.has(p))){s(o,i);continue}let u=0;for(let p of r.timestamps)for(let m of l.timestamps)Math.abs(p-m)<=30&&u++;let d=Math.min(r.timestamps.length,l.timestamps.length);u>=3&&u>=d*.5&&s(o,i)}let a=new Map;for(let o=0;o<t;o++){let i=n(o);a.has(i)||a.set(i,[]),a.get(i).push(e[o])}return[...a.values()]}function dy(e){let t=e.reduce((l,c)=>l+c,0);if(t<=0||!e.length)return null;let n=e.map(l=>l/t).sort((l,c)=>c-l),s=n.reduce((l,c)=>l+c*c,0)*1e4,a=[...e].sort((l,c)=>l-c),o=a.length,i=0;a.forEach((l,c)=>{i+=(c+1)*l});let r=o>1&&t>0?Math.max(0,2*i/(o*t)-(o+1)/o):0;return{hhi:s,gini:r,top1Share:n[0]||0,top5Share:n.slice(0,5).reduce((l,c)=>l+c,0),effectiveParticipants:s>0?1e4/s:o}}var Lu=200;function py(e,t){let n=new Map;for(let{tx:o}of e){let i=[o.TakerGets,o.Amount],r=(o.Memos||[]).map(l=>{var c;return ry(((c=l.Memo)==null?void 0:c.MemoData)||"")}).filter(Boolean);for(let l of i){if(!l||typeof l!="object")continue;let c=l.currency,u=Number(l.value||0),d=o.Account;if(!c||!d||u<=0||!Number.isFinite(u))continue;n.has(c)||n.set(c,{senderMap:new Map,vol:0,trades:0});let p=n.get(c);p.vol+=u,p.trades++,p.senderMap.has(d)||p.senderMap.set(d,{sender:d,vol:0,memos:new Set,timestamps:[]});let m=p.senderMap.get(d);m.vol+=u,m.timestamps.push(Wn(o));for(let f of r)m.memos.add(f)}}let s=[],a=[];for(let[o,i]of n.entries()){if(i.trades<8)continue;let r=[...i.senderMap.values()],l=r.length,c=l>Lu,u=c?r.map(f=>[f]):cy(r),d=u.map(f=>f.reduce((g,v)=>g+v.vol,0)),p=dy(d);if(!p)continue;let m=l-u.length;a.push({currency:o,rawActorCount:l,estimatedActorClusters:u.length,vol:i.vol,trades:i.trades,...p}),p.hhi>1500&&s.push(Se({module:"Volume Concentration",category:"market-integrity",sev:p.hhi>2500?"critical":"warn",confidence:c?.3:m>0?.45:.3,headline:`${o}: ~${u.length} estimated economic actor(s) (${l} raw addresses), HHI ${Math.round(p.hhi)}`,detail:`${i.trades} trades totalling ${_(i.vol,2)} ${o}.`,observed:[`Raw distinct addresses: ${l}`,c?`Address count exceeded the clustering cap (${Lu}) for this pass \u2014 shown as raw addresses, not clustered`:m>0?`${m} address(es) merged into fewer likely-same-controller clusters via shared memo text or synchronized timing`:"No clustering signal found \u2014 each address treated as a separate actor",`HHI: ${Math.round(p.hhi)} (${p.hhi>2500?"highly concentrated":"moderately concentrated"} by standard antitrust bands: <1500 unconcentrated, 1500-2500 moderate, >2500 high)`,`Gini coefficient: ${p.gini.toFixed(2)}`,`Top-1 actor share: ${(p.top1Share*100).toFixed(0)}% \xB7 Top-5: ${(p.top5Share*100).toFixed(0)}%`,`Effective participant count (10000/HHI): ${p.effectiveParticipants.toFixed(1)}`],alternativeExplanations:m>0?["One legitimate market participant operating multiple wallets for ordinary reasons (custody segregation, accounting)"]:["A genuinely thin, low-participation market rather than coordinated activity"],classification:"Clustering here is best-effort \u2014 shared memo text or tightly synchronized timing only. It cannot detect a shared funding source or off-chain relationships between addresses, so the true number of distinct economic actors may be lower than shown, not higher."}))}return a.length?s.length||s.push({sev:"ok",label:"Volume concentration normal",detail:`${a.length} token(s) analysed \u2014 all show broad, unconcentrated participation (HHI < 1500).`}):s.push({sev:"info",label:"No IOU/token volume data",detail:"No token-denominated transactions found in history (XRP-only activity)."}),{signals:s,concentrations:a}}function uy(e,t,n,s){let a=[],o=!!(n&_e.lsfDefaultRipple)||t.some(h=>h.account===e.Account),i=t.filter(h=>Number(h.balance)<0),r=i.reduce((h,b)=>h+Math.abs(Number(b.balance)),0);i.length>0&&a.push({sev:"info",label:`Token issuer: ${i.length} outstanding currency lines`,detail:`Total outstanding: ${_(r,2)} across ${i.length} holder(s).`});let l=t.filter(h=>h.freeze),c=t.filter(h=>h.freeze_peer);l.length&&a.push({sev:"warn",label:`${l.length} trustline(s) frozen by this account`,detail:"This account has frozen specific trustlines."}),c.length&&a.push({sev:"critical",label:`${c.length} of your trustline(s) frozen by issuer`,detail:`Frozen currencies: ${c.map(h=>h.currency).join(", ")}. You cannot transfer these tokens.`}),n&_e.lsfGlobalFreeze&&a.push({sev:"critical",label:"Global Freeze \u2014 all token transfers suspended",detail:"No holders can transfer tokens issued by this account."}),n&_e.lsfNoFreeze&&a.push({sev:"ok",label:"NoFreeze flag set \u2014 issuer cannot freeze balances",detail:"Token holders are protected against future freeze actions."});let u={requireAuth:2,noFreeze:6,globalFreeze:7,defaultRipple:8,depositAuth:9},d=s.filter(({tx:h})=>h.TransactionType==="AccountSet"&&h.Account===e.Account&&(h.SetFlag!=null||h.ClearFlag!=null)).map(({tx:h})=>({date:h.date,hash:h.hash,setFlag:h.SetFlag??null,clearFlag:h.ClearFlag??null})).sort((h,b)=>(h.date??0)-(b.date??0)),p=h=>d.filter(b=>b.setFlag===h||b.clearFlag===h).length,m=p(u.globalFreeze),f=p(u.requireAuth);if(m>0){let h=d.filter(b=>b.setFlag===u.globalFreeze||b.clearFlag===u.globalFreeze).slice(-1)[0];a.push(Se({module:"Token Issuer",category:"issuer",sev:m>1?"warn":"info",confidence:.5,headline:`Global Freeze toggled ${m} time(s) in fetched history`,detail:`Most recent change: ${h.setFlag!=null?"frozen":"unfrozen"}.`,observed:[`${m} AccountSet transaction(s) setting or clearing Global Freeze`],alternativeExplanations:["A brief, disclosed freeze for a migration, exploit response, or contract upgrade"],classification:m>1?"Repeated freeze/unfreeze cycles show the issuer actively exercises this control, not just holds it theoretically \u2014 worth understanding why, from the project's own communications.":"A single freeze event in this account's history \u2014 check whether it was disclosed and time-bound."}))}f>0&&a.push({sev:"info",label:`Require Auth toggled ${f} time(s) in fetched history`,detail:"The issuer has changed whether new trustlines require its approval at least once."});let g=Number(e.Balance||0)/1e6,v=10+Number(e.OwnerCount||0)*2;return i.length>0&&g<v+1&&a.push({sev:"warn",label:"Issuer balance near reserve \u2014 possible black hole",detail:"Issuer with outstanding tokens has almost no XRP above reserve. Tokens may be stranded."}),a.length===0&&a.push({sev:"ok",label:"No token issuer flags",detail:"This account does not appear to be a token issuer."}),{signals:a,isIssuer:o,obligationCount:i.length,issuerFlagHistory:d}}function my(e,t,n,s=new Map,a=null){var f,g,v;let o=[],i=[],r=e.filter(h=>h.currency&&Number(h.balance)!==0&&Du(h.currency)),l=t.filter(({tx:h})=>h.TransactionType==="AMMDeposit"),c=t.filter(({tx:h})=>h.TransactionType==="AMMWithdraw"),u=t.filter(({tx:h})=>h.TransactionType==="AMMCreate"),d=t.filter(({tx:h})=>h.TransactionType==="AMMVote"),p=t.filter(({tx:h})=>h.TransactionType==="AMMBid");if(r.forEach(h=>{let b=Number(h.balance),x=Number(h.limit);i.push({currency:h.currency,issuer:h.account,balance:b,limit:x})}),a)for(let h of i){let b=[...l,...c].filter(({tx:S,meta:$})=>{var E,C;return(C=(E=$==null?void 0:$.AffectedNodes)==null?void 0:E.some)==null?void 0:C.call(E,P=>{var R;return((R=P.CreatedNode||P.ModifiedNode||P.DeletedNode)==null?void 0:R.LedgerEntryType)==="RippleState"&&[P.CreatedNode,P.ModifiedNode,P.DeletedNode].some(O=>{var D,I,F,H;return((I=(D=O==null?void 0:O.FinalFields)==null?void 0:D.Balance)==null?void 0:I.currency)===h.currency||((H=(F=O==null?void 0:O.NewFields)==null?void 0:F.Balance)==null?void 0:H.currency)===h.currency})})}),x=0,k=[],T=[];for(let{tx:S,meta:$}of b){let E=nr(S,$,a),C=E.lpDeltas.find(R=>R.currency===h.currency);if(!C)continue;let P={hash:S.hash,date:S.date,lpTokenDelta:C.delta,xrpDelta:E.xrpDelta,tokenDeltas:E.tokenDeltas};S.TransactionType==="AMMDeposit"?(k.push(P),x+=-E.xrpDelta):(T.push(P),x-=-E.xrpDelta)}(k.length||T.length)&&(h.depositEvents=k,h.withdrawEvents=T,h.costBasisXrp=x>0?x:null)}if(i.length){o.push({sev:"info",label:`${i.length} LP token position(s)`,detail:`Active liquidity provider in ${i.length} AMM pool(s).`});for(let h of i){let b=s.get(h.currency);if(b){if(h.tvl=b.amount?Number(b.amount)/1e6:null,h.tvl2=(f=b.amount2)!=null&&f.value?Number(b.amount2.value):null,h.feeRate=b.trading_fee!=null?b.trading_fee/1e3:null,h.lpSupply=(g=b.lp_token)!=null&&g.value?Number(b.lp_token.value):null,h.lpSupply&&h.balance){let x=Math.abs(h.balance)/h.lpSupply*100;h.ownerPct=x,x>50&&o.push({sev:"warn",label:`Dominant AMM position: ${x.toFixed(0)}% of pool`,detail:`This account controls ${x.toFixed(0)}% of the LP token supply for pool ${z(h.currency)}. Withdrawing all at once would severely impact pool liquidity and anyone currently trading in it.`})}h.tvl!=null&&o.push({sev:"info",label:`Pool TVL: ${_(h.tvl,2)} XRP${h.tvl2?` + ${_(h.tvl2,2)} tokens`:""} \xB7 Fee: ${((v=h.feeRate)==null?void 0:v.toFixed(2))??"?"}%`,detail:`Actual pool context from amm_info. Your LP position represents ${h.ownerPct!=null?h.ownerPct.toFixed(1)+"% of the pool.":"an unknown share of the pool."}`})}}}return u.length&&o.push({sev:"info",label:`Created ${u.length} AMM pool(s)`,detail:"This account bootstrapped one or more liquidity pools."}),(l.length||c.length)&&o.push({sev:"info",label:`${l.length} deposit(s) \xB7 ${c.length} withdrawal(s)`,detail:"LP activity history."}),d.length&&o.push({sev:"info",label:`${d.length} AMM fee vote(s)`,detail:"This account has voted on AMM trading fee parameters."}),p.length&&o.push({sev:"info",label:`${p.length} continuous auction bid(s)`,detail:"Bid for the AMM auction slot (reduced fee trading window)."}),i.filter(h=>Math.abs(h.balance)>1e3).length&&o.push({sev:"warn",label:"Large LP positions \u2014 impermanent loss risk",detail:"Significant liquidity positions carry exposure to price divergence between pool assets."}),o.length===0&&o.push({sev:"ok",label:"No AMM positions",detail:"This account is not a liquidity provider."}),{signals:o,positions:i,deposits:l.length,withdrawals:c.length}}function fy(e){let t=[],s=e.filter(({tx:p})=>p.Fee&&Number(p.Fee)>0);if(s.length<10)return{signals:[],verdict:"insufficient",riskPenalty:0,avgFeeMultiplier:null,spikeCount:0,topFeeHashes:[]};let a=s.map(({tx:p})=>Number(p.Fee)/12),o=a.reduce((p,m)=>p+m,0)/a.length,r=s.filter(({tx:p})=>Number(p.Fee)/12>100).length,l=r/s.length,c=0,u="normal",d=[...s].sort((p,m)=>Number(m.tx.Fee)-Number(p.tx.Fee)).slice(0,5).map(({tx:p})=>({hash:p.hash,mult:(Number(p.Fee)/12).toFixed(0),fee:Number(p.Fee)}));return l>.15&&r>=5?(c=10,u="elevated",t.push({sev:"warn",label:`Fee spike pattern: ${r} txs paid >100x base fee (${(l*100).toFixed(0)}% of history)`,detail:`Average fee multiplier: ${o.toFixed(0)}x. In XRPL, bots often pay elevated fees to guarantee same-ledger execution as a counterparty \u2014 a technique used in coordinated wash trading and sandwich attacks. Organic users rarely pay more than 2\u20135x the base fee. Top hashes: ${d.slice(0,3).map(p=>z(p.hash)).join(", ")}.`,hashes:d.map(p=>p.hash)})):o>20?(c=4,t.push({sev:"info",label:`Elevated average fee (${o.toFixed(0)}x base fee)`,detail:"This wallet consistently pays above-average fees. Could indicate priority execution requirements or automated trading."})):t.push({sev:"ok",label:`Fee levels normal (avg ${o.toFixed(1)}x base fee)`,detail:"Transaction fees are within typical organic ranges."}),{signals:t,verdict:u,riskPenalty:c,avgFeeMultiplier:+o.toFixed(2),spikeCount:r,topFeeHashes:d}}function hy(e,t){let n=[],s=new Map;for(let{tx:u}of e){if(u.TransactionType!=="Payment"||u.Account!==t)continue;let d=u.Destination,p=u.DestinationTag;d&&(s.has(d)||s.set(d,new Set),p!=null&&s.get(d).add(p))}let a=[...s.entries()].filter(([u])=>{let d=zn(u);return(d==null?void 0:d.type)==="exchange"}),o=e.filter(({tx:u})=>u.TransactionType==="Payment"&&u.Account===t&&u.Destination).length,i=e.filter(({tx:u})=>u.TransactionType==="Payment"&&u.Account===t&&u.Destination&&u.DestinationTag!=null).length,r=o>0?i/o*100:null,l=0,c=[];for(let[u,d]of s.entries()){let p=zn(u),m=(p==null?void 0:p.name)||z(u),f=d.size,g=e.filter(({tx:h})=>h.Account===t&&h.Destination===u).length,v=!p&&f>=8&&g>=10;c.push({dest:u,name:m,uniqueTags:f,txCount:g,looksCustodial:v,tags:[...d].slice(0,10)}),f===1&&g>=5&&(p==null?void 0:p.type)==="exchange"?n.push({sev:"info",label:`${m}: ${g} payments all using tag ${[...d][0]}`,detail:`Single destination tag used across all ${g} payments to ${m}. This is the normal pattern for one person funding their own exchange account.`}):f>10&&(p==null?void 0:p.type)==="exchange"?(l=Math.max(l,8),n.push({sev:"warn",label:`${m}: ${f} different destination tags used`,detail:`${g} payments to ${m} used ${f} different tags \u2014 each tag typically identifies a different customer account. Funding many exchange sub-accounts can indicate either a service (legitimate) or coordinated deposit layering where funds are spread across many exchange wallets to avoid detection.`})):f===0&&g>=2&&(p==null?void 0:p.type)==="exchange"?n.push({sev:"warn",label:`${m}: ${g} payments with no destination tag`,detail:"Payments to exchange addresses without a destination tag may not be credited. Most exchanges require a tag to identify which customer account receives the funds."}):v&&n.push(Se({module:"Destination Tags",category:"counterparty",sev:"info",confidence:.4,headline:`${z(u)}: unlabeled destination behaves like a custodial service (${f} distinct tags, ${g} payments)`,detail:"Not in the known-entity registry, but its tag-usage pattern matches an exchange/custodial routing scheme.",observed:[`${f} distinct destination tags across ${g} payments`,"Pattern matches per-customer sub-account routing, whoever operates it"],alternativeExplanations:["An exchange or custodial service not yet in this app's known-entity registry","A payment processor or merchant service using tags as invoice/order references"],classification:"Behavioral inference from tag-usage shape only \u2014 not a confirmed entity identification."}))}return r!=null&&o>=10&&n.push({sev:"ok",label:`Destination Tag usage: ${r.toFixed(0)}% of outbound payments (${i}/${o})`,detail:"Overall tag-usage rate across all outbound payments \u2014 context for the per-destination findings above, not a signal on its own."}),n.length===0&&s.size>0?n.push({sev:"ok",label:"Destination tag patterns normal",detail:"Payment routing tags are consistent with regular outbound payments."}):s.size===0&&n.push({sev:"info",label:"No outbound payments to analyse for destination tags",detail:"No outbound Payment transactions found in history."}),{signals:n,riskPenalty:l,tagProfiles:c}}function gy(e,t){var c,u;let n=[],s=e.filter(({tx:d})=>d.TransactionType==="Payment"&&d.Account===t&&(Array.isArray(d.Paths)&&d.Paths.length>0||d.SendMax!=null));if(s.length===0)return{signals:[],riskPenalty:0,roundTripCount:0,deepHopCount:0,selfRoutedCount:0,noData:!0};let a=s.length<5?` (small sample: ${s.length} path payments found \u2014 patterns may not be statistically significant)`:"",o=s.filter(({tx:d})=>{let p=typeof d.Amount=="string",m=typeof d.SendMax=="string";return p&&m}),i=s.filter(({tx:d})=>Array.isArray(d.Paths)?d.Paths.some(p=>Array.isArray(p)&&p.length>=3):!1),r=s.filter(({tx:d})=>d.Destination===t),l=0;return o.length>=1&&(l+=12,n.push({sev:"warn",label:`${o.length} XRP\u2192IOU\u2192XRP round-trip path payments`,detail:`Sending XRP and receiving XRP via intermediate token pairs means the payment routes through the DEX and creates trading volume without changing economic position. ${o.length} occurrences suggests this is deliberate. This is the classic cross-currency wash-trading arb pattern on XRPL. Example hash: ${(u=(c=o[0])==null?void 0:c.tx)!=null&&u.hash?z(o[0].tx.hash):"N/A"}.`,hashes:o.slice(0,5).map(({tx:d})=>d.hash).filter(Boolean)})),i.length>=1&&(l+=6,n.push({sev:"info",label:`${i.length} path payments with \u22653 intermediate hops`,detail:"Deep routing chains (3+ hops) can indicate: legitimate arbitrage, liquidity optimization, or deliberate obfuscation of fund origin. Check each transaction for the intermediate issuers in the path."})),r.length>0&&(l+=15,n.push({sev:"critical",label:`${r.length} path payment(s) where sender = destination`,detail:`Money sent to your own address via a multi-hop path creates DEX trading volume with no net change in balance. This is a direct wash-trading technique: the path through the order book generates artificial volume on every intermediate pair. Hashes: ${r.slice(0,3).map(({tx:d})=>z(d.hash||"")).join(", ")}.`,hashes:r.slice(0,5).map(({tx:d})=>d.hash).filter(Boolean)})),n.length===0&&n.push({sev:"ok",label:`${s.length} path payment(s) \u2014 no suspicious routing patterns${a}`,detail:"No circular routing (XRP\u2192IOU\u2192XRP), self-routing, or unusual deep hop chains detected."}),{signals:n,riskPenalty:l,roundTripCount:o.length,deepHopCount:i.length,selfRoutedCount:r.length}}function by(e,t){var d;let n=new Map,s=[];for(let{tx:p,meta:m}of e){if(p.TransactionType!=="Payment"||p.Destination!==t)continue;let f=p.Account;if(!f||f===t)continue;let g=0,v=null,h=(m==null?void 0:m.delivered_amount)||p.Amount;typeof h=="string"?g=Number(h)/1e6:h!=null&&h.value&&(v={value:Number(h.value),currency:Hn(h.currency),issuer:h.issuer});let b=Wn(p);s.push({src:f,amtXrp:g,amtToken:v,ts:b,hash:p.hash||"",destTag:p.DestinationTag}),n.has(f)||n.set(f,{addr:f,totalXrp:0,txCount:0,firstSeen:b,lastSeen:b,entity:zn(f)||null});let x=n.get(f);x.totalXrp+=g,x.txCount++,x.lastSeen=Math.max(x.lastSeen,b),x.firstSeen=Math.min(x.firstSeen,b)}let a=[...n.values()].sort((p,m)=>m.totalXrp-p.totalXrp||m.txCount-p.txCount).slice(0,10),o=a.reduce((p,m)=>p+m.totalXrp,0),i=a.filter(p=>{var m;return((m=p.entity)==null?void 0:m.type)==="exchange"}),r={};for(let p of s){if(p.amtXrp<=0)continue;let m=Math.round(p.amtXrp/10)*10;r[m]=(r[m]||0)+1}let l=Object.entries(r).sort((p,m)=>m[1]-p[1])[0],c=l&&l[1]>=5&&l[1]/s.length>.4,u=[];if(i.length){let p=[...new Set(i.map(m=>m.entity.name))].join(", ");u.push({sev:"info",label:`Funding from ${i.length} known exchange(s): ${p}`,detail:`${_(i.reduce((m,f)=>m+f.totalXrp,0),2)} XRP received from exchange withdrawals \u2014 typical for a personal trading wallet.`})}if(c&&u.push({sev:"warn",label:`Structured inbound pattern: ${l[1]} payments near ~${l[0]} XRP`,detail:`Over 40% of inbound payments cluster around the same amount (~${l[0]} XRP). Structured deposits can indicate layering \u2014 deliberately splitting large amounts into smaller equal transfers to avoid detection.`}),n.size===1&&s.length>=5){let p=a[0];u.push({sev:"info",label:`Single funding source: all ${s.length} inbound payments from one address`,detail:`${((d=p.entity)==null?void 0:d.name)||z(p.addr)} is the sole funding source. This is normal for a personal wallet but notable for a wallet claiming broad community usage.`})}return!u.length&&s.length>0&&u.push({sev:"ok",label:`${s.length} inbound payment(s) from ${n.size} source(s)`,detail:`Total received: ${_(o,2)} XRP. No unusual inbound patterns.`}),s.length===0&&u.push({sev:"info",label:"No inbound payments found in analysed history",detail:"Wallet may be funded via DEX activity or in ledgers outside the analysed range."}),{signals:u,topSources:a,totalIn:o,uniqueSources:n.size,timeline:s.slice(-20).reverse(),exchangeSrcs:i,structuredFlag:!!c}}function vy(e,t){var c,u;let n=[],s=[],a=[/airdrop/i,/claim.*reward/i,/free.*xrp/i,/verify.*wallet/i,/support.*team/i,/urgent/i,/suspended/i,/confirm.*seed/i,/your.*account.*hold/i,/unlock/i];for(let{tx:d}of e)if((c=d.Memos)!=null&&c.length)for(let p of d.Memos){let m=((u=p.Memo)==null?void 0:u.MemoData)||"";if(!m)continue;let f="";try{f=decodeURIComponent(m.replace(/../g,v=>"%"+v))}catch{f=m}if(!f||f===m)try{let v="";for(let h=0;h<m.length;h+=2){let b=parseInt(m.slice(h,h+2),16);b>=32&&b<127&&(v+=String.fromCharCode(b))}v.length>4&&(f=v)}catch{}let g=d.Account===t?d.Destination:d.Account;s.push({tx:d.hash||"",type:d.TransactionType,sender:d.Account,counterparty:g,date:d.date,text:f.slice(0,200),raw:m})}if(s.length===0)return{signals:[],allMemos:[],scamMemos:[],repeatedMemos:[],fingerprints:[]};let o=s.filter(d=>a.some(p=>p.test(d.text)));o.length&&n.push({sev:"critical",label:`${o.length} memo(s) match known scam patterns`,detail:`Memos containing phrases like "airdrop", "claim reward", "verify wallet", or "urgent" are used in social engineering attacks. These payments were likely sent to trick the recipient into taking action. Examples: ${o.slice(0,2).map(d=>'"'+d.text.slice(0,40)+'"').join(", ")}`});let i=new Map;for(let d of s){let p=d.text.slice(0,50).trim().toLowerCase();p.length<=3||(i.has(p)||i.set(p,[]),i.get(p).push(d))}let r=[...i.entries()].filter(([,d])=>d.length>=3).map(([d,p])=>{let m=[...new Set(p.map(v=>v.type))],f=new Set(p.map(v=>v.counterparty).filter(Boolean)),g=new Set(p.map(v=>v.sender));return{text:d,count:p.length,types:m,counterpartyCount:f.size,senderCount:g.size,crossAccount:g.size>1,occurrences:p}}).sort((d,p)=>p.count-d.count);for(let d of r.slice(0,5)){let p=Math.min(.9,.3+d.count*.05+(d.crossAccount?.15:0));n.push(Se({module:"Memo Analysis",category:"automation",sev:"info",confidence:p,headline:`Automation Fingerprint Detected: "${d.text.slice(0,40)}" \u2014 ${Math.round(p*100)}% confidence`,detail:`Appears ${d.count} time(s) across ${d.counterpartyCount} counterpart(y/ies) and ${d.types.length} transaction type(s).`,observed:[`${d.count} occurrences`,`Transaction types: ${d.types.join(", ")}`,`Distinct counterparties: ${d.counterpartyCount}`,d.crossAccount?`Sent by ${d.senderCount} different accounts, not just this one \u2014 likely shared tooling/infrastructure rather than something unique to this wallet`:"Only sent by this account in the fetched history"],alternativeExplanations:["Standard software/bot signature (exchange withdrawal tooling, a trading bot's build tag, issuer distribution tooling)","A recurring invoice or reference code used for ordinary bookkeeping"],classification:"Repeated identical memo text is a fingerprint of shared tooling or a scripted process, not inherently suspicious on its own \u2014 useful for identifying infrastructure, bots, or coordinated actors, but needs other evidence to say which."}))}let l=[...new Set(s.filter(d=>/\bv?\d+\.\d+(\.\d+)?\b/i.test(d.text)).map(d=>d.text))];return l.length>=2&&n.push({sev:"info",label:`${l.length} distinct version-like memo tag(s) observed`,detail:`Tags: ${l.slice(0,5).join(", ")}. Consistent with an automated tool's memo tag being bumped across software versions over time.`}),n.length||n.push({sev:"ok",label:`${s.length} memo(s) found \u2014 no suspicious patterns`,detail:"Memo content looks normal."}),{signals:n,allMemos:s,scamMemos:o,repeatedMemos:r.slice(0,5).map(d=>[d.text,d.count]),fingerprints:r}}function yy(e,t,n){let s=e.filter(d=>d.LedgerEntryType==="Escrow");if(!s.length)return{signals:[],escrows:[],hasThirdParty:!1};let a=[],o=Math.floor(Date.now()/1e3),i=946684800,r=s.map(d=>{let p=d.Account||null,m=d.Destination||null,f=Number(d.Amount||0)/1e6,g=d.FinishAfter?d.FinishAfter+i:null,v=d.CancelAfter?d.CancelAfter+i:null,h=p&&p!==n&&m===n,b=p===n&&m===n,x=g?Math.ceil((g-o)/86400):null;return{creator:p,dest:m,amtXrp:f,finishAfter:g,cancelAfter:v,isThirdParty:h,isSelfEscrow:b,daysToFinish:x,conditional:!!d.Condition}}),l=r.filter(d=>d.isThirdParty),c=r.reduce((d,p)=>d+p.amtXrp,0);l.length&&a.push({sev:"warn",label:`${l.length} escrow(s) created by external account(s) \u2014 funds locked to this address`,detail:`${_(l.reduce((d,p)=>d+p.amtXrp,0),2)} XRP in escrows that an outside party controls. The creator sets the conditions. Escrows created by attackers just before a drain attempt have been observed in some compromise patterns \u2014 verify who created these.`});let u=r.filter(d=>d.daysToFinish!=null&&d.daysToFinish>=0&&d.daysToFinish<=7);return u.length&&a.push({sev:"info",label:`${u.length} escrow(s) mature within 7 days`,detail:`${_(u.reduce((d,p)=>d+p.amtXrp,0),2)} XRP will become claimable soon. If these are third-party escrows, the creator can claim funds once the condition is met.`}),a.length||a.push({sev:"ok",label:`${s.length} self-escrow(s) \u2014 ${_(c,2)} XRP locked`,detail:"All escrows appear to be self-controlled time-locks. No third-party escrow risk."}),{signals:a,escrows:r,hasThirdParty:l.length>0,totalLocked:c}}function wy(e){let t=e.filter(l=>l.LedgerEntryType==="Check");if(!t.length)return{signals:[],checks:[]};let n=[],s=946684800,a=Math.floor(Date.now()/1e3),o=t.map(l=>{let c=typeof l.SendMax=="string"?Number(l.SendMax)/1e6:null,u=typeof l.SendMax=="object"?l.SendMax:null,d=l.Expiration?l.Expiration+s:null,p=(l.ledger_index,null),m=d&&d<a;return{sender:l.Account,dest:l.Destination,amtXrp:c,amtToken:u,expiry:d,expired:m,id:l.index||""}}),i=o.filter(l=>l.amtXrp&&l.amtXrp>100),r=o.filter(l=>l.expired);return i.length&&n.push({sev:"info",label:`${i.length} large uncashed check(s) \u2014 ${_(i.reduce((l,c)=>l+(c.amtXrp||0),0),2)} XRP pending`,detail:"Open checks can be cashed by the recipient at any time before expiry. Large uncashed checks represent a future outflow commitment."}),r.length&&n.push({sev:"info",label:`${r.length} expired check(s) \u2014 should be cancelled to reclaim reserve`,detail:"Expired checks still occupy owner reserve slots (2 XRP each). Cancelling them returns the reserved XRP."}),n.length||n.push({sev:"ok",label:`${t.length} check(s) found \u2014 no unusual patterns`,detail:"Check amounts are within normal range."}),{signals:n,checks:o}}function xy(e,t){var m,f,g;if(!e||!((m=e.offers)!=null&&m.length))return{signals:[],hasData:!1};let{pair:n,offers:s}=e,a=[],o=new Map;for(let v of s){let h=v.Account,b=typeof v.TakerGets=="string"?Number(v.TakerGets)/1e6:Number(((f=v.TakerGets)==null?void 0:f.value)||0);o.set(h,(o.get(h)||0)+b)}let i=[...o.values()].reduce((v,h)=>v+h,0),r=o.get(t)||0,l=i>0?r/i:0,u=[...s].sort((v,h)=>{var k,T;let b=typeof v.TakerGets=="string"?Number(v.TakerGets)/1e6:Number(((k=v.TakerGets)==null?void 0:k.value)||0);return(typeof h.TakerGets=="string"?Number(h.TakerGets)/1e6:Number(((T=h.TakerGets)==null?void 0:T.value)||0))-b})[0],d=typeof(u==null?void 0:u.TakerGets)=="string"?Number(u.TakerGets)/1e6:Number(((g=u==null?void 0:u.TakerGets)==null?void 0:g.value)||0),p=i>0?d/i:0;return p>.4&&(u==null?void 0:u.Account)===t?a.push({sev:"critical",label:`Active wall order: this wallet controls ${(p*100).toFixed(0)}% of current book depth`,detail:`A single order from this address represents ${(p*100).toFixed(0)}% of the visible order book depth on pair ${n}. Large orders placed to make a market look deeper than it is \u2014 without intent to fill \u2014 is spoofing. This order is live right now.`}):p>.4&&a.push({sev:"warn",label:`Wall order present: ${(p*100).toFixed(0)}% of book depth in one order`,detail:`A single address controls ${(p*100).toFixed(0)}% of the current order book for pair ${n}. Wall orders dominate book depth and can be removed instantly \u2014 they create false liquidity signals.`}),l>.25&&a.push({sev:"info",label:`This wallet controls ${(l*100).toFixed(0)}% of current order book depth`,detail:`${_(r,2)} of ${_(i,2)} total book volume on pair ${n}.`}),a.length||a.push({sev:"ok",label:`Live order book looks normal (${s.length} orders, pair: ${n.split("\u2194").map(v=>v.split("+")[0]).join("\u2194")})`,detail:"No wall orders or unusual depth concentration detected in the current order book."}),{signals:a,hasData:!0,pair:n,offerCount:s.length,ourShare:l,wallShare:p}}function ky(e,t,n,s,a,o,i,r,l,c,u,d,p,m){var g,v;return[{label:"Security",pts:Math.round((100-t.score)*.4),max:40,color:"#ff5555",icon:"\u{1F510}"},{label:"Drain Risk",pts:{low:0,medium:10,high:25,critical:35}[n.riskLevel]||0,max:35,color:"#ff5555",icon:"\u26A0\uFE0F"},{label:"Wash Trading",pts:Math.min(15,Math.round((a.score||0)*.15)),max:15,color:"#ffb86c",icon:"\u{1F4CA}"},{label:"NFT Risk",pts:Math.min(15,s.flags.filter(h=>h.sev==="critical").length*8+s.flags.filter(h=>h.sev==="warn").length*3),max:15,color:"#bd93f9",icon:"\u{1F3A8}"},{label:"Benford's",pts:Math.round(Wu(o)),max:10,color:"#f1fa8c",icon:"\u{1F4D0}"},{label:"Forensic Suite",pts:Math.min(20,Math.min(8,Math.round(((r==null?void 0:r.riskPenalty)||0)*.35))+Math.min(8,Math.round(((l==null?void 0:l.riskPenalty)||0)*.4))+Math.min(8,Math.round(((c==null?void 0:c.riskPenalty)||0)*.35))+Math.min(8,Math.round(((u==null?void 0:u.riskPenalty)||0)*.35))),max:20,color:"#00d4ff",icon:"\u{1F9EC}"},{label:"Vol Conc",pts:Math.min(10,(((g=i==null?void 0:i.signals)==null?void 0:g.filter(h=>h.sev==="critical").length)||0)*6+(((v=i==null?void 0:i.signals)==null?void 0:v.filter(h=>h.sev==="warn").length)||0)*3),max:10,color:"#ffb86c",icon:"\u{1FAE7}"},{label:"Fee Spikes",pts:Math.min(5,(d==null?void 0:d.riskPenalty)||0),max:5,color:"#ffb86c",icon:"\u{1F4B8}"}].filter(h=>h.pts>0)}var Yi=["security","market-integrity","counterparty","issuer","liquidity","automation"],$y={security:"Security Risk","market-integrity":"Market Integrity Risk",counterparty:"Counterparty Risk",issuer:"Issuer Risk",liquidity:"Liquidity Risk",automation:"Automation Probability"},Sy={Security:"security","Drain Risk":"security",NFT:"security","Wash Trading":"market-integrity","Benford's Law":"market-integrity","Offer/Flow Coupling":"market-integrity","Volume Concentration":"market-integrity","Shannon's Entropy":"market-integrity","Zipf's Law":"market-integrity","Time Series":"market-integrity","Live Order Book":"market-integrity","Token Issuer":"issuer","Issuer Connections":"issuer",AMM:"liquidity","Fund Flow":"counterparty","Destination Tags":"counterparty","Path Payments":"counterparty","Inbound Flow":"counterparty","Escrow Depth":"counterparty","Fee Spikes":"automation","Memo Analysis":"automation"},Ty={critical:40,warn:15,info:3,ok:0};function Cy(e){let t={};for(let n of Yi)t[n]={score:0,findings:[]};for(let n of e){if(n.sev==="ok"||!n.sev)continue;let s=n.category||Sy[n.module]||"security";if(!t[s])continue;let a=n.confidence??.5;t[s].score+=(Ty[n.sev]??0)*a,t[s].findings.push(n)}for(let n of Yi)t[n].score=Math.round(Math.min(100,t[n].score));return t}function Py(e,t,n,s,a,o,i,r,l,c,u=null){let d=0;d+=Math.round((100-e.score)*.4),d+={low:0,medium:10,high:25,critical:35}[t.riskLevel]||0;let m=n.flags.filter(g=>g.sev==="critical").length,f=n.flags.filter(g=>g.sev==="warn").length;if(d+=Math.min(15,m*8+f*3),d+=Math.min(15,Math.round(s.score*.15)),d+=Wu(a),o!=null&&o.signals){let g=o.signals.filter(h=>h.sev==="critical").length,v=o.signals.filter(h=>h.sev==="warn").length;d+=Math.min(10,g*6+v*3)}return i!=null&&i.riskPenalty&&(d+=Math.min(8,Math.round(i.riskPenalty*.35))),r!=null&&r.riskPenalty&&(d+=Math.min(8,Math.round(r.riskPenalty*.4))),l!=null&&l.riskPenalty&&(d+=Math.min(8,Math.round(l.riskPenalty*.35))),c!=null&&c.riskPenalty&&(d+=Math.min(8,Math.round(c.riskPenalty*.35))),u!=null&&u.riskPenalty&&(d+=Math.min(5,u.riskPenalty)),Math.round(Math.min(100,d))}function My(e){var g;let t=document.getElementById("inspect-benfords-body");if(!t)return;let n=e.signals.map(Dt).join(""),s=(g=e.digitBreakdown)!=null&&g.length?`
    <div class="benford-grid">
      <div class="benford-grid-h">Digit</div>
      <div class="benford-grid-h">Observed</div>
      <div class="benford-grid-h">Expected</div>
      <div class="benford-grid-h">Bar</div>
      ${e.digitBreakdown.map(v=>{let h=parseFloat(v.obs),b=parseFloat(v.exp),x=h-b,k=Math.abs(x)>5?"#ff5555":Math.abs(x)>2.5?"#ffb86c":"#50fa7b",T=`<div style="height:6px;border-radius:3px;background:rgba(255,255,255,.08);overflow:hidden">
          <div style="height:100%;width:${Math.min(100,h*3.3).toFixed(0)}%;background:${k};border-radius:3px"></div>
        </div>`;return`<div class="mono" style="text-align:center">${v.digit}</div>
                <div class="mono" style="color:${k}">${v.obs}%</div>
                <div class="mono" style="opacity:.6">${v.exp}%</div>
                <div>${T}</div>`}).join("")}
    </div>`:"",a=e.chiSq!=null?`<div class="wash-stat-row" style="margin-top:8px">
        <span>Sample size</span><span class="mono">${e.sampleSize}</span>
       </div>
       <div class="wash-stat-row">
        <span>Chi-squared (\u03C7\xB2)</span>
        <span class="mono ${e.chiSq>20.09?"risk-text-high":e.chiSq>15.51?"risk-text-med":""}">${e.chiSq.toFixed(2)}</span>
       </div>
       <div class="wash-stat-row">
        <span>Critical values</span><span class="mono" style="opacity:.6">p&lt;0.05: 15.51 \xB7 p&lt;0.01: 20.09</span>
       </div>`:"",o=e.verdict,i=e.chiSq,r=e.sampleSize,l="\u{1F4CA}",c="What is Benford\u2019s Law?",u="In nature \u2014 population sizes, river lengths, stock prices, real financial transactions \u2014 the leading (first) digit of numbers is NOT random. The number 1 appears as the first digit about 30% of the time. The number 9 appears only 4.6% of the time. This predictable pattern is Benford's Law.",d="",p="rgba(255,255,255,.08)",m="rgba(255,255,255,.10)";o==="insufficient"?d=`<p class="benford-explain-result">Not enough data yet \u2014 we need at least 50 transaction amounts to run this test. This account has ${r} so far. The more activity, the more reliable the analysis.</p>`:o==="high-deviation"?(l="\u{1F6A8}",p="rgba(255,85,85,.06)",m="rgba(255,85,85,.22)",d=`<p class="benford-explain-result">
      <strong style="color:#ff5555">What this means for this account:</strong>
      The transaction amounts here deviate strongly from what you'd expect in real organic activity
      (\u03C7\xB2&nbsp;=&nbsp;${i==null?void 0:i.toFixed(1)}, which is above the suspicious threshold of 20.09 at 99% confidence).
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
    </p>`):o==="moderate-deviation"?(l="\u26A0",p="rgba(255,184,108,.05)",m="rgba(255,184,108,.20)",d=`<p class="benford-explain-result">
      <strong style="color:#ffb86c">What this means for this account:</strong>
      There's a moderate mismatch from natural patterns (\u03C7\xB2&nbsp;=&nbsp;${i==null?void 0:i.toFixed(1)}).
      This could mean some automated or repeated transactions are mixed in with genuine activity.
      It isn't alarming on its own but is worth watching \u2014 especially if other sections also show signals.
    </p>`):o==="normal"&&(l="\u2705",p="rgba(80,250,123,.04)",m="rgba(80,250,123,.15)",d=`<p class="benford-explain-result">
      <strong style="color:#50fa7b">What this means for this account:</strong>
      The transaction amounts follow the natural Benford's pattern closely (\u03C7\xB2&nbsp;=&nbsp;${i==null?void 0:i.toFixed(1)}).
      This is what you'd expect from organic, real-world financial activity.
      No statistical red flags here.
    </p>`);let f=`
    <div class="benford-explainer" style="background:${p};border-color:${m}">
      <div class="benford-explainer-head">
        <span class="benford-explainer-icon">${l}</span>
        <span class="benford-explainer-title">${c}</span>
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
      ${d}
    </div>
  `;t.innerHTML=n+a+s+f}function Ly(e){var a;let t=document.getElementById("inspect-volconc-body");if(!t)return;let n=e.signals.map(Dt).join(""),s=(a=e.concentrations)!=null&&a.length?`
    <table class="benford-grid" style="margin-top:10px;width:100%">
      <tr style="opacity:.5;font-size:10px">
        <th style="text-align:left">Currency</th>
        <th>Unique actors</th>
        <th>Trades</th>
        <th>Indicator</th>
      </tr>
      ${e.concentrations.map(o=>{let i=o.uniqueActors<5?"#ff5555":o.uniqueActors<10?"#ffb86c":"#50fa7b",r=o.uniqueActors<5?"\u{1F6A8} Wash risk":o.uniqueActors<10?"\u26A0 Low diversity":"\u2713 OK";return`<tr>
          <td class="mono" style="padding:3px 0">${y(o.currency.slice(0,10))}</td>
          <td class="mono" style="text-align:center;color:${i}">${o.uniqueActors}</td>
          <td class="mono" style="text-align:center;opacity:.7">${o.trades}</td>
          <td style="font-size:11px;color:${i}">${r}</td>
        </tr>`}).join("")}
    </table>`:"";t.innerHTML=n+s}function ao(e,t,n){let s=document.getElementById(e);if(!s)return;let a=t.signals.map(Dt).join("");s.innerHTML=a+(n||"")}function Ay(e){let t=[["Sample size",e.sampleSize],["Amount entropy",e.amountEntropy!=null?e.amountEntropy.toFixed(2)+" bits":"\u2014",e.amountEntropy!=null&&e.amountEntropy<2?"risk-text-high":""],["Counterparty entropy",e.counterpartyEntropy!=null?e.counterpartyEntropy.toFixed(2)+" bits":"\u2014"],["Time-of-day entropy",e.timeEntropy!=null?e.timeEntropy.toFixed(2)+" bits":"\u2014"],["Unique counterparties",e.uniqueCounterparties],["Verdict",e.verdict,e.verdict==="anomalous"?"risk-text-high":e.verdict==="elevated"?"risk-text-med":""]];ao("inspect-entropy-body",e,'<div class="wash-stat-row" style="margin-top:10px"><span>Metric</span><span class="mono" style="opacity:.45">Value</span></div>'+t.map(([n,s,a])=>`<div class="wash-stat-row"><span>${n}</span><span class="mono ${a||""}">${s}</span></div>`).join(""))}function Ey(e){var s;let t=[["Unique counterparties",e.uniqueCounterparties],["Zipf exponent (s)",e.zipfExponent!=null?e.zipfExponent.toFixed(3):"\u2014",e.zipfExponent!=null&&(e.zipfExponent<.4||e.zipfExponent>2.2)?"risk-text-high":""],["Fit quality (R\xB2)",e.rSquared!=null?e.rSquared.toFixed(3):"\u2014",e.rSquared!=null&&e.rSquared<.55?"risk-text-high":""],["Natural range","s \u2248 0.8\u20131.3, R\xB2 > 0.55"],["Verdict",e.verdict,e.verdict==="anomalous"?"risk-text-high":e.verdict==="elevated"?"risk-text-med":""]],n=((s=e.freqTable)==null?void 0:s.slice(0,10).map((a,o)=>{let i=e.freqTable[0]||1,r=(a/i*100).toFixed(0),l=e.freqTable[0]?(e.freqTable[0]/Math.pow(o+1,e.zipfExponent||1)).toFixed(1):0;return`<div class="wash-stat-row">
      <span class="mono" style="min-width:28px">Rank ${o+1}</span>
      <div style="flex:1;height:6px;background:rgba(255,255,255,.06);border-radius:3px;overflow:hidden;margin:0 8px">
        <div style="height:100%;width:${r}%;background:var(--accent);border-radius:3px"></div>
      </div>
      <span class="mono" style="opacity:.6">${a}</span>
    </div>`}).join(""))||"";ao("inspect-zipf-body",e,t.map(([a,o,i])=>`<div class="wash-stat-row" style="margin-top:${a==="Unique counterparties"?10:0}px"><span>${a}</span><span class="mono ${i||""}">${o}</span></div>`).join("")+(n?`<div style="margin-top:14px;opacity:.75;font-size:.72rem;letter-spacing:.08em;color:rgba(255,255,255,.45);margin-bottom:6px">COUNTERPARTY RANK\u2013FREQUENCY</div>${n}`:""))}function Ny(e){let t=[["Transactions timed",e.totalTimestamped||"\u2014"],["Active span",e.activeSpanDays!=null?e.activeSpanDays+" days":"\u2014"],["Interval CV",e.intervalCV!=null?e.intervalCV.toFixed(3):"\u2014",e.intervalCV!=null&&e.intervalCV<.5?"risk-text-high":""],["Periodicity score",e.periodicityScore!=null?(e.periodicityScore*100).toFixed(0)+"%":"\u2014",e.periodicityScore>.55?"risk-text-high":""],["Burst score (z)",e.burstScore!=null?e.burstScore.toFixed(2):"\u2014"],["Lag-1 autocorrelation",e.autocorrelation!=null?e.autocorrelation.toFixed(3):"\u2014",e.autocorrelation>.6?"risk-text-med":""],["Day-of-week entropy",e.dowEntropy!=null?e.dowEntropy.toFixed(2)+" bits":"\u2014"],["Verdict",e.verdict,e.verdict==="elevated"?"risk-text-med":""]],n=["Sun","Mon","Tue","Wed","Thu","Fri","Sat"],s=e.dowBins?Math.max(...e.dowBins,1):1,a=e.dowBins?`
    <div style="margin-top:14px;opacity:.75;font-size:.72rem;letter-spacing:.08em;color:rgba(255,255,255,.45);margin-bottom:6px">DAY-OF-WEEK DISTRIBUTION</div>
    <div style="display:flex;gap:5px;align-items:flex-end;height:42px">
      ${e.dowBins.map((o,i)=>`
        <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:3px">
          <div style="width:100%;height:${(o/s*36).toFixed(0)}px;background:rgba(0,212,255,.35);border-radius:2px 2px 0 0;min-height:2px"></div>
          <div style="font-size:.6rem;opacity:.5">${n[i]}</div>
        </div>`).join("")}
    </div>`:"";ao("inspect-timeseries-body",e,t.map(([o,i,r])=>`<div class="wash-stat-row" style="margin-top:${o==="Transactions timed"?10:0}px"><span>${o}</span><span class="mono ${r||""}">${i}</span></div>`).join("")+a)}function Ry(e){let t=e.offerCancelCausality,n=e.inflowOutflowCausality,s=(o,i)=>{if(!(o!=null&&o.length))return"";let r=Math.max(.01,...o.map(Math.abs));return`<div style="margin-top:12px;opacity:.75;font-size:.72rem;letter-spacing:.08em;color:rgba(255,255,255,.45);margin-bottom:6px">${i}</div>
    <div style="display:flex;gap:4px;align-items:flex-end;height:40px">
      ${o.map((l,c)=>{let u=(Math.abs(l)/r*36).toFixed(0),d=l>.5?"rgba(255,85,85,.7)":l>.3?"rgba(255,184,108,.6)":"rgba(0,212,255,.3)";return`<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:3px">
          <div style="width:100%;height:${u}px;background:${d};border-radius:2px 2px 0 0;min-height:2px"></div>
          <div style="font-size:.6rem;opacity:.5">L${c}</div>
        </div>`}).join("")}
    </div>`},a=[["Time windows",e.windowCount||"\u2014"],["OfferCreate\u2194Cancel \u03C1",t?t.maxCorr.toFixed(3):"\u2014",t&&t.maxCorr>.55?"risk-text-high":""],["OC lag",t?`${t.maxLag} window${t.maxLag===1?"":"s"} (${t.maxLag*12}h)`:"\u2014"],["Inflow\u2194Outflow \u03C1",n?n.maxCorr.toFixed(3):"\u2014",n&&n.maxCorr>.65?"risk-text-high":""],["IO lag",n?`${n.maxLag} window${n.maxLag===1?"":"s"}`:"\u2014"],["Verdict",e.verdict,e.verdict==="strong-coupling"?"risk-text-high":e.verdict==="elevated"?"risk-text-med":""]];ao("inspect-granger-body",e,a.map(([o,i,r])=>`<div class="wash-stat-row" style="margin-top:${o==="Time windows"?10:0}px"><span>${o}</span><span class="mono ${r||""}">${i}</span></div>`).join("")+s(t==null?void 0:t.ccf,"OFFER-CREATE \u2194 CANCEL CROSS-CORRELATION")+s(n==null?void 0:n.ccf,"INFLOW \u2194 OUTFLOW CROSS-CORRELATION"))}function _y(e,t,n,s,a){let o=document.getElementById("inspect-forensic-suite-body");if(!o)return;let i=(b,x=25)=>{if(!b||b.verdict==="insufficient")return null;if(b.chiSq!=null)return b.verdict==="high-deviation"?{val:x,cls:"risk-text-high",label:"HIGH DEVIATION"}:b.verdict==="moderate-deviation"?{val:Math.round(x*.5),cls:"risk-text-med",label:"MODERATE"}:{val:0,cls:"",label:"NORMAL"};let k=b.riskPenalty||0;return k>=18?{val:x,cls:"risk-text-high",label:"ANOMALOUS"}:k>=8?{val:Math.round(x*.5),cls:"risk-text-med",label:"ELEVATED"}:{val:0,cls:"",label:"NORMAL"}},r=[{name:"Benford's Law",icon:"\u{1F4D0}",desc:"First-digit digit distribution vs log-uniform expected",s:i(e)},{name:"Shannon's Entropy",icon:"\u{1F500}",desc:"Randomness of amounts, counterparties, time-of-day, tx types",s:i(t)},{name:"Zipf's Law",icon:"\u{1F4C8}",desc:"Counterparty rank-frequency power-law fit",s:i(n)},{name:"Time Series",icon:"\u{1F550}",desc:"Interval regularity, periodicity, burst detection, autocorrelation",s:i(s)},{name:"Offer/Flow Coupling",icon:"\u{1F517}",desc:"Cross-correlation, not causality: offer create\u2194cancel, inflow\u2194outflow",s:i(a)}],l=r.some(b=>b.s&&b.s.val>0),c=r.filter(b=>{var x;return((x=b.s)==null?void 0:x.cls)==="risk-text-high"}).length,u=r.filter(b=>{var x;return((x=b.s)==null?void 0:x.cls)==="risk-text-med"}).length,d=r.filter(b=>!b.s).length,p,m,f;c>=3?(p="STRONG MANIPULATION SIGNALS \u2014 Multiple independent engines converging on anomalous patterns.",m="#ff5555",f="\u{1F6A8}"):c>=2||c>=1&&u>=2?(p="SIGNIFICANT ANOMALIES \u2014 At least two engines detect non-organic behavior. Cross-reference with Wash Trading and Drain Risk.",m="#ff5555",f="\u26A0\uFE0F"):c>=1||u>=2?(p="ELEVATED RISK \u2014 One or more engines flag behavioral anomalies. Investigate the specific modules for detail.",m="#ffb86c",f="\u26A0\uFE0F"):!l&&d<3?(p="NO ANOMALIES \u2014 All five engines return results consistent with organic financial activity.",m="#50fa7b",f="\u2705"):(p="INSUFFICIENT DATA \u2014 More transaction history needed for a reliable multi-engine assessment.",m="rgba(255,255,255,.4)",f="\u{1F4CA}");let g=r.map(b=>{let x=!b.s,k=x?"rgba(255,255,255,.25)":b.s.val===0?"#50fa7b":b.s.cls==="risk-text-high"?"#ff5555":"#ffb86c",T=x?"NO DATA":b.s.label,S=x?0:b.s.val===0?4:b.s.cls==="risk-text-high"?100:55;return`<div style="background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);border-radius:12px;padding:14px 14px 12px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span style="font-size:1.05rem">${b.icon}</span>
        <div style="flex:1">
          <div style="font-size:.82rem;font-weight:700;color:rgba(255,255,255,.85)">${b.name}</div>
          <div style="font-size:.7rem;color:rgba(255,255,255,.35);margin-top:1px;line-height:1.4">${b.desc}</div>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        <div style="flex:1;height:5px;background:rgba(255,255,255,.08);border-radius:3px;overflow:hidden">
          <div style="height:100%;width:${S}%;background:${k};border-radius:3px;transition:width .6s ease"></div>
        </div>
        <span style="font-size:.65rem;font-weight:800;color:${k};min-width:80px;text-align:right;letter-spacing:.06em">${T}</span>
      </div>
    </div>`}).join(""),v=r.filter(b=>b.s&&b.s.val>0),h="";v.length>=2?h=`<div style="background:rgba(255,184,108,.05);border:1px solid rgba(255,184,108,.2);border-radius:12px;padding:14px 16px;margin-top:14px">
      <div style="font-size:.68rem;font-weight:900;color:#ffb86c;letter-spacing:.12em;text-transform:uppercase;margin-bottom:8px">\u26A1 Convergence Analysis</div>
      <p style="font-size:.84rem;color:rgba(255,255,255,.65);line-height:1.7;margin:0">
        ${v.map(b=>b.name).join(" and ")} are all flagging behavioral anomalies.
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
    ${h}`}function Dy(e,t,n,s,a,o,i,r=null,l=null,c=!1){let u=w("inspect-addr-badge");u&&(u.textContent=e.length>20?e.slice(0,10)+"\u2026"+e.slice(-8):e,u.title=e,u.dataset.fullAddr=e);let d=w("inspect-risk-score");d&&(d.textContent=i,d.className="irb-score-val "+Qi(i));let p=w("inspect-risk-label");p&&(p.textContent=i<20?"Low Risk":i<45?"Moderate":i<70?"High Risk":"Critical",p.className="irb-score-label "+Qi(i));let m=w("inspect-acct-grid");if(!m)return;let f=Math.max(0,n-s),g=Number(t.Flags||0),v=r!=null?r===0?"Created today":r===1?"1 day old":r<30?`${r} days old`:r<365?`${Math.floor(r/30)} months old`:`${(r/365).toFixed(1)} years old`:"\u2014",h=l?new Date(l).toLocaleDateString("en-US",{year:"numeric",month:"short",day:"numeric"}):null,b=h?c?`Created ${h}`:`Created ${h} (estimated \u2014 full history not confirmed)`:null,x=wn(n),k=wn(f),T=[{label:"XRP Balance",value:`${_(n,6)} XRP${x}`,mono:!0},{label:"Spendable",value:`${_(f,6)} XRP${k}`,mono:!0,note:`${s} XRP reserved`},{label:"Wallet Age",value:v,note:b,highlight:r!=null&&r<7?"new":null},{label:"Owner Count",value:a,note:`${a*2} XRP tied up`},{label:"Sequence",value:o,mono:!0},{label:"Regular Key",value:t.RegularKey?z(t.RegularKey):"None",warn:!!t.RegularKey,mono:!0},{label:"Master Key",value:g&_e.lsfDisableMaster?"Disabled":"Active",warn:!!(g&_e.lsfDisableMaster)}];m.innerHTML=T.map(S=>`
    <div class="acct-cell ${S.warn?"acct-cell--warn":""} ${S.highlight==="new"?"acct-cell--new":""}">
      <div class="acct-cell-label">${y(S.label)}</div>
      <div class="acct-cell-value ${S.mono?"mono":""}">${y(String(S.value))}</div>
      ${S.note?`<div class="acct-cell-note">${y(S.note)}</div>`:""}
      ${S.highlight==="new"?'<div class="acct-cell-new-badge">\u26A0 New wallet</div>':""}
    </div>`).join("")}function Iy(e,t,n,s,a){let o=w("inspect-security-body");if(!o)return;let i=Object.entries(_e).filter(([,u])=>n&u).map(([u])=>u.replace("lsf","")),r=e.controlState,c=r&&{Normal:"#50fa7b","Regular-Key Controlled":"rgba(255,255,255,.7)","Multisig Controlled":"rgba(255,255,255,.7)",Blackholed:"rgba(255,255,255,.7)",Recoverable:"rgba(255,255,255,.7)","Potentially Misconfigured":"#ff5555",Unknown:"#ffb86c"}[r.state]||"rgba(255,255,255,.7)";o.innerHTML=`
    ${r?`
    <div class="drain-level" style="border-color:${c}44;margin-bottom:10px" title="${y(r.reversibility)}">
      <span class="drain-level-icon" style="color:${c}">\u25CF</span>
      <span class="drain-level-text">Account Control State: <strong style="color:${c}">${y(r.state)}</strong></span>
    </div>`:""}
    <div class="audit-items">
      ${e.findings.map(u=>jn(u)).join("")}
    </div>
    ${i.length?`
    <div class="audit-flags">
      <div class="audit-flags-label">Active Flags</div>
      <div class="audit-flags-pills">
        ${i.map(u=>`<span class="flag-pill">${y(u)}</span>`).join("")}
      </div>
    </div>`:""}
    ${s.length?`
    <div class="signer-list-block">
      <div class="signer-list-title">Signer List (Multisig)</div>
      ${s.map(u=>`
        <div class="signer-entries">
          ${(u.SignerEntries||[]).map(d=>{var p,m;return`
            <div class="signer-entry">
              <span class="signer-addr mono">${y(((p=d.SignerEntry)==null?void 0:p.Account)||"\u2014")}</span>
              <span class="signer-weight">weight ${((m=d.SignerEntry)==null?void 0:m.SignerWeight)||1}</span>
            </div>`}).join("")}
          <div class="signer-quorum">Quorum: ${u.SignerQuorum}</div>
        </div>`).join("")}
    </div>`:""}
    ${a.length?`
    <div class="audit-note">
      <span class="audit-note-label">DepositPreauth grants:</span>
      ${a.slice(0,8).map(u=>`<span class="mono">${z(u.Authorize||"")}</span>`).join(", ")}
      ${a.length>8?`+${a.length-8} more`:""}
    </div>`:""}
  `,oo("badge-security",e.findings)}function Fy(e,t,n,s){let a=w("inspect-drain-body");if(!a)return;let o={low:"#50fa7b",medium:"#ffb86c",high:"#ff8c42",critical:"#ff5555",none:"#50fa7b"},i={low:"\u2713",medium:"\u26A0",high:"\u26A0",critical:"\u26D4",none:"\u2713"},r=e.compromiseRiskLevel??e.riskLevel,l=e.assetDrainSeverity??"none";a.innerHTML=`
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
      ${e.signals.map(c=>jn(c)).join("")}
    </div>
    ${t.length?`
    <div class="drain-sub-section">
      <div class="drain-sub-title">Open Payment Channels</div>
      ${t.map(c=>`
        <div class="drain-channel-row">
          <span class="mono">${z(c.Destination)}</span>
          <span>${_(Number(c.Amount||0)/1e6,2)} XRP allocated</span>
          <span>${_(Number(c.Balance||0)/1e6,2)} XRP claimed</span>
        </div>`).join("")}
    </div>`:""}
    ${n.length?`
    <div class="drain-sub-section">
      <div class="drain-sub-title">Open Escrows</div>
      ${n.slice(0,5).map(c=>`
        <div class="drain-channel-row">
          <span>${c.Destination?z(c.Destination):"self"}</span>
          <span>${_(Number(c.Amount||0)/1e6,2)} XRP</span>
          <span class="mono">${c.Condition?"conditional":c.FinishAfter?"time-locked":""}</span>
        </div>`).join("")}
    </div>`:""}
  `,p0("badge-drain",e.riskLevel)}function Oy(e,t){let n=w("inspect-nft-body");n&&(n.innerHTML=`
    <div class="audit-items">
      ${e.flags.map(s=>jn(s)).join("")}
    </div>
    ${t.length?`
    <div class="nft-grid">
      ${t.slice(0,12).map(s=>By(s)).join("")}
    </div>
    ${t.length>12?`<div class="nft-more">+${t.length-12} more NFTs</div>`:""}
    `:""}
  `,oo("badge-nft",e.flags))}function By(e){let t=Number(e.Flags||0),n=!!(t&Cu.lsfTransferable),s=!!(t&Cu.lsfBurnable),a=e.NFTokenTaxon||0,o=e.TransferFee?`${(e.TransferFee/1e3).toFixed(1)}%`:"0%";return`
    <div class="nft-card">
      <div class="nft-id mono">${e.NFTokenID?z(e.NFTokenID):"\u2014"}</div>
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
      ${e.Issuer&&e.Issuer!==e.Account?`<div class="nft-issuer mono">Issuer: ${z(e.Issuer)}</div>`:""}
    </div>`}function Xy(e){let t=w("inspect-wash-body");if(!t)return;let n=e.verdict==="clean"||e.verdict==="low-risk"?"#50fa7b":e.verdict==="suspicious"?"#ffb86c":"#ff5555";t.innerHTML=`
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
      ${Ys("Offer Creates",e.stats.creates)}
      ${Ys("Offer Cancels",e.stats.cancels)}
      ${Ys("Filled Offers",e.stats.fills)}
      ${Ys("Payments",e.stats.payments)}
      ${Ys("Round-trip Counterparties",e.stats.roundTrip)}
    </div>
    <div class="audit-items">
      ${e.signals.map(a=>jn(a)).join("")}
    </div>
  `;let s=w("badge-wash");if(s){let a=e.verdict==="clean"||e.verdict==="low-risk"?"ok":e.verdict==="suspicious"?"warn":"crit";s.textContent=e.verdict.replace("-"," "),s.className="section-badge section-badge--"+a}}function Ys(e,t){return`<div class="wash-stat"><span class="wash-stat-label">${y(e)}</span><span class="wash-stat-val">${t}</span></div>`}function Hy(e,t){let n=w("inspect-issuer-body");if(!n)return;let s=t.filter(a=>a.currency&&(a.currency.length===3||a.currency.length===40));n.innerHTML=`
    <div class="audit-items">
      ${e.signals.map(a=>jn(a)).join("")}
    </div>
    ${s.length?`
    <div class="trustline-list">
      ${s.slice(0,10).map(a=>`
        <div class="trustline-row">
          <span class="trustline-currency">${y(Hn(a.currency))}</span>
          <span class="trustline-issuer mono">${z(a.account)}</span>
          <span class="trustline-balance ${Number(a.balance)<0?"trustline-owed":""} mono">
            ${Number(a.balance)<0?"\u25BC ":""}${_(Math.abs(Number(a.balance)),2)}
            ${a.freeze?'<span class="trustline-frozen">FROZEN</span>':""}
            ${a.freeze_peer?'<span class="trustline-frozen trustline-frozen--peer">FROZEN BY ISSUER</span>':""}
          </span>
        </div>`).join("")}
      ${s.length>10?`<div class="trustline-more">+${s.length-10} more trustlines</div>`:""}
    </div>`:""}
  `,oo("badge-issuer",e.signals)}function zy(e,t){let n=w("inspect-amm-body");n&&(n.innerHTML=`
    <div class="audit-items">
      ${e.signals.map(s=>jn(s)).join("")}
    </div>
    ${e.positions.length?`
    <div class="amm-positions">
      ${e.positions.map(s=>`
        <div class="amm-position-card">
          <div class="amm-position-currency mono">${z(s.currency)}</div>
          <div class="amm-position-meta">
            <span>Pool: ${z(s.issuer)}</span>
            <span class="amm-position-balance">${_(Math.abs(s.balance),4)} LP tokens</span>
          </div>
        </div>`).join("")}
    </div>`:""}
  `,oo("badge-amm",e.signals))}function jy(e){let t=w("trust-count-badge");t&&(t.textContent=e.length);let n=w("inspect-trust-body");n&&(n.innerHTML=e.length?e.map(s=>{let a=s.freeze?'<span class="trustline-frozen">Frozen</span>':"",o=s.freeze_peer?'<span class="trustline-frozen trustline-frozen--peer">Issuer Frozen</span>':"",i=s.no_ripple?'<span class="trustline-norip">NoRipple</span>':"";return`
          <div class="trustline-row">
            <span class="trustline-currency">${y(Hn(s.currency))}</span>
            <span class="trustline-issuer mono">${z(s.account)}</span>
            <span class="trustline-balance mono">${y(s.balance)} / ${y(s.limit)}</span>
            <span class="trustline-flags">${a}${o}${i}</span>
          </div>`}).join(""):'<div class="inspect-empty-note">No trustlines found.</div>')}function Wy(e,t){let n=w("inspect-tx-timeline");if(!n)return;let s=60,a=e.slice(0,s),o=w("badge-tx");if(o){let i=window._inspectMaxTx||5e3,r=e.length>=i;o.textContent=e.length.toLocaleString()+" tx"+(r?" (cap reached)":""),o.className="section-badge section-badge--neutral",r&&(o.title=`Fetched ${e.length.toLocaleString()} transactions \u2014 cap of ${i.toLocaleString()} reached. Set window._inspectMaxTx = 20000 in console to go deeper.`)}n.innerHTML=a.length?a.map(({tx:i,meta:r})=>{let l=i.TransactionType||"Unknown",c=(r==null?void 0:r.TransactionResult)==="tesSUCCESS",u=n0(i,r,t),d=Wn(i),p=d?new Date(d*1e3).toLocaleString():"\u2014",m=s0(i,t),f=i.hash?i.hash.slice(0,8)+"\u2026"+i.hash.slice(-4):"",g=i.hash?`https://livenet.xrpl.org/transactions/${i.hash}`:null,v=i.hash?`https://xrpscan.com/tx/${i.hash}`:null;return`
          <div class="tx-row tx-row--${u}">
            <span class="tx-type-badge tx-type-badge--${a0(l)}">${y(l)}</span>
            <span class="tx-brief">${m}</span>
            <span class="tx-result ${c?"tx-ok":"tx-fail"}">${c?"\u2713":"\u2717"}</span>
            <span class="tx-time">${p}</span>
            ${g?`<span class="tx-links">
              <a href="${g}" target="_blank" rel="noopener" class="tx-explorer-link" title="View on XRPL Livenet">\u{1F517}</a>
              <a href="${v}" target="_blank" rel="noopener" class="tx-explorer-link" title="View on XRPScan">\u{1F50D}</a>
            </span>`:""}
          </div>`}).join(""):'<div class="inspect-empty-note">No transactions found.</div>',e.length>s&&(n.innerHTML+=`<div class="tx-more">Showing ${s} of ${e.length} transactions</div>`)}function Uu(e,t,n){let s=Number((n==null?void 0:n.totalIn)||0),a=Number((t==null?void 0:t.totalOut)||0),o=Number(e||0);if(s<=0&&a<=0)return'<div class="inspect-empty-note">No inbound or outbound XRP flow found in the analysed transaction history.</div>';let i=new Set(((t==null?void 0:t.blackHoleDests)||[]).map(k=>k.addr)),r=new Set(((t==null?void 0:t.exchangeDests)||[]).map(k=>k.addr)),l=new Set(((t==null?void 0:t.newWalletDests)||[]).map(k=>k.addr)),c=0,u=0,d=0,p=0;for(let k of(t==null?void 0:t.destinations)||[])i.has(k.addr)?c+=k.totalXrp:r.has(k.addr)?u+=k.totalXrp:l.has(k.addr)?d+=k.totalXrp:p+=k.totalXrp;let m=Math.max(s,a,o,1),f=k=>(k>0?Math.max(1.5,k/m*100):0).toFixed(1),g=[{label:"Black hole",xrp:c,color:yn.blackhole},{label:"Exchange",xrp:u,color:yn.exchange},{label:"New wallet",xrp:d,color:yn.newWallet},{label:"Other",xrp:p,color:yn.other}].filter(k=>k.xrp>0),v=a>0?Math.max(1.5,a/m*100):0,h=g.map(k=>`<div style="width:${(a>0?k.xrp/a*100:0).toFixed(1)}%;background:${k.color};height:100%" title="${y(k.label)}: ${_(k.xrp,2)} XRP"></div>`).join(""),b=(k,T,S,$,E)=>`
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
      <div style="width:84px;font-size:.72rem;color:rgba(255,255,255,.55);flex-shrink:0">${k}</div>
      <div style="flex:1;height:16px;border-radius:5px;overflow:hidden;background:rgba(255,255,255,.05)">
        <div style="width:${S}%;height:100%;display:flex">${$||`<div style="width:100%;height:100%;background:${E}"></div>`}</div>
      </div>
      <div class="mono" style="width:92px;text-align:right;font-size:.75rem;color:rgba(255,255,255,.75);flex-shrink:0">${_(T,2)} XRP</div>
    </div>`,x=g.map(k=>`<span style="font-size:.66rem;color:${k.color};margin-right:12px">\u25CF ${y(k.label)} ${_(k.xrp,0)}</span>`).join("");return`
    <div style="margin-bottom:16px">
      <div style="font-size:.65rem;color:rgba(255,255,255,.35);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px">
        Fund Flow \u2014 Inbound vs Outbound vs Current Balance
      </div>
      ${b("Total In",s,f(s),null,"#50fa7b")}
      ${b("Total Out",a,v,g.length?h:null,"rgba(255,255,255,.3)")}
      ${b("Balance Now",o,f(o),null,"#00d4ff")}
      ${g.length?`<div style="margin-top:2px">${x}</div>`:""}
    </div>`}function Uy(e,t,n){var l;let s=w("inspect-fundflow-body");if(!s)return;let a=w("badge-fundflow");if(!e.timeline.length&&!e.destinations.length){s.innerHTML='<div class="audit-row audit-row--ok"><span class="audit-icon">\u2713</span><div class="audit-text"><div class="audit-label">No outbound payments found in analysed transaction history</div></div></div>',a&&(a.textContent="Clear",a.className="section-badge section-badge--ok");return}let o=e.exchangeDests.length?`<div class="flow-alert flow-alert--exchange">\u{1F4B1} Funds reached ${e.exchangeDests.length} known exchange(s): ${e.exchangeDests.map(c=>c.entity.name).join(", ")}</div>`:"",i=e.blackHoleDests.length?'<div class="flow-alert flow-alert--blackhole">\u{1F573} Funds sent to black hole address \u2014 irrecoverable!</div>':"",r=(l=e.newWalletDests)!=null&&l.length?`<div class="flow-alert" style="background:rgba(255,85,85,.06);border:1px solid rgba(255,85,85,.25);color:#ff5555;border-radius:8px;padding:10px 14px;margin-bottom:8px">
        \u26A0\uFE0F <strong>${e.newWalletDests.length} destination(s) are brand-new wallets</strong> (Sequence &lt; 10) receiving large XRP amounts.
        New wallets receiving large transfers shortly after creation are a common pattern in drain attacks \u2014 the attacker creates a disposable wallet and drains funds there.
       </div>`:"";if(s.innerHTML=`
    ${Uu(t,e,n)}
    ${r}${o}${i}
    <div class="flow-summary">
      <div class="flow-stat"><span>Unique destinations</span><b>${e.uniqueDests}</b></div>
      <div class="flow-stat"><span>Path payments</span><b>${e.totalPathPay}</b></div>
      <div class="flow-stat"><span>Exchange dests</span><b>${e.exchangeDests.length}</b></div>
    </div>

    <div class="flow-section-h">\u{1F4CD} Top Destinations</div>
    <div class="flow-dest-list">
      ${e.destinations.map((c,u)=>{var g,v,h,b;let d=e.totalOut>0?c.totalXrp/e.totalOut*100:0,p=c.entity?`<span class="flow-entity-badge flow-entity--${c.entity.type}">${y(c.entity.name)}</span>`:"",m=c.pathCount>0?`<span class="flow-path-badge">${c.maxHops}-hop path \xD7${c.pathCount}</span>`:"",f=c.tokens.slice(0,2).map(x=>`<span class="flow-token-chip">${y(x.k.split(".")[0])}</span>`).join("");return`
          <div class="flow-dest-row">
            <div class="flow-dest-rank ${((g=c.entity)==null?void 0:g.type)==="exchange"?"flow-rank--exchange":((v=c.entity)==null?void 0:v.type)==="blackhole"?"flow-rank--blackhole":""}">${u+1}</div>
            <div class="flow-dest-info">
              <div class="flow-dest-top">
                <button class="addr-link mono cut flow-dest-addr" data-addr="${y(c.addr)}" title="${y(c.addr)}">${y(z(c.addr))}</button>
                <a href="https://xrpscan.com/account/${y(c.addr)}" target="_blank" rel="noopener" class="tx-explorer-link" title="View on XRPScan">\u{1F50D}</a>
                ${p}${m}${f}
              </div>
              <div class="flow-bar-row">
                <div class="flow-dest-bar"><div class="flow-dest-fill" style="width:${Math.min(100,d).toFixed(1)}%;background:${((h=c.entity)==null?void 0:h.type)==="exchange"?"#00d4ff":((b=c.entity)==null?void 0:b.type)==="blackhole"?"#ff5555":"rgba(80,250,123,.7)"}"></div></div>
                <span class="mono flow-dest-pct">${d.toFixed(0)}%</span>
              </div>
              <div class="flow-dest-meta">
                <span class="mono">${_(c.totalXrp,2)} XRP</span>
                <span class="flow-dest-cnt">${c.txCount} tx</span>
                ${c.txCount>1?`<span class="flow-dest-span">${qu(c.firstSeen,c.lastSeen)}</span>`:""}
              </div>
            </div>
          </div>`}).join("")}
    </div>

    <div class="flow-section-h" style="margin-top:18px">\u23F1 Outflow Timeline</div>
    <div class="flow-timeline">
      ${e.timeline.map(c=>{let u=new Date(c.ts*1e3).toLocaleDateString(),d=new Date(c.ts*1e3).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"}),p=c.amtXrp>0?`${_(c.amtXrp,2)} XRP`:c.amtToken?`${_(c.amtToken.value,2)} ${c.amtToken.currency}`:"\u2014",m=zn(c.dest),f=m?`<span class="flow-entity-badge flow-entity--${m.type}" style="font-size:.65rem">${y(m.name)}</span>`:"";return`
          <div class="flow-tx-row">
            <span class="flow-tx-date">${u} ${d}</span>
            <button class="addr-link mono cut flow-tx-dest" data-addr="${y(c.dest)}" title="${y(c.dest)}">${y(z(c.dest))}</button>
            ${f}
            <span class="flow-tx-amt mono">${p}</span>
            ${c.isPathPay?`<span class="flow-path-tag">${c.hopCount}-hop</span>`:""}
          </div>`}).join("")}
    </div>
  `,a){let c=e.blackHoleDests.length||e.exchangeDests.length>2;a.textContent=`${e.uniqueDests} dests`,a.className=`section-badge section-badge--${c?"crit":e.uniqueDests>0?"warn":"ok"}`}}function qu(e,t){if(!e||!t)return"";let n=new Date(e*1e3).toLocaleDateString(),s=new Date(t*1e3).toLocaleDateString();return n===s?n:`${n} \u2013 ${s}`}function qy(e,t){let n=w("inspect-issuer-connections-body");if(!n)return;let s=e.totalIssued,a=w("badge-issuer-connections");if(n.innerHTML=`
    <div class="audit-items">
      ${e.signals.map(o=>jn(o)).join("")}
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
            <button class="addr-link mono cut conn-holder-addr" data-addr="${y(o.addr)}" title="${y(o.addr)}">${y(z(o.addr))}</button>
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
        <button class="addr-chip mono" data-addr="${y(o)}" title="${y(o)}">${y(z(o))}</button>
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
              <button class="addr-chip mono" data-addr="${y(i.addr)}" title="${y(i.addr)}">${y(z(i.addr))}</button>
            `).join("")}
            ${o.accounts.length>8?`<span class="conn-mirror-more">+${o.accounts.length-8} more</span>`:""}
          </div>
        </div>
      `).join("")}
    </div>`:""}
  `,a){let o=e.signals.some(i=>i.sev==="critical")?"crit":e.signals.some(i=>i.sev==="warn")?"warn":e.signals.some(i=>i.sev==="info")?"neutral":"ok";a.className=`section-badge section-badge--${o}`,a.textContent=s>0?`${e.holderCount} holders`:"No issuance"}}function Vy(e){var c;let t=document.getElementById("inspect-fee-analysis-body");if(!t||!e)return;let n=(e.signals||[]).map(Dt).join(""),s=e.avgFeeMultiplier!=null?`
    <div class="wash-stat-row" style="margin-top:10px">
      <span>Average fee multiplier</span><span class="mono">${e.avgFeeMultiplier}x base (12 drops)</span>
    </div>
    <div class="wash-stat-row">
      <span>High-fee transactions (>100x)</span><span class="mono ${e.spikeCount>5?"risk-text-high":""}">${e.spikeCount}</span>
    </div>`:"",a=(c=e.topFeeHashes)!=null&&c.length?`
    <div style="margin-top:12px;font-size:.72rem;color:rgba(255,255,255,.4);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">TOP FEE TRANSACTIONS</div>
    ${e.topFeeHashes.map(u=>`
      <div class="wash-stat-row">
        <a href="https://livenet.xrpl.org/transactions/${y(u.hash)}" target="_blank" rel="noopener"
           class="mono" style="font-size:.75rem;color:var(--accent);text-decoration:none">${z(u.hash)}</a>
        <span class="mono" style="color:#ffb86c">${u.mult}x base fee</span>
      </div>`).join("")}`:"",o=document.getElementById("section-fee-analysis"),i=(e.signals||[]).some(u=>u.sev==="warn"||u.sev==="critical");o&&(o.style.display="");let r=i?"":`
    <div class="finding finding--ok">
      <span class="finding-sev sev-ok">OK</span>
      <div class="finding-body">
        <div class="finding-label">No elevated fees detected</div>
        <div class="finding-detail">Transaction fees across this account's history are within normal ranges.</div>
      </div>
    </div>`;t.innerHTML=r+n+s+a;let l=document.getElementById("badge-fee-analysis");l&&(l.textContent=i?"Elevated":"Normal",l.className=`section-badge section-badge--${i?"warn":"ok"}`)}function Gy(e){var c,u;let t=document.getElementById("inspect-desttag-body");if(!t||!e)return;let n=(e.signals||[]).map(Dt).join(""),s=(c=e.tagProfiles)!=null&&c.length?`
    <div style="margin-top:12px;font-size:.72rem;color:rgba(255,255,255,.4);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">DESTINATION TAG SUMMARY</div>
    ${e.tagProfiles.slice(0,8).map(d=>`
      <div class="wash-stat-row">
        <span>${y(d.name)}</span>
        <span class="mono" style="opacity:.65">${d.txCount} tx \xB7 ${d.uniqueTags} unique tag${d.uniqueTags!==1?"s":""}</span>
      </div>`).join("")}`:"",a=document.getElementById("section-desttag"),o=(e.signals||[]).some(d=>d.sev==="warn"||d.sev==="critical"),i=((u=e.tagProfiles)==null?void 0:u.length)>0;a&&(a.style.display="");let r=!o&&!i?`
    <div class="finding finding--ok">
      <span class="finding-sev sev-ok">OK</span>
      <div class="finding-body">
        <div class="finding-label">No destination tag patterns to report</div>
        <div class="finding-detail">No exchange payments with destination tags were found in this account's history.</div>
      </div>
    </div>`:"";t.innerHTML=r+n+s;let l=document.getElementById("badge-desttag");l&&(l.textContent=o?"Check":"Normal",l.className=`section-badge section-badge--${o?"warn":"ok"}`)}function Ky(e){var i;let t=document.getElementById("section-pathdepth"),n=document.getElementById("inspect-pathdepth-body"),s=document.getElementById("badge-pathdepth");if(t&&(t.style.display=""),!n)return;if(!e||e.noData||!((i=e.signals)!=null&&i.length)){n.innerHTML='<div class="inspect-empty-note">No path payments found.</div>',s&&(s.textContent="None",s.className="section-badge section-badge--neutral");return}let a=e.signals.map(Dt).join(""),o=`
    <div class="wash-stat-row" style="margin-top:10px">
      <span>Total path payments</span><span class="mono">${e.roundTripCount+e.deepHopCount+(e.selfRoutedCount||0)+(e.signals.filter(r=>r.sev==="ok").length>0?1:0)}</span>
    </div>
    ${e.roundTripCount?`<div class="wash-stat-row"><span>XRP\u2192IOU\u2192XRP round-trips</span><span class="mono ${e.roundTripCount>=3?"risk-text-high":"risk-text-med"}">${e.roundTripCount}</span></div>`:""}
    ${e.deepHopCount?`<div class="wash-stat-row"><span>Deep hop chains (\u22653 hops)</span><span class="mono">${e.deepHopCount}</span></div>`:""}
    ${e.selfRoutedCount?`<div class="wash-stat-row"><span>Self-routed payments</span><span class="mono risk-text-high">${e.selfRoutedCount}</span></div>`:""}`;if(n.innerHTML=a+o,s){let r=e.signals.some(c=>c.sev==="critical"),l=e.signals.some(c=>c.sev==="warn");s.textContent=r?"Critical":l?"Check":"Normal",s.className=`section-badge section-badge--${r?"crit":l?"warn":"ok"}`}}function Jy(e){var i,r,l;let t=w("inspect-inbound-body");if(!t)return;let n=(e.signals||[]).map(Dt).join(""),s=`
    <div class="flow-summary" style="margin-top:10px">
      <div class="flow-stat"><span>Inbound payments</span><b>${((i=e.timeline)==null?void 0:i.length)||0}</b></div>
      <div class="flow-stat"><span>Unique sources</span><b>${e.uniqueSources}</b></div>
      <div class="flow-stat"><span>Total XRP received</span><b class="mono">${_(e.totalIn,2)}</b></div>
      <div class="flow-stat"><span>Exchange sources</span><b>${((r=e.exchangeSrcs)==null?void 0:r.length)||0}</b></div>
    </div>`,a=(l=e.topSources)!=null&&l.length?`
    <div class="flow-section-h" style="margin-top:14px">\u{1F4E5} Top Funding Sources</div>
    <div class="flow-dest-list">
      ${e.topSources.map((c,u)=>{let d=e.totalIn>0?(c.totalXrp/e.totalIn*100).toFixed(0):0,p=c.entity,m=p?`<span class="flow-entity-badge flow-entity--${p.type}">${y(p.name)}</span>`:"";return`<div class="flow-dest-row">
          <div class="flow-dest-rank">${u+1}</div>
          <div class="flow-dest-info">
            <div class="flow-dest-top">
              <a href="https://xrpscan.com/account/${y(c.addr)}" target="_blank" rel="noopener" class="addr-link mono cut">${y(z(c.addr))}</a>
              ${m}
            </div>
            <div class="flow-bar-row">
              <div class="flow-dest-bar"><div class="flow-dest-fill" style="width:${Math.min(100,d)}%;background:${(p==null?void 0:p.type)==="exchange"?"#00d4ff":"rgba(80,250,123,.7)"}"></div></div>
              <span class="mono flow-dest-pct">${d}%</span>
            </div>
            <div class="flow-dest-meta">
              <span class="mono">${_(c.totalXrp,2)} XRP${wn(c.totalXrp)}</span>
              <span class="flow-dest-cnt">${c.txCount} tx</span>
            </div>
          </div>
        </div>`}).join("")}
    </div>`:"";t.innerHTML=n+s+a;let o=w("badge-inbound");if(o){let c=(e.signals||[]).some(u=>u.sev==="warn"||u.sev==="critical");o.textContent=`${e.uniqueSources} src${e.uniqueSources!==1?"s":""}`,o.className=`section-badge section-badge--${c?"warn":"neutral"}`}}function Yy(e){var i;let t=w("section-memos"),n=w("inspect-memos-body");if(t&&(t.style.display=""),!n)return;if(!e||!((i=e.allMemos)!=null&&i.length)){n.innerHTML='<div class="inspect-empty-note">No memos found.</div>';let r=w("badge-memos");r&&(r.textContent="None",r.className="section-badge section-badge--neutral");return}let s=(e.signals||[]).map(Dt).join(""),a=e.allMemos.slice(0,10).map(r=>`
    <div class="wash-stat-row" style="flex-direction:column;align-items:flex-start;gap:2px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.05)">
      <div style="font-size:.72rem;color:rgba(255,255,255,.35)">${y(r.type)} \xB7 <a href="https://livenet.xrpl.org/transactions/${y(r.tx)}" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none">${z(r.tx)}</a></div>
      <div style="font-size:.82rem;word-break:break-all;color:rgba(255,255,255,.75)">${y(r.text.slice(0,120))}${r.text.length>120?"\u2026":""}</div>
    </div>`).join("");n.innerHTML=s+`<div style="margin-top:10px;font-size:.72rem;color:rgba(255,255,255,.4);text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px">MEMO CONTENTS (${e.allMemos.length} found)</div>`+a;let o=w("badge-memos");if(o){let r=(e.signals||[]).some(c=>c.sev==="critical"),l=(e.signals||[]).some(c=>c.sev==="warn");o.textContent=r?"Scam text":l?"Patterns":"Normal",o.className=`section-badge section-badge--${r?"crit":l?"warn":"ok"}`}}function Qy(e){var r;let t=w("section-escrow-depth"),n=w("inspect-escrow-depth-body");if(t&&(t.style.display=""),!n)return;if(!e||!((r=e.escrows)!=null&&r.length)){n.innerHTML='<div class="inspect-empty-note">No escrows found.</div>';let l=w("badge-escrow-depth");l&&(l.textContent="None",l.className="section-badge section-badge--neutral");return}let s=(e.signals||[]).map(Dt).join(""),a=946684800,o=e.escrows.map(l=>`
    <div class="wash-stat-row">
      <span>${l.isSelfEscrow?"Self-escrow":l.isThirdParty?'<span style="color:#ff5555">Third-party \u2192</span>':z(l.dest||"")}</span>
      <span class="mono">${_(l.amtXrp,2)} XRP${wn(l.amtXrp)}</span>
      <span style="font-size:.72rem;opacity:.55">${l.daysToFinish!=null?l.daysToFinish<0?"matured":l.daysToFinish+"d":l.conditional?"conditional":"\u2014"}</span>
    </div>`).join("");n.innerHTML=s+`<div style="margin-top:10px">${o}</div>`;let i=w("badge-escrow-depth");if(i){let l=e.hasThirdParty;i.textContent=`${e.escrows.length} escrow${e.escrows.length!==1?"s":""}`,i.className=`section-badge section-badge--${l?"warn":"neutral"}`}}function Zy(e){var i;let t=w("section-checks"),n=w("inspect-checks-body");if(t&&(t.style.display=""),!n)return;if(!e||!((i=e.checks)!=null&&i.length)){n.innerHTML='<div class="inspect-empty-note">No open Checks found.</div>';let r=w("badge-checks");r&&(r.textContent="None",r.className="section-badge section-badge--neutral");return}let s=(e.signals||[]).map(Dt).join(""),a=e.checks.map(r=>{var l,c;return`
    <div class="wash-stat-row">
      <span class="mono">${z(r.sender)} \u2192 ${z(r.dest||"")}</span>
      <span class="mono">${r.amtXrp!=null?_(r.amtXrp,2)+" XRP"+wn(r.amtXrp):(((l=r.amtToken)==null?void 0:l.value)||"?")+" "+((c=r.amtToken)==null?void 0:c.currency)}</span>
      <span style="font-size:.72rem;${r.expired?"color:#ff5555":"opacity:.55"}">${r.expired?"Expired":"Open"}</span>
    </div>`}).join("");n.innerHTML=s+`<div style="margin-top:10px">${a}</div>`;let o=w("badge-checks");o&&(o.textContent=`${e.checks.length} check${e.checks.length!==1?"s":""}`,o.className="section-badge section-badge--neutral")}function e0(e){let t=w("section-livebook"),n=w("inspect-livebook-body");if(t&&(t.style.display=""),!n)return;if(!(e!=null&&e.hasData)){n.innerHTML='<div class="inspect-empty-note">No live order book activity found for this wallet.</div>';let i=w("badge-livebook");i&&(i.textContent="None",i.className="section-badge section-badge--neutral");return}let s=(e.signals||[]).map(Dt).join(""),a=`
    <div class="wash-stat-row" style="margin-top:10px">
      <span>Pair</span><span class="mono">${y(e.pair.split("\u2194").map(i=>i.split("+")[0]).join(" \u2194 "))}</span>
    </div>
    <div class="wash-stat-row">
      <span>Live orders in book</span><span class="mono">${e.offerCount}</span>
    </div>
    ${e.ourShare>0?`<div class="wash-stat-row"><span>This wallet's book share</span><span class="mono ${e.ourShare>.25?"risk-text-high":""}">${(e.ourShare*100).toFixed(1)}%</span></div>`:""}
    ${e.wallShare>.3?`<div class="wash-stat-row"><span>Largest single order share</span><span class="mono ${e.wallShare>.4?"risk-text-high":"risk-text-med"}">${(e.wallShare*100).toFixed(1)}%</span></div>`:""}`;n.innerHTML=s+a;let o=w("badge-livebook");if(o){let i=(e.signals||[]).some(l=>l.sev==="critical"),r=(e.signals||[]).some(l=>l.sev==="warn");o.textContent=i?"Wall order":r?"Check":"Normal",o.className=`section-badge section-badge--${i?"crit":r?"warn":"ok"}`}}function t0(e,...t){let n=w("inspect-risk-breakdown");if(!n)return;let s=ky(e,...t);if(!s.length){n.innerHTML="";return}let a=Math.max(1,s.reduce((o,i)=>o+i.pts,0));n.innerHTML=`
    <div style="margin-top:8px">
      <div style="font-size:.65rem;color:rgba(255,255,255,.35);text-transform:uppercase;letter-spacing:.1em;margin-bottom:5px">Score Breakdown</div>
      <div style="display:flex;height:8px;border-radius:4px;overflow:hidden;gap:1px">
        ${s.map(o=>`<div style="flex:${o.pts};background:${o.color};opacity:.85" title="${y(o.label)}: ${o.pts} pts"></div>`).join("")}
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px">
        ${s.map(o=>`<span style="font-size:.67rem;color:${o.color};opacity:.8">${o.icon} ${y(o.label)} ${o.pts}pts</span>`).join("")}
      </div>
    </div>`}function jn({sev:e,label:t,detail:n,confidence:s,observed:a,alternativeExplanations:o,evidenceAgainstBenign:i,classification:r}){let l={ok:"\u2713",info:"\u2139",warn:"\u26A0",critical:"\u26D4"},c=(u,d)=>d&&d.length?`<div class="audit-evidence-group">
         <div class="audit-evidence-title">${y(u)}</div>
         <ul class="audit-evidence-list">${d.map(p=>`<li>${y(p)}</li>`).join("")}</ul>
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
    </div>`}function Dt(e){let t={critical:"sev-critical",warn:"sev-warn",info:"sev-info",ok:"sev-ok"},n=(s,a)=>a&&a.length?`<div class="audit-evidence-group">
         <div class="audit-evidence-title">${y(s)}</div>
         <ul class="audit-evidence-list">${a.map(o=>`<li>${y(o)}</li>`).join("")}</ul>
       </div>`:"";return`
    <div class="finding finding--${e.sev}">
      <span class="finding-sev ${t[e.sev]||""}">${(e.sev||"").toUpperCase()}</span>
      <div class="finding-body">
        <div class="finding-label">${y(e.label)}${e.confidence!=null?` <span class="audit-confidence">confidence ${Math.round(e.confidence*100)}%</span>`:""}</div>
        ${e.detail?`<div class="finding-detail">${y(e.detail)}</div>`:""}
        ${n("Observed",e.observed)}
        ${n("Alternative explanations",e.alternativeExplanations)}
        ${n("Evidence against benign explanation",e.evidenceAgainstBenign)}
        ${e.classification?`<div class="audit-classification">${y(e.classification)}</div>`:""}
      </div>
    </div>`}function Qi(e){return e<20?"risk-ok":e<45?"risk-medium":e<70?"risk-high":"risk-critical"}function n0(e,t,n){if($v.has(e.TransactionType))return"warn";if(e.TransactionType==="NFTokenCreateOffer"){let s=e.Amount;if(!s||typeof s=="string"&&Number(s)<1e6)return"critical"}return t!=null&&t.TransactionResult&&t.TransactionResult!=="tesSUCCESS"?"fail":"normal"}function s0(e,t){var s,a,o,i,r;let n=e.TransactionType;if(n==="Payment"){let l=e.Account===t?`\u2192 ${z(e.Destination)}`:`\u2190 ${z(e.Account)}`,c=typeof e.Amount=="string"?`${_(Number(e.Amount)/1e6,2)} XRP`:(s=e.Amount)!=null&&s.value?`${_(Number(e.Amount.value),2)} ${e.Amount.currency}`:"";return y(`${c} ${l}`)}if(n==="OfferCreate"){let l=typeof e.TakerPays=="string"?`${_(Number(e.TakerPays)/1e6,2)} XRP`:`${_(Number((a=e.TakerPays)==null?void 0:a.value),2)} ${(o=e.TakerPays)==null?void 0:o.currency}`,c=typeof e.TakerGets=="string"?`${_(Number(e.TakerGets)/1e6,2)} XRP`:`${_(Number((i=e.TakerGets)==null?void 0:i.value),2)} ${(r=e.TakerGets)==null?void 0:r.currency}`;return y(`${l} for ${c}`)}return n==="SetRegularKey"?y(`Key: ${e.RegularKey?z(e.RegularKey):"REMOVED"}`):n==="NFTokenMint"?y(`Taxon: ${e.NFTokenTaxon??"\u2014"}`):n==="NFTokenBurn"?y(`Token: ${e.NFTokenID?z(e.NFTokenID):"\u2014"}`):n==="AMMDeposit"?y("Pool deposit"):n==="AMMWithdraw"?y("LP withdrawal"):n==="EscrowCreate"?y(`${_(Number(e.Amount||0)/1e6,2)} XRP \u2192 ${z(e.Destination)}`):""}function a0(e){return{Payment:"payment",OfferCreate:"offer",OfferCancel:"offer",NFTokenMint:"nft",NFTokenBurn:"nft",NFTokenCreateOffer:"nft",NFTokenAcceptOffer:"nft",SetRegularKey:"auth",SignerListSet:"auth",AccountSet:"auth",AccountDelete:"auth",TrustSet:"trust",AMMCreate:"amm",AMMDeposit:"amm",AMMWithdraw:"amm",AMMVote:"amm",AMMBid:"amm",EscrowCreate:"escrow",EscrowFinish:"escrow",EscrowCancel:"escrow",PaymentChannelCreate:"channel",PaymentChannelFund:"channel",PaymentChannelClaim:"channel"}[e]||"other"}function Wn(e){let t=(e==null?void 0:e.date)||(e==null?void 0:e.close_time)||(e==null?void 0:e.ledger_close_time);return t?Number(t)+Eu:0}function Hn(e){if(!e||e.length!==40)return e||"";try{let t="";for(let n=0;n<e.length;n+=2){let s=parseInt(e.slice(n,n+2),16);if(s!==0){if(s<32||s>126)return e;t+=String.fromCharCode(s)}}return t||e}catch{return e}}function o0(e,t,n,s,a,o,i,r,l,c,u,d,p,m,f,g,v,h,b,x={}){var be,Ue,ft,sn,pa,Sr,Tr,Cr,Pr,Mr,Lr,Ar,Er;let{feeAnalysis:k=null,destTagAnalysis:T=null,pathDepthAnalysis:S=null,gatewayBalances:$=null,inboundFlowAnalysis:E=null,memoAnalysis:C=null,escrowDepthAnalysis:P=null,checkAnalysis:R=null,liveBookAnalysis:O=null,walletAgeDays:D=null,walletCreatedTs:I=null,walletAgeVerified:F=!1,historyCoverage:H=null}=x,N=946684800,j=new Date().toLocaleString(),se=e.slice(0,10)+"\u2026"+e.slice(-8),re=s<20?"LOW":s<45?"MODERATE":s<70?"HIGH":"CRITICAL",pe=s<20?"#50fa7b":s<45?"#ffb86c":s<70?"#ff8c42":"#ff5555",ae=f.filter(({tx:A})=>A.date!=null),te=f.length.toLocaleString()+" transactions",de="",le=0;if(ae.length>=2){let A=ae[0].tx.date+N,Le=ae[ae.length-1].tx.date+N;le=Math.round((Le-A)/86400);let an=new Date(A*1e3).toLocaleDateString("en-US",{year:"numeric",month:"short",day:"numeric"}),rt=new Date(Le*1e3).toLocaleDateString("en-US",{year:"numeric",month:"short",day:"numeric"});de=`${an} \u2013 ${rt} (${le} days)`,te=`${f.length.toLocaleString()} transactions from ${de}`}let Pe=[],B=(A,Le,an,rt,Kn,ht={})=>Pe.push({module:A,sev:Le,headline:an,detail:rt||"",hashes:Kn||[],category:ht.category??null,confidence:ht.confidence??null,observed:ht.observed??[],alternativeExplanations:ht.alternativeExplanations??[],evidenceAgainstBenign:ht.evidenceAgainstBenign??[],classification:ht.classification??null});for(let A of a.findings||[])B("Security",A.sev,A.label,A.detail,A.hashes,A);B("Drain Risk",o.riskLevel==="low"?"ok":o.riskLevel==="medium"?"warn":"critical","Drain Risk Level: "+o.riskLevel.toUpperCase(),null);for(let A of o.signals||[])A.sev!=="ok"&&B("Drain Risk",A.sev,A.label,A.detail,A.hashes,A);for(let A of i.flags||[])A.sev!=="ok"&&B("NFT",A.sev,A.label,A.detail,A.hashes,A);r.verdict&&!["clean","low-risk"].includes(r.verdict)&&B("Wash Trading",r.score>=60?"critical":"warn",`Wash score ${r.score}/100 \u2014 ${r.verdict.replace("-"," ")}`,null);for(let A of r.signals||[])A.sev!=="ok"&&B("Wash Trading",A.sev,A.label,A.detail,A.hashes,A);for(let A of l.signals||[])A.sev!=="ok"&&B("Benford's Law",A.sev,A.label,A.detail,A.hashes,A);for(let A of c.signals||[])A.sev!=="ok"&&B("Volume Concentration",A.sev,A.label,A.detail,A.hashes,A);for(let A of(g==null?void 0:g.signals)||[])A.sev!=="ok"&&B("Shannon's Entropy",A.sev,A.label,A.detail,A.hashes,A);for(let A of(v==null?void 0:v.signals)||[])A.sev!=="ok"&&B("Zipf's Law",A.sev,A.label,A.detail,A.hashes,A);for(let A of(h==null?void 0:h.signals)||[])A.sev!=="ok"&&B("Time Series",A.sev,A.label,A.detail,A.hashes,A);for(let A of(b==null?void 0:b.signals)||[])A.sev!=="ok"&&B("Offer/Flow Coupling",A.sev,A.label,A.detail,A.hashes,A);for(let A of u.signals||[])A.sev!=="ok"&&B("Token Issuer",A.sev,A.label,A.detail,A.hashes,A);for(let A of d.signals||[])A.sev!=="ok"&&B("AMM",A.sev,A.label,A.detail,A.hashes,A);(be=p.blackHoleDests)!=null&&be.length&&B("Fund Flow","critical",`Funds sent to ${p.blackHoleDests.length} black hole address(es)`,"These funds are permanently irrecoverable."),(Ue=p.exchangeDests)!=null&&Ue.length&&B("Fund Flow","warn",`${p.exchangeDests.length} known exchange(s) received funds`,p.exchangeDests.map(A=>A.entity.name).join(", ")),(ft=p.newWalletDests)!=null&&ft.length&&B("Fund Flow","critical",`${p.newWalletDests.length} brand-new wallet(s) received large XRP transfers`,"New wallets (Sequence < 10) receiving large amounts are a classic drain-mule pattern.");for(let A of m.signals||[])A.sev!=="ok"&&B("Issuer Connections",A.sev,A.label,A.detail,A.hashes,A);for(let A of(k==null?void 0:k.signals)||[])A.sev!=="ok"&&B("Fee Spikes",A.sev,A.label,A.detail,A.hashes,A);for(let A of(T==null?void 0:T.signals)||[])A.sev!=="ok"&&B("Destination Tags",A.sev,A.label,A.detail,A.hashes,A);for(let A of(S==null?void 0:S.signals)||[])A.sev!=="ok"&&B("Path Payments",A.sev,A.label,A.detail,A.hashes,A);for(let A of(E==null?void 0:E.signals)||[])A.sev!=="ok"&&B("Inbound Flow",A.sev,A.label,A.detail,A.hashes,A);for(let A of(C==null?void 0:C.signals)||[])A.sev!=="ok"&&B("Memo Analysis",A.sev,A.label,A.detail,A.hashes,A);for(let A of(P==null?void 0:P.signals)||[])A.sev!=="ok"&&B("Escrow Depth",A.sev,A.label,A.detail,A.hashes,A);for(let A of(O==null?void 0:O.signals)||[])A.sev!=="ok"&&B("Live Order Book",A.sev,A.label,A.detail,A.hashes,A);let q=Pe.filter(A=>A.sev==="critical"),J=Pe.filter(A=>A.sev==="warn");window._lastAllFindings=Pe,window._lastCategoryRisk=Cy(Pe);let ue=A=>{let Le={critical:"background:rgba(255,85,85,.15);border:1px solid rgba(255,85,85,.35);color:#ff5555",warn:"background:rgba(255,184,108,.10);border:1px solid rgba(255,184,108,.30);color:#ffb86c",info:"background:rgba(120,180,255,.08);border:1px solid rgba(120,180,255,.18);color:rgba(120,180,255,.9)",ok:"background:rgba(80,250,123,.08);border:1px solid rgba(80,250,123,.22);color:#50fa7b"};return`<span style="padding:2px 8px;border-radius:999px;font-size:.68rem;font-weight:900;letter-spacing:.3px;text-transform:uppercase;${Le[A]||Le.info}">${A.toUpperCase()}</span>`};function ke(){var rt,Kn,ht,Sn,Nr,Rr,_r,Dr,Ir,Fr,Or,Br;let A=[];A.push(`<strong>Address ${se}</strong> was inspected on ${j}. The account holds <strong>${_(n,4)} XRP</strong>. This report analyzed <strong>${te}</strong>, plus all open on-chain objects (escrows, payment channels, trustlines, NFTs, AMM positions). The overall risk score is <strong style="color:${pe}">${s}/100 \u2014 ${re}</strong>. <em style="opacity:.7">Risk scores reflect statistical patterns \u2014 not legal proof. A high score means unusual patterns were detected. Always verify before drawing conclusions.</em>`),q.length&&A.push(`\u26A0\uFE0F The scan found <strong>${q.length} critical issue${q.length>1?"s":""}</strong> and <strong>${J.length} warning${J.length!==1?"s":""}</strong> \u2014 explained in plain English below.`);{let Ae=o.riskLevel==="critical"||o.riskLevel==="high",gt=((rt=p.newWalletDests)==null?void 0:rt.length)>0,ua=((Kn=p.blackHoleDests)==null?void 0:Kn.length)>0,ma=r.score>=60,vo=(k==null?void 0:k.verdict)==="elevated",yo=[l.verdict==="high-deviation",(g==null?void 0:g.verdict)==="anomalous",(v==null?void 0:v.verdict)==="anomalous"||(v==null?void 0:v.verdict)==="elevated",(h==null?void 0:h.verdict)==="elevated",(b==null?void 0:b.verdict)==="strong-coupling"].filter(Boolean).length>=2,Tn=null;if(Ae&&gt)Tn="The key change and the transfers to freshly-created wallets aren't separate concerns \u2014 together they're the specific sequence a drain follows: take control of signing, then move funds somewhere that isn't the attacker's known address.";else if(Ae&&ua)Tn="A compromised-looking key change followed by funds reaching an address nobody controls is consistent with a drain where the funds are gone rather than just moved.";else if(ma&&vo)Tn="The order-cancellation pattern and the fee spikes reinforce each other: overpaying fees to guarantee same-ledger execution is how the cancel-before-fill pattern gets coordinated with a counterparty.";else if(ma&&yo)Tn="This isn't just one statistical test disagreeing with the others \u2014 the wash-trading signal from actual order behavior and the independent mathematical tests are pointing at the same conclusion from two different directions.";else if(q.length+J.length>=3){let wo=[...new Set(q.concat(J).map(Dm=>Dm.module))];Tn=`${wo.length} different analysis categories flagged this account (${wo.slice(0,4).join(", ")}${wo.length>4?", \u2026":""}) \u2014 any one alone could be circumstantial, but that many independent methods agreeing is the stronger signal here.`}Tn&&A.push(`<strong>\u{1F9E9} How these findings fit together:</strong> ${Tn}`)}if(o.riskLevel==="critical"?A.push(`<span style="color:#ff5555"><strong>\u{1F6A8} WALLET DRAIN RISK \u2014 CRITICAL</strong></span><br><strong>What was found:</strong> The account's security structure matches a known attack pattern \u2014 the master signing key has been disabled and replaced with a different key.<br><strong>What it means in plain English:</strong> If you did not personally do this, your wallet may have been taken over. An attacker who controls the replacement key can drain every XRP and token from the account.<br><strong>What to do right now:</strong> Stop sending any funds to this address. If it's your wallet, contact a security professional immediately.`):o.riskLevel==="high"&&A.push("<strong>\u26A0\uFE0F Elevated Drain Risk:</strong> Unusual security patterns found \u2014 possibly a key change followed by large outflows. See the Drain Risk section for exact transactions."),(ht=p.newWalletDests)!=null&&ht.length&&A.push(`<strong>\u{1F195} Brand-New Receiving Wallets:</strong> ${p.newWalletDests.length} of the top destinations are freshly-created wallets (fewer than 10 lifetime transactions) that received significant XRP. Creating a new disposable wallet to receive drained funds \u2014 then disappearing \u2014 is the most common drain attack pattern on XRPL.`),(Sn=p.blackHoleDests)!=null&&Sn.length&&A.push('<span style="color:#ff5555"><strong>\u{1F573} Funds Sent to Uncontrolled Address:</strong></span> Some XRP reached a "black hole" \u2014 an address nobody controls. <strong>These funds cannot be recovered by anyone.</strong>'),(Nr=p.exchangeDests)!=null&&Nr.length){let Ae=[...new Set(p.exchangeDests.map(gt=>gt.entity.name))].join(", ");A.push(`<strong>\u{1F4B1} Exchange Activity:</strong> Funds reached known exchange(s): <strong>${Ae}</strong>. Total outflow tracked: ${_(p.totalOut,2)} XRP to ${p.uniqueDests} destination(s). This is often normal \u2014 people cash out to exchanges. It becomes a concern when combined with the security or timing signals above.`)}else p.totalOut>0&&A.push(`<strong>Outbound payments:</strong> ${_(p.totalOut,2)} XRP sent to ${p.uniqueDests} destination(s). None matched known exchange addresses.`);if(r.score>=60){let Ae=r.stats,gt=Ae.creates>0?(Ae.cancels/Ae.creates*100).toFixed(0):0;A.push(`<strong>\u{1F4CA} Wash Trading Signals (Score: ${r.score}/100 \u2014 ${r.verdict.replace("-"," ").toUpperCase()}):</strong><br><strong>What was found:</strong> Out of ${Ae.creates} DEX offers placed, ${Ae.cancels} (${gt}%) were cancelled before filling. Only ${Ae.fills} actually filled.`+(Ae.selfTrades>0?` ${Ae.selfTrades} payment(s) were sent from and back to the same address.`:"")+"<br><strong>What it means:</strong> Placing orders and cancelling them before they fill inflates a token's visible trading activity without any real buying or selling. It makes a thin market look active to attract other traders.<br><strong>Caveat:</strong> Legitimate market makers do cancel many orders as prices move. This finding is strongest when combined with the self-trade and fee-spike signals.")}else r.score>=30?A.push(`<strong>Moderate trading signals</strong> (score ${r.score}/100): Some DEX patterns look unusual but not conclusive alone. See Wash Trading section for specifics.`):A.push(`<strong>\u2705 DEX activity looks normal</strong> (wash score ${r.score}/100). Cancel ratios, fill rates, and trade sizes are within organic ranges.`);(S==null?void 0:S.selfRoutedCount)>0&&A.push(`<strong>\u{1F504} Self-Routing Path Payments:</strong> ${S.selfRoutedCount} payment(s) where the sender and destination are the same address. Routing XRP through the DEX back to yourself creates trading volume on every intermediate pair with no net economic transfer \u2014 a DEX-specific wash trading technique that's harder to detect than simple self-trades.`),(S==null?void 0:S.roundTripCount)>=3&&A.push(`<strong>XRP\u2192IOU\u2192XRP round-trips:</strong> ${S.roundTripCount} path payments paid and received XRP through intermediate token pairs \u2014 generating DEX volume without changing economic position.`),(k==null?void 0:k.verdict)==="elevated"&&A.push(`<strong>\u{1F4B8} Fee Spike Pattern:</strong> ${k.spikeCount} transaction(s) paid more than 100\xD7 the normal fee. Bots often overpay fees to guarantee same-ledger execution alongside a counterparty \u2014 a coordination technique used in wash trading and front-running. Organic users almost never need fees this high.`);let Le=[l.verdict==="high-deviation",(g==null?void 0:g.verdict)==="anomalous",(v==null?void 0:v.verdict)==="anomalous"||(v==null?void 0:v.verdict)==="elevated",(h==null?void 0:h.verdict)==="bot-pattern",(b==null?void 0:b.verdict)==="strong-coupling"].filter(Boolean).length;if(Le>=3?A.push(`<strong>\u{1F52C} Statistical Analysis \u2014 Multiple Engines Agree:</strong><br>${Le} out of 5 independent mathematical tests found patterns inconsistent with human organic activity. These tests each use different mathematical approaches (number patterns, information theory, power laws, timing, causality) so they can't all be false alarms from the same data artifact.<br><strong>What it means:</strong> When unrelated statistical methods all flag the same account, the probability that all findings are coincidental false positives drops dramatically. This strongly suggests automated or coordinated activity, though it's not proof of fraud.`):Le>=2?A.push(`<strong>Statistical analysis:</strong> ${Le}/5 tests flagged unusual patterns. Multiple independent tests agreeing is a meaningful signal \u2014 see the Forensic Suite section.`):Le===1?A.push("<strong>Statistical analysis:</strong> 1/5 tests flagged an unusual pattern. A single flag is a hypothesis to investigate further, not a conclusion."):f.length>=30&&A.push(`<strong>\u2705 All statistical tests normal:</strong> Benford's Law, entropy, Zipf's Law, time series, and offer/flow coupling all returned results consistent with organic activity across ${f.length} transactions.`),l.verdict==="high-deviation"&&l.chiSq!=null&&A.push(`<strong>Benford's Law detail (\u03C7\xB2=${l.chiSq.toFixed(1)}):</strong> In real financial data, "1" appears as the first digit ~30% of the time and "9" only ~4.6%. Computer-generated amounts break this pattern. This wallet's amounts deviate significantly (\u03C7\xB2=${l.chiSq.toFixed(1)} exceeds the 99% confidence threshold of 20.09).`),m.totalIssued>0){let Ae=(Rr=m.topHolders)==null?void 0:Rr[0],gt=Ae?(Ae.balance/m.totalIssued*100).toFixed(0):null,ua=(_r=$==null?void 0:$.result)!=null&&_r.obligations?Object.values($.result.obligations).reduce((vo,yo)=>vo+Number(yo),0):null,ma=ua?` (verified via gateway_balances: ${_(ua,0)} total obligations)`:"";A.push(`<strong>\u{1FA99} Token Issuance:</strong> This account has issued tokens \u2014 <strong>${_(m.totalIssued,0)} outstanding</strong> across ${m.holderCount} holder(s)${ma}. `+(gt?`The largest single holder controls <strong>${gt}% of supply</strong>. `:"")+(gt&&Number(gt)>50?"Holding more than half the supply means one wallet could dump and collapse the token price. ":"")+((Dr=m.mirrorGroups)!=null&&Dr.length?`<strong>${m.mirrorGroups.length} cluster(s)</strong> of wallets each received identical token amounts \u2014 possible coordinated/insider wallets. `:"")+((Ir=m.createdAccts)!=null&&Ir.length?`This issuer also created ${m.createdAccts.length} wallet(s) \u2014 they may be controlled by the same entity. `:""))}let an=(i.flags||[]).filter(Ae=>Ae.sev==="critical");if(an.length&&A.push(`<strong>\u{1F3A8} NFT Risk:</strong> ${an.length} critical NFT issue(s) \u2014 most commonly a zero-price sell offer. The most common XRPL NFT scam: a malicious dApp tricks the wallet owner into signing a transaction that creates a sell offer for 0 XRP, making the NFT free for anyone to take.`),E!=null&&E.structuredFlag)A.push(`<strong>\u{1F4E5} Structured Inbound Pattern:</strong> ${E.uniqueSources} source(s) funded this wallet \u2014 many payments arrive at near-identical amounts. Structured deposits deliberately break large transfers into smaller equal amounts to reduce traceability.`);else if((Fr=E==null?void 0:E.exchangeSrcs)!=null&&Fr.length){let Ae=[...new Set(E.exchangeSrcs.map(gt=>gt.entity.name))].join(", ");A.push(`<strong>\u{1F4E5} Funding Sources:</strong> Wallet received funds from ${E.uniqueSources} source(s) \u2014 ${Ae} among them. Total inbound: ${_(E.totalIn,2)} XRP.`)}return(Or=C==null?void 0:C.scamMemos)!=null&&Or.length&&A.push(`<strong>\u{1F4DD} Scam Memo Content Detected:</strong> ${C.scamMemos.length} transaction memo(s) contain text matching known scam patterns (airdrop claims, wallet verification requests, urgency language). These payments were likely sent by attackers attempting social engineering.`),(Br=O==null?void 0:O.signals)!=null&&Br.some(Ae=>Ae.sev==="critical")&&A.push("<strong>\u{1F4D6} Active Spoofing Detected Right Now:</strong> This wallet currently has an order that controls over 40% of the visible order book depth. Large orders placed without intent to fill \u2014 then quickly cancelled when approached \u2014 is spoofing. This is happening in the live order book at time of inspection."),(T==null?void 0:T.riskPenalty)>0&&A.push("<strong>\u{1F3F7} Destination Tag Pattern:</strong> Payments to exchanges used an unusually wide variety of destination tags \u2014 each tag identifies a different customer account. This can indicate a service routing payments to many accounts, or deliberate spread of deposits across exchange accounts to reduce traceability."),q.length===0&&J.length===0&&A.push(`<span style="color:#50fa7b"><strong>\u2705 No Elevated Signals Found</strong></span><br>All checks returned results within normal ranges across ${te}. This does not guarantee the account is trustworthy \u2014 it means no identifiable red flags were found in the data analyzed.`),f.length<100&&A.push(`<em style="opacity:.6;font-size:.86em">Data coverage: ${te}. Fewer than 100 transactions means some statistical tests above may not reach reliable conclusions \u2014 treat those specifically as weaker signal.</em>`),A}let Me={Security:{icon:"\u{1F510}",desc:"Keys, flags, multisig, auth changes"},"Drain Risk":{icon:"\u26A0\uFE0F",desc:"Auth changes \u2192 large outflows, external key injection"},"Fund Flow":{icon:"\u{1F30A}",desc:"Exchange flows, black holes, new-wallet recipients, path routing"},NFT:{icon:"\u{1F3A8}",desc:"Zero-value offers, no-metadata tokens, burns"},"Wash Trading":{icon:"\u{1F4CA}",desc:"Cancel ratios, self-trades, order uniformity, burst patterns"},"Benford's Law":{icon:"\u{1F4D0}",desc:"First-digit natural distribution test on all amounts"},"Volume Concentration":{icon:"\u{1FAE7}",desc:"How many wallets drive token trading volume"},"Shannon's Entropy":{icon:"\u{1F500}",desc:"Randomness of amounts, counterparties, timing, tx types"},"Zipf's Law":{icon:"\u{1F4C8}",desc:"Counterparty frequency power-law distribution"},"Time Series":{icon:"\u{1F550}",desc:"Interval regularity, periodicity \u2014 bot vs human timing"},"Offer/Flow Coupling":{icon:"\u{1F517}",desc:"Cross-correlation (not causality): create\u2194cancel, inflow\u2194outflow"},"Token Issuer":{icon:"\u{1FA99}",desc:"Supply, freeze state, concentration"},AMM:{icon:"\u{1F4A7}",desc:"LP positions, pool TVL, ownership share"},"Issuer Connections":{icon:"\u{1F578}",desc:"Distribution patterns, mirror wallets, account creation chains"},"Fee Spikes":{icon:"\u{1F4B8}",desc:"Elevated fee transactions \u2014 coordination signal"},"Destination Tags":{icon:"\u{1F3F7}",desc:"Exchange sub-account routing patterns"},"Path Payments":{icon:"\u{1F504}",desc:"Circular routing, self-routing, deep-hop obfuscation"},"Inbound Flow":{icon:"\u{1F4E5}",desc:"Funding sources, exchange deposits, structured inbound patterns"},"Memo Analysis":{icon:"\u{1F4DD}",desc:"Scam patterns, coordination text, hex-decoded memo data"},"Escrow Depth":{icon:"\u{1F512}",desc:"Third-party escrows, maturity dates, conditional locks"},"Live Order Book":{icon:"\u{1F4D6}",desc:"Current spoofing detection \u2014 wall orders, book depth concentration"}},We=["Security","Drain Risk","Fund Flow","NFT","Wash Trading","Benford's Law","Volume Concentration","Shannon's Entropy","Zipf's Law","Time Series","Offer/Flow Coupling","Token Issuer","AMM","Issuer Connections","Fee Spikes","Destination Tags","Path Payments"],De={};for(let A of We)De[A]=Pe.filter(Le=>Le.module===A&&Le.sev!=="ok"&&Le.sev!=="info");let Ie=We.filter(A=>De[A].length>0).map(A=>{let Le=Me[A]||{icon:"\u{1F4CB}",desc:""},an=De[A].map(rt=>{var ht;let Kn=(ht=rt.hashes)!=null&&ht.length?`
          <div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:6px">
            ${rt.hashes.slice(0,5).map(Sn=>`
              <a href="https://livenet.xrpl.org/transactions/${y(Sn)}" target="_blank" rel="noopener"
                 style="font-size:.7rem;font-family:monospace;color:var(--accent);text-decoration:none;
                        background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.2);
                        border-radius:4px;padding:2px 6px" title="${y(Sn)}">
                ${Sn.slice(0,8)}\u2026${Sn.slice(-4)} \u{1F517}
              </a>`).join("")}
          </div>`:"";return`
          <div class="report-finding-row">
            <div class="report-finding-top">
              ${ue(rt.sev)}
              <span class="report-finding-headline">${y(rt.headline)}</span>
            </div>
            ${rt.detail?`<div class="report-finding-detail">${y(rt.detail)}</div>`:""}
            ${Kn}
          </div>`}).join("");return`
        <div class="report-module">
          <div class="report-module-h">
            <span style="margin-right:6px">${Le.icon}</span>${y(A)}
            <span style="font-size:.72rem;font-weight:400;opacity:.45;margin-left:8px">${y(Le.desc)}</span>
          </div>
          ${an}
        </div>`}).join(""),Y=[{k:"Address",v:e,mono:!0},{k:"Balance",v:_(n,4)+" XRP"+wn(n),mono:!0},{k:"Wallet Age",v:D!=null?(D<1?"Created today":D+" days")+(I?" \u2014 created "+new Date(I).toLocaleDateString("en-US",{year:"numeric",month:"short",day:"numeric"}):""):"\u2014"},{k:"Risk Score",v:s+"/100 \u2014 "+re,color:pe},{k:"Transactions Analyzed",v:f.length+(de?" \xB7 "+de:"")},{k:"Activity Span",v:le>0?le+" days":"unknown"},{k:"Outbound Destinations",v:p.uniqueDests+" addresses received funds"},{k:"Total XRP Sent Out",v:_(p.totalOut,2)+" XRP",mono:!0},{k:"New-Wallet Recipients",v:(((sn=p.newWalletDests)==null?void 0:sn.length)||0)+((pa=p.newWalletDests)!=null&&pa.length?" \u26A0":" \u2014 none"),color:(Sr=p.newWalletDests)!=null&&Sr.length?"#ff5555":null},{k:"Wash Trading Score",v:(r.score||0)+"/100 \u2014 "+(r.verdict||"\u2014").replace("-"," ")+(r.score<25?" \u2713":r.score<50?" \u26A0 moderate":" \u{1F6A8} elevated")},{k:"Fee Spike Count (>100\xD7 base)",v:((k==null?void 0:k.spikeCount)??"N/A")+((k==null?void 0:k.spikeCount)>5?" \u26A0":""),mono:!0},{k:"Benford \u03C7\xB2 (normal \u2264 15.5)",v:l.chiSq!=null?l.chiSq.toFixed(2)+" \u2014 "+l.verdict.replace("-"," "):"insufficient data",mono:!0},{k:"Amount Entropy (natural 2.4\u20134.2)",v:(g==null?void 0:g.amountEntropy)!=null?g.amountEntropy.toFixed(2)+" bits":"N/A",mono:!0},{k:"Zipf Exponent (natural 0.8\u20131.3)",v:(v==null?void 0:v.zipfExponent)!=null?v.zipfExponent.toFixed(3)+"  R\xB2="+((Tr=v.rSquared)==null?void 0:Tr.toFixed(2)):"N/A",mono:!0},{k:"Timing Regularity CV (bot < 0.25)",v:(h==null?void 0:h.intervalCV)!=null?h.intervalCV.toFixed(3)+(h.intervalCV<.25?" \u26A0 bot-level":" \u2713"):"N/A",mono:!0},{k:"Offer Create\u2194Cancel Correlation",v:((Cr=b==null?void 0:b.offerCancelCausality)==null?void 0:Cr.maxCorr)!=null?b.offerCancelCausality.maxCorr.toFixed(3)+(b.offerCancelCausality.maxCorr>.55?" \u26A0":" \u2713"):"N/A",mono:!0},{k:"XRP\u2192IOU\u2192XRP Round-Trips",v:((S==null?void 0:S.roundTripCount)??0)+((S==null?void 0:S.roundTripCount)>=3?" \u26A0":""),mono:!0},{k:"Token Holders",v:m.holderCount>0?m.holderCount+" wallets hold tokens from this issuer":"Not a token issuer"},{k:"Critical Findings",v:q.length+(q.length===0?" \u2014 none":""),color:q.length>0?"#ff5555":"#50fa7b"},{k:"Warnings",v:J.length+(J.length===0?" \u2014 none":""),color:J.length>0?"#ffb86c":"#50fa7b"}].map(A=>`
    <div class="report-stat-row">
      <span class="report-stat-k">${y(A.k)}</span>
      <span class="report-stat-v ${A.mono?"mono":""}" style="${A.color?"color:"+A.color:""}">${y(String(A.v))}</span>
    </div>`).join(""),Ce={critical:"rgba(255,85,85,.08)",warn:"rgba(255,184,108,.06)",info:"rgba(120,180,255,.05)",ok:"rgba(80,250,123,.05)"},Ye={critical:"rgba(255,85,85,.25)",warn:"rgba(255,184,108,.20)",info:"rgba(120,180,255,.15)",ok:"rgba(80,250,123,.15)"},$e=[];(o.riskLevel==="critical"||o.riskLevel==="high")&&$e.push({icon:"\u{1F534}",sev:"critical",text:"If this is your wallet: stop sending funds here immediately. The account's security keys match a known drain attack pattern. Contact a security professional or the XRPL community before taking any action."}),(Pr=p.newWalletDests)!=null&&Pr.length&&$e.push({icon:"\u26A0\uFE0F",sev:"critical",text:`${p.newWalletDests.length} brand-new wallet(s) received large XRP transfers. This is a classic drain pattern. If this was unexpected, the funds have likely already been moved further down the chain.`}),(Mr=p.blackHoleDests)!=null&&Mr.length&&$e.push({icon:"\u26D4",sev:"critical",text:"Funds sent to black hole addresses are gone permanently. No exchange, no support team, and no legal action can retrieve them."}),(Lr=p.exchangeDests)!=null&&Lr.length&&$e.push({icon:"\u{1F4B1}",sev:"warn",text:`If this was a drain: contact ${[...new Set(p.exchangeDests.map(A=>A.entity.name))].join(", ")} exchange support immediately with the transaction hashes from the Fund Flow section. Act within hours \u2014 exchanges can sometimes freeze funds quickly but not after they've been withdrawn.`}),r.score>=60&&$e.push({icon:"\u{1F4CA}",sev:"warn",text:"Significant wash trading signals detected. If you're a market maker: high cancel ratios are normal for your role \u2014 review the self-trade and self-routing signals specifically. If you're a token holder or researcher: this pattern suggests the token's apparent volume may be artificial."}),(S==null?void 0:S.selfRoutedCount)>0&&$e.push({icon:"\u{1F504}",sev:"warn",text:`${S.selfRoutedCount} path payment(s) routed XRP from and back to the same address through the DEX. This creates artificial trading volume on every intermediate pair. Check the Path Payments section for specific transaction hashes.`}),(Ar=m.mirrorGroups)!=null&&Ar.length&&$e.push({icon:"\u{1F578}",sev:"warn",text:"Mirror wallet clusters found. If you are the issuer, determine whether these are genuine holders or insider accounts used to create the appearance of broader distribution. These wallets could coordinate a sell-off."}),(Er=i.flags)!=null&&Er.some(A=>A.sev==="critical")&&$e.push({icon:"\u{1F3A8}",sev:"critical",text:"Zero-value NFT offer detected. If you didn't intentionally list your NFT for free: identify what website or app you used around the time this transaction was signed, and revoke any approvals it has."}),(k==null?void 0:k.verdict)==="elevated"&&$e.push({icon:"\u{1F4B8}",sev:"info",text:`${k.spikeCount} transactions paid >100\xD7 normal fees. Check the Fee Spikes section to see if these align with moments of concentrated trading \u2014 elevated fees often mark coordinated activity windows.`}),$e.length===0&&$e.push({icon:"\u2705",sev:"ok",text:"No immediate actions required. The account shows no identifiable red flags. Continue monitoring as activity grows \u2014 some patterns only become statistically significant with more data."});let Ct=$e.map(A=>`
    <div style="background:${Ce[A.sev]||Ce.info};border:1px solid ${Ye[A.sev]||Ye.info};border-radius:10px;padding:12px 14px;margin-bottom:8px;display:flex;gap:12px;align-items:flex-start">
      <span style="font-size:1.15rem;flex-shrink:0;margin-top:1px">${A.icon}</span>
      <span style="font-size:.85rem;line-height:1.65;color:rgba(255,255,255,.78)">${A.text}</span>
    </div>`).join(""),G=`
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:8px;margin-top:10px">
      ${[["Benford's Law","In organic financial data, amounts starting with '1' appear ~30% of the time. Computer-generated amounts often break this law."],["Shannon's Entropy","Measures how 'predictable' transaction amounts and partners are. Bots repeat the same amounts; humans don't."],["Zipf's Law","Natural networks have a few heavy relationships and many light ones. Wash rings show unnaturally equal relationships."],["Time Series CV","Coefficient of Variation of gaps between transactions. Humans: >0.8 (irregular). Bots: <0.3 (clock-like)."],["Offer/Flow Coupling","Cross-correlation between two event series at a time lag \u2014 e.g., offer creation and cancellation moving together. A correlation, not a causality test; it can't show which one actually drives the other."],["Interval CV","The regularity of timing between transactions. Very low = mechanical/automated. Very high = erratic/bursty."],["Gateway Balances","The XRPL API command that returns the true outstanding obligations of a token issuer \u2014 more accurate than just reading trustlines."],["Destination Tag","A number attached to a payment that identifies the recipient sub-account at an exchange. Like a bank account reference number."],["Path Payment","An XRPL payment that routes through intermediate DEX pairs. Can create trading volume on pairs the sender never intended to trade."],["XRP Round-Trip","A path payment that starts and ends in XRP, routed through IOU pairs. Creates DEX volume with no net economic transfer."],["Fee Multiplier","XRPL's base transaction fee is 12 drops (~$0.000001). Paying 100\xD7 means paying 1,200 drops \u2014 bots do this for guaranteed same-ledger execution."]].map(([A,Le])=>`
        <div style="background:rgba(255,255,255,.03);border-radius:8px;padding:10px 12px;border:1px solid rgba(255,255,255,.05)">
          <div style="font-size:.78rem;font-weight:700;color:rgba(255,255,255,.75);margin-bottom:4px">${y(A)}</div>
          <div style="font-size:.74rem;color:rgba(255,255,255,.42);line-height:1.5">${y(Le)}</div>
        </div>`).join("")}
    </div>`,me=ke();return`
    <div class="report-wrap">

      <!-- \u2500\u2500 Cover \u2500\u2500 -->
      <div class="report-cover">
        <div class="report-cover-left">
          <div class="report-logo">\u26A1 NaluXRP</div>
          <h2 class="report-title">Account Investigation Report</h2>
          <div class="report-addr mono">${y(e)}</div>
          <div class="report-ts">Generated ${j}</div>
          <div style="font-size:.75rem;color:rgba(255,255,255,.38);margin-top:4px">Coverage: ${y(te)}</div>
        </div>
        <div class="report-score-circle" style="--score-color:${pe}">
          <div class="report-score-num" style="color:${pe}">${s}</div>
          <div class="report-score-den">/100</div>
          <div class="report-score-word" style="color:${pe}">${re}</div>
        </div>
      </div>

      <!-- \u2500\u2500 Executive Summary \u2500\u2500 -->
      <div class="report-section">
        <h3 class="report-section-h">\u{1F4CB} Executive Summary</h3>
        <div class="report-narrative">
          ${me.map(A=>`<p style="margin-bottom:12px;line-height:1.7">${A}</p>`).join("")}
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
        <div style="margin-bottom:16px">${_0(f,e)}</div>
        ${Uu(n,p,E)}
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
        <div class="report-stats-grid">${Y}</div>
      </div>

      <!-- \u2500\u2500 Findings by Module \u2500\u2500 -->
      ${Ie?`
      <div class="report-section">
        <h3 class="report-section-h">\u{1F52C} Findings by Module
          <span class="report-counts">
            <span class="report-count report-count--crit">${q.length} Critical</span>
            <span class="report-count report-count--warn">${J.length} Warnings</span>
          </span>
        </h3>
        <p style="font-size:.8rem;color:rgba(255,255,255,.4);margin-bottom:14px;line-height:1.6">
          Each module below used a different method to analyse the account.
          Findings include clickable transaction hash links so you can verify everything on-chain.
        </p>
        <div class="report-findings">${Ie}</div>
      </div>`:`
      <div class="report-section">
        <h3 class="report-section-h">\u{1F52C} Findings</h3>
        <div class="report-clean-note">\u2705 No elevated findings across all ${We.length} analysis modules.</div>
      </div>`}

      <!-- \u2500\u2500 Recommendations \u2500\u2500 -->
      <div class="report-section">
        <h3 class="report-section-h">\u{1F4A1} Recommended Actions</h3>
        ${Ct}
      </div>

      <!-- \u2500\u2500 Glossary \u2500\u2500 -->
      <div class="report-section">
        <h3 class="report-section-h">\u{1F4D6} Understanding This Report</h3>
        <p style="font-size:.82rem;color:rgba(255,255,255,.45);line-height:1.65;margin-bottom:10px">
          Plain-English definitions for every technical term used in this report.
        </p>
        ${G}
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
  `}function i0(e,...t){e.innerHTML=o0(...t)}function r0(){let e=document.getElementById("tab-inspector");e&&(e.querySelector("[data-inspector-v2]")||(e.innerHTML=`
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
  `))}function l0(){if(document.getElementById("inspector-nav"))return;let e=document.createElement("nav");e.id="inspector-nav",e.setAttribute("aria-label","Inspector navigation"),e.innerHTML=`
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
  `;let t=document.getElementById("tab-inspector");t&&t.appendChild(e)}function c0(){if(document.getElementById("inspector-howto"))return;let e=document.createElement("div");e.id="inspector-howto",e.className="howto-overlay",e.style.display="none",e.innerHTML=`
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
  `,e.addEventListener("click",t=>{t.target===e&&Zi()}),document.addEventListener("keydown",t=>{t.key==="Escape"&&e.style.display!=="none"&&Zi()}),document.body.appendChild(e)}function Vu(e){Xe("#inspector-nav .in-btn[data-jump]").forEach(t=>t.classList.toggle("in-btn--active",t.dataset.jump===e))}function d0(){var n;if(!document.body.classList.contains("inspector")||((n=w("inspect-result"))==null?void 0:n.style.display)==="none")return;let e=["security","drain","nft","wash","issuer","amm","trustlines","tx"],t=null;for(let s of e){let a=document.getElementById("section-"+s);a&&a.getBoundingClientRect().top<=150&&(t=s)}t&&Vu(t)}function oo(e,t){let n=w(e);if(!n)return;let s=t.filter(o=>o.sev==="critical").length,a=t.filter(o=>o.sev==="warn").length;s?(n.textContent=s+" critical",n.className="section-badge section-badge--crit"):a?(n.textContent=a+" warn",n.className="section-badge section-badge--warn"):(n.textContent="OK",n.className="section-badge section-badge--ok")}function p0(e,t){let n=w(e);if(!n)return;let s={low:"ok",medium:"warn",high:"warn",critical:"crit"};n.textContent=t,n.className="section-badge section-badge--"+(s[t]||"ok")}window._toggleForensicTab=function(e){var a,o;let t=document.getElementById("forensic-tab-"+e);if(!t)return;let n=t.style.display!=="none";t.style.display=n?"none":"";let s=document.getElementById("ftab-chevron-"+e);s&&(s.textContent=n?"\u25BE":"\u25B4"),(a=document.getElementById("ftab-btn-"+e))==null||a.setAttribute("aria-expanded",String(!n)),!n&&((o=t.querySelector('[id^="inspect-"]'))==null?void 0:o.innerHTML)===""&&(t.querySelector('[id^="inspect-"]').innerHTML='<div style="opacity:.45;font-size:.8rem;padding:8px 0">Run an inspection first.</div>')};function u0(){var n,s;let e=w("inspect-addr-badge"),t=((n=e==null?void 0:e.dataset)==null?void 0:n.fullAddr)||(e==null?void 0:e.textContent);!t||t==="\u2014"||(s=navigator.clipboard)==null||s.writeText(t).then(()=>{let a=document.querySelector(".irb-copy-btn");a&&(a.textContent="\u2713",setTimeout(()=>a.textContent="\u{1F4CB}",1500))})}window.inspectorGoBack=function(){let e=w("inspect-result"),t=w("inspect-empty"),n=w("inspect-err"),s=w("inspect-addr");e&&(e.style.display="none"),n&&(n.style.display="none"),t&&(t.style.display=""),s&&(s.value=""),ar(),or(),window.scrollTo({top:0,behavior:"smooth"}),setTimeout(()=>s==null?void 0:s.focus(),300)};function m0(){let e=document.getElementById("inspector-howto");e&&(e.style.display="",requestAnimationFrame(()=>e.classList.add("howto-visible")))}function Zi(){let e=document.getElementById("inspector-howto");e&&(e.classList.remove("howto-visible"),setTimeout(()=>{e.classList.contains("howto-visible")||(e.style.display="none")},260))}var sr="nalulf_inspect_history",f0="nalulf_wallets",ea="nalulf_watchlist",Gu="nalulf_analyst_mode";var h0=[{label:"SOLO Issuer",addr:"rsoLo2S1kiGeCcn6hCUXVrCpGMWLrRrLZz",tag:"Token Issuer",icon:"\u{1FA99}",note:"200 trustlines \xB7 master disabled \xB7 liquidity provider",color:"#ffb86c"},{label:"Ripple Genesis",addr:"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",tag:"Genesis",icon:"\u{1F310}",note:"Original genesis wallet \xB7 100 billion XRP issued",color:"#50fa7b"},{label:"Bitstamp Hot",addr:"rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B",tag:"Exchange",icon:"\u{1F3E6}",note:"Major exchange hot wallet \xB7 high payment volume",color:"#8be9fd"},{label:"GateHub Hot",addr:"rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq",tag:"Exchange",icon:"\u{1F3E6}",note:"GateHub gateway \xB7 multi-currency issuance",color:"#8be9fd"},{label:"XAMAN Wallet",addr:"rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY",tag:"Wallet App",icon:"\u{1F4F1}",note:"XAMAN (XUMM) custodial wallet address",color:"#bd93f9"},{label:"DEX Market Maker",addr:"r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59",tag:"Market Maker",icon:"\u{1F4CA}",note:"High-volume DEX activity \xB7 offer patterns",color:"#ff79c6"}],g0=[{icon:"\u{1F510}",title:"Security Audit",desc:"Decodes all account flags, checks master key status, regular key age, multisig signer lists, and suspicious auth changes.",color:"#50fa7b"},{icon:"\u26A0",title:"Drain Detection",desc:"Classic drain setup, external key injection (3rd party sets your key), large outflows within 48h of auth change, open payment channels.",color:"#ff5555"},{icon:"\u{1F3A8}",title:"NFT Risk",desc:"Zero-value sell offers (free NFT drain vector), no-URI spam tokens, unexpected burns, transfer fee exposure.",color:"#bd93f9"},{icon:"\u{1F4CA}",title:"Wash Trading",desc:"Five-signal scoring: cancel ratio, round-trip counterparties, single-pair concentration, fill rate, burst activity.",color:"#ffb86c"},{icon:"\u{1FA99}",title:"Token Issuer",desc:"Outstanding obligations, individual line freezes, global freeze, NoFreeze protection, black hole risk detection.",color:"#f1fa8c"},{icon:"\u{1F4A7}",title:"AMM & Liquidity",desc:"LP token positions, deposit/withdrawal history, fee votes, auction slot bids, impermanent loss warnings.",color:"#8be9fd"},{icon:"\u{1F30A}",title:"Fund Flow Tracer",desc:"Traces every outbound payment from a wallet \u2014 where funds went, which exchanges they reached, multi-hop path payment routes, and a full chronological drain timeline.",color:"#00d4ff"},{icon:"\u{1F578}",title:"Issuer Connection Graph",desc:"Token supply concentration, top holder %, accounts the issuer created/funded, and mirror-wallet clusters \u2014 groups of wallets receiving identical token amounts (sybil detection).",color:"#bd93f9"}];function b0(){v0(),y0(),ar(),or(),na(),w0(),Yu()}function v0(){let e=document.getElementById("isd-notable-grid");e&&(e.innerHTML=h0.map(t=>`
    <button class="isd-notable-card" onclick="inspectorLoadAddr('${t.addr}')" type="button">
      <div class="isd-notable-top">
        <span class="isd-notable-icon" style="color:${t.color}">${t.icon}</span>
        <span class="isd-notable-tag" style="border-color:${t.color}40;color:${t.color}">${y(t.tag)}</span>
      </div>
      <div class="isd-notable-label">${y(t.label)}</div>
      <div class="isd-notable-addr mono">${t.addr.slice(0,8)}\u2026${t.addr.slice(-6)}</div>
      <div class="isd-notable-note">${y(t.note)}</div>
    </button>
  `).join(""))}function y0(){let e=document.getElementById("isd-cap-grid");e&&(e.innerHTML=g0.map(t=>`
    <div class="isd-cap" style="--cap-color:${t.color}">
      <div class="isd-cap-icon-wrap"><span class="isd-cap-icon">${t.icon}</span></div>
      <div class="isd-cap-body">
        <div class="isd-cap-title">${y(t.title)}</div>
        <div class="isd-cap-desc">${y(t.desc)}</div>
      </div>
    </div>
  `).join(""))}function ar(){let e=document.getElementById("isd-wallets-section"),t=document.getElementById("isd-wallet-list");if(!e||!t)return;let n=ge(Q(f0))||[];if(!n.length){e.style.display="none";return}e.style.display="",t.innerHTML=n.map(s=>{let a=s.color||"#50fa7b",o=s.emoji||"\u{1F48E}",i=s.label||"Wallet",r=s.address||"",l=r?r.slice(0,8)+"\u2026"+r.slice(-6):"\u2014",c=s.testnet?'<span class="isd-wallet-testnet">TESTNET</span>':"";return`
      <button class="isd-wallet-card" onclick="inspectorLoadAddr('${y(r)}')" type="button">
        <div class="isd-wallet-avatar" style="background:${a}20;border-color:${a}50">${o}</div>
        <div class="isd-wallet-info">
          <div class="isd-wallet-name">${y(i)} ${c}</div>
          <div class="isd-wallet-addr mono">${l}</div>
        </div>
        <div class="isd-wallet-inspect">Inspect \u2192</div>
      </button>
    `}).join("")}function or(){let e=document.getElementById("isd-recent-section"),t=document.getElementById("isd-recent-list");if(!e||!t)return;let n=io();if(!n.length){e.style.display="none";return}e.style.display="",t.innerHTML=n.map((s,a)=>{let o=s.addr?s.addr.slice(0,10)+"\u2026"+s.addr.slice(-8):"\u2014",i=s.riskScore!=null?`<span class="isd-risk-pill isd-risk-pill--${Ju(s.riskScore)}">${s.riskScore}</span>`:"";return`
      <button class="isd-recent-row" onclick="inspectorLoadAddr('${y(s.addr)}')" type="button">
        <span class="isd-recent-n">${a+1}</span>
        <span class="isd-recent-addr mono">${o}</span>
        <div class="isd-recent-right">
          ${i}
          <span class="isd-recent-time">${ro(s.ts)}</span>
        </div>
      </button>
    `}).join("")}function w0(){so(),window.addEventListener("xrpl-ledger",x0),window.addEventListener("xrpl-connection",so)}function x0(e){no()&&so(e.detail)}var Gi=null;function k0(){return Gi||(Gi={idx:document.getElementById("isd-ledger-idx"),age:document.getElementById("isd-ledger-age"),tps:document.getElementById("isd-tps"),tpsTrnd:document.getElementById("isd-tps-trend"),fee:document.getElementById("isd-fee"),feeLv:document.getElementById("isd-fee-level"),close:document.getElementById("isd-close-time"),dot:document.getElementById("isd-conn-dot"),connLbl:document.getElementById("isd-conn-label"),pill:document.getElementById("isd-conn-pill"),domTx:document.getElementById("isd-dom-tx"),domPct:document.getElementById("isd-dom-pct"),bar:document.getElementById("isd-fee-bar"),barLbl:document.getElementById("isd-fee-bar-label")})}function so(){let{idx:e,age:t,tps:n,tpsTrnd:s,fee:a,feeLv:o,close:i,dot:r,connLbl:l,pill:c,domTx:u,domPct:d,bar:p,barLbl:m}=k0(),f=X.connectionState||"disconnected",g={connected:{label:"Connected",cls:"conn--live"},connecting:{label:"Connecting\u2026",cls:"conn--warn"},disconnected:{label:"Disconnected",cls:"conn--dead"}},v=g[f]||g.disconnected;r&&(r.className="isd-conn-dot"),l&&(l.textContent=v.label),c&&(c.className=`isd-conn-pill ${v.cls}`);let h=X.ledgerLog||[];if(h.length&&e){let S=h[0];if(e.textContent=Number(S.ledgerIndex||0).toLocaleString(),t&&(t.textContent=S.closeTimeSec!=="\u2014"?S.closeTimeSec+"s close":"\u2014"),i){let $=parseFloat(S.closeTimeSec);i.textContent=isNaN($)?"\u2014":$.toFixed(1)}}let b=X.tpsHistory||[];if(b.length&&n){let S=b.slice(-5),$=S.reduce((E,C)=>E+C,0)/S.length;if(n.textContent=$.toFixed(1),s&&b.length>=6){let E=b.slice(-10,-5),C=E.reduce((R,O)=>R+O,0)/E.length,P=$-C;s.textContent=P>.5?"\u2191 rising":P<-.5?"\u2193 falling":"\u2192 stable",s.className=`isd-metric-sub ${P>.5?"isd-up":P<-.5?"isd-down":""}`}}let x=X.feeHistory||[];if(x.length&&a){let S=x.slice(-5),$=S.reduce((P,R)=>P+R,0)/S.length,E=$/1e6;a.textContent=$<5e3?$.toFixed(0)+" drops":E.toFixed(5)+" XRP";let C=$<20?{lbl:"Low",cls:"fee-low",pct:10}:$<100?{lbl:"Normal",cls:"fee-normal",pct:28}:$<500?{lbl:"Elevated",cls:"fee-elevated",pct:60}:$<2e3?{lbl:"High",cls:"fee-high",pct:82}:{lbl:"Congested",cls:"fee-congest",pct:100};o&&(o.textContent=C.lbl,o.className=`isd-metric-sub ${C.cls}`),p&&(p.style.width=C.pct+"%",p.className=`isd-fee-bar-fill ${C.cls}`),m&&(m.textContent=C.lbl,m.className=`isd-fee-bar-level ${C.cls}`)}let k=X.txMixAccum||{},T=Object.entries(k).filter(([,S])=>S>0).sort(([,S],[,$])=>$-S);if(T.length&&u){let S=T.reduce((C,[,P])=>C+P,0),[$,E]=T[0];u.textContent=$,d&&(d.textContent=(E/S*100).toFixed(0)+"% of traffic")}}window.exportTxCSV=function(e){var l,c;if(!e||!e.length){alert("No transaction data to export. Run an inspection first.");return}let t=946684800,s=[["Hash","Date","Type","Account","Destination","Amount_XRP","Amount_Token","Currency","Fee_Drops","DestinationTag","Result","LedgerIndex"],...e.map(({tx:u,meta:d})=>{var h,b;let p=u.date?new Date((u.date+t)*1e3).toISOString():"",m=typeof u.Amount=="string"?(Number(u.Amount)/1e6).toFixed(6):"",f=(h=u.Amount)!=null&&h.value?u.Amount.value:"",g=((b=u.Amount)==null?void 0:b.currency)||(typeof u.Amount=="string"?"XRP":""),v=(d==null?void 0:d.TransactionResult)||"";return[u.hash||"",p,u.TransactionType||"",u.Account||"",u.Destination||"",m,f,g,u.Fee||"",u.DestinationTag??"",v,u.ledger_index||""]})].map(u=>u.map(d=>{let p=String(d);return p.includes(",")||p.includes('"')||p.includes(`
`)?'"'+p.replace(/"/g,'""')+'"':p}).join(",")).join(`
`),a=new Blob([s],{type:"text/csv;charset=utf-8;"}),o=URL.createObjectURL(a),i=document.createElement("a"),r=((c=(l=document.getElementById("inspect-addr-badge"))==null?void 0:l.dataset)==null?void 0:c.fullAddr)||"wallet";i.href=o,i.download=`naluxrp_${r.slice(0,10)}_${new Date().toISOString().slice(0,10)}.csv`,document.body.appendChild(i),i.click(),document.body.removeChild(i),URL.revokeObjectURL(o)};function $0(e,t){let s=io().find(o=>o.addr===e);if(!s||s.riskScore==null||t==null)return null;let a=t-s.riskScore;return{prev:s.riskScore,curr:t,diff:a,ts:s.ts}}function S0(e,t){let n=$0(e,t);if(!n||Math.abs(n.diff)<2)return;let s=document.getElementById("inspect-risk-score");if(!s)return;let a=n.diff>0?`<span style="color:#ff5555;font-size:.7rem;font-weight:700"> \u2191${n.diff}</span>`:`<span style="color:#50fa7b;font-size:.7rem;font-weight:700"> \u2193${Math.abs(n.diff)}</span>`,o=ro(n.ts);s.insertAdjacentHTML("afterend",`<span class="risk-score-diff" title="Changed from ${n.prev} \u2192 ${n.curr} since ${o}">${a} vs ${o}</span>`)}window._inspectMaxTx||(window._inspectMaxTx=5e3);window._debugBalanceDeltas=Iu;window._debugOfferLifecycles=ju;window._debugReconstructBalanceHistory=Fu;window._debugFindDrainEpisodes=Ou;window._debugDrainRisk=zu;window.inspectorLoadAddr=function(e){let t=w("inspect-addr");t&&(t.value=e),xs()};window.inspectWalletAddr=function(e){var n,s;window.inspectorLoadAddr(e);let t=document.querySelector('[data-tab="inspector"]');t&&((n=window.switchTab)==null||n.call(window,t,"inspector")),(s=window.showDashboard)==null||s.call(window)};window.printInspectorReport=function(){var s,a;let e=document.getElementById("inspect-report-body");if(!e)return;let t=((a=(s=document.getElementById("inspect-addr-badge"))==null?void 0:s.dataset)==null?void 0:a.fullAddr)||"wallet",n=window.open("","_blank","width=900,height=700");n.document.write(`<!DOCTYPE html><html><head>
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
  </body></html>`),n.document.close()};window.exportInspectorReport=function(){var n;let e=document.getElementById("inspect-report-body");if(!e)return;let t=e.innerText||e.textContent||"";(n=navigator.clipboard)==null||n.writeText(t).then(()=>{let s=document.getElementById("report-export-btn");s&&(s.textContent="\u2713 Copied!",setTimeout(()=>{s.textContent="\u{1F4CB} Copy Report"},2e3))}).catch(()=>{let s=document.createRange();s.selectNodeContents(e);let a=window.getSelection();a.removeAllRanges(),a.addRange(s)})};window.inspectorClearHistory=function(){bt(sr);let e=document.getElementById("isd-recent-section");e&&(e.style.display="none")};window.inspectorClearWatchlist=function(){bt(ea),na()};function io(){return ge(Q(sr))||[]}function T0(e,t,n=[]){let s=io();s=s.filter(o=>o.addr!==e);let a=n.filter(o=>o.sev==="critical"||o.sev==="warn").map(o=>o.module+":"+o.headline.slice(0,40)).sort().join("|");s.unshift({addr:e,riskScore:t,ts:Date.now(),fingerprint:a}),s=s.slice(0,12),Z(sr,JSON.stringify(s))}function ta(){return ge(Q(ea))||[]}function C0(e,t){let n=ta().filter(s=>s.addr!==e);n.unshift({addr:e,label:t||z(e),addedTs:Date.now(),lastScore:null,lastTs:null}),Z(ea,JSON.stringify(n.slice(0,50)))}function Ku(e){Z(ea,JSON.stringify(ta().filter(t=>t.addr!==e)))}function er(e){return ta().some(t=>t.addr===e)}function P0(e,t){let n=ta().map(s=>s.addr===e?{...s,lastScore:t,lastTs:Date.now()}:s);Z(ea,JSON.stringify(n))}function ro(e){let t=Date.now()-e;return t<6e4?"just now":t<36e5?Math.floor(t/6e4)+"m ago":t<864e5?Math.floor(t/36e5)+"h ago":Math.floor(t/864e5)+"d ago"}function Ju(e){return Qi(e).replace("risk-","")}var en=!1;function Yu(){en=localStorage.getItem(Gu)==="true",ir()}function ir(){let e=document.getElementById("inspect-result");if(!e)return;e.classList.toggle("mode-advanced",en),e.classList.toggle("mode-simple",!en);let t=document.getElementById("analyst-mode-btn");t&&(t.textContent=en?"\u2697 Advanced":"\u{1F441} Simple",t.title=en?"Switch to Simple view":"Switch to Advanced (analyst) view",t.setAttribute("aria-pressed",String(en)))}window.toggleAnalystMode=function(){en=!en,localStorage.setItem(Gu,en),ir()};var M0=new Set(["section-overview","section-report"]),L0=new Set(["section-security","section-drain","section-fundflow","section-inbound"]);function A0(){let e=document.getElementById("inspect-result");if(!e)return;let t=[...e.querySelectorAll(".inspector-section")],n={crit:0,warn:1,neutral:2,ok:3,"":4},s=t.filter(i=>!M0.has(i.id)&&!L0.has(i.id));s.sort((i,r)=>{let l=c=>{let u=c.querySelector(".section-badge");if(!u)return"";let d=u.className;return d.includes("crit")?"crit":d.includes("warn")?"warn":d.includes("neutral")?"neutral":d.includes("ok")?"ok":""};return(n[l(i)]??4)-(n[l(r)]??4)});let a=document.getElementById("section-inbound")||document.getElementById("section-drain");if(!a)return;let o=a;for(let i of s)o.after(i),o=i}function E0(e){let t=(e||[]).filter(s=>s.confidence!=null);if(!t.length)return null;let n=t.reduce((s,a)=>s+a.confidence,0)/t.length;return n>=.7?"Strong":n>=.4?"Moderate":"Weak"}function N0(e,t,n,s,a={},o=!1,i=null){let r=document.getElementById("quick-verdict-body");if(!r)return;let l=t.filter(E=>E.sev==="critical"),c=t.filter(E=>E.sev==="warn"),u=e<20?"#50fa7b":e<45?"#ffb86c":e<70?"#ff8c42":"#ff5555",d=e<20?"Low Risk":e<45?"Moderate":e<70?"High Risk":"Critical",p=(E,C)=>(C.confidence??.5)-(E.confidence??.5),m=[...l].sort(p),f=[...c].sort(p),g="",v="";if(l.length===0&&c.length===0)g=`No elevated signals found across ${s.toLocaleString()} transactions${n!=null?` and ${n} days of history`:""}.`,v="This wallet appears to operate within normal parameters.";else{let E=m.slice(0,2).map(P=>P.headline).join("; "),C=f.slice(0,2).map(P=>P.headline).join("; ");g=l.length?`${l.length} critical issue${l.length>1?"s":""}: ${E}.`:`${c.length} warning${c.length>1?"s":""}: ${C}.`,v=l.length?"Review the highlighted sections below. Scroll to the Report for full recommendations.":"Review the flagged sections below for context before drawing conclusions."}let h=Yi.map(E=>({cat:E,...a[E]})).filter(E=>E.score>0).sort((E,C)=>C.score-E.score),b=E=>E<20?"#50fa7b":E<45?"#ffb86c":E<70?"#ff8c42":"#ff5555",x={Strong:"#50fa7b",Moderate:"#ffb86c",Weak:"#ff8c42"},k=h.length?`
    <div style="margin-top:10px;padding-top:10px;border-top:1px solid rgba(255,255,255,.06)">
      <div style="font-size:.65rem;font-weight:800;letter-spacing:.08em;color:rgba(255,255,255,.35);text-transform:uppercase;margin-bottom:6px">By category \u2014 an overall score alone can hide which kind of risk is present</div>
      <div style="display:flex;flex-direction:column;gap:4px">
        ${h.map(E=>{let C=E0(E.findings);return`
          <div style="display:flex;align-items:center;gap:8px;font-size:.76rem">
            <span style="width:150px;color:rgba(255,255,255,.6);flex-shrink:0">${y($y[E.cat])}</span>
            <div style="flex:1;height:5px;border-radius:3px;background:rgba(255,255,255,.06);overflow:hidden">
              <div style="width:${E.score}%;height:100%;background:${b(E.score)};border-radius:3px"></div>
            </div>
            <span class="mono" style="color:${b(E.score)};width:28px;text-align:right;flex-shrink:0">${E.score}</span>
            ${C?`<span style="width:62px;text-align:right;flex-shrink:0;font-size:.66rem;color:${x[C]}" title="Evidence strength \u2014 average confidence across this category's findings">${C}</span>`:'<span style="width:62px;flex-shrink:0"></span>'}
          </div>`}).join("")}
      </div>
    </div>`:"",T=i!=null&&i.newestToOldestComplete?"Full history confirmed \u2014 pagination reached this account's earliest transaction":i!=null&&i.hitTxCap?`Capped at ${s.toLocaleString()} transactions \u2014 this account has more history than was analyzed`:i!=null&&i.fetchErrorOccurred?"A fetch error occurred during pagination \u2014 history may be incomplete":"History coverage not confirmed complete",S=!!(i!=null&&i.newestToOldestComplete),$=`
    <div style="margin-top:10px;padding-top:10px;border-top:1px solid rgba(255,255,255,.06)">
      <div style="font-size:.65rem;font-weight:800;letter-spacing:.08em;color:rgba(255,255,255,.35);text-transform:uppercase;margin-bottom:6px">Data quality \u2014 this report is only as good as the history it saw</div>
      <div style="display:flex;flex-direction:column;gap:3px;font-size:.76rem;color:rgba(255,255,255,.55)">
        <div><span style="color:${S?"#50fa7b":"#ffb86c"}">${S?"\u2713":"\u26A0"}</span> ${y(T)} (${s.toLocaleString()} transactions)</div>
        <div><span style="color:${o?"#50fa7b":"#ffb86c"}">${o?"\u2713":"\u26A0"}</span> Wallet age ${o?"verified":"estimated"}${n!=null?` \u2014 ${n} day(s)${o?"":", true age may be older"}`:""}</div>
        ${i!=null&&i.fetchErrorOccurred?'<div><span style="color:#ffb86c">\u26A0</span> A network fetch error occurred during history pagination \u2014 some transactions may be missing</div>':""}
      </div>
    </div>`;r.innerHTML=`
    <div style="display:flex;align-items:flex-start;gap:16px;flex-wrap:wrap">
      <div style="text-align:center;flex-shrink:0">
        <div style="font-size:2.2rem;font-weight:900;color:${u};line-height:1">${e}</div>
        <div style="font-size:.65rem;font-weight:800;color:${u};letter-spacing:.1em;text-transform:uppercase">${d}</div>
      </div>
      <div style="flex:1;min-width:200px">
        <div style="font-size:.92rem;color:rgba(255,255,255,.88);line-height:1.6;margin-bottom:6px">${y(g)}</div>
        <div style="font-size:.8rem;color:rgba(255,255,255,.45);line-height:1.5">${y(v)}</div>
        ${l.length||c.length?`
        <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
          ${l.length?`<span style="background:rgba(255,85,85,.12);border:1px solid rgba(255,85,85,.3);color:#ff5555;border-radius:999px;padding:2px 10px;font-size:.72rem;font-weight:700">${l.length} Critical</span>`:""}
          ${c.length?`<span style="background:rgba(255,184,108,.10);border:1px solid rgba(255,184,108,.25);color:#ffb86c;border-radius:999px;padding:2px 10px;font-size:.72rem;font-weight:700">${c.length} Warnings</span>`:""}
          <button onclick="document.getElementById('section-report')?.scrollIntoView({behavior:'smooth'})"
            style="background:rgba(0,212,255,.08);border:1px solid rgba(0,212,255,.2);color:var(--accent);border-radius:999px;padding:2px 10px;font-size:.72rem;cursor:pointer">Full Report \u2193</button>
        </div>`:""}
      </div>
    </div>
    ${k}
    ${$}`}function R0(e,t){let n=document.getElementById("change-banner");if(!n)return;n.style.display="none";let a=io().find(d=>d.addr===e);if(!(a!=null&&a.fingerprint))return;let o=new Set(t.filter(d=>d.sev==="critical"||d.sev==="warn").map(d=>d.module+":"+d.headline.slice(0,40))),i=new Set((a.fingerprint||"").split("|").filter(Boolean)),r=[...o].filter(d=>!i.has(d)),l=[...i].filter(d=>!o.has(d));if(!r.length&&!l.length)return;let c=ro(a.ts),u=[];r.length&&u.push(`<span style="color:#ff5555">+${r.length} new finding${r.length>1?"s":""}</span>`),l.length&&u.push(`<span style="color:#50fa7b">${l.length} resolved</span>`),n.style.display="",n.innerHTML=`
    <div style="background:rgba(255,184,108,.07);border:1px solid rgba(255,184,108,.25);border-radius:10px;
                padding:10px 14px;margin-bottom:10px;display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <span style="font-size:1rem">\u{1F514}</span>
      <span style="font-size:.84rem;color:rgba(255,255,255,.75)">
        Since last inspection <strong>${c}</strong>: ${u.join(", ")}
        ${r.length?"\u2014 "+r.slice(0,2).map(d=>d.split(":")[1]).join("; "):""}
      </span>
      <button onclick="document.getElementById('change-banner').style.display='none'" aria-label="Dismiss"
        style="margin-left:auto;background:none;border:none;color:rgba(255,255,255,.35);font-size:.9rem;cursor:pointer">\u2715</button>
    </div>`}function na(){let e=document.getElementById("isd-watchlist-section"),t=document.getElementById("isd-watchlist-list");if(!e||!t)return;let n=ta();if(!n.length){e.style.display="none";return}e.style.display="",t.innerHTML=n.map(s=>{let a=s.addr.slice(0,8)+"\u2026"+s.addr.slice(-6),o=s.lastScore!=null?`<span class="isd-risk-pill isd-risk-pill--${Ju(s.lastScore)}">${s.lastScore}</span>`:"",i=s.lastTs?ro(s.lastTs):"never checked";return`
      <div class="isd-recent-row" style="align-items:center">
        <button class="isd-recent-addr mono" style="flex:1;text-align:left;background:none;border:none;cursor:pointer;color:inherit"
          onclick="inspectorLoadAddr('${y(s.addr)}')">${y(s.label||a)} <span style="opacity:.45;font-size:.75em">${a}</span></button>
        <div style="display:flex;align-items:center;gap:8px">
          ${o}
          <span style="font-size:.72rem;opacity:.45">${i}</span>
          <button onclick="_removeFromWatchlistUI('${y(s.addr)}')" aria-label="Remove ${y(s.label||a)} from watchlist"
            style="background:none;border:none;color:rgba(255,85,85,.6);font-size:.85rem;cursor:pointer;padding:2px 4px">\u2715</button>
        </div>
      </div>`}).join("")}window._removeFromWatchlistUI=function(e){Ku(e),na()};function Qu(e){let t=document.getElementById("watchlist-btn");if(!t)return;let n=er(e);t.textContent=n?"\u2605 Watching":"\u2606 Watch",t.title=n?"Remove from watchlist":"Add to watchlist",t.style.color=n?"#ffb86c":"",t.onclick=()=>{er(e)?Ku(e):C0(e,null),Qu(e),na()}}function Au(e,t="inspect-activity-chart"){let n=document.getElementById(t);if(!n)return;if(!e.length){n.innerHTML='<div style="opacity:.4;font-size:.8rem;padding:10px 0">No transaction history to chart.</div>';return}let s=946684800,a={Payment:"#50fa7b",OfferCreate:"#00d4ff",OfferCancel:"#8be9fd",NFTokenMint:"#bd93f9",NFTokenCreateOffer:"#bd93f9",NFTokenAcceptOffer:"#ff79c6",AMMDeposit:"#ffb86c",AMMWithdraw:"#ffb86c",AMMCreate:"#ffb86c",SetRegularKey:"#ff5555",SignerListSet:"#ff5555",AccountSet:"#f1fa8c"},o="rgba(255,255,255,.25)",i={};for(let{tx:f}of e){if(!f.date)continue;let g=new Date((f.date+s)*1e3),v=new Date(g.getFullYear(),0,1),h=Math.ceil(((g-v)/864e5+v.getDay()+1)/7),b=`${g.getFullYear()}-${String(h).padStart(2,"0")}`;i[b]||(i[b]={count:0,types:{}}),i[b].count++;let x=f.TransactionType||"Other";i[b].types[x]=(i[b].types[x]||0)+1}let r=Object.entries(i).sort((f,g)=>f[0].localeCompare(g[0]));if(r.length<2){n.innerHTML='<div style="opacity:.4;font-size:.8rem;padding:10px 0">Not enough dated transactions for timeline.</div>';return}let l=Math.max(...r.map(([,f])=>f.count),1),c=Math.max(3,Math.min(16,Math.floor(600/r.length))),u=1,d=60,p=r.length*(c+u),m=r.map(([f,g])=>{var k;let v=Math.max(2,Math.round(g.count/l*d)),h=d-v,b=((k=Object.entries(g.types).sort((T,S)=>S[1]-T[1])[0])==null?void 0:k[0])||"Other",x=a[b]||o;return`<rect x="0" y="${h}" width="${c}" height="${v}" fill="${x}" opacity=".8" rx="1">
      <title>${f}: ${g.count} tx (dominant: ${b})</title></rect>`}).join("");n.innerHTML=`
    <div style="font-size:.65rem;color:rgba(255,255,255,.35);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">
      Activity Timeline \u2014 ${r.length} weeks \xB7 ${e.length.toLocaleString()} transactions
    </div>
    <div style="overflow-x:auto;padding-bottom:4px">
      <svg width="${p}" height="${d}" xmlns="http://www.w3.org/2000/svg" style="display:block;min-width:${p}px">
        ${r.map(([,f],g)=>{var k;let v=Math.max(2,Math.round(f.count/l*d)),h=d-v,b=((k=Object.entries(f.types).sort((T,S)=>S[1]-T[1])[0])==null?void 0:k[0])||"Other",x=a[b]||o;return`<rect x="${g*(c+u)}" y="${h}" width="${c}" height="${v}"
            fill="${x}" opacity=".8" rx="1">
            <title>${r[g][0]}: ${f.count} tx (${b})</title></rect>`}).join("")}
      </svg>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:5px">
      ${Object.entries(a).slice(0,8).map(([f,g])=>`<span style="font-size:.62rem;color:${g};opacity:.7">\u25CF ${f}</span>`).join("")}
    </div>`}function Zu(e,t){let n=new Map;for(let{tx:s,meta:a}of e){let o=s.Account===t,i=s.Destination===t;if(!o&&!i)continue;let r=o?s.Destination:s.Account;if(!r||r===t)continue;let l=Wn(s);n.has(r)||n.set(r,{cnt:0,xrpOut:0,xrpIn:0,entity:zn(r),firstSeen:l,lastSeen:l});let c=n.get(r);c.cnt++,l&&(c.firstSeen=c.firstSeen?Math.min(c.firstSeen,l):l,c.lastSeen=Math.max(c.lastSeen,l));let u=(a==null?void 0:a.delivered_amount)||s.Amount,d=typeof u=="string"?Number(u)/1e6:0;o?c.xrpOut+=d:c.xrpIn+=d}return n}function _0(e,t,n=15){let s=Zu(e,t),a=[...s.entries()].sort((r,l)=>l[1].xrpOut+l[1].xrpIn-(r[1].xrpOut+r[1].xrpIn)||l[1].cnt-r[1].cnt).slice(0,n);if(!a.length)return'<div class="inspect-empty-note">No counterparty interactions found.</div>';let o=Math.max(...a.map(([,r])=>r.xrpOut+r.xrpIn),1),i=a.map(([r,l],c)=>{var h;let u=l.xrpOut+l.xrpIn,d=Math.max(1.5,u/o*100),p=yn[(h=l.entity)==null?void 0:h.type]||yn.other,m=u>0?l.xrpOut/u:.5,f=m>.65?"\u2192 out":m<.35?"\u2190 in":"\u21C4 both",g=l.entity?`<span style="font-size:.64rem;color:${p};border:1px solid ${p};border-radius:999px;padding:1px 7px;margin-left:6px">${y(l.entity.name)}</span>`:"",v=qu(l.firstSeen,l.lastSeen);return`
      <div style="display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.05)">
        <div style="width:18px;text-align:center;font-size:.7rem;color:rgba(255,255,255,.35);flex-shrink:0">${c+1}</div>
        <div style="width:150px;flex-shrink:0;overflow:hidden">
          <div style="display:flex;align-items:center">
            <span class="mono" style="font-size:.76rem;color:rgba(255,255,255,.85)" title="${y(r)}">${y(z(r))}</span>
            ${g}
          </div>
          ${v?`<div style="font-size:.62rem;color:rgba(255,255,255,.35);margin-top:1px">${y(v)}</div>`:""}
        </div>
        <div style="flex:1;height:10px;border-radius:4px;overflow:hidden;background:rgba(255,255,255,.05)">
          <div style="width:${d.toFixed(1)}%;height:100%;background:${p}"></div>
        </div>
        <div style="width:46px;text-align:center;font-size:.66rem;color:rgba(255,255,255,.5);flex-shrink:0">${f}</div>
        <div class="mono" style="width:100px;text-align:right;font-size:.75rem;color:rgba(255,255,255,.8);flex-shrink:0">${_(u,2)} XRP</div>
        <div style="width:46px;text-align:right;font-size:.68rem;color:rgba(255,255,255,.4);flex-shrink:0">${l.cnt} tx</div>
      </div>`}).join("");return`
    <div style="font-size:.65rem;color:rgba(255,255,255,.35);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px">
      Top Counterparties \u2014 ${a.length} of ${s.size} addresses, ranked by volume
    </div>
    ${i}`}function D0(e,t,n,s,a="inspect-network-map"){let o=document.getElementById(a);if(!o)return;let r=[...Zu(e,t).entries()].sort(($,E)=>E[1].xrpOut+E[1].xrpIn-($[1].xrpOut+$[1].xrpIn)||E[1].cnt-$[1].cnt).slice(0,20);if(r.length<2){o.style.display="",o.innerHTML=`<div class="inspect-empty-note">${r.length===0?"No counterparty interactions found.":"Only one counterparty found \u2014 not enough to chart a network map."}</div>`;return}o.style.display="";let l=560,c=340,u=l/2,d=c/2,p=95,m=7,f=155,g=13,v=r[0][1].xrpOut+r[0][1].xrpIn||1,h=r[0][1].cnt||1,b=[{id:t,x:u,y:d,r:13,main:!0,label:z(t),color:"#00d4ff",xrpOut:0,xrpIn:0,cnt:0}];r.forEach(([$,E],C)=>{let P=C<m?p:f,R=C<m?m:g,D=(C<m?C:C-m)/R*2*Math.PI-Math.PI/2,I=E.xrpOut+E.xrpIn,F=Math.max(5,Math.min(14,4+I/v*10)),H=E.entity,N=yn[H==null?void 0:H.type]||yn.other,j=I>0?E.xrpOut/I:.5,se=j>.65?"out":j<.35?"in":"both";b.push({id:$,x:u+P*Math.cos(D),y:d+P*Math.sin(D),r:F,color:N,label:(H==null?void 0:H.name)||z($),ent:H,xrpOut:E.xrpOut,xrpIn:E.xrpIn,cnt:E.cnt,dir:se,vol:I,ring:P})});let x=`<defs>
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
  </defs>`,k=b.slice(1).map($=>{let E=$.vol/v,C=Math.max(.8,E*3),P=.12+E*.45,R=$.dir==="out"?"rgba(80,250,123,":$.dir==="in"?"rgba(0,212,255,":"rgba(255,184,108,",O=$.dir==="out"?`rgba(80,250,123,${P})`:$.dir==="in"?`rgba(0,212,255,${P})`:`rgba(255,184,108,${P})`,D=$.dir==="in"?"5,3":"none",I=`marker-end="url(#arrow-${$.dir})"`,F=$.x-u,H=$.y-d,N=Math.sqrt(F*F+H*H),j=($.r+2)/N,se=u+F*(1-j),re=d+H*(1-j),pe=`${$.xrpOut>0?"\u2192 "+_($.xrpOut,2)+" XRP out":""}${$.xrpIn>0?($.xrpOut>0?" / ":"")+"\u2190 "+_($.xrpIn,2)+" XRP in":""}, ${$.cnt} tx`;return`<line x1="${u}" y1="${d}" x2="${se.toFixed(1)}" y2="${re.toFixed(1)}"
      stroke="${O}" stroke-width="${C.toFixed(1)}" stroke-dasharray="${D}" ${I}>
      <title>${pe}</title></line>`}).join(""),T=b.map($=>{var H,N;if($.main){let j=z($.id);return`<g>
        <title>Inspected account: ${y($.id)}</title>
        <circle cx="${u}" cy="${d}" r="13" fill="rgba(0,212,255,.2)" stroke="#00d4ff" stroke-width="2"/>
        <circle cx="${u}" cy="${d}" r="13" fill="rgba(0,212,255,.15)"/>
        <text x="${u}" y="${d+4}" text-anchor="middle" font-size="6.5" fill="#00d4ff" font-weight="800">${y(j)}</text>
        <text x="${u}" y="${d+13+10}" text-anchor="middle" font-size="6"
          fill="rgba(255,255,255,.4)">Inspected account</text>
      </g>`}let E=((H=$.ent)==null?void 0:H.type)==="blackhole",C=((N=$.ent)==null?void 0:N.type)==="exchange",P=E?'filter="url(#glow-red)"':"",R=$.dir==="out"?"rgba(80,250,123,.5)":$.dir==="in"?"rgba(0,212,255,.5)":"rgba(255,184,108,.5)",O=1.5,D=$.label.length>14?$.label.slice(0,14)+"\u2026":$.label,I=$.vol>0?$.xrpOut>0&&$.xrpIn>0?`\u21C4 ${_($.vol,0)} XRP`:$.xrpOut>0?`\u2192 ${_($.xrpOut,0)} XRP`:`\u2190 ${_($.xrpIn,0)} XRP`:`${$.cnt} tx`,F=$.id+($.ent?" ("+$.ent.name+")":"")+" | "+($.xrpOut>0?"Sent: "+_($.xrpOut,2)+" XRP"+wn($.xrpOut)+" | ":"")+($.xrpIn>0?"Received: "+_($.xrpIn,2)+" XRP"+wn($.xrpIn)+" | ":"")+"Interactions: "+$.cnt;return`<g style="cursor:pointer" onclick="inspectorLoadAddr('${$.id}')">
      <title>${F}</title>
      ${E?`<circle cx="${$.x}" cy="${$.y}" r="${$.r+4}" fill="rgba(255,85,85,.1)" stroke="rgba(255,85,85,.4)" stroke-width="1" stroke-dasharray="3,2"/>`:""}
      <circle cx="${$.x}" cy="${$.y}" r="${$.r}" fill="${$.color}" opacity=".18" ${P}/>
      <circle cx="${$.x}" cy="${$.y}" r="${$.r}" fill="${$.color}" opacity=".1" stroke="${R}" stroke-width="${O}"/>
      <text x="${$.x}" y="${$.y+3.5}" text-anchor="middle" font-size="${$.ring===p?7.5:6.5}"
        fill="${$.color}" font-weight="700" opacity=".95">${y(D)}</text>
      <text x="${$.x}" y="${$.y+$.r+10}" text-anchor="middle" font-size="6"
        fill="rgba(255,255,255,.4)">${y(I)}</text>
    </g>`}).join(""),S=`
    <text x="${u}" y="${d-p-8}" text-anchor="middle" font-size="6"
      fill="rgba(255,255,255,.15)" font-style="italic">inner ring</text>
    <text x="${u}" y="${d-f-8}" text-anchor="middle" font-size="6"
      fill="rgba(255,255,255,.10)" font-style="italic">outer ring</text>`;o.innerHTML=`
    <div style="font-size:.65rem;color:rgba(255,255,255,.35);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px">
      Counterparty Network Map \u2014 ${r.length} addresses \xB7 click any node to inspect
    </div>
    <div style="overflow-x:auto">
      <svg width="${l}" height="${c}" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${l} ${c}"
        style="display:block;border-radius:10px;background:rgba(255,255,255,.015);border:1px solid rgba(255,255,255,.06);min-width:${Math.min(l,360)}px">
        ${x}${S}${k}${T}
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
    </div>`}function I0(){let e=window._lastInspectResult,t=window._lastAllFindings||[];if(!e)return null;let n=t.length?t.map(a=>`- [${a.sev.toUpperCase()}] ${a.module}: ${a.headline}${a.detail?" \u2014 "+a.detail:""}`).join(`
`):"(No elevated findings \u2014 all checks returned normal ranges.)",s=e.walletAgeDays!=null?e.walletAgeVerified?" (verified \u2014 full history confirmed)":" (estimated \u2014 full history not confirmed, true age may be older)":"";return`XRPL ACCOUNT FORENSIC ANALYSIS
Account: ${e.addr}
Risk score: ${e.riskScore}/100
Wallet age: ${e.walletAgeDays!=null?e.walletAgeDays+" days":"unknown"}${s}
Transactions analyzed: ${e.txCount}
Snapshot taken: ${e.timestamp}

Automated findings from a rule-based XRPL forensics scan:
${n}

---
You are acting as a security analyst explaining automated blockchain forensics findings to someone who isn't a blockchain expert. Write a clear, plain-English explanation of what this account's activity suggests. Synthesize the findings above into a coherent read of the account rather than restating them one by one \u2014 call out which ones reinforce each other and which are weak signals on their own. Be direct about how concerning (or not) this looks, and be skeptical of your own confidence where the evidence is thin rather than overstating it. Do not repeat the address or risk score back verbatim; the reader can already see those above your response.`}window.copyInspectorAnalysisForAi=function(){let e=document.getElementById("ai-explanation-body"),t=I0();if(!t){e&&(e.innerHTML='<p style="font-size:.82rem;color:#ff5555">Run an inspection first.</p>');return}zs(t)};window.exportInspectorJSON=function(){var o,i;let e=window._lastInspectResult;if(!e){alert("Run an inspection first.");return}let t=new Blob([JSON.stringify(e,null,2)],{type:"application/json"}),n=URL.createObjectURL(t),s=document.createElement("a"),a=((i=(o=document.getElementById("inspect-addr-badge"))==null?void 0:o.dataset)==null?void 0:i.fullAddr)||"wallet";s.href=n,s.download=`naluxrp_${a.slice(0,10)}_${new Date().toISOString().slice(0,10)}.json`,document.body.appendChild(s),s.click(),document.body.removeChild(s),URL.revokeObjectURL(n)};var F0=6e4,O0=1e4,B0=12e4,X0=8e3,H0=12e4,z0=300,pm="nalulf_net_baseline_v2",j0=80,W0=5,oa="/api/v1/validatorregistry",um="/api/v1/validator";var U0=5*60*1e3,mm=10*60*1e3,em=1e4,fm=8e3,dr=new Map,pr=new Map;var nn={quorumTight:{w:3,label:"Quorum within 3 validators of failure threshold"},nUnlActive:{w:2,label:"Negative UNL active \u2014 validators currently being ignored"},amendVeto:{w:1,label:"Amendment veto clustering \u2014 protocol governance dispute"},feeSpike:{w:2,label:"Open ledger fee 10\xD7 minimum \u2014 DDoS / spam attack likely"},burnAnomaly:{w:2,label:"XRP burn rate z-score > 3\u03C3 \u2014 resource exhaustion pattern"},peerSaturate:{w:2,label:"Inbound peers > 80% of connections \u2014 Eclipse Attack risk"},eclipseRisk:{w:3,label:"Peer count < 6 \u2014 node highly vulnerable to isolation"},dexSpike:{w:1,label:"DEX volume > 3\xD7 AMM baseline \u2014 unusual event-driven flow"},reserveSpike:{w:1,label:"New account rate > 3\xD7 baseline \u2014 possible bot creation"},slowConverge:{w:2,label:"Consensus convergence > 6s \u2014 network agreement degraded"},lowProposers:{w:2,label:"Proposer count below quorum \u2014 validator participation low"},queuePressure:{w:2,label:"TX queue > 80% full \u2014 fee surge imminent"},spamLedger:{w:1,label:"Ledger > 2\xD7 expected size \u2014 ledger spam in progress"},ioStressed:{w:1,label:"Node IO latency > 5ms \u2014 storage or network I/O stress"},peerChurn:{w:1,label:"Elevated peer disconnect rate \u2014 DDoS or instability"},staleLedger:{w:3,label:"Ledger age > 10s \u2014 validation appears stalled"}},hm={MultiSign:{purpose:"Multi-signature authorization",intro:"rippled 0.31",desc:"Lets multiple keys jointly authorize one transaction. Essential for institutional custody and hardware-wallet setups.",impact:"New transaction: SignerListSet. All signers submit their signature; the last one broadcasts."},MultiSignReserve:{purpose:"Cheaper signer-list reserve",intro:"rippled 1.2",desc:"Cuts the owner reserve for SignerList objects from 5 owner-items (10 XRP) down to 1 owner-item (2 XRP).",impact:"Existing SignerLists do not gain the reduction automatically; delete and re-create the list."},DepositAuth:{purpose:"Block unsolicited incoming payments",intro:"rippled 0.90",desc:"An account can set lsfDepositAuth so it only receives payments explicitly pre-authorized via DepositPreauth.",impact:"Senders to un-authorized accounts receive tecNO_PERMISSION."},DeletableAccounts:{purpose:"Permanent account deletion + reserve reclaim",intro:"rippled 1.4",desc:"An account with no objects and sequence \u2265 (current ledger \u2212 256) can permanently delete itself and recover the base reserve.",impact:"New transaction: AccountDelete. Sends all XRP minus fees to a destination."},NegativeUNL:{purpose:"Fault-tolerant consensus during outages",intro:"rippled 1.6",desc:"When validators are persistently offline, the network may add them to the Negative UNL so they do not count against quorum.",impact:"Enables the network to survive planned outages of up to 20% of trusted validators."},Checks:{purpose:"Deferred, cancellable payments",intro:"rippled 1.0",desc:"The sender creates a Check; the recipient can later cash it up to the authorized amount or let it expire. The sender can cancel at any time.",impact:"New transactions: CheckCreate, CheckCash, CheckCancel. Each open Check uses one owner-reserve slot."},AMM:{purpose:"Native Automated Market Maker DEX",intro:"rippled 1.12",desc:"Adds a Constant-Product (x*y=k) AMM directly in the ledger. Anyone can deposit two assets to earn LP tokens and a share of swap fees.",impact:"New transactions: AMMCreate, AMMDeposit, AMMWithdraw, AMMVote, AMMBid, AMMDelete."},XChainBridge:{purpose:"Cross-chain bridge protocol",intro:"rippled 2.0",desc:"Lets assets move between XRPL Mainnet, sidechains, and EVM chains via a locking/minting bridge secured by Witness servers.",impact:"New ledger objects: Bridge, XChainOwnedCreateAccountClaimID, etc. Requires Witness infrastructure."},Clawback:{purpose:"Token-issuer recovery",intro:"rippled 1.12",desc:"Issuers who set lsfAllowTrustLineClawback before issuing tokens can claw back tokens from any holder.",impact:"Must be enabled on a fresh account before any trust lines are created."},NonFungibleTokensV1:{purpose:"Native NFT support",intro:"rippled 1.9",desc:"Adds NFTokenMint, NFTokenBurn, and offer-based transfer mechanics for non-fungible tokens stored in NFTokenPage objects.",impact:"Each NFTokenPage holds up to 32 tokens and costs one owner-reserve slot. Royalties up to 50%."},NonFungibleTokensV1_1:{purpose:"NFT V1 corrections",intro:"rippled 1.10",desc:"Fixes pagination bugs, transfer-fee edge cases, and minting with the URI field that were present in V1.",impact:"Breaking fix for some V1 edge cases. Wallets built for V1 should test V1_1 compatibility."},PayChan:{purpose:"Payment channels for streaming micropayments",intro:"rippled 0.33",desc:"Sender deposits XRP into a channel, then issues signed claims off-ledger. Recipient submits the highest claim at any time to settle on-ledger.",impact:"New transactions: PaymentChannelCreate, PaymentChannelFund, PaymentChannelClaim."},Escrow:{purpose:"Time-locked and condition-based XRP transfers",intro:"rippled 0.60",desc:"Lock XRP until a future time OR a cryptographic fulfillment (PREIMAGE-SHA-256) is revealed, enabling vesting schedules and atomic swaps.",impact:"New transactions: EscrowCreate, EscrowFinish, EscrowCancel. Locked XRP counts against reserves."},DisallowIncoming:{purpose:"Block unsolicited ledger-object creation",intro:"rippled 1.10",desc:"New account flags let you individually block incoming Trust Lines, Check objects, NFToken offers, and Payment Channels.",impact:"Four new AccountSet flags; existing incoming objects are unaffected."},ExpandedSignerList:{purpose:"Larger multi-sig signer lists",intro:"rippled 1.9.1",desc:"Increases the maximum signers per SignerList from 8 to 32, enabling more complex institutional multi-sig and DAO governance.",impact:"Reserve cost scales with signer count. Requires MultiSignReserve to be cost-effective."},OwnerPaysFee:{purpose:"Correct fee payer in PayChan",intro:"rippled 0.33",desc:"Fixes a spec inconsistency where the channel owner correctly pays the transaction fee when closing or expiring channels.",impact:"Purely a fee-accounting fix; no user-visible behavior changes."},fixMasterKeyAsRegularKey:{purpose:"Master-key mis-use bug fix",intro:"rippled 0.90",desc:"Prevents accounts from setting their master key as their regular key \u2014 an operation that could create an unusable account state.",impact:"No application changes needed; existing accounts are not affected."},TrustSetAuth:{purpose:"Authorized trust lines",intro:"rippled 0.30",desc:"Issuers can require explicit authorization before anyone can hold their token \u2014 a prerequisite for regulatory-grade stablecoins.",impact:"New flow: issuer sends TrustSet with tfSetfAuth to approve each holder."}},tm=new Set(["xrpscan.com","xrpl.aesthetes.art","xrpkuwait.com","xrpgoat.com","xrp.vet","xrp.unic.ac.cy","xrp-validator.interledger.org","xpmarket.com","verum.eminence.im","validator.xrpl.robertswarthout.com","validator.xrpl-labs.com","validator.poli.usp.br","validator.gatehub.net","validator.aspired.nz","v2.xrpl-commons.org","tequ.dev","squidrouter.com","ripple.ittc.ku.edu","ripple.com","peersyst.cloud","onxrp.com","katczynski.net","jon-nilsen.no","ekiserrepe.es","cabbit.tech","bithomp.com","aureusox.com","arrington-xrp-capital.blockdaemon.com","anodos.finance","bitso.com","ripple.kenan-flagler.unc.edu","ripplevalidator.uwaterloo.ca","shadow.haas.berkeley.edu","www.bitrue.com","xrp-col.anu.edu.au"]),q0=new Set(["nHBu3iuq1SQ9Z686pYwWYVKpScSMDWfpUJHdNEQRxn5XyETui7Db","nHDwBbubxJswoweWQKEgWLNRJv2hNRCTR4GGApJmbtCcbtYNSpdB","nHU2FpRbPrvVcyQQpkqrAUDJDTRHZpjij8DpKeSC481PYY9ikYkb","nHUbmg8QNzEGjHzgnt99e9YE2scU3DZGH7FsF6MCcK5eiPt3AtaH","nHUxBD1UPb383SdWgJx62GGQ7W2WKvgpUtUXLjiGGRRcPb3nbSXd","nHUP6rfQfgzg6tKga3k9ziEvtjwn1PB32gcr5dLcamqzmitszYv2","nHBT58yHyDdPdJ6gzaBMT7gqwTMpj5ERji1s9SvfKKtfoZUS89WX","nHBxsUzx3Bbf6J4yJ3fLQ3VizPtdREVwTJ6mdqkuDTjLcVbggVbk","nHUeUNSn3zce2xQZWNghQvd9WRH6FWEnCBKYVJu2vAizMxnXegfJ","nHUCAdca6VoWWYVdBH1bwCUQggEX2e5acQSqxM3DwyuhsFknxmh3","nHDDiwQBqXhEL1CFoRHdMXD33x9K7rpYJfniXxL7kFavpPd21EGe","nHBipbbREjNEiCs4hpy3K2489dRf27MPnxdivTTWKSd8ZUhfRvn8","nHDDe5uAdiv6RA59MA1oM4JLDtVSYKNShgjEqq1KsdJXZiR47CQT","nHBbiP5ua5dUqCTz5i5vd3ia9jg3KJthohDjgKxnc7LxtmnauW7Z","nHBQ3CT3EWYZ4uzbnL3k6TRf9bBPhWRFVcK1F5NjtwCBksMEt5yy","nHU16DF2kq7TmbR1Y5z8yKNXiLEf3oHT19HVpVXv7unFLfxa17nT","nHUC23NnutZyYeQxQbAbPUpKoVGj5aisBxf2zzcZzJ43fcw5rc9z","nHUgdMvuchx7AWG4ATMQdNNuMryo1SFoNptLCEVt2Dn7wEc625mF","nHUhQVE93dajM3srxubsEj1mK1gzRwJob14QSrJefY1FdLs6r7WJ","nHUU8xBczYzW6kZ6Ei9DsggzTJXRFkN3wE3FP5H4SLYzhbodeYcG","nHUGqooyfGqFkyH6uskbaEi6y2MjXjdA7QdbmyZ6p9etL5isRKLT","nHDp1ZXxEn7eo5YaUtiagaxSLwXudnKZDx68C96p4tdVLGLLLUFn","nHBcLEB4S6moQGrhMjJo1jbp58WL5psHY9EMDWNAtdqykUYiA1rF","nHUAECq1v1cKwn3NsYVyD7v6BNbfqyXmNVSF3e4XCVxPgBHRWkvv","nHUif4sukXu9pJGyyBaeVMwmE8L1fJ5KJj4X4ksgTKhgjG6k96s2","nHUVJR7SeT3nn6JPTz46JHqYRf7vX2if1sdTxnceywmSBWa167pt","nHUEYz4TtTv7yebjhY3aDib5KYPHnKjnY5mPYK5y4QuKdocwS5tD","nHUN5n2S3nQ8bzKm7bqeFMiQeDijh1LMgEocyNyQbb4mREazVdZ5","nHUgchANqM3giYSSvY5HsafFW6qxmG5jJ3CvPiv7n8gjNQuNm8Uz","nHDUqGoM7KR1pgbdYBRgKpGKdFLhpnMzVbECs8RE73RGZm3Va6MJ","nHUVxTi8XfXjaaJppw7mLSrYDRpkDpf8H9ypzgVKxfSXShcWwAoK","nHBveTxA1NaBj5AayRAU91f6YopuFWt9rmxfGaEh77a32Q6ZzzHc"]),V0=new Set(["validator.pftperry.com","rip973.com","preaware.org","postfiat.org","pftmeech.xyz","pft.xbtseal.com","pft.wizbubba.xyz","pft.permanentupperclass.com","pft.g.money","pft.akirax.xyz","jollydinger.com","auri0x.io","app.w.ai"]);function gm(e,t){let n=(t||"").toLowerCase().replace(/^www\./,"");return q0.has(e)||V0.has(n)?{chain:"test",isUnl:!1}:tm.has(n)||tm.has("www."+n)?{chain:"main",isUnl:!0}:{chain:"main",isUnl:!1}}var yr={"xrpscan.com":{label:"XRP Scan",domain:"xrpscan.com",chain:"main",category:"unl"},"xrpl.aesthetes.art":{label:"Aesthetes",domain:"xrpl.aesthetes.art",chain:"main",category:"unl"},"xrpkuwait.com":{label:"XRP Kuwait",domain:"xrpkuwait.com",chain:"main",category:"unl"},"xrpgoat.com":{label:"XRP Goat",domain:"xrpgoat.com",chain:"main",category:"unl"},"xrp.vet":{label:"XRP Vet",domain:"xrp.vet",chain:"main",category:"unl"},"xrp.unic.ac.cy":{label:"Univ. of Nicosia",domain:"xrp.unic.ac.cy",chain:"main",category:"unl"},"xrp-validator.interledger.org":{label:"Interledger",domain:"xrp-validator.interledger.org",chain:"main",category:"unl"},"xpmarket.com":{label:"XPMarket",domain:"xpmarket.com",chain:"main",category:"unl"},"verum.eminence.im":{label:"Eminence",domain:"verum.eminence.im",chain:"main",category:"unl"},"validator.xrpl.robertswarthout.com":{label:"R. Swarthout",domain:"validator.xrpl.robertswarthout.com",chain:"main",category:"unl"},"validator.xrpl-labs.com":{label:"XRPL Labs",domain:"validator.xrpl-labs.com",chain:"main",category:"unl"},"validator.poli.usp.br":{label:"USP",domain:"validator.poli.usp.br",chain:"main",category:"unl"},"validator.gatehub.net":{label:"Gatehub",domain:"validator.gatehub.net",chain:"main",category:"unl"},"validator.aspired.nz":{label:"Aspired NZ",domain:"validator.aspired.nz",chain:"main",category:"unl"},"v2.xrpl-commons.org":{label:"XRPL Commons",domain:"v2.xrpl-commons.org",chain:"main",category:"unl"},"tequ.dev":{label:"Tequ",domain:"tequ.dev",chain:"main",category:"unl"},"squidrouter.com":{label:"Squid Router",domain:"squidrouter.com",chain:"main",category:"unl"},"ripple.ittc.ku.edu":{label:"Univ. of Kansas",domain:"ripple.ittc.ku.edu",chain:"main",category:"unl"},"ripple.com":{label:"Ripple",domain:"ripple.com",chain:"main",category:"unl"},"peersyst.cloud":{label:"Peersyst",domain:"peersyst.cloud",chain:"main",category:"unl"},"onxrp.com":{label:"OnXRP",domain:"onxrp.com",chain:"main",category:"unl"},"katczynski.net":{label:"Katczynski",domain:"katczynski.net",chain:"main",category:"unl"},"jon-nilsen.no":{label:"Jon Nilsen",domain:"jon-nilsen.no",chain:"main",category:"unl"},"ekiserrepe.es":{label:"Ekiserrepe",domain:"ekiserrepe.es",chain:"main",category:"unl"},"cabbit.tech":{label:"Cabbit",domain:"cabbit.tech",chain:"main",category:"unl"},"bithomp.com":{label:"Bithomp",domain:"bithomp.com",chain:"main",category:"unl"},"aureusox.com":{label:"Aureus Ox",domain:"aureusox.com",chain:"main",category:"unl"},"arrington-xrp-capital.blockdaemon.com":{label:"Arrington / Blockdaemon",domain:"arrington-xrp-capital.blockdaemon.com",chain:"main",category:"unl"},"anodos.finance":{label:"Anodos Finance",domain:"anodos.finance",chain:"main",category:"unl"},"bitso.com":{label:"Bitso",domain:"bitso.com",chain:"main",category:"unl"},"ripple.kenan-flagler.unc.edu":{label:"UNC Kenan-Flagler",domain:"ripple.kenan-flagler.unc.edu",chain:"main",category:"unl"},"ripplevalidator.uwaterloo.ca":{label:"Univ. of Waterloo",domain:"ripplevalidator.uwaterloo.ca",chain:"main",category:"unl"},"shadow.haas.berkeley.edu":{label:"UC Berkeley Haas",domain:"shadow.haas.berkeley.edu",chain:"main",category:"unl"},"www.bitrue.com":{label:"Bitrue",domain:"www.bitrue.com",chain:"main",category:"unl"},"xrp-col.anu.edu.au":{label:"ANU",domain:"xrp-col.anu.edu.au",chain:"main",category:"unl"},"xrpval.rawsec.de":{label:"Rawsec",domain:"xrpval.rawsec.de",chain:"main",category:"other"},"xrplvl.carbonvibe.com":{label:"Carbon Vibe",domain:"xrplvl.carbonvibe.com",chain:"main",category:"other"},"xrplvalidator.alloy.ee":{label:"Alloy",domain:"xrplvalidator.alloy.ee",chain:"main",category:"other"},"xrpl.uni.lu":{label:"Univ. of Luxembourg",domain:"xrpl.uni.lu",chain:"main",category:"other"},"xrpl.to":{label:"XRPL.to",domain:"xrpl.to",chain:"main",category:"other"},"xrpl.su":{label:"XRPL.su",domain:"xrpl.su",chain:"main",category:"other"},"xrpl.sbivc.co.jp":{label:"SBI VC Trade",domain:"xrpl.sbivc.co.jp",chain:"main",category:"other"},"xrpl-verification.flare.network":{label:"Flare Network",domain:"xrpl-verification.flare.network",chain:"main",category:"other"},"xrpl-validator.7rev.dev":{label:"7Rev",domain:"xrpl-validator.7rev.dev",chain:"main",category:"other"},"xrp.teacopula.com":{label:"Teacopula",domain:"xrp.teacopula.com",chain:"main",category:"other"},"xrp.moneymindedapes.com":{label:"MoneyMindedApes",domain:"xrp.moneymindedapes.com",chain:"main",category:"other"},"xrp.hazza-systems.de":{label:"Hazza Systems",domain:"xrp.hazza-systems.de",chain:"main",category:"other"},"xrp.cs.uoregon.edu":{label:"Univ. of Oregon",domain:"xrp.cs.uoregon.edu",chain:"main",category:"other"},"xrp.bpsqn.com":{label:"BPSQN",domain:"xrp.bpsqn.com",chain:"main",category:"other"},"xrp-validator.grapedrop.xyz":{label:"Grapedrop",domain:"xrp-validator.grapedrop.xyz",chain:"main",category:"other"},"xaodao.io":{label:"XaoDAO",domain:"xaodao.io",chain:"main",category:"other"},"vl.xrpsalute.com":{label:"XRP Salute",domain:"vl.xrpsalute.com",chain:"main",category:"other"},"validator.xrpl.app":{label:"XRPL App",domain:"validator.xrpl.app",chain:"main",category:"other"},"validator.ukcbt.org":{label:"UKCBT",domain:"validator.ukcbt.org",chain:"main",category:"other"},"validator.sugarxrpl.com":{label:"SugarXRPL",domain:"validator.sugarxrpl.com",chain:"main",category:"other"},"validator.boscaern.digital":{label:"Boscaern",domain:"validator.boscaern.digital",chain:"main",category:"other"},"trimaera.tech":{label:"Trimaera",domain:"trimaera.tech",chain:"main",category:"other"},"textrp.io":{label:"TextRP",domain:"textrp.io",chain:"main",category:"other"},"tesbert.com":{label:"Tesbert",domain:"tesbert.com",chain:"main",category:"other"},"tachyon-xrpl-validator.github.io":{label:"Tachyon",domain:"tachyon-xrpl-validator.github.io",chain:"main",category:"other"},"solonation.io":{label:"SoloNation",domain:"solonation.io",chain:"main",category:"other"},"smokydrip.com":{label:"SmokyDrip",domain:"smokydrip.com",chain:"main",category:"other"},"rippled-validator.us":{label:"rippled-validator.us",domain:"rippled-validator.us",chain:"main",category:"other"},"rippleat.snt.uni.lu":{label:"Univ. Luxembourg (SNT)",domain:"rippleat.snt.uni.lu",chain:"main",category:"other"},"ripple.uni.lu":{label:"Univ. Luxembourg",domain:"ripple.uni.lu",chain:"main",category:"other"},"ripple.j2b.com":{label:"J2B",domain:"ripple.j2b.com",chain:"main",category:"other"},"rich-list.info":{label:"Rich List",domain:"rich-list.info",chain:"main",category:"other"},"proptoexchange.com":{label:"ProPtoExchange",domain:"proptoexchange.com",chain:"main",category:"other"},"printscierge.com":{label:"Printscierge",domain:"printscierge.com",chain:"main",category:"other"},"opulencex.io":{label:"OpulenceX",domain:"opulencex.io",chain:"main",category:"other"},"onledger.net":{label:"OnLedger",domain:"onledger.net",chain:"main",category:"other"},"oclost.art":{label:"Oclost",domain:"oclost.art",chain:"main",category:"other"},"managednetwork.us":{label:"ManagedNetwork",domain:"managednetwork.us",chain:"main",category:"other"},"joshuahamsa.com":{label:"Joshua Hamsa",domain:"joshuahamsa.com",chain:"main",category:"other"},"grimmsxrpflow.jwscott.net":{label:"Grimm XRP Flow",domain:"grimmsxrpflow.jwscott.net",chain:"main",category:"other"},"getlol.xyz":{label:"GetLol",domain:"getlol.xyz",chain:"main",category:"other"},"gen3labs.xyz":{label:"Gen3 Labs",domain:"gen3labs.xyz",chain:"main",category:"other"},"garveyvalid.com":{label:"Garvey",domain:"garveyvalid.com",chain:"main",category:"other"},"easynpl.kr":{label:"EasyNPL",domain:"easynpl.kr",chain:"main",category:"other"},"diseb.ewi.tudelft.nl":{label:"TU Delft",domain:"diseb.ewi.tudelft.nl",chain:"main",category:"other"},"datamossa.com":{label:"DataMossa",domain:"datamossa.com",chain:"main",category:"other"},"crypto.unibe.ch":{label:"Univ. of Bern",domain:"crypto.unibe.ch",chain:"main",category:"other"},"commonprefix.com":{label:"Common Prefix",domain:"commonprefix.com",chain:"main",category:"other"},"catalyze-research.com":{label:"Catalyze Research",domain:"catalyze-research.com",chain:"main",category:"other"},"catalog.org":{label:"Catalog",domain:"catalog.org",chain:"main",category:"other"},"blockchain.korea.ac.kr":{label:"Korea Univ.",domain:"blockchain.korea.ac.kr",chain:"main",category:"other"},"astatiumprotocol.com":{label:"Astatium Protocol",domain:"astatiumprotocol.com",chain:"main",category:"other"},"ladykxrpl.mywire.org":{label:"LadyK XRPL",domain:"LadyKXRPL.mywire.org",chain:"main",category:"other"},"eelap-p1201-xrp.abudhabi.nyu.edu":{label:"NYU Abu Dhabi",domain:"EELAP-P1201-XRP.ABUDHABI.NYU.EDU",chain:"main",category:"other"},"589.clouds.hspeed.ch":{label:"HSpeed",domain:"589.clouds.hspeed.ch",chain:"main",category:"other"},"validator.pftperry.com":{label:"PFT Perry",domain:"validator.pftperry.com",chain:"test",category:"other"},"rip973.com":{label:"rip973",domain:"rip973.com",chain:"test",category:"other"},"preaware.org":{label:"Preaware",domain:"preaware.org",chain:"test",category:"other"},"postfiat.org":{label:"PostFiat",domain:"postfiat.org",chain:"test",category:"other"},"pftmeech.xyz":{label:"PFT Meech",domain:"pftmeech.xyz",chain:"test",category:"other"},"pft.xbtseal.com":{label:"PFT XBT Seal",domain:"pft.xbtseal.com",chain:"test",category:"other"},"pft.wizbubba.xyz":{label:"PFT Wizbubba",domain:"pft.wizbubba.xyz",chain:"test",category:"other"},"pft.permanentupperclass.com":{label:"PFT Perm Upper Class",domain:"pft.permanentupperclass.com",chain:"test",category:"other"},"pft.g.money":{label:"PFT G.Money",domain:"pft.g.money",chain:"test",category:"other"},"pft.akirax.xyz":{label:"PFT Akirax",domain:"pft.akirax.xyz",chain:"test",category:"other"},"jollydinger.com":{label:"Jollydinger",domain:"jollydinger.com",chain:"test",category:"other"},"auri0x.io":{label:"Auri0x",domain:"auri0x.io",chain:"test",category:"other"},"app.w.ai":{label:"W.ai",domain:"app.w.ai",chain:"test",category:"other"}},fo={nHB8QMKGt9VB4Vg71VszjBVQnDW3v3QudM4436zXRZgiuUBBSWJe:{lat:37.77,lng:-122.42,city:"San Francisco",org:"Ripple"},nHUon2tpyJEHHYGmxqNd3h3oGNQwNyX8PNS3aHe3bNpCrNXZlHo:{lat:37.77,lng:-122.41,city:"San Francisco",org:"Ripple"},nHUpwrafS45zmi6eT72XS5ijpkW5JwfL5mLdPhEibrqUvtRcMAjU:{lat:37.78,lng:-122.4,city:"San Francisco",org:"Ripple"},nHUkp7WhouVMobBUKGrV5FNqjsdD9zKP5jpGnnLfQXCMNe4dkDqo:{lat:37.76,lng:-122.43,city:"San Francisco",org:"Ripple"},nHUryiyDqEtyWVtFG24AAhaYjMf9FRLietZGBWYwUTojmugMsx3o:{lat:37.79,lng:-122.38,city:"San Francisco",org:"Ripple"},nHUpcmNsxAw47yt2ADDoNoQrzLyTJPgnyq16u6Qx2kRPA17oUNHz:{lat:37.8,lng:-122.39,city:"San Francisco",org:"Ripple"},nHUnhRJK3csknycNK5SXRFi8jvDp3sKoWvS9wKWLq1ATBBGgPBjp:{lat:37.75,lng:-122.44,city:"San Francisco",org:"Ripple"},nHUq9tJvk5QTDkwurB7EzbzkZ2uuoHjS3GKjP6pZiU3DJGnobNYK:{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"AWS (Coil)"},nHUvcCcmoH1FJMMC6NtF9KKA4LpCWhjsxk2reCQidsp5AHQ7QY9H:{lat:49.45,lng:11.08,city:"Nuremberg",org:"Hetzner (Gatehub)"},nHDH7bQJpVfDhVSqdui3Z8GPvKEBQpo6AKHcnXe21zoD4nABA6xj:{lat:52.37,lng:4.9,city:"Amsterdam",org:"GCP (XRPL Labs)"},nHUED59jjpQ5QbNtesAbB6Es3uUPv3c9Ri5MNNgfMv5t5Lhb5ndW:{lat:19.43,lng:-99.13,city:"Mexico City",org:"AWS (Bitso)"},nHBidG3pZK11zqjeVos6hFxTDPGYuqfRFZ5gu9b7tQFdB8nPZujG:{lat:35.69,lng:139.69,city:"Tokyo",org:"NTT (Digital Garage)"},nHDB2PAPYqF86j9j3c6w1F1ZqwvQfiWcFShZ9Pokg9q4ohNDSkAz:{lat:47.61,lng:-122.33,city:"Seattle, WA",org:"Azure (Arrington)"},nHUdphn3LXa31w5sLd39MQdPEKQNrNYL3DQFByijVXiNQ3G6BYBZ:{lat:1.35,lng:103.82,city:"Singapore",org:"AWS (Tokenize)"},nHUFCyRCrUjvtZmKiLeF8ReopzKuSkVzdl1VsMCqm75aqyohLYEg:{lat:48.86,lng:2.35,city:"Paris",org:"OVH (XRPL Commons)"},nHULqGBkJtWeNFjhTzYeAsHA3qKKS7HoBh8CV3BAGTGMZuepEhWC:{lat:40.71,lng:-74.01,city:"New York",org:"Equinix (Blockchain LLC)"},nHBdXSF6YHAHSZUk7rvox6jwbvvyqBnsWGcewBtq8x1XuH6KXKXr:{lat:37.79,lng:-122.4,city:"San Francisco",org:"Cloudflare (XRP Scan)"}},nm={"xrpscan.com":{lat:51.51,lng:-.13,city:"London",org:"XRPScan"},"xrpl.aesthetes.art":{lat:52.37,lng:4.9,city:"Amsterdam",org:"Aesthetes"},"xrpkuwait.com":{lat:29.37,lng:47.98,city:"Kuwait City",org:"XRP Kuwait"},"xrpgoat.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"XRP Goat"},"xrp.vet":{lat:48.86,lng:2.35,city:"Paris",org:"XRP Vet"},"xrp.unic.ac.cy":{lat:35.17,lng:33.37,city:"Nicosia",org:"Univ. of Nicosia"},"xrp-validator.interledger.org":{lat:40.71,lng:-74.01,city:"New York",org:"Interledger Foundation"},"xpmarket.com":{lat:52.37,lng:4.9,city:"Amsterdam",org:"XPMarket"},"verum.eminence.im":{lat:51.51,lng:-.13,city:"London",org:"Eminence"},"validator.xrpl.robertswarthout.com":{lat:52.37,lng:4.9,city:"Amsterdam",org:"R. Swarthout"},"validator.xrpl-labs.com":{lat:52.37,lng:4.9,city:"Amsterdam",org:"XRPL Labs"},"validator.xrpl.app":{lat:52.37,lng:4.9,city:"Amsterdam",org:"XRPL App"},"validator.poli.usp.br":{lat:-23.55,lng:-46.63,city:"S\xE3o Paulo",org:"USP"},"validator.gatehub.net":{lat:46.05,lng:14.51,city:"Ljubljana",org:"Gatehub"},"validator.aspired.nz":{lat:-36.86,lng:174.76,city:"Auckland",org:"Aspired NZ"},"v2.xrpl-commons.org":{lat:48.86,lng:2.35,city:"Paris",org:"XRPL Commons"},"tequ.dev":{lat:60.17,lng:24.94,city:"Helsinki",org:"Tequ"},"squidrouter.com":{lat:37.77,lng:-122.42,city:"San Francisco",org:"Squid Router"},"ripple.ittc.ku.edu":{lat:38.97,lng:-95.24,city:"Lawrence, KS",org:"Univ. of Kansas"},"ripple.com":{lat:37.77,lng:-122.42,city:"San Francisco",org:"Ripple"},"peersyst.cloud":{lat:41.39,lng:2.15,city:"Barcelona",org:"Peersyst"},"onxrp.com":{lat:51.51,lng:-.13,city:"London",org:"OnXRP"},"katczynski.net":{lat:52.23,lng:21.01,city:"Warsaw",org:"Katczynski"},"jon-nilsen.no":{lat:59.91,lng:10.75,city:"Oslo",org:"Jon Nilsen"},"ekiserrepe.es":{lat:40.42,lng:-3.7,city:"Madrid",org:"Ekiserrepe"},"cabbit.tech":{lat:51.51,lng:-.13,city:"London",org:"Cabbit"},"bithomp.com":{lat:59.33,lng:18.07,city:"Stockholm",org:"Bithomp"},"aureusox.com":{lat:40.71,lng:-74.01,city:"New York",org:"Aureus Ox"},"arrington-xrp-capital.blockdaemon.com":{lat:40.71,lng:-74.01,city:"New York",org:"Blockdaemon"},"anodos.finance":{lat:37.98,lng:23.73,city:"Athens",org:"Anodos Finance"},"bitso.com":{lat:19.43,lng:-99.13,city:"Mexico City",org:"Bitso"},"ripple.kenan-flagler.unc.edu":{lat:35.9,lng:-79.05,city:"Chapel Hill, NC",org:"UNC Kenan-Flagler"},"ripplevalidator.uwaterloo.ca":{lat:43.47,lng:-80.54,city:"Waterloo, ON",org:"Univ. of Waterloo"},"shadow.haas.berkeley.edu":{lat:37.87,lng:-122.26,city:"Berkeley, CA",org:"UC Berkeley Haas"},"www.bitrue.com":{lat:1.35,lng:103.82,city:"Singapore",org:"Bitrue"},"xrp-col.anu.edu.au":{lat:-35.28,lng:149.13,city:"Canberra",org:"ANU"},"xrpval.rawsec.de":{lat:51.17,lng:10.45,city:"Germany",org:"Rawsec"},"xrplvl.carbonvibe.com":{lat:51.51,lng:-.13,city:"London",org:"Carbon Vibe"},"xrplvalidator.alloy.ee":{lat:59.44,lng:24.75,city:"Tallinn",org:"Alloy"},"xrpl.uni.lu":{lat:49.61,lng:6.13,city:"Luxembourg",org:"Univ. of Luxembourg"},"xrpl.to":{lat:48.86,lng:2.35,city:"Paris",org:"XRPL.to"},"xrpl.su":{lat:55.75,lng:37.62,city:"Moscow",org:"XRPL.su"},"xrpl.sbivc.co.jp":{lat:35.69,lng:139.69,city:"Tokyo",org:"SBI VC Trade"},"xrpl-verification.flare.network":{lat:51.51,lng:-.13,city:"London",org:"Flare Network"},"xrpl-validator.7rev.dev":{lat:52.52,lng:13.4,city:"Berlin",org:"7Rev"},"xrp.teacopula.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"Teacopula"},"xrp.moneymindedapes.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"MoneyMindedApes"},"xrp.hazza-systems.de":{lat:52.52,lng:13.4,city:"Berlin",org:"Hazza Systems"},"xrp.cs.uoregon.edu":{lat:44.05,lng:-123.08,city:"Eugene, OR",org:"Univ. of Oregon"},"xrp.bpsqn.com":{lat:37.77,lng:-122.42,city:"San Francisco",org:"BPSQN"},"xrp-validator.grapedrop.xyz":{lat:52.37,lng:4.9,city:"Amsterdam",org:"Grapedrop"},"xaodao.io":{lat:1.35,lng:103.82,city:"Singapore",org:"XaoDAO"},"vl.xrpsalute.com":{lat:40.71,lng:-74.01,city:"New York",org:"XRP Salute"},"validator.ukcbt.org":{lat:51.51,lng:-.13,city:"London",org:"UKCBT"},"validator.sugarxrpl.com":{lat:37.77,lng:-122.42,city:"San Francisco",org:"SugarXRPL"},"validator.boscaern.digital":{lat:53.33,lng:-6.25,city:"Dublin",org:"Boscaern"},"trimaera.tech":{lat:48.86,lng:2.35,city:"Paris",org:"Trimaera"},"textrp.io":{lat:1.35,lng:103.82,city:"Singapore",org:"TextRP"},"tesbert.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"Tesbert"},"tachyon-xrpl-validator.github.io":{lat:37.77,lng:-122.42,city:"San Francisco",org:"Tachyon"},"solonation.io":{lat:1.35,lng:103.82,city:"Singapore",org:"SoloNation"},"smokydrip.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"SmokyDrip"},"rippled-validator.us":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"rippled-validator.us"},"rippleat.snt.uni.lu":{lat:49.61,lng:6.13,city:"Luxembourg",org:"Univ. of Luxembourg"},"ripple.uni.lu":{lat:49.61,lng:6.13,city:"Luxembourg",org:"Univ. of Luxembourg"},"ripple.j2b.com":{lat:37.77,lng:-122.42,city:"San Francisco",org:"J2B"},"rich-list.info":{lat:51.51,lng:-.13,city:"London",org:"Rich List"},"proptoexchange.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"ProPtoExchange"},"printscierge.com":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"Printscierge"},"opulencex.io":{lat:1.35,lng:103.82,city:"Singapore",org:"OpulenceX"},"onledger.net":{lat:52.37,lng:4.9,city:"Amsterdam",org:"OnLedger"},"oclost.art":{lat:48.86,lng:2.35,city:"Paris",org:"Oclost"},"managednetwork.us":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"ManagedNetwork"},"joshuahamsa.com":{lat:37.77,lng:-122.42,city:"San Francisco",org:"Joshua Hamsa"},"grimmsxrpflow.jwscott.net":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"Grimm XRP Flow"},"getlol.xyz":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"GetLol"},"gen3labs.xyz":{lat:37.77,lng:-122.42,city:"San Francisco",org:"Gen3 Labs"},"garveyvalid.com":{lat:40.71,lng:-74.01,city:"New York",org:"Garvey"},"easynpl.kr":{lat:37.57,lng:126.98,city:"Seoul",org:"EasyNPL"},"diseb.ewi.tudelft.nl":{lat:52,lng:4.36,city:"Delft",org:"TU Delft"},"datamossa.com":{lat:48.86,lng:2.35,city:"Paris",org:"DataMossa"},"crypto.unibe.ch":{lat:46.95,lng:7.45,city:"Bern",org:"Univ. of Bern"},"commonprefix.com":{lat:37.98,lng:23.73,city:"Athens",org:"Common Prefix"},"catalyze-research.com":{lat:51.51,lng:-.13,city:"London",org:"Catalyze Research"},"catalog.org":{lat:37.77,lng:-122.42,city:"San Francisco",org:"Catalog"},"blockchain.korea.ac.kr":{lat:37.57,lng:126.98,city:"Seoul",org:"Korea Univ."},"astatiumprotocol.com":{lat:1.35,lng:103.82,city:"Singapore",org:"Astatium Protocol"},"ladykxrpl.mywire.org":{lat:39.04,lng:-77.49,city:"Ashburn, VA",org:"LadyK XRPL"},"eelap-p1201-xrp.abudhabi.nyu.edu":{lat:24.47,lng:54.37,city:"Abu Dhabi",org:"NYU Abu Dhabi"},"589.clouds.hspeed.ch":{lat:47.38,lng:8.54,city:"Zurich",org:"HSpeed"},"www.payonline.financial":{lat:55.75,lng:37.62,city:"Moscow",org:"PayOnline"}};function wr(e){if(!e)return null;let t=e.toLowerCase().replace(/^www\./,"");return nm[t]??nm["www."+t]??null}var G0=[{lat:37.34,lng:-121.89,label:"s1.ripple.com",city:"San Jose, CA",org:"Ripple"},{lat:37.34,lng:-121.87,label:"s2.ripple.com",city:"San Jose, CA",org:"Ripple"},{lat:52.37,lng:4.91,label:"xrplcluster.com",city:"Amsterdam",org:"Cluster"},{lat:52.36,lng:4.89,label:"xrpl.ws",city:"Amsterdam",org:"Cluster"}],Oe={nunl:{hex:"#ff5555",glow:"rgba(255,85,85,.4)",label:"Negative UNL"},both:{hex:"#50fa7b",glow:"rgba(80,250,123,.4)",label:"UNL + dUNL"},unl:{hex:"#00fff0",glow:"rgba(0,255,240,.35)",label:"UNL"},dunl:{hex:"#bd93f9",glow:"rgba(189,147,249,.4)",label:"dUNL only"},other:{hex:"#ffb86c",glow:"rgba(255,184,108,.4)",label:"Other"},pub:{hex:"#50fa7b",glow:"rgba(80,250,123,.4)",label:"Public Node"}},ur="https://api.xrpscan.com/api/v1/validatorregistry",xe=new Map,xn={},uo=0,Vn=!1,kn="fallback";function bm(){if(!Vn){xe.clear();for(let[e,t]of Object.entries(yr)){let n=t.domain??e,s=gm("",n),a=wr(n)??null;xe.set(e,{key:e,label:t.label,domain:n,domainVerified:!1,provider:t.provider??(a==null?void 0:a.org)??null,lists:t.lists??[],category:s.isUnl?"unl":"other",chain:s.chain,unl:s.isUnl,dunl:!1,geo:a,meta:{},agreement:{"1h":null,"24h":null,"30d":null}})}kn="fallback",xr({ok:!1,source:"fallback",error:"using hardcoded data \u2014 mount /api/v1 router"})}}var mr=0,K0=5*60*1e3;function sm(e,t){var s,a;let n=Array.isArray(e)?e:e.validators??e.data??[];if(!n.length)throw new Error("Empty validators array");xe.clear();for(let o of n){let i=o.key??o.validation_public_key??o.master_key??o.signing_key??null;if(!i)continue;let r=o.domain??null,l=r?r.toLowerCase().replace(/^www\./,""):null,c=o.unl===!0||o.unl===1||o.unl==="true",u=gm(i,l),d=c||u.isUnl,p=u.chain,m=d?"unl":"other",f=Object.values(yr).find(x=>x.domain&&x.domain.toLowerCase().replace(/^www\./,"")===l),g=(f==null?void 0:f.label)??o.label??o.account_name??o.name??l??null??`${i.slice(0,8)}\u2026${i.slice(-6)}`,v=fo[i]??wr(l)??null,b=(((s=o.geo)==null?void 0:s.lat)!=null&&((a=o.geo)==null?void 0:a.lng)!=null?o.geo:null)??v;xe.set(i,{key:i,label:g,domain:r??null,domainVerified:!!(o.domainVerified??o.domain_verified),provider:o.provider??(b==null?void 0:b.org)??(f==null?void 0:f.provider)??null,lists:Array.isArray(o.lists)?o.lists:[],category:m,chain:p,unl:d,dunl:!1,geo:b,version:o.version??o.build_version??null,baseFee:o.base_fee_xrp??o.base_fee??null,ownerReserve:o.reserve_inc_xrp??o.owner_reserve??null,meta:o.meta??{},agreement:o.agreement??{"1h":rr(o.agreement_1h??o.agr_1h),"24h":rr(o.agreement_24h??o.agr_24h),"30d":rr(o.agreement_30d??o.agr_30d)}})}xn=e.lists??{},uo=Date.now(),Vn=!0,kn=t,mr=0,xr({ok:!0,count:xe.size,lists:xn,source:t})}function rr(e){if(!e)return null;let t=Number(e.total??e.ledgers??0),n=Number(e.missed??0),s=t-n,a=t>0?(s/t*100).toFixed(1):null;return{total:t,missed:n,hit:s,score:a?`${a}%`:null,scoreRaw:e.score??null}}async function po(e=!1){let t=Date.now();if(!e&&Vn&&t-uo<U0)return!0;if(!e&&!Vn&&t-mr<K0)return!1;let n=typeof oa=="string"&&oa.startsWith("/api/"),s=location.protocol==="file:"||location.hostname==="127.0.0.1"||location.hostname==="localhost";if(!(n&&s))try{let a=new AbortController,o=setTimeout(()=>a.abort(),em),i=await fetch(oa,{signal:a.signal,headers:{Accept:"application/json"}});if(clearTimeout(o),!i.ok)throw new Error(`HTTP ${i.status}`);let r=await i.json();return sm(r,"proxy"),!0}catch(a){console.warn("[registry] tier 1 (proxy) failed:",a.message)}try{let a=new AbortController,o=setTimeout(()=>a.abort(),em),i=await fetch(ur,{signal:a.signal});if(clearTimeout(o),!i.ok)throw new Error(`HTTP ${i.status}`);let r=await i.text(),l=JSON.parse(r);return sm(l,"xrpscan"),!0}catch(a){console.warn("[registry] tier 2 (xrpscan direct) failed:",a.message),(a.message.includes("Failed to fetch")||a.message.includes("CORS"))&&console.warn("[registry] CORS blocked \u2014 mount the backend proxy route (see validatorregistry.js)")}return console.warn("[registry] all sources failed \u2014 showing",Object.keys(yr).length,"hardcoded validators"),mr=Date.now(),Vn||bm(),xr({ok:!1,source:"fallback",error:"all sources failed \u2014 mount /api/v1 router"}),!1}window.debugRegistry=async function(){console.group("\u{1F50D} Registry debug"),console.log("Current source:",kn),console.log("Validators loaded:",xe.size),console.log("Registry ok:",Vn),console.log("Last fetch:",uo?new Date(uo).toLocaleTimeString():"never"),console.log(""),console.log("Testing proxy \u2192",oa);try{let e=await fetch(oa),t=await e.text();console.log("  Status:",e.status,"\u2014 body preview:",t.slice(0,300))}catch(e){console.warn("  Failed:",e.message)}console.log(""),console.log("Testing XRPScan direct \u2192",ur);try{let e=await fetch(ur),t=await e.text();console.log("  Status:",e.status,"\u2014 body preview:",t.slice(0,300))}catch(e){console.warn("  Failed:",e.message)}return console.groupEnd(),{source:kn,size:xe.size,ok:Vn}};function it(e){return xe.get(e)??{key:e,label:`${e.slice(0,10)}\u2026${e.slice(-6)}`,domain:null,provider:null,lists:[],category:"other",geo:fo[e]??null,meta:{}}}function $n(e){var n;if(!e)return null;if(((n=e.geo)==null?void 0:n.lat)!=null)return e.geo;let t=fo[e.key];return t||wr(e.domain)}function vm(){return[...xe.values()].filter(e=>(e.category==="unl"||e.category==="both")&&e.chain!=="test").map(e=>e.key)}function J0(){return[...xe.values()].filter(e=>(e.category==="dunl"||e.category==="both")&&e.chain!=="test").map(e=>e.key)}function Y0(){return[...xe.values()].filter(e=>e.category==="other"&&e.chain!=="test").map(e=>e.key)}function Q0(){return[...xe.values()].filter(e=>e.chain==="test").map(e=>e.key)}function xr({ok:e,count:t,lists:n,source:s,error:a}){let o=w("m1-registry-badge");if(o)if(e){let i=[...xe.values()].filter(c=>c.category==="unl").length,r=[...xe.values()].filter(c=>c.chain==="test").length,l=t-r;o.textContent=`${l} mainnet \xB7 ${i} UNL \xB7 ${r} testnet \xB7 live`,o.className="registry-badge registry-badge--ok"}else o.textContent=s==="fallback"?`Fallback data \xB7 ${xe.size} known \xB7 ${a??"endpoint unreachable"}`:"Refreshing\u2026",o.className="registry-badge registry-badge--warn"}var mo=null,am=!1,lr=!1,om=0,im=0,rm=0,cr=0,ym=!0,nt=null,qn=null,la=null,zt=null,je={},lo=null,fr={},tt=null,tn=[],co=null,hr={},sa="unl",mt={fees:[],burnDrops:[],dexOffers:[],ammSwaps:[],newAccounts:[],converge:[],proposers:[],peerCounts:[],peerDiscon:[]};function wm(){var t,n;if(am)return;am=!0,Tw(),bm(),po(!0),kw(),$w(),window.addEventListener("xrpl-connected",()=>{aa(),Ss()&&(ia({force:!0}),ra({force:!1}))}),window.addEventListener("xrpl-disconnected",()=>{gr(),vr(null)}),window.addEventListener("xrpl-connection",s=>{var a;((a=s==null?void 0:s.detail)==null?void 0:a.state)==="connecting"&&(gr(),vr(null,"Switching networks\u2026"))}),window.addEventListener("xrpl-ledger",s=>{yw(s.detail),Ss()&&ww(s.detail)}),(t=w("btn-network-refresh"))==null||t.addEventListener("click",()=>{ia({force:!0}),po(!0),ra({force:!0})}),(n=document.querySelector('.dash-tab[data-tab="network"]'))==null||n.addEventListener("click",()=>{aa(),ia({force:!0}),po(!1),ra({force:!1})});let e=w("tab-network");e&&new MutationObserver(aa).observe(e,{attributes:!0,attributeFilter:["style","class"]}),document.addEventListener("visibilitychange",aa)}function Ss(){let e=w("tab-network"),t=e?e.style.display!=="none":!1;return ym&&X.currentPage==="dashboard"&&X.currentTab==="network"&&t&&!document.hidden}function aa(){Ss()?Z0():gr()}function xm(e){ym=!!e,aa()}function Z0(){mo||(ia({force:!1}),mo=setInterval(()=>{Ss()&&ia({force:!1})},F0))}function gr(){clearInterval(mo),mo=null}async function ia({force:e=!1}={}){var n;if(!Ss()&&!e)return;let t=Date.now();if(!(!e&&(t-om<O0||lr||t<im))){lr=!0,om=t,je={},lm(!0);try{await Promise.allSettled([po(!1),ew(),tw(),nw(),sw(),aw()]),ow(),cw(),dw(),pw(),bw(),vr({info:nt,fee:qn,vals:la}),Cw()}catch(s){String((s==null?void 0:s.message)??"").toLowerCase().includes("too much load")&&(im=Date.now()+B0,(n=he)==null||n("Rate-limited \u2014 backing off 2 min."))}finally{lm(!1),lr=!1}}}function lm(e){var t;(t=w("btn-network-refresh"))==null||t.classList.toggle("spinning",e)}async function ew(){var n,s,a;let e=await Ee({command:"server_info"});if(nt=((n=e==null?void 0:e.result)==null?void 0:n.info)??null,!nt)return;ot("converge",Number(((s=nt.last_close)==null?void 0:s.converge_time_s)??0)),ot("proposers",Number(((a=nt.last_close)==null?void 0:a.proposers)??0)),ot("peerCounts",Number(nt.peers??0));let t=Number(nt.peer_disconnects_resources??0);lo!==null&&t>lo&&ot("peerDiscon",t-lo),lo=t}async function tw(){var t;let e=await Ee({command:"fee"});qn=(e==null?void 0:e.result)??null,((t=qn==null?void 0:qn.drops)==null?void 0:t.open_ledger_fee)!=null&&ot("fees",Number(qn.drops.open_ledger_fee))}async function nw(){try{let e=await Ee({command:"validators"});la=(e==null?void 0:e.result)??null}catch{la=null}}async function sw(){var e;try{let t=await Ee({command:"peers"});zt=Array.isArray((e=t==null?void 0:t.result)==null?void 0:e.peers)?t.result.peers:null}catch{zt=null}}async function aw(){var e;try{let t=await Ee({command:"feature"});(e=t==null?void 0:t.result)!=null&&e.features&&(uw(t.result.features),$m(t.result.features))}catch{}}function ow(){var C,P,R,O,D,I;let e=nt,t=la,n=(t==null?void 0:t.trusted_validator_keys)??[],s=vm(),a=J0(),o=n.length?n:s,i=a,r=Number((t==null?void 0:t.validation_quorum)??(e==null?void 0:e.validation_quorum)??0),l=o.length,c=l-r,u=l>0?r/l*100:0,d=o.filter(F=>xe.has(F)).length,p=l>0?Math.round(d/l*100):0,m=Number(((C=e==null?void 0:e.last_close)==null?void 0:C.converge_time_s)??0),f=Number(((P=e==null?void 0:e.last_close)==null?void 0:P.proposers)??0),g=r>0?Math.round(f/r*100):0,v=Array.isArray(e==null?void 0:e.negative_unl)?e.negative_unl:[],h=!!la;c>=0&&c<=3&&(je.quorumTight=!0),v.length>0&&(je.nUnlActive=!0),m>6&&(je.slowConverge=!0),f>0&&r>0&&f<r&&(je.lowProposers=!0),K("m1-active",h?l:"\u2014"),K("m1-quorum",r>0?r:"\u2014"),K("m1-margin",h?c>=0?c:`\u2212${Math.abs(c)}`:"\u2014"),K("m1-overlap",h?`${p}%`:"\u2014"),K("m1-known",h?`${d} / ${l} identified`:"\u2014 (validators cmd unavailable)"),K("m1-proposers",((R=e==null?void 0:e.last_close)==null?void 0:R.proposers)!=null?f:"\u2014"),K("m1-particip",r>0&&((O=e==null?void 0:e.last_close)==null?void 0:O.proposers)!=null?`${g}%`:"\u2014"),K("m1-converge",((D=e==null?void 0:e.last_close)==null?void 0:D.converge_time_s)!=null?`${m.toFixed(2)}s`:"\u2014"),K("m1-converge-avg",ca("converge")>0?`avg ${ca("converge").toFixed(2)}s`:"\u2014"),Tt("m1-qbar",u,u>90?"bar-danger":u>80?"bar-warn":"bar-ok"),Tt("m1-obar",p,p<40?"bar-danger":p<70?"bar-warn":"bar-ok"),Tt("m1-pbar",g,g<80?"bar-danger":g<95?"bar-warn":"bar-ok"),Tt("m1-cvgbar",Math.min(100,m/10*100),m>6?"bar-danger":m>4?"bar-warn":"bar-ok"),lw({active:l,quorum:r,margin:c,nUnl:v,valsAvail:h});let b=(I=t==null?void 0:t.publisher_lists)==null?void 0:I[0],x=(xn==null?void 0:xn.ripple)??(xn==null?void 0:xn.xrplf)??null,k=(b==null?void 0:b.uri)??(x==null?void 0:x.uri)??"\u2014",T=(b==null?void 0:b.seq)??(x==null?void 0:x.seq)??"\u2014";if(K("m1-vl-uri",k),K("m1-vl-seq",T),b!=null&&b.expiration||x!=null&&x.expiration){let F=w("m1-vl-expiry");if(F){let H=(b==null?void 0:b.expiration)??(x==null?void 0:x.expiration),N=Math.floor((new Date(H)-Date.now())/864e5);F.textContent=N>0?`Expires ${N}d`:"\u26A0 EXPIRED",F.className=`expiry-pill ${N>30?"pill-ok":N>7?"pill-warn":"pill-bad"}`,F.style.display=""}}let S=w("m1-nunl-list");if(K("m1-nunl-count",v.length||"0"),S)if(!v.length)S.innerHTML='<div class="nunl-empty">\u2713 No validators on Negative UNL</div>';else{let F={};S.innerHTML=v.map(N=>{let j=it(N);return j.provider&&(F[j.provider]=(F[j.provider]||0)+1),`<div class="nunl-entry">
          <span class="nunl-dot"></span>
          <div class="nunl-info">
            <span class="nunl-label">${y(j.label)}</span>
            ${j.domain?`<span class="nunl-prov">${y(j.domain)}</span>`:""}
          </div>
          <span class="nunl-key" onclick="navigator.clipboard?.writeText('${y(N)}')">${N.slice(0,8)}...</span>
        </div>`}).join("");let H=Object.entries(F).sort((N,j)=>j[1]-N[1])[0];(H==null?void 0:H[1])>1&&(S.innerHTML+=`<div class="nunl-alert">\u26A0 ${H[1]} offline validators share <b>${y(H[0])}</b> \u2014 likely provider outage</div>`)}km(o,i,r,v,h);let $=Number((nt==null?void 0:nt.peers)??0);K("wm-stat-val",h?`${l} validators`:`${xe.size} in registry`),K("wm-stat-nunl",`${v.length} on nUNL`),K("wm-stat-peers",`${zt?zt.length:$} peers`);let E=[...xe.keys()];fw(o,i,v,zt,!h)}function km(e,t,n,s,a){let o=w("m1-val-grid");if(!o)return;let i=new Set(e),r=new Set(t),l=new Set(s),c=vm(),u=Q0(),d=Y0(),p=e.length?e:c,m=[...xe.keys()],f=m.filter(D=>{var I;return(((I=xe.get(D))==null?void 0:I.chain)??"main")==="main"}),g=u,v=d,h=p.filter(D=>!!it(D).domain),b=p.filter(D=>!it(D).domain),x=v.filter(D=>!!it(D).domain),k=v.filter(D=>!it(D).domain),T=m.filter(D=>!!$n(it(D))),S=[{id:"unl",label:"UNL",count:p.length,dot:"unl"},{id:"others",label:"Others",count:v.length,dot:"other"},{id:"all",label:"All",count:f.length,dot:null},{id:"test",label:"Testnet",count:g.length,dot:null}],$={unl:"#00fff0",dunl:"#bd93f9",both:"#50fa7b",nunl:"#ff5555",other:"#ffb86c"},E='<div class="vg-tabs" role="tablist">'+S.map(D=>`<button class="vg-tab ${sa===D.id?"vg-tab--active":""}" data-vgtab="${D.id}">
        ${D.dot?`<span class="vg-tab-dot" style="background:${$[D.dot]}"></span>`:""}
        ${y(D.label)}
        <span class="vg-tab-count">${D.count}</span>
      </button>`).join("")+"</div>",C=[],P="";if(sa==="unl"){let D=p.filter(N=>l.has(N)),I=h.filter(N=>!l.has(N)),F=b.filter(N=>!l.has(N));D.length&&C.push({title:`\u26A0 Negative UNL (${D.length})`,keys:D,cls:"vgs-warn"}),C.push({title:`Named UNL validators \xB7 ${I.length}`,keys:I}),F.length&&C.push({title:`Key-only UNL validators \xB7 ${F.length}`,keys:F,collapsed:!0}),p.length||C.push({title:"No UNL data",keys:[],notice:"Registry not loaded yet"});let H=a?"live rippled":`registry (${kn})`;P=`${p.length} trusted \xB7 quorum ${n} \xB7 ${s.length} on nUNL \xB7 source: ${H}`}else if(sa==="others")C.push({title:`Named mainnet (non-UNL) \xB7 ${x.length}`,keys:x}),k.length&&C.push({title:`Key-only mainnet \xB7 ${k.length}`,keys:k,collapsed:!0}),P=`${v.length} mainnet validators not on UNL \xB7 source: ${kn}`;else if(sa==="test"){let D=g.filter(F=>!!it(F).domain),I=g.filter(F=>!it(F).domain);D.length&&C.push({title:`Named testnet \xB7 ${D.length}`,keys:D}),I.length&&C.push({title:`Key-only testnet \xB7 ${I.length}`,keys:I,collapsed:!0}),P=`${g.length} testnet validators`}else C.push({title:`\u2B50 UNL \xB7 ${p.length}`,keys:p}),C.push({title:`Other mainnet \xB7 ${v.length}`,keys:v,collapsed:!0}),g.length&&C.push({title:`Testnet \xB7 ${g.length}`,keys:g,collapsed:!0}),P=`${f.length} mainnet \xB7 ${g.length} testnet \xB7 ${T.length} geo-located \xB7 source: ${kn}`;function R(D,I){var ke;let F=it(D),H=l.has(D),N=i.has(D),j=r.has(D),se=F.chain==="test",re,pe,ae;H?(re="vp-nunl",pe="nUNL",ae=$.nunl):N&&j?(re="vp-both",pe="UNL+dUNL",ae=$.both):N?(re="vp-unl",pe="UNL",ae=$.unl):j?(re="vp-dunl",pe="dUNL",ae=$.dunl):(re="vp-other",pe="Other",ae=$.other);let te=$n(F),de=!!te,le=te?`\u{1F4CD} ${te.city??""}`:"",Pe=F.domain?F.domain.replace(/^www\./,"").replace(/^validator\./,"").replace(/^xrp\./,""):null,B=`${D.slice(0,8)}\u2026${D.slice(-6)}`,q=N&&I!=null?`<span class="vg-num">${I+1}</span>`:"",J=(ke=F.agreement)==null?void 0:ke["24h"],ue=J!=null&&J.score?`<span class="vg-agr" style="color:${parseFloat(J.score)>=99?"#50fa7b":parseFloat(J.score)>=95?"#ffb86c":"#ff5555"}" title="24h agreement">${J.score}</span>`:"";return`<div class="vpill ${re} ${de?"vp-locatable":""}"
                 title="${y([F.label,F.domain,te==null?void 0:te.city,D].filter(Boolean).join(" \xB7 "))}"
                 onclick="window.focusValidator('${y(D)}')"
                 data-key="${y(D)}">
      ${q}
      <span class="vpdot" style="background:${ae};box-shadow:0 0 5px ${ae}55"></span>
      <div class="vptext">
        <span class="vplabel">${y(Pe??F.label??B)}</span>
        ${le?`<span class="vpprov vp-geo">${y(le)}</span>`:""}
      </div>
      <div class="vpactions">
        ${ue}
        <span class="vntag vntag-cat" style="border-color:${ae}44;color:${ae}">${pe}</span>
        ${se?'<span class="vntag" style="opacity:.5">test</span>':""}
      </div>
    </div>`}let O="";C.forEach(D=>{if(!D.keys.length)return;let I=D.keys.some(j=>i.has(j)),F=D.keys.map((j,se)=>R(j,I?se:null)).join(""),H=`vgs-${Math.random().toString(36).slice(2,8)}`,N=!D.collapsed;O+=`
      <div class="vg-section ${D.cls??""}">
        <button class="vg-section-hdr" onclick="
          const c=document.getElementById('${H}');
          const open=c.style.display!=='none';
          c.style.display=open?'none':'';
          this.querySelector('.vg-chevron').textContent=open?'\u25B6':'\u25BC';
        ">
          <span class="vg-chevron">${N?"\u25BC":"\u25B6"}</span>
          <span class="vg-sec-title">${y(D.title)}</span>
        </button>
        <div id="${H}" class="vg-section-body" style="display:${N?"":"none"}">
          ${F}
        </div>
      </div>`}),O||(O='<div class="nunl-empty">No validators in this view.</div>'),o.innerHTML=E+O,K("m1-val-summary",P),o.querySelectorAll(".vg-tab").forEach(D=>{D.addEventListener("click",I=>{I.stopPropagation();let F=D.getAttribute("data-vgtab");F&&(sa=F,km(e,t,n,s,a))})})}async function iw(e){let t=dr.get(e);if(t&&Date.now()-t.cachedAt<mm)return t.data;try{let n=new AbortController,s=setTimeout(()=>n.abort(),fm),a=await fetch(`${um}/${encodeURIComponent(e)}`,{signal:n.signal});if(clearTimeout(s),!a.ok)throw new Error(`HTTP ${a.status}`);let o=await a.json();return dr.set(e,{data:o,cachedAt:Date.now()}),o}catch{return null}}async function rw(e){let t=pr.get(e);if(t&&Date.now()-t.cachedAt<mm)return t.data;try{let n=new AbortController,s=setTimeout(()=>n.abort(),fm),a=await fetch(`${um}/${encodeURIComponent(e)}/reports`,{signal:n.signal});if(clearTimeout(s),!a.ok)throw new Error(`HTTP ${a.status}`);let o=await a.json(),i=o.reports??o??[];return pr.set(e,{data:i,cachedAt:Date.now()}),i}catch{return[]}}window.focusValidator=async function(e){let t=it(e),n=$n(t);document.querySelectorAll(".vpill").forEach(o=>o.classList.remove("vp-active"));let s=document.querySelector(`.vpill[data-key="${CSS.escape(e)}"]`);if(s&&(s.classList.add("vp-active"),s.scrollIntoView({behavior:"smooth",block:"nearest"})),br(e,t,null),iw(e).then(o=>{o&&br(e,t,o)}),!n){let o=w("world-map-container");if(o){let i=o.querySelector(".wm-no-geo");i&&i.remove();let r=document.createElement("div");r.className="wm-no-geo",r.textContent=`\u{1F4CD} ${t.label} \u2014 geographic location unknown`,o.appendChild(r),setTimeout(()=>r.remove(),3500)}return}let a=w("world-map-container");a&&a.scrollIntoView({behavior:"smooth",block:"nearest"}),tt&&(tt.flyTo([n.lat,n.lng],6,{duration:1.2}),setTimeout(()=>{let o=hr[e];o&&o.openPopup()},1300))};function br(e,t,n){var C,P,R,O,D;let s=w("amend-modal-overlay"),a=w("amend-modal-body");if(!s||!a)return;let o=n??{},i=t.label??o.label??o.account_name??e.slice(0,16)+"\u2026",r=t.domain??o.domain??null,l=t.chain??o.chain??"main",c=t.category??"other",u=Oe[c]??Oe.other,d=$n(t),p=t.unl||c==="unl"||c==="both",m=t.dunl||c==="dunl"||c==="both",f=t.domainVerified||o.domain_verified?"\u2713 Verified":r?"Unverified":"\u2014",g=t.agreement??o.agreement??{},v=!n&&!((C=t.agreement)!=null&&C["24h"]);function h(I,F){if(!F||!F.total)return`<div class="adm-mi"><span class="adm-mk">${I}</span><span class="adm-mv" style="opacity:.5">\u2014</span></div>`;let H=parseFloat(F.score)||0,N=H>=99?"color:#50fa7b":H>=95?"color:#ffb86c":"color:#ff5555";return`<div class="adm-mi">
      <span class="adm-mk">${I}</span>
      <span class="adm-mv mono" style="${N}">${F.score??"\u2014"}
        <span style="opacity:.55;font-size:10px;font-weight:400"> \xB7 ${F.missed??0} missed / ${F.total??0}</span>
      </span>
    </div>`}function b(I,F,H=!1){return!F&&F!==0?"":`<div class="adm-mi"><span class="adm-mk">${I}</span><span class="adm-mv ${H?"mono":""}">${y(String(F))}</span></div>`}let x=pr.get(e),k=((P=x==null?void 0:x.data)==null?void 0:P.slice(-14))??[],T=k.length?`<div class="adm-section">
        <div class="adm-slbl">Ledger agreement \u2014 last ${k.length} days</div>
        <div style="display:flex;gap:2px;align-items:flex-end;height:32px;margin-top:6px;">
          ${k.map(I=>{let F=Number(I.missed??I.miss??0),H=Number(I.total??I.ledgers??1),N=H>0?(H-F)/H*100:100,j=Math.round(4+N/100*28),se=N>=99?"#50fa7b":N>=95?"#ffb86c":"#ff5555";return`<div title="${I.date??""} \xB7 ${N.toFixed(1)}% (${F} missed)" style="flex:1;height:${j}px;background:${se};border-radius:2px 2px 0 0;opacity:.85;transition:opacity .15s" onmouseover="this.style.opacity=1" onmouseout="this.style.opacity=.85"></div>`}).join("")}
        </div>
      </div>`:"",S=c==="unl"?"\u2B50 UNL":c==="both"?"\u2B50 UNL + dUNL":c==="nunl"?"\u26A0 Neg-UNL":c==="dunl"?"dUNL":"Non-UNL",$=c==="unl"||c==="both"?"background:rgba(0,255,240,.15);color:#00fff0;border-color:#00fff044":c==="nunl"?"background:rgba(255,85,85,.15);color:#ff5555;border-color:#ff555544":"background:rgba(255,184,108,.1);color:#ffb86c;border-color:#ffb86c44",E=r?`https://xrpscan.com/validator/${encodeURIComponent(r)}`:`https://xrpscan.com/validator/${encodeURIComponent(e)}`;a.innerHTML=`
    <div class="adm-header" style="border-bottom:1px solid rgba(255,255,255,.08);padding-bottom:12px;margin-bottom:12px;">
      <div class="adm-title-row" style="display:flex;align-items:flex-start;gap:10px;margin-bottom:6px;">
        <div style="flex:1">
          <h2 class="adm-title" style="color:${u.hex};margin:0;font-size:17px;font-weight:700">${y(i)}</h2>
          ${r?`<div style="font-size:12px;opacity:.65;margin-top:2px">${y(r)} <span style="opacity:.6">${y(f)}</span></div>`:""}
        </div>
        <span style="font-size:11px;padding:3px 8px;border-radius:10px;border:1px solid;flex-shrink:0;font-weight:600;${$}">${S}</span>
      </div>
      <div style="font-family:monospace;font-size:10px;opacity:.45;word-break:break-all;cursor:pointer" title="Click to copy" onclick="navigator.clipboard?.writeText('${y(e)}');this.style.opacity=.8;setTimeout(()=>this.style.opacity=.45,800)">${y(e)}</div>
    </div>

    <div class="adm-section">
      <div class="adm-slbl">Identity &amp; Status</div>
      ${b("Chain",l==="main"?"\u{1F310} Mainnet":"\u{1F9EA} Testnet")}
      ${b("UNL",p?"\u2B50 Yes \u2014 Ripple UNL":"No")}
      ${b("dUNL",m?"\u2713 Yes \u2014 XRPL Foundation UNL":"No")}
      ${d?b("Location",[d.city,d.country].filter(Boolean).join(", ")||"\u2014"):""}
      ${d!=null&&d.org?b("Provider",d.org):""}
      ${b("Version",t.version??o.version??o.build_version??null)}
      ${b("Base fee",t.baseFee??o.base_fee_xrp??o.baseFee??null)}
      ${b("Ledger",o.currentIndex?Number(o.currentIndex).toLocaleString():null,!0)}
    </div>

    <div class="adm-section">
      <div class="adm-slbl">Ledger Agreement ${v?'<span style="opacity:.4;font-size:10px;margin-left:6px">loading\u2026</span>':""}</div>
      ${h("1-hour",g["1h"]??((R=o.agreement)==null?void 0:R["1h"]))}
      ${h("24-hour",g["24h"]??((O=o.agreement)==null?void 0:O["24h"]))}
      ${h("30-day",g["30d"]??((D=o.agreement)==null?void 0:D["30d"]))}
    </div>

    ${T}

    <div class="adm-footer" style="display:flex;gap:10px;margin-top:12px;padding-top:10px;border-top:1px solid rgba(255,255,255,.07)">
      <a class="adm-link" href="${E}" target="_blank" rel="noopener noreferrer">\u2197 XRPScan</a>
      <button class="adm-link" style="background:none;border:none;cursor:pointer;color:inherit;padding:0" onclick="window._loadValidatorReports('${y(e)}')">\u{1F4CA} Load reports</button>
      ${(d==null?void 0:d.lat)!=null?`<button class="adm-link" style="background:none;border:none;cursor:pointer;color:inherit;padding:0" onclick="window.closeAmendModal();setTimeout(()=>window.focusValidator('${y(e)}'),200)">\u{1F4CD} Show on map</button>`:""}
    </div>`,s.style.display="flex",s.addEventListener("click",I=>{I.target===s&&window.closeAmendModal()},{once:!0})}window._loadValidatorReports=async function(e){var n;let t=it(e);await rw(e),br(e,t,((n=dr.get(e))==null?void 0:n.data)??null)};function lw({active:e,quorum:t,margin:n,nUnl:s,valsAvail:a}){let o=w("m1-quorum-ring");if(!o)return;if(!a||!t||!e){o.innerHTML='<div style="opacity:.4;font-size:12px;text-align:center;padding:16px">Connect to view quorum</div>';return}let i=44,r=2*Math.PI*i,l=new Set(s),c=e-s.length,u=s.length,d=Math.max(0,e-t),p=t,m=n<=0?"#ff5555":n<=3?"#ffb86c":"#50fa7b",f=e>0?c/e:0,g=e>0?u/e:0,v=e>0?t/e:0,h=e>0?Math.max(0,n)/e:0,b=e>0?u/e:0;function x(k,T,S,$=8){if(T<=0)return"";let E=k*r,C=T*r;return`<circle r="${i}" cx="50" cy="50" fill="none"
      stroke="${S}" stroke-width="${$}" opacity=".85"
      stroke-dasharray="${C} ${r-C}"
      stroke-dashoffset="${r-E}"
      stroke-linecap="round"
      style="transform-origin:50px 50px;transform:rotate(-90deg)"/>`}o.innerHTML=`
    <div class="qr-wrap">
      <svg viewBox="0 0 100 100" width="100" height="100" style="overflow:visible">
        <!-- Background ring -->
        <circle r="${i}" cx="50" cy="50" fill="none" stroke="rgba(255,255,255,.06)" stroke-width="9"/>
        <!-- Quorum zone (required validators) -->
        ${x(0,v,"rgba(0,255,240,.25)",9)}
        <!-- Margin zone (extra validators) -->
        ${x(v,h,"#50fa7b",9)}
        <!-- Negative UNL (offline) -->
        ${b>0?x(v+h,b,"#ff5555",9):""}
        <!-- Centre text -->
        <text x="50" y="45" text-anchor="middle" fill="${m}" font-size="18" font-weight="700" font-family="monospace">${e}</text>
        <text x="50" y="57" text-anchor="middle" fill="rgba(255,255,255,.45)" font-size="9">validators</text>
      </svg>
      <div class="qr-legend">
        <div class="qr-leg-row"><span class="qr-dot" style="background:rgba(0,255,240,.5)"></span>Required for quorum <strong>${t}</strong></div>
        <div class="qr-leg-row"><span class="qr-dot" style="background:#50fa7b"></span>Margin <strong style="color:${m}">${Math.max(0,n)}</strong></div>
        ${u>0?`<div class="qr-leg-row"><span class="qr-dot" style="background:#ff5555"></span>Offline (nUNL) <strong style="color:#ff5555">${u}</strong></div>`:""}
        <div class="qr-leg-row" style="margin-top:6px;border-top:1px solid rgba(255,255,255,.06);padding-top:6px">
          <span style="opacity:.5;font-size:10px">Need ${t} \xB7 have ${e} \xB7 ${n>0?n+" can fail safely":"\u26A0 AT QUORUM LIMIT"}</span>
        </div>
      </div>
    </div>`}function cw(){var F,H,N;let e=nt,t=(e==null?void 0:e.server_state)??"unknown",n=(e==null?void 0:e.build_version)??"\u2014",s=Number((e==null?void 0:e.uptime)??0),a=e==null?void 0:e.network_id,o=Number((e==null?void 0:e.io_latency_ms)??0),i=String((e==null?void 0:e.jq_trans_overflow)??"0"),r=Number((e==null?void 0:e.peer_disconnects_resources)??0),l=Number((e==null?void 0:e.load_factor)??1),c=Number((e==null?void 0:e.load_factor_net)??1),u=Number((e==null?void 0:e.load_factor_server)??(e==null?void 0:e.load_factor_local)??1),d=Number(((F=e==null?void 0:e.validated_ledger)==null?void 0:F.age)??0),p=(H=e==null?void 0:e.validated_ledger)==null?void 0:H.seq,m=(e==null?void 0:e.complete_ledgers)??"",f=(e==null?void 0:e.state_accounting)??null;d>10&&(je.staleLedger=!0),o>5&&(je.ioStressed=!0),ca("peerDiscon")>5&&(je.peerChurn=!0);let g=w("m2-state");if(g){g.textContent=t;let j=["full","proposing","validating"].includes(t),se=["syncing","tracking","connected"].includes(t);g.className=`state-pill state-${j?"ok":se?"warn":"bad"}`}K("m2-version",n),K("m2-uptime",Mw(s)),K("m2-netid",a===0?"0 (Mainnet)":a===1?"1 (Testnet)":a??"\u2014"),K("m2-ledger-seq",p!=null?Number(p).toLocaleString():"\u2014"),K("m2-ledger-age",d>0?`${d}s`:"< 1s"),K("m2-io-ms",o>0?`${o}ms`:"< 1ms"),K("m2-jq",i==="0"?"0 (clean)":`\u26A0 ${i}`),K("m2-discon",r.toLocaleString());let v=w("m2-ledger-age");v&&(v.className=`kv-v ${d>10?"text-danger":d>5?"text-warn":""}`);let h=Math.min(100,(l-1)/49*100);Tt("m2-load-bar",h,l>5?"bar-danger":l>2?"bar-warn":"bar-ok"),K("m2-load-total",`${l.toFixed(2)}\xD7`),K("m2-load-net",`${c.toFixed(2)}\xD7`),K("m2-load-local",`${u.toFixed(2)}\xD7`);let b=u>c*1.5?"Local node stressed":c>u*1.5?"Network-wide stress":l>1.2?"Distributed":"Normal";K("m2-load-src",b);let x=X.tpsHistory.length?X.tpsHistory[X.tpsHistory.length-1]:null;K("m2-tps",x!=null?x.toFixed(1):"\u2014"),K("m2-txcount",((N=X.ledgerLog[0])==null?void 0:N.txCount)??"\u2014");let k=m==="entire ledger"||m.startsWith("32570"),T=k?100:Pw(m);if(K("m2-ledger-range",m||"\u2014"),K("m2-hist-type",k?"Full History Node":"Pruned / Partial"),K("m2-hist-score",`${T}%`),Tt("m2-hist-bar",T,T<30?"bar-danger":T<70?"bar-warn":"bar-ok"),f){let j=w("m2-state-acct");if(j){let se=["full","syncing","tracking","connected","disconnected"],re=0,pe={};se.forEach(ae=>{var te;pe[ae]=Number(((te=f[ae])==null?void 0:te.duration_us)??0),re+=pe[ae]}),j.innerHTML=re>0?se.map(ae=>{let te=Math.round(pe[ae]/re*100);return te?`<div class="sa-row"><span class="sa-lbl">${ae}</span>
          <div class="bar-track sa-bar"><div class="bar-fill ${ae==="full"?"bar-ok":ae==="syncing"?"bar-warn":"bar-danger"}" style="width:${te}%"></div></div>
          <span class="sa-pct">${te}%</span></div>`:""}).join(""):'<span class="dim">No data</span>'}}let S=(e==null?void 0:e.peers)!=null?Number(e.peers):null,$=S!=null,E=0,C=0,P=!1;zt&&(zt.forEach(j=>{j.inbound===!0?E++:C++}),P=!0);let R=P&&E+C>0?Math.round(E/(E+C)*100):0,O=P?zt.length:S??0,D=O<6?"HIGH":O<15?"MEDIUM":"LOW";O<6&&(je.eclipseRisk=!0),R>80&&(je.peerSaturate=!0),K("m2-peers",$?O:"\u2014"),K("m2-inbound",P?E:$?"\u2014 (cmd restricted)":"\u2014"),K("m2-outbound",P?C:$?"\u2014 (cmd restricted)":"\u2014"),K("m2-ib-pct",P?`${R}%`:"\u2014"),Tt("m2-peer-bar",Math.min(100,O/21*100),O>18?"bar-danger":O>15?"bar-warn":"bar-ok"),Tt("m2-ib-bar",R,R>80?"bar-danger":R>60?"bar-warn":"bar-ok");let I=w("m2-eclipse");I&&(I.textContent=D,I.className=`risk-badge risk-${D.toLowerCase()}`)}function dw(){var C,P,R,O;let e=qn,t=Number(((C=e==null?void 0:e.drops)==null?void 0:C.minimum_fee)??10),n=Number(((P=e==null?void 0:e.drops)==null?void 0:P.open_ledger_fee)??10),s=Number(((R=e==null?void 0:e.drops)==null?void 0:R.median_fee)??10),a=Number(((O=e==null?void 0:e.drops)==null?void 0:O.base_fee)??10),o=Number((e==null?void 0:e.current_ledger_size)??0),i=Number((e==null?void 0:e.expected_ledger_size)??1),r=Number((e==null?void 0:e.current_queue_size)??0),l=Number((e==null?void 0:e.max_queue_size)??1),c=l>0?Math.round(r/l*100):0,u=i>0?o/i:1,d=ca("fees"),p=d>0?Math.round((n-d)/d*100):0,m=Math.min(100,Math.round(Math.log2(Math.max(1,n/10))*14));n>t*10&&(je.feeSpike=!0),c>80&&(je.queuePressure=!0),u>2&&(je.spamLedger=!0);let f=mt.burnDrops.slice(-10),g=f.length?f.reduce((D,I)=>D+I,0)/f.length:0,v=Sw(mt.burnDrops),h=ca("burnDrops"),b=v>0&&mt.burnDrops.length>5?((g-h)/v).toFixed(2):"0.00",x=Math.min(100,Math.abs(Number(b))*20);Math.abs(Number(b))>3&&(je.burnAnomaly=!0);let k=n>5e3?"Severe":n>500?"High":n>100?"Elevated":n>20?"Normal":"Minimal",S={Severe:"#ff5555",High:"#ff9955",Elevated:"#ffb86c",Normal:"#50fa7b",Minimal:"#6272a4"}[k]??"#50fa7b",$=w("m3-pressure");$&&($.textContent=k,$.className=`pressure-badge p-${k.toLowerCase()}`),K("m3-open",`${n} drops`),K("m3-med",`${s} drops`),K("m3-base",`${a} drops`),K("m3-devpct",`${p>0?"+":""}${p}% vs baseline`),K("m3-spam",`${m} / 100`),K("m3-qsize",`${r} / ${l}`),K("m3-qpct",`${c}%`),K("m3-szratio",`${u.toFixed(2)}\xD7`),K("m3-curledger",`${o} txs`),K("m3-expledger",`${i} expected`),K("m3-burn",g>0?`${(g/1e6).toFixed(4)} XRP / ledger`:"\u2014"),K("m3-burnz",`z = ${b}`),Tt("m3-spam-bar",m,m>70?"bar-danger":m>40?"bar-warn":"bar-ok"),Tt("m3-q-bar",c,c>80?"bar-danger":c>50?"bar-warn":"bar-ok"),Tt("m3-sz-bar",Math.min(100,u*50),u>2?"bar-danger":u>1.5?"bar-warn":"bar-ok"),Tt("m3-burn-bar",x,x>60?"bar-danger":x>30?"bar-warn":"bar-ok");let E=w("m3-congestion-summary");if(E){let D=[];u>2&&D.push({icon:"\u{1F6A8}",txt:`Ledger ${u.toFixed(1)}\xD7 normal size \u2014 possible spam burst`,col:"#ff5555"}),c>80&&D.push({icon:"\u26A0",txt:`TX queue ${c}% full \u2014 fee surge imminent`,col:"#ffb86c"}),m>70&&D.push({icon:"\u26A0",txt:`Spam index ${m}/100 \u2014 elevated DDoS risk`,col:"#ffb86c"}),Math.abs(Number(b))>3&&D.push({icon:"\u{1F4C9}",txt:`Burn rate z=${b} \u2014 resource exhaustion pattern`,col:"#ff9955"}),p>200&&D.push({icon:"\u{1F4B8}",txt:`Open fee ${p}% above baseline \u2014 network stress`,col:"#ffb86c"}),E.innerHTML=D.length?D.map(I=>`<div class="cong-line"><span>${I.icon}</span><span style="color:${I.col}">${y(I.txt)}</span></div>`).join(""):'<div class="cong-clear"><span style="color:#50fa7b">\u2713</span> No congestion signals \u2014 network traffic is normal</div>'}}function pw(){var d,p;let e={},t=0;for(let m of xe.values()){if(m.chain==="test")continue;let f=m.version??"unknown";e[f]=(e[f]??0)+1,t++}let n={},s=0;if(Array.isArray(zt))for(let m of zt){let f=(m.version??"unknown").replace(/rippled-/i,"").split(" ")[0];n[f]=(n[f]??0)+1,s++}let a=w("m4-version-dist");if(a&&t>0){let m=Object.entries(e).sort((h,b)=>b[1]-h[1]),f=((d=m[0])==null?void 0:d[0])??"?",g=t>0?Math.round((((p=m[0])==null?void 0:p[1])??0)/t*100):0,v=["#00fff0","#50fa7b","#ffb86c","#bd93f9","#ff5555","#8be9fd"];a.innerHTML=m.slice(0,6).map(([h,b],x)=>{let k=Math.round(b/t*100),T=v[x%v.length],S=h.includes("beta")||h.includes("rc")||h.includes("RC");return`<div class="vd-row">
        <div class="vd-ver-label">
          <span style="color:${T};font-weight:600">${y(h)}</span>
          ${S?'<span class="vd-beta-tag">beta</span>':""}
        </div>
        <div class="vd-bar-wrap">
          <div class="vd-bar-fill" style="width:${k}%;background:${T};opacity:.75"></div>
        </div>
        <span class="vd-count">${b} <span style="opacity:.5">(${k}%)</span></span>
      </div>`}).join("")+`<div class="vd-summary">${t} validators \xB7 ${m.length} versions \xB7 ${g}% on latest (${y(f)})</div>`}let o={"North America":0,Europe:0,"Asia Pacific":0,"Middle East":0,"South America":0,Other:0};function i(m,f){return m>15&&f<-30?"North America":m>-60&&f<-30?"South America":m>35&&f>-30&&f<60?"Europe":m>10&&f>=60&&f<150||m>=-40&&f>=110?"Asia Pacific":m>10&&m<40&&f>=30&&f<70?"Middle East":"Other"}let r=0;for(let m of xe.values()){if(m.chain==="test")continue;let f=$n(m);if(!(f!=null&&f.lat))continue;let g=i(f.lat,f.lng);o[g]=(o[g]??0)+1,r++}let l=w("m4-geo-dist");if(l&&r>0){let m={"North America":"#00fff0",Europe:"#50fa7b","Asia Pacific":"#bd93f9","Middle East":"#ffb86c","South America":"#8be9fd",Other:"#6272a4"},f=Object.entries(o).filter(([,b])=>b>0).sort((b,x)=>x[1]-b[1]),g=f.reduce((b,[,x])=>b+(x/r)**2,0),v=g>.4?"Concentrated":g>.25?"Moderate":"Distributed",h=g>.4?"#ff5555":g>.25?"#ffb86c":"#50fa7b";l.innerHTML=f.map(([b,x])=>{let k=Math.round(x/r*100),T=m[b]??"#6272a4";return`<div class="vd-row">
        <span class="vd-ver-label" style="color:${T};font-weight:600">${y(b)}</span>
        <div class="vd-bar-wrap">
          <div class="vd-bar-fill" style="width:${k}%;background:${T};opacity:.65"></div>
        </div>
        <span class="vd-count">${x} <span style="opacity:.5">(${k}%)</span></span>
      </div>`}).join("")+`<div class="vd-summary">${r} geo-located \xB7 <span style="color:${h}">${v}</span> (HHI ${g.toFixed(2)})</div>`}let c={};for(let m of xe.values()){if(m.chain==="test")continue;let f=$n(m),g=m.provider??(f==null?void 0:f.org)??"Unknown",v=g.match(/AWS|Amazon/i)?"AWS":g.match(/Azure|Microsoft/i)?"Azure":g.match(/GCP|Google/i)?"GCP":g.match(/Hetzner/i)?"Hetzner":g.match(/OVH/i)?"OVH":g.match(/Cloudflare/i)?"Cloudflare":g.match(/Equinix/i)?"Equinix":g.match(/NTT/i)?"NTT":g.match(/Ripple/i)?"Ripple":"Other";c[v]=(c[v]??0)+1}let u=w("m4-provider-dist");if(u){let m=Object.values(c).reduce((f,g)=>f+g,0);if(m>0){let f=Object.entries(c).sort((v,h)=>h[1]-v[1]),g=["#ff5555","#ffb86c","#50fa7b","#00fff0","#bd93f9","#8be9fd","#6272a4"];u.innerHTML=f.slice(0,7).map(([v,h],b)=>{let x=Math.round(h/m*100),k=g[b%g.length],T=x>33?"\u26A0 ":"";return`<div class="vd-row">
          <span class="vd-ver-label" style="color:${k};font-weight:600">${T}${y(v)}</span>
          <div class="vd-bar-wrap">
            <div class="vd-bar-fill" style="width:${x}%;background:${k};opacity:.7;${x>33?"box-shadow:0 0 6px "+k+"88":""}"></div>
          </div>
          <span class="vd-count">${h} <span style="opacity:.5">(${x}%)</span></span>
        </div>`}).join("")}}}var ks="pending";function $m(e){let t=w("amendment-list");if(!t)return;let n=w("amend-pipeline-header"),s=Object.entries(e).map(([u,d])=>({hash:u,...d})),a=s.filter(u=>u.enabled),o=s.filter(u=>!u.enabled&&!u.vetoed).sort((u,d)=>(d.count??0)-(u.count??0)),i=s.filter(u=>u.vetoed),r=o.filter(u=>u.majority),l=o.filter(u=>!u.majority&&(u.count??0)>=(u.threshold??28)*.8);if(o.some(u=>(u.count??0)<(u.threshold??28)*.5)&&(je.amendVeto=!0),n){let u=[{id:"pending",label:"Voting",count:o.length,color:"#8be9fd"},{id:"active",label:"Active",count:a.length,color:"#50fa7b"},{id:"vetoed",label:"Vetoed",count:i.length,color:"#ff5555"},{id:"all",label:"All",count:s.length,color:null}];n.innerHTML=`
      <div class="ap-tabs">
        ${u.map(d=>`
          <button class="ap-tab ${ks===d.id?"ap-tab--active":""}" data-aptab="${d.id}">
            ${d.color?`<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:${d.color};margin-right:5px;vertical-align:middle"></span>`:""}
            ${d.label}
            <span class="ap-tab-count">${d.count}</span>
          </button>`).join("")}
      </div>
      ${r.length?`<div class="ap-alert-bar">\u23F3 ${r.length} amendment${r.length>1?"s":""} reached validator majority \u2014 activates in ~14 days if maintained</div>`:""}
      ${l.length?`<div class="ap-near-bar">\u{1F4C8} ${l.length} amendment${l.length>1?"s":""} approaching 80% threshold</div>`:""}`,n.querySelectorAll(".ap-tab").forEach(d=>{d.onclick=()=>{ks=d.dataset.aptab,$m(e)}})}let c=ks==="active"?a:ks==="vetoed"?i:ks==="all"?s.sort((u,d)=>u.enabled!==d.enabled?u.enabled?1:-1:u.vetoed!==d.vetoed?u.vetoed?1:-1:(d.count??0)-(u.count??0)):o;if(!c.length){t.innerHTML=`<div class="amend-empty">${ks==="vetoed"?"No vetoed amendments":"No data"}</div>`;return}t.innerHTML=c.map(u=>{var $;let d=u.count??0,p=u.threshold??28,m=Math.min(100,Math.round(d/p*100)),f=u.name??`${u.hash.slice(0,10)}...`,g=!!u.enabled,v=!!u.vetoed,h=!!u.majority,b=hm[f]??{},x=($=mt.amendMomentum)==null?void 0:$[u.hash],k="";if(h&&!g&&u.majority){let E=Date.now()-new Date(u.majority).getTime(),C=E>0?Math.floor(E/864e5):0,P=Math.max(0,14-C),R=Math.min(100,Math.round(C/14*100));k=`<div class="ap-countdown">
        <span class="ap-countdown-lbl">Majority held ${C}d \xB7 activates in ~${P}d</span>
        <div class="ap-countdown-track"><div class="ap-countdown-fill" style="width:${R}%"></div></div>
      </div>`}let T=g?"#50fa7b":v?"#ff5555":h?"#ffb86c":m>=80?"#8be9fd":"rgba(255,255,255,.3)",S=g?"Active":v?"Vetoed":h?"Majority":m>=80?"Near":"Voting";return`<div class="ap-row" onclick="window.showAmendDetail('${y(u.hash)}')">
      <div class="ap-row-main">
        <div class="ap-row-top">
          <span class="ap-name">${y(f)}</span>
          <span class="ap-status-tag" style="border-color:${T}44;color:${T}">${S}</span>
        </div>
        ${b.purpose?`<div class="ap-purpose">${y(b.purpose)}</div>`:""}
        ${g?`<div class="ap-active-note">\u2713 Running on all ledgers${b.intro?" \xB7 since "+b.intro:""}</div>`:`<div class="ap-vote-row">
          <div class="ap-vote-track">
            <div class="ap-vote-fill" style="width:${m}%;background:${T};opacity:${g?1:.75}"></div>
            <div class="ap-vote-thresh" title="80% threshold"></div>
          </div>
          <span class="ap-vote-label">${d}/${p} <span style="opacity:.5">(${m}%)</span></span>
        </div>`}
        ${k}
      </div>
    </div>`}).join("")}function uw(e){fr={},Object.entries(e).forEach(([t,n])=>{fr[t]={hash:t,...n}})}window.showAmendDetail=function(e){let t=fr[e];if(!t)return;let n=t.name||`${e.slice(0,16)}...`,s=hm[n]||{},a=t.count??0,o=t.threshold??28,i=Math.min(100,Math.round(a/o*100)),r=t.enabled?"Active on Ledger":t.vetoed?"Vetoed":t.majority?"Majority Reached":"Voting in Progress",l=t.enabled?"adm-s-ok":t.vetoed?"adm-s-bad":t.majority?"adm-s-warn":"adm-s-info",c=t.enabled?"bar-ok":t.vetoed?"bar-danger":t.majority?"bar-warn":"bar-info",u=t.majority&&!t.enabled?`
    <div class="adm-note adm-note-warn">
      Majority reached. If maintained for 2 weeks this amendment will auto-activate.
      Majority since: ${y(String(t.majority))}
    </div>`:"",d=w("amend-modal-overlay"),p=w("amend-modal-body");!d||!p||(p.innerHTML=`
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
        ${u}`}
    </div>
    <div class="adm-meta">
      <div class="adm-mi"><span class="adm-mk">Node supports</span><span class="adm-mv ${t.supported?"adm-ok":"adm-bad"}">${t.supported?"Yes":"No \u2014 upgrade required"}</span></div>
      <div class="adm-mi"><span class="adm-mk">Vetoed by node</span><span class="adm-mv ${t.vetoed?"adm-bad":""}">${t.vetoed?"Yes":"No"}</span></div>
      ${s.intro?`<div class="adm-mi"><span class="adm-mk">First available</span><span class="adm-mv">${y(s.intro)}</span></div>`:""}
    </div>
    <div class="adm-footer">
      <a class="adm-link" href="https://xrpl.org/known-amendments.html" target="_blank" rel="noopener noreferrer">Amendment Reference</a>
      <a class="adm-link" href="https://xrpl.org/consensus.html" target="_blank" rel="noopener noreferrer">Consensus Docs</a>
    </div>`,d.style.display="flex",d.addEventListener("click",m=>{m.target===d&&window.closeAmendModal()},{once:!0}))};window.closeAmendModal=function(){let e=w("amend-modal-overlay");e&&(e.style.display="none")};function mw(e){if(window.L){e();return}if(!document.querySelector("#leaflet-css")){let n=document.createElement("link");n.id="leaflet-css",n.rel="stylesheet",n.href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css",document.head.appendChild(n)}let t=document.createElement("script");t.src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js",t.onload=e,document.head.appendChild(t)}function fw(e,t,n,s,a=!1){w("world-map-container")&&mw(()=>hw(e,t,n,s,a))}function hw(e,t,n,s,a=!1){let o=w("world-map-container");if(!o)return;let i=new Set(n||[]),r=new Set(e||[]),l=new Set(t||[]),c=X.currentNetwork||"xrpl-mainnet";if(tt&&co!==c&&(tt.remove(),tt=null,tn=[],co=null),!tt){o.innerHTML="";let k=document.createElement("div");k.id="wm-leaflet",k.style.cssText="width:100%;height:440px;",o.appendChild(k),tt=L.map("wm-leaflet",{center:[25,5],zoom:2,minZoom:1,maxZoom:12,zoomControl:!0,attributionControl:!0,worldCopyJump:!0}),L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",{attribution:'&copy; <a href="https://carto.com">CARTO</a> &copy; <a href="https://openstreetmap.org">OSM</a>',subdomains:"abcd",maxZoom:19}).addTo(tt),co=c}tn.forEach(k=>{try{k.remove()}catch{}}),tn=[];function u(k){return i.has(k)?"nunl":r.has(k)&&l.has(k)?"both":r.has(k)?"unl":l.has(k)?"dunl":"other"}hr={};let d={};for(let[k,T]of xe){let S=$n(T);if(!(S!=null&&S.lat)||!(S!=null&&S.lng))continue;let $=`${(Math.round(S.lat*2)/2).toFixed(1)},${(Math.round(S.lng*2)/2).toFixed(1)}`;d[$]||(d[$]={lat:S.lat,lng:S.lng,keys:[],city:S.city,org:S.org}),d[$].keys.push(k)}if(Object.values(d).forEach(k=>{let T=k.keys.length,S=k.keys.map(u),$=["nunl","both","unl","dunl","other"].find(O=>S.includes(O))||"other",E=Oe[$],C=T>5?13:T>2?10:7,P=L.divIcon({html:`<div class="wm-lmarker wm-lmarker-val ${$==="nunl"?"wm-lmarker-nunl":""} ${a?"wm-lmarker-ref":""}"
                  style="--mc:${E.hex};--mg:${E.glow};"
                  title="${k.keys.map(O=>it(O).label).join(", ")}">
        <div class="wm-lring"></div>
        <div class="wm-ldot" style="width:${C*2}px;height:${C*2}px;">${T>1?`<span>${T}</span>`:""}</div>
      </div>`,className:"",iconSize:[(C+8)*2,(C+8)*2],iconAnchor:[C+8,C+8]}),R=L.marker([k.lat,k.lng],{icon:P}).bindPopup(gw(k.keys,k.city,k.org,i,r,l,a),{maxWidth:380,className:"wm-popup-wrap"}).addTo(tt);k.keys.forEach(O=>{hr[O]=R}),tn.push(R)}),a){let k=L.control({position:"bottomleft"});k.onAdd=()=>{let T=L.DomUtil.create("div","wm-ref-banner");return T.innerHTML="\u{1F4E1} Reference positions \xB7 live validator list unavailable from endpoint",T},k.addTo(tt),tn.push(k)}let p=[...xe.keys()].filter(k=>{var S;return((S=xe.get(k).geo)==null?void 0:S.lat)!=null||fo[k]}).length,m=xe.size-p;if(m>0){let k=L.control({position:"bottomright"});k.onAdd=()=>{let T=L.DomUtil.create("div","wm-unknown-ctrl");return T.innerHTML=`+ ${m} validators \xB7 location unknown`,T},k.addTo(tt),tn.push(k)}G0.forEach(k=>{let T=L.divIcon({html:`<div class="wm-lmarker wm-lmarker-pub">
        <div class="wm-lring"></div>
        <div class="wm-ldot" style="width:10px;height:10px;"></div>
      </div>`,className:"",iconSize:[20,20],iconAnchor:[10,10]}),S=L.marker([k.lat,k.lng],{icon:T}).bindPopup(`
        <div class="wm-popup-inner">
          <div class="wm-popup-badge wm-popup-badge-pub">Public Node</div>
          <div class="wm-popup-name">${y(k.label)}</div>
          <div class="wm-popup-row"><span class="wm-popup-key">Location</span><span>\u{1F4CD} ${y(k.city)}</span></div>
          <div class="wm-popup-row"><span class="wm-popup-key">Operator</span><span>${y(k.org)}</span></div>
          <div class="wm-popup-row"><span class="wm-popup-key">Type</span><span>Full history node</span></div>
        </div>`,{maxWidth:260,className:"wm-popup-wrap"}).addTo(tt);tn.push(S)});let f=Array.isArray(s)?s:[],g=f.filter(k=>k.inbound===!0).length,v=f.length-g,h=f.length>0?`${f.length} peers (${g}\u2193 ${v}\u2191)`:`${Number((nt==null?void 0:nt.peers)??0)} peers`,b=L.control({position:"topleft"});b.onAdd=()=>{let k=L.DomUtil.create("div","wm-legend-ctrl");return k.innerHTML=`
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${Oe.unl.hex};box-shadow:0 0 5px ${Oe.unl.glow}"></span>UNL Validator</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${Oe.dunl.hex};box-shadow:0 0 5px ${Oe.dunl.glow}"></span>dUNL only</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${Oe.both.hex};box-shadow:0 0 5px ${Oe.both.glow}"></span>UNL + dUNL</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${Oe.other.hex};box-shadow:0 0 5px ${Oe.other.glow}"></span>Other validator</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${Oe.nunl.hex};box-shadow:0 0 5px ${Oe.nunl.glow}"></span>Negative UNL</div>
      <div class="wm-leg-row"><span class="wm-leg-dot" style="background:${Oe.pub.hex};box-shadow:0 0 5px ${Oe.pub.glow}"></span>Public Node</div>
      <div class="wm-leg-row wm-leg-peers"><span class="wm-leg-dot" style="background:#8be9fd"></span>${h}</div>
      <div class="wm-leg-src" style="opacity:.55;font-size:10px;margin-top:4px;">
        Registry: ${kn==="live"?"\u{1F7E2} live":"\u{1F7E1} fallback"}
      </div>`,k},b.addTo(tt),tn.push(b);let x=tn.filter(k=>k&&typeof k.getLatLng=="function");if(x.length>=2)try{let k=L.latLngBounds(x.map(T=>T.getLatLng()));k.isValid()&&tt.fitBounds(k.pad(.15),{maxZoom:6})}catch{}try{window.dispatchEvent(new CustomEvent("nalulf-network-map",{detail:{map:tt,networkId:co}}))}catch{}}function gw(e,t,n,s,a,o,i=!1){let r=e.length>1,l=e.map(u=>{let d=it(u),p=s.has(u),m=a.has(u),f=o.has(u),g=u.slice(0,20)+"...",v,h;return p?(v=Oe.nunl.hex,h="Negative UNL"):m&&f?(v=Oe.both.hex,h="UNL + dUNL"):m?(v=Oe.unl.hex,h="UNL"):f?(v=Oe.dunl.hex,h="dUNL"):(v=Oe.other.hex,h="Other"),`<div class="wm-popup-val-row">
      <span class="wm-popup-val-dot" style="background:${v};box-shadow:0 0 6px ${v}66"></span>
      <div class="wm-popup-val-info">
        <span class="wm-popup-val-name">${y(d.label)}</span>
        ${d.domain?`<span class="wm-popup-val-domain">${y(d.domain)}</span>`:""}
        <span class="wm-popup-val-key"
              onclick="navigator.clipboard?.writeText('${y(u)}');this.textContent='\u2713 Copied!';setTimeout(()=>this.textContent='${y(g)}',1400)"
              title="Click to copy full key">${y(g)}</span>
        <div class="wm-popup-val-tags">
          <span class="wm-popup-ok-tag" style="border-color:${v}66;color:${v}">${h}</span>
          ${d.provider?`<span class="wm-popup-prov">${y(d.provider)}</span>`:""}
        </div>
      </div>
    </div>`}).join(""),c=[...new Set(e.map(u=>{var p;let d=it(u);return d.provider??((p=$n(d))==null?void 0:p.org)??null}).filter(Boolean))];return`<div class="wm-popup-inner">
    <div class="wm-popup-loc-row">
      <span class="wm-popup-loc-icon">\u{1F4CD}</span>
      <div>
        <div class="wm-popup-name">${y(t||"Unknown Location")}</div>
        ${c.map(u=>`<div class="wm-popup-org">${y(u)}</div>`).join("")}
      </div>
    </div>
    <div class="wm-popup-badges">
      ${r?`<div class="wm-popup-badge wm-popup-badge-cluster">${e.length} Validators at this location</div>`:""}
      ${i?'<div class="wm-popup-badge wm-popup-badge-ref">Reference data</div>':""}
    </div>
    <div class="wm-popup-divider"></div>
    <div class="wm-popup-vals">${l}</div>
  </div>`}var $s=[];function bw(){let e=Object.keys(je),t=e.reduce((r,l)=>{var c;return r+(((c=nn[l])==null?void 0:c.w)??1)},0),n=t>=W0;for(e.forEach(r=>{var l,c;$s.find(u=>u.key===r&&Date.now()-u.ts<3e5)||$s.push({key:r,label:((l=nn[r])==null?void 0:l.label)??r,ts:Date.now(),weight:((c=nn[r])==null?void 0:c.w)??1})});$s.length>20;)$s.shift();let s=w("adversarial-alert");s&&(s.classList.toggle("adv-active",n),s.classList.toggle("adv-inactive",!n));let a=w("adversarial-score");if(a){let r=t===0?"All Clear":t<3?"Monitor":t<5?"Elevated":t<10?"High":"Critical",l=t===0?"#50fa7b":t<3?"#8be9fd":t<5?"#ffb86c":t<10?"#ff9955":"#ff5555";a.innerHTML=`<span style="color:${l};font-weight:700">${r}</span>
      <span style="opacity:.5;font-size:11px;margin-left:8px">threat score ${t}</span>`,a.className="adv-score"}let o=w("adversarial-signals");if(!o)return;if(!e.length)o.innerHTML=`<div class="adv-clear-card">
      <span class="adv-clear-icon">\u2713</span>
      <div>
        <div class="adv-clear-title">No Active Signals</div>
        <div class="adv-clear-sub">All ${Object.keys(nn).length} threat indicators are nominal</div>
      </div>
    </div>`;else{let r=e.filter(d=>{var p;return(((p=nn[d])==null?void 0:p.w)??1)>=3}),l=e.filter(d=>{var p;return(((p=nn[d])==null?void 0:p.w)??1)===2}),c=e.filter(d=>{var p;return(((p=nn[d])==null?void 0:p.w)??1)===1}),u=(d,p,m)=>p.length===0?"":`
      <div class="adv-group-title" style="color:${m}">${d} (${p.length})</div>
      ${p.map(f=>{let g=nn[f]??{w:1,label:f},v=g.label.split(" \u2014 "),h=v[0],b=v[1]||"";return`<div class="adv-sig-card adv-sig-${g.w>=3?"critical":g.w>=2?"elevated":"monitor"}">
          <div class="adv-sig-top">
            <span class="adv-sig-dot" style="background:${m}"></span>
            <span class="adv-sig-title">${y(h)}</span>
            <span class="adv-sig-badge" style="border-color:${m}44;color:${m}">W${g.w}</span>
          </div>
          ${b?`<div class="adv-sig-detail">${y(b)}</div>`:""}
        </div>`}).join("")}`;o.innerHTML=u("Critical",r,"#ff5555")+u("Elevated",l,"#ffb86c")+u("Monitor",c,"#8be9fd")}let i=w("adversarial-history");if(i&&$s.length){let r=Date.now();i.innerHTML=$s.slice(-8).reverse().map(l=>{let c=Math.round((r-l.ts)/6e4),u=e.includes(l.key);return`<div class="adv-hist-row ${u?"adv-hist-active":"adv-hist-resolved"}">
        <span class="adv-hist-dot"></span>
        <span class="adv-hist-lbl">${y(l.label.split(" \u2014 ")[0].substring(0,40))}</span>
        <span class="adv-hist-time">${c<1?"now":`${c}m ago`} ${u?'<span class="adv-hist-tag-active">active</span>':'<span class="adv-hist-tag-res">resolved</span>'}</span>
      </div>`}).join("")}}function vr(e,t){var S,$,E,C;let n=w("nh-banner");if(!n)return;if(!e||X.connectionState!=="connected"){K("nh-score","\u2014"),K("nh-grade","Disconnected"),K("nh-sub",t||"Connect to begin"),n.className="nh-banner nh-dead",cm({}),dm(null);return}let{info:s,fee:a,vals:o}=e,i=100,r=(s==null?void 0:s.server_state)??"unknown";["full","proposing","validating"].includes(r)||(i-=r==="syncing"?20:40);let l=Number((s==null?void 0:s.load_factor)??1);l>2&&(i-=10),l>5&&(i-=15),l>20&&(i-=20);let c=Number((s==null?void 0:s.peers)??0);c<6?i-=30:c<15&&(i-=10);let u=Number(((S=s==null?void 0:s.last_close)==null?void 0:S.converge_time_s)??0);u>6&&(i-=10),u>10&&(i-=15);let d=Number((($=s==null?void 0:s.validated_ledger)==null?void 0:$.age)??0);d>5&&(i-=5),d>10&&(i-=15);let p=Number(((E=a==null?void 0:a.drops)==null?void 0:E.open_ledger_fee)??10);p>500&&(i-=5),p>2e3&&(i-=10);let m=((C=o==null?void 0:o.trusted_validator_keys)==null?void 0:C.length)??0,f=(o==null?void 0:o.validation_quorum)??0;f>0&&m<f&&(i-=30);let g=((s==null?void 0:s.negative_unl)??[]).length;i-=Math.min(20,g*4);let v=Object.keys(je).reduce((P,R)=>{var O;return P+(((O=nn[R])==null?void 0:O.w)??1)},0);i-=Math.min(25,v*3),i=Math.max(0,Math.min(100,Math.round(i)));let h=Object.keys(je).length,{grade:b,status:x,cls:k}=vw(i);K("nh-score",x),K("nh-grade",b),K("nh-sub",`${new Date().toLocaleTimeString()} \xB7 ${h>0?h+" signal"+(h!==1?"s":"")+" active":"All signals clear"}`),n.className=`nh-banner nh-${k}`;let T=w("nh-ring");if(T){let P=2*Math.PI*28;T.style.strokeDasharray=P,T.style.strokeDashoffset=P*(1-i/100);let R=k==="great"?"#00fff0":k==="good"?"#50fa7b":k==="fair"?"#ffb86c":k==="warn"?"#ff9955":"#ff5555";T.style.stroke=R}cm({st:r,pc:c,q:f,tc:m,lf:l,cvg:u,age:d,nc:g}),dm({info:s,fee:a,vals:o})}function vw(e){return e>=90?{grade:"All Systems Nominal",status:"Optimal",cls:"great"}:e>=70?{grade:"Operating Normally",status:"Good",cls:"good"}:e>=50?{grade:"Minor Issues Detected",status:"Watch",cls:"fair"}:e>=30?{grade:"Attention Required",status:"Warning",cls:"warn"}:{grade:"Critical Issues",status:"Critical",cls:"bad"}}function cm(e){Un("nh-v-state",["full","proposing","validating"].includes(e.st)?"ok":e.st==="syncing"?"warn":"bad",e.st??"\u2014"),Un("nh-v-peers",(e.pc??0)>=15?"ok":(e.pc??0)>=6?"warn":"bad",e.pc!=null?`${e.pc} peers`:"\u2014"),Un("nh-v-cvg",(e.cvg??0)<4?"ok":(e.cvg??0)<7?"warn":"bad",e.cvg!=null?`${Number(e.cvg).toFixed(1)}s`:"\u2014"),Un("nh-v-age",(e.age??0)<3?"ok":(e.age??0)<8?"warn":"bad",e.age!=null?`${Number(e.age)}s ago`:"\u2014"),Un("nh-v-load",(e.lf??1)<2?"ok":(e.lf??1)<5?"warn":"bad",e.lf!=null?`${Number(e.lf).toFixed(2)}\xD7 load`:"\u2014"),Un("nh-v-nunl",(e.nc??0)===0?"ok":(e.nc??0)<=2?"warn":"bad",e.nc!=null?e.nc===0?"None offline":`${e.nc} offline`:"\u2014");let t=e.q??0,n=e.tc??0,s=n-t;Un("nh-v-quorum",s>3?"ok":s>0?"warn":"bad",t>0?`${t} required \xB7 margin ${s}`:"\u2014")}function Un(e,t,n){let s=w(e);s&&(s.textContent=n,s.className=`nh-vval nh-vval--${t}`)}function dm(e){let t=w("nh-health-checks");if(!t)return;if(!e){t.innerHTML='<div class="hc-disconnected">Connect to an XRPL node to run health checks</div>';return}let{info:n,fee:s,vals:a}=e,i=[{label:"Node State",group:"consensus",icon:"\u2B21",check:()=>{let p=(n==null?void 0:n.server_state)||"unknown",m=["full","proposing","validating"].includes(p),f=p==="syncing"||p==="tracking";return{value:p,status:m?"ok":f?"watch":"alert",note:m?"Participating in consensus":f?"Catching up to network":"Not participating"}}},{label:"Quorum Margin",group:"consensus",icon:"\u2696",check:()=>{var g;let p=((g=a==null?void 0:a.trusted_validator_keys)==null?void 0:g.length)??0,m=(a==null?void 0:a.validation_quorum)??0,f=p-m;return m?{value:`${f} spare`,status:f>3?"ok":f>0?"watch":"alert",note:f>3?`${m} of ${p} needed \u2014 ${f} can go offline safely`:f>0?`Only ${f} validator(s) above quorum \u2014 very tight`:"Below quorum \u2014 consensus may stall"}:{value:"\u2014",status:"watch",note:"Validator data not available"}}},{label:"Negative UNL",group:"consensus",icon:"\u26D4",check:()=>{let p=((n==null?void 0:n.negative_unl)||[]).length;return{value:p===0?"None":`${p} listed`,status:p===0?"ok":p<=2?"watch":"alert",note:p===0?"All UNL validators are online":`${p} validator(s) temporarily excluded from consensus counting`}}},{label:"Ledger Age",group:"consensus",icon:"\u23F1",check:()=>{var m;let p=Number(((m=n==null?void 0:n.validated_ledger)==null?void 0:m.age)??0);return{value:p<2?"< 1s":`${p}s`,status:p<5?"ok":p<10?"watch":"alert",note:p<5?"Ledger closing on schedule (3\u20134s target)":p<10?"Slightly delayed \u2014 network may be busy":"Ledger stalled \u2014 consensus issue likely"}}},{label:"Convergence Time",group:"consensus",icon:"\u{1F504}",check:()=>{var m;let p=Number(((m=n==null?void 0:n.last_close)==null?void 0:m.converge_time_s)??0);return{value:p>0?`${p.toFixed(1)}s`:"\u2014",status:p<4?"ok":p<7?"watch":"alert",note:p<4?"Validators agreeing quickly":p<7?"Slightly slow \u2014 check for network latency":"Slow convergence \u2014 validator disagreement or network partition"}}},{label:"Peer Count",group:"infra",icon:"\u{1F517}",check:()=>{let p=Number((n==null?void 0:n.peers)??0);return{value:`${p} peers`,status:p>=15?"ok":p>=6?"watch":"alert",note:p>=15?"Well-connected to the network":p>=6?"Below recommended (15+) \u2014 consider adding peers":"Critically low \u2014 eclipse attack risk is high"}}},{label:"Load Factor",group:"infra",icon:"\u26A1",check:()=>{let p=Number((n==null?void 0:n.load_factor)??1);return{value:`${p.toFixed(2)}\xD7`,status:p<2?"ok":p<5?"watch":"alert",note:p<2?"Normal load \u2014 node processing freely":p<5?"Elevated load \u2014 fees increasing":"High load \u2014 this node is throttling transactions"}}},{label:"IO Latency",group:"infra",icon:"\u{1F4BE}",check:()=>{let p=Number((n==null?void 0:n.io_latency_ms)??0);return{value:p>0?`${p}ms`:"< 1ms",status:p<2?"ok":p<10?"watch":"alert",note:p<2?"Storage and network I/O responding well":p<10?"Moderate I/O latency \u2014 monitor disk/network":"High I/O latency \u2014 storage or network bottleneck"}}},{label:"Job Queue",group:"infra",icon:"\u{1F4CB}",check:()=>{let p=Number((n==null?void 0:n.jq_trans_overflow)??0);return{value:p===0?"Clear":`${p} overflow`,status:p===0?"ok":"alert",note:p===0?"No transaction job queue overflows":"Queue overflowing \u2014 node is overwhelmed, upgrade resources"}}},{label:"Fee Pressure",group:"ledger",icon:"\u{1F4B8}",check:()=>{var f;let p=Number(((f=s==null?void 0:s.drops)==null?void 0:f.open_ledger_fee)??10),m=p<100?"Minimal":p<500?"Elevated":p<5e3?"High":"Severe";return{value:`${p} drops`,status:p<100?"ok":p<500?"watch":"alert",note:p<100?"Normal transaction fees \u2014 network not congested":p<500?"Fees rising \u2014 moderate network congestion":"High fees \u2014 significant congestion or spam attack"}}},{label:"TX Queue Fill",group:"ledger",icon:"\u{1F5C2}",check:()=>{let p=Number((s==null?void 0:s.current_queue_size)??0),m=Number((s==null?void 0:s.max_queue_size)??1),f=m>0?Math.round(p/m*100):0;return{value:`${f}% (${p}/${m})`,status:f<50?"ok":f<80?"watch":"alert",note:f<50?`Queue at ${f}% \u2014 plenty of headroom`:f<80?`Queue ${f}% full \u2014 fee spike likely soon`:"Queue nearly full \u2014 transactions being dropped"}}}].map(p=>({...p,result:p.check()})),r=i.filter(p=>p.result.status==="ok").length,l=i.filter(p=>p.result.status==="watch").length,c=i.filter(p=>p.result.status==="alert").length,u=w("nh-health-summary");u&&(u.innerHTML=`
      <span class="hcs-count hcs-pass">${r}</span><span class="hcs-lbl">nominal</span>
      <span class="hcs-sep">\xB7</span>
      <span class="hcs-count hcs-warn">${l}</span><span class="hcs-lbl">watch</span>
      <span class="hcs-sep">\xB7</span>
      <span class="hcs-count hcs-fail">${c}</span><span class="hcs-lbl">alert</span>
      <span class="hcs-total">of ${i.length} checks</span>`);let d={consensus:"Consensus Health",infra:"Node Infrastructure",ledger:"Ledger & Fees"};t.innerHTML=Object.entries(d).map(([p,m])=>{let f=i.filter(x=>x.group===p),g=f.map(x=>{let k=x.result.status,T=k==="ok"?"hc-ok":k==="watch"?"hc-warn":"hc-fail",S="\u25CF";return`<div class="hc-item ${T}">
        <div class="hc-item-top">
          <span class="hc-dot" style="background:${k==="ok"?"#50fa7b":k==="watch"?"#ffb86c":"#ff5555"}"></span>
          <span class="hc-label">${y(x.icon)} ${y(x.label)}</span>
          <span class="hc-value">${y(x.result.value)}</span>
        </div>
        <div class="hc-note">${y(x.result.note)}</div>
      </div>`}).join(""),v=f.filter(x=>x.result.status==="ok").length;return`<div class="hc-group ${f.filter(x=>x.result.status==="alert").length>0?"hcg-alert":v===f.length?"hcg-ok":"hcg-watch"}">
      <div class="hc-group-title">${y(m)}
        <span class="hcg-badge">${v}/${f.length}</span>
      </div>
      <div class="hc-group-items">${g}</div>
    </div>`}).join("")}function yw(e){var t,n,s,a,o,i,r,l,c,u;e&&(ot("burnDrops",(e.avgFee||0)*1e6*(e.txPerLedger??0)),ot("dexOffers",((t=e.txTypes)==null?void 0:t.OfferCreate)??0),ot("ammSwaps",(((n=e.txTypes)==null?void 0:n.AMMDeposit)??0)+(((s=e.txTypes)==null?void 0:s.AMMWithdraw)??0)+(((a=e.txTypes)==null?void 0:a.AMMBid)??0)),ot("newAccounts",((o=e.txTypes)==null?void 0:o.AccountSet)??0),ot("txPayment",((i=e.txTypes)==null?void 0:i.Payment)??0),ot("txNFT",(((r=e.txTypes)==null?void 0:r.NFTokenMint)??0)+(((l=e.txTypes)==null?void 0:l.NFTokenBurn)??0)+(((c=e.txTypes)==null?void 0:c.NFTokenCreateOffer)??0)+(((u=e.txTypes)==null?void 0:u.NFTokenAcceptOffer)??0)),ot("txLedger",e.txPerLedger??0),ot("tps",e.tps??(e.txPerLedger??0)/3.5),ot("closeTime",e.closeTime??3.5))}function ww(e){let t=X.tpsHistory.length?X.tpsHistory[X.tpsHistory.length-1]:null;K("m2-tps",t!=null?t.toFixed(1):"\u2014"),K("m2-txcount",e.txPerLedger??"\u2014"),e.successRate!=null&&K("m2-success",`${e.successRate.toFixed(0)}%`)}async function ra({force:e=!1}={}){if(!Ss()&&!e)return;let t=Date.now();if(!e&&t-rm<H0)return;rm=t;let n=w("latency-list");if(!n)return;let s=Xr[X.currentNetwork]??[],a=++cr;n.innerHTML=s.map((i,r)=>`
    <div class="latency-row lat-pending" id="lat-row-${r}">
      <div class="lat-ep">
        <span class="lat-name">${y(i.name)}</span>
        <span class="lat-url">${y(i.url)}</span>
      </div>
      <div class="lat-bwrap"><div class="lat-bfill" id="lat-bar-${r}" style="width:0%"></div></div>
      <span class="lat-val" id="lat-val-${r}">\u2014</span>
    </div>`).join("");let o=w("btn-ping-all");o&&(o.disabled=!0);try{for(let i=0;i<s.length;i++){if(a!==cr)return;await xw(s[i],i),await Lw(z0)}}finally{a===cr&&o&&(o.disabled=!1)}}async function xw(e,t){var i;let n=w(`lat-val-${t}`),s=w(`lat-bar-${t}`),a=w(`lat-row-${t}`);a==null||a.classList.remove("lat-pending"),a==null||a.classList.add("lat-probing"),n&&(n.innerHTML='<span class="spinner"></span>');let o=performance.now();try{let r=new WebSocket(e.url);await new Promise((u,d)=>{let p=setTimeout(()=>d(),X0);r.onopen=()=>{clearTimeout(p),u()},r.onerror=()=>{clearTimeout(p),d()}});let l=Math.round(performance.now()-o);try{r.close()}catch{}let c=l<100?"lat-fast":l<300?"lat-med":"lat-slow";n&&(n.textContent=`${l}ms`,n.className=`lat-val ${c}`),s&&(s.style.width=`${Math.min(100,l/600*100)}%`),a==null||a.classList.toggle("lat-active",((i=X.wsConn)==null?void 0:i.url)===e.url)}catch{n&&(n.textContent="timeout",n.className="lat-val lat-slow")}finally{a==null||a.classList.remove("lat-probing")}}function kw(){if(document.getElementById("vg-tab-styles"))return;let e=document.createElement("style");e.id="vg-tab-styles",e.textContent=`
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
  `,document.head.appendChild(e)}function $w(){if(document.getElementById("m4-panel"))return;let e=[()=>document.querySelector('[data-section="fee-market"]'),()=>document.querySelector('[data-section="infrastructure"]'),()=>document.querySelector("#tab-network .section-grid"),()=>document.querySelector("#tab-network"),()=>document.body],t=null;for(let a of e)if(t=a(),t)break;if(!t)return;t.insertAdjacentHTML("beforeend",`
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
  `,document.getElementById("net-panel-styles")||document.head.appendChild(s)}function ot(e,t){mt[e]||(mt[e]=[]),mt[e].push(Number(t)),mt[e].length>j0&&mt[e].shift()}function ca(e){let t=mt[e]??[];return t.length?t.reduce((n,s)=>n+s,0)/t.length:0}function Sw(e){if(e.length<2)return 0;let t=e.reduce((n,s)=>n+s,0)/e.length;return Math.sqrt(e.reduce((n,s)=>n+(s-t)**2,0)/e.length)}function Tw(){try{let e=localStorage.getItem(pm);if(!e)return;let t=JSON.parse(e);Object.keys(mt).forEach(n=>{Array.isArray(t[n])&&(mt[n]=t[n])})}catch{}}function Cw(){try{localStorage.setItem(pm,JSON.stringify(mt))}catch{}}function K(e,t){let n=w(e);n&&(n.textContent=t??"\u2014")}function Tt(e,t,n){let s=w(e);s&&(s.style.width=`${Math.min(100,Math.max(0,Number(t)||0))}%`,s.className=`bar-fill ${n??""}`)}function Pw(e){if(!e)return 0;let t=e.match(/(\d+)-(\d+)/);if(!t)return 10;let n=Number(t[2])-Number(t[1]);return n>1e7?95:n>1e6?70:n>1e5?40:15}function Mw(e){if(!e)return"\u2014";let t=Math.floor(e/86400),n=Math.floor(e%86400/3600),s=Math.floor(e%3600/60);return t>0?`${t}d ${n}h`:n>0?`${n}h ${s}m`:`${s}m`}function Lw(e){return new Promise(t=>setTimeout(t,e))}var Aw={"xrpl-ledger":{title:"XRPL Ledger",subtitle:"What a ledger is, what validated means, and how to interpret ledger snapshots.",sections:[{heading:"In simple terms",paragraphs:["Think of the XRP Ledger (XRPL) as a public spreadsheet that the whole network agrees on.","A \u201Cledger version\u201D is one snapshot of that spreadsheet: balances, trustlines, offers, AMMs, and more.","When a ledger becomes \u201Cvalidated\u201D, it\u2019s final\u2014analytics based on validated ledgers reflect settled history."],bullets:["Ledger Index = the ledger number (sequence).","Ledger Hash = fingerprint of that ledger\u2019s contents.","Open \u2192 Closed \u2192 Validated = in-progress \u2192 proposed snapshot \u2192 final snapshot."]},{heading:"How NaluLF uses this",paragraphs:["NaluLF listens to validated ledger events, then summarizes what changed and what patterns are emerging.","You can quickly see dominant transaction types, fee pressure, DEX/AMM bursts, and concentration signals."],bullets:["Live stream cards summarize each ledger close.","Narratives turn raw changes into readable reporting.","Signals are heuristics (useful indicators, not proof)."]}],links:[{label:"XRPL Docs: Ledgers (overview)",url:"https://xrpl.org/docs/concepts/ledgers"},{label:"Open / Closed / Validated Ledgers",url:"https://xrpl.org/docs/concepts/ledgers/open-closed-validated-ledgers"},{label:"Ledger Structure",url:"https://xrpl.org/docs/concepts/ledgers/ledger-structure"},{label:"Ledger Header (hash/index basics)",url:"https://xrpl.org/docs/references/protocol/ledger-data/ledger-header"}],ctas:[{label:"Launch Dashboard \u2192",action:"auth:signup"},{label:"Close",action:"modal:close"}]},"accounts-trustlines":{title:"Accounts, Reserves, and Trustlines",subtitle:"How addresses work, why reserves exist, and what trustlines mean for tokens.",sections:[{heading:"In simple terms",paragraphs:["An XRPL account is a public address with a balance and settings (flags).","Reserves exist to prevent ledger spam: certain objects (offers, trustlines, signer lists) require reserved XRP.","Trustlines are \u201Cpermission slips\u201D that prevent you from receiving random issued tokens you didn\u2019t opt into."],bullets:["Reserves: base reserve + owner reserve for certain objects.","Trustlines: define limits and balances for issued tokens.","Flags/settings: control behaviors like Deposit Authorization."]},{heading:"Why this matters for investigations",paragraphs:["During compromises, account settings and objects can change quickly.","Trustlines and offers can reveal what tokens/markets are being targeted."],bullets:["Inspector helps you read balances, flags, and trustlines.","Reserve signals can hint at heavy offer/trustline usage."]}],links:[{label:"AccountRoot (ledger entry)",url:"https://xrpl.org/docs/references/protocol/ledger-data/ledger-entry-types/accountroot"},{label:"Reserves (why they exist)",url:"https://xrpl.org/docs/concepts/accounts/reserves"},{label:"Trust Line Tokens (concept)",url:"https://xrpl.org/docs/concepts/tokens/fungible-tokens/trust-line-tokens"},{label:"account_lines API (trustlines)",url:"https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_lines"},{label:"Deposit Authorization (DepositAuth)",url:"https://xrpl.org/docs/concepts/accounts/depositauth"},{label:"XRPL: Cryptographic Keys",url:"https://xrpl.org/docs/concepts/accounts/cryptographic-keys"}],ctas:[{label:"Inspect an Address \u2192",action:"auth:login"},{label:"Close",action:"modal:close"}]},"dex-amm":{title:"DEX, Offers, and AMMs",subtitle:"How trading works on XRPL and how AMM liquidity moves show up on-ledger.",sections:[{heading:"How XRPL trading works",paragraphs:["XRPL has a built-in decentralized exchange (DEX). People place \u201Coffers\u201D (limit orders) to trade between XRP and tokens, or token-to-token.","AMMs (Automated Market Makers) hold pools of two assets. Liquidity providers deposit/withdraw and traders swap against the pool."],bullets:["OfferCreate = place an order (limit order).","OfferCancel = remove an order (may still succeed even if nothing cancels).","AMMCreate/Deposit/Withdraw = liquidity lifecycle signals."]},{heading:"Manipulation signals (heuristics)",paragraphs:["On-ledger \u201Cspoofing\u201D isn\u2019t identical to centralized exchanges, but suspicious churn can still stand out.","Rapid OfferCreate/OfferCancel bursts, concentrated actors, and repeated short-lived behavior can indicate bot-driven or staged activity."],bullets:["Offer churn: creates vs cancels intensity.","Concentration: whether a small set of accounts dominates.","AMM bursts: sudden waves of deposits/withdraws."]}],links:[{label:"DEX (concept)",url:"https://xrpl.org/docs/concepts/tokens/decentralized-exchange"},{label:"Offers (concept)",url:"https://xrpl.org/docs/concepts/tokens/decentralized-exchange/offers"},{label:"OfferCreate (tx type)",url:"https://xrpl.org/docs/references/protocol/transactions/types/offercreate"},{label:"OfferCancel (tx type)",url:"https://xrpl.org/docs/references/protocol/transactions/types/offercancel"},{label:"AMMs (concept)",url:"https://xrpl.org/docs/concepts/tokens/decentralized-exchange/automated-market-makers"},{label:"book_offers API (order book)",url:"https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/path-and-order-book-methods/book_offers"}],ctas:[{label:"Launch Dashboard \u2192",action:"auth:signup"},{label:"Close",action:"modal:close"}]},"security-drains":{title:"Wallet Safety + Compromise Response (Defensive)",subtitle:"How to read suspicious patterns safely and what to watch for during incident response.",sections:[{heading:"What a \u201Cdrain\u201D usually means",paragraphs:["A wallet drain typically follows a compromise: stolen keys, malicious signing requests, phishing, or unsafe approvals.","NaluLF is designed for defensive investigation and monitoring\u2014NOT for unauthorized access or theft."],bullets:["Watch for sudden outbound bursts from a previously quiet account.","Look for new trustlines/offers right before the loss.","Check transaction result codes and whether actions are validated."]},{heading:"How NaluLF helps (defensive)",paragraphs:["Inspect the address, review counterparties, and watch for repeated interactions or suspicious churn.","Use narratives to communicate what changed and what to check next."],bullets:["Inspector: balances, trustlines, flags, reserve signals.","Breadcrumbs: repeating \u201Cwho touches who\u201D pairs.","Signals: concentration + churn + bot-like timing proxies."]}],links:[{label:"XRPL Learning: Security Best Practices",url:"https://learn.xrpl.org/lesson/security-best-practices-for-xrp/"},{label:"XRPL Learning: DeFi Security 101",url:"https://learn.xrpl.org/course/blockchain-for-business/lesson/defi-security-101-staying-safe-in-the-new-decentralized-world/"},{label:"XRPL: Secure Signing",url:"https://xrpl.org/docs/concepts/transactions/secure-signing"},{label:"Transaction Results",url:"https://xrpl.org/docs/references/protocol/transactions/transaction-results"},{label:"tesSUCCESS",url:"https://xrpl.org/docs/references/protocol/transactions/transaction-results/tes-success"}],ctas:[{label:"Inspect an Address \u2192",action:"auth:login"},{label:"Close",action:"modal:close"}]},"bots-data":{title:"Bots on the Data (Monitoring / Alerts)",subtitle:"How to build legit automation on top of public XRPL data.",sections:[{heading:"What to automate",paragraphs:["XRPL is public, so you can build monitoring bots for events: whale payments, DEX churn spikes, AMM liquidity changes, or sudden flag updates.","Good bots explain what they saw and provide confidence/validation steps."],bullets:["Use WebSocket subscriptions for live events.","Use API methods for snapshots (account_info, account_lines, book_offers).","Treat signals as indicators and confirm with multiple checks."]},{heading:"How NaluLF fits",paragraphs:["NaluLF is the \u201Chuman dashboard\u201D to validate what the bot flags.","You can click addresses (breadcrumbs/clusters) and open Inspector for context."],bullets:["Bots: alerting, reporting, research, and risk monitoring.","Not for unauthorized access."]}],links:[{label:"subscribe (WebSocket)",url:"https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/subscription-methods/subscribe"},{label:"Monitor Incoming Payments (tutorial)",url:"https://xrpl.org/docs/tutorials/http-websocket-apis/build-apps/monitor-incoming-payments-with-websocket"},{label:"account_info API",url:"https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_info"},{label:"account_lines API",url:"https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/account-methods/account_lines"},{label:"book_offers API",url:"https://xrpl.org/docs/references/http-websocket-apis/public-api-methods/path-and-order-book-methods/book_offers"}],ctas:[{label:"Launch Dashboard \u2192",action:"auth:signup"},{label:"Close",action:"modal:close"}]},"crypto-basics":{title:"Crypto Basics: Keys + Signing",subtitle:"Why keys matter, what signing does, and why validated actions are final.",sections:[{heading:"Key concepts",paragraphs:["Your private key proves ownership. If someone has it, they can sign actions as you.","A digital signature is a tamper-proof stamp: the network can verify it, but nobody can forge it without the private key.","This is why phishing is so dangerous: a valid signature is usually final once validated."],bullets:["Public key: shareable.","Private key: never share.","Hashing: detects tampering."]}],links:[{label:"XRPL: Cryptographic Keys",url:"https://xrpl.org/docs/concepts/accounts/cryptographic-keys"},{label:"XRPL: Secure Signing",url:"https://xrpl.org/docs/concepts/transactions/secure-signing"},{label:"Cloudflare: Public key cryptography",url:"https://www.cloudflare.com/learning/ssl/how-does-public-key-encryption-work/"},{label:"Cloudflare: What is a cryptographic key?",url:"https://www.cloudflare.com/learning/ssl/what-is-a-cryptographic-key/"}],ctas:[{label:"Close",action:"modal:close"}]},"about-naluxrp":{title:"What is NaluLF?",subtitle:"Client-only XRPL forensic & analytics suite: readable reporting + manipulation signals + investigation workflow.",sections:[{heading:"The goal",paragraphs:["NaluLF turns raw ledger firehose data into something you can understand quickly:","what happened, who seems involved, what changed, and what looks unusual."],bullets:["Live stream: what the network is doing right now.","Inspector: what\u2019s going on with this address.","Signals: what looks unusual or coordinated (heuristics)."]},{heading:"How it helps defenders",paragraphs:["When investigating suspicious activity (compromises, scams, wash-like churn), you need context fast.","NaluLF helps you gather data, pivot between entities, and produce a clear report of what the ledger shows."],bullets:["Pattern windows (repeat pairs, cluster-like co-activity).","DEX churn signals (OfferCreate/Cancel intensity + concentration).","AMM/LP bursts (deposit/withdraw waves)."]},{heading:"Ethics",paragraphs:["Designed for defensive monitoring, research, and investigations.","Not for stealing funds or unauthorized access."]}],links:[{label:"XRPL Docs: Transactions",url:"https://xrpl.org/docs/concepts/transactions"},{label:"XRPL Docs: DEX",url:"https://xrpl.org/docs/concepts/tokens/decentralized-exchange"},{label:"XRPL Docs: AMMs",url:"https://xrpl.org/docs/concepts/tokens/decentralized-exchange/automated-market-makers"},{label:"XRPL Learning: Scam safety checklist",url:"https://learn.xrpl.org/blog/safeguarding-your-crypto-wallet-your-essential-checklist-against-defi-scams/"}],ctas:[{label:"Launch Dashboard \u2192",action:"auth:signup"},{label:"Close",action:"modal:close"}]}},Ew=[{icon:"\u{1F4D8}",title:"XRPL Ledgers",body:"Ledgers, validation, and indices.",topic:"xrpl-ledger"},{icon:"\u{1F464}",title:"Accounts",body:"Balances, reserves, flags, and keys.",topic:"accounts-trustlines"},{icon:"\u{1FA99}",title:"Trustlines",body:"Token safety model on XRPL.",topic:"accounts-trustlines"},{icon:"\u{1F501}",title:"DEX + Offers",body:"OfferCreate/Cancel + churn signals.",topic:"dex-amm"},{icon:"\u{1F4A7}",title:"AMMs / LPs",body:"Liquidity lifecycle and bursts.",topic:"dex-amm"},{icon:"\u{1F6E1}\uFE0F",title:"Security",body:"Defensive investigation workflow.",topic:"security-drains"}],Nw=[{icon:"\u{1F6E1}\uFE0F",title:"NaluLF Overview",desc:"What the app does, how it helps investigations, and what signals mean.",topic:"about-naluxrp"},{icon:"\u{1F4D8}",title:"XRPL Ledger",desc:"Ledgers, validated finality, and how to interpret snapshots.",topic:"xrpl-ledger"},{icon:"\u{1F464}",title:"Accounts + Trustlines",desc:"Reserves, flags, and trustline fundamentals for tokens.",topic:"accounts-trustlines"},{icon:"\u{1F501}",title:"DEX / Offers / AMMs",desc:"Trading primitives + what churn signals can indicate.",topic:"dex-amm"},{icon:"\u{1F9EF}",title:"Compromise Response",desc:"How to read suspicious flows defensively and safely.",topic:"security-drains"},{icon:"\u{1F916}",title:"Bots + Monitoring",desc:"Legit automation ideas using public XRPL data + validation steps.",topic:"bots-data"},{icon:"\u{1F510}",title:"Keys + Signing",desc:"Why signatures matter and how to stay safe.",topic:"crypto-basics"}],Rw=[{num:1,title:"Learn the ecosystem with real sources",body:"Open learning cards with detailed explanations and trusted references.",topic:"xrpl-ledger"},{num:2,title:"Investigate suspicious wallet activity (defensive)",body:"Inspector + counterparties + patterns to build a clear timeline.",topic:"security-drains"},{num:3,title:"Monitor DEX/AMM churn for anomaly signals",body:"OfferCreate/Cancel bursts, concentration, and LP waves.",topic:"dex-amm"},{num:4,title:"Build monitoring bots on public data",body:"Subscriptions + APIs for alerts, reporting, and research.",topic:"bots-data"}],Sm=!1;function _w(){if(document.getElementById("learnModalOverlay"))return;let e=document.createElement("div");e.id="learnModalOverlay",e.className="learn-modal-overlay",e.innerHTML=`
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
  `,document.body.appendChild(e),e.addEventListener("click",t=>{t.target===e&&da()}),document.addEventListener("keydown",t=>{t.key==="Escape"&&e.classList.contains("show")&&da()})}function Dw(e){let t=Aw[e];if(!t)return;_w();let n=document.getElementById("learnModalOverlay"),s=document.getElementById("learnModalTitle"),a=document.getElementById("learnModalSub"),o=document.getElementById("learnModalBody"),i=document.getElementById("learnModalLinks"),r=document.getElementById("learnModalCtas");!n||!s||!a||!o||!i||!r||(s.textContent=t.title,a.textContent=t.subtitle||"",o.innerHTML=(t.sections||[]).map(l=>`
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
  `).join(""),n.classList.add("show"),document.body.classList.add("modal-open"))}function da(){var e;(e=document.getElementById("learnModalOverlay"))==null||e.classList.remove("show"),document.body.classList.remove("modal-open")}function Iw(e){var t,n,s;if(e==="modal:close")return da();if(e==="auth:signup"){da(),(t=window.openAuth)==null||t.call(window,"signup");return}if(e==="auth:login"){da(),(n=window.openAuth)==null||n.call(window,"login");return}if(e.startsWith("topic:"))return Dw(e.split(":")[1]);if(e.startsWith("scroll:")){let a=e.split(":")[1];(s=document.getElementById(a))==null||s.scrollIntoView({behavior:"smooth",block:"start"})}}function Fw(){Sm||(Sm=!0,document.addEventListener("click",e=>{var s,a;let t=(a=(s=e.target).closest)==null?void 0:a.call(s,"[data-action]");if(!t)return;let n=t.getAttribute("data-action")||"";n&&(e.preventDefault(),Iw(n))}))}function Tm(){var l,c,u,d,p;Fw(),(l=document.querySelector(".landing-features"))==null||l.setAttribute("id","learn"),(c=document.querySelector(".landing-simple-value"))==null||c.setAttribute("id","use-cases"),(u=document.querySelector(".landing-cta"))==null||u.setAttribute("id","about"),(d=document.querySelector(".landing-tagline"))==null||d.classList.add("tagline-pill");let e=document.querySelector(".landing-stats-strip");e&&(e.classList.add("landing-learn-strip"),e.innerHTML=Ew.map(m=>`
      <button class="learn-tile reveal" type="button" data-action="topic:${y(m.topic)}" aria-label="${y(m.title)}">
        <div class="learn-tile-ico">${m.icon}</div>
        <div class="learn-tile-t">${y(m.title)}</div>
        <div class="learn-tile-b">${y(m.body)}</div>
      </button>
    `).join(""));let t=w("features-grid");t&&(t.innerHTML=Nw.map(m=>`
      <div class="feature-card reveal">
        <span class="feature-icon">${m.icon}</span>
        <h3>${y(m.title)}</h3>
        <p>${y(m.desc)}</p>
        <button class="feature-cta" type="button" data-action="topic:${y(m.topic)}">
          Learn more \u2192
        </button>
      </div>
    `).join(""));let n=document.querySelector(".landing-simple-value"),s=n==null?void 0:n.querySelector("h2");s&&(s.textContent="What you can do with NaluLF");let a=w("value-grid");a&&(a.innerHTML=Rw.map(m=>`
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
    `)}function Cm(){let e=new IntersectionObserver(t=>t.forEach(n=>{n.isIntersecting&&n.target.classList.add("visible")}),{threshold:.12});document.querySelectorAll(".reveal").forEach(t=>e.observe(t))}function Pm(){let e=document.getElementById("particle-canvas");if(!e)return;let t=e.getContext("2d"),n,s,a=[],o=80,i=120;function r(){n=e.width=window.innerWidth,s=e.height=window.innerHeight}function l(){return{x:Math.random()*n,y:Math.random()*s,vx:(Math.random()-.5)*.4,vy:(Math.random()-.5)*.4,r:Math.random()*1.5+.5,alpha:Math.random()*.5+.1}}function c(){r(),a=Array.from({length:o},l)}function u(){return getComputedStyle(document.body).getPropertyValue("--accent-secondary").trim()||"#ffd700"}function d(){t.clearRect(0,0,n,s);let g=u();for(let v=0;v<a.length;v++)for(let h=v+1;h<a.length;h++){let b=a[v].x-a[h].x,x=a[v].y-a[h].y,k=Math.sqrt(b*b+x*x);k<i&&(t.beginPath(),t.moveTo(a[v].x,a[v].y),t.lineTo(a[h].x,a[h].y),t.strokeStyle=`rgba(255,255,255,${(1-k/i)*.06})`,t.lineWidth=1,t.stroke())}a.forEach(v=>{t.beginPath(),t.arc(v.x,v.y,v.r,0,Math.PI*2),t.fillStyle=`rgba(255,255,255,${v.alpha*.6})`,t.fill()})}function p(){a.forEach(g=>{g.x+=g.vx,g.y+=g.vy,(g.x<0||g.x>n)&&(g.vx*=-1),(g.y<0||g.y>s)&&(g.vy*=-1)})}let m;function f(){p(),d(),m=requestAnimationFrame(f)}c(),f(),document.addEventListener("visibilitychange",()=>{document.hidden?(m&&cancelAnimationFrame(m),m=null):!m&&X.currentPage==="landing"&&f()}),window.addEventListener("naluxrp:pagechange",g=>{var v;((v=g==null?void 0:g.detail)==null?void 0:v.pageId)!=="landing"?(m&&cancelAnimationFrame(m),m=null):m||f()}),window.addEventListener("resize",()=>{r(),a.forEach(g=>{g.x=Math.min(g.x,n),g.y=Math.min(g.y,s)})}),e.style.cssText=`
    position: fixed; inset: 0;
    width: 100%; height: 100%;
    pointer-events: none;
    z-index: 0; opacity: 0.4;
  `}function Ts(e){var t;(t=window.showProfile)==null||t.call(window),setTimeout(()=>e==null?void 0:e(),250)}var kr=[{label:"\u{1F30A} Live Stream",hint:"Dashboard \u2192 Stream tab",action:()=>An(document.querySelector('[data-tab="stream"]'),"stream")},{label:"\u{1F50D} Inspector",hint:"Dashboard \u2192 Inspector tab",action:()=>An(document.querySelector('[data-tab="inspector"]'),"inspector")},{label:"\u{1F4E1} Network Health",hint:"Dashboard \u2192 Network tab",action:()=>An(document.querySelector('[data-tab="network"]'),"network")},{label:"\u{1F464} Profile",hint:"View your profile",action:()=>{var e;return(e=window.showProfile)==null?void 0:e.call(window)}},{label:"\u{1F48E} Wallets",hint:"Profile \u2192 Wallets",action:()=>Ts(()=>{var e;return(e=window.switchProfileTab)==null?void 0:e.call(window,"wallets")})},{label:"\u{1F4CA} Portfolio Analytics",hint:"Profile \u2192 Balance history, heatmap, flow",action:()=>Ts(()=>{var e;return(e=window.switchProfileTab)==null?void 0:e.call(window,"analytics")})},{label:"\u{1F517} Social Links",hint:"Profile \u2192 Connect Discord, X, GitHub\u2026",action:()=>Ts(()=>{var e;return(e=window.switchProfileTab)==null?void 0:e.call(window,"social")})},{label:"\u{1F4DC} Activity Log",hint:"Profile \u2192 Recent account activity",action:()=>Ts(()=>{var e;return(e=window.switchProfileTab)==null?void 0:e.call(window,"activity")})},{label:"\u2699\uFE0F Settings",hint:"Profile \u2192 Preferences & AI Explanations",action:()=>Ts(()=>{var e;return(e=window.switchProfileTab)==null?void 0:e.call(window,"settings")})},{label:"\u{1F52C} Analyze a Project",hint:"Liquidity depth, holder/LP concentration, issuer risk",action:()=>Ts(()=>{var e;return(e=window.jumpToProjectIntelLookup)==null?void 0:e.call(window)})},{label:"\u{1F9ED} Replay App Tour",hint:"Retake the onboarding walkthrough",action:()=>{var e;(e=window.showDashboard)==null||e.call(window),setTimeout(()=>{var t;return(t=window.startTour)==null?void 0:t.call(window)},300)}},{label:"\u2753 Help & Glossary",hint:"Search app features and on-chain terms",action:()=>{var e;return(e=window.openHelp)==null?void 0:e.call(window)}},{label:"\u{1F511} Sign In",hint:"Open auth",action:()=>{var e;return(e=window._openAuth)==null?void 0:e.call(window,"login")}},{label:"\u2728 Sign Up",hint:"Create account",action:()=>{var e;return(e=window._openAuth)==null?void 0:e.call(window,"signup")}},{label:"\u{1F3E0} Landing Page",hint:"Go home",action:()=>{var e;return(e=window._goHome)==null?void 0:e.call(window)}},{label:"\u{1F3A8} Cycle Theme",hint:"gold \u2192 cosmic \u2192 starry \u2192",action:()=>{var e;return(e=window._cycleTheme)==null?void 0:e.call(window)}}];function Ow(e){let t=e.trim();return He(t)?[{label:`\u{1F50D} Inspect ${t.slice(0,8)}\u2026${t.slice(-6)}`,hint:"Run the full account inspection on this address",action:()=>{An(document.querySelector('[data-tab="inspector"]'),"inspector"),setTimeout(()=>{var s;let n=document.getElementById("inspect-addr");n&&(n.value=t),(s=window.runInspect)==null||s.call(window)},200)}}]:[]}var Gn=0,ho=[...kr];function go(e=""){let t=w("cmdkOverlay"),n=w("cmdkInput");!t||!n||(t.classList.add("show"),n.value=e||"",Am(e),n.focus())}function Cs(){var e;(e=w("cmdkOverlay"))==null||e.classList.remove("show")}function Lm(){let e=w("cmdkOverlay"),t=w("cmdkInput");!e||!t||(t.addEventListener("input",()=>Am(t.value)),t.addEventListener("keydown",n=>{n.key==="ArrowDown"&&(n.preventDefault(),Mm(1)),n.key==="ArrowUp"&&(n.preventDefault(),Mm(-1)),n.key==="Enter"&&(n.preventDefault(),Bw()),n.key==="Escape"&&Cs()}),e.addEventListener("click",n=>{n.target===e&&Cs()}))}function Am(e=""){let t=w("cmdkList");if(!t)return;let n=e.toLowerCase().trim(),s=Ow(e);ho=n?[...s,...kr.filter(a=>a.label.toLowerCase().includes(n)||a.hint.toLowerCase().includes(n))]:[...s,...kr],Gn=0,t.innerHTML=ho.length?ho.map((a,o)=>`
        <button class="cmdk-item${o===0?" is-active":""}" data-index="${o}">
          <span class="cmdk-label">${y(a.label)}</span>
          <span class="cmdk-hint2">${y(a.hint)}</span>
        </button>`).join(""):'<div class="cmdk-section-label">No results</div>',t.querySelectorAll(".cmdk-item").forEach(a=>{a.addEventListener("click",()=>Em(Number(a.dataset.index)))})}function Mm(e){var n,s,a;let t=Xe("#cmdkList .cmdk-item");t.length&&((n=t[Gn])==null||n.classList.remove("is-active"),Gn=(Gn+e+t.length)%t.length,(s=t[Gn])==null||s.classList.add("is-active"),(a=t[Gn])==null||a.scrollIntoView({block:"nearest"}))}function Em(e){let t=ho[e];t&&(Cs(),t.action())}function Bw(){Em(Gn)}var bo=!1;function $r(){let e=X.currentPage,t=X.currentTab,n=e==="dashboard"&&t==="stream",s=e==="dashboard"&&t==="inspector",a=e==="dashboard"&&t==="network";mu(n),_u(s),xm(a)}function Nm(){bo||(uu(),Ru(),wm(),ec(),$r(),bo=!0)}window.openAuth=e=>Do(e);window.closeAuth=()=>ln();window.showAuthView=e=>rn(e);window.authKeydown=e=>ul(e);window.submitSignIn=()=>Fo();window.submitSignUp=()=>Oo();window.refreshCaptcha=()=>Qr();window.showForgotView=()=>sl();window.forgotRestoreFromFile=()=>al();window.forgotWipeConfirm=()=>ol();window.forgotWipeExecute=()=>il();window.forgotBackToOptions=()=>rl();window.submitSyncImport=()=>Bo();window.exportVaultSyncCode=()=>ll();window.syncImportFromFile=()=>cl();window.signupNext=()=>Io();window.signupBack=()=>Yr();window.logout=()=>dl();window.goHome=()=>Mn();window.showLandingPage=()=>Mn();window.showDashboard=()=>Ln();window.showProfile=()=>So();window.switchTab=(e,t)=>An(e,t);window.runInspect=()=>xs();window.closeCommandPalette=()=>Cs();window.openCmdk=()=>go();window.setTheme=e=>Pn(e);window.cycleTheme=()=>ko();window.measureLatency=()=>ra();window.switchProfileTab=e=>ui(e);window.openProfileEditor=()=>Gd();window.closeProfileEditor=()=>Xs();window.saveProfileEditor=()=>Kd();window.selectAvatar=e=>Jd(e);window.selectBanner=e=>Yd(e);window.uploadAvatarImage=e=>Qd(e);window.removeAvatarImage=()=>Zd();window.uploadBannerImage=e=>ep(e);window.removeBannerImage=()=>tp();window.prefSetTheme=e=>wp(e);window.setPrefCurrency=e=>xp(e);window.setPrefNetwork=e=>kp(e);window.setPrefAutoLock=e=>$p(e);window.openPublicProfilePreview=()=>yp();window.exportVaultBackup=()=>np();window.logActivity=(e,t)=>kt(e,t);window.toggleWalletDrawer=e=>jd(e);window.switchWalletDrawerTab=(e,t)=>Wd(e,t);window.cancelOffer=(e,t,n)=>qd(e,t,n);window.fetchBalance=e=>On(e);window.setActiveWallet=e=>ac(e);window.openImportAddressModal=()=>mp();window.closeImportAddressModal=()=>Ti();window.importWatchOnlyWallet=()=>fp();window.openImportSeedModal=()=>hp();window.closeImportSeedModal=()=>Ci();window.executeImportFromSeed=()=>gp();window.openTokenDetailsModal=(e,t,n)=>bp(e,t,n);window.closeTokenDetailsModal=()=>vp();window.refreshXrplDashboard=()=>ns();window.refreshMarketData=()=>Ed();window.refreshNftGallery=()=>Nd();window.refreshAmmPools=()=>Rd();window.refreshPoolExplorer=()=>_d();window.loadCustomAmmPool=()=>$c();window.sendNft=e=>Dd(e);window.toggleSeedBackupStatus=()=>_c();window.setDexPair=e=>Dc(e);window.setDexInterval=e=>Ic(e);window.setDexChartType=e=>Fc(e);window.refreshDexChart=()=>Oc();window.setComparePair=e=>Qc(e);window.toggleIndicator=(e,t)=>Bc(e,t);window.toggleTerminalTheme=()=>dd();window.toggleChartFullscreen=()=>pd();window.exportChartPng=()=>ud();window.saveChartLayoutPreset=()=>fd();window.loadChartLayoutPreset=()=>hd();window.setIndicatorFromDropdown=e=>Zc(e);window.toggleIndicatorMenu=()=>Xc();window.toggleChartMoreMenu=()=>Hc();window.setIndicatorQuery=e=>zc(e);window.addIndicatorFromMenu=e=>jc(e);window.removeIndicator=e=>Wc(e);window.openIndicatorSettings=e=>Uc(e);window.closeIndicatorSettings=()=>qc();window.applyIndicatorSettings=e=>Vc(e);window.resetIndicatorSettings=e=>Gc(e);window.copyChartLink=()=>Kc();window.toggleThreeEffects=()=>Jc();window.setThreeEffects=e=>Yc(e);window.setDrawingTool=e=>ed(e);window.clearAllDrawings=()=>sd();window.addPriceAlert=()=>td();window.removePriceAlert=e=>nd(e);window.zoomChartIn=()=>ad();window.zoomChartOut=()=>od();window.panChartLeft=()=>id();window.panChartRight=()=>rd();window.toggleEducationPanel=()=>ld();window.selectEducationTab=e=>cd(e);window.searchTokens=e=>vd(e);window.lookupIssuedAsset=()=>vi();window.lookupAndAnalyzeProject=()=>Ld();window.addTokenToWatchlist=e=>Td(e);window.removeTokenFromWatchlist=e=>Cd(e);window.openTokenOnChart=e=>Oa(e);window.loadToken=e=>Pd(e);window.refreshTokenDiscovery=()=>Md();window.refreshRecentTransactions=()=>Ad();window.setTokenFilter=(e,t)=>yd(e,t);window.clearTokenFilters=()=>wd();window.selectTokenDetails=e=>Sd(e);window.openProjectIntel=e=>hi(e);window.jumpToProjectIntelLookup=()=>ic();window.toggleProjectIntelSubScore=e=>rc(e);window.setProjectGraphView=e=>cc(e);window.copyProjectIntelForAi=()=>bc();window.closeProjectIntel=()=>dc();window.showMoreIssuedTokens=()=>xd();window.showAllIssuedTokens=()=>kd();window.resetIssuedTokenLimit=()=>$d();window.openWalletCreator=()=>$i();window.closeWalletCreator=()=>Hs();window.wizardNext=()=>sp();window.wizardBack=()=>ap();window.selectAlgo=e=>op(e);window.selectWalletEmoji=e=>ip(e);window.selectWalletColor=e=>rp(e);window.toggleSecurityCheck=e=>lp(e);window.revealSeed=()=>dp();window.copySeed=()=>pp();window.copyAddress=()=>up();window.copyToClipboard=e=>zs(e);window.deleteWallet=e=>Hd(e);window.inspectWalletAddr=e=>zd(e);window.openSocialModal=e=>Fd(e);window.closeSocialModal=()=>is();window.saveSocialModal=()=>Od();window.deleteSocial=()=>Bd();window.viewSocial=e=>Xd(e);window.connectXRPL=()=>import("./xrpl-6AERZ5KD.js").then(({connectXRPL:e})=>e());window._openAuth=Do;window._goHome=Mn;window._cycleTheme=ko;window._showProfile=So;window.startTour=()=>Po();window.tourNext=()=>Gr();window.tourPrev=()=>Kr();window.tourSkip=()=>ha();window.openHelp=()=>Sp();window.closeHelp=()=>Ha();window.filterHelp=e=>Mi(e);document.addEventListener("DOMContentLoaded",()=>{var e;console.log("\u{1F30A} NaluLF: booting\u2026"),zr(),Mn(),Tm(),Cm(),Pm(),Lm(),Tp(),Xw(),window.addEventListener("naluxrp:pagechange",t=>{var s;let n=(s=t==null?void 0:t.detail)==null?void 0:s.pageId;(n==="dashboard"||n==="inspector"||n==="profile")&&Nm(),bo&&$r()}),window.addEventListener("naluxrp:tabchange",()=>{bo&&$r()}),document.addEventListener("keydown",t=>{var s;let n=["INPUT","TEXTAREA"].includes((s=document.activeElement)==null?void 0:s.tagName);if((t.ctrlKey||t.metaKey)&&t.key==="k"){t.preventDefault(),go();return}if(t.key==="/"&&!n){t.preventDefault(),go();return}t.key==="Escape"&&(Cs(),ln(),Xs(),Hs(),is(),ha(),Ha())}),(e=document.getElementById("auth-overlay"))==null||e.addEventListener("click",t=>{t.target===t.currentTarget&&ln()}),pl()&&(Nm(),Ln(),import("./xrpl-6AERZ5KD.js").then(({connectXRPL:t})=>t())),console.log("\u2705 NaluLF: ready")});function Xw(){_m(),setInterval(()=>{document.hidden||_m()},3e4)}async function Rm(e){let t=[s=>`https://corsproxy.io/?${encodeURIComponent(s)}`,s=>`https://api.allorigins.win/raw?url=${encodeURIComponent(s)}`],n=async s=>{let a=typeof(AbortSignal==null?void 0:AbortSignal.timeout)=="function"?AbortSignal.timeout(7e3):void 0,o=await fetch(s,{mode:"cors",cache:"no-store",signal:a});if(!o.ok)throw new Error(`HTTP ${o.status}`);return await o.json()};try{return await n(e)}catch{for(let s of t)try{return await n(s(e))}catch{}throw new Error("Price feed unreachable")}}async function _m(){try{let e=await Rm("https://api.exchange.coinbase.com/products/XRP-USD/ticker"),t=await Rm("https://api.exchange.coinbase.com/products/XRP-USD/candles?granularity=86400");if(e!=null&&e.price){let n=Number(e.price),s=Array.isArray(t)&&t.length?t[0]:null,a=s?Number(s[3]||n):n,o=a?(n-a)/a*100:0,i=document.getElementById("xrpPrice"),r=document.getElementById("xrpChange");if(i&&(i.textContent=`$${Number(n).toFixed(3)}`),r){let l=o>=0;r.textContent=`${l?"+":""}${Number(o).toFixed(2)}%`,r.className=`xrp-price-change ${Math.abs(o)<.1?"flat":l?"up":"down"}`}}}catch{}}
