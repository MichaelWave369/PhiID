import React,{useEffect,useState} from 'react';
import {Check,CircleAlert,Clipboard,LockKeyhole,ShieldCheck,X} from 'lucide-react';
import './pocket-approval.css';

/**
 * R6 localhost-only review UI. No signing keys, credentials or OIDC tokens
 * ever enter the browser. A signed permit must be independently created by
 * the PocketMesh planner and signer, then explicitly reviewed here.
 */
export default function PocketApprovalCenter({authenticated}){
  const [enabled,setEnabled]=useState(false);
  const [permitted,setPermitted]=useState(false);
  const [raw,setRaw]=useState('');
  const [review,setReview]=useState(null);
  const [ack,setAck]=useState(false);
  const [output,setOutput]=useState('');
  const [busy,setBusy]=useState(false);
  const [notice,setNotice]=useState('');
  useEffect(()=>{
    let active=true;
    setReview(null);setAck(false);setOutput('');setNotice('');
    fetch('/auth/pocket/status',{credentials:'same-origin',cache:'no-store'})
      .then(r=>r.json())
      .then(result=>{
        if(!active)return;
        setEnabled(result.enabled===true);
        setPermitted(result.permitted===true);
      })
      .catch(()=>{if(active){setEnabled(false);setPermitted(false);}});
    return ()=>{active=false;};
  },[authenticated]);
  async function action(path,verb,body){
    const response=await fetch('/auth/pocket/'+path,{
      method:'POST',credentials:'same-origin',cache:'no-store',
      headers:{'Content-Type':'application/json','X-PhiID-Action':verb},
      body:JSON.stringify(body)
    });
    const result=await response.json();
    if(!response.ok)throw new Error(result?.error||'local_approval_denied');
    return result;
  }
  async function stage(){
    if(busy||!enabled||!permitted||!authenticated)return;
    setBusy(true);setReview(null);setOutput('');setAck(false);setNotice('');
    try{
      if(raw.length>8192)throw new Error('Permit is too large for the local lab');
      const permit=JSON.parse(raw);
      const result=await action('review','pocket-review',{permit});
      setReview(result);setNotice('Review the approved profile, revision and exact permit hash before confirming.');
    }catch{
      setNotice('Review refused. Check the signed permit, session and operator policy; nothing was authorized.');
    }finally{setBusy(false);}
  }
  async function confirm(){
    if(!review||!ack||busy)return;
    setBusy(true);setNotice('');
    try{
      const result=await action('approve','pocket-approve',{
        reviewId:review.reviewId,acknowledged:true
      });
      setOutput(JSON.stringify(result,null,2));
      setNotice('Signed approval issued for this one reviewed permit. No album was executed by PhiID.');
      setReview(null);setAck(false);setRaw('');
    }catch{
      setReview(null);setAck(false);
      setNotice('Approval refused or expired. Stage a new permit; no approval was issued.');
    }finally{setBusy(false);}
  }
  async function cancel(){
    setReview(null);setAck(false);setOutput('');setNotice('');
    try{await action('cancel','pocket-cancel',{});}
    catch{setNotice('Local cancellation could not be confirmed. The pending review expires automatically.');}
  }
  async function copy(){
    try{
      await navigator.clipboard.writeText(output);
      setNotice('Signed envelope copied. It still requires separate operator policy and PocketMesh verification.');
    }catch{setNotice('Clipboard unavailable. Copy the visible envelope manually.');}
  }
  return <section className="pocket-approval">
    <div className="section-intro">
      <span className="eyebrow">R6 / LOCAL VERIFIED-SESSION ACTION LAB</span>
      <h2>Approve a specific performance.</h2>
      <p>PhiID verifies your development login, then permits an explicit review of a separately signed Pocket Album request. Your login alone never grants permission to run an album.</p>
    </div>
    <div className="r2-warning"><CircleAlert size={18}/>
      <p><strong>Development only.</strong> A reviewed permit is not an OAuth token or a general OS permission. The signed approval must still pass a separately configured PocketMesh executor and its one-use Keyhole.</p>
    </div>
    {!authenticated?<div className="r2-panel">
      <LockKeyhole size={26}/>
      <h3>Verified local OIDC sign-in required</h3>
      <p>This action lab exists only on 127.0.0.1:8786. Public GitHub Pages never signs approvals.</p>
      <a className="primary-btn" href="/auth/login">Sign in to local Keycloak</a>
    </div>:!enabled?<div className="r2-panel">
      <h3>Approval signing is disabled</h3>
      <p>Its operator-owned signing configuration is absent. The default is deny. See R6 setup documentation; no key is generated inside the browser.</p>
    </div>:!permitted?<div className="r2-panel">
      <ShieldCheck size={26}/>
      <h3>This session is not approved for local Pocket actions</h3>
      <p>The operator's separate allowlist does not include this verified development subject.</p>
    </div>:<>
      <div className="r2-panel pocket-stage">
        <h3>1. Import a signed execution permit</h3>
        <p>Paste the complete JSON permit created by the trusted PocketMesh planner and permit signer. PhiID verifies the signature before showing an approval.</p>
        <textarea rows={7} value={raw} onChange={e=>setRaw(e.target.value)}
          placeholder='{"schema":"NBGPocketMesh.SignedExecutionPermit.v1",...}'
          maxLength={8192} spellCheck={false} disabled={busy||!!review}/>
        <button type="button" className="primary-btn" onClick={stage}
          disabled={busy||!!review||!raw.trim()}>Verify and review permit</button>
      </div>
      {review&&<div className="r2-panel pocket-review">
        <h3>2. Explicitly approve this action</h3>
        <dl>
          <div><dt>Action</dt><dd>{review.details.purpose}</dd></div>
          <div><dt>Scope</dt><dd>{review.details.scope}</dd></div>
          <div><dt>Album</dt><dd>{review.details.albumId}</dd></div>
          <div><dt>Profile</dt><dd>{review.details.profile}</dd></div>
          <div><dt>Revision</dt><dd>{review.details.revision}</dd></div>
          <div><dt>Mode</dt><dd>{review.details.mode}</dd></div>
          <div><dt>Permit fingerprint</dt><dd><code>{review.details.permitSha256}</code></dd></div>
          <div><dt>Permit expiry</dt><dd>{new Date(review.details.expiresAtMs).toLocaleString()}</dd></div>
        </dl>
        <label className="r2-ack">
          <input type="checkbox" checked={ack} onChange={e=>setAck(e.target.checked)}/>
          I explicitly approve this exact synthetic Pocket Album execution request, not a blanket permission or a profile-sharing consent.
        </label>
        <div className="r2-actions">
          <button className="primary-btn" type="button" disabled={!ack||busy} onClick={confirm}><Check size={16}/> Sign this reviewed action</button>
          <button type="button" className="r2-cancel" disabled={busy} onClick={cancel}><X size={15}/> Cancel</button>
        </div>
      </div>}
      {output&&<div className="r2-panel pocket-result">
        <h3>3. Signed approval envelope</h3>
        <p>Copy this envelope to your separately controlled PocketMesh executor. PhiID did not execute anything or open a network listener.</p>
        <pre>{output}</pre>
        <button type="button" className="primary-btn" onClick={copy}><Clipboard size={16}/> Copy signed envelope</button>
      </div>}
    </>}
    {notice&&<div className="r2-notice" role="status"><ShieldCheck size={17}/>{notice}</div>}
  </section>;
}
