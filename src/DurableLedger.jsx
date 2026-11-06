import { useEffect, useState } from 'react';
import { Check, Database, History, LockKeyhole, ShieldAlert, Trash2 } from 'lucide-react';
import './durable-ledger.css';

const PROPOSED_SERVICES = [
  {id:'phimail',name:'PhiMail',scope:'profile.basic.read'},
  {id:'phicloud',name:'PhiCloud',scope:'profile.basic.read'},
];

const INITIAL = {
  enabled:false,persistent:false,authority_granted:false,active:[],history:[],
};

/**
 * A LOCAL durable record of consent *review*. NOT a real connection.
 * This component is reachable only in PhiID's localhost OIDC lab.
 */
export default function DurableLedger({ authenticated }) {
  const [data,setData] = useState(INITIAL);
  const [pending,setPending] = useState('');
  const [agreed,setAgreed] = useState(false);
  const [busy,setBusy] = useState(false);
  const [loading,setLoading] = useState(false);
  const [message,setMessage] = useState('');
  const [error,setError] = useState('');

  async function readLedger() {
    const response=await fetch('/auth/ledger',{
      credentials:'same-origin',cache:'no-store'
    });
    if(!response.ok)throw new Error('ledger_unavailable');
    const parsed=await response.json();
    if(parsed.schema!=='phiid.local-choice-ledger/0.1' ||
       parsed.authority_granted!==false ||
       !Array.isArray(parsed.active) || !Array.isArray(parsed.history)) {
      throw new Error('unexpected_ledger_contract');
    }
    setData(parsed);
    return parsed;
  }

  useEffect(()=>{
    if(!authenticated) {
      setData(INITIAL);setPending('');setAgreed(false);
      setError('');setMessage('');
      return;
    }
    let live=true;
    setLoading(true);
    fetch('/auth/ledger',{credentials:'same-origin',cache:'no-store'})
      .then(async response=>{
        if(!response.ok)throw new Error('local_choice_ledger_unavailable');
        return response.json();
      })
      .then(parsed=>{
        if(!live)return;
        if(parsed.schema!=='phiid.local-choice-ledger/0.1' ||
           parsed.authority_granted!==false ||
           !Array.isArray(parsed.active) || !Array.isArray(parsed.history))
          throw new Error('invalid_ledger_response');
        setData(parsed);
      })
      .catch(()=>{if(live)setError('Local consent history could not be loaded. No choice was saved.');})
      .finally(()=>{if(live)setLoading(false);});
    return()=>{live=false};
  },[authenticated]);

  async function persistChoice() {
    if(!agreed || !pending || busy)return;
    const entry=PROPOSED_SERVICES.find(item=>item.id===pending);
    if(!entry)return;
    setBusy(true);setError('');setMessage('');
    try{
      const response=await fetch('/auth/ledger',{
        method:'POST',credentials:'same-origin',
        headers:{'Content-Type':'application/json','X-PhiID-Action':'ledger-record'},
        body:JSON.stringify({
          service:entry.id,scopes:[entry.scope],
          acknowledged:true,persist_acknowledged:true,
        }),
      });
      if(!response.ok)throw new Error('local_choice_record_failed');
      const result=await response.json();
      if(result.receipt?.authority_granted!==false ||
         result.receipt?.connected!==false ||
         result.receipt?.service_called!==false) {
        throw new Error('unsafe_ledger_response');
      }
      await readLedger();
      setMessage('Durable local choice saved. No service was connected or granted access.');
      setPending('');setAgreed(false);
    }catch {
      setError('Could not save the local choice. Nothing was authorized.');
    }finally{setBusy(false)}
  }

  async function revokeChoice(service) {
    if(busy)return;
    setBusy(true);setError('');setMessage('');
    try{
      const response=await fetch('/auth/ledger/'+encodeURIComponent(service),{
        method:'DELETE',credentials:'same-origin',
        headers:{'X-PhiID-Action':'ledger-revoke'},
      });
      if(!response.ok)throw new Error('revoke_failed');
      const result=await response.json();
      if(result.external_token_revoked!==false || result.connection_revoked!==false ||
         result.authority_granted!==false)throw new Error('unsafe_revoke_response');
      await readLedger();
      setMessage('Local choice revoked; history retained. No external token ever existed.');
    }catch {setError('Unable to revoke the local choice.');}
    finally{setBusy(false)}
  }

  if(!authenticated)return null;
  return <section className="ledger-area" aria-label="Persistent local consent history">
    <div className="ledger-title"><Database size={19}/><strong>R6 · Persistent choice history</strong></div>
    <p className="ledger-description">Optional private storage on this computer for choices you explicitly reviewed. Unlike R2 temporary receipts, these survive application restarts. <strong>They do not connect an app or grant permissions.</strong></p>
    {loading&&<p className="ledger-muted">Reading local audit history…</p>}
    {!loading&&!data.enabled&&!error&&<div className="ledger-disabled">
      <LockKeyhole size={16}/>
      <span>Disabled by default. To test privately, restart the PhiID localhost bridge with <code>PHIID_LOCAL_LEDGER=1</code>. Nothing is stored persistently until you enable it and approve a choice.</span>
    </div>}
    {data.enabled&&<>
      <p className="ledger-muted">Private SQLite file · 30-day choice expiry · 90-day audit retention · no external access</p>
      <div className="ledger-services">
        {PROPOSED_SERVICES.map(item=>{
          const current=data.active.find(r=>r.service===item.id);
          return <div className="ledger-service" key={item.id}>
            <div><strong>{item.name}</strong><small>Proposed: <code>{item.scope}</code></small></div>
            {current ? <button type="button" className="ledger-revoke" disabled={busy}
                onClick={()=>revokeChoice(item.id)}><Trash2 size={14}/> Revoke local choice</button>
              : <button type="button" className="ledger-review" disabled={busy}
                onClick={()=>{setPending(item.id);setAgreed(false);setMessage('')}}>
                Review durable choice</button>}
            {current&&<small className="ledger-current"><Check size={13}/> Saved choice, not a link · expires {new Date(current.expires_at).toLocaleDateString()}</small>}
          </div>;
        })}
      </div>
      {pending&&<div className="ledger-confirm">
        <strong>Review {PROPOSED_SERVICES.find(x=>x.id===pending)?.name}</strong>
        <p>Record a choice to review basic profile sharing in a private local audit file for up to 90 days. This saves only a pseudonymous account key, service, scope and timestamps. No access token, email address, device permission, cloud file, or mailbox is shared.</p>
        <label><input type="checkbox" checked={agreed} onChange={event=>setAgreed(event.target.checked)}/>
          <span>I explicitly agree to storing this local choice history. I understand no service access is granted.</span></label>
        <div className="ledger-buttons">
          <button type="button" className="ledger-review" disabled={!agreed||busy} onClick={persistChoice}>Save local choice</button>
          <button type="button" className="ledger-cancel" disabled={busy}
            onClick={()=>{setPending('');setAgreed(false)}}>Cancel</button>
        </div>
      </div>}
      <div className="ledger-history"><div className="ledger-history-title"><History size={15}/> Recent local history ({data.history.length})</div>
        {data.history.length===0
          ? <small>No durable choices have been recorded.</small>
          : <ul>{data.history.slice(0,12).map(entry=><li key={entry.receipt_id}>
              <strong>{entry.service}</strong> · {entry.status.replaceAll('_',' ')}
              <small>Recorded {new Date(entry.recorded_at).toLocaleString()}
                {entry.revoked_at ? ' · Revoked '+new Date(entry.revoked_at).toLocaleString() : ''}</small>
            </li>)}</ul>}
      </div>
    </>}
    {message&&<p className="ledger-success" role="status"><Check size={15}/>{message}</p>}
    {error&&<p className="ledger-error" role="alert"><ShieldAlert size={15}/>{error}</p>}
  </section>;
}
