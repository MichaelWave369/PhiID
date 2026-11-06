import React, { useEffect, useState } from 'react';
import { Check, CircleAlert, Fingerprint, Link2, LockKeyhole, Shield, Trash2 } from 'lucide-react';
import './consent.css';
import DurableLedger from '../src/DurableLedger.jsx';

/**
 * R2 consent is NOT remote account linking and NOT an OAuth scope grant.
 * It is a visible short-lived receipt bound to a verified LOCAL dev session.
 */
export default function ConsentCenter({ authenticated }) {
  const [catalog, setCatalog] = useState([]);
  const [receipts, setReceipts] = useState([]);
  const [pending, setPending] = useState(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!authenticated) {
      setCatalog([]);
      setReceipts([]);
      setPending(null);
      setNotice('');
      return;
    }
    let active = true;
    setLoading(true);
    fetch('/auth/consents', { credentials: 'same-origin', cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error('consent catalog unavailable');
        return response.json();
      })
      .then(payload => {
        if (!active) return;
        if (payload.permissions_enforced !== false || payload.service_calls !== false ||
            !Array.isArray(payload.catalog) || !Array.isArray(payload.receipts)) {
          throw new Error('unsafe or unexpected consent response');
        }
        setCatalog(payload.catalog);
        setReceipts(payload.receipts);
      })
      .catch(() => { if (active) setNotice('Could not load local consent records. No service link was created.'); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [authenticated]);

  const activeSpec = catalog.find(item => item.service === pending);

  async function record() {
    if (!acknowledged || !activeSpec || busy) return;
    setBusy(true);
    try {
      const response = await fetch('/auth/consents', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-PhiID-Action': 'consent',
        },
        body: JSON.stringify({
          service: activeSpec.service,
          scopes: activeSpec.available_scopes,
          acknowledged: true,
        }),
      });
      if (!response.ok) throw new Error('local receipt declined');
      const data = await response.json();
      if (!data.receipt || data.receipt.connected !== false ||
          data.receipt.authority_granted !== false ||
          data.receipt.service_called !== false) {
        throw new Error('invalid receipt response');
      }
      setReceipts(previous => [
        ...previous.filter(item => item.service !== activeSpec.service),
        data.receipt,
      ]);
      setNotice('Consent receipt recorded for this local session. No real app was connected.');
      setPending(null);
      setAcknowledged(false);
    } catch {
      setNotice('The local consent record could not be created. No authority was granted.');
    } finally {
      setBusy(false);
    }
  }

  async function remove(service) {
    if (busy) return;
    setBusy(true);
    try {
      const response = await fetch('/auth/consents/' + encodeURIComponent(service), {
        method: 'DELETE',
        credentials: 'same-origin',
        headers: { 'X-PhiID-Action': 'revoke' },
      });
      if (!response.ok) throw new Error('failed to remove record');
      const data = await response.json();
      if (data.connection_revoked !== false || data.external_token_revoked !== false) {
        throw new Error('unexpected response');
      }
      setReceipts(previous => previous.filter(item => item.service !== service));
      setNotice('Local receipt removed. No remote service or token was connected.');
    } catch {
      setNotice('Unable to remove the local record.');
    } finally {
      setBusy(false);
    }
  }

  function review(service) {
    setPending(service);
    setAcknowledged(false);
    setNotice('');
  }

  return <div className="r2-consent-center">
    <div className="section-intro">
      <span className="eyebrow">R2 / LOCAL ACCOUNT LINKING LAB</span>
      <h2>Connect by choice.<br/>Disconnect by design.</h2>
      <p>This lab records exactly what you consented to, for which proposed service, under an authenticated local identity session. The next step is implementing actual service authorization separately.</p>
    </div>
    <div className="r2-warning"><CircleAlert size={18}/>
      <p><strong>No live connections.</strong> A receipt is not an OAuth token, mail access, file permission, PhiOS authority, or a remote app integration. These temporary R2 receipts disappear when your session expires. The separate R6 optional audit below may persist review choices, but never grants access.</p>
    </div>

    {!authenticated ? <section className="r2-panel">
      <Fingerprint size={31}/>
      <h3>Verified local sign-in required</h3>
      <p>Log in to the Keycloak development realm to review and record temporary consent. The public GitHub Pages preview cannot access this functionality.</p>
      <a className="primary-btn" href="/auth/login"><LockKeyhole size={16}/> Sign in to local Keycloak</a>
    </section> : <>
      {loading && <p className="r2-muted">Loading declared local-only consent options...</p>}
      {!loading && catalog.length === 0 && <p className="r2-muted">No local consent services are available.</p>}
      <div className="r2-options">
        {catalog.map(service => {
          const receipt = receipts.find(item => item.service === service.service);
          return <article className="r2-option" key={service.service}>
            <div className="r2-option-top">
              <span className="r2-icon"><Link2 size={19}/></span>
              <span className="r2-status">{receipt ? 'LOCAL RECEIPT RECORDED' : 'NOT RECORDED'}</span>
            </div>
            <h3>{service.name}</h3>
            <p>{service.purpose}</p>
            <div className="r2-scope">Scope proposed: <code>{service.available_scopes.join(', ')}</code></div>
            {receipt
              ? <div className="r2-record">
                  <span><Check size={14}/> Recorded for this session</span>
                  <small>Expires {new Date(receipt.expires_at).toLocaleString()}</small>
                  <button type="button" className="r2-remove" onClick={() => remove(service.service)} disabled={busy}>
                    <Trash2 size={14}/> Remove local receipt
                  </button>
                </div>
              : <button type="button" className="r2-review" onClick={() => review(service.service)} disabled={busy}>
                  <Shield size={16}/> Review explicit consent
                </button>}
          </article>;
        })}
      </div>
      {activeSpec && <section className="r2-review-panel" aria-label="Local consent confirmation">
        <span className="eyebrow">EXPLICIT REVIEW · NOT A LIVE GRANT</span>
        <h3>{activeSpec.name}</h3>
        <p>{activeSpec.purpose}</p>
        <div className="r2-scope">Requested scope: <code>{activeSpec.available_scopes.join(', ')}</code></div>
        <p>No data is transferred. No PhiMail mailbox, PhiCloud vault or PhiOS device is connected. This only records a bounded choice under your current local test identity.</p>
        <label className="r2-ack"><input type="checkbox" checked={acknowledged}
          onChange={event => setAcknowledged(event.target.checked)} />
          <span>I understand this is a temporary local consent receipt and grants no real access.</span></label>
        <div className="r2-actions">
          <button className="primary-btn" type="button" disabled={busy || !acknowledged} onClick={record}>
            <Check size={16}/> Record consent
          </button>
          <button className="r2-cancel" type="button" disabled={busy} onClick={() => setPending(null)}>Cancel</button>
        </div>
      </section>}
    </>}

    {authenticated && <DurableLedger authenticated={authenticated} />}

    {notice && <div role="status" className="r2-notice"><Shield size={15}/>{notice}</div>}
    <div className="info-strip"><LockKeyhole size={18}/><div>
      <strong>Identity never implies authorization.</strong>
      <p>Actual application links will require separate permission scopes, validated tokens, service-side enforcement, revocation and user-visible audit receipts.</p>
    </div></div>
  </div>;
}
