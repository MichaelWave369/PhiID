import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity, ArrowRight, ArrowUpRight, Check, ChevronRight, Cloud, Code2,
  Database, Download, Fingerprint, Globe2, HardDrive, KeyRound, Layers3,
  Link2, LockKeyhole, Mail, MonitorSmartphone, Network, ShieldCheck, Shield,
  Sparkles, Unplug, UserRound, WifiOff
} from 'lucide-react';
import { DEMO_ACCOUNT, createDemoExport, previewIdentityKey, validatePreviewAccount } from './identity.js';
import ConsentCenter from './ConsentCenter.jsx';
import PocketApprovalCenter from './PocketApprovalCenter.jsx';

const LOCAL_AUTH_LAB = typeof window !== 'undefined' && window.location.origin === 'http://127.0.0.1:8786';

const NAV = [
  { id: 'overview', name: 'Overview', icon: Layers3 },
  { id: 'ecosystem', name: 'Ecosystem', icon: Network },
  ...(LOCAL_AUTH_LAB ? [{ id: 'consent', name: 'Consent Lab', icon: Link2 }, { id: 'pocket-approval', name: 'Pocket Approval Lab', icon: ShieldCheck }] : []),
  { id: 'security', name: 'Security', icon: ShieldCheck },
  { id: 'portability', name: 'Portability', icon: Download },
];

const SERVICES = [
  { id: 'phios', title: 'PhiOS', category: 'Operating environment', description: 'Local permissions stay local. PhiID linkage is optional, never required to use the OS.', icon: MonitorSmartphone, accent: 'gold', href: 'https://github.com/MichaelWave369/PhiOS', kind: 'Independent by design' },
  { id: 'phimail', title: 'PhiMail', category: 'Communication', description: 'An email experience for the Field. Real PhiID sign-in and mailbox delivery are future integrations.', icon: Mail, accent: 'teal', href: 'https://github.com/MichaelWave369/PhiMail', kind: 'Integration planned' },
  { id: 'phicloud', title: 'PhiCloud', category: 'Storage and services', description: 'User-controlled sync, backups, and apps. Account linking will require independent consent.', icon: Cloud, accent: 'violet', href: 'https://github.com/MichaelWave369/PhiCloud', kind: 'Integration planned' },
  { id: 'phiserve', title: 'PhiServe', category: 'Local intelligence', description: 'Local model serving remains independent. A remote bridge would need explicit authorization.', icon: Activity, accent: 'blue', href: 'https://github.com/MichaelWave369/PhiServe', kind: 'Independent by design' },
];

const SAFETY = [
  { icon: Fingerprint, name: 'Passkeys / WebAuthn', summary: 'Planned: passwordless enrollment through an audited identity provider.', stage: 'NOT ENROLLED' },
  { icon: KeyRound, name: 'OIDC + PKCE', summary: 'Planned: standard, scoped sign-in across browser, desktop and mobile.', stage: 'NOT CONFIGURED' },
  { icon: LockKeyhole, name: 'Recovery', summary: 'Planned: recovery codes and device-loss handling that do not depend only on email.', stage: 'NOT CONFIGURED' },
  { icon: Shield, name: 'Local PhiOS authority', summary: 'A remote session must not override the PhiOS effect-approval boundary.', stage: 'DESIGN RULE' },
];

function Pill({ children, color = 'neutral' }) {
  return <span className={'pill ' + color}>{children}</span>;
}

function SectionIntro({ eyebrow, title, description }) {
  return <div className="section-intro">
    <span className="eyebrow">{eyebrow}</span>
    <h2>{title}</h2>
    <p>{description}</p>
  </div>;
}

function ServiceCard({ service, linked, onToggle }) {
  const Icon = service.icon;
  return <article className={'service-card ' + service.accent}>
    <div className="service-top">
      <span className="icon-frame"><Icon size={20} /></span>
      <a className="external" href={service.href} target="_blank" rel="noreferrer" aria-label={'View ' + service.title + ' source repository'}><ArrowUpRight size={17}/></a>
    </div>
    <h3>{service.title}</h3>
    <div className="service-category">{service.category}</div>
    <p>{service.description}</p>
    <div className="service-bottom">
      <span className="service-kind">{service.kind}</span>
      <button type="button" className={'small-action ' + (linked ? 'on' : '')} aria-pressed={linked}
        onClick={() => onToggle(service.id)}
        aria-label={(linked ? 'Remove simulated link for ' : 'Simulate linking ') + service.title}>
        {linked ? <><Check size={13}/> Preview linked</> : <>Simulate link <ChevronRight size={14}/></>}
      </button>
    </div>
  </article>;
}

function App() {
  const [tab, setTab] = useState('overview');
  const [alias, setAlias] = useState(DEMO_ACCOUNT.preferred_username);
  const [previewLinks, setPreviewLinks] = useState([]);
  const [notice, setNotice] = useState('');
  const [localSession, setLocalSession] = useState(null);

  useEffect(() => {
    if (!LOCAL_AUTH_LAB) return;
    let active = true;
    fetch('/auth/session', { credentials: 'same-origin', cache: 'no-store' })
      .then(response => {
        if (!response.ok) throw new Error('local session unavailable');
        return response.json();
      })
      .then(profile => { if (active) setLocalSession(profile); })
      .catch(() => { if (active) setNotice('Local identity bridge is unavailable.'); });
    return () => { active = false; };
  }, []);

  async function endLocalSession() {
    try {
      const response = await fetch('/auth/logout', {
        method: 'POST', headers: { 'X-PhiID-Action': 'logout' },
        credentials: 'same-origin',
      });
      if (!response.ok) throw new Error('logout refused');
      setLocalSession({ authenticated: false });
      setNotice('Local bridge session ended. Keycloak SSO may still be active.');
    } catch {
      setNotice('Could not end the local session.');
    }
  }

  const account = useMemo(() => {
    const candidate = (alias.trim() || DEMO_ACCOUNT.preferred_username).slice(0, 64);
    return validatePreviewAccount({ ...DEMO_ACCOUNT, preferred_username: candidate });
  }, [alias]);
  const identityKey = useMemo(() => previewIdentityKey(account), [account]);
  const exportPayload = useMemo(() => createDemoExport(account), [account]);

  function changeLink(id) {
    setPreviewLinks(current => current.includes(id)
      ? current.filter(key => key !== id)
      : [...current, id]);
    setNotice('Preview only. No real account was linked and no permission was granted.');
  }

  function downloadPreview() {
    const blob = new Blob([JSON.stringify(exportPayload, null, 2) + '\n'], { type: 'application/json' });
    const objectURL = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = objectURL;
    link.download = 'phiid-demo-metadata.json';
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(objectURL), 1000);
    setNotice('Synthetic demo metadata exported. This JSON is not an identity credential.');
  }

  function navigate(id) {
    setTab(id);
    setNotice('');
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="https://github.com/MichaelWave369/PhiID" target="_blank" rel="noreferrer" aria-label="PhiID GitHub repository">
        <span className="brand-symbol">Φ</span>
        <span className="brand-text"><strong>PhiID</strong><small>THE IDENTITY LAYER</small></span>
      </a>
      <span className="sidebar-group">YOUR FIELD</span>
      <nav className="navigation" aria-label="Identity Center">
        {NAV.map(item => {
          const Icon = item.icon;
          return <button key={item.id} type="button" onClick={() => navigate(item.id)}
            className={'nav-item ' + (tab === item.id ? 'active' : '')}
            aria-current={tab === item.id ? 'page' : undefined}>
            <Icon size={18}/><span>{item.name}</span>{tab === item.id && <span className="active-dot"/>}
          </button>;
        })}
      </nav>
      <div className="side-note">
        <div className="side-note-icon"><WifiOff size={16}/></div>
        <strong>Local by principle</strong>
        <p>PhiOS remains yours, even when the network is gone.</p>
      </div>
      <div className="sidebar-foot">PHI369 LABS <span>·</span> OPEN SOURCE<br/>R0 CONCEPT PREVIEW</div>
    </aside>

    <main className="content">
      <div className="topbar">
        <div className="breadcrumb"><span>PHI ECOSYSTEM</span><ChevronRight size={13}/><strong>IDENTITY CENTER</strong></div>
        {LOCAL_AUTH_LAB
          ? <Pill color="amber"><span className="live-dot"/> LOCAL IDENTITY LAB · DEV ONLY</Pill>
          : <Pill color="amber"><span className="live-dot"/> STATIC DEMO · NO LOGIN</Pill>}
      </div>
      <div className="content-body">
        {tab === 'overview' && <>
          <section className="hero">
            <div className="orbit orbit-a"/><div className="orbit orbit-b"/><div className="orbit orbit-c"/>
            <div className="hero-content">
              <div className="hero-pre"><Sparkles size={15}/> WELCOME TO THE FIELD</div>
              <h1>One identity.<br/><em>Your authority.</em></h1>
              <p>A sovereign home for your account across PhiOS, PhiMail, and PhiCloud. Built to keep control with you.</p>
              <button type="button" onClick={() => navigate('ecosystem')} className="primary-btn">Explore your ecosystem <ArrowRight size={16}/></button>
            </div>
            <div className="hero-mark" aria-hidden="true">Φ</div>
          </section>
          <div className="section-caption"><span>IDENTITY PREVIEW</span><span>00 / R0</span></div>
          <section className="overview-grid">
            <article className="account-card">
              <div className="card-topline"><span>PHI ACCOUNT</span><Pill color="amber">{localSession?.authenticated ? 'VERIFIED LOCAL OIDC' : 'SYNTHETIC'}</Pill></div>
              <div className="profile-row">
                <div className="avatar"><UserRound size={26}/></div>
                <div><h3>{localSession?.authenticated ? (localSession.preferred_username || 'Local identity') : account.preferred_username}</h3><p>{localSession?.authenticated ? 'Verified local dev session · not OS authorization' : 'Preview persona · not signed in'}</p></div>
              </div>
              <div className="account-property"><span>Subject</span><code>{localSession?.authenticated ? localSession.sub : account.sub}</code></div>
              <div className="account-property"><span>Email</span><strong>Not provisioned</strong></div>
              <div className="account-property"><span>Identity provider</span><strong>{localSession?.authenticated ? 'Local Keycloak DEV' : 'Not signed in'}</strong></div>
              {LOCAL_AUTH_LAB && <div className="auth-controls">
                {localSession?.authenticated
                  ? <button type="button" className="primary-btn" onClick={endLocalSession}>End local session</button>
                  : <button type="button" className="primary-btn" onClick={() => window.location.assign('/auth/login')}>Sign in to local Keycloak <ArrowRight size={15}/></button>}
                <small>Loopback-only test. Never grants PhiOS, PhiMail or PhiCloud permissions.</small>
              </div>}
              <button type="button" className="text-action" onClick={() => navigate('portability')}>View sample metadata <ArrowRight size={15}/></button>
            </article>
            <article className="principles-card">
              <div className="card-topline"><span>BUILT AROUND YOU</span><Pill>FOUNDATION</Pill></div>
              <div className="principle"><span className="principle-icon"><Fingerprint size={19}/></span><div><strong>Your identity is portable</strong><p>Your email is an alias, never the permanent account key.</p></div></div>
              <div className="principle"><span className="principle-icon"><Unplug size={19}/></span><div><strong>Offline still means yours</strong><p>PhiOS does not need an online account to operate.</p></div></div>
              <div className="principle"><span className="principle-icon"><ShieldCheck size={19}/></span><div><strong>Access requires permission</strong><p>Authentication never bypasses local PhiOS approval.</p></div></div>
            </article>
          </section>
          <section className="overview-lower">
            <div><span className="eyebrow">THE ECOSYSTEM</span><h2>Made to connect.<br/>Never to trap.</h2><p>PhiID will eventually link the Field's applications using standard identity protocols and user-directed consent.</p></div>
            <div className="mini-apps">
              {SERVICES.map(service => { const Icon = service.icon; return <div key={service.id}><Icon size={19}/><strong>{service.title}</strong><span>Planned integration</span></div>; })}
            </div>
          </section>
        </>}

        {tab === 'ecosystem' && <>
          <SectionIntro eyebrow="CONNECTED WORLDS" title="Your Field, your connections." description="Preview what voluntary account linking could look like. These controls change this page only and never contact the real projects."/>
          <div className="disclaimer"><Shield size={17}/><span>All link states are temporary simulations. There is no login, authorization, network call, or real grant.</span></div>
          <div className="service-grid">{SERVICES.map(s => <ServiceCard key={s.id} service={s} linked={previewLinks.includes(s.id)} onToggle={changeLink}/>)}</div>
          <div className="info-strip"><Network size={17}/><div><strong>One identity, separate permissions.</strong><p>Future integrations will need explicit opt-in, scoped access and service-side authorization. A sign-in cannot authorize OS actions.</p></div></div>
        </>}

        {tab === 'consent' && LOCAL_AUTH_LAB && <ConsentCenter authenticated={localSession?.authenticated === true} />}

        {tab === 'pocket-approval' && LOCAL_AUTH_LAB && <PocketApprovalCenter authenticated={localSession?.authenticated === true} />}

        {tab === 'security' && <>
          <SectionIntro eyebrow="TRUST BY DESIGN" title="Secure foundations, not security theater." description="We plan to rely on established open identity standards instead of inventing our own passwords, encryption or token service."/>
          <div className="security-feature">
            <div className="feature-orb"><Fingerprint size={40}/></div>
            <div><Pill color="amber">FUTURE INTEGRATION</Pill><h3>Passkeys first. User control always.</h3><p>A future audited OpenID Connect provider can handle login, passkeys, sessions and recovery. This concept page has no credential collection or account enrollment.</p></div>
          </div>
          <div className="security-list">
            {SAFETY.map(item => { const Icon = item.icon; return <div className="security-row" key={item.name}><span className="security-row-icon"><Icon size={20}/></span><div><strong>{item.name}</strong><p>{item.summary}</p></div><span className="security-stage">{item.stage}</span></div>; })}
          </div>
          <div className="info-strip"><LockKeyhole size={18}/><div><strong>Capability is not authority.</strong><p>Even a valid future PhiID session cannot silently unlock PhiOS, launch an agent, read local files or approve an infrastructure change.</p></div></div>
        </>}

        {tab === 'portability' && <>
          <SectionIntro eyebrow="EXIT IS A FEATURE" title="Your identity, without captivity." description="Inspect and export a synthetic metadata example. Real account exports and privacy tooling require an audited, deployed identity provider."/>
          <div className="portability-layout">
            <div className="account-card export-form">
              <div className="card-topline"><span>PREVIEW PROFILE</span><Pill color="amber">NOT VERIFIED</Pill></div>
              <label htmlFor="preview-alias">Display username (demo only)</label>
              <input id="preview-alias" value={alias} maxLength={64} onChange={e => setAlias(e.target.value)}
                placeholder="field-explorer" autoComplete="off" />
              <p>Changes stay in this browser session's page state and are not saved to a user account.</p>
              <div className="account-property"><span>Issuer</span><code>{account.issuer}</code></div>
              <div className="account-property"><span>Identity comparison key</span><code className="long-key">{identityKey}</code></div>
              <button type="button" className="primary-btn export-button" onClick={downloadPreview}><Download size={16}/> Download demo JSON</button>
            </div>
            <div className="json-card">
              <div className="card-topline"><span>PHI-ACCOUNT / 0.1</span><span>JSON PREVIEW</span></div>
              <pre>{JSON.stringify(exportPayload, null, 2)}</pre>
            </div>
          </div>
          <div className="info-strip"><Database size={17}/><div><strong>This is not a credential or identity backup.</strong><p>The exported sample cannot sign in, recover a real account, verify identity, or prove ownership. A future portability system needs real secure provider-side export and recovery.</p></div></div>
        </>}
        {notice && <div role="status" className="toast"><Check size={15}/>{notice}<button type="button" aria-label="Dismiss notice" onClick={() => setNotice('')}>×</button></div>}
        <footer><span>Φ PHIID · SOVEREIGN IDENTITY CONCEPT</span><span>PUBLIC R0 · NO ACTIVE ACCOUNTS</span><a href="https://github.com/MichaelWave369/PhiID" target="_blank" rel="noreferrer">SOURCE <ArrowUpRight size={13}/></a></footer>
      </div>
    </main>
  </div>;
}

export default App;
