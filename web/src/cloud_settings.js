
        // ═══════════════════════════════════════════════
        // Cloud Settings — server/branding tab only (part 2/N of making
        // Cloud a real layout, not preview). Domain/port/SSL/ACME/SMTP/
        // webhooks/plugins are much bigger and come in later installments;
        // this covers what the roadmap called "서버/브랜딩" specifically.
        //
        // NS: /api/settings/server's form-data branch does NOT do partial
        // updates the way its JSON branch does — request.form.get('domain','')
        // with a blank-string default means an omitted field gets reset, not
        // left alone (confirmed by reading pegaprox/api/settings.py directly,
        // not assumed). So this component fetches the FULL settings object,
        // keeps all of it in state even though the UI below only exposes a
        // few fields, and re-sends the *entire* thing on save — same safe
        // pattern the classic Settings modal already uses, just with a
        // narrower visible form on top of it.
        // ═══════════════════════════════════════════════
        function CloudSettings({ t, addToast }) {
            const { getAuthHeaders } = useAuth();
            const [settings, setSettings] = useState(null); // null until first fetch completes
            const [loading, setLoading] = useState(true);
            const [saving, setSaving] = useState(false);
            const [logoFile, setLogoFile] = useState(null);
            const [faviconFile, setFaviconFile] = useState(null);
            const [loginBgFile, setLoginBgFile] = useState(null);
            const [fileErr, setFileErr] = useState('');

            const fetchAll = async () => {
                setLoading(true);
                try {
                    const r = await fetch(`${API_URL}/settings/server`, { credentials: 'include', headers: getAuthHeaders() });
                    if (r.ok) setSettings(await r.json());
                } catch (e) { /* keep last-known settings on transient failure */ }
                setLoading(false);
            };
            useEffect(() => { fetchAll(); }, []);

            const deleteAsset = async (field) => {
                try {
                    const r = await fetch(`${API_URL}/settings/branding/${field}`, { method: 'DELETE', credentials: 'include', headers: getAuthHeaders() });
                    if (r.ok) {
                        addToast('제거되었습니다', 'success');
                        setSettings(prev => ({ ...prev, [`${field}_url`]: '' }));
                    }
                } catch (e) { addToast('오류가 발생했습니다', 'error'); }
            };

            const deleteLoginBg = async () => {
                try {
                    const r = await fetch(`${API_URL}/settings/login-background`, { method: 'DELETE', credentials: 'include', headers: getAuthHeaders() });
                    if (r.ok) {
                        addToast('로그인 배경이 삭제되었습니다', 'success');
                        setSettings(prev => ({ ...prev, login_background: '' }));
                    }
                } catch (e) { addToast('오류가 발생했습니다', 'error'); }
            };

            const handleSave = async () => {
                if (!settings) return;
                setSaving(true);
                try {
                    // Re-send the whole settings object, not just what this form shows —
                    // see the module comment above for why that matters here.
                    const fd = new FormData();
                    fd.append('domain', settings.domain || '');
                    fd.append('port', settings.port || 5000);
                    fd.append('http_redirect_port', settings.http_redirect_port ?? 0);
                    fd.append('ssl_enabled', settings.ssl_enabled ? 'true' : 'false');
                    fd.append('default_theme', settings.default_theme || 'proxmoxDark');
                    fd.append('reverse_proxy_enabled', settings.reverse_proxy_enabled ? 'true' : 'false');
                    fd.append('trusted_proxies', settings.trusted_proxies || '');
                    fd.append('proxy_bind_address', settings.proxy_bind_address || '');
                    fd.append('acme_enabled', settings.acme_enabled ? 'true' : 'false');
                    fd.append('acme_provider', settings.acme_provider || 'letsencrypt');
                    fd.append('acme_email', settings.acme_email || '');
                    fd.append('acme_staging', settings.acme_staging ? 'true' : 'false');
                    fd.append('acme_challenge_type', settings.acme_challenge_type || 'http-01');
                    fd.append('acme_dns_provider', settings.acme_dns_provider || 'manual');
                    fd.append('acme_allow_private_ca', settings.acme_allow_private_ca ? 'true' : 'false');
                    fd.append('audit_retention_days', String(settings.audit_retention_days || 90));
                    fd.append('air_gap_mode', settings.air_gap_mode ? 'true' : 'false');
                    fd.append('app_name', settings.app_name || 'MAKUS vLAB');
                    fd.append('app_tagline', settings.app_tagline || '');
                    fd.append('alert_email_recipients', JSON.stringify(settings.alert_email_recipients || []));
                    fd.append('alert_update_available', settings.alert_update_available ? 'true' : 'false');
                    fd.append('syslog_filter_by_selected_cluster', settings.syslog_filter_by_selected_cluster ? 'true' : 'false');
                    fd.append('syslog_enabled', settings.syslog_enabled ? 'true' : 'false');
                    if (logoFile) fd.append('logo', logoFile);
                    if (faviconFile) fd.append('favicon', faviconFile);
                    if (loginBgFile) fd.append('login_background', loginBgFile);

                    const r = await fetch(`${API_URL}/settings/server`, {
                        method: 'POST', credentials: 'include',
                        headers: { ...getAuthHeaders(), 'X-Requested-With': 'XMLHttpRequest' },
                        body: fd,
                    });
                    if (r.ok) {
                        const data = await r.json();
                        addToast('설정이 저장되었습니다', 'success');
                        if (data.restart_required) addToast('서버를 재시작해야 적용됩니다', 'info');
                        setLogoFile(null); setFaviconFile(null); setLoginBgFile(null);
                        fetchAll();
                    } else {
                        const d = await r.json().catch(() => ({}));
                        addToast(d.error || '저장 중 오류가 발생했습니다', 'error');
                    }
                } catch (e) { addToast('저장 중 오류가 발생했습니다', 'error'); }
                setSaving(false);
            };

            const onPick = (setFile, maxMB, errMsg) => (e) => {
                const file = e.target.files[0];
                if (file && file.size > maxMB * 1024 * 1024) {
                    setFileErr(errMsg);
                    e.target.value = '';
                    setFile(null);
                } else {
                    setFileErr('');
                    setFile(file || null);
                }
            };

            if (loading || !settings) {
                return <div style={{ padding: 40, textAlign: 'center', color: 'var(--cloud-text-secondary)' }}>불러오는 중…</div>;
            }

            return (
                <div>
                    <CloudPageHeader title="설정" sub="서버 · 브랜딩">
                        <button className="cloud-btn cloud-btn-primary" onClick={handleSave} disabled={saving}>
                            {saving ? '저장 중…' : '저장'}
                        </button>
                    </CloudPageHeader>

                    <div className="cloud-card" style={{ padding: 20, marginBottom: 16 }}>
                        <h3 style={{ margin: '0 0 4px', fontSize: '1rem', color: 'var(--color-text)' }}>브랜딩</h3>
                        <p style={{ margin: '0 0 16px', fontSize: '.8rem', color: 'var(--cloud-text-secondary)' }}>
                            로그인 화면, 대시보드, 이메일 알림에 표시되는 앱 이름·로고·파비콘을 설정합니다.
                        </p>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
                            <CloudField label="앱 이름">
                                <input className="cloud-input" value={settings.app_name || ''} maxLength={80}
                                    onChange={e => setSettings({ ...settings, app_name: e.target.value })} placeholder="MAKUS vLAB" />
                            </CloudField>
                            <CloudField label="태그라인">
                                <input className="cloud-input" value={settings.app_tagline || ''} maxLength={120}
                                    onChange={e => setSettings({ ...settings, app_tagline: e.target.value })} placeholder="for Proxmox Virtual Environment" />
                            </CloudField>
                        </div>

                        <div style={{ paddingTop: 12, borderTop: '1px solid var(--cloud-divider)', marginBottom: 12 }}>
                            <label style={{ display: 'block', fontSize: '.8rem', color: 'var(--cloud-text-secondary)', marginBottom: 6 }}>로고</label>
                            {settings.logo_url && (
                                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                                    <img src={settings.logo_url} alt="Logo" style={{ height: 40, width: 40, objectFit: 'contain', background: 'var(--cloud-surface-2)', borderRadius: 6, padding: 4 }} />
                                    <button className="cloud-link-btn" style={{ color: '#ef4444' }} onClick={() => deleteAsset('logo')}>제거</button>
                                </div>
                            )}
                            <input type="file" accept=".png,.jpg,.jpeg,.webp,.svg" onChange={onPick(setLogoFile, 2, '로고 파일이 너무 큽니다 (최대 2MB)')} />
                            {logoFile && <p style={{ fontSize: '.75rem', color: '#22c55e', marginTop: 4 }}>{logoFile.name}</p>}
                        </div>

                        <div style={{ paddingTop: 12, borderTop: '1px solid var(--cloud-divider)' }}>
                            <label style={{ display: 'block', fontSize: '.8rem', color: 'var(--cloud-text-secondary)', marginBottom: 6 }}>파비콘</label>
                            {settings.favicon_url && (
                                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                                    <img src={settings.favicon_url} alt="Favicon" style={{ height: 28, width: 28, objectFit: 'contain', background: 'var(--cloud-surface-2)', borderRadius: 6, padding: 4 }} />
                                    <button className="cloud-link-btn" style={{ color: '#ef4444' }} onClick={() => deleteAsset('favicon')}>제거</button>
                                </div>
                            )}
                            <input type="file" accept=".ico,.png,.svg" onChange={onPick(setFaviconFile, 1, '파비콘 파일이 너무 큽니다 (최대 1MB)')} />
                            {faviconFile && <p style={{ fontSize: '.75rem', color: '#22c55e', marginTop: 4 }}>{faviconFile.name}</p>}
                        </div>
                    </div>

                    <div className="cloud-card" style={{ padding: 20, marginBottom: 16 }}>
                        <h3 style={{ margin: '0 0 4px', fontSize: '1rem', color: 'var(--color-text)' }}>로그인 배경</h3>
                        <p style={{ margin: '0 0 16px', fontSize: '.8rem', color: 'var(--cloud-text-secondary)' }}>로그인 화면에 사용자 정의 배경 이미지를 설정합니다. 최대 2MB.</p>
                        {settings.login_background && (
                            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                                <img src={settings.login_background} alt="Login background" style={{ height: 56, borderRadius: 6, objectFit: 'cover' }} />
                                <button className="cloud-link-btn" style={{ color: '#ef4444' }} onClick={deleteLoginBg}>배경 제거</button>
                            </div>
                        )}
                        <input type="file" accept=".png,.jpg,.jpeg,.webp,.svg" onChange={onPick(setLoginBgFile, 2, '배경 이미지 파일이 너무 큽니다 (최대 2MB)')} />
                        {loginBgFile && <p style={{ fontSize: '.75rem', color: '#22c55e', marginTop: 4 }}>{loginBgFile.name}</p>}
                    </div>

                    {fileErr && <p style={{ fontSize: '.8rem', color: '#ef4444', marginBottom: 16 }}>{fileErr}</p>}

                    <div className="cloud-card" style={{ padding: 20, marginBottom: 16 }}>
                        <h3 style={{ margin: '0 0 16px', fontSize: '1rem', color: 'var(--color-text)' }}>도메인 & 포트</h3>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
                            <CloudField label="도메인">
                                <input className="cloud-input" value={settings.domain || ''} placeholder="vlab.example.com"
                                    onChange={e => setSettings({ ...settings, domain: e.target.value })} />
                            </CloudField>
                            <CloudField label="포트">
                                <input className="cloud-input" type="number" min="1" max="65535" value={settings.port || 5000}
                                    onChange={e => setSettings({ ...settings, port: parseInt(e.target.value) || 5000 })} />
                            </CloudField>
                            <CloudField label="HTTP 리다이렉트 포트">
                                <input className="cloud-input" type="number" min="-1" max="65535" value={settings.http_redirect_port ?? 0}
                                    onChange={e => setSettings({ ...settings, http_redirect_port: parseInt(e.target.value) || 0 })} />
                            </CloudField>
                        </div>
                        <p style={{ fontSize: '.75rem', color: 'var(--cloud-text-secondary)', marginTop: 10 }}>
                            포트나 SSL 설정을 바꾸면 서버 재시작이 필요할 수 있습니다. SSL/ACME, SMTP, 웹훅, 플러그인 관리 등 나머지 설정은 곧 이어서 만들 예정입니다 —
                            지금 당장 필요하시면 우측 상단 프로필 메뉴에서 "클라우드 종료 (기업용 화면으로)"를 눌러 클래식 설정 화면을 이용하실 수 있습니다.
                        </p>
                    </div>
                </div>
            );
        }
