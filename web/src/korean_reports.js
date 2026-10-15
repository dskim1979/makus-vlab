        // ═══════════════════════════════════════════════════════════════════════
        // 한국형 보고서 (공공기관 보고 양식) — 보고서 탭 > '공공 보고서'
        //  가상화 인프라 운영 현황 보고 · 자원 사용 현황 및 증설 검토 · 가상서버 자원 현황 대장
        //  자료: POST /api/korean-reports/data (pegaprox/api/korean_reports.py)
        //  문서: static/js/makus-reports.js (web/reports-src, 필요할 때 불러옴) — 미리보기·인쇄(PDF)·한글(HWPX)·워드(DOCX)·엑셀(XLSX)
        //  작성 정보(기관·부서·작성자)는 이 브라우저에 기억 (localStorage)
        //  원본: 한국형 보고서 (Makus Systems)
        // ═══════════════════════════════════════════════════════════════════════

        const KR_META_KEY = 'makus-report-meta';
        const KR_PREVIEW_DELAY = 700;
        const KR_TYPE_ICON = { ops: 'FileText', resource: 'BarChart', asset: 'Server' };
        const KR_PRESETS = ['이번 달', '지난 달', '최근 7일', '최근 30일', '지난 분기', '올해'];
        const KR_CLS = ['대외비', '내부용', '비공개'];

        let _krLibPromise = null;
        function loadKoreanReportsLib() {
            if (window.MakusReports) return Promise.resolve(window.MakusReports);
            if (_krLibPromise) return _krLibPromise;
            _krLibPromise = new Promise((resolve, reject) => {
                const s = document.createElement('script');
                s.src = '/static/js/makus-reports.js';
                s.onload = () => (window.MakusReports ? resolve(window.MakusReports) : reject(new Error('보고서 모듈을 불러오지 못했습니다')));
                s.onerror = () => { _krLibPromise = null; reject(new Error('보고서 모듈(makus-reports.js)을 불러오지 못했습니다')); };
                document.head.appendChild(s);
            });
            return _krLibPromise;
        }

        // 한국 날짜(YYYY-MM-DD)
        function krYmd(d) {
            return new Date(d.getTime() + 9 * 3600000).toISOString().slice(0, 10);
        }
        function krPresetRanges() {
            const now = new Date();
            const k = new Date(now.getTime() + 9 * 3600000);
            const y = k.getUTCFullYear(), m = k.getUTCMonth();
            const first = (yy, mm) => new Date(Date.UTC(yy, mm, 1) - 9 * 3600000);
            const last = (yy, mm) => new Date(Date.UTC(yy, mm + 1, 0) - 9 * 3600000);
            const q = Math.floor(m / 3);
            const pq = q === 0 ? { y: y - 1, q: 3 } : { y, q: q - 1 };
            return [
                { label: KR_PRESETS[0], from: krYmd(first(y, m)), to: krYmd(now) },
                { label: KR_PRESETS[1], from: krYmd(first(y, m - 1)), to: krYmd(last(y, m - 1)) },
                { label: KR_PRESETS[2], from: krYmd(new Date(now.getTime() - 6 * 86400000)), to: krYmd(now) },
                { label: KR_PRESETS[3], from: krYmd(new Date(now.getTime() - 29 * 86400000)), to: krYmd(now) },
                { label: KR_PRESETS[4], from: krYmd(first(pq.y, pq.q * 3)), to: krYmd(last(pq.y, pq.q * 3 + 2)) },
                { label: KR_PRESETS[5], from: `${y}-01-01`, to: krYmd(now) },
            ];
        }

        function KoreanReportsTab({ clusterId, authFetch, addToast }) {
            const ranges = React.useMemo(() => krPresetRanges(), []);
            const [lib, setLib] = React.useState(window.MakusReports || null);
            const [libError, setLibError] = React.useState('');
            const [type, setType] = React.useState('ops');
            const [from, setFrom] = React.useState(ranges[1].from);
            const [to, setTo] = React.useState(ranges[1].to);
            const [clusters, setClusters] = React.useState([]);
            const [picked, setPicked] = React.useState(clusterId ? [clusterId] : []);  // 빈 배열 = 전체
            const [meta, setMeta] = React.useState(() => {
                const base = { org: '', dept: '', author: '', contact: '', classification: '' };
                try { return { ...base, ...(JSON.parse(localStorage.getItem(KR_META_KEY) || 'null') || {}) }; } catch (e) { return base; }
            });
            const [data, setData] = React.useState(null);
            const [loading, setLoading] = React.useState(false);
            const [error, setError] = React.useState('');
            const [busy, setBusy] = React.useState('');
            const [reload, setReload] = React.useState(0);
            const seq = React.useRef(0);

            React.useEffect(() => {
                loadKoreanReportsLib().then(setLib).catch(e => setLibError(e.message || String(e)));
            }, []);
            React.useEffect(() => {
                (async () => {
                    const r = await authFetch(`${API_URL}/korean-reports/clusters`);
                    if (r?.ok) setClusters(await r.json());
                })();
            }, []);

            const setMetaField = (k, v) => {
                const next = { ...meta, [k]: v };
                setMeta(next);
                try { localStorage.setItem(KR_META_KEY, JSON.stringify(next)); } catch (e) {}
            };
            const toggleCluster = (id) => setPicked(p => (p.includes(id) ? p.filter(x => x !== id) : [...p, id]));

            const invalid = !from || !to || from > to;

            // 미리보기: 조건이 바뀌면 잠시 뒤 다시 모음 (늦게 도착한 앞선 응답은 버림)
            React.useEffect(() => {
                if (invalid) return;
                const timer = setTimeout(async () => {
                    const my = ++seq.current;
                    setLoading(true);
                    setError('');
                    try {
                        const r = await authFetch(`${API_URL}/korean-reports/data`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ type, from, to, clusterIds: picked, meta, locale: 'ko' }),
                        });
                        if (my !== seq.current) return;
                        if (!r) throw new Error('연결 오류');
                        const j = await r.json().catch(() => ({}));
                        if (!r.ok) throw new Error(j.error || `오류 (${r.status})`);
                        setData(j);
                    } catch (e) {
                        if (my === seq.current) setError(e.message || String(e));
                    } finally {
                        if (my === seq.current) setLoading(false);
                    }
                }, KR_PREVIEW_DELAY);
                return () => clearTimeout(timer);
            }, [type, from, to, picked.join(','), JSON.stringify(meta), reload, invalid]);

            const html = React.useMemo(() => (lib && data ? lib.html(data) : ''), [lib, data]);

            const saveFile = (fmt) => {
                if (!lib || !data) return;
                setBusy(fmt);
                try {
                    const { blob, name } = lib.file(data, fmt);
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = name;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    setTimeout(() => URL.revokeObjectURL(url), 10000);
                } catch (e) {
                    addToast && addToast(`문서를 만들지 못했습니다: ${e.message || e}`, 'error');
                } finally {
                    setBusy('');
                }
            };

            // PDF: 보고서 HTML 을 숨은 창에 넣고 브라우저 인쇄 → 'PDF 로 저장' (파일 이름은 보고서 제목)
            const printPdf = () => {
                if (!lib || !data) return;
                const f = document.createElement('iframe');
                f.style.cssText = 'position:fixed;right:0;bottom:0;width:0;height:0;border:0;';
                document.body.appendChild(f);
                const doc = f.contentWindow.document;
                doc.open();
                doc.write(html.replace(/<title>[^<]*<\/title>/i, `<title>${lib.fileName(data, 'pdf').replace(/\.pdf$/, '')}</title>`));
                doc.close();
                setTimeout(() => {
                    try { f.contentWindow.focus(); f.contentWindow.print(); } catch (e) { addToast && addToast('인쇄 창을 열지 못했습니다', 'error'); }
                    setTimeout(() => f.remove(), 60000);
                }, 300);
            };

            const card = 'bg-proxmox-dark border border-proxmox-border rounded-lg';
            const input = 'w-full bg-proxmox-darker border border-proxmox-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-proxmox-orange';
            const label = 'block text-xs text-gray-400 mb-1';
            const TypeIcon = (k) => { const I = Icons[KR_TYPE_ICON[k]] || Icons.FileText; return <I className="w-5 h-5" />; };
            const typeKeys = ['ops', 'resource', 'asset'];

            if (libError) {
                return <div className="text-center py-12 text-red-400">{libError}</div>;
            }

            return (
                <div className="space-y-4">
                    {/* 보고서 종류 */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                        {typeKeys.map(k => {
                            const on = type === k;
                            const tx = lib ? lib.typeText(k, 'ko') : { title: k, desc: '' };
                            return (
                                <button key={k} onClick={() => setType(k)}
                                    className={`${card} text-left p-4 flex gap-3 items-start transition-colors ${on ? 'border-proxmox-orange ring-1 ring-proxmox-orange' : 'hover:border-gray-500'}`}>
                                    <span className={`w-10 h-10 shrink-0 rounded-lg flex items-center justify-center ${on ? 'bg-proxmox-orange text-white' : 'bg-proxmox-darker text-gray-400'}`}>{TypeIcon(k)}</span>
                                    <span className="min-w-0">
                                        <span className="block text-white font-semibold">{tx.title}</span>
                                        <span className="block text-xs text-gray-400 mt-0.5 leading-relaxed">{tx.desc}</span>
                                    </span>
                                </button>
                            );
                        })}
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                        {/* 설정 */}
                        <div className={`${card} p-4 space-y-4`}>
                            <div>
                                <div className="text-sm font-semibold text-white mb-2">보고 기간 및 대상</div>
                                <div className="flex flex-wrap gap-1.5 mb-3">
                                    {ranges.map(r => {
                                        const sel = from === r.from && to === r.to;
                                        return (
                                            <button key={r.label} onClick={() => { setFrom(r.from); setTo(r.to); }}
                                                className={`text-xs px-2.5 py-1 rounded-full border ${sel ? 'bg-proxmox-orange border-proxmox-orange text-white' : 'border-proxmox-border text-gray-300 hover:text-white'}`}>
                                                {r.label}
                                            </button>
                                        );
                                    })}
                                </div>
                                <div className="grid grid-cols-2 gap-2">
                                    <div><label className={label}>시작일</label><input type="date" className={input} value={from} onChange={e => setFrom(e.target.value)} /></div>
                                    <div><label className={label}>종료일</label><input type="date" className={`${input} ${invalid ? 'border-red-500' : ''}`} value={to} onChange={e => setTo(e.target.value)} /></div>
                                </div>
                                <div className="mt-3">
                                    <label className={label}>대상 클러스터 {picked.length === 0 && <span className="text-proxmox-orange">(전체)</span>}</label>
                                    <div className="flex flex-wrap gap-1.5">
                                        <button onClick={() => setPicked([])}
                                            className={`text-xs px-2.5 py-1 rounded-lg border ${picked.length === 0 ? 'bg-proxmox-orange/20 border-proxmox-orange text-white' : 'border-proxmox-border text-gray-300'}`}>전체</button>
                                        {clusters.map(c => (
                                            <button key={c.id} onClick={() => toggleCluster(c.id)} title={c.connected ? '' : '연결 안 됨'}
                                                className={`text-xs px-2.5 py-1 rounded-lg border ${picked.includes(c.id) ? 'bg-proxmox-orange/20 border-proxmox-orange text-white' : 'border-proxmox-border text-gray-300'} ${c.connected ? '' : 'opacity-50'}`}>
                                                {c.name}
                                            </button>
                                        ))}
                                    </div>
                                </div>
                                {type === 'asset' && <div className="text-xs text-gray-500 mt-2">가상서버 대장은 기간과 관계없이 생성 시점의 현황을 담습니다.</div>}
                            </div>

                            <div className="border-t border-proxmox-border pt-3">
                                <div className="text-sm font-semibold text-white mb-2">작성 정보 <span className="text-xs font-normal text-gray-500">(선택 · 이 브라우저에 기억됩니다)</span></div>
                                <div className="grid grid-cols-2 gap-2">
                                    <div><label className={label}>기관명</label><input className={input} placeholder="예: ○○시청" value={meta.org} onChange={e => setMetaField('org', e.target.value)} /></div>
                                    <div><label className={label}>부서명</label><input className={input} placeholder="예: 정보통신과" value={meta.dept} onChange={e => setMetaField('dept', e.target.value)} /></div>
                                    <div><label className={label}>작성자</label><input className={input} placeholder="예: 홍길동 주무관" value={meta.author} onChange={e => setMetaField('author', e.target.value)} /></div>
                                    <div><label className={label}>연락처</label><input className={input} placeholder="예: 02-000-0000" value={meta.contact} onChange={e => setMetaField('contact', e.target.value)} /></div>
                                    <div className="col-span-2">
                                        <label className={label}>보안 등급 표시</label>
                                        <select className={input} value={meta.classification} onChange={e => setMetaField('classification', e.target.value)}>
                                            <option value="">표시 안 함</option>
                                            {KR_CLS.map(c => <option key={c} value={c}>{c}</option>)}
                                        </select>
                                    </div>
                                </div>
                            </div>

                            <div className="space-y-2">
                                <button disabled={invalid || !data || !lib || !!busy} onClick={printPdf}
                                    className="w-full py-2.5 rounded-lg bg-proxmox-orange text-white font-semibold disabled:opacity-40 flex items-center justify-center gap-2">
                                    <Icons.FileText className="w-4 h-4" /> PDF (인쇄 → PDF로 저장)
                                </button>
                                <div className="grid grid-cols-3 gap-2">
                                    {[['hwpx', '한글'], ['docx', '워드'], ['xlsx', '엑셀']].map(([f, n]) => (
                                        <button key={f} disabled={invalid || !data || !lib || !!busy} onClick={() => saveFile(f)}
                                            className="py-2 rounded-lg border border-proxmox-border text-sm text-gray-200 hover:text-white hover:border-gray-500 disabled:opacity-40">
                                            {busy === f ? '만드는 중…' : `${n} (${f.toUpperCase()})`}
                                        </button>
                                    ))}
                                </div>
                                <div className="text-[11px] text-gray-500 leading-relaxed text-center">
                                    한글 문서는 한글 2014 이후에서 열리며 HWP 가 필요하면 한글에서 '다른 이름으로 저장 → HWP' · 엑셀은 표마다 시트로 나뉘고 숫자는 계산할 수 있는 값
                                </div>
                            </div>
                        </div>

                        {/* 미리보기 */}
                        <div className={`${card} lg:col-span-2 flex flex-col overflow-hidden`} style={{ minHeight: 640 }}>
                            <div className="flex items-center gap-2 px-4 py-2.5 border-b border-proxmox-border">
                                <Icons.Eye className="w-4 h-4 text-gray-400" />
                                <span className="text-sm font-semibold text-white">미리보기</span>
                                <span className="text-xs text-gray-500 flex-1 truncate">조건을 바꾸면 자동으로 갱신됩니다</span>
                                {loading && <span className="text-xs text-proxmox-orange">자료를 모으는 중…</span>}
                                <button onClick={() => setReload(n => n + 1)} disabled={invalid || loading}
                                    className="text-xs px-2.5 py-1 rounded border border-proxmox-border text-gray-300 hover:text-white disabled:opacity-40">새로 고침</button>
                            </div>
                            <div className="flex-1 relative" style={{ background: '#e9ecf2' }}>
                                {error ? (
                                    <div className="p-6 text-sm text-red-500">{error}</div>
                                ) : html ? (
                                    <iframe title="보고서 미리보기" srcDoc={html} sandbox=""
                                        style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', border: 0, opacity: loading ? 0.6 : 1, transition: 'opacity .2s' }} />
                                ) : (
                                    <div className="absolute inset-0 flex items-center justify-center text-sm text-gray-600">
                                        {invalid ? '보고 기간을 확인하세요' : '보고서 자료를 모으는 중입니다…'}
                                    </div>
                                )}
                            </div>
                            {data?.errors?.length > 0 && (
                                <div className="px-4 py-2 text-xs text-yellow-400 border-t border-proxmox-border">
                                    일부 클러스터를 읽지 못했습니다: {data.errors.map(e => `${e.connection} (${e.error})`).join(', ')}
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            );
        }
