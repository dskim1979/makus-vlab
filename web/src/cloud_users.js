
        // ═══════════════════════════════════════════════
        // Cloud Users — user/group/role management, styled to match the rest
        // of the Cloud shell (CloudPageHeader/CloudSearch/CloudModal/CloudField).
        // Reuses the exact same /api/users endpoints the classic Settings >
        // Users tab uses — no new backend, just a Cloud-native front end for it.
        // NS: this replaces the CloudClassicLauncher fallback for 'users'.
        // ═══════════════════════════════════════════════
        function CloudUsers({ t, addToast }) {
            const { getAuthHeaders } = useAuth();
            const [users, setUsers] = useState([]);
            const [allRoles, setAllRoles] = useState([]);
            const [loading, setLoading] = useState(true);
            const [query, setQuery] = useState('');
            const [showAdd, setShowAdd] = useState(false);
            const [editingUser, setEditingUser] = useState(null); // user object or null
            const [passwordResetUser, setPasswordResetUser] = useState(null); // username or null
            const [newPasswordValue, setNewPasswordValue] = useState('');
            const [saving, setSaving] = useState(false);

            const emptyForm = { username: '', password: '', display_name: '', email: '', role: 'user' };
            const [form, setForm] = useState(emptyForm);

            const fetchAll = async () => {
                setLoading(true);
                try {
                    const [uRes, rRes] = await Promise.all([
                        fetch(`${API_URL}/users`, { credentials: 'include', headers: getAuthHeaders() }),
                        fetch(`${API_URL}/roles`, { credentials: 'include', headers: getAuthHeaders() }).catch(() => null),
                    ]);
                    if (uRes.ok) setUsers(await uRes.json());
                    if (rRes && rRes.ok) setAllRoles(await rRes.json());
                } catch (e) { /* keep last-known list on transient failure */ }
                setLoading(false);
            };
            useEffect(() => { fetchAll(); }, []);

            const filtered = users.filter(u =>
                !query || u.username.toLowerCase().includes(query.toLowerCase()) ||
                (u.display_name || '').toLowerCase().includes(query.toLowerCase()) ||
                (u.email || '').toLowerCase().includes(query.toLowerCase())
            );

            const handleCreate = async () => {
                setSaving(true);
                try {
                    const res = await fetch(`${API_URL}/users`, {
                        method: 'POST', credentials: 'include',
                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                        body: JSON.stringify(form),
                    });
                    if (res.ok) {
                        addToast(t('userCreated') || 'User created', 'success');
                        setShowAdd(false);
                        setForm(emptyForm);
                        fetchAll();
                    } else {
                        const d = await res.json().catch(() => ({}));
                        addToast(d.error || 'Error creating user', 'error');
                    }
                } catch (e) { addToast('Error creating user', 'error'); }
                setSaving(false);
            };

            const handleUpdate = async (username, updates) => {
                setSaving(true);
                try {
                    const res = await fetch(`${API_URL}/users/${username}`, {
                        method: 'PUT', credentials: 'include',
                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                        body: JSON.stringify(updates),
                    });
                    if (res.ok) {
                        addToast(t('userUpdated') || 'User updated', 'success');
                        setEditingUser(null);
                        fetchAll();
                    } else {
                        const d = await res.json().catch(() => ({}));
                        addToast(d.error || 'Error updating user', 'error');
                    }
                } catch (e) { addToast('Error updating user', 'error'); }
                setSaving(false);
            };

            const handleDelete = async (username) => {
                if (!confirm(t('deleteUserConfirm') || `Delete user "${username}"?`)) return;
                try {
                    const res = await fetch(`${API_URL}/users/${username}`, { method: 'DELETE', credentials: 'include', headers: getAuthHeaders() });
                    if (res.ok) { addToast(t('userDeleted') || 'User deleted', 'success'); fetchAll(); }
                    else { const d = await res.json().catch(() => ({})); addToast(d.error || 'Error deleting user', 'error'); }
                } catch (e) { addToast('Error deleting user', 'error'); }
            };

            const handleResetPassword = async () => {
                if (!newPasswordValue || newPasswordValue.length < 4) {
                    addToast(t('passwordTooShort') || 'Password too short', 'error');
                    return;
                }
                setSaving(true);
                try {
                    const res = await fetch(`${API_URL}/users/${passwordResetUser}/password`, {
                        method: 'PUT', credentials: 'include',
                        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                        body: JSON.stringify({ password: newPasswordValue }),
                    });
                    if (res.ok) {
                        addToast(t('passwordResetSuccess') || 'Password reset', 'success');
                        setPasswordResetUser(null);
                        setNewPasswordValue('');
                    } else {
                        const d = await res.json().catch(() => ({}));
                        addToast(d.error || 'Error resetting password', 'error');
                    }
                } catch (e) { addToast('Error resetting password', 'error'); }
                setSaving(false);
            };

            const roleLabel = (role) => {
                const builtin = { admin: t('roleAdmin') || 'Admin', user: t('roleUser') || 'User', viewer: t('roleViewer') || 'Viewer' };
                if (builtin[role]) return builtin[role];
                const custom = allRoles.find(r => r.id === role);
                return custom ? (custom.name || custom.id) : role;
            };

            return (
                <div>
                    <CloudPageHeader title={t('users') || 'Users'} sub={`${users.length} ${t('users') || 'users'}`}>
                        <CloudSearch value={query} onChange={setQuery} placeholder={t('cloud.searchUsers') || 'Search username, name, email…'} />
                        <button className="cloud-btn cloud-btn-primary" onClick={() => setShowAdd(true)}>
                            <Icons.UserPlus className="w-4 h-4" /> {t('addUser') || 'Add User'}
                        </button>
                    </CloudPageHeader>

                    {loading ? (
                        <div className="cloud-loading">{'불러오는 중…'}</div>
                    ) : filtered.length === 0 ? (
                        <CloudEmpty icon="Users" title={query ? '검색 결과 없음' : '사용자가 없습니다'} text={query ? '이 검색어와 일치하는 결과가 없습니다.' : ''} />
                    ) : (
                        <div className="cloud-table-wrap">
                            <table className="cloud-table">
                                <thead>
                                    <tr>
                                        <th>{t('usernameLabel') || 'Username'}</th>
                                        <th>{t('displayName') || 'Display Name'}</th>
                                        <th>{t('email') || 'Email'}</th>
                                        <th>{t('role') || 'Role'}</th>
                                        <th>2FA</th>
                                        <th></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {filtered.map(u => (
                                        <tr key={u.username}>
                                            <td className="cloud-cell-strong">{u.username}</td>
                                            <td>{u.display_name || '—'}</td>
                                            <td>{u.email || '—'}</td>
                                            <td><CloudPill color="#49afd9" bg="rgba(73,175,217,0.12)" border="rgba(73,175,217,0.3)">{roleLabel(u.role)}</CloudPill></td>
                                            <td>{u.totp_enabled ? <CloudPill color="#60b515" bg="rgba(96,181,21,0.12)" border="rgba(96,181,21,0.3)">{'활성화됨'}</CloudPill> : <span style={{ color: '#728b9a' }}>—</span>}</td>
                                            <CloudRowActions>
                                                <CloudIconBtn icon="Edit" title={'편집 / 하드웨어'} onClick={() => setEditingUser({ ...u, password: '' })} />
                                                <CloudIconBtn icon="Key" title={t('resetPassword') || 'Reset Password'} onClick={() => setPasswordResetUser(u.username)} />
                                                <CloudIconBtn icon="Trash2" title={'삭제'} danger onClick={() => handleDelete(u.username)} />
                                            </CloudRowActions>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}

                    {/* Add User */}
                    {showAdd && (
                        <CloudModal title={t('addUser') || 'Add User'} onClose={() => { setShowAdd(false); setForm(emptyForm); }} onSubmit={handleCreate} submitLabel={saving ? (t('saving') || 'Saving…') : ('생성')} t={t}>
                            <CloudField label={t('usernameLabel') || 'Username'}>
                                <input className="cloud-input" required value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} />
                            </CloudField>
                            <CloudField label={t('passwordLabel') || 'Password'}>
                                <input className="cloud-input" type="password" required value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} />
                            </CloudField>
                            <CloudField label={t('displayName') || 'Display Name'}>
                                <input className="cloud-input" value={form.display_name} onChange={e => setForm({ ...form, display_name: e.target.value })} />
                            </CloudField>
                            <CloudField label={t('email') || 'Email'}>
                                <input className="cloud-input" type="email" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} />
                            </CloudField>
                            <CloudField label={t('role') || 'Role'}>
                                <select className="cloud-input" value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}>
                                    <option value="admin">{t('roleAdmin') || 'Admin'}</option>
                                    <option value="user">{t('roleUser') || 'User'}</option>
                                    <option value="viewer">{t('roleViewer') || 'Viewer'}</option>
                                    {allRoles.filter(r => !r.builtin).map(r => <option key={r.id} value={r.id}>{r.name || r.id}</option>)}
                                </select>
                            </CloudField>
                        </CloudModal>
                    )}

                    {/* Edit User */}
                    {editingUser && (
                        <CloudModal title={`${'편집 / 하드웨어'}: ${editingUser.username}`} onClose={() => setEditingUser(null)}
                            onSubmit={() => handleUpdate(editingUser.username, { display_name: editingUser.display_name, email: editingUser.email, role: editingUser.role })}
                            submitLabel={saving ? (t('saving') || 'Saving…') : (t('save') || 'Save')} t={t}>
                            <CloudField label={t('displayName') || 'Display Name'}>
                                <input className="cloud-input" value={editingUser.display_name || ''} onChange={e => setEditingUser({ ...editingUser, display_name: e.target.value })} />
                            </CloudField>
                            <CloudField label={t('email') || 'Email'}>
                                <input className="cloud-input" type="email" value={editingUser.email || ''} onChange={e => setEditingUser({ ...editingUser, email: e.target.value })} />
                            </CloudField>
                            <CloudField label={t('role') || 'Role'}>
                                <select className="cloud-input" value={editingUser.role} onChange={e => setEditingUser({ ...editingUser, role: e.target.value })}>
                                    <option value="admin">{t('roleAdmin') || 'Admin'}</option>
                                    <option value="user">{t('roleUser') || 'User'}</option>
                                    <option value="viewer">{t('roleViewer') || 'Viewer'}</option>
                                    {allRoles.filter(r => !r.builtin).map(r => <option key={r.id} value={r.id}>{r.name || r.id}</option>)}
                                </select>
                            </CloudField>
                        </CloudModal>
                    )}

                    {/* Reset Password */}
                    {passwordResetUser && (
                        <CloudModal title={`${t('resetPassword') || 'Reset Password'}: ${passwordResetUser}`} onClose={() => { setPasswordResetUser(null); setNewPasswordValue(''); }}
                            onSubmit={handleResetPassword}
                            submitLabel={saving ? (t('saving') || 'Saving…') : (t('resetPassword') || 'Reset')} t={t}>
                            <CloudField label={t('newPassword') || 'New Password'}>
                                <input className="cloud-input" type="password" autoFocus value={newPasswordValue} onChange={e => setNewPasswordValue(e.target.value)} />
                            </CloudField>
                        </CloudModal>
                    )}
                </div>
            );
        }
