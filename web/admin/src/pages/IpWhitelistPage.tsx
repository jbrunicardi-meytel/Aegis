import React, { useEffect, useMemo, useState } from 'react';
import {
  Button,
  Checkbox,
  DataTableSkeleton,
  InlineNotification,
  Modal,
  Pagination,
  Search,
  Select,
  SelectItem,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Tag,
  TextArea,
} from '@carbon/react';
import { Add as AddIcon, CheckmarkOutline } from '@carbon/icons-react';
import { PageHeader, KpiCard, MetricStrip } from '../components/common';
import { apiService } from '../services/api';

interface WhitelistEntry {
  target: string;
  note?: string;
  expires_at?: string;
}

function isValidWhitelistTarget(value: string): boolean {
  const [address, prefix, ...extra] = value.split('/');
  if (!address || extra.length > 0) return false;

  if (address.includes(':')) {
    try {
      new URL(`http://[${address}]/`);
    } catch {
      return false;
    }
    return prefix === undefined || (/^\d+$/.test(prefix) && Number(prefix) <= 128);
  }

  const octets = address.split('.');
  if (octets.length !== 4 || octets.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) {
    return false;
  }
  return prefix === undefined || (/^\d+$/.test(prefix) && Number(prefix) <= 32);
}

function normalizeEntries(config: Awaited<ReturnType<typeof apiService.getIPWhitelistConfig>>): WhitelistEntry[] {
  const entries = [...(config.entries || [])];
  const known = new Set(entries.map((entry) => entry.target));
  for (const target of [...(config.ips || []), ...(config.cidrs || [])]) {
    if (target && !known.has(target)) entries.push({ target });
  }
  return entries;
}

export const IpWhitelistPage: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [enabled, setEnabled] = useState(false);
  const [entries, setEntries] = useState<WhitelistEntry[]>([]);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [notification, setNotification] = useState<{ kind: 'success' | 'error' | 'warning'; message: string } | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [editingTarget, setEditingTarget] = useState<string | null>(null);
  const [targetsText, setTargetsText] = useState('');
  const [note, setNote] = useState('');
  const [duration, setDuration] = useState('permanent');
  const [submitting, setSubmitting] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const config = await apiService.getIPWhitelistConfig();
      setEnabled(config.enabled);
      setEntries(normalizeEntries(config));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, []);

  const parsedTargets = useMemo(() => {
    const values = targetsText.split(/[\r\n,]+/).map((value) => value.trim()).filter(Boolean);
    return {
      valid: values.filter(isValidWhitelistTarget),
      invalid: values.filter((value) => !isValidWhitelistTarget(value)),
    };
  }, [targetsText]);

  const filteredEntries = useMemo(() => {
    const query = search.trim().toLowerCase();
    return query
      ? entries.filter((entry) => `${entry.target} ${entry.note || ''}`.toLowerCase().includes(query))
      : entries;
  }, [entries, search]);
  const totalPages = Math.max(1, Math.ceil(filteredEntries.length / pageSize));
  const pageEntries = filteredEntries.slice((page - 1) * pageSize, page * pageSize);
  const cidrCount = entries.filter((entry) => entry.target.includes('/')).length;
  const expiringCount = entries.filter((entry) => Boolean(entry.expires_at)).length;

  useEffect(() => {
    if (page > totalPages) setPage(1);
  }, [page, totalPages]);

  const saveEntries = async (nextEntries: WhitelistEntry[], nextEnabled: boolean) => {
    return apiService.saveIPWhitelistConfig({
      enabled: nextEnabled,
      ips: [],
      cidrs: [],
      entries: nextEntries,
    });
  };

  const toggleEnabled = async (nextEnabled: boolean) => {
    setSubmitting(true);
    const ok = await saveEntries(entries, nextEnabled);
    setSubmitting(false);
    if (ok) {
      setEnabled(nextEnabled);
      setNotification({ kind: 'success', message: nextEnabled ? 'Whitelist enabled' : 'Whitelist disabled' });
    } else {
      setNotification({ kind: 'error', message: 'Failed to update whitelist state' });
    }
  };

  const openAdd = () => {
    setEditingTarget(null);
    setTargetsText('');
    setNote('');
    setDuration('permanent');
    setModalOpen(true);
  };

  const openEdit = (entry: WhitelistEntry) => {
    setEditingTarget(entry.target);
    setTargetsText(entry.target);
    setNote(entry.note || '');
    setDuration(entry.expires_at ? 'existing' : 'permanent');
    setModalOpen(true);
  };

  const handleSave = async () => {
    if (parsedTargets.valid.length === 0 || parsedTargets.invalid.length > 0) return;
    setSubmitting(true);
    const current = await apiService.getIPWhitelistConfig();
    const removeTargets = new Set(parsedTargets.valid);
    if (editingTarget) removeTargets.add(editingTarget);
    const nextEntries = normalizeEntries(current).filter((entry) => !removeTargets.has(entry.target));
    const oldExpiry = entries.find((entry) => entry.target === editingTarget)?.expires_at;
    const expiryMap: Record<string, number> = {
      '1h': 60 * 60 * 1000,
      '24h': 24 * 60 * 60 * 1000,
      '7d': 7 * 24 * 60 * 60 * 1000,
      '30d': 30 * 24 * 60 * 60 * 1000,
    };
    const expiresAt = duration === 'existing' ? oldExpiry : expiryMap[duration] ? new Date(Date.now() + expiryMap[duration]).toISOString() : undefined;
    for (const target of parsedTargets.valid) {
      nextEntries.push({ target, ...(note.trim() ? { note: note.trim() } : {}), ...(expiresAt ? { expires_at: expiresAt } : {}) });
    }
    const ok = await saveEntries(nextEntries, true);
    setSubmitting(false);
    if (ok) {
      setModalOpen(false);
      setNotification({ kind: 'success', message: editingTarget ? 'Whitelist entry updated' : `Added ${parsedTargets.valid.length} allowed target${parsedTargets.valid.length === 1 ? '' : 's'}` });
      await loadData();
    } else {
      setNotification({ kind: 'error', message: 'Failed to save whitelist entries' });
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setSubmitting(true);
    const nextEntries = entries.filter((entry) => entry.target !== deleteTarget);
    const ok = await saveEntries(nextEntries, enabled);
    setSubmitting(false);
    setDeleteTarget(null);
    if (ok) {
      setEntries(nextEntries);
      setNotification({ kind: 'success', message: `Removed ${deleteTarget} from whitelist` });
    } else {
      setNotification({ kind: 'error', message: 'Failed to remove whitelist entry' });
    }
  };

  return (
    <div style={{ padding: '32px 32px 80px', width: '100%', boxSizing: 'border-box' }}>
      <PageHeader
        kicker="Traffic control"
        title="IP Whitelist"
        icon={CheckmarkOutline}
        action={<Button kind="primary" renderIcon={AddIcon} onClick={openAdd}>Add entry</Button>}
      />

      {notification && (
        <div style={{ marginBottom: '20px' }}>
          <InlineNotification
            kind={notification.kind}
            subtitle={notification.message}
            onClose={() => setNotification(null)}
            onCloseButtonClick={() => setNotification(null)}
          />
        </div>
      )}

      <div style={{ marginBottom: '20px', padding: '16px 20px', background: 'var(--cds-layer-01)', borderLeft: '3px solid var(--cds-support-warning)' }}>
        <Checkbox
          id="ip-whitelist-enabled"
          labelText="Enable whitelist bypass for matching addresses"
          checked={enabled}
          disabled={submitting}
          onChange={(_, { checked }) => void toggleEnabled(checked)}
        />
        <p style={{ margin: '8px 0 0 28px', color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
          Active entries bypass Traffic Control checks and WAF inspection.
        </p>
      </div>

      <MetricStrip minColWidth="200px">
        <KpiCard label="Allowed targets" value={entries.length} subtext="Configured IPs and ranges" status="default" />
        <KpiCard label="CIDR ranges" value={cidrCount} subtext="Network ranges" status="default" />
        <KpiCard label="Expiring entries" value={expiringCount} subtext="Configured with an expiry" status="default" />
      </MetricStrip>

      <div style={{ background: 'var(--cds-layer-01)', marginTop: '16px' }}>
        <div style={{ padding: '14px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '16px', borderBottom: '1px solid var(--cds-border-subtle)', flexWrap: 'wrap' }}>
          <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
            <strong style={{ color: 'var(--cds-text-primary)' }}>{filteredEntries.length}</strong> {search ? `matching of ${entries.length}` : 'allowed targets'}
          </div>
          <div style={{ width: '280px' }}>
            <Search size="md" labelText="Search whitelist" placeholder="Search IP, CIDR, or note" value={search} onChange={(event) => { setSearch(event.target.value); setPage(1); }} />
          </div>
        </div>

        {loading ? (
          <DataTableSkeleton columnCount={5} rowCount={8} showHeader={false} showToolbar={false} />
        ) : (
          <Table size="md" aria-label="IP Whitelist Entries">
            <TableHead>
              <TableRow>
                <TableHeader>Target</TableHeader>
                <TableHeader>Type</TableHeader>
                <TableHeader>Expiration</TableHeader>
                <TableHeader>Note</TableHeader>
                <TableHeader style={{ textAlign: 'right' }}>Actions</TableHeader>
              </TableRow>
            </TableHead>
            <TableBody>
              {pageEntries.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} style={{ textAlign: 'center', padding: '48px 16px' }}>
                    <div style={{ fontWeight: 600, fontSize: '14px', marginBottom: '4px' }}>{search ? 'No matching targets' : 'No allowed IPs yet'}</div>
                    <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '16px' }}>{search ? 'Try another address or note.' : 'Add an IP address or CIDR range to bypass Traffic Control and WAF inspection.'}</div>
                    {!search && <Button kind="tertiary" size="sm" renderIcon={AddIcon} onClick={openAdd}>Add first entry</Button>}
                  </TableCell>
                </TableRow>
              ) : pageEntries.map((entry) => {
                const isCidr = entry.target.includes('/');
                const expired = Boolean(entry.expires_at && Date.parse(entry.expires_at) <= Date.now());
                return (
                  <TableRow key={entry.target}>
                    <TableCell>
                      <span style={{ fontFamily: 'var(--cds-font-family-mono, monospace)', fontWeight: 600 }}>{entry.target}</span>
                    </TableCell>
                    <TableCell><Tag type={isCidr ? 'purple' : 'blue'} size="sm">{isCidr ? 'CIDR' : 'IP'}</Tag></TableCell>
                    <TableCell><Tag type={expired ? 'red' : 'cool-gray'} size="sm">{expired ? 'EXPIRED' : entry.expires_at ? new Date(entry.expires_at).toLocaleDateString() : 'Permanent'}</Tag></TableCell>
                    <TableCell>{entry.note || '—'}</TableCell>
                    <TableCell style={{ textAlign: 'right' }}>
                      <Button kind="ghost" size="sm" onClick={() => openEdit(entry)}>Edit</Button>
                      <Button kind="danger--ghost" size="sm" onClick={() => setDeleteTarget(entry.target)}>Remove</Button>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
        {filteredEntries.length > 0 && (
          <Pagination
            totalItems={filteredEntries.length}
            page={page}
            pageSize={pageSize}
            pageSizes={[10, 25, 50, 100]}
            onChange={({ page: nextPage, pageSize: nextSize }) => { if (nextPage) setPage(nextPage); if (nextSize) setPageSize(nextSize); }}
          />
        )}
      </div>

      <Modal
        open={modalOpen}
        modalHeading={editingTarget ? 'Edit whitelist entry' : 'Add to whitelist'}
        primaryButtonText={submitting ? 'Saving...' : editingTarget ? 'Save changes' : 'Add entries'}
        secondaryButtonText="Cancel"
        primaryButtonDisabled={parsedTargets.valid.length === 0 || parsedTargets.invalid.length > 0 || submitting}
        onRequestSubmit={handleSave}
        onRequestClose={() => setModalOpen(false)}
        size="md"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '16px 0' }}>
          <InlineNotification kind="warning" lowContrast hideCloseButton title="Security impact" subtitle="Matching addresses bypass Traffic Control checks and WAF inspection." />
          <TextArea
            id="whitelist-targets"
            labelText="IP addresses or CIDR ranges"
            rows={4}
            value={targetsText}
            onChange={(event) => setTargetsText(event.target.value)}
            placeholder={'203.0.113.10\n198.51.100.0/24'}
            invalid={parsedTargets.invalid.length > 0}
            invalidText={`Invalid target(s): ${parsedTargets.invalid.slice(0, 3).join(', ')}`}
            helperText="Enter one IPv4, IPv6, or CIDR target per line."
          />
          <TextArea id="whitelist-note" labelText="Note" rows={2} value={note} onChange={(event) => setNote(event.target.value)} />
          <Select id="whitelist-duration" labelText="Duration" value={duration} onChange={(event) => setDuration(event.target.value)}>
            {editingTarget && entries.find((entry) => entry.target === editingTarget)?.expires_at && <SelectItem value="existing" text="Keep current expiry" />}
            <SelectItem value="permanent" text="Permanent" />
            <SelectItem value="1h" text="1 hour" />
            <SelectItem value="24h" text="24 hours" />
            <SelectItem value="7d" text="7 days" />
            <SelectItem value="30d" text="30 days" />
          </Select>
        </div>
      </Modal>

      <Modal
        open={Boolean(deleteTarget)}
        danger
        modalHeading="Remove whitelist entry"
        primaryButtonText={submitting ? 'Removing...' : 'Remove'}
        secondaryButtonText="Cancel"
        onRequestSubmit={handleDelete}
        onRequestClose={() => setDeleteTarget(null)}
        size="sm"
      >
        <p style={{ padding: '8px 0', color: 'var(--cds-text-secondary)' }}>
          {deleteTarget} will no longer bypass Traffic Control or WAF inspection.
        </p>
      </Modal>
    </div>
  );
};

export default IpWhitelistPage;