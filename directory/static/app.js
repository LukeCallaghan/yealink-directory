document.querySelectorAll('[data-open]').forEach(button => {
  button.addEventListener('click', () => document.getElementById(button.dataset.open).showModal());
});
document.querySelectorAll('[data-close]').forEach(button => {
  button.addEventListener('click', () => button.closest('dialog').close());
});
const search = document.getElementById('search');
if (search) search.addEventListener('input', () => {
  let count = 0;
  document.querySelectorAll('[data-contact-row]').forEach(row => {
    row.hidden = !row.textContent.toLowerCase().includes(search.value.toLowerCase());
    if (!row.hidden) count++;
  });
  document.getElementById('contact-count').textContent = `${count} contacts`;
});
const summary = document.getElementById('sync-summary');
if (summary) {
  async function refreshStatus() {
    try {
      const response = await fetch('/status', {headers: {'Accept': 'application/json'}});
      if (!response.ok || !response.headers.get('content-type')?.includes('application/json')) return;
      const data = await response.json();
      const enrolled = data.phones.filter(p => p.enrolled);
      const updated = enrolled.filter(p => p.status === 'Up to date' && p.revision === data.revision).length;
      const attention = enrolled.filter(p => p.status === 'Needs attention').length;
      summary.textContent = enrolled.length ? `${updated} of ${enrolled.length} phones up to date${attention ? ` · ${attention} need attention` : ''}` : 'No phones enrolled';
      document.getElementById('worker-status').textContent = data.worker ? 'Updates run in the background' : 'Background worker unavailable';
    } catch (_) { document.getElementById('worker-status').textContent = 'Connection unavailable'; }
  }
  refreshStatus();
  setInterval(refreshStatus, 10000);
}
