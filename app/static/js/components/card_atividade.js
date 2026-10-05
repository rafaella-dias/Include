document.addEventListener('click', (e) => {
  const btn = e.target.closest('.atv-card__save');
  if (!btn) return;
  const ativo = btn.getAttribute('aria-pressed') === 'true';
  btn.setAttribute('aria-pressed', String(!ativo));
  // TODO (backend): fetch(`/materiais/${btn.dataset.id}/favoritar`, { method: 'POST' })
});