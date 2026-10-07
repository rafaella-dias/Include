/* static/js/card-material.js — comportamento compartilhado do card de material */
document.addEventListener('click', (e) => {
  const btn = e.target.closest('.mat-card__save');
  if (!btn) return;
  const ativo = btn.getAttribute('aria-pressed') === 'true';
  btn.setAttribute('aria-pressed', String(!ativo));
  // TODO (backend): fetch(`/materiais/${btn.dataset.id}/favoritar`, { method: 'POST' })
});