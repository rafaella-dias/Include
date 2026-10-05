/* static/js/home.js */
(() => {
  /* Carrossel: bolinhas */
  const track = document.querySelector('.hm-carousel__track');
  const dots = document.querySelector('.hm-carousel__dots');
  if (track && dots) {
    const slides = [...track.children];
    dots.hidden = slides.length < 2;
    slides.forEach((slide, i) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.setAttribute('aria-label', `Ir para o slide ${i + 1}`);
      b.addEventListener('click', () =>
        slide.scrollIntoView({ behavior: 'smooth', inline: 'center', block: 'nearest' }));
      dots.appendChild(b);
    });
    const sync = () => {
      const i = Math.round(track.scrollLeft / track.clientWidth);
      [...dots.children].forEach((d, j) => d.setAttribute('aria-current', String(i === j)));
    };
    track.addEventListener('scroll', sync, { passive: true });
    sync();
  }

  /* Matérias técnicas: mostra só os materiais do curso escolhido */
  const pills = [...document.querySelectorAll('.hm-curso')];
  const panels = [...document.querySelectorAll('.hm-panel')];
  const home = document.getElementById('hm-default');

  const select = (id) => {
    pills.forEach(p => p.setAttribute('aria-pressed', String(p.dataset.target === id)));
    panels.forEach(p => { p.hidden = p.id !== id; });
    if (home) home.hidden = Boolean(id);
  };
  pills.forEach(p => p.addEventListener('click', () =>
    select(p.getAttribute('aria-pressed') === 'true' ? null : p.dataset.target)));
  document.querySelectorAll('[data-clear]').forEach(b =>
    b.addEventListener('click', () => select(null)));

  /* Matérias: seta que avança o carrossel (volta ao início no fim) */
  const list = document.getElementById('hm-cursos');
  const next = document.getElementById('hm-cursos-next');
  if (list && next) {
    const atEnd = () => list.scrollLeft + list.clientWidth >= list.scrollWidth - 4;
    const update = () => {
      next.hidden = list.scrollWidth <= list.clientWidth + 4;
      next.dataset.end = String(atEnd());
    };
    next.addEventListener('click', () => {
      const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
      list.scrollTo({
        left: atEnd() ? 0 : list.scrollLeft + list.clientWidth + 10,
        behavior: reduce ? 'auto' : 'smooth'
      });
    });
    list.addEventListener('scroll', update, { passive: true });
    addEventListener('resize', update);
    update();
  }

  /* Salvar (visual por enquanto) */
  document.querySelectorAll('.hm-card__save').forEach(btn =>
    btn.addEventListener('click', () =>
      btn.setAttribute('aria-pressed', String(btn.getAttribute('aria-pressed') !== 'true'))));
})();