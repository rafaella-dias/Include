const selectCurso = document.getElementById('cursoForm')
const selectMateria = document.getElementById('materiaForm')
const selectConteudo = document.getElementById('conteudoForm')

console.log(cursos);



cursos.forEach(curso => {
    const option = document.createElement('option');

    option.value = curso.id;
    option.textContent = curso.nome;

    selectCurso.appendChild(option); 
});




selectCurso.addEventListener('change', () => {

    const idCurso = Number(selectCurso.value);

    const curso = cursos.find(c => c.id === idCurso);

    if (!curso) {
        return;
    }

    console.log(curso);

    selectMateria.disabled = false;

    selectMateria.innerHTML = '';


    const optionPadrao = document.createElement('option');
    optionPadrao.value = '';
    optionPadrao.textContent = 'Selecione uma matéria';
    optionPadrao.selected = true;
    optionPadrao.disabled = true;

    selectMateria.appendChild(optionPadrao);


    selectConteudo.disabled = true;
    selectConteudo.innerHTML = '';

    const optionConteudo = document.createElement('option');
    optionConteudo.value = '';
    optionConteudo.textContent = 'Selecione uma matéria primeiro.';
    optionConteudo.selected = true;
    optionConteudo.disabled = true;

    selectConteudo.appendChild(optionConteudo);


    curso.materias.forEach(materia => {

        const option = document.createElement('option');

        option.value = materia.id;
        option.textContent = materia.nome;

        selectMateria.appendChild(option);

    });

});



selectMateria.addEventListener('change', () => {

    const idCurso = Number(selectCurso.value);
    const curso = cursos.find(c => c.id === idCurso);

    if (!curso) {
        return;
    }

    const idMateria = Number(selectMateria.value);
    const materia = curso.materias.find(m => m.id === idMateria);

    if (!materia) {
        return;
    }

    console.log(materia);

    selectConteudo.disabled = false;

    selectConteudo.innerHTML = '';

    const optionPadrao = document.createElement('option');
    optionPadrao.value = '';
    optionPadrao.textContent = 'Selecione um conteúdo';
    optionPadrao.selected = true;
    optionPadrao.disabled = true;

    selectConteudo.appendChild(optionPadrao);

    materia.conteudos.forEach(conteudo => {

        const option = document.createElement('option');

        option.value = conteudo.id;
        option.textContent = conteudo.nome;

        selectConteudo.appendChild(option);

    });

}); 