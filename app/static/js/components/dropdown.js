/* 
<button class="btn-menu" id="btn-menu">⋮</button>

    <div class="dropdown" id="dropdown">
        <a href="#">Baixar</a>
        <a href="#">Favoritar</a>

        {% if current_user.id_usuario == atividade.autor.id_usuario %}
            <a href="#">Editar</a>
            <a href="#" class="danger">Excluir</a>
                            
            {% endif %}

    </div> 
*/

const btnMenu = document.getElementById('btn-menu')
const dropdown = document.getElementById('dropdown')

if (btnMenu && dropdown) {

    btnMenu.addEventListener('click', (event) => {
        event.stopPropagation()

        dropdown.classList.toggle('show')
    })

    document.addEventListener('click', () => {
        dropdown.classList.remove('show')
    })
}