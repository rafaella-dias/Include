/* ELEMENTOS */

const form = document.querySelector('form')

const inputArquivos = document.getElementById('arquivosForm')
const listaArquivos = document.getElementById('lista-arquivos')
const erroUpload = document.getElementById('uploadErro')

let arquivosSelecionados = []


/* EVENTOS */

inputArquivos.addEventListener('change', () => {

    erroUpload.textContent = ''

    const novosArquivos = Array.from(inputArquivos.files)

    novosArquivos.forEach(novoArquivo => {

        const jaExiste = arquivosSelecionados.some(arquivo =>
            arquivo.name === novoArquivo.name &&
            arquivo.size === novoArquivo.size
        )

        if (!jaExiste) {
            arquivosSelecionados.push(novoArquivo)
        }

    })

    atualizarInputFiles()
    renderizarArquivos()

})


form.addEventListener('submit', (event) => {

    if (arquivosSelecionados.length === 0) {

        event.preventDefault()

        erroUpload.textContent = 'Selecione pelo menos um arquivo.'

        return

    }

    erroUpload.textContent = ''

})


/* FUNÇÕES */

function renderizarArquivos() {

    listaArquivos.innerHTML = ''

    arquivosSelecionados.forEach((arquivo, index) => {

        const item = document.createElement('div')
        item.classList.add('upload-arquivo-item')

        const tamanhoKB = (arquivo.size / 1024).toFixed(1)

        item.innerHTML = `
            <div class="upload-arquivo-info">

                <div class="upload-arquivo-icon">
                    📄
                </div>

                <div class="upload-arquivo-textos">

                    <span class="upload-arquivo-nome">
                        ${arquivo.name}
                    </span>

                    <span class="upload-arquivo-tamanho">
                        ${tamanhoKB} KB
                    </span>

                </div>

            </div>

            <button
                type="button"
                class="upload-remover-btn"
                onclick="removerArquivos(${index})">
                ✕
            </button>
        `

        listaArquivos.appendChild(item)

    })

}


function removerArquivos(index) {

    arquivosSelecionados.splice(index, 1)

    atualizarInputFiles()
    renderizarArquivos()

    if (arquivosSelecionados.length > 0) {
        erroUpload.textContent = ''
    }

}


function atualizarInputFiles() {

    const dataTransfer = new DataTransfer()

    arquivosSelecionados.forEach(arquivo => {
        dataTransfer.items.add(arquivo)
    })

    inputArquivos.files = dataTransfer.files

}