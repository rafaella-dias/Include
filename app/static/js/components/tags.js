const chips = document.querySelectorAll('.tag-chip')
const selectTags = document.getElementById('tagsForm')

chips.forEach(chip => {
    chip.addEventListener('click', () => {

        chip.classList.toggle('active')
            
        const tagId = chip.dataset.tagId
        const option = selectTags.querySelector(
            `option[value='${tagId}']`
        )

        option.selected = chip.classList.contains('active')
    })
})