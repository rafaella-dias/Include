document.addEventListener('DOMContentLoaded', () => {
    const alerts = document.querySelectorAll('.alert.auto-dismiss');
    alerts.forEach(alert => {
        alert.addEventListener('animationend', () => {
            alert.remove();
            const container = document.querySelector('.alert-container');
            if(container && container.children.length === 0){
                container.remove(); 
            }
        });
    });
});
