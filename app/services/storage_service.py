from werkzeug.utils import secure_filename
import cloudinary.uploader

from app.utils.upload import validar_arquivo

def upload_arquivo(arquivo):
    #---- arquivo e validação ---- 
            
        valido, resultado = validar_arquivo(arquivo)

        if not valido:
            raise ValueError(resultado)

        response = cloudinary.uploader.upload(arquivo,
                                            folder = 'atividades',
                                            unique_filename = True,
                                            overwrite = True,
                                            )
        return {
              'secure_url': response.get('secure_url'),
              'public_id': response.get('public_id'),
              'nome': secure_filename(arquivo.filename),
              'tipo': arquivo.mimetype,
              'tamanho': resultado
        }



def delete_cloudinary(public_id):
        cloudinary.uploader.destroy(public_id)