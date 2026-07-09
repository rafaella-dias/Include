import uuid
from werkzeug.utils import secure_filename
import cloudinary.uploader
from app.extensions import supabase
from app.utils import upload



def upload_arquivo(arquivo):
    #---- arquivo e validação ---- 
            
        valido, resultado = upload.validar_arquivo(arquivo)

        if not valido:
            raise ValueError(resultado)
        
        nome_seguro = secure_filename(arquivo.filename)
        nome_unico = f'{uuid.uuid4()}_{nome_seguro}'
        conteudo = arquivo.read()

        response = supabase.storage.from_('include-arquivos').upload(
              path=nome_unico, 
              file=conteudo,
              file_options={'content-type': arquivo.mimetype}
              )

        url_publica = supabase.storage.from_('include-arquivos').get_public_url(response.path)

        return {
            'nome': nome_seguro,
            'nome_unico': nome_unico,
            'tipo': arquivo.mimetype,
            'tamanho': resultado,
            'arquivo_url': url_publica,
            'storage_path': response.path
            }



def delete_arquivo(storage_path):
      supabase.storage.from_('include-arquivos').remove([storage_path])



def upload_imagem(arquivo):#---- imagem e validação ----
        valido, resultado = upload.validar_imagem(arquivo)

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