import yara
import os
import git
from git import Repo
import glob
import shutil
import fnmatch


folder = os.path.dirname(os.path.abspath(__file__))
namespace = os.path.join(folder, 'all_rules', 'rules_compiled')
repos_folder = '/home/Desktop/yara_automatico/Repos/'

def clone_pull (dst, path):
    if os.path.isdir(dst):       
            print(dst,':Comprobando si hay cambios recientes y actualizando')
            repo = Repo(dst) 
            repo.remotes.origin.pull()
    else:                           
            print('Clonando repositorio')
            repo = Repo.clone_from(path, dst)
            

def copyfiles(src, dst):
    for root, dirs, files in os.walk(repos_folder):
        for filename in files:
            if ('.yara' in filename or '.yar' in filename):
                try:
                    shutil.copy(os.path.join(root, filename), os.path.join(dst, filename))
                except shutil.SameFileError:
                    pass
                
                for file in glob.glob(dst):
                    basename, ext = os.path.splitext(filename)
                 
                    if ext == '.yara':
                        ext = ext.replace('.yara', '.yar')
                        new_file = basename + ext

                        old_path = os.path.join(dst, filename)
                        new_path = os.path.join(dst, new_file)
                        os.rename(old_path, new_path)
            

def compile(filepaths, dst):
    namespace = dict()
    for file in filepaths:
        for filename in glob.glob('/home/Desktop/yara_automatico/all_rules/*.yar'):
            name = os.path.basename(os.path.splitext(filename)[0])
            namespace[name] = filename
     
        rules = yara.compile(filepaths = namespace)
        if os.path.exists(dst):
             os.remove(dst)
        rules.save(dst)   



# Actualizar o clonar repositorios de reglas Yara:

# 1. Crear carpetas de los repositorios
cape_repo = os.path.join(os.path.abspath(repos_folder), 'cape_repo')
#yara_rules_repo = os.path.join(os.path.abspath(repos_test_folder), 'yara_rules_repo')
malice_repo = os.path.join(os.path.abspath(repos_folder), 'malice_repo')
#open_source_repo = os.path.join(os.path.abspath(repos_folder), 'open_source_repo')
#bartblaze_repo = os.path.join(os.path.abspath(repos_test_folder), 'bartblaze_repo')
#florian_roth_repo = os.path.join(os.path.abspath(repos_test_folder), 'florian_roth__repo')
#h3x2b_repo = os.path.join(os.path.abspath(repos_test_folder), 'h3x2b_repo')
#intezer_repo = os.path.join(os.path.abspath(repos_test_folder), 'intezer_repo')
jeFF0Falltrades_repo = os.path.join(os.path.abspath(repos_folder), 'jeFF0Falltrades_repo')
malpedia_repo = os.path.join(os.path.abspath(repos_folder), 'malpedia_repo')
mcafee_repo = os.path.join(os.path.abspath(repos_folder), 'mcafee_repo')



# 2. Clonar o actualizar repositorios

clone_pull(dst=cape_repo, path='https://github.com/kevoreilly/CAPEv2.git')
#clone_pull(dst=yara_rules_repo, path='https://github.com/Yara-Rules/rules.git')
clone_pull(dst=malice_repo, path='https://github.com/malice-plugins/yara.git')
#clone_pull(dst=open_source_repo, path='https://github.com/mikesxrs/Open-Source-YARA-rules.git')
#clone_pull(dst=bartblaze_repo, path='https://github.com/bartblaze/Yara-rules.git')
#clone_pull(dst=florian_roth_repo, path = 'https://github.com/Neo23x0/signature-base.git')
#clone_pull(dst=h3x2b_repo, path='https://github.com/h3x2b/yara-rules.git')
#clone_pull(dst=intezer_repo, path='https://github.com/intezer/yara-rules.git')
clone_pull(dst=jeFF0Falltrades_repo, path='https://github.com/jeFF0Falltrades/YARA-Signatures.git')
clone_pull(dst=malpedia_repo, path='https://github.com/malpedia/signator-rules.git')
clone_pull(dst=mcafee_repo, path='https://github.com/advanced-threat-research/Yara-Rules.git')

#Crear carpeta donde almacenar todas las reglas Yara de todos los repositorios

os.makedirs('all_rules', exist_ok=True)
all_rules_folder = os.path.join(folder + '/all_rules')


#Copiar todas las reglas Yara de todos los repositorios a la carpeta creada y convertir los ficheros con extension .yara en .yar

copyfiles(src=repos_folder, dst=all_rules_folder)


#Compilar todas las reglas en un solo fichero dentro de la carpeta all_rules

compile(filepaths=all_rules_folder, dst=namespace)

# Matchear varias muestras de malware almacenadas en la misma carpeta 

malware_folder = r'/home/Desktop/yara_automatico/malware'
filepaths = [os.path.join(malware_folder, name) for name in os.listdir(malware_folder)]
rules = yara.load('/home/Desktop/yara_automatico/all_rules/rules_compiled')

for file in filepaths:
    with open(file, 'rb') as f:
        matches = rules.match(data=f.read())
        print(file, ':', matches)
