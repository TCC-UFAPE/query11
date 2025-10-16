import os
import pandas as pd
import re
import requests
import time
from pathlib import Path

GITHUB_TOKEN = "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"
GITHUB_API_BASE = "https://api.github.com"
BASE_URL = "https://vulnerabilityhistory.org/api"


def get_github_headers():
    """Retorna headers para requisições ao GitHub"""
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'vuln-history-script/1.0'
    }
    if GITHUB_TOKEN:
        headers['Authorization'] = f'token {GITHUB_TOKEN}'
    return headers


def sanitize_folder_name(cve_name):
    """
    Sanitiza o nome do CVE para criar um nome de pasta válido
    Remove caracteres não permitidos em nomes de pastas do Windows
    """
    # Remove caracteres não permitidos: \ / : * ? " < > |
    sanitized = re.sub(r'[\\/:*?"<>|]', '_', cve_name)
    # Remove espaços extras e limita o tamanho
    sanitized = sanitized.strip()
    return sanitized


def sanitize_file_path(file_path):
    """
    Sanitiza o caminho do arquivo para criar uma estrutura válida no Windows
    """
    # Substitui caracteres inválidos
    sanitized = file_path.replace(':', '_').replace('*', '_').replace('?', '_')
    sanitized = sanitized.replace('"', '_').replace('<', '_').replace('>', '_')
    sanitized = sanitized.replace('|', '_')
    return sanitized


def get_commit_hashes_from_vulnerability(cve, session):
    """Extrai hashes de commits de uma vulnerabilidade específica através dos eventos"""
    try:
        events_response = session.get(f"{BASE_URL}/vulnerabilities/{cve}/events", timeout=30)
        events_response.raise_for_status()
        events = events_response.json()
        
        commit_hashes = []
        for event in events:
            event_type = event.get('event_type', '')
            if event_type in ['fix', 'vcc']:
                description = event.get('description', '')
                commit_match = re.search(r'/commits/([a-f0-9]{40})', description)
                if commit_match:
                    commit_hashes.append(commit_match.group(1))
        
        return commit_hashes
    except requests.exceptions.RequestException:
        return []


def get_github_commit_data(repo_full_name, commit_hash, session):
    """Busca dados completos do commit no GitHub via API REST"""
    try:
        headers = get_github_headers()
        url = f"{GITHUB_API_BASE}/repos/{repo_full_name}/commits/{commit_hash}"
        response = session.get(url, headers=headers, timeout=30)

        if response.status_code in [401, 403, 404, 422]:
            return None

        response.raise_for_status()
        data = response.json()

        if 'commit' not in data:
            return None

        return data

    except:
        return None


def download_file_from_github(repo_full_name, commit_hash, file_path, session):
    """
    Baixa o conteúdo de um arquivo específico de um commit do GitHub
    
    Args:
        repo_full_name: Nome completo do repositório (owner/repo)
        commit_hash: Hash do commit
        file_path: Caminho do arquivo no repositório
        session: Sessão de requests
        
    Returns:
        Conteúdo do arquivo ou None se houver erro
    """
    try:
        headers = get_github_headers()
        # URL para buscar o arquivo em um commit específico
        url = f"{GITHUB_API_BASE}/repos/{repo_full_name}/contents/{file_path}?ref={commit_hash}"
        response = session.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            # O conteúdo vem em base64
            import base64
            if 'content' in data:
                content = base64.b64decode(data['content']).decode('utf-8', errors='ignore')
                return content
        
        return None
    except:
        return None


def create_commit_files(cve_folder, repo_full_name, commit_hashes, session):
    """
    Cria arquivos modificados de cada commit dentro da pasta do CVE
    
    Args:
        cve_folder: Caminho da pasta do CVE
        repo_full_name: Nome completo do repositório GitHub
        commit_hashes: Lista de hashes dos commits
        session: Sessão de requests
    """
    if not repo_full_name or repo_full_name == 'N/A':
        return 0, 0
    
    total_files_created = 0
    total_commits_processed = 0
    
    for commit_idx, commit_hash in enumerate(commit_hashes, 1):
        print(f"      → Processando commit {commit_idx}/{len(commit_hashes)}: {commit_hash[:8]}...")
        
        # Buscar dados do commit
        commit_data = get_github_commit_data(repo_full_name, commit_hash, session)
        if not commit_data:
            print(f"        ✗ Não foi possível obter dados do commit")
            continue
        
        total_commits_processed += 1
        
        # Criar pasta para o commit
        commit_folder = os.path.join(cve_folder, f"commit_{commit_hash[:8]}")
        os.makedirs(commit_folder, exist_ok=True)
        
        # Obter lista de arquivos modificados
        files = commit_data.get('files', [])
        if not files:
            print(f"        - Nenhum arquivo modificado")
            continue
        
        print(f"        - {len(files)} arquivo(s) modificado(s)")
        
        # Criar um arquivo com informações do commit
        commit_info_path = os.path.join(commit_folder, "_commit_info.txt")
        with open(commit_info_path, 'w', encoding='utf-8') as f:
            commit_obj = commit_data.get('commit', {})
            f.write(f"Commit: {commit_hash}\n")
            f.write(f"URL: {commit_data.get('html_url', 'N/A')}\n")
            f.write(f"Autor: {commit_obj.get('author', {}).get('name', 'N/A')}\n")
            f.write(f"Data: {commit_obj.get('author', {}).get('date', 'N/A')}\n")
            f.write(f"Mensagem: {commit_obj.get('message', 'N/A')}\n")
            f.write(f"\nEstatísticas:\n")
            stats = commit_data.get('stats', {})
            f.write(f"  - Adições: {stats.get('additions', 0)}\n")
            f.write(f"  - Deleções: {stats.get('deletions', 0)}\n")
            f.write(f"  - Total: {stats.get('total', 0)}\n")
            f.write(f"\nArquivos modificados:\n")
            for file_info in files:
                f.write(f"  - {file_info.get('filename', 'N/A')} ({file_info.get('status', 'N/A')})\n")
        
        # Baixar cada arquivo modificado
        for file_info in files:
            file_path = file_info.get('filename', '')
            if not file_path:
                continue
            
            # Criar estrutura de pastas para o arquivo
            sanitized_path = sanitize_file_path(file_path)
            full_file_path = os.path.join(commit_folder, sanitized_path)
            
            # Criar diretórios necessários
            os.makedirs(os.path.dirname(full_file_path), exist_ok=True)
            
            # Baixar conteúdo do arquivo
            file_content = download_file_from_github(repo_full_name, commit_hash, file_path, session)
            
            if file_content:
                with open(full_file_path, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(file_content)
                total_files_created += 1
            
            # Salvar o diff/patch do arquivo
            patch = file_info.get('patch', '')
            if patch:
                patch_file_path = full_file_path + ".patch"
                with open(patch_file_path, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(f"Arquivo: {file_path}\n")
                    f.write(f"Status: {file_info.get('status', 'N/A')}\n")
                    f.write(f"Adições: {file_info.get('additions', 0)}\n")
                    f.write(f"Deleções: {file_info.get('deletions', 0)}\n")
                    f.write(f"Mudanças: {file_info.get('changes', 0)}\n")
                    f.write(f"\n{'='*60}\n")
                    f.write(f"DIFF:\n")
                    f.write(f"{'='*60}\n\n")
                    f.write(patch)
            
            # Pequena pausa para não sobrecarregar a API
            time.sleep(0.1)
        
        # Pausa entre commits
        time.sleep(0.3)
    
    return total_commits_processed, total_files_created


def create_cve_folders_from_excel(excel_file="5_analise_completa_tokens.xlsx", base_folder="CVEs", download_files=True):
    """
    Lê o arquivo Excel e cria uma pasta para cada CVE encontrado
    Também baixa os arquivos modificados de cada commit relacionado
    
    Args:
        excel_file: Nome do arquivo Excel a ser analisado
        base_folder: Nome da pasta base onde as pastas dos CVEs serão criadas
        download_files: Se True, baixa os arquivos modificados dos commits
    """
    
    # Verificar se o arquivo Excel existe
    if not os.path.exists(excel_file):
        print(f"[ERRO] Arquivo '{excel_file}' não encontrado!")
        print(f"   Certifique-se de que o arquivo está no diretório atual: {os.getcwd()}")
        return
    
    print(f"\n=== Analisando arquivo: {excel_file} ===\n")
    
    try:
        # Ler o arquivo Excel
        df = pd.read_excel(excel_file)
        print(f"-> Arquivo carregado com sucesso!")
        print(f"-> Total de linhas: {len(df)}")
        print(f"-> Colunas disponíveis: {list(df.columns)}\n")
        
        # Verificar se a coluna CVE existe
        if 'CVE' not in df.columns:
            print("[ERRO] Coluna 'CVE' não encontrada no arquivo!")
            print(f"   Colunas disponíveis: {list(df.columns)}")
            return
        
        # Criar pasta base se não existir
        if not os.path.exists(base_folder):
            os.makedirs(base_folder)
            print(f"-> Pasta base '{base_folder}' criada.\n")
        else:
            print(f"-> Pasta base '{base_folder}' já existe.\n")
        
        # Obter lista de CVEs únicos
        cves = df['CVE'].dropna().unique()
        print(f"-> {len(cves)} CVEs únicos encontrados.\n")
        
        if download_files:
            print("-> Download de arquivos modificados: ATIVADO\n")
        else:
            print("-> Download de arquivos modificados: DESATIVADO\n")
        
        print("=== Criando pastas para cada CVE ===\n")
        
        # Criar sessão HTTP
        session = requests.Session()
        
        created_folders = 0
        existing_folders = 0
        errors = []
        total_commits = 0
        total_files = 0
        
        # Criar uma pasta para cada CVE
        for idx, cve in enumerate(cves, 1):
            try:
                # Sanitizar o nome do CVE
                folder_name = sanitize_folder_name(str(cve))
                folder_path = os.path.join(base_folder, folder_name)
                
                # Criar a pasta se não existir
                if not os.path.exists(folder_path):
                    os.makedirs(folder_path)
                    created_folders += 1
                    print(f"   [{idx}/{len(cves)}] ✓ Criada: {folder_name}")
                else:
                    existing_folders += 1
                    print(f"   [{idx}/{len(cves)}] - Já existe: {folder_name}")
                    
                # Criar um arquivo README dentro da pasta com informações do CVE
                create_readme_for_cve(df, cve, folder_path)
                
                # Baixar arquivos modificados dos commits, se solicitado
                if download_files:
                    # Buscar repositório do CVE
                    cve_data = df[df['CVE'] == cve].iloc[0]
                    repo_full_name = cve_data.get('Repositório GitHub', 'N/A')
                    
                    if repo_full_name and repo_full_name != 'N/A':
                        print(f"      Buscando commits do repositório: {repo_full_name}")
                        
                        # Buscar commits relacionados ao CVE
                        commit_hashes = get_commit_hashes_from_vulnerability(cve, session)
                        
                        if commit_hashes:
                            print(f"      Encontrados {len(commit_hashes)} commit(s)")
                            commits_processed, files_created = create_commit_files(
                                folder_path, repo_full_name, commit_hashes, session
                            )
                            total_commits += commits_processed
                            total_files += files_created
                            print(f"      ✓ {commits_processed} commit(s) processado(s), {files_created} arquivo(s) criado(s)")
                        else:
                            print(f"      - Nenhum commit encontrado")
                    else:
                        print(f"      - Sem repositório GitHub associado")
                    
            except Exception as e:
                errors.append((cve, str(e)))
                print(f"   [{idx}/{len(cves)}] ✗ ERRO ao criar pasta para {cve}: {e}")
        
        # Resumo final
        print("\n" + "="*60)
        print("=== RESUMO DA CRIAÇÃO DE PASTAS E ARQUIVOS ===")
        print("="*60)
        print(f"   Total de CVEs processados: {len(cves)}")
        print(f"   Pastas criadas: {created_folders}")
        print(f"   Pastas já existentes: {existing_folders}")
        
        if download_files:
            print(f"   Total de commits processados: {total_commits}")
            print(f"   Total de arquivos baixados: {total_files}")
        
        print(f"   Erros: {len(errors)}")
        
        if errors:
            print("\n--- Erros Encontrados ---")
            for cve, error in errors:
                print(f"   • {cve}: {error}")
        
        print("\n[SUCESSO] Processo concluído!")
        print(f"   As pastas foram criadas em: {os.path.abspath(base_folder)}")
        
    except Exception as e:
        print(f"\n[ERRO FATAL] Erro ao processar o arquivo: {e}")


def create_readme_for_cve(df, cve, folder_path):
    """
    Cria um arquivo README.md com informações sobre o CVE dentro da pasta
    
    Args:
        df: DataFrame com os dados do Excel
        cve: Identificador do CVE
        folder_path: Caminho da pasta onde o README será criado
    """
    try:
        # Filtrar dados do CVE específico
        cve_data = df[df['CVE'] == cve].iloc[0]
        
        readme_path = os.path.join(folder_path, "README.md")
        
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(f"# {cve}\n\n")
            f.write(f"## Informações Gerais\n\n")
            
            # Escrever todas as informações disponíveis
            for column in df.columns:
                if column != 'CVE':
                    value = cve_data.get(column, 'N/A')
                    f.write(f"**{column}:** {value}\n\n")
            
            f.write(f"\n---\n\n")
            f.write(f"*Dados extraídos de: 5_analise_completa_tokens.xlsx*\n")
            
    except Exception as e:
        # Se houver erro, não impede a criação da pasta
        pass


def main():
    """Função principal"""
    print("="*60)
    print("  CRIADOR DE PASTAS PARA CVEs")
    print("  Baseado no arquivo: 5_analise_completa_tokens.xlsx")
    print("="*60)
    
    # Verificar se estamos no diretório correto
    current_dir = os.getcwd()
    print(f"\nDiretório atual: {current_dir}")
    
    # Criar as pastas
    create_cve_folders_from_excel()
    
    print("\n" + "="*60)


if __name__ == "__main__":
    main()
