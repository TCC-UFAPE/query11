import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

EXCEL_FILE = 'Relatorio_Analise_CVEs_LLM.xlsx'
OUT_DIR = 'charts'
os.makedirs(OUT_DIR, exist_ok=True)

# Ler todas as abas com header=1
xls = pd.read_excel(EXCEL_FILE, sheet_name=None, header=1, engine='openpyxl')

frames = []
for sheet_name, df in xls.items():
    df = df.copy()
    df['Modelo_Sheet'] = sheet_name
    frames.append(df)

all_df = pd.concat(frames, ignore_index=True, sort=False)
all_df.columns = [str(c).strip() for c in all_df.columns]

# detect columns
def find_column(columns, keywords):
    cols = list(columns)
    low = [c.lower() for c in cols]
    for kw in keywords:
        for i, c in enumerate(low):
            if kw in c:
                return cols[i]
    return None

cve_col = find_column(all_df.columns, ['cve'])
files_col = find_column(all_df.columns, ['arquivo', 'arquivos', 'file', 'files'])
vuln_col = find_column(all_df.columns, ['vulnerab', 'vulnerability', 'vuln'])

print('Colunas detectadas: CVE=', cve_col, 'Arquivos=', files_col, 'Vulnerab=', vuln_col)

if vuln_col is None:
    raise SystemExit('Coluna de vulnerabilidade não encontrada.')

# Normalize vulnerability column
all_df[vuln_col] = all_df[vuln_col].astype(str).str.upper().str.strip()

def normalize_vuln(x):
    if x in ('YES', 'Y', 'TRUE', 'SIM'):
        return 'YES'
    if x in ('NO', 'N', 'FALSE', 'NAO', 'NÃO'):
        return 'NO'
    if x.startswith('ERROR') or x == 'ERROR':
        return 'ERROR'
    if x in ('N/A', 'NA', 'N A', ''):
        return 'N/A'
    return x

all_df['Vuln_Normalizada'] = all_df[vuln_col].apply(normalize_vuln)

# Group
group = all_df.groupby(['Modelo_Sheet', 'Vuln_Normalizada']).size().reset_index(name='count')
pivot = group.pivot(index='Modelo_Sheet', columns='Vuln_Normalizada', values='count').fillna(0)

# Sort by total
pivot['total'] = pivot.sum(axis=1)
pivot = pivot.sort_values('total', ascending=False)

cols = [c for c in pivot.columns if c != 'total']
colors = sns.color_palette('tab10', n_colors=len(cols))

# 1) Stacked counts (maior e com rotação de rótulos)
fig_w = 20
fig_h = max(6, len(pivot) * 0.8)
plt.figure(figsize=(fig_w, fig_h), dpi=200)
ax = pivot[cols].plot(kind='bar', stacked=True, color=colors, width=0.75)
plt.title('LLM - Counts por status (empilhado)')
plt.ylabel('Quantidade')
plt.xlabel('Modelo LLM')
plt.xticks(rotation=45, ha='right')
plt.legend(title='Status', bbox_to_anchor=(1.02, 1), loc='upper left')
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, 'llm_stacked_counts.png'), bbox_inches='tight', dpi=200)
plt.close()

# 2) Stacked percentages (normalize rows)
pivot_pct = pivot.copy()
for col in cols:
    pivot_pct[col] = pivot_pct[col] / pivot_pct['total']

fig_w = 20
fig_h = max(6, len(pivot_pct) * 0.8)
plt.figure(figsize=(fig_w, fig_h), dpi=200)
ax = pivot_pct[cols].plot(kind='bar', stacked=True, color=colors, width=0.75)
plt.title('LLM - Percentual por status (empilhado)')
plt.ylabel('Proporção')
plt.xlabel('Modelo LLM')
plt.xticks(rotation=45, ha='right')
plt.legend(title='Status', bbox_to_anchor=(1.02, 1), loc='upper left')
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, 'llm_stacked_percent.png'), bbox_inches='tight', dpi=200)
plt.close()

# 3) Only YES/NO counts (filter columns)
yn_cols = [c for c in cols if c in ('YES','NO')]
if yn_cols:
    fig_w = 18
    fig_h = max(5, len(pivot) * 0.6)
    plt.figure(figsize=(fig_w, fig_h), dpi=200)
    ax = pivot[yn_cols].plot(kind='bar', stacked=False)
    plt.title('LLM - YES vs NO (counts)')
    plt.ylabel('Quantidade')
    plt.xlabel('Modelo LLM')
    plt.xticks(rotation=45, ha='right')
    plt.legend(title='Status', bbox_to_anchor=(1.02, 1), loc='upper left')
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, 'llm_yes_no_counts.png'), bbox_inches='tight', dpi=200)
    plt.close()
else:
    print('Nenhuma coluna YES/NO encontrada para o gráfico YES/NO.')

# 4) Heatmap (models x status) usando counts
heatmap_df = pivot[cols].copy()
# normalizar por linha para melhor visualização (opcional)
heatmap_norm = heatmap_df.div(heatmap_df.sum(axis=1).replace(0,1), axis=0)

fig_w = 18
fig_h = max(6, len(heatmap_norm) * 0.5)
plt.figure(figsize=(fig_w, fig_h), dpi=200)
sns.heatmap(heatmap_norm, annot=True, fmt='.2f', cmap='Blues', cbar_kws={'shrink':0.6})
plt.title('Heatmap: proporção de status por LLM')
plt.ylabel('Modelo LLM')
plt.xlabel('Status')
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, 'llm_heatmap_status.png'), bbox_inches='tight', dpi=200)
plt.close()

print('Gráficos gerados em:', OUT_DIR)
