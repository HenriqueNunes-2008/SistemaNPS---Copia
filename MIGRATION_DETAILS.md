# Detalhes da Migração: Supabase para PostgreSQL (Magalu Cloud)

## Alterações Realizadas
- **ORM**: Implementação do SQLAlchemy para substituir o cliente SDK do Supabase.
- **Modelos**: Criação de `app/models.py` mapeando as tabelas físicas.
    - **Ressalvas**: O modelo `RessalvaItem` foi expandido para incluir campos como `prazo` (agora do tipo `Date`), `responsavel`, `observacao`, `aprovacao`, `imagem_hash` e `criado_em` para detalhamento das ressalvas.
- **Banco**: Utilização de `JSONB` no PostgreSQL para compatibilidade com dados dinâmicos de NPS.
- **Serialização de Datas**: Implementada a conversão de objetos `datetime.date` para strings ISO (`YYYY-MM-DD`) ao salvar dados em colunas `JSONB` para evitar erros de serialização.
- **Segurança**: Adicionado status `pendente` no cadastro de usuários. O acesso só é liberado após o administrador alterar o status para `ativo` no banco ou painel.
- **Storage**: Migrado do Supabase Storage para armazenamento local em `app/static/uploads/`, compatível com Magalu Cloud.

## Atualização do Esquema do Banco de Dados (Pós-Migração)
Após a migração inicial, se novas colunas forem adicionadas aos modelos SQLAlchemy, o `Base.metadata.create_all()` não as adicionará automaticamente em tabelas já existentes. Para aplicar as alterações no esquema do banco de dados, execute o seguinte comando SQL diretamente no seu cliente PostgreSQL (ex: DBeaver, pgAdmin, ou terminal):

```sql
ALTER TABLE ressalvas_itens
ADD COLUMN IF NOT EXISTS prazo DATE,
ADD COLUMN IF NOT EXISTS responsavel TEXT,
ADD COLUMN IF NOT EXISTS observacao TEXT,
ADD COLUMN IF NOT EXISTS aprovacao BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS imagem_hash TEXT,
ADD COLUMN IF NOT EXISTS criado_em TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;
```

## Configurações na Magalu Cloud
1. No console da Magalu Cloud, crie uma instância Ubuntu.
2. Instale o PostgreSQL ou utilize o serviço de banco gerenciado.
3. Configure a variável de ambiente `DATABASE_URL` no seu servidor.
4. **Importante**: Crie a pasta `app/static/uploads` e garanta permissão de escrita (`chmod 775`).

## Como aprovar um usuário manualmente
Execute no SQL do banco:
```sql
UPDATE perfis SET status = 'ativo' WHERE email = 'email@usuario.com';
```