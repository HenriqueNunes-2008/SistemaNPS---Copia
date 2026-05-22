# Detalhes da Migração: Supabase para PostgreSQL (Magalu Cloud)

## Alterações Realizadas
- **ORM**: Implementação do SQLAlchemy para substituir o cliente SDK do Supabase.
- **Modelos**: Criação de `app/models.py` mapeando as tabelas físicas.
- **Banco**: Utilização de `JSONB` no PostgreSQL para compatibilidade com dados dinâmicos de NPS.
- **Segurança**: Adicionado status `pendente` no cadastro de usuários. O acesso só é liberado após o administrador alterar o status para `ativo` no banco ou painel.
- **Storage**: Migrado do Supabase Storage para armazenamento local em `app/static/uploads/`, compatível com Magalu Cloud.

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