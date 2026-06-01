# Daniê Perfumaria — Backend + Frontend

## Estrutura

```
danie/
├── server.js          # Backend Node.js + Express
├── db.json            # Banco de dados (JSON)
├── package.json
└── public/
    └── index.html     # Frontend (servido pelo próprio backend)
```

## Instalação

```bash
# 1. Entrar na pasta
cd danie

# 2. Instalar dependências (apenas na primeira vez)
npm install

# 3. Iniciar o servidor
node server.js
```

O site estará disponível em: **http://localhost:3000**

---

## Credenciais

| Perfil         | E-mail              | Senha     |
|----------------|---------------------|-----------|
| Administradora | admin@danie.com     | admin123  |

Clientes se cadastram pelo próprio site.

---

## O que cada parte faz

### Backend (server.js)
- Autentica usuários com **bcrypt** (senhas nunca ficam em texto puro)
- Emite **JWT** com validade de 8h para sessão
- Protege rotas de admin com middleware — cliente comum não consegue criar/editar/excluir produtos mesmo tentando via DevTools
- Salva tudo em `db.json` (sem banco de dados externo necessário)

### Frontend (public/index.html)
- Nunca recebe lista de usuários ou senhas
- Armazena apenas o token JWT no localStorage
- Todas as operações de escrita passam pela API com validação de token

---

## Endpoints da API

| Método | Rota                  | Acesso       | Descrição                  |
|--------|-----------------------|--------------|----------------------------|
| POST   | /api/auth/login       | Público      | Login, retorna JWT         |
| POST   | /api/auth/register    | Público      | Cadastro de cliente        |
| GET    | /api/auth/me          | Autenticado  | Valida token ativo         |
| GET    | /api/products         | Público      | Lista produtos             |
| POST   | /api/products         | Admin        | Cria produto               |
| PUT    | /api/products/:id     | Admin        | Edita produto              |
| DELETE | /api/products/:id     | Admin        | Remove produto             |

---

## Para hospedar (Render.com — gratuito)

1. Criar conta em https://render.com
2. New → Web Service → conectar repositório GitHub com este código
3. Build command: `npm install`
4. Start command: `node server.js`
5. Pronto — URL pública gerada automaticamente
