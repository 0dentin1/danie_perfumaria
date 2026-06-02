# Souvenir Perfumes

Loja de fragrâncias árabes e europeias — Maringá, PR.

## Stack

- **Frontend:** HTML/CSS/JS vanilla (SPA via innerHTML)
- **Backend:** Node.js + Express 5
- **Banco de dados:** MongoDB Atlas (Mongoose)
- **Deploy:** Vercel (serverless)
- **Domínio:** souvenirperfumes.com.br

## Instalação local

```bash
npm install
```

Crie o arquivo `.env` na raiz com as variáveis:

```
MONGODB_URI=mongodb+srv://...
JWT_SECRET=...
```

```bash
node server.js
```

O site estará em: **http://localhost:3000**

## Endpoints da API

| Método | Rota                       | Acesso      | Descrição                |
|--------|----------------------------|-------------|--------------------------|
| POST   | /api/auth/login            | Público     | Login, retorna JWT       |
| POST   | /api/auth/register         | Público     | Cadastro de cliente      |
| GET    | /api/auth/me               | Autenticado | Valida token ativo       |
| GET    | /api/products              | Público     | Lista produtos           |
| POST   | /api/products              | Admin       | Cria produto             |
| PUT    | /api/products/:id          | Admin       | Edita produto            |
| DELETE | /api/products/:id          | Admin       | Remove produto           |
| GET    | /api/user/data             | Autenticado | Exporta dados (LGPD)     |
| DELETE | /api/user/account          | Autenticado | Exclui conta (LGPD)      |
| POST   | /api/legal/consent/cookies | Público     | Registra consentimento   |
| GET    | /api/legal/privacy-policy  | Público     | Política de privacidade  |
| GET    | /api/legal/cookie-policy   | Público     | Política de cookies      |

## Variáveis de ambiente (Vercel)

Configure em Settings → Environment Variables:

- `MONGODB_URI` — string de conexão do MongoDB Atlas
- `JWT_SECRET` — segredo para assinar tokens JWT

Nunca commitar o `.env` no repositório.
