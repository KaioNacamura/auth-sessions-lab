# auth-sessions-lab

Login com senha em Argon2 e sessão por cookie, com os cuidados que costumam ficar para depois. O principal: **trocar a senha derruba a sessão em todos os aparelhos**.

Esse último ponto veio de uma auditoria que fiz num sistema real: depois de trocar a senha, as sessões antigas continuavam valendo. Se a senha foi trocada porque vazou, quem estava usando a conta continuava dentro. Aqui o problema está resolvido e coberto por teste.

## O que está implementado

| Cuidado | Como |
| --- | --- |
| Senha | Argon2id. O banco guarda só o hash. |
| Senha mínima | 10 caracteres. |
| Token de sessão | 32 bytes aleatórios. O navegador recebe o token e o armazenamento guarda só o SHA-256 dele: quem copiar a tabela de sessões não consegue entrar. |
| Cookie | `HttpOnly` (o JavaScript da página não lê), `SameSite=Lax` (não vai junto em POST de outro site) e `Secure` em produção. |
| Validade | Sessão vence em 7 dias. Sessão vencida é apagada quando alguém tenta usar. |
| Login | E-mail inexistente e senha errada recebem a mesma mensagem. Mesmo sem usuário, roda um `verify` do Argon2 para o tempo de resposta não entregar se o e-mail existe. |
| Troca de senha | Pede a senha atual, apaga **todas** as sessões do usuário e cria uma nova só para quem trocou. |
| Logout | Apaga a sessão no servidor, não só o cookie. |

## Rotas

| Método | Rota | O que faz |
| --- | --- | --- |
| POST | `/register` | `{ email, password }` cria a conta |
| POST | `/login` | `{ email, password }` cria a sessão e devolve o cookie |
| GET | `/me` | mostra o usuário logado |
| POST | `/change-password` | `{ currentPassword, newPassword }` |
| POST | `/logout` | encerra a sessão |

## Rodando

Precisa de Node 20 ou mais novo.

```bash
npm install
npm start
```

Sobe em `http://localhost:3001`. Para testar no terminal (Git Bash):

```bash
curl -c cookies.txt -H "Content-Type: application/json" \
  -d '{"email":"ana@exemplo.com","password":"senha-boa-123"}' http://localhost:3001/register
curl -c cookies.txt -H "Content-Type: application/json" \
  -d '{"email":"ana@exemplo.com","password":"senha-boa-123"}' http://localhost:3001/login
curl -b cookies.txt http://localhost:3001/me
```

## Testes

```bash
npm test
```

São 11 testes com Vitest e Supertest. O mais importante abre duas sessões (celular e notebook), troca a senha pelo notebook e confere que as duas sessões antigas param de funcionar e só a nova continua valendo.

Para conferir que esse teste pega o problema de verdade, apaguei a linha que derruba as sessões e rodei de novo: o teste falhou. Voltei a linha e ele passou.

## Limites

- Os usuários e as sessões ficam em memória para o exemplo rodar sem banco. Num sistema real seriam duas tabelas; a lógica de `src/auth.ts` não muda.
- Não tem limite de tentativas de login. Em produção precisaria, por IP e por e-mail.
