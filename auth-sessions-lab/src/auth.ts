import { createHash, randomBytes, randomUUID } from "node:crypto";
import argon2 from "argon2";
import type { MemoryStore, User } from "./store.js";

export const SESSION_DAYS = 7;
const MIN_PASSWORD = 10;

export class AuthError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

// O token vai para o navegador; no armazenamento fica só o SHA-256 dele.
// Se alguém copiar a tabela de sessões, não consegue usar nenhuma.
export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function checkPassword(password: string): void {
  if (password.length < MIN_PASSWORD) {
    throw new AuthError(`A senha precisa ter pelo menos ${MIN_PASSWORD} caracteres`, 400);
  }
}

export class AuthService {
  // Hash calculado uma vez, usado quando o e-mail não existe (ver login).
  private dummyHash: Promise<string>;

  constructor(
    private readonly store: MemoryStore,
    private readonly now: () => Date = () => new Date(),
  ) {
    this.dummyHash = argon2.hash("senha-que-nao-existe-de-ninguem");
  }

  async register(email: string, password: string): Promise<User> {
    const normalized = normalizeEmail(email);
    if (!normalized.includes("@")) throw new AuthError("E-mail inválido", 400);
    checkPassword(password);
    if (this.store.findUserByEmail(normalized)) throw new AuthError("E-mail já cadastrado", 409);

    const user: User = {
      id: randomUUID(),
      email: normalized,
      passwordHash: await argon2.hash(password, { type: argon2.argon2id }),
    };
    this.store.saveUser(user);
    return user;
  }

  /** Devolve o token da sessão nova. Mesma mensagem para e-mail inexistente e senha errada. */
  async login(email: string, password: string): Promise<string> {
    const user = this.store.findUserByEmail(normalizeEmail(email));
    // Mesmo sem usuário, roda um verify: assim o tempo de resposta não
    // entrega se o e-mail está cadastrado ou não.
    const ok = await argon2.verify(user?.passwordHash ?? (await this.dummyHash), password);
    if (!user || !ok) throw new AuthError("E-mail ou senha incorretos", 401);
    return this.createSession(user.id);
  }

  createSession(userId: string): string {
    const token = randomBytes(32).toString("base64url");
    const expiresAt = new Date(this.now().getTime() + SESSION_DAYS * 24 * 60 * 60 * 1000);
    this.store.saveSession({ tokenHash: hashToken(token), userId, expiresAt });
    return token;
  }

  /** Usuário dono do token, ou undefined se o token não existe ou venceu. */
  authenticate(token: string | undefined): User | undefined {
    if (!token) return undefined;
    const tokenHash = hashToken(token);
    const session = this.store.findSession(tokenHash);
    if (!session) return undefined;
    if (session.expiresAt <= this.now()) {
      this.store.deleteSession(tokenHash);
      return undefined;
    }
    return this.store.findUserById(session.userId);
  }

  logout(token: string | undefined): void {
    if (token) this.store.deleteSession(hashToken(token));
  }

  /**
   * Troca a senha e derruba TODAS as sessões do usuário, inclusive em outros
   * aparelhos. Se a senha foi trocada porque vazou, quem estava usando a
   * conta perde o acesso na hora. Devolve um token novo para quem trocou.
   */
  async changePassword(user: User, currentPassword: string, newPassword: string): Promise<string> {
    if (!(await argon2.verify(user.passwordHash, currentPassword))) {
      throw new AuthError("Senha atual incorreta", 401);
    }
    checkPassword(newPassword);
    user.passwordHash = await argon2.hash(newPassword, { type: argon2.argon2id });
    this.store.saveUser(user);
    this.store.deleteSessionsOfUser(user.id);
    return this.createSession(user.id);
  }
}
