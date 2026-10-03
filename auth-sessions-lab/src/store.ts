// Armazenamento em memória para o exemplo ficar simples de rodar.
// Num sistema real seriam duas tabelas no banco; a lógica do auth.ts não muda.

export interface User {
  id: string;
  email: string;
  passwordHash: string;
}

export interface Session {
  tokenHash: string;
  userId: string;
  expiresAt: Date;
}

export class MemoryStore {
  private users = new Map<string, User>();
  private sessions = new Map<string, Session>();

  findUserByEmail(email: string): User | undefined {
    for (const user of this.users.values()) {
      if (user.email === email) return user;
    }
    return undefined;
  }

  findUserById(id: string): User | undefined {
    return this.users.get(id);
  }

  saveUser(user: User): void {
    this.users.set(user.id, user);
  }

  saveSession(session: Session): void {
    this.sessions.set(session.tokenHash, session);
  }

  findSession(tokenHash: string): Session | undefined {
    return this.sessions.get(tokenHash);
  }

  deleteSession(tokenHash: string): void {
    this.sessions.delete(tokenHash);
  }

  deleteSessionsOfUser(userId: string): number {
    let removidas = 0;
    for (const [hash, session] of this.sessions) {
      if (session.userId === userId) {
        this.sessions.delete(hash);
        removidas++;
      }
    }
    return removidas;
  }

  countSessionsOfUser(userId: string): number {
    let total = 0;
    for (const session of this.sessions.values()) {
      if (session.userId === userId) total++;
    }
    return total;
  }
}
