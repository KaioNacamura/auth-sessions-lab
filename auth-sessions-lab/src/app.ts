import express, { type NextFunction, type Request, type Response } from "express";
import { AuthError, AuthService, SESSION_DAYS } from "./auth.js";
import { MemoryStore } from "./store.js";

const COOKIE = "sid";

function readCookie(req: Request, name: string): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return undefined;
}

export function createApp(auth = new AuthService(new MemoryStore())) {
  const app = express();
  app.use(express.json({ limit: "10kb" }));

  const secure = process.env.NODE_ENV === "production";

  function setSessionCookie(res: Response, token: string) {
    res.cookie(COOKIE, token, {
      httpOnly: true, // JavaScript da página não lê o cookie
      sameSite: "lax", // não vai junto em POST vindo de outro site
      secure, // só por HTTPS em produção
      maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000,
      path: "/",
    });
  }

  function requireUser(req: Request, res: Response, next: NextFunction) {
    const user = auth.authenticate(readCookie(req, COOKIE));
    if (!user) {
      res.status(401).json({ error: "Faça login" });
      return;
    }
    res.locals.user = user;
    next();
  }

  app.post("/register", async (req, res, next) => {
    try {
      const user = await auth.register(String(req.body?.email ?? ""), String(req.body?.password ?? ""));
      res.status(201).json({ id: user.id, email: user.email });
    } catch (e) {
      next(e);
    }
  });

  app.post("/login", async (req, res, next) => {
    try {
      const token = await auth.login(String(req.body?.email ?? ""), String(req.body?.password ?? ""));
      setSessionCookie(res, token);
      res.json({ ok: true });
    } catch (e) {
      next(e);
    }
  });

  app.post("/logout", (req, res) => {
    auth.logout(readCookie(req, COOKIE));
    res.clearCookie(COOKIE, { path: "/" });
    res.json({ ok: true });
  });

  app.get("/me", requireUser, (_req, res) => {
    res.json({ id: res.locals.user.id, email: res.locals.user.email });
  });

  app.post("/change-password", requireUser, async (req, res, next) => {
    try {
      const token = await auth.changePassword(
        res.locals.user,
        String(req.body?.currentPassword ?? ""),
        String(req.body?.newPassword ?? ""),
      );
      setSessionCookie(res, token);
      res.json({ ok: true });
    } catch (e) {
      next(e);
    }
  });

  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof AuthError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    console.error(err);
    res.status(500).json({ error: "Erro interno" });
  });

  return app;
}
