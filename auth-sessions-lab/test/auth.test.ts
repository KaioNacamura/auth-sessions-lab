import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { AuthService, hashToken, SESSION_DAYS } from "../src/auth.js";
import { MemoryStore } from "../src/store.js";

const SENHA = "senha-boa-123";

function novoApp() {
  const store = new MemoryStore();
  return { store, app: createApp(new AuthService(store)) };
}

async function cadastrarELogar(app: ReturnType<typeof createApp>, email = "ana@exemplo.com") {
  await request(app).post("/register").send({ email, password: SENHA }).expect(201);
  const res = await request(app).post("/login").send({ email, password: SENHA }).expect(200);
  return res.headers["set-cookie"] as unknown as string[];
}

describe("cadastro e login", () => {
  it("senha curta é recusada", async () => {
    const { app } = novoApp();
    await request(app).post("/register").send({ email: "a@b.com", password: "123" }).expect(400);
  });

  it("e-mail repetido é recusado, sem diferença de maiúscula", async () => {
    const { app } = novoApp();
    await request(app).post("/register").send({ email: "Ana@Exemplo.com", password: SENHA }).expect(201);
    await request(app).post("/register").send({ email: "ana@exemplo.com", password: SENHA }).expect(409);
  });

  it("a senha guardada é hash Argon2id, não o texto", async () => {
    const { app, store } = novoApp();
    await request(app).post("/register").send({ email: "ana@exemplo.com", password: SENHA });
    const user = store.findUserByEmail("ana@exemplo.com");
    expect(user?.passwordHash).toMatch(/^\$argon2id\$/);
    expect(user?.passwordHash).not.toContain(SENHA);
  });

  it("e-mail inexistente e senha errada dão a mesma resposta", async () => {
    const { app } = novoApp();
    await request(app).post("/register").send({ email: "ana@exemplo.com", password: SENHA });
    const semUsuario = await request(app).post("/login").send({ email: "x@x.com", password: SENHA });
    const senhaErrada = await request(app).post("/login").send({ email: "ana@exemplo.com", password: "outra-senha-qualquer" });
    expect(semUsuario.status).toBe(401);
    expect(senhaErrada.status).toBe(401);
    expect(semUsuario.body).toEqual(senhaErrada.body);
  });
});

describe("cookie e sessão", () => {
  it("cookie sai com HttpOnly e SameSite", async () => {
    const { app } = novoApp();
    const cookies = await cadastrarELogar(app);
    expect(cookies[0]).toMatch(/HttpOnly/);
    expect(cookies[0]).toMatch(/SameSite=Lax/);
  });

  it("o token não fica guardado em texto, só o hash", async () => {
    const { app, store } = novoApp();
    const cookies = await cadastrarELogar(app);
    const token = decodeURIComponent(cookies[0]!.split(";")[0]!.split("=")[1]!);
    expect(store.findSession(token)).toBeUndefined();
    expect(store.findSession(hashToken(token))).toBeDefined();
  });

  it("logout derruba a sessão", async () => {
    const { app } = novoApp();
    const cookies = await cadastrarELogar(app);
    await request(app).get("/me").set("Cookie", cookies).expect(200);
    await request(app).post("/logout").set("Cookie", cookies).expect(200);
    await request(app).get("/me").set("Cookie", cookies).expect(401);
  });

  it("sessão vencida não vale", async () => {
    const store = new MemoryStore();
    let agora = new Date("2026-01-01T00:00:00Z");
    const auth = new AuthService(store, () => agora);
    const user = await auth.register("ana@exemplo.com", SENHA);
    const token = auth.createSession(user.id);
    expect(auth.authenticate(token)?.id).toBe(user.id);

    agora = new Date(agora.getTime() + SESSION_DAYS * 24 * 60 * 60 * 1000);
    expect(auth.authenticate(token)).toBeUndefined();
  });
});

describe("troca de senha", () => {
  it("derruba as sessões de todos os aparelhos e mantém quem trocou logado", async () => {
    const { app, store } = novoApp();
    const celular = await cadastrarELogar(app);
    const notebook = (await request(app).post("/login").send({ email: "ana@exemplo.com", password: SENHA }))
      .headers["set-cookie"] as unknown as string[];
    const user = store.findUserByEmail("ana@exemplo.com")!;
    expect(store.countSessionsOfUser(user.id)).toBe(2);

    const troca = await request(app)
      .post("/change-password")
      .set("Cookie", notebook)
      .send({ currentPassword: SENHA, newPassword: "senha-nova-456" })
      .expect(200);
    const novoCookie = troca.headers["set-cookie"] as unknown as string[];

    await request(app).get("/me").set("Cookie", celular).expect(401);
    await request(app).get("/me").set("Cookie", notebook).expect(401);
    await request(app).get("/me").set("Cookie", novoCookie).expect(200);
    expect(store.countSessionsOfUser(user.id)).toBe(1);
  });

  it("senha antiga para de funcionar e a nova funciona", async () => {
    const { app } = novoApp();
    const cookies = await cadastrarELogar(app);
    await request(app)
      .post("/change-password")
      .set("Cookie", cookies)
      .send({ currentPassword: SENHA, newPassword: "senha-nova-456" })
      .expect(200);
    await request(app).post("/login").send({ email: "ana@exemplo.com", password: SENHA }).expect(401);
    await request(app).post("/login").send({ email: "ana@exemplo.com", password: "senha-nova-456" }).expect(200);
  });

  it("senha atual errada não troca nada", async () => {
    const { app } = novoApp();
    const cookies = await cadastrarELogar(app);
    await request(app)
      .post("/change-password")
      .set("Cookie", cookies)
      .send({ currentPassword: "nao-e-essa-senha", newPassword: "senha-nova-456" })
      .expect(401);
    await request(app).get("/me").set("Cookie", cookies).expect(200);
  });
});
