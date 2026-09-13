import { getStore } from "@netlify/blobs";

const STORE_NAME = "aldagher-cloud-v1";
const SNAPSHOT_KEY = "snapshot";
const SESSION_PREFIX = "session/";
const SESSION_DAYS = 30;

function json(data: any, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

function token() {
  return crypto.randomUUID() + crypto.randomUUID();
}

function findUser(snapshot: any, username: string, password: string) {
  const users = Array.isArray(snapshot?.users) ? snapshot.users : [];

  return users.find((u: any) =>
    String(u?.username || "").trim().toLowerCase() ===
      String(username || "").trim().toLowerCase() &&
    String(u?.password || "") === String(password || "") &&
    u?.active !== false
  );
}

function validSnapshot(value: any) {
  return value && typeof value === "object" && !Array.isArray(value);
}

async function readBody(req: Request) {
  try {
    return await req.json();
  } catch {
    return {};
  }
}

async function getSession(req: Request, store: any) {
  const auth = req.headers.get("authorization") || "";

  if (!auth.startsWith("Bearer ")) return null;

  const sessionToken = auth.slice(7).trim();
  if (!sessionToken) return null;

  const session = await store.get(SESSION_PREFIX + sessionToken, {
    type: "json"
  });

  if (!session) return null;

  if (session.expiresAt && Date.now() > session.expiresAt) {
    await store.delete(SESSION_PREFIX + sessionToken);
    return null;
  }

  return {
    token: sessionToken,
    ...session
  };
}

export default async (req: Request) => {
  const store = getStore(STORE_NAME);
  const url = new URL(req.url);
  const path = url.pathname;
  const body = await readBody(req);

  try {
    if (req.method === "POST" && path.endsWith("/login")) {
      const username = String(body?.username || "").trim();
      const password = String(body?.password || "");
      const candidateSnapshot = body?.candidateSnapshot;

      let snapshot = await store.get(SNAPSHOT_KEY, { type: "json" });

      if (!snapshot) {
        if (
          validSnapshot(candidateSnapshot) &&
          Array.isArray(candidateSnapshot.users) &&
          candidateSnapshot.users.length
        ) {
          const candidateUser = findUser(
            candidateSnapshot,
            username,
            password
          );

          if (candidateUser) {
            snapshot = candidateSnapshot;
            await store.setJSON(SNAPSHOT_KEY, snapshot);
          }
        }

        if (!snapshot && username === "Admin" && password === "1234") {
          snapshot = validSnapshot(candidateSnapshot)
            ? candidateSnapshot
            : {
                users: [
                  {
                    id: "admin",
                    username: "Admin",
                    password: "1234",
                    role: "admin",
                    active: true
                  }
                ]
              };

          await store.setJSON(SNAPSHOT_KEY, snapshot);
        }
      }

      if (!snapshot) {
        return json(
          { ok: false, message: "لا توجد قاعدة بيانات سحابية مهيأة بعد." },
          401
        );
      }

      const user = findUser(snapshot, username, password);

      if (!user) {
        return json(
          { ok: false, message: "اسم المستخدم أو كلمة المرور غير صحيحة." },
          401
        );
      }

      const sessionToken = token();
      const expiresAt =
        Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000;

      await store.setJSON(SESSION_PREFIX + sessionToken, {
        userId: user.id,
        username: user.username,
        expiresAt
      });

      return json({
        ok: true,
        token: sessionToken,
        expiresAt,
        user: {
          id: user.id,
          username: user.username,
          role: user.role
        },
        snapshot
      });
    }

    if (req.method === "GET" && path.endsWith("/snapshot")) {
      const session = await getSession(req, store);

      if (!session) {
        return json({ ok: false, message: "غير مصرح." }, 401);
      }

      const snapshot = await store.get(SNAPSHOT_KEY, { type: "json" });

      return json({
        ok: true,
        snapshot: snapshot || null
      });
    }

    if (req.method === "POST" && path.endsWith("/save")) {
      const session = await getSession(req, store);

      if (!session) {
        return json({ ok: false, message: "غير مصرح." }, 401);
      }

      const snapshot = body?.snapshot;

      if (!validSnapshot(snapshot)) {
        return json(
          { ok: false, message: "بيانات الحفظ غير صالحة." },
          400
        );
      }

      const users = Array.isArray(snapshot.users)
        ? snapshot.users
        : [];

      const activeUser = users.find(
        (u: any) =>
          String(u?.id) === String(session.userId) &&
          u?.active !== false
      );

      if (!activeUser) {
        return json(
          { ok: false, message: "المستخدم غير نشط." },
          403
        );
      }

      await store.setJSON(SNAPSHOT_KEY, snapshot);

      return json({
        ok: true,
        savedAt: new Date().toISOString()
      });
    }

    if (req.method === "POST" && path.endsWith("/recover")) {
      const recoveryCode = String(body?.recoveryCode || "").trim();

      if (!recoveryCode) {
        return json(
          { ok: false, message: "أدخل رقم الاسترداد." },
          400
        );
      }

      const snapshot = await store.get(SNAPSHOT_KEY, {
        type: "json"
      });

      if (!snapshot) {
        return json(
          { ok: false, message: "لا توجد بيانات سحابية." },
          404
        );
      }

      const users = Array.isArray(snapshot.users)
        ? snapshot.users
        : [];

      const matches = users.filter(
        (u: any) =>
          u?.active !== false &&
          String(u?.recoveryCode || "").trim() === recoveryCode
      );

      if (matches.length !== 1) {
        return json(
          {
            ok: false,
            message:
              matches.length > 1
                ? "رقم الاسترداد مكرر."
                : "رقم الاسترداد غير صحيح."
          },
          404
        );
      }

      const user = matches[0];

      return json({
        ok: true,
        username: user.username,
        password: user.password
      });
    }

    return json(
      { ok: false, message: "المسار غير موجود." },
      404
    );
  } catch (error: any) {
    console.error(error);

    return json(
      {
        ok: false,
        message: "حدث خطأ في الخادم السحابي."
      },
      500
    );
  }
};
