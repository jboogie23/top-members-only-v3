import { Hono } from "hono";
import type { FC } from "hono/jsx";
import type { User, Session } from "lucia";
import { zValidator } from "@hono/zod-validator";
import { z } from "zod";
import { Lucia } from "lucia";
import { D1Adapter } from "@lucia-auth/adapter-sqlite";
import { csrf } from "hono/csrf";
import { getCookie } from "hono/cookie";

function initializeLucia(D1: D1Database) {
  const adapter = new D1Adapter(D1, {
    user: "users",
    session: "sessions",
  });
  return new Lucia(adapter, {
    sessionCookie: {
      attributes: {
        secure: false,
      },
    },
    getUserAttributes: (attributes) => {
      return {
        email: attributes.email,
      };
    },
  });
}

declare module "lucia" {
  interface Register {
    Lucia: ReturnType<typeof initializeLucia>;
    DatabaseUserAttributes: DatabaseUserAttributes;
  }
}

const Layout: FC = (props) => {
  return (
    <html>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:ital,opsz,wght@0,14..32,100..900;1,14..32,100..900&display=swap"
          rel="stylesheet"
        />
        <style>
          {`
            body {
              background-color: black;
              color: white;
              font-family: "Inter", sans-serif;
            }
            a {
              color: white;
              text-decoration: none;
              font-family: "Inter", sans-serif;
            }
            a:hover, a:active, a:focus {
              color: white;
              text-decoration: none;
              font-family: "Inter", sans-serif;
            }
            * {
              font-family: "Inter", sans-serif;
            }
          `}
        </style>
      </head>
      <body>{props.children}</body>
    </html>
  );
};

type Bindings = {
  DB: D1Database;
};

const app = new Hono<{
  Bindings: Bindings;
  Variables: {
    user: User | null;
    session: Session | null;
  };
}>();

app.use(csrf());

app.use("*", async (c, next) => {
  const lucia = initializeLucia(c.env.DB);
  const sessionId = getCookie(c, lucia.sessionCookieName) ?? null;
  if (!sessionId) {
    c.set("user", null);
    c.set("session", null);
    return next();
  }
  const { session, user } = await lucia.validateSession(sessionId);
  if (session && session.fresh) {
    // use `header()` instead of `setCookie()` to avoid TS errors
    c.header("Set-Cookie", lucia.createSessionCookie(session.id).serialize(), {
      append: true,
    });
  }
  if (!session) {
    c.header("Set-Cookie", lucia.createBlankSessionCookie().serialize(), {
      append: true,
    });
  }
  c.set("user", user);
  c.set("session", session);
  return next();
});

app.get("/", (c) => {
  const user = c.get("user");
  if (user) {
    return c.html(
      <Layout>
        <div>Current user: {JSON.stringify(user)}</div>
        <form method="POST" action="/logout">
          <button>Logout</button>
        </form>
      </Layout>
    );
  } else {
    return c.html(
      <Layout>
        <a href="/signup">signup</a>
        <br />
        <a href="/login">login</a>
      </Layout>
    );
  }
});

app.get("/signup", (c) => {
  return c.html(
    <Layout>
      Sign up for a new account:
      <form method="POST">
        <label for="email">Email</label>
        <input name="email" />
        <label for="password">Password</label>
        <input name="password" />
        <button>Signup</button>
      </form>
      <a href="/signup">signup</a>
      <br />
      <a href="/login">login</a>
    </Layout>
  );
});

app.get("/login", (c) => {
  return c.html(
    <Layout>
      Login to your account:
      <form method="POST">
        <label for="email">Email</label>
        <input name="email" />
        <label for="password">Password</label>
        <input name="password" />
        <button>Login</button>
      </form>
      <a href="/signup">signup</a>
      <br />
      <a href="/login">login</a>
    </Layout>
  );
});

app.post(
  "/signup",
  zValidator(
    "form",
    z.object({
      email: z.string().email(),
      password: z.string().min(1),
    })
  ),
  (c) => {
    const { email, password } = c.req.valid("form");
    console.log(email);
    return c.redirect("/");
  }
);

export default app;
