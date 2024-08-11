// Imports
import { Hono } from "hono";
import type { FC } from "hono/jsx";
import type { User, Session } from "lucia";
import { zValidator } from "@hono/zod-validator";
import { string, z } from "zod";
import { Lucia } from "lucia";
import { D1Adapter } from "@lucia-auth/adapter-sqlite";
import { csrf } from "hono/csrf";
import { getCookie } from "hono/cookie";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";
import { generateIdFromEntropySize } from "lucia";
import { TimeSpan, createDate } from "oslo";
import { generateRandomString, alphabet } from "oslo/crypto";
import { isWithinExpirationDate } from "oslo";
import { Resend } from "resend";

// Email verification code
async function generateEmailVerificationCode(
  db: D1Database,
  userId: string,
  email: string
): Promise<string> {
  await db
    .prepare("delete from email_verification_codes where user_id = ?")
    .bind(userId)
    .run();
  const code = generateRandomString(4, alphabet("0-9"));
  await db
    .prepare(
      "insert into email_verification_codes (user_id, email, code, expires_at) values (?, ?, ?, ?)"
    )
    .bind(userId, email, code, createDate(new TimeSpan(15, "m")).toString())
    .run();
  return code;
}

// Initialize the database lucia connections
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
        emailVerified: Boolean(attributes.email_verified),
        email: attributes.email,
      };
    },
  });
}

// Utility function to hash password
const hashPassword = (password: string): string => {
  const passwordBytes = new TextEncoder().encode(password);
  const hashedPassword = sha256(passwordBytes);
  return bytesToHex(hashedPassword);
};

// Define the user attributes
interface DatabaseUserAttributes {
  email: string;
  email_verified: boolean;
}

type UserRow = {
  id: string;
  email: string;
  hashed_password: string;
  email_verified: number;
};

type EmailVerificationCode = {
  id: string;
  code: string;
  email: string;
  expires_at: string;
};

// Extend the Lucia type
declare module "lucia" {
  interface Register {
    Lucia: ReturnType<typeof initializeLucia>;
    DatabaseUserAttributes: DatabaseUserAttributes;
  }
}

// Layout view
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

// Cloudflare TS binding
type Bindings = {
  DB: D1Database;
  RESEND_API_KEY?: string;
};

// Hono app initialiser
const app = new Hono<{
  Bindings: Bindings;
  Variables: {
    user: User | null;
    session: Session | null;
  };
}>();

// function to send emails
const sendEmailOrLog = async (
  env: Bindings,
  recipient: string,
  subject: string,
  content: string
) => {
  if (env.RESEND_API_KEY) {
    const resend = new Resend(env.RESEND_API_KEY);

    try {
      const data = await resend.emails.send({
        from: "Buildkit <noreply@buildkit.app>",
        to: [recipient],
        subject: subject,
        text: content,
      });

      console.log("Email sent successfully:", data);
    } catch (error) {
      console.error("Error sending email:", error);
    }
  } else {
    console.log("Sending email (log only)");
    console.log({
      from: "Buildkit <noreply@buildkit.app>",
      to: recipient,
      subject: subject,
      text: content,
    });
  }
};

// CSRF protection
app.use(csrf());

// Session middleware
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

// Homepage GET Routes
app.get("/", (c) => {
  const user = c.get("user");
  if (user) {
    return c.html(
      <Layout>
        {user.emailVerified ? (
          <div>Current user: {JSON.stringify(user)}</div>
        ) : (
          <form method="POST" action="/email-verification">
            <input name="code" />
            <button>verify</button>
          </form>
        )}

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

// Signup GET route
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

// Login GET route
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

// Signup POST route
app.post(
  "/signup",
  zValidator(
    "form",
    z.object({
      email: z.string().email(),
      password: z.string().min(1),
    })
  ),
  async (c) => {
    const { email, password } = c.req.valid("form");
    const lucia = initializeLucia(c.env.DB);

    const passwordHash = hashPassword(password);
    const userId = generateIdFromEntropySize(10); // 16 characters long

    try {
      // insert user into DB
      const insertedUser = await c.env.DB.prepare(
        "INSERT INTO USERS (id, email, hashed_password, email_verified) values (?, ?, ?, ?) RETURNING *"
      )
        .bind(userId, email, passwordHash, false)
        .first();
      console.log("New user");
      console.log(insertedUser);

      // send verification email
      const verificationCode = await generateEmailVerificationCode(
        c.env.DB,
        userId,
        email
      );
      console.log(verificationCode);

      sendEmailOrLog(
        c.env,
        email,
        "Welcome",
        "Your verification code is: " + verificationCode
      );

      // create session
      const session = await lucia.createSession(userId, {});
      const sessionCookie = lucia.createSessionCookie(session.id);

      // set session cookie
      c.header("Set-Cookie", sessionCookie.serialize(), {
        append: true,
      });

      // redirect to home
      return c.redirect("/");
    } catch (error) {
      console.error(error);
      return c.body("Something went wrong", 400);
    }
  }
);

// Login POST route
app.post(
  "/login",
  zValidator(
    "form",
    z.object({
      email: z.string().email(),
      password: z.string().min(1),
    })
  ),
  async (c) => {
    const { email, password } = c.req.valid("form");
    const lucia = initializeLucia(c.env.DB);

    const user = await c.env.DB.prepare("SELECT * FROM users WHERE email = ?")
      .bind(email)
      .first<UserRow>();

    if (!user) {
      return c.body("Invalid email", 400);
    }

    const passwordHash = hashPassword(password);

    if (passwordHash !== user.hashed_password) {
      return c.body("Invalid password", 400);
    }

    // create session
    const session = await lucia.createSession(user.id, {});
    const sessionCookie = lucia.createSessionCookie(session.id);

    // set session cookie
    c.header("Set-Cookie", sessionCookie.serialize(), {
      append: true,
    });

    // redirect to home
    return c.redirect("/");
  }
);

// Logout POST route
app.post("/logout", async (c) => {
  const lucia = initializeLucia(c.env.DB);
  // invalidate session
  const session = c.get("session");
  if (session) {
    await lucia.invalidateSession(session.id);
  }
  const sessionCookie = lucia.createBlankSessionCookie();
  // set session cookie
  c.header("Set-Cookie", sessionCookie.serialize(), {
    append: true,
  });
  // redirect to home
  return c.redirect("/");
});

// function to verify email verification code
async function verifyVerificationCode(
  db: D1Database,
  user: User,
  code: string
) {
  // check if code is valid
  const databaseCode = await db
    .prepare(
      "delete from email_verification_code where user_id = ? and code = ? and email = ? returning *"
    )
    .bind(user.id, code, user.email)
    .first<EmailVerificationCode>();
  if (!databaseCode) {
    return false;
  }

  // check if code is expired
  if (!isWithinExpirationDate(new Date(databaseCode.expires_at))) {
    return false;
  }
  return true;
}

// email verification route
app.post(
  "/email-verification",
  zValidator(
    "form",
    z.object({
      code: z.string().min(1),
    })
  ),
  async (c) => {
    const user = c.get("user");
    if (!user) {
      return c.body("Invalid user", 400);
    }
    const { code } = c.req.valid("form");
    if (!user) {
      return c.body(null, 400);
    }
    const validCode = verifyVerificationCode(c.env.DB, user, code);
    if (!validCode) {
      return c.body(null, 400);
    }
    const lucia = initializeLucia(c.env.DB);
    await lucia.invalidateUserSessions(user.id);
    await c.env.DB.prepare(
      "UPDATE users SET email_verified = true WHERE id = ?"
    )
      .bind(user.id)
      .run();
    // create session
    const session = await lucia.createSession(user.id, {});
    const sessionCookie = lucia.createSessionCookie(session.id);

    // set session cookie
    c.header("Set-Cookie", sessionCookie.serialize(), {
      append: true,
    });

    // redirect to home
    return c.redirect("/");
  }
);
export default app;
