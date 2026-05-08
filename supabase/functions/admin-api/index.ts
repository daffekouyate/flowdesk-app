import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

const SUPABASE_URL        = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY    = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const ANON_KEY            = Deno.env.get("SUPABASE_ANON_KEY")!;

const CORS = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
};

Deno.serve(async (req: Request) => {
  // Preflight CORS
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: CORS });
  }

  try {
    // 1. Vérifier le JWT de l'utilisateur appelant
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return json({ error: "Unauthorized" }, 401);
    }

    const userClient = createClient(SUPABASE_URL, ANON_KEY, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: { user }, error: authErr } = await userClient.auth.getUser();

    if (authErr || !user) {
      return json({ error: "Unauthorized" }, 401);
    }

    // 2. Vérifier le rôle admin (défini via app_metadata côté serveur)
    if (user.app_metadata?.role !== "admin") {
      return json({ error: "Forbidden — admin role required" }, 403);
    }

    // 3. Extraire la sous-route (/users, /users/:id, etc.)
    const url      = new URL(req.url);
    const subPath  = url.pathname.replace(/^\/functions\/v1\/admin-api/, "");
    const target   = `${SUPABASE_URL}/auth/v1/admin${subPath}${url.search}`;

    // 4. Proxy vers l'API admin Supabase avec la service_role key (côté serveur uniquement)
    const body = req.method !== "GET" && req.method !== "DELETE"
      ? await req.text()
      : undefined;

    const upstream = await fetch(target, {
      method: req.method,
      headers: {
        apikey:          SERVICE_ROLE_KEY,
        Authorization:   `Bearer ${SERVICE_ROLE_KEY}`,
        "Content-Type":  "application/json",
      },
      body,
    });

    const data = await upstream.json();
    return json(data, upstream.status);

  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal error";
    return json({ error: msg }, 500);
  }
});

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}
