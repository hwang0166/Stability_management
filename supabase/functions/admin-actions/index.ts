// admin-actions — Supabase Edge Function (Deno)
// 리더 비밀번호로 재인증 후 관리자 액션 수행
// 지원 액션:
//   resetPassword    — 팀원 비밀번호 초기화 (임시 비밀번호 발급)
//   sendNotification — 이메일 알림 수동 발송

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const NOTIFY_SECRET = Deno.env.get("NOTIFY_SECRET") ?? "";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}

// 임시 비밀번호 생성 (대문자+소문자+숫자+특수문자, 10자)
function generateTempPassword(): string {
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const lower = "abcdefghjkmnpqrstuvwxyz";
  const digits = "23456789";
  const rand = (s: string) => s[Math.floor(Math.random() * s.length)];
  return rand(upper) + rand(upper) +
    rand(lower) + rand(lower) +
    rand(digits) + rand(digits) +
    rand(upper) + rand(lower) +
    rand(digits) + "!";
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }
  if (req.method !== "POST") {
    return json({ error: "Method Not Allowed" }, 405);
  }

  try {
    // ── 1. 세션 토큰 추출 ──────────────────────────────────────────
    const authHeader = req.headers.get("Authorization") ?? "";
    const sessionToken = authHeader.replace(/^Bearer\s+/i, "").trim();
    if (!sessionToken) return json({ error: "Authorization 헤더가 없습니다." }, 401);

    // ── 2. 요청 바디 파싱 ──────────────────────────────────────────
    const { action, targetUserId } = await req.json() as {
      action: string;
      targetUserId?: string;
    };
    if (!action) {
      return json({ error: "action파라미터는 필수입니다." }, 400);
    }

    // ── 3. 서비스 클라이언트 생성 ──────────────────────────────────
    const adminClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    // ── 4. 세션 JWT로 현재 사용자 확인 ────────────────────────────
    const { data: { user }, error: getUserError } = await adminClient.auth.getUser(sessionToken);
    if (getUserError || !user) {
      return json({ error: "유효하지 않은 세션입니다. 다시 로그인해 주세요." }, 401);
    }

    // ── 6. 리더 권한 확인 ──────────────────────────────────────────
    const { data: profile } = await adminClient
      .from("profiles")
      .select("role")
      .eq("id", user.id)
      .single();
    if (profile?.role !== "leader") {
      return json({ error: "리더 권한이 필요합니다." }, 403);
    }

    // ── 7. 액션 수행 ───────────────────────────────────────────────
    if (action === "resetPassword") {
      if (!targetUserId) {
        return json({ error: "targetUserId가 없습니다." }, 400);
      }
      const tempPw = generateTempPassword();
      const { error: resetError } = await adminClient.auth.admin.updateUserById(
        targetUserId,
        { password: tempPw }
      );
      if (resetError) {
        return json({ error: "비밀번호 초기화 오류: " + resetError.message }, 500);
      }
      return json({ success: true, tempPassword: tempPw });
    }

    if (action === "deleteUser") {
      if (!targetUserId) {
        return json({ error: "targetUserId가 없습니다." }, 400);
      }

      // auth.users 에서 사용자 완전 삭제 (프로필도 외래키/트리거에 의해 자동 삭제 또는 서비스키 통과)
      // 만약을 위해 프로필을 명시적으로 선 삭제합니다.
      await adminClient.from("profiles").delete().eq("id", targetUserId);
      const { error: delUserErr } = await adminClient.auth.admin.deleteUser(targetUserId);

      if (delUserErr) {
        return json({ error: "계정 완전 삭제 오류: " + delUserErr.message }, 500);
      }
      return json({ success: true });
    }

    if (action === "sendNotification") {
      // notify-upcoming-tests를 서버 내부에서 호출 (NOTIFY_SECRET 브라우저 미노출)
      const notifyUrl = `${SUPABASE_URL}/functions/v1/notify-upcoming-tests?secret=${encodeURIComponent(NOTIFY_SECRET)}`;
      const res = await fetch(notifyUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      const result = await res.json();
      return json(result, res.status);
    }

    return json({ error: "알 수 없는 action: " + action }, 400);

  } catch (err) {
    console.error(err);
    return json({ error: String(err) }, 500);
  }
});
