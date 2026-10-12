// Vercel Serverless Function: 계정 인증 + 북마크 데이터 저장 (Upstash Redis REST)
const crypto = require('crypto');

const REDIS_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

async function redis(...cmd) {
    const r = await fetch(REDIS_URL, {
        method: 'POST',
        headers: { Authorization: `Bearer ${REDIS_TOKEN}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(cmd)
    });
    const j = await r.json();
    if (j.error) throw new Error(j.error);
    return j.result;
}

function hashPw(password, salt) {
    return crypto.scryptSync(password, salt, 32).toString('hex');
}

module.exports = async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    if (req.method !== 'POST') return res.status(405).json({ error: 'method' });
    if (!REDIS_URL || !REDIS_TOKEN) return res.status(500).json({ error: 'DB 환경변수가 설정되지 않았습니다.' });

    try {
        const { action, username, password, data } = req.body || {};
        if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
            return res.status(400).json({ error: '사용자 이름과 비밀번호를 입력하세요.' });
        }

        const key = 'ws:user:' + crypto.createHash('sha256').update(username.trim().toLowerCase()).digest('hex');
        const raw = await redis('GET', key);
        let rec = raw ? JSON.parse(raw) : null;

        // 처음 보는 사용자 → 자동 가입
        if (!rec) {
            if (action !== 'load') return res.status(401).json({ error: 'auth' });
            const salt = crypto.randomBytes(16).toString('hex');
            rec = { salt, hash: hashPw(password, salt), data: null };
            await redis('SET', key, JSON.stringify(rec));
            return res.status(200).json({ ok: true, created: true, data: null });
        }

        // 비밀번호 검증
        const given = Buffer.from(hashPw(password, rec.salt), 'hex');
        const stored = Buffer.from(rec.hash, 'hex');
        if (!crypto.timingSafeEqual(given, stored)) {
            return res.status(401).json({ error: '비밀번호가 올바르지 않습니다.' });
        }

        if (action === 'load') {
            return res.status(200).json({ ok: true, created: false, data: rec.data });
        }
        if (action === 'save') {
            if (!data || typeof data !== 'object') return res.status(400).json({ error: 'data' });
            rec.data = data;
            await redis('SET', key, JSON.stringify(rec));
            return res.status(200).json({ ok: true });
        }
        return res.status(400).json({ error: 'action' });
    } catch (e) {
        return res.status(500).json({ error: String(e.message || e) });
    }
};
