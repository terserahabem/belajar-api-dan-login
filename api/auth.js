import { neon } from '@neondatabase/serverless';
import { randomBytes, scryptSync, timingSafeEqual, createHmac } from 'node:crypto';

const SECRET = process.env.SESSION_SECRET;
const MASA = 60 * 60 * 24 * 7; // sesi berlaku 7 hari (dalam detik)

// Mengacak password menjadi hash. Password asli tidak pernah disimpan.
function buatHash(password) {
  const salt = randomBytes(16).toString('hex');
  const hash = scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function cekPassword(password, tersimpan) {
  const [salt, hash] = tersimpan.split(':');
  const hashBaru = scryptSync(password, salt, 64);
  const hashLama = Buffer.from(hash, 'hex');
  return hashLama.length === hashBaru.length && timingSafeEqual(hashLama, hashBaru);
}

// Tanda tangan agar cookie sesi tidak bisa dipalsukan
function tandatangani(isi) {
  return createHmac('sha256', SECRET).update(isi).digest('hex');
}

function buatToken(id) {
  const kedaluwarsa = Math.floor(Date.now() / 1000) + MASA;
  const isi = `${id}.${kedaluwarsa}`;
  return `${isi}.${tandatangani(isi)}`;
}

function bacaToken(req) {
  const cocok = (req.headers.cookie || '').match(/(?:^|;\s*)sesi=([^;]+)/);
  if (!cocok) return null;
  const [id, kedaluwarsa, tanda] = cocok[1].split('.');
  if (!id || !kedaluwarsa || !tanda) return null;
  const tandaBenar = tandatangani(`${id}.${kedaluwarsa}`);
  if (
    tanda.length !== tandaBenar.length ||
    !timingSafeEqual(Buffer.from(tanda), Buffer.from(tandaBenar))
  ) return null;
  if (Number(kedaluwarsa) < Date.now() / 1000) return null;
  return Number(id);
}

function pasangCookie(res, token, maxAge) {
  res.setHeader(
    'Set-Cookie',
    `sesi=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`
  );
}

export default async function handler(req, res) {
  if (!SECRET) {
    return res.status(500).json({ error: 'SESSION_SECRET belum diatur di Vercel' });
  }
  const sql = neon(process.env.DATABASE_URL);

  // GET: cek siapa yang sedang masuk
  if (req.method === 'GET') {
    const id = bacaToken(req);
    if (!id) return res.status(401).json({ error: 'Belum masuk' });
    const rows = await sql`SELECT id, username FROM pengguna WHERE id = ${id}`;
    if (!rows.length) return res.status(401).json({ error: 'Belum masuk' });
    return res.status(200).json(rows[0]);
  }

  if (req.method === 'POST') {
    const aksi = req.query.aksi;

    if (aksi === 'keluar') {
      pasangCookie(res, '', 0);
      return res.status(200).json({ ok: true });
    }

    const username = String(req.body?.username || '').trim().toLowerCase();
    const password = String(req.body?.password || '');

    if (!/^[a-z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({ error: 'Username 3-20 karakter: huruf kecil, angka, atau _' });
    }
    if (password.length < 8 || password.length > 100) {
      return res.status(400).json({ error: 'Password minimal 8 karakter' });
    }

    if (aksi === 'daftar') {
      try {
        const rows = await sql`
          INSERT INTO pengguna (username, password_hash)
          VALUES (${username}, ${buatHash(password)})
          RETURNING id, username
        `;
        pasangCookie(res, buatToken(rows[0].id), MASA);
        return res.status(201).json(rows[0]);
      } catch (err) {
        if (err.code === '23505') {
          return res.status(409).json({ error: 'Username sudah dipakai' });
        }
        throw err;
      }
    }

    if (aksi === 'masuk') {
      const rows = await sql`
        SELECT id, username, password_hash FROM pengguna WHERE username = ${username}
      `;
      if (!rows.length || !cekPassword(password, rows[0].password_hash)) {
        return res.status(401).json({ error: 'Username atau password salah' });
      }
      pasangCookie(res, buatToken(rows[0].id), MASA);
      return res.status(200).json({ id: rows[0].id, username: rows[0].username });
    }
  }

  res.status(405).json({ error: 'Metode tidak diizinkan' });
}
