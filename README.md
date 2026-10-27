# Tugas DDKI — Perbaikan Draf RBAC "Project Aegis"

Repo ini berisi bahan tugas mata kuliah **Dasar-Dasar Keamanan Informasi (DDKI)**:
studi kasus perbaikan desain kontrol akses berbasis peran (RBAC) pada backend
akademik fiktif **Project Aegis**, plus rekaman layar proses pengerjaannya.

| Isi repo | Keterangan |
|---|---|
| `draft/aegis_rbac_draft.json` | Draf awal (versi bermasalah) |
| `fixed/fix_aegis_rbac_draft.json` | Versi perbaikan |
| `check_rbac.py` | Validator + penghitung permission efektif + audit otomatis |
| `media/aegis-rbac-demo.mp4` | Rekaman layar pengerjaan (2 menit 53 detik, 1080p) |

---

## 1. Masalah pada draf awal

Draf pertama hanya mendaftar nama peran dan nama izin. Terlihat rapi, tapi
tidak bisa dipakai menegakkan apa pun. Enam masalah utama:

**a. Izin tanpa scope.** `read_grades`, `edit_grades`, `manage_students`,
`view_courses` hanya menyebut *tindakan*, bukan *objek*. `edit_grades` tidak
menjawab pertanyaan penting: nilai siapa, mata kuliah mana? Kalau implementasi
membacanya sebagai "boleh mengedit nilai apa pun", setiap dosen bisa mengubah
nilai kelas dosen lain.

**b. Tidak ada pemeriksaan kepemilikan (ownership).** Endpoint
`/api/grades/update` hanya mencocokkan nama peran (`lecturer`, `admin`).
Dosen A lolos pemeriksaan untuk mata kuliah yang diampu dosen B. Ini contoh
kegagalan otorisasi paling klasik: *role check* ≠ *authorization check*.

**c. Wildcard `"all"` pada admin.** Satu string yang membuka segalanya. Tidak
bisa diaudit, tidak bisa di-*least privilege*, dan kalau ada endpoint baru,
admin otomatis punya akses tanpa ada yang memutuskannya.

**d. Warisan peran yang salah arah.** `lecturer` mewarisi `student`. Kedengarannya
logis ("dosen juga bisa melihat seperti mahasiswa"), akibatnya `lecturer`
mewarisi `submit_assignment` dan `read_grades` milik mahasiswa — termasuk
`edit_grades` diwarisi turun ke `admin`. Warisan harus menambah izin yang
*searah* dengan tanggung jawab, bukan menumpuk semua yang ada di bawah.

**e. Izin diberikan tapi tidak dipakai (dan sebaliknya).** `guest_lecturer`
punya `edit_grades` padahal endpoint nilai tidak mengizinkannya — izin mati
yang tetap muncul di audit dan membingungkan. Sebaliknya `guest_lecturer`
tidak punya cara mengunggah materi padahal itu tugasnya.

**f. Metadata endpoint tidak lengkap.** Tidak ada HTTP method, tidak ada
penanda audit untuk operasi destruktif (`DELETE /api/users/delete`), dan
`/api/courses/view` memakai `allowed_roles` sementara endpoint lain memakai
daftar peran — dua gaya berbeda di satu file, sumber bug implementasi.

## 2. Perbaikan pada versi `fix`

| Masalah | Perbaikan |
|---|---|
| Izin tanpa scope | Format `resource:action:scope`, mis. `grades:update:assigned_course`, `assignments:submit:self` |
| Tidak ada ownership | `enforce_ownership_check: true` + `ownership_rule` eksplisit (`user.id == course.assigned_lecturer_id`) |
| Wildcard `all` | Dihapus; admin dapat izin eksplisit (`users:create`, `users:update`, `users:deactivate`, `courses:manage_catalog`, `audit_logs:read`) |
| Warisan salah arah | `lecturer` mewarisi `guest_lecturer` (sesama pengajar), `student` berdiri sendiri; `admin` **tidak** mewarisi siapa pun |
| Izin mati | `guest_lecturer`: `edit_grades` dibuang, diganti `materials:upload:assigned_course` |
| Metadata endpoint | `method` (PATCH/DELETE/GET), `required_permissions`, dan `audit_logged: true` untuk operasi destruktif |

Hasil permission efektif setelah warisan dihitung (dari `check_rbac.py`):

```
student         -> assignments:submit:self, courses:view:enrolled, grades:read:self
guest_lecturer  -> courses:view:assigned, materials:upload:assigned_course
lecturer        -> assignments:create:assigned_course, courses:view:assigned,
                   grades:read:assigned_course, grades:update:assigned_course,
                   materials:upload:assigned_course, students:view_roster:assigned_course
admin           -> audit_logs:read, courses:manage_catalog, users:create,
                   users:deactivate, users:read, users:update
```

Pemetaan endpoint:

```
/api/grades/update  (PATCH)  -> lecturer            (wajib cocok assigned_lecturer_id)
/api/users/delete   (DELETE) -> admin               (audit_logged)
/api/courses/view   (GET)    -> student, guest_lecturer, lecturer, admin
```

## 3. Prinsip yang dipakai

- **Least privilege** — tiap peran hanya dapat yang benar-benar dibutuhkan tugasnya.
  `guest_lecturer` mengunggah materi, bukan mengubah nilai.
- **Defense in depth** — role check *dan* ownership check. Lolos satu, belum tentu lolos dua.
- **Explicit over wildcard** — tidak ada `"all"`. Setiap kenaikan hak akses harus
  terlihat di diff, bukan tersembunyi di balik satu string.
- **Separation of duties** — admin mengelola pengguna dan katalog, bukan nilai akademik.
  Perubahan nilai tetap milik dosen pengampu (lihat catatan di bawah).
- **Auditability** — operasi destruktif ditandai `audit_logged` supaya ada jejak siapa menghapus apa.

## 4. Cara menjalankan validator

Butuh Python 3.9+, tanpa dependensi eksternal.

```bash
python check_rbac.py
```

Yang dilakukan skrip:

1. **Validasi struktur** — `roles`/`endpoints` ada, role yang diwarisi benar-benar
   terdefinisi, dan tidak ada siklus warisan (A→B→A).
2. **Hitung permission efektif** — menelusuri `inherits_from` secara rekursif,
   jadi yang tercetak adalah hak akses nyata, bukan hanya yang tertulis.
3. **Cek akses endpoint** — mendukung dua gaya deklarasi (`allowed_roles` pada
   draf lama, `required_permissions` pada versi fix).
4. **Audit otomatis** — menandai wildcard, izin tanpa scope, endpoint yang
   menyentuh nilai tanpa ownership check, dan operasi destruktif tanpa audit log.

Output untuk draf memunculkan 11 temuan; untuk versi fix **0 temuan**. Skrip juga
punya `self_check()` berisi assertion yang gagal kalau logika perbaikan rusak —
jalankan `python check_rbac.py` dan lihat baris `self-check OK`.

## 5. Rekaman pengerjaan

`media/aegis-rbac-demo.mp4` — rekaman layar VS Code saat membandingkan draf
kiri-kanan dan menulis versi perbaikan. Dikompres dari rekaman mentah 106 MB
(1080p30, H.264, CRF 24) supaya muat di repo.

---

## Catatan / keterbatasan

- `admin` pada versi fix **tidak** bisa memanggil `/api/grades/update`. Ini
  disengaja (separation of duties), tapi kalau kebijakan kampus mengizinkan
  admin mengoreksi nilai, tambahkan `grades:update:assigned_course` ke admin
  **plus** audit log wajib.
- `ownership_rule` di sini masih berupa *string dokumentasi* untuk dibaca manusia
  dan mesin pemeriksa. Pada implementasi nyata, aturan ini harus diterjemahkan
  jadi query yang di-*enforce* di lapisan data, bukan hanya di lapisan routing.
- Draf ini tidak membahas pemisahan peran per-program-studi maupun delegasi
  sementara (dosen pengganti). Di luar cakupan tugas.

**Mata kuliah:** Dasar-Dasar Keamanan Informasi (DDKI) — Semester 3
**Penulis:** Mohammad Reihan Islami Wijaya (252410102080)
