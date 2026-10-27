"""Validator + permission resolver untuk draf RBAC Project Aegis.

Pakai:  python check_rbac.py

Tujuan:
  1. Validasi struktur JSON (role, permission, endpoint, warisan sah).
  2. Hitung permission efektif tiap role (ikut warisan `inherits_from`).
  3. Cek siapa yang boleh memanggil endpoint, dari `required_permissions`/`allowed_roles`.
  4. Cetak temuan (temuan kebocoran hak akses) supaya bisa dibandingkan draf vs fix.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
FILES = {
    "draft": HERE / "draft" / "aegis_rbac_draft.json",
    "fix": HERE / "fixed" / "fix_aegis_rbac_draft.json",
}


def load(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data.get("roles"), dict) and data["roles"], f"{path}: roles kosong"
    assert isinstance(data.get("endpoints"), dict), f"{path}: endpoints hilang"
    return data


def effective_permissions(data, role, seen=None):
    """Permission efektif = milik sendiri + warisan, rekursif, aman dari siklus."""
    seen = seen or set()
    assert role not in seen, f"siklus warisan terdeteksi: {role}"
    seen.add(role)
    spec = data["roles"][role]
    perms = set(spec.get("permissions", []))
    for parent in spec.get("inherits_from", []):
        assert parent in data["roles"], f"{role} mewarisi role tak dikenal: {parent}"
        perms |= effective_permissions(data, parent, seen)
    return perms


def allowed(data, role, endpoint):
    """True kalau role boleh memanggil endpoint (mode `allowed_roles` atau `required_permissions`)."""
    perms = effective_permissions(data, role)
    if "all" in perms:  # wildcard kasar, hanya ada di draf
        return True
    ep = data["endpoints"][endpoint]
    if "allowed_roles" in ep:
        return role in ep["allowed_roles"]
    need = ep.get("required_permissions", [])
    return any(p in perms for p in need)


def report(name, data):
    print(f"\n=== {name}: {data.get('system', '?')}")
    for role in data["roles"]:
        print(f"  {role:15s} -> {sorted(effective_permissions(data, role))}")
    for ep in data["endpoints"]:
        who = [r for r in data["roles"] if allowed(data, r, ep)]
        print(f"  {ep:22s} -> {who}")


def audit(data):
    """Temuan masalah keamanan yang bisa dideteksi otomatis."""
    found = []
    for role, spec in data["roles"].items():
        perms = effective_permissions(data, role)
        if "all" in perms:
            found.append(f"[{role}] permission wildcard 'all' — tidak bisa di-audit, ganti permission eksplisit")
        for p in spec.get("permissions", []):
            # permission global (tanpa scope) yang menyentuh nilai/user = terlalu luas
            if p in {"edit_grades", "manage_students", "read_grades"}:
                found.append(f"[{role}] permission '{p}' tanpa scope (siapa? mata kuliah mana?)")
            if role == "student" and p in {"grades:update:assigned_course", "users:deactivate"}:
                found.append(f"[{role}] punya permission administratif: {p}")
        # role non-dosen yang bisa mengubah nilai
        if role in {"guest_lecturer"} and {"edit_grades", "grades:update:assigned_course"} & perms:
            found.append(f"[{role}] bisa mengubah nilai — cek lagi (least privilege + ownership)")
    for ep, spec in data["endpoints"].items():
        touches_grade = "grade" in ep
        if touches_grade and not spec.get("enforce_ownership_check"):
            found.append(f"[{ep}] mengubah nilai tanpa ownership check (dosen lain bisa ikut mengubah)")
        if ep.endswith("/delete") and not spec.get("audit_logged"):
            found.append(f"[{ep}] operasi destruktif tanpa audit log")
        if "method" not in spec:
            found.append(f"[{ep}] HTTP method tidak dideklarasikan")
    seen = set()
    for f in found:
        if f not in seen:
            seen.add(f)
            print("  !", f)
    return found


def self_check():
    data = load(FILES["draft"])
    # warisan: lecturer mewarisi student
    assert "read_grades" in effective_permissions(data, "lecturer")
    # draft: 'all' + endpoint berbasis allowed_roles → admin boleh apa saja
    assert allowed(data, "admin", "/api/users/delete")
    # draft: endpoint nilai hanya cek nama role, tak ada kepemilikan → dosen mana pun lolos
    assert allowed(data, "lecturer", "/api/grades/update")
    assert not data["endpoints"]["/api/grades/update"].get("enforce_ownership_check")
    # draft: izin edit_grades diberikan ke guest_lecturer tapi endpoint tak pernah mengizinkannya
    assert "edit_grades" in effective_permissions(data, "guest_lecturer")
    assert not allowed(data, "guest_lecturer", "/api/grades/update")

    fixed = load(FILES["fix"])
    # di versi fix, student tidak lagi mewarisi ke lecturer
    assert "grades:read:self" not in effective_permissions(fixed, "lecturer")
    # guest_lecturer tidak lagi punya hak ubah nilai
    assert not allowed(fixed, "guest_lecturer", "/api/grades/update")
    # admin hanya lewat users:deactivate untuk endpoint delete
    assert allowed(fixed, "admin", "/api/users/delete")
    # student tetap boleh lihat katalog (courses:view:enrolled)
    assert allowed(fixed, "student", "/api/courses/view")
    print("self-check OK")


if __name__ == "__main__":
    self_check()
    for name, path in FILES.items():
        if not path.exists():
            sys.exit(f"file tidak ditemukan: {path}")
        data = load(path)
        report(name, data)
        print(f"--- temuan {name}:")
        audit(data)
