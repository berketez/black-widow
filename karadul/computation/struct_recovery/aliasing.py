"""Alias analizi — same_object ve same_type ayrimiyla.

KRITIK UYARI (Codex):
    Tek bir `same(x, y)` iliskisi YETMEZ. Struct recovery sessizce
    yanlis sonuc uretir cunku:
        - x ve y ayni tipte ama FARKLI instance'lar olabilir.
        - Solver bunlari ayni class'a atarsa, iki ayri yasam dongusu
          tek bir struct gibi gorunur ve offset cakismalari yaratir.

Bu yuzden iki AYRI iliski tutariz:
    - ``must_alias`` (same_object): SSA copy/phi/pointer-equality
      analizinden gelen KESIN ayni-instance cifti. Birlestirilir.
    - ``type_hints`` (same_type): tip-tabanli gruplama. Ayri class
      olsalar bile solver'a "ayni struct secilmeli" kisitini getirir.

Kullanim:
    analyzer = AliasingAnalyzer()
    classes = analyzer.build_classes(
        variables=["p", "q", "r", "s"],
        must_alias=[("p", "q")],          # p ve q ayni instance
        type_hints={"p": "T", "q": "T", "r": "T", "s": "U"},
    )
    # Sonuc: 3 class (p+q birlesir; r tek; s tek).
    # type_family: {p,q}:"T", {r}:"T" (ayni aile), {s}:"U".
"""

from __future__ import annotations

import hashlib
from typing import Optional

from karadul.computation.struct_recovery.types import AliasClass, MemoryAccess


class _UnionFind:
    """Klasik union-find — SSA must-alias birlestirme icin."""

    def __init__(self, items: list[str]) -> None:
        self._parent: dict[str, str] = {x: x for x in items}
        self._rank: dict[str, int] = {x: 0 for x in items}

    def find(self, x: str) -> str:
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        # Path compression.
        while self._parent[x] != root:
            nxt = self._parent[x]
            self._parent[x] = root
            x = nxt
        return root

    def union(self, x: str, y: str) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self._rank[rx] < self._rank[ry]:
            rx, ry = ry, rx
        self._parent[ry] = rx
        if self._rank[rx] == self._rank[ry]:
            self._rank[rx] += 1

    def groups(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for item in self._parent:
            root = self.find(item)
            out.setdefault(root, []).append(item)
        return out


class AliasingAnalyzer:
    """must_alias -> same_object, type_hints -> same_type.

    Cikti: ``AliasClass`` listesi. Her class bir ``same_object`` kumesi
    ve bir ``type_family`` kimligi tasir. Ayni type_family'ye sahip iki
    class, solver'da ayni aday struct'a zorlanacak ama birbirlerinin
    erisim listelerini KARISTIRMAYACAK.

    v1.10.0 Batch 6A (Codex matematik audit): Eski surum TUM type-hint'siz
    degiskenleri tekil ``__unknown__`` ailesine dusuruyordu. encoder.py H4
    hard equality ayni aileye giren TUM class'lari ayni adaya zorladigi
    icin alakasiz (hatta farkli fonksiyonlara ait) degiskenler sessizce
    tek struct'a coupling yapiyordu. Artik her type-hint'siz must_alias
    component'ina BENZERSIZ (``__unknown_<hash>__``) aile ismi verilir;
    boylece H4 sadece ayni instance'in varyantlarini esitler, bagimsiz
    unknown'lari birbirine yapistirmaz.
    """

    _UNKNOWN_FAMILY_PREFIX = "__unknown_"

    @classmethod
    def is_unknown_family(cls, family: str) -> bool:
        """Bir aile ismi 'bilinmeyen' (unique-per-component) mi?

        encoder.py H4 bunu kullanip ayni isim-prefix'li aileleri birbirine
        esitleme riskini ortadan kaldirmak icin skip kontrolunde kullanir.
        """
        return family.startswith(cls._UNKNOWN_FAMILY_PREFIX)

    def build_classes(
        self,
        variables: list[str],
        must_alias: list[tuple[str, str]],
        type_hints: Optional[dict[str, str]] = None,
    ) -> list[AliasClass]:
        """Degisken listesinden alias class'lari kur.

        Args:
            variables: Tum degisken isimleri.
            must_alias: Kesin same_object ciftleri (SSA must-alias).
            type_hints: var -> type_family haritasi. Atlanmis var'lar
                her must_alias component'i icin BENZERSIZ bir
                ``__unknown_<hash>__`` ailesi alir; boylece bagimsiz
                gruplar encoder H4 ile yanlislikla couple edilmez.

        Returns:
            AliasClass listesi. Deterministik siralama: type_family,
            sonra ilk degisken adi.

        Raises:
            ValueError: Cakisan tip atamasi (ayni must_alias class'inda
                farkli type_hint'ler). Bu sessiz kabul edilemez —
                Codex uyarisinin ana sebebi.
        """
        if type_hints is None:
            type_hints = {}

        # Bilinmeyen degiskeni listeye ekle (must_alias'tan gelebilir).
        all_vars: set[str] = set(variables)
        for a, b in must_alias:
            all_vars.add(a)
            all_vars.add(b)

        uf = _UnionFind(sorted(all_vars))
        for a, b in must_alias:
            uf.union(a, b)

        # Her grup icin type_family belirle.
        classes: list[AliasClass] = []
        # Deterministik siralama icin groups()'u root'a gore sirala; her
        # type-hint'siz component kendi __unknown_<hash>__ ailesini alacak.
        for _root, members in sorted(
            uf.groups().items(), key=lambda kv: kv[0],
        ):
            families: set[str] = set()
            for m in members:
                if m in type_hints:
                    families.add(type_hints[m])
            if len(families) > 1:
                # Cakisma: must_alias ile birlesen vars farkli tiplere
                # map edilmis. Bu coguzunlukla alt-sistem hatasidir.
                raise ValueError(
                    f"must_alias cakismasi: {sorted(members)} -> "
                    f"farkli tipler {sorted(families)}",
                )
            if families:
                family = next(iter(families))
            else:
                # BENZERSIZ unknown family: component uyelerinin stabil
                # (sorted) join'inden blake2b hash. id() kullanmiyoruz cunku
                # determinizm kritik (cache/test/repro).
                key = "|".join(sorted(members))
                digest = hashlib.blake2b(
                    key.encode("utf-8"), digest_size=8,
                ).hexdigest()
                family = f"{self._UNKNOWN_FAMILY_PREFIX}{digest}__"
            classes.append(
                AliasClass(
                    variables=sorted(members),
                    type_family=family,
                ),
            )

        # Deterministik sirala.
        classes.sort(key=lambda c: (c.type_family, c.variables[0]))
        return classes

    def group_accesses_by_class(
        self,
        classes: list[AliasClass],
        access_var_names: list[str],
    ) -> dict[int, list[int]]:
        """Erisim indekslerini ait olduklari class indeksine grupla.

        Args:
            classes: ``build_classes`` ciktisi.
            access_var_names: Her erisimin var_name'i (index==access index).

        Returns:
            class_index -> access index listesi. Sinifsiz erisimler
            dahil EDILMEZ (bunlar unknown_i olarak modellenir).
        """
        var_to_class: dict[str, int] = {}
        for ci, cls in enumerate(classes):
            for v in cls.variables:
                var_to_class[v] = ci
        out: dict[int, list[int]] = {}
        for ai, v in enumerate(access_var_names):
            if v in var_to_class:
                out.setdefault(var_to_class[v], []).append(ai)
        return out

    def family_to_classes(
        self,
        classes: list[AliasClass],
    ) -> dict[str, list[int]]:
        """type_family -> bu aileye ait class indeksleri.

        Solver'in ayni aileye tek aday atamasi icin gerekli.
        """
        out: dict[str, list[int]] = {}
        for ci, cls in enumerate(classes):
            out.setdefault(cls.type_family, []).append(ci)
        return out

    def find_connected_components(
        self,
        classes: list[AliasClass],
    ) -> list[list[int]]:
        """Ayni scope'taki alias class'lari disjoint "solve unit"lere bol.

        v1.10.0 Batch 6D (FIX 5 full): Paralel solve icin, birbirini etkilemeyen
        class gruplari ayri Z3 Optimize oturumlarinda cozulebilir. Iki class
        birbirini **etkiler** ancak su durumlarda:
            - Ayni type_family'ye aitse (encoder H4 hard equality birbirine
              kilitler) -> ayni component.
            - Class'larin variable setleri kesissiyorsa (teorik; `build_classes`
              sonrasi genellikle disjoint ama defansif).

        Bu yuzden component'ler yukaridaki iliskilerin uzerinde run edilen
        union-find'in ciktisidir. Type-hint'siz family'ler (``__unknown_<hash>__``)
        her class icin BENZERSIZ oldugu icin DOGAL olarak kendi component'lerine
        duser — bu kritik kazanim.

        Args:
            classes: ``build_classes`` ciktisi.

        Returns:
            List of class-index lists; her icteki liste bir component
            olusturur. Deterministik siralama: her component icinde indeksler
            artan, component'ler ilk indeksine gore artan.
        """
        if not classes:
            return []

        # Union-find class indeksleri uzerinde.
        idx_uf = _UnionFind([str(i) for i in range(len(classes))])

        # Kural 1: Ayni type_family -> birlestir. Unknown family'ler dogal
        # olarak benzersiz (her class farkli family) oldugundan bu kural
        # onlari birlestirmez.
        family_to_idx: dict[str, list[int]] = {}
        for ci, cls in enumerate(classes):
            family_to_idx.setdefault(cls.type_family, []).append(ci)
        for _family, idxs in family_to_idx.items():
            if len(idxs) < 2:
                continue
            first = idxs[0]
            for other in idxs[1:]:
                idx_uf.union(str(first), str(other))

        # Kural 2: variable seti kesisimi -> birlestir (defansif; genelde
        # build_classes disjoint uretir ama dis cagricilar manuel class
        # kurabilir).
        var_to_first_idx: dict[str, int] = {}
        for ci, cls in enumerate(classes):
            for v in cls.variables:
                if v in var_to_first_idx:
                    idx_uf.union(str(var_to_first_idx[v]), str(ci))
                else:
                    var_to_first_idx[v] = ci

        # Component'leri topla.
        groups = idx_uf.groups()
        components: list[list[int]] = []
        for _root, members in groups.items():
            sorted_members = sorted(int(m) for m in members)
            components.append(sorted_members)

        # Deterministik: her component'in ilk indeksine gore sirala.
        components.sort(key=lambda c: c[0] if c else -1)
        return components

    def partition_accesses_by_component(
        self,
        classes: list[AliasClass],
        components: list[list[int]],
        accesses: list[MemoryAccess],
    ) -> tuple[list[list[AliasClass]], list[list[MemoryAccess]], list[MemoryAccess]]:
        """Component'lere gore class + access partition'lari uret.

        Args:
            classes: Tum alias class'lar.
            components: ``find_connected_components`` ciktisi.
            accesses: Tum memory access'ler.

        Returns:
            (per_component_classes, per_component_accesses, orphan_accesses).
            Orphan: hicbir class'a ait olmayan access'ler (var_name
            classes'taki hicbir variable'a esit degil). Bunlar zorunlu
            unknown olarak toplu aggregate sonuca eklenir.
        """
        var_to_component: dict[str, int] = {}
        per_component_classes: list[list[AliasClass]] = []
        for comp_idx, class_idxs in enumerate(components):
            comp_classes: list[AliasClass] = []
            for ci in class_idxs:
                cls = classes[ci]
                comp_classes.append(cls)
                for v in cls.variables:
                    var_to_component[v] = comp_idx
            per_component_classes.append(comp_classes)

        per_component_accesses: list[list[MemoryAccess]] = [
            [] for _ in components
        ]
        orphan_accesses: list[MemoryAccess] = []
        for acc in accesses:
            comp_idx = var_to_component.get(acc.var_name)
            if comp_idx is None:
                orphan_accesses.append(acc)
            else:
                per_component_accesses[comp_idx].append(acc)

        return per_component_classes, per_component_accesses, orphan_accesses
