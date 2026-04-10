#!/usr/bin/env python3
"""
gen_cpp_stl_sigs.py - C++ STL Mangled Name Signature Generator for Karadul

Strateji:
1. Her STL bileseni icin minimal C++ dosyasi olustur
2. clang++ ile derle (-O0, template instantiation zorlama)
3. nm ile mangled sembolleri cikar
4. c++filt ile demangle et
5. JSON'a yaz

macOS libc++ (std::__1::) ve Linux libstdc++ (std::) mangling farkliliklari
dikkate alinir.
"""

import json
import os
import subprocess
import sys
import tempfile
import re
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# ============================================================
# C++ Test Dosyalari
# Her dosya bir STL bilesenini kapsamli sekilde kullanir.
# Trick: template fonksiyonlari "kullanmak" lazim ki derleyici
# onlari instantiate etsin. Sadece header include etmek yetmez.
# ============================================================

CPP_SOURCES = {}

# --------------------------------------------------
# CONTAINERS
# --------------------------------------------------

CPP_SOURCES["vector"] = r"""
#include <vector>
#include <string>
#include <algorithm>

// Force instantiation for common types
template class std::vector<int>;
template class std::vector<double>;
template class std::vector<float>;
template class std::vector<char>;
template class std::vector<long>;
template class std::vector<unsigned>;
template class std::vector<unsigned long>;
template class std::vector<bool>;
template class std::vector<void*>;
template class std::vector<std::string>;
template class std::vector<std::vector<int>>;

__attribute__((used)) void use_vector_int() {
    std::vector<int> v;
    v.push_back(1);
    v.pop_back();
    v.emplace_back(42);
    v.insert(v.begin(), 1);
    v.erase(v.begin());
    v.resize(10);
    v.reserve(20);
    v.clear();
    v.shrink_to_fit();
    v.swap(v);
    v.assign(5, 0);
    volatile auto s = v.size();
    volatile auto c = v.capacity();
    volatile auto e = v.empty();
    volatile auto f = v.front();
    volatile auto b = v.back();
    volatile auto d = v.data();
    volatile auto it = v.begin();
    volatile auto eit = v.end();
    volatile auto rit = v.rbegin();
    volatile auto reit = v.rend();
    volatile auto ref = v.at(0);
    volatile auto ref2 = v[0];
    (void)s; (void)c; (void)e; (void)f; (void)b; (void)d;
    (void)it; (void)eit; (void)rit; (void)reit; (void)ref; (void)ref2;
}

__attribute__((used)) void use_vector_double() {
    std::vector<double> v;
    v.push_back(1.0);
    v.emplace_back(2.0);
    v.resize(10);
    v.reserve(20);
    volatile auto s = v.size();
    volatile auto d = v.data();
    (void)s; (void)d;
}

__attribute__((used)) void use_vector_string() {
    std::vector<std::string> v;
    v.push_back("hello");
    v.emplace_back("world");
    v.resize(10);
    volatile auto s = v.size();
    (void)s;
}
"""

CPP_SOURCES["map"] = r"""
#include <map>
#include <string>

template class std::map<int, int>;
template class std::map<std::string, int>;
template class std::map<std::string, std::string>;
template class std::map<int, std::string>;
template class std::map<int, double>;

template class std::multimap<int, int>;
template class std::multimap<std::string, int>;

__attribute__((used)) void use_map() {
    std::map<std::string, int> m;
    m.insert({"key", 1});
    m.emplace("key2", 2);
    m.erase("key");
    m.clear();
    m["key3"] = 3;
    volatile auto s = m.size();
    volatile auto e = m.empty();
    volatile auto it = m.begin();
    volatile auto eit = m.end();
    volatile auto f = m.find("key");
    volatile auto c = m.count("key");
    volatile auto lb = m.lower_bound("a");
    volatile auto ub = m.upper_bound("z");
    volatile auto er = m.equal_range("key");
    (void)s; (void)e; (void)it; (void)eit; (void)f; (void)c;
    (void)lb; (void)ub; (void)er;

    std::map<int, int> m2;
    m2[1] = 2;
    m2.insert({3, 4});
    volatile auto s2 = m2.size();
    (void)s2;
}
"""

CPP_SOURCES["unordered_map"] = r"""
#include <unordered_map>
#include <string>

template class std::unordered_map<int, int>;
template class std::unordered_map<std::string, int>;
template class std::unordered_map<std::string, std::string>;
template class std::unordered_map<int, std::string>;

template class std::unordered_multimap<int, int>;
template class std::unordered_multimap<std::string, int>;

__attribute__((used)) void use_unordered_map() {
    std::unordered_map<std::string, int> m;
    m.insert({"key", 1});
    m.emplace("key2", 2);
    m.erase("key");
    m.clear();
    m["key3"] = 3;
    volatile auto s = m.size();
    volatile auto e = m.empty();
    volatile auto it = m.begin();
    volatile auto eit = m.end();
    volatile auto f = m.find("key");
    volatile auto c = m.count("key");
    volatile auto bc = m.bucket_count();
    volatile auto lf = m.load_factor();
    volatile auto mlf = m.max_load_factor();
    m.rehash(100);
    m.reserve(200);
    (void)s; (void)e; (void)it; (void)eit; (void)f; (void)c;
    (void)bc; (void)lf; (void)mlf;
}
"""

CPP_SOURCES["set"] = r"""
#include <set>
#include <string>

template class std::set<int>;
template class std::set<double>;
template class std::set<std::string>;
template class std::set<char>;

template class std::multiset<int>;
template class std::multiset<std::string>;

__attribute__((used)) void use_set() {
    std::set<int> s;
    s.insert(1);
    s.emplace(2);
    s.erase(1);
    s.clear();
    volatile auto sz = s.size();
    volatile auto e = s.empty();
    volatile auto it = s.begin();
    volatile auto f = s.find(1);
    volatile auto c = s.count(1);
    volatile auto lb = s.lower_bound(0);
    volatile auto ub = s.upper_bound(10);
    (void)sz; (void)e; (void)it; (void)f; (void)c; (void)lb; (void)ub;

    std::set<std::string> ss;
    ss.insert("hello");
    volatile auto sf = ss.find("hello");
    (void)sf;
}
"""

CPP_SOURCES["unordered_set"] = r"""
#include <unordered_set>
#include <string>

template class std::unordered_set<int>;
template class std::unordered_set<std::string>;
template class std::unordered_set<double>;

template class std::unordered_multiset<int>;

__attribute__((used)) void use_unordered_set() {
    std::unordered_set<int> s;
    s.insert(1);
    s.emplace(2);
    s.erase(1);
    s.clear();
    volatile auto sz = s.size();
    volatile auto e = s.empty();
    volatile auto it = s.begin();
    volatile auto f = s.find(1);
    volatile auto c = s.count(1);
    s.rehash(100);
    s.reserve(200);
    (void)sz; (void)e; (void)it; (void)f; (void)c;
}
"""

CPP_SOURCES["list"] = r"""
#include <list>
#include <string>

template class std::list<int>;
template class std::list<double>;
template class std::list<std::string>;

__attribute__((used)) void use_list() {
    std::list<int> l;
    l.push_back(1);
    l.push_front(0);
    l.pop_back();
    l.pop_front();
    l.emplace_back(2);
    l.emplace_front(-1);
    l.insert(l.begin(), 3);
    l.erase(l.begin());
    l.clear();
    l.resize(10);
    l.sort();
    l.reverse();
    l.unique();
    std::list<int> l2;
    l.merge(l2);
    l.splice(l.begin(), l2);
    l.remove(1);
    volatile auto s = l.size();
    volatile auto e = l.empty();
    volatile auto f = l.front();
    volatile auto b = l.back();
    (void)s; (void)e; (void)f; (void)b;
}
"""

CPP_SOURCES["deque"] = r"""
#include <deque>
#include <string>

template class std::deque<int>;
template class std::deque<double>;
template class std::deque<std::string>;

__attribute__((used)) void use_deque() {
    std::deque<int> d;
    d.push_back(1);
    d.push_front(0);
    d.pop_back();
    d.pop_front();
    d.emplace_back(2);
    d.emplace_front(-1);
    d.insert(d.begin(), 3);
    d.erase(d.begin());
    d.clear();
    d.resize(10);
    d.shrink_to_fit();
    volatile auto s = d.size();
    volatile auto e = d.empty();
    volatile auto f = d.front();
    volatile auto b = d.back();
    volatile auto ref = d.at(0);
    volatile auto ref2 = d[0];
    (void)s; (void)e; (void)f; (void)b; (void)ref; (void)ref2;
}
"""

CPP_SOURCES["array_stack_queue"] = r"""
#include <array>
#include <stack>
#include <queue>
#include <string>

template class std::array<int, 10>;
template class std::array<double, 10>;
template class std::array<float, 4>;
template class std::array<char, 256>;

__attribute__((used)) void use_array_stack_queue() {
    std::array<int, 10> a;
    volatile auto s = a.size();
    volatile auto e = a.empty();
    volatile auto d = a.data();
    volatile auto f = a.front();
    volatile auto b = a.back();
    volatile auto ref = a.at(0);
    a.fill(0);
    (void)s; (void)e; (void)d; (void)f; (void)b; (void)ref;

    std::stack<int> st;
    st.push(1);
    st.emplace(2);
    st.pop();
    volatile auto st_s = st.size();
    volatile auto st_e = st.empty();
    volatile auto st_t = st.top();
    (void)st_s; (void)st_e; (void)st_t;

    std::queue<int> q;
    q.push(1);
    q.emplace(2);
    q.pop();
    volatile auto q_s = q.size();
    volatile auto q_e = q.empty();
    volatile auto q_f = q.front();
    volatile auto q_b = q.back();
    (void)q_s; (void)q_e; (void)q_f; (void)q_b;

    std::priority_queue<int> pq;
    pq.push(1);
    pq.emplace(2);
    pq.pop();
    volatile auto pq_s = pq.size();
    volatile auto pq_e = pq.empty();
    volatile auto pq_t = pq.top();
    (void)pq_s; (void)pq_e; (void)pq_t;
}
"""

# --------------------------------------------------
# STRING
# --------------------------------------------------

CPP_SOURCES["string"] = r"""
#include <string>
#include <string_view>

template class std::basic_string<char>;
template class std::basic_string<wchar_t>;
template class std::basic_string<char16_t>;
template class std::basic_string<char32_t>;

__attribute__((used)) void use_string() {
    std::string s = "hello";
    s += " world";
    s.append("!");
    s.push_back('x');
    s.pop_back();
    s.insert(0, "pre");
    s.erase(0, 3);
    s.replace(0, 5, "hi");
    s.clear();
    s.resize(10);
    s.reserve(100);
    s.shrink_to_fit();
    s.assign("new");
    volatile auto sz = s.size();
    volatile auto len = s.length();
    volatile auto cap = s.capacity();
    volatile auto e = s.empty();
    volatile auto cs = s.c_str();
    volatile auto d = s.data();
    volatile auto ref = s.at(0);
    volatile auto ref2 = s[0];
    volatile auto f = s.front();
    volatile auto b = s.back();
    volatile auto pos = s.find("e");
    volatile auto rpos = s.rfind("e");
    volatile auto ffo = s.find_first_of("aeiou");
    volatile auto fln = s.find_last_of("aeiou");
    volatile auto ffno = s.find_first_not_of("aeiou");
    volatile auto flno = s.find_last_not_of("aeiou");
    volatile auto sub = s.substr(0, 3);
    volatile auto cmp = s.compare("other");
    volatile auto it = s.begin();
    volatile auto eit = s.end();
    (void)sz; (void)len; (void)cap; (void)e; (void)cs; (void)d;
    (void)ref; (void)ref2; (void)f; (void)b;
    (void)pos; (void)rpos; (void)ffo; (void)fln; (void)ffno; (void)flno;
    (void)sub; (void)cmp; (void)it; (void)eit;

    std::wstring ws = L"wide";
    ws += L" string";
    volatile auto wsz = ws.size();
    (void)wsz;

    std::string_view sv = "view";
    volatile auto svs = sv.size();
    volatile auto svd = sv.data();
    volatile auto svf = sv.find("i");
    volatile auto svsub = sv.substr(0, 2);
    (void)svs; (void)svd; (void)svf; (void)svsub;
}

__attribute__((used)) void use_string_ops() {
    std::string a = "hello";
    std::string b = "world";
    volatile auto c = a + b;
    volatile bool eq = (a == b);
    volatile bool ne = (a != b);
    volatile bool lt = (a < b);
    volatile bool gt = (a > b);
    (void)c; (void)eq; (void)ne; (void)lt; (void)gt;

    // stoi, stol, stof, stod
    volatile auto i = std::stoi("42");
    volatile auto l = std::stol("42");
    volatile auto f = std::stof("3.14");
    volatile auto d = std::stod("3.14");
    volatile auto ts = std::to_string(42);
    (void)i; (void)l; (void)f; (void)d; (void)ts;
}
"""

# --------------------------------------------------
# ALGORITHMS
# --------------------------------------------------

CPP_SOURCES["algorithm"] = r"""
#include <algorithm>
#include <numeric>
#include <vector>
#include <string>
#include <functional>
#include <iterator>
#include <random>

__attribute__((used)) void use_algorithms() {
    std::vector<int> v = {5, 3, 1, 4, 2};
    std::vector<int> v2(5);

    // Sorting
    std::sort(v.begin(), v.end());
    std::stable_sort(v.begin(), v.end());
    std::partial_sort(v.begin(), v.begin() + 3, v.end());
    std::nth_element(v.begin(), v.begin() + 2, v.end());
    volatile bool sorted = std::is_sorted(v.begin(), v.end());

    // Searching
    volatile auto it = std::find(v.begin(), v.end(), 3);
    volatile auto fit = std::find_if(v.begin(), v.end(), [](int x){ return x > 2; });
    volatile auto lb = std::lower_bound(v.begin(), v.end(), 3);
    volatile auto ub = std::upper_bound(v.begin(), v.end(), 3);
    volatile bool bs = std::binary_search(v.begin(), v.end(), 3);
    volatile auto er = std::equal_range(v.begin(), v.end(), 3);
    volatile auto cnt = std::count(v.begin(), v.end(), 3);
    volatile auto cntif = std::count_if(v.begin(), v.end(), [](int x){ return x > 2; });

    // Copying
    std::copy(v.begin(), v.end(), v2.begin());
    std::copy_if(v.begin(), v.end(), v2.begin(), [](int x){ return x > 2; });
    std::copy_n(v.begin(), 3, v2.begin());
    std::copy_backward(v.begin(), v.end(), v2.end());
    std::move(v.begin(), v.end(), v2.begin());
    std::move_backward(v.begin(), v.end(), v2.end());

    // Transform
    std::transform(v.begin(), v.end(), v2.begin(), [](int x){ return x * 2; });

    // Fill / Generate
    std::fill(v.begin(), v.end(), 0);
    std::fill_n(v.begin(), 3, 42);
    std::generate(v.begin(), v.end(), [n=0]() mutable { return n++; });

    // Remove
    auto rit = std::remove(v.begin(), v.end(), 0);
    auto rif = std::remove_if(v.begin(), v.end(), [](int x){ return x < 2; });
    std::unique(v.begin(), v.end());

    // Min/Max
    volatile auto mn = std::min(1, 2);
    volatile auto mx = std::max(1, 2);
    volatile auto mm = std::minmax(1, 2);
    volatile auto mne = std::min_element(v.begin(), v.end());
    volatile auto mxe = std::max_element(v.begin(), v.end());
    volatile auto mme = std::minmax_element(v.begin(), v.end());

    // Heap
    std::make_heap(v.begin(), v.end());
    std::push_heap(v.begin(), v.end());
    std::pop_heap(v.begin(), v.end());
    std::sort_heap(v.begin(), v.end());

    // Permutations
    std::next_permutation(v.begin(), v.end());
    std::prev_permutation(v.begin(), v.end());
    std::reverse(v.begin(), v.end());
    std::rotate(v.begin(), v.begin() + 1, v.end());
    std::mt19937 rng{42};
    std::shuffle(v.begin(), v.end(), rng);

    // Numeric
    volatile auto sum = std::accumulate(v.begin(), v.end(), 0);
    volatile auto ip = std::inner_product(v.begin(), v.end(), v2.begin(), 0);
    std::partial_sum(v.begin(), v.end(), v2.begin());
    std::adjacent_difference(v.begin(), v.end(), v2.begin());
    std::iota(v.begin(), v.end(), 0);

    // Other
    std::swap(v[0], v[1]);
    std::iter_swap(v.begin(), v.begin() + 1);
    volatile bool eq = std::equal(v.begin(), v.end(), v2.begin());
    volatile auto mis = std::mismatch(v.begin(), v.end(), v2.begin());
    volatile bool lex = std::lexicographical_compare(v.begin(), v.end(), v2.begin(), v2.end());
    std::for_each(v.begin(), v.end(), [](int x){ (void)x; });
    volatile bool any = std::any_of(v.begin(), v.end(), [](int x){ return x > 3; });
    volatile bool all = std::all_of(v.begin(), v.end(), [](int x){ return x > 0; });
    volatile bool none = std::none_of(v.begin(), v.end(), [](int x){ return x < 0; });

    (void)sorted; (void)it; (void)fit; (void)lb; (void)ub; (void)bs;
    (void)er; (void)cnt; (void)cntif; (void)rit; (void)rif;
    (void)mn; (void)mx; (void)mm; (void)mne; (void)mxe; (void)mme;
    (void)sum; (void)ip; (void)eq; (void)mis; (void)lex;
    (void)any; (void)all; (void)none;
}

__attribute__((used)) void use_algorithms_double() {
    std::vector<double> v = {5.0, 3.0, 1.0, 4.0, 2.0};
    std::sort(v.begin(), v.end());
    volatile auto s = std::accumulate(v.begin(), v.end(), 0.0);
    volatile auto mn = std::min_element(v.begin(), v.end());
    volatile auto mx = std::max_element(v.begin(), v.end());
    (void)s; (void)mn; (void)mx;
}

__attribute__((used)) void use_algorithms_string() {
    std::vector<std::string> v = {"banana", "apple", "cherry"};
    std::sort(v.begin(), v.end());
    volatile auto it = std::find(v.begin(), v.end(), std::string("apple"));
    (void)it;
}
"""

# --------------------------------------------------
# STREAMS / IO
# --------------------------------------------------

CPP_SOURCES["iostream"] = r"""
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>

__attribute__((used)) void use_iostream() {
    // cout, cin, cerr, clog - these are extern objects
    std::cout << "hello" << std::endl;
    std::cout << 42 << std::endl;
    std::cout << 3.14 << std::endl;
    std::cerr << "error" << std::endl;

    std::string line;
    // Intentionally don't actually read from cin in compiled test
    // but reference the symbols
    auto& ref = std::cin;
    (void)ref;
}

__attribute__((used)) void use_fstream() {
    std::ifstream ifs("/dev/null");
    ifs.is_open();
    ifs.good();
    ifs.eof();
    ifs.fail();
    ifs.bad();
    std::string line;
    std::getline(ifs, line);
    ifs.close();

    std::ofstream ofs("/dev/null");
    ofs << "hello";
    ofs.write("data", 4);
    ofs.flush();
    ofs.close();

    std::fstream fs;
    fs.open("/dev/null", std::ios::in | std::ios::out);
    fs.close();
}

__attribute__((used)) void use_stringstream() {
    std::stringstream ss;
    ss << "hello " << 42 << " " << 3.14;
    volatile auto str = ss.str();
    (void)str;

    std::istringstream iss("42 3.14 hello");
    int i; double d; std::string s;
    iss >> i >> d >> s;

    std::ostringstream oss;
    oss << std::setw(10) << std::setfill('0') << 42;
    oss << std::fixed << std::setprecision(2) << 3.14;
    oss << std::hex << 255;
    volatile auto ostr = oss.str();
    (void)ostr;
}
"""

# --------------------------------------------------
# MEMORY / SMART POINTERS
# --------------------------------------------------

CPP_SOURCES["memory"] = r"""
#include <memory>
#include <string>
#include <vector>

struct TestObj {
    int x;
    std::string name;
    TestObj() : x(0), name("default") {}
    TestObj(int x, std::string n) : x(x), name(std::move(n)) {}
    virtual ~TestObj() = default;
    virtual int getValue() { return x; }
};

struct DerivedObj : TestObj {
    DerivedObj() : TestObj(1, "derived") {}
    int getValue() override { return x * 2; }
};

__attribute__((used)) void use_unique_ptr() {
    auto p1 = std::make_unique<int>(42);
    auto p2 = std::make_unique<TestObj>(1, "hello");
    auto p3 = std::make_unique<int[]>(10);

    volatile auto raw = p1.get();
    volatile auto val = *p1;
    volatile bool b = (bool)p1;
    p1.reset();
    p1.reset(new int(99));
    auto released = p2.release();
    delete released;
    (void)raw; (void)val; (void)b;

    std::unique_ptr<TestObj> base = std::make_unique<DerivedObj>();
    volatile auto v = base->getValue();
    (void)v;
}

__attribute__((used)) void use_shared_ptr() {
    auto p1 = std::make_shared<int>(42);
    auto p2 = std::make_shared<TestObj>(1, "hello");
    auto p3 = p1;  // copy

    volatile auto raw = p1.get();
    volatile auto val = *p1;
    volatile auto cnt = p1.use_count();
    volatile bool uniq = p1.unique();
    volatile bool b = (bool)p1;
    p1.reset();
    p1.reset(new int(99));
    (void)raw; (void)val; (void)cnt; (void)uniq; (void)b;

    std::shared_ptr<TestObj> base = std::make_shared<DerivedObj>();
    auto derived = std::dynamic_pointer_cast<DerivedObj>(base);
    auto sbase = std::static_pointer_cast<TestObj>(derived);
    (void)derived; (void)sbase;
}

__attribute__((used)) void use_weak_ptr() {
    auto sp = std::make_shared<int>(42);
    std::weak_ptr<int> wp = sp;

    volatile auto cnt = wp.use_count();
    volatile bool exp = wp.expired();
    auto locked = wp.lock();
    wp.reset();
    (void)cnt; (void)exp; (void)locked;
}

__attribute__((used)) void use_allocator() {
    std::allocator<int> alloc;
    int* p = alloc.allocate(10);
    alloc.deallocate(p, 10);

    std::allocator<std::string> salloc;
    std::string* sp = salloc.allocate(5);
    salloc.deallocate(sp, 5);
}
"""

# --------------------------------------------------
# UTILITY
# --------------------------------------------------

CPP_SOURCES["utility"] = r"""
#include <utility>
#include <tuple>
#include <optional>
#include <variant>
#include <any>
#include <functional>
#include <string>
#include <typeinfo>

template class std::pair<int, int>;
template class std::pair<std::string, int>;
template class std::pair<int, std::string>;
template class std::pair<std::string, std::string>;

template class std::tuple<int>;
template class std::tuple<int, double>;
template class std::tuple<int, double, std::string>;
template class std::tuple<std::string, int, double>;

template class std::optional<int>;
template class std::optional<double>;
template class std::optional<std::string>;

__attribute__((used)) void use_pair() {
    auto p = std::make_pair(1, std::string("hello"));
    volatile auto f = p.first;
    volatile auto s = p.second;
    auto p2 = std::make_pair(std::string("key"), 42);
    (void)f; (void)s; (void)p2;
}

__attribute__((used)) void use_tuple() {
    auto t = std::make_tuple(1, 3.14, std::string("hello"));
    volatile auto v0 = std::get<0>(t);
    volatile auto v1 = std::get<1>(t);
    volatile auto v2 = std::get<2>(t);
    volatile auto sz = std::tuple_size<decltype(t)>::value;
    auto t2 = std::tie(v0, v1, v2);
    (void)v0; (void)v1; (void)v2; (void)sz; (void)t2;
}

__attribute__((used)) void use_optional() {
    std::optional<int> o1;
    std::optional<int> o2 = 42;
    std::optional<std::string> o3 = "hello";

    volatile bool h1 = o1.has_value();
    volatile bool h2 = o2.has_value();
    volatile auto v = o2.value();
    volatile auto vor = o1.value_or(-1);
    o1.emplace(99);
    o1.reset();
    (void)h1; (void)h2; (void)v; (void)vor;

    volatile auto v3 = o3.value();
    (void)v3;
}

__attribute__((used)) void use_variant() {
    std::variant<int, double, std::string> v1 = 42;
    std::variant<int, double, std::string> v2 = 3.14;
    std::variant<int, double, std::string> v3 = std::string("hello");

    volatile auto idx = v1.index();
    volatile auto val = std::get<int>(v1);
    volatile auto* ptr = std::get_if<int>(&v1);
    volatile bool holds = std::holds_alternative<int>(v1);
    (void)idx; (void)val; (void)ptr; (void)holds;
}

__attribute__((used)) void use_any() {
    std::any a = 42;
    std::any b = std::string("hello");
    std::any c = 3.14;

    volatile bool h = a.has_value();
    volatile auto v = std::any_cast<int>(a);
    a.reset();
    a.emplace<std::string>("world");
    volatile auto& t = a.type();
    (void)h; (void)v; (void)t;
}

__attribute__((used)) void use_function() {
    std::function<int(int)> f1 = [](int x) { return x * 2; };
    std::function<void()> f2 = []() {};
    std::function<std::string(const std::string&)> f3 = [](const std::string& s) { return s + "!"; };

    volatile auto r1 = f1(21);
    f2();
    volatile auto r3 = f3("hello");
    volatile bool b = (bool)f1;
    (void)r1; (void)r3; (void)b;
}

__attribute__((used)) void use_typeinfo() {
    const auto& ti = typeid(int);
    const auto& ts = typeid(std::string);
    auto n = ti.name();
    bool eq = (ti == ts);
    (void)ti; (void)ts; (void)n; (void)eq;
}
"""

# --------------------------------------------------
# THREADING / CONCURRENCY
# --------------------------------------------------

CPP_SOURCES["threading"] = r"""
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <atomic>
#include <future>
#include <chrono>

__attribute__((used)) void use_thread() {
    std::thread t([]() {});
    t.join();

    std::thread t2([]() {});
    t2.detach();

    volatile auto id = std::this_thread::get_id();
    volatile auto hc = std::thread::hardware_concurrency();
    (void)id; (void)hc;
}

__attribute__((used)) void use_mutex() {
    std::mutex m;
    m.lock();
    m.unlock();
    volatile bool b = m.try_lock();
    (void)b;

    std::recursive_mutex rm;
    rm.lock();
    rm.unlock();

    std::timed_mutex tm;
    tm.lock();
    tm.unlock();

    {
        std::lock_guard<std::mutex> lg(m);
    }
    {
        std::unique_lock<std::mutex> ul(m);
        ul.unlock();
        ul.lock();
    }
    {
        std::shared_mutex sm;
        std::shared_lock<std::shared_mutex> sl(sm);
    }
}

__attribute__((used)) void use_condition_variable() {
    std::condition_variable cv;
    std::mutex m;
    std::unique_lock<std::mutex> ul(m);
    cv.notify_one();
    cv.notify_all();
    cv.wait(ul, []() { return true; });
}

__attribute__((used)) void use_atomic() {
    std::atomic<int> ai(0);
    ai.store(42);
    volatile auto v = ai.load();
    volatile auto prev = ai.exchange(99);
    int expected = 99;
    ai.compare_exchange_strong(expected, 100);
    ai.compare_exchange_weak(expected, 101);
    ai.fetch_add(1);
    ai.fetch_sub(1);
    ai.fetch_and(0xFF);
    ai.fetch_or(0x01);
    ai.fetch_xor(0x10);
    volatile bool lf = ai.is_lock_free();
    (void)v; (void)prev; (void)lf;

    std::atomic<bool> ab(false);
    ab.store(true);
    volatile auto bv = ab.load();
    (void)bv;

    std::atomic<long> al(0);
    al.fetch_add(1);
    volatile auto lv = al.load();
    (void)lv;

    std::atomic_flag af = ATOMIC_FLAG_INIT;
    af.test_and_set();
    af.clear();
}

__attribute__((used)) void use_future() {
    auto f1 = std::async(std::launch::async, []() { return 42; });
    volatile auto v = f1.get();
    (void)v;

    std::promise<int> p;
    auto f2 = p.get_future();
    p.set_value(99);
    volatile auto v2 = f2.get();
    (void)v2;

    std::packaged_task<int()> pt([]() { return 7; });
    auto f3 = pt.get_future();
    pt();
    volatile auto v3 = f3.get();
    (void)v3;
}
"""

# --------------------------------------------------
# CHRONO
# --------------------------------------------------

CPP_SOURCES["chrono"] = r"""
#include <chrono>

__attribute__((used)) void use_chrono() {
    auto now = std::chrono::system_clock::now();
    auto tp = std::chrono::system_clock::to_time_t(now);
    auto from = std::chrono::system_clock::from_time_t(tp);
    (void)now; (void)tp; (void)from;

    auto steady_now = std::chrono::steady_clock::now();
    (void)steady_now;

    auto hi_now = std::chrono::high_resolution_clock::now();
    (void)hi_now;

    auto dur = std::chrono::seconds(5);
    auto ms = std::chrono::milliseconds(100);
    auto us = std::chrono::microseconds(1000);
    auto ns = std::chrono::nanoseconds(1000000);
    auto min = std::chrono::minutes(1);
    auto hr = std::chrono::hours(1);

    auto ms_count = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();
    (void)dur; (void)ms; (void)us; (void)ns; (void)min; (void)hr; (void)ms_count;

    auto start = std::chrono::steady_clock::now();
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    volatile auto cnt = elapsed.count();
    (void)cnt;
}
"""

# --------------------------------------------------
# FILESYSTEM
# --------------------------------------------------

CPP_SOURCES["filesystem"] = r"""
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

__attribute__((used)) void use_filesystem() {
    fs::path p("/tmp/test");
    fs::path p2 = p / "subdir" / "file.txt";

    volatile auto str = p.string();
    volatile auto stem = p.stem().string();
    volatile auto ext = p.extension().string();
    volatile auto fn = p.filename().string();
    volatile auto par = p.parent_path().string();
    volatile auto root = p.root_path().string();
    volatile bool abs = p.is_absolute();
    volatile bool rel = p.is_relative();
    volatile bool he = p.has_extension();
    volatile bool hf = p.has_filename();
    (void)str; (void)stem; (void)ext; (void)fn; (void)par; (void)root;
    (void)abs; (void)rel; (void)he; (void)hf;

    volatile bool ex = fs::exists("/tmp");
    volatile bool isdir = fs::is_directory("/tmp");
    volatile bool isreg = fs::is_regular_file("/tmp");
    volatile bool issym = fs::is_symlink("/tmp");
    volatile bool isempty = fs::is_empty("/tmp");
    (void)ex; (void)isdir; (void)isreg; (void)issym; (void)isempty;

    volatile auto sz = fs::file_size("/dev/null");
    volatile auto space = fs::space("/tmp");
    volatile auto cwd = fs::current_path();
    volatile auto tmp = fs::temp_directory_path();
    (void)sz; (void)space; (void)cwd; (void)tmp;

    // directory iteration
    for (auto& entry : fs::directory_iterator("/tmp")) {
        volatile auto ep = entry.path().string();
        volatile bool eis = entry.is_regular_file();
        (void)ep; (void)eis;
        break;  // just one iteration for symbols
    }
}
"""

# --------------------------------------------------
# REGEX
# --------------------------------------------------

CPP_SOURCES["regex"] = r"""
#include <regex>
#include <string>

__attribute__((used)) void use_regex() {
    std::regex r("\\d+");
    std::regex r2("[a-z]+", std::regex::icase);

    std::string text = "hello 42 world 99";
    std::smatch m;
    volatile bool found = std::regex_search(text, m, r);
    volatile bool match = std::regex_match(std::string("42"), r);
    auto replaced = std::regex_replace(text, r, "NUM");
    (void)found; (void)match; (void)replaced;

    if (found) {
        volatile auto full = m[0].str();
        volatile auto prefix = m.prefix().str();
        volatile auto suffix = m.suffix().str();
        volatile auto sz = m.size();
        volatile bool e = m.empty();
        (void)full; (void)prefix; (void)suffix; (void)sz; (void)e;
    }

    // Iterator
    auto begin = std::sregex_iterator(text.begin(), text.end(), r);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        volatile auto s = it->str();
        (void)s;
    }
}
"""

# --------------------------------------------------
# EXCEPTIONS
# --------------------------------------------------

CPP_SOURCES["exception"] = r"""
#include <exception>
#include <stdexcept>
#include <system_error>
#include <new>
#include <typeinfo>
#include <string>

__attribute__((used)) void use_exceptions() {
    try {
        throw std::runtime_error("runtime error");
    } catch (const std::runtime_error& e) {
        volatile auto w = e.what();
        (void)w;
    }

    try {
        throw std::logic_error("logic error");
    } catch (const std::logic_error& e) {
        volatile auto w = e.what();
        (void)w;
    }

    try { throw std::invalid_argument("invalid"); } catch (...) {}
    try { throw std::out_of_range("range"); } catch (...) {}
    try { throw std::overflow_error("overflow"); } catch (...) {}
    try { throw std::underflow_error("underflow"); } catch (...) {}
    try { throw std::domain_error("domain"); } catch (...) {}
    try { throw std::length_error("length"); } catch (...) {}
    try { throw std::range_error("range"); } catch (...) {}
    try { throw std::bad_alloc(); } catch (...) {}
    try { throw std::bad_cast(); } catch (...) {}
    try { throw std::bad_typeid(); } catch (...) {}

    volatile auto ep = std::current_exception();
    volatile auto nep = std::make_exception_ptr(std::runtime_error("test"));
    (void)ep; (void)nep;

    auto ec = std::make_error_code(std::errc::invalid_argument);
    volatile auto msg = ec.message();
    volatile auto val = ec.value();
    volatile auto cat = ec.category().name();
    (void)msg; (void)val; (void)cat;
}
"""

# --------------------------------------------------
# RANDOM
# --------------------------------------------------

CPP_SOURCES["random"] = r"""
#include <random>

__attribute__((used)) void use_random() {
    std::mt19937 gen(42);
    std::mt19937_64 gen64(42);
    std::minstd_rand minstd(42);
    std::default_random_engine dre(42);

    std::uniform_int_distribution<int> uid(0, 100);
    std::uniform_real_distribution<double> urd(0.0, 1.0);
    std::normal_distribution<double> nd(0.0, 1.0);
    std::bernoulli_distribution bd(0.5);
    std::poisson_distribution<int> pd(4.0);
    std::exponential_distribution<double> ed(1.0);
    std::discrete_distribution<int> dd({1.0, 2.0, 3.0});
    std::binomial_distribution<int> bid(10, 0.5);
    std::geometric_distribution<int> gd(0.5);
    std::chi_squared_distribution<double> csd(2.0);
    std::cauchy_distribution<double> cd(0.0, 1.0);
    std::gamma_distribution<double> gad(2.0, 1.0);
    std::lognormal_distribution<double> lnd(0.0, 1.0);

    volatile auto v1 = uid(gen);
    volatile auto v2 = urd(gen);
    volatile auto v3 = nd(gen);
    volatile auto v4 = bd(gen);
    volatile auto v5 = pd(gen);
    volatile auto v6 = ed(gen);
    volatile auto v7 = dd(gen);
    volatile auto v8 = bid(gen);
    volatile auto v9 = gd(gen);
    volatile auto v10 = csd(gen);
    volatile auto v11 = cd(gen);
    volatile auto v12 = gad(gen);
    volatile auto v13 = lnd(gen);
    volatile auto v14 = gen();
    volatile auto v15 = gen64();
    (void)v1; (void)v2; (void)v3; (void)v4; (void)v5; (void)v6; (void)v7;
    (void)v8; (void)v9; (void)v10; (void)v11; (void)v12; (void)v13;
    (void)v14; (void)v15;

    std::random_device rd;
    volatile auto rv = rd();
    (void)rv;

    std::seed_seq ss{1, 2, 3, 4, 5};
    gen.seed(ss);
}
"""

# --------------------------------------------------
# TYPE TRAITS (compile-time, but generate some symbols)
# --------------------------------------------------

CPP_SOURCES["typetraits"] = r"""
#include <type_traits>
#include <string>
#include <vector>
#include <memory>

// These are mostly compile-time, but explicit instantiation
// forces vtable/typeinfo generation for some

__attribute__((used)) void use_type_traits() {
    static_assert(std::is_integral<int>::value, "");
    static_assert(std::is_floating_point<double>::value, "");
    static_assert(std::is_pointer<int*>::value, "");
    static_assert(std::is_same<int, int>::value, "");
    static_assert(!std::is_same<int, double>::value, "");
    static_assert(std::is_class<std::string>::value, "");
    static_assert(std::is_default_constructible<std::string>::value, "");
    static_assert(std::is_copy_constructible<std::string>::value, "");
    static_assert(std::is_move_constructible<std::string>::value, "");

    // These generate actual symbols
    using decay_t = std::decay_t<const int&>;
    using remove_ref = std::remove_reference_t<int&>;
    using add_ptr = std::add_pointer_t<int>;

    volatile decay_t a = 42;
    volatile remove_ref b = 42;
    volatile add_ptr c = nullptr;
    (void)a; (void)b; (void)c;
}
"""

# --------------------------------------------------
# NUMERIC LIMITS / CMATH
# --------------------------------------------------

CPP_SOURCES["numeric"] = r"""
#include <limits>
#include <cmath>
#include <cstdlib>
#include <complex>

__attribute__((used)) void use_numeric_limits() {
    volatile auto imin = std::numeric_limits<int>::min();
    volatile auto imax = std::numeric_limits<int>::max();
    volatile auto fmin = std::numeric_limits<float>::min();
    volatile auto fmax = std::numeric_limits<float>::max();
    volatile auto finf = std::numeric_limits<float>::infinity();
    volatile auto fnan = std::numeric_limits<float>::quiet_NaN();
    volatile auto feps = std::numeric_limits<float>::epsilon();
    volatile auto dmin = std::numeric_limits<double>::min();
    volatile auto dmax = std::numeric_limits<double>::max();
    volatile auto dinf = std::numeric_limits<double>::infinity();
    volatile auto dnan = std::numeric_limits<double>::quiet_NaN();
    volatile auto deps = std::numeric_limits<double>::epsilon();
    (void)imin; (void)imax; (void)fmin; (void)fmax; (void)finf; (void)fnan; (void)feps;
    (void)dmin; (void)dmax; (void)dinf; (void)dnan; (void)deps;
}

__attribute__((used)) void use_cmath() {
    volatile auto a = std::sin(1.0);
    volatile auto b = std::cos(1.0);
    volatile auto c = std::tan(1.0);
    volatile auto d = std::asin(0.5);
    volatile auto e = std::acos(0.5);
    volatile auto f = std::atan(1.0);
    volatile auto g = std::atan2(1.0, 1.0);
    volatile auto h = std::exp(1.0);
    volatile auto i = std::log(1.0);
    volatile auto j = std::log10(1.0);
    volatile auto k = std::log2(1.0);
    volatile auto l = std::pow(2.0, 3.0);
    volatile auto m = std::sqrt(4.0);
    volatile auto n = std::cbrt(8.0);
    volatile auto o = std::abs(-1.0);
    volatile auto p = std::fabs(-1.0);
    volatile auto q = std::ceil(1.5);
    volatile auto r = std::floor(1.5);
    volatile auto s = std::round(1.5);
    volatile auto t = std::trunc(1.5);
    volatile auto u = std::fmod(5.0, 3.0);
    volatile auto v = std::remainder(5.0, 3.0);
    volatile auto w = std::hypot(3.0, 4.0);
    volatile bool x = std::isnan(0.0);
    volatile bool y = std::isinf(0.0);
    volatile bool z = std::isfinite(1.0);
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g; (void)h;
    (void)i; (void)j; (void)k; (void)l; (void)m; (void)n; (void)o; (void)p;
    (void)q; (void)r; (void)s; (void)t; (void)u; (void)v; (void)w;
    (void)x; (void)y; (void)z;
}

__attribute__((used)) void use_complex() {
    std::complex<double> c1(1.0, 2.0);
    std::complex<double> c2(3.0, 4.0);
    auto sum = c1 + c2;
    auto prod = c1 * c2;
    volatile auto re = sum.real();
    volatile auto im = sum.imag();
    volatile auto ab = std::abs(c1);
    volatile auto arg = std::arg(c1);
    volatile auto conj = std::conj(c1);
    volatile auto norm = std::norm(c1);
    (void)sum; (void)prod; (void)re; (void)im; (void)ab;
    (void)arg; (void)conj; (void)norm;

    std::complex<float> cf(1.0f, 2.0f);
    volatile auto cfr = cf.real();
    (void)cfr;
}
"""

# --------------------------------------------------
# BITSET / VALARRAY
# --------------------------------------------------

CPP_SOURCES["bitset_valarray"] = r"""
#include <bitset>
#include <valarray>
#include <string>

__attribute__((used)) void use_bitset() {
    std::bitset<32> b1(0xFF);
    std::bitset<64> b2(0xDEADBEEF);
    std::bitset<8> b3("10101010");

    volatile auto cnt = b1.count();
    volatile auto sz = b1.size();
    volatile bool any = b1.any();
    volatile bool none = b1.none();
    volatile bool all = b1.all();
    volatile bool t = b1.test(0);
    b1.set(0);
    b1.set(1, false);
    b1.reset(0);
    b1.flip();
    b1.flip(0);
    volatile auto str = b1.to_string();
    volatile auto ul = b1.to_ulong();
    volatile auto ull = b1.to_ullong();
    auto b4 = b1 & std::bitset<32>(b2.to_ullong());
    (void)cnt; (void)sz; (void)any; (void)none; (void)all; (void)t;
    (void)str; (void)ul; (void)ull; (void)b4;
}

__attribute__((used)) void use_valarray() {
    std::valarray<double> v1 = {1.0, 2.0, 3.0, 4.0, 5.0};
    std::valarray<double> v2 = {5.0, 4.0, 3.0, 2.0, 1.0};

    auto sum = v1 + v2;
    auto diff = v1 - v2;
    auto prod = v1 * v2;
    auto div = v1 / v2;
    auto neg = -v1;
    volatile auto s = v1.sum();
    volatile auto mn = v1.min();
    volatile auto mx = v1.max();
    volatile auto sz = v1.size();
    auto shifted = v1.shift(1);
    auto cshifted = v1.cshift(1);
    auto applied = v1.apply([](double x) { return x * 2; });
    v1.resize(10, 0.0);
    (void)sum; (void)diff; (void)prod; (void)div; (void)neg;
    (void)s; (void)mn; (void)mx; (void)sz;
    (void)shifted; (void)cshifted; (void)applied;
}
"""

# ============================================================
# COMPILATION & EXTRACTION
# ============================================================

def compile_and_extract(name: str, source: str, tmpdir: str) -> list:
    """Compile C++ source and extract mangled symbols."""
    cpp_file = os.path.join(tmpdir, f"stl_{name}.cpp")
    obj_file = os.path.join(tmpdir, f"stl_{name}.o")

    with open(cpp_file, "w") as f:
        f.write(source)

    # Compile with clang++ -O0 to keep all symbols
    # -fno-inline to prevent inlining
    # -std=c++17 for filesystem, optional, variant, any, string_view
    cmd = [
        "clang++", "-c", "-O0", "-fno-inline",
        "-std=c++17",
        "-Wno-unused-result", "-Wno-unused-value",
        "-Wno-unused-variable", "-Wno-unused-but-set-variable",
        "-o", obj_file, cpp_file
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  [WARN] {name}: compilation warnings/errors:")
        # Only print errors, not warnings
        for line in result.stderr.splitlines():
            if "error:" in line:
                print(f"    {line}")
        if not os.path.exists(obj_file):
            print(f"  [ERROR] {name}: compilation failed, skipping")
            return []

    # Extract symbols with nm
    # T = text (code), W = weak (template instantiations), S = other
    nm_cmd = ["nm", obj_file]
    nm_result = subprocess.run(nm_cmd, capture_output=True, text=True)
    if nm_result.returncode != 0:
        print(f"  [ERROR] {name}: nm failed")
        return []

    symbols = []
    for line in nm_result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            sym_type = parts[1]
            sym_name = parts[2]
            # T = text section, W = weak, S = data
            if sym_type in ("T", "W", "S", "t", "w"):
                if sym_name.startswith("_Z") or sym_name.startswith("__Z"):
                    symbols.append((sym_name, sym_type))
        elif len(parts) == 2:
            sym_type = parts[0]
            sym_name = parts[1]
            if sym_type in ("U",):  # undefined - external symbols
                if sym_name.startswith("_Z") or sym_name.startswith("__Z"):
                    symbols.append((sym_name, "U"))

    return symbols


def demangle_symbols(symbols: list) -> dict:
    """Demangle a list of symbols using c++filt."""
    if not symbols:
        return {}

    mangled_names = [s[0] for s in symbols]

    # Batch demangle
    input_text = "\n".join(mangled_names)
    result = subprocess.run(
        ["c++filt"],
        input=input_text,
        capture_output=True,
        text=True
    )

    demangled = result.stdout.splitlines()
    result_dict = {}
    for i, (mangled, sym_type) in enumerate(symbols):
        if i < len(demangled):
            result_dict[mangled] = (demangled[i], sym_type)

    return result_dict


def classify_symbol(demangled: str) -> tuple:
    """Classify a demangled symbol into category and a clean purpose string.

    Classification uses a priority system. The FIRST class name/pattern
    found in the symbol determines the category. This prevents e.g.
    'std::vector<int, std::allocator<int>>' from being classified as
    'cpp_memory' instead of 'cpp_container'.

    We look at the "outermost" type -- the first std:: qualified name
    that appears, which is typically the class the method belongs to.
    """
    # Remove ABI tags like [abi:ne200100]
    clean = re.sub(r'\[abi:\w+\]', '', demangled).strip()
    # Remove extra spaces
    clean = re.sub(r'\s+', ' ', clean)

    # Determine category based on namespace/class
    if "std::__1::" in clean:
        clean_for_cat = clean.replace("std::__1::", "std::")
    else:
        clean_for_cat = clean

    # Extract the primary class/function name.
    # For member functions like "std::vector<...>::push_back(...)"
    # we want "vector" as the primary identifier.
    # For free functions like "std::sort<...>(...)" we want "sort".

    # Strategy: find the first std:: token after any return type
    # The "primary" is what comes right after the outermost "std::"

    # Check categories in priority order.
    # Each check uses the primary class name (first significant std:: type).

    # Helper: check if the primary (outermost) std:: type matches
    def primary_type_is(names):
        """Check if the primary std:: type in the symbol matches any of the given names."""
        # Pattern: look for std::NAME< or std::NAME:: or std::NAME(
        for name in names:
            # Match std::NAME as the primary type (not inside template args)
            # We look for it NOT preceded by < or , which would indicate a template argument
            pattern = rf'std::{re.escape(name)}(?:<|::|$|\s|\()'
            if re.search(pattern, clean_for_cat):
                # But make sure it's not just in template args
                # Find position of this match
                m = re.search(pattern, clean_for_cat)
                if m:
                    pos = m.start()
                    # Count < and > before this position to see nesting depth
                    prefix = clean_for_cat[:pos]
                    depth = prefix.count('<') - prefix.count('>')
                    if depth <= 0:
                        return True
        return False

    category = "cpp_stl"

    # Container types - highest priority
    container_types = [
        "vector", "deque", "list", "forward_list",
        "map", "multimap", "unordered_map", "unordered_multimap",
        "set", "multiset", "unordered_set", "unordered_multiset",
        "array", "stack", "queue", "priority_queue",
    ]
    if primary_type_is(container_types):
        category = "cpp_container"
    elif primary_type_is(["__split_buffer", "__hash_table", "__tree"]):
        # Internal data structures used by containers
        category = "cpp_container"
    elif primary_type_is(["basic_string", "string", "wstring", "u16string", "u32string",
                          "basic_string_view", "string_view"]):
        category = "cpp_string"
    elif "char_traits" in clean_for_cat and "string" not in clean_for_cat.lower():
        category = "cpp_string"
    elif primary_type_is(["basic_ios", "basic_ostream", "basic_istream",
                          "basic_iostream", "basic_fstream", "basic_ifstream",
                          "basic_ofstream", "basic_stringstream", "basic_istringstream",
                          "basic_ostringstream", "basic_streambuf", "basic_filebuf",
                          "basic_stringbuf", "ios_base"]) \
            or any(x in clean_for_cat for x in ["std::cout", "std::cin", "std::cerr",
                                                  "std::clog", "std::endl", "getline"]):
        category = "cpp_io"
    elif primary_type_is(["unique_ptr", "shared_ptr", "weak_ptr",
                          "default_delete", "enable_shared_from_this",
                          "make_unique", "make_shared"]):
        category = "cpp_memory"
    elif primary_type_is(["allocator", "allocator_traits"]) and \
         not any(ct in clean_for_cat for ct in container_types) and \
         "basic_string" not in clean_for_cat:
        # Only classify as memory if allocator is the PRIMARY type,
        # not when it appears as a template param of containers
        category = "cpp_memory"
    elif primary_type_is(["thread", "mutex", "recursive_mutex", "timed_mutex",
                          "recursive_timed_mutex", "shared_mutex", "shared_timed_mutex",
                          "condition_variable", "condition_variable_any",
                          "atomic", "atomic_flag",
                          "future", "shared_future", "promise", "packaged_task",
                          "shared_lock", "unique_lock", "lock_guard", "scoped_lock",
                          "this_thread"]) \
            or "std::async" in clean_for_cat:
        category = "cpp_concurrency"
    elif primary_type_is(["basic_regex", "regex", "wregex",
                          "match_results", "smatch", "cmatch",
                          "sub_match", "regex_iterator", "sregex_iterator",
                          "regex_token_iterator"]) \
            or any(x in clean_for_cat for x in ["regex_search", "regex_match", "regex_replace"]):
        category = "cpp_regex"
    elif "filesystem" in clean_for_cat or "directory_entry" in clean_for_cat or \
         "directory_iterator" in clean_for_cat or \
         primary_type_is(["path"]):
        category = "cpp_filesystem"
    elif "chrono" in clean_for_cat or primary_type_is(["duration", "time_point",
                                                        "system_clock", "steady_clock",
                                                        "high_resolution_clock"]):
        category = "cpp_chrono"
    elif primary_type_is(["exception", "runtime_error", "logic_error",
                          "invalid_argument", "out_of_range", "overflow_error",
                          "underflow_error", "domain_error", "length_error",
                          "range_error", "bad_alloc", "bad_cast", "bad_typeid",
                          "bad_exception", "nested_exception",
                          "error_code", "error_condition", "error_category",
                          "system_error"]) \
            or any(x in clean_for_cat for x in ["current_exception", "make_exception_ptr",
                                                  "rethrow_exception"]):
        category = "cpp_exception"
    elif primary_type_is(["pair", "tuple", "optional", "variant", "any",
                          "function", "reference_wrapper", "type_info",
                          "type_index"]) \
            or any(x in clean_for_cat for x in ["any_cast", "holds_alternative",
                                                  "get_if", "make_pair", "make_tuple",
                                                  "make_optional"]):
        category = "cpp_utility"
    elif any(alg in clean_for_cat for alg in [
        "std::sort", "std::find", "std::copy", "std::transform",
        "std::accumulate", "std::count", "std::fill", "std::generate",
        "std::remove", "std::unique", "std::reverse", "std::rotate",
        "std::shuffle", "std::binary_search", "std::lower_bound",
        "std::upper_bound", "std::equal_range", "std::merge",
        "std::min_element", "std::max_element", "std::nth_element",
        "std::partial_sort", "std::stable_sort", "std::make_heap",
        "std::push_heap", "std::pop_heap", "std::sort_heap",
        "std::next_permutation", "std::prev_permutation",
        "std::for_each", "std::any_of", "std::all_of", "std::none_of",
        "std::mismatch", "std::lexicographical_compare",
        "std::inner_product", "std::partial_sum", "std::adjacent_difference",
        "std::iota", "std::equal", "std::swap",
    ]):
        category = "cpp_algorithm"
    elif any(r in clean_for_cat for r in [
        "mt19937", "minstd_rand", "default_random_engine",
        "uniform_int_distribution", "uniform_real_distribution",
        "normal_distribution", "bernoulli_distribution",
        "poisson_distribution", "exponential_distribution",
        "random_device", "seed_seq", "discrete_distribution",
        "binomial_distribution", "geometric_distribution",
        "chi_squared_distribution", "cauchy_distribution",
        "gamma_distribution", "lognormal_distribution",
        "mersenne_twister_engine", "linear_congruential_engine",
    ]):
        category = "cpp_random"
    elif "complex" in clean_for_cat or "valarray" in clean_for_cat or \
         "numeric_limits" in clean_for_cat:
        category = "cpp_numeric"
    elif "bitset" in clean_for_cat:
        category = "cpp_bitset"
    elif "initializer_list" in clean_for_cat:
        category = "cpp_utility"
    elif "ctype" in clean_for_cat or "locale" in clean_for_cat or "codecvt" in clean_for_cat:
        category = "cpp_locale"
    elif any(x in clean_for_cat for x in [
        "__wrap_iter", "__deque_iterator", "__list_iterator",
        "__tree_iterator", "__tree_const_iterator",
        "__hash_iterator", "__hash_const_iterator",
        "move_iterator", "reverse_iterator", "iterator_traits",
    ]):
        category = "cpp_iterator"
    elif any(x in clean_for_cat for x in [
        "__function", "std::__function", "__invoke",
        "__invoke_r", "__invoke_void_return_wrapper",
    ]):
        category = "cpp_utility"
    elif any(x in clean_for_cat for x in [
        "__hash_table", "__tree", "__split_buffer",
        "__bucket_list", "__hash_node", "__list_imp",
        "__list_node", "__allocation_guard",
    ]):
        # Internal data structures for containers
        category = "cpp_container"
    elif any(x in clean_for_cat for x in [
        "__optional_storage", "__variant_detail",
        "bad_optional_access", "bad_variant_access",
    ]):
        category = "cpp_utility"
    elif any(x in clean_for_cat for x in [
        "__atomic_base", "atomic_signal_fence",
        "atomic_thread_fence",
    ]):
        category = "cpp_concurrency"
    elif any(x in clean_for_cat for x in [
        "exception_ptr", "__nested",
    ]):
        category = "cpp_exception"

    return category, clean


def normalize_mangled(mangled: str) -> str:
    """
    Normalize macOS mangled name to cross-platform format.
    macOS adds extra underscore prefix: __Z -> _Z
    """
    if mangled.startswith("__Z"):
        return mangled[1:]  # Remove extra leading underscore
    return mangled


def generate_libstdcxx_variant(mangled: str, demangled: str) -> str | None:
    """
    Try to generate a libstdc++ mangled name from a libc++ one.

    libc++ uses std::__1:: namespace internally,
    but the mangling for public API should be similar.
    The main difference is:
    - libc++: Ns = std namespace, but sometimes uses __1 inline namespace
    - libstdc++: Uses substitution more aggressively

    For now, we strip ABI tags (B8ne200100 etc.) to get the "generic" form.
    """
    # Remove ABI version tags like B8ne200100, B7v160006, etc.
    generic = re.sub(r'B\d+\w+', '', mangled)
    if generic != mangled:
        return generic
    return None


def is_interesting_symbol(demangled: str) -> bool:
    """Filter out uninteresting internal symbols."""
    skip_patterns = [
        "__sanitizer",
        "__asan",
        "__msan",
        "___block_",
        "__cxx_global",
        "GCC_except_table",
        ".cold.",
        "typeinfo name for",
        "typeinfo for",
        "vtable for",
        "VTT for",
        "construction vtable",
        "guard variable",
        "non-virtual thunk",
        "virtual thunk",
        # Skip purely internal/helper symbols that aren't useful for recognition
        "__compressed_pair",
        "__value_type",
        "__node_type",
        "__begin_node",
        # Skip our test structs (not STL)
        "TestObj",
        "DerivedObj",
        # Skip use_* test functions themselves
        "use_vector", "use_map", "use_unordered", "use_set", "use_list",
        "use_deque", "use_array", "use_string", "use_pair", "use_tuple",
        "use_optional", "use_variant", "use_any", "use_function",
        "use_typeinfo", "use_thread", "use_mutex", "use_condition",
        "use_atomic", "use_future", "use_chrono", "use_filesystem",
        "use_regex", "use_exceptions", "use_random", "use_type_traits",
        "use_numeric", "use_cmath", "use_complex", "use_bitset",
        "use_valarray", "use_iostream", "use_fstream", "use_stringstream",
        "use_algorithms", "use_unique_ptr", "use_shared_ptr", "use_weak_ptr",
        "use_allocator",
    ]
    for pat in skip_patterns:
        if pat in demangled:
            return False

    # Keep symbols that are clearly from std namespace
    if "std::" in demangled:
        return True

    # Keep operator overloads (common in STL)
    if "operator" in demangled:
        return True

    return False


def build_purpose(demangled: str) -> str:
    """Build a clean purpose string from demangled name."""
    # Remove ABI tags
    clean = re.sub(r'\[abi:\w+\]', '', demangled).strip()
    # Normalize std::__1:: to std::
    clean = clean.replace("std::__1::", "std::")
    # Remove extra spaces
    clean = re.sub(r'\s+', ' ', clean)
    return clean


def main():
    output_path = "/Users/apple/Desktop/black-widow/sigs/cpp_stl_mangled.json"
    script_name = "gen_cpp_stl_sigs.py"

    print(f"=== C++ STL Mangled Name Signature Generator ===")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Output: {output_path}")
    print()

    all_signatures = {}
    category_counts = defaultdict(int)
    source_counts = defaultdict(int)

    with tempfile.TemporaryDirectory(prefix="karadul_stl_") as tmpdir:
        print(f"Temp dir: {tmpdir}")
        print()

        for name, source in CPP_SOURCES.items():
            print(f"[{name}] Compiling...")
            symbols = compile_and_extract(name, source, tmpdir)
            print(f"  Raw symbols: {len(symbols)}")

            # Demangle
            demangled_map = demangle_symbols(symbols)
            print(f"  Demangled: {len(demangled_map)}")

            kept = 0
            for mangled, (demangled, sym_type) in demangled_map.items():
                if not is_interesting_symbol(demangled):
                    continue

                category, clean_demangled = classify_symbol(demangled)
                purpose = build_purpose(demangled)

                # Store with macOS mangled name (with __)
                normalized = normalize_mangled(mangled)

                if normalized not in all_signatures:
                    all_signatures[normalized] = {
                        "lib": "libc++",
                        "purpose": purpose,
                        "category": category,
                        "sym_type": sym_type
                    }
                    category_counts[category] += 1
                    source_counts[name] += 1
                    kept += 1

                # Also store macOS variant (with __ prefix) for direct matching
                if mangled.startswith("__Z") and mangled not in all_signatures:
                    all_signatures[mangled] = {
                        "lib": "libc++",
                        "purpose": purpose,
                        "category": category,
                        "sym_type": sym_type
                    }
                    category_counts[category] += 1
                    kept += 1

                # Generate ABI-tag-stripped variant (works across libc++ versions)
                generic = generate_libstdcxx_variant(normalized, demangled)
                if generic and generic not in all_signatures and generic != normalized:
                    all_signatures[generic] = {
                        "lib": "libstdc++/libc++",
                        "purpose": purpose,
                        "category": category,
                        "sym_type": sym_type
                    }
                    category_counts[category] += 1
                    kept += 1

            print(f"  Kept (interesting): {kept}")
            print()

    # Build output JSON
    # Convert sym_type codes to readable form
    sym_type_map = {
        "T": "defined",
        "W": "weak",
        "S": "data",
        "t": "local_text",
        "w": "local_weak",
        "U": "undefined"
    }

    output_sigs = {}
    for mangled, info in sorted(all_signatures.items()):
        output_sigs[mangled] = {
            "lib": info["lib"],
            "purpose": info["purpose"],
            "category": info["category"]
        }

    output = {
        "meta": {
            "generator": "karadul-sig-gen-cpp-stl",
            "script": script_name,
            "date": datetime.now().strftime("%Y-%m-%d"),
            "compiler": "Apple clang 17 (libc++, arm64-apple-darwin)",
            "std": "c++17",
            "description": "C++ STL mangled name signatures extracted from actual compiler output",
            "total": len(output_sigs),
            "stats": {
                "by_category": dict(sorted(category_counts.items(), key=lambda x: -x[1])),
                "by_source": dict(sorted(source_counts.items(), key=lambda x: -x[1]))
            }
        },
        "signatures": output_sigs
    }

    # Write output
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print("=" * 60)
    print(f"TOTAL signatures: {len(output_sigs)}")
    print()
    print("Category breakdown:")
    for cat, cnt in sorted(category_counts.items(), key=lambda x: -x[1]):
        print(f"  {cat}: {cnt}")
    print()
    print("Source file breakdown:")
    for src, cnt in sorted(source_counts.items(), key=lambda x: -x[1]):
        print(f"  {src}: {cnt}")
    print()
    print(f"Written to: {output_path}")


if __name__ == "__main__":
    main()
