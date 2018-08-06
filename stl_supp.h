//////////////////////////////////////////////////////////////////
//
// stl_supp.h
//
// Supplementary of STL
//
// Copyright (c) 2001-2018, Jan Willamowius
//
// Part of this code is adapted from the SGI implementation
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#ifndef STL_SUPP_H
#define STL_SUPP_H "@(#) $Id$"

#include <string>
#include <iterator>
#include <algorithm>
#include <functional>

// Composition adapter is not part of C++ standard
#if !defined(__GNUC__) || (defined(__GNUC__) && __GNUC__ >= 3)
template <class _Operation1, class _Operation2>
class unary_compose
	: public std::unary_function<typename _Operation2::argument_type,
                          typename _Operation1::result_type>
{
protected:
  _Operation1 __op1;
  _Operation2 __op2;
public:
  unary_compose(const _Operation1& __x, const _Operation2& __y)
    : __op1(__x), __op2(__y) {}
  typename _Operation1::result_type
  operator()(const typename _Operation2::argument_type& __x) const {
    return __op1(__op2(__x));
  }
};

template <class _Operation1, class _Operation2>
inline unary_compose<_Operation1,_Operation2>
compose1(const _Operation1& __op1, const _Operation2& __op2)
{
  return unary_compose<_Operation1,_Operation2>(__op1, __op2);
}
#else
using std::compose1;
#endif


// since VC6 didn't support partial specialization, use different names
template <class _Tp>
class mem_vfun_t : public std::unary_function<_Tp*,void> {
public:
  explicit mem_vfun_t(void (_Tp::*__pf)()) : _M_f(__pf) {}
  void operator()(_Tp* __p) const { (__p->*_M_f)(); }
private:
  void (_Tp::*_M_f)();
};

template <class _Tp>
class const_mem_vfun_t : public std::unary_function<const _Tp*,void> {
public:
  explicit const_mem_vfun_t(void (_Tp::*__pf)() const) : _M_f(__pf) {}
  void operator()(const _Tp* __p) const { (__p->*_M_f)(); }
private:
  void (_Tp::*_M_f)() const;
};

template <class _Tp>
class mem_vfun_ref_t : public std::unary_function<_Tp,void> {
public:
  explicit mem_vfun_ref_t(void (_Tp::*__pf)()) : _M_f(__pf) {}
  void operator()(_Tp& __r) const { (__r.*_M_f)(); }
private:
  void (_Tp::*_M_f)();
};

template <class _Tp>
class const_mem_vfun_ref_t : public std::unary_function<_Tp,void> {
public:
  explicit const_mem_vfun_ref_t(void (_Tp::*__pf)() const) : _M_f(__pf) {}
  void operator()(const _Tp& __r) const { (__r.*_M_f)(); }
private:
  void (_Tp::*_M_f)() const;
};

template <class _Tp, class _Arg>
class mem_vfun1_t : public std::binary_function<_Tp*,_Arg,void> {
public:
  explicit mem_vfun1_t(void (_Tp::*__pf)(_Arg)) : _M_f(__pf) {}
  void operator()(_Tp* __p, _Arg __x) const { (__p->*_M_f)(__x); }
private:
  void (_Tp::*_M_f)(_Arg);
};

template <class _Tp, class _Arg>
class const_mem_vfun1_t : public std::binary_function<const _Tp*,_Arg,void> {
public:
  explicit const_mem_vfun1_t(void (_Tp::*__pf)(_Arg) const) : _M_f(__pf) {}
  void operator()(const _Tp* __p, _Arg __x) const { (__p->*_M_f)(__x); }
private:
  void (_Tp::*_M_f)(_Arg) const;
};

template <class _Tp, class _Arg>
class mem_vfun1_ref_t : public std::binary_function<_Tp,_Arg,void> {
public:
  explicit mem_vfun1_ref_t(void (_Tp::*__pf)(_Arg)) : _M_f(__pf) {}
  void operator()(_Tp& __r, _Arg __x) const { (__r.*_M_f)(__x); }
private:
  void (_Tp::*_M_f)(_Arg);
};

template <class _Tp, class _Arg>
class const_mem_vfun1_ref_t : public std::binary_function<_Tp,_Arg,void> {
public:
  explicit const_mem_vfun1_ref_t(void (_Tp::*__pf)(_Arg) const) : _M_f(__pf) {}
  void operator()(const _Tp& __r, _Arg __x) const { (__r.*_M_f)(__x); }
private:
  void (_Tp::*_M_f)(_Arg) const;
};

template <class _Tp>
inline mem_vfun_t<_Tp> mem_vfun(void (_Tp::*__f)())
  { return mem_vfun_t<_Tp>(__f); }

template <class _Tp>
inline const_mem_vfun_t<_Tp> mem_vfun(void (_Tp::*__f)() const)
  { return const_mem_vfun_t<_Tp>(__f); }

template <class _Tp, class _Arg>
inline mem_vfun1_t<_Tp,_Arg> mem_vfun(void (_Tp::*__f)(_Arg))
  { return mem_vfun1_t<_Tp,_Arg>(__f); }

template <class _Tp, class _Arg>
inline const_mem_vfun1_t<_Tp,_Arg> mem_vfun(void (_Tp::*__f)(_Arg) const)
  { return const_mem_vfun1_t<_Tp,_Arg>(__f); }

template <class _Tp, class _Arg>
inline mem_vfun1_ref_t<_Tp,_Arg> mem_vfun_ref(void (_Tp::*__f)(_Arg))
  { return mem_vfun1_ref_t<_Tp,_Arg>(__f); }

template <class _Tp>
inline const_mem_vfun_ref_t<_Tp> mem_vfun_ref(void (_Tp::*__f)() const)
  { return const_mem_vfun_ref_t<_Tp>(__f); }

template <class _Tp, class _Arg>
inline const_mem_vfun1_ref_t<_Tp,_Arg> mem_vfun_ref(void (_Tp::*__f)(_Arg) const)
  { return const_mem_vfun1_ref_t<_Tp,_Arg>(__f); }

// end of partial specialization


struct str_prefix_greater : public std::binary_function<std::string, std::string, bool> {

	bool operator()(const std::string& s1, const std::string& s2) const
	{
		if (s1.size() == s2.size())
			return s1 > s2;
		else
			return s1.size() > s2.size();
	}
};

struct str_prefix_lesser : public std::binary_function<std::string, std::string, bool> {

	bool operator()(const std::string& s1, const std::string& s2) const
	{
		if (s1.size() == s2.size())
			return s1 < s2;
		else
			return s1.size() < s2.size();
	}
};

struct pstr_prefix_lesser : public std::binary_function<PString, PString, bool> {

	bool operator()(const PString& s1, const PString& s2) const
	{
		if (s1.GetLength() == s2.GetLength())
			return s1 < s2;
		else
			return s1.GetLength() < s2.GetLength();
	}
};


template <class PT>
class deleteobj { // PT is a pointer type
public:
	void operator()(PT pt) { delete pt; }
};

template <class PAIR>
class deletepair { // PAIR::second_type is a pointer type
public:
	void operator()(const PAIR & p) { delete p.second; }
};

template <class C, class F>
inline void ForEachInContainer(const C & c, const F & f)
{
	std::for_each(c.begin(), c.end(), f);
}

template <class C>
inline void DeleteObjectsInContainer(C & c)
{
	typedef typename C::value_type PT;
	std::for_each(c.begin(), c.end(), deleteobj<PT>());
	c.clear();
}

template <class M>
inline void DeleteObjectsInMap(M & m)
{
	typedef typename M::value_type PAIR;
	std::for_each(m.begin(), m.end(), deletepair<PAIR>());
	m.clear();
}

template <class PT>
inline void DeleteObjectsInArray(PT *begin, PT *end)
{
	std::for_each(begin, end, deleteobj<PT>());
}

template <class Iterator>
inline void DeleteObjects(Iterator begin, Iterator end)
{
	typedef typename Iterator::value_type PT;
	std::for_each(begin, end, deleteobj<PT>());
}

#endif  // STL_SUPP_H
