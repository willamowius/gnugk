//////////////////////////////////////////////////////////////////
//
// stl_supp.h
//
// Supplementary of STL
//
// The codes are adapted from SGI implementation
//
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
//      2001/09/03      initial version (Chih-Wei Huang)
//
//////////////////////////////////////////////////////////////////

#ifndef STL_SUPP_H
#define STL_SUPP_H "@(#) $Id$"

#include <iterator>
#include <algorithm>
#include <functional>

namespace std {

// Oops... the standard STL minus object is too restricted
template <class _Tp, class R>
struct Minus : public binary_function<_Tp,_Tp, R> {
  R operator()(const _Tp& __x, const _Tp& __y) const { return __x - __y; }
};

// Composition adaptor is not part of C++ standard
#if !defined(__GNUC__) || (defined(__GNUC__) && __GNUC__ >= 3)
template <class _Operation1, class _Operation2>
class unary_compose
  : public unary_function<typename _Operation2::argument_type,
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
#endif


#ifdef WIN32
#if (_MSC_VER <= 1200)
// VC++ didn't define these
template <class _Ret, class _Tp>
class const_mem_fun_t : public unary_function<const _Tp*,_Ret> {
public:
  explicit const_mem_fun_t(_Ret (_Tp::*__pf)() const) : _M_f(__pf) {}
  _Ret operator()(const _Tp* __p) const { return (__p->*_M_f)(); }
private:
  _Ret (_Tp::*_M_f)() const;
};

template <class _Ret, class _Tp>
class const_mem_fun_ref_t : public unary_function<_Tp,_Ret> {
public:
  explicit const_mem_fun_ref_t(_Ret (_Tp::*__pf)() const) : _M_f(__pf) {}
  _Ret operator()(const _Tp& __r) const { return (__r.*_M_f)(); }
private:
  _Ret (_Tp::*_M_f)() const;
};

template <class _Ret, class _Tp, class _Arg>
class const_mem_fun1_t : public binary_function<const _Tp*,_Arg,_Ret> {
public:
  explicit const_mem_fun1_t(_Ret (_Tp::*__pf)(_Arg) const) : _M_f(__pf) {}
  _Ret operator()(const _Tp* __p, _Arg __x) const
    { return (__p->*_M_f)(__x); }
private:
  _Ret (_Tp::*_M_f)(_Arg) const;
};

template <class _Ret, class _Tp, class _Arg>
class const_mem_fun1_ref_t : public binary_function<_Tp,_Arg,_Ret> {
public:
  explicit const_mem_fun1_ref_t(_Ret (_Tp::*__pf)(_Arg) const) : _M_f(__pf) {}
  _Ret operator()(const _Tp& __r, _Arg __x) const { return (__r.*_M_f)(__x); }
private:
  _Ret (_Tp::*_M_f)(_Arg) const;
};

template <class _Ret, class _Tp>
inline const_mem_fun_t<_Ret,_Tp> mem_fun(_Ret (_Tp::*__f)() const)
  { return const_mem_fun_t<_Ret,_Tp>(__f); }

template <class _Ret, class _Tp, class _Arg>
inline mem_fun1_t<_Ret,_Tp,_Arg> mem_fun(_Ret (_Tp::*__f)(_Arg))
  { return mem_fun1_t<_Ret,_Tp,_Arg>(__f); }

template <class _Ret, class _Tp, class _Arg>
inline const_mem_fun1_t<_Ret,_Tp,_Arg> mem_fun(_Ret (_Tp::*__f)(_Arg) const)
  { return const_mem_fun1_t<_Ret,_Tp,_Arg>(__f); }

template <class _Ret, class _Tp, class _Arg>
inline mem_fun1_ref_t<_Ret,_Tp,_Arg> mem_fun_ref(_Ret (_Tp::*__f)(_Arg))
  { return mem_fun1_ref_t<_Ret,_Tp,_Arg>(__f); }

template <class _Ret, class _Tp>
inline const_mem_fun_ref_t<_Ret,_Tp> mem_fun_ref(_Ret (_Tp::*__f)() const)
  { return const_mem_fun_ref_t<_Ret,_Tp>(__f); }

template <class _Ret, class _Tp, class _Arg>
inline const_mem_fun1_ref_t<_Ret,_Tp,_Arg> mem_fun_ref(_Ret (_Tp::*__f)(_Arg) const)
  { return const_mem_fun1_ref_t<_Ret,_Tp,_Arg>(__f); }

#ifdef min
#undef min
#endif

template <class _Tp>
inline const _Tp& min(const _Tp& __a, const _Tp& __b)
{
  return __b < __a ? __b : __a;
}

#ifdef max
#undef max
#endif

template <class _Tp>
inline const _Tp& max(const _Tp& __a, const _Tp& __b)
{
  return  __a < __b ? __b : __a;
}

#else
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif
#endif // _MSC_VER <= 1200
#endif // WIN32

struct str_prefix_greater : public binary_function<std::string, std::string, bool> {

	bool operator()(const std::string& s1, const std::string& s2) const 
	{
		if (s1.size() == s2.size())
			return s1 > s2;
		else
			return s1.size() > s2.size();
	}
};

struct pstr_prefix_lesser : public binary_function<PString, PString, bool> {

	bool operator()(const PString& s1, const PString& s2) const 
	{
		if (s1.GetLength() == s2.GetLength())
			return s1 < s2;
		else
			return s1.GetLength() < s2.GetLength();
	}
};

// since VC6 didn't support partial specialization, use different names
template <class _Tp>
class mem_vfun_t : public unary_function<_Tp*,void> {
public:
  explicit mem_vfun_t(void (_Tp::*__pf)()) : _M_f(__pf) {}
  void operator()(_Tp* __p) const { (__p->*_M_f)(); }
private:
  void (_Tp::*_M_f)();
};

template <class _Tp>
class const_mem_vfun_t : public unary_function<const _Tp*,void> {
public:
  explicit const_mem_vfun_t(void (_Tp::*__pf)() const) : _M_f(__pf) {}
  void operator()(const _Tp* __p) const { (__p->*_M_f)(); }
private:
  void (_Tp::*_M_f)() const;
};

template <class _Tp>
class mem_vfun_ref_t : public unary_function<_Tp,void> {
public:
  explicit mem_vfun_ref_t(void (_Tp::*__pf)()) : _M_f(__pf) {}
  void operator()(_Tp& __r) const { (__r.*_M_f)(); }
private:
  void (_Tp::*_M_f)();
};

template <class _Tp>
class const_mem_vfun_ref_t : public unary_function<_Tp,void> {
public:
  explicit const_mem_vfun_ref_t(void (_Tp::*__pf)() const) : _M_f(__pf) {}
  void operator()(const _Tp& __r) const { (__r.*_M_f)(); }
private:
  void (_Tp::*_M_f)() const;
};

template <class _Tp, class _Arg>
class mem_vfun1_t : public binary_function<_Tp*,_Arg,void> {
public:
  explicit mem_vfun1_t(void (_Tp::*__pf)(_Arg)) : _M_f(__pf) {}
  void operator()(_Tp* __p, _Arg __x) const { (__p->*_M_f)(__x); }
private:
  void (_Tp::*_M_f)(_Arg);
};

template <class _Tp, class _Arg>
class const_mem_vfun1_t : public binary_function<const _Tp*,_Arg,void> {
public:
  explicit const_mem_vfun1_t(void (_Tp::*__pf)(_Arg) const) : _M_f(__pf) {}
  void operator()(const _Tp* __p, _Arg __x) const { (__p->*_M_f)(__x); }
private:
  void (_Tp::*_M_f)(_Arg) const;
};

template <class _Tp, class _Arg>
class mem_vfun1_ref_t : public binary_function<_Tp,_Arg,void> {
public:
  explicit mem_vfun1_ref_t(void (_Tp::*__pf)(_Arg)) : _M_f(__pf) {}
  void operator()(_Tp& __r, _Arg __x) const { (__r.*_M_f)(__x); }
private:
  void (_Tp::*_M_f)(_Arg);
};

template <class _Tp, class _Arg>
class const_mem_vfun1_ref_t : public binary_function<_Tp,_Arg,void> {
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

} // end of namespace std


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
inline void DeleteObjectsInContainer(const C & c)
{
	typedef typename C::value_type PT;
	std::for_each(c.begin(), c.end(), deleteobj<PT>());
}

template <class M>
inline void DeleteObjectsInMap(const M & m)
{
	typedef typename M::value_type PAIR;
	std::for_each(m.begin(), m.end(), deletepair<PAIR>());
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


using std::back_inserter;
using std::bind1st;
using std::bind2nd;
using std::mem_fun;
using std::mem_vfun;
using std::mem_fun_ref;
using std::mem_vfun_ref;
using std::compose1;
using std::greater;
using std::equal_to;
using std::not1;
using std::copy;
using std::swap;
using std::fill;
using std::find;
using std::find_if;
using std::remove_if;
using std::for_each;
using std::partition;
using std::transform;
using std::distance;
using std::sort;
using std::stable_sort;
using std::unique;
using std::ptr_fun;
using std::min_element;

#endif  // STL_SUPP_H
