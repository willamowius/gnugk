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


#ifndef __stl_supp_h_
#define __stl_supp_h_

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
#ifndef __GNUC__
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
#endif
#endif

} // end of namespace std


using std::back_inserter;
using std::bind1st;
using std::bind2nd;
using std::mem_fun;
using std::mem_fun_ref;
using std::compose1;
using std::greater;
using std::equal_to;
using std::not1;
using std::copy;
using std::find;
using std::find_if;
using std::for_each;
using std::partition;
using std::transform;
using std::distance;
using std::sort;
using std::unique;


#endif  // __stl_supp_h_

