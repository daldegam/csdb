/**
  * @file csdb_unit_tests_environment.h
  * @author Evgeny V. Zalivochkin
  */

#pragma once
#ifndef _CREDITS_CSDB_UNIT_TESTS_ENVIRONMENT_H_INCLUDED_
#define _CREDITS_CSDB_UNIT_TESTS_ENVIRONMENT_H_INCLUDED_

#include <iostream>

#include "csdb/address.h"
#include "csdb/amount.h"
#include "csdb/currency.h"
#include "csdb/transaction.h"
#include "csdb/pool.h"
#include "csdb/user_field.h"

#include <gtest/gtest.h>

namespace csdb {

bool operator ==(const Transaction& a, const Transaction& b);

inline bool operator !=(const Transaction& a, const Transaction& b)
{
  return !(a == b);
}

bool is_equal(const Pool& a, const Pool& b, bool compare_hash);

inline bool operator ==(const Pool& a, const Pool& b)
{
  return is_equal(a, b, true);
}

inline bool operator !=(const Pool& a, const Pool& b)
{
  return !is_equal(a, b, true);
}

} // namespace csdb

::std::ostream& operator <<(::std::ostream& os, const ::csdb::UserField& value);

#endif // _CREDITS_CSDB_UNIT_TESTS_ENVIRONMENT_H_INCLUDED_
