#include "csdb/pool.h"

#include <cstring>
#include <sstream>
#include <iomanip>
#include <map>
#include <algorithm>

#include "csdb/csdb.h"

#include "csdb/internal/shared_data_ptr_implementation.h"
#include "csdb/internal/utils.h"
#include "binary_streams.h"
#include "priv_crypto.h"
#include "transaction_p.h"

namespace {
#pragma pack(push,1)
struct pool_common_header_t
{
  uint16_t version_;
  uint32_t signature_offset_;
};
#pragma pack(pop)
enum SerializationVersion : uint16_t {
  /**
   * Данная версия будет использоваться вплоть до момента первого запуска
   * с необходимостью созранения данных.
   */
  SERIALIZATION_V1 = 0x0001,
};
}

namespace csdb {

class PoolHash::priv : public ::csdb::internal::shared_data
{
public:
  internal::byte_array value;
};
SHARED_DATA_CLASS_IMPLEMENTATION(PoolHash)

bool PoolHash::is_empty() const noexcept
{
  return d->value.empty();
}

size_t PoolHash::size()  const noexcept
{
  return d->value.size();
}

std::string PoolHash::to_string() const noexcept
{
  return internal::to_hex(d->value);
}

::csdb::internal::byte_array PoolHash::to_binary() const noexcept
{
  return d->value;
}

PoolHash PoolHash::from_binary(const ::csdb::internal::byte_array& data)
{
  const size_t sz = data.size();
  PoolHash res;
  if ((0 == sz)
      || (::csdb::priv::crypto::hash_size == sz)
      ) {
    res.d->value = data;
  }
  return res;
}

bool PoolHash::operator ==(const PoolHash &other) const noexcept
{
  return (d == other.d) || (d->value == other.d->value);
}

bool PoolHash::operator <(const PoolHash &other) const noexcept
{
  return (d != other.d) && (d->value < other.d->value);
}

PoolHash PoolHash::from_string(const ::std::string& str)
{
  const ::csdb::internal::byte_array hash = ::csdb::internal::from_hex(str);
  const size_t sz = hash.size();
  PoolHash res;
  if ((0 == sz)
      || (::csdb::priv::crypto::hash_size == sz)
      ) {
    res.d->value = hash;
  }
  return res;
}

PoolHash PoolHash::calc_from_data(const internal::byte_array &data)
{
  PoolHash res;
  res.d->value = ::csdb::priv::crypto::calc_hash(data);
  return res;
}

void PoolHash::put(::csdb::priv::obstream &os) const
{
  os.put(d->value);
}

bool PoolHash::get(::csdb::priv::ibstream &is)
{
  return is.get(d->value);
}

class Pool::priv : public ::csdb::internal::shared_data
{
  priv() : common_header_{0,0}, is_valid_(false), read_only_(false), sequence_(0) {}
  priv(PoolHash previous_hash, Pool::sequence_t sequence, ::csdb::Storage::WeakPtr storage) :
    common_header_{0,0},
    is_valid_(true),
    read_only_(false),
    previous_hash_(previous_hash),
    sequence_(sequence),
    storage_(storage)
  {}

  void put(::csdb::priv::obstream& os) const
  {
    os.put(&common_header_, sizeof(common_header_));
    os.put(previous_hash_);
    os.put(sequence_);

    os.put(transactions_.size());
    for(const auto& it : transactions_) {
      os.put(it);
    }

    os.put(user_fields_);
  }

  bool get(::csdb::priv::ibstream& is)
  {
    if (!is.get(&common_header_, sizeof(common_header_))) {
      return false;
    }

    if ((SERIALIZATION_V1 != common_header_.version_)
        || ((is.size() + sizeof(common_header_)) < common_header_.signature_offset_)) {
      return false;
    }

    if(!is.get(previous_hash_)) {
      return false;
    }

    if(!is.get(sequence_))
      return false;

    size_t cnt;
    if(!is.get(cnt)) {
      return false;
    }

    transactions_.clear();
    transactions_.reserve(cnt);
    for(size_t i = 0; i < cnt; ++i )
    {
      Transaction tran;
      if(!is.get(tran))
        return false;
      transactions_.emplace_back(tran);
    }

    if(!is.get(user_fields_)) {
      return false;
    }

    is_valid_ = true;
    read_only_ = true;
    return true;
  }

  void compose(Pool::sign_fn_t sign_fn)
  {
    if (!is_valid_) {
      binary_representation_.clear();
      hash_ = PoolHash();
      return;
    }

    if (!binary_representation_.empty()) {
      return;
    }

    ::csdb::priv::obstream os;
    put(os);
    binary_representation_ = os.buffer();

    common_header_.version_ = SERIALIZATION_V1;
    common_header_.signature_offset_ = static_cast<uint32_t>(binary_representation_.size());
    memcpy(&(binary_representation_[0]), &common_header_, sizeof(common_header_));
    if (nullptr != sign_fn) {
      ::csdb::internal::byte_array sign = sign_fn(binary_representation_.data(), binary_representation_.size());
      if (!sign.empty()) {
        binary_representation_.insert(binary_representation_.end(), sign.begin(), sign.end());
      }
    }

    read_only_ = true;

    update_transactions();
  }

  void update_transactions()
  {
    hash_ = PoolHash::calc_from_data(binary_representation_);
    for (size_t idx = 0; idx < transactions_.size(); ++idx) {
      transactions_[idx].d->_update_id(hash_, idx);
    }
  }

  bool verify_sign(Pool::verify_fn_t verify_fn) const
  {
    if (nullptr == verify_fn) {
      return false;
    }

    if ((!read_only_) || (binary_representation_.size() <= common_header_.signature_offset_)) {
      return verify_fn(binary_representation_.data(), binary_representation_.size(), nullptr, 0);
    }

    const ::csdb::internal::byte_array::value_type* data = binary_representation_.data();
    size_t size = binary_representation_.size();
    return verify_fn(data, common_header_.signature_offset_,
                     data + common_header_.signature_offset_, size - common_header_.signature_offset_);
  }

  Storage get_storage(Storage candidate)
  {
    if (candidate.isOpen()) {
      return candidate;
    }

    candidate = Storage(storage_);
    if (candidate.isOpen()) {
      return candidate;
    }

    return ::csdb::defaultStorage();
  }

  pool_common_header_t common_header_;
  bool is_valid_;
  bool read_only_;
  PoolHash hash_;
  PoolHash previous_hash_;
  Pool::sequence_t sequence_;
  std::vector<Transaction> transactions_;
  ::std::map<::csdb::user_field_id_t, ::csdb::UserField> user_fields_;
  ::csdb::internal::byte_array binary_representation_;
  ::csdb::Storage::WeakPtr storage_;
  friend class Pool;
};
SHARED_DATA_CLASS_IMPLEMENTATION(Pool)

Pool::Pool(PoolHash previous_hash, sequence_t sequence, Storage storage) :
  d(new priv(previous_hash, sequence, storage.weak_ptr()))
{
}

bool Pool::is_valid() const noexcept
{
  return d->is_valid_;
}

bool Pool::is_read_only() const noexcept
{
  return d->read_only_;
}

PoolHash Pool::hash() const noexcept
{
  return d->hash_;
}

::csdb::internal::byte_array Pool::sign() const noexcept
{
  const priv* data = d.constData();

  if (!data->read_only_ || (data->binary_representation_.size() <= data->common_header_.signature_offset_)) {
    return ::csdb::internal::byte_array{};
  }

  return ::csdb::internal::byte_array(data->binary_representation_.begin() + data->common_header_.signature_offset_,
                                      data->binary_representation_.end());
}

bool Pool::verify(verify_fn_t verify_fn) const noexcept
{
  return d->verify_sign(verify_fn);
}

PoolHash Pool::previous_hash() const noexcept
{
  return d->previous_hash_;
}

Storage Pool::storage() const noexcept
{
  return Storage(d->storage_);
}

Transaction Pool::transaction(size_t index) const
{
  return (d->transactions_.size() > index) ? d->transactions_[index] : Transaction{};
}

Transaction Pool::transaction(TransactionID id) const
{
  if ((!d->is_valid_) || (!d->read_only_)
      || (!id.is_valid()) || (id.pool_hash() != d->hash_)
      || (d->transactions_.size() <= id.d->index_)) {
    return Transaction{};
  }
  return d->transactions_[id.d->index_];
}

Transaction Pool::get_last_by_source(Address source) const noexcept
{
  const auto data = d.constData();

  if ((!data->is_valid_))
  {
    return Transaction{};
  }

  auto it_rend = data->transactions_.rend();
  for (auto it = data->transactions_.rbegin(); it != it_rend; ++it)
  {
    const auto& t = *it;

    if (t.source() == source)
    {
      return t;
    }
  }

  return Transaction{};
}

Transaction Pool::get_last_by_target(Address target) const noexcept
{
  const auto data = d.constData();

  if ((!data->is_valid_))
  {
    return Transaction{};
  }

  auto it_rend = data->transactions_.rend();
  for (auto it = data->transactions_.rbegin(); it != it_rend; ++it)
  {
    const auto t = *it;

    if (t.target() == target)
    {
      return t;
    }
  }

  return Transaction{};
}

bool Pool::add_transaction(Transaction transaction
#ifdef CSDB_UNIT_TEST
                     , bool skip_check
#endif
                     )
{
  if(d.constData()->read_only_) {
    return false;
  }

  if (!transaction.is_valid()) {
    return false;
  }

#ifdef CSDB_UNIT_TEST
  if (!skip_check) {
#endif
  /// \todo Add transaction checking.
#ifdef CSDB_UNIT_TEST
  }
#endif

  d->transactions_.push_back(Transaction(new Transaction::priv(*(transaction.d.constData()))));
  return true;
}

size_t Pool::transactions_count() const noexcept
{
  return d->transactions_.size();
}

Pool::sequence_t Pool::sequence() const noexcept
{
  return d->sequence_;
}

void Pool::set_sequence(Pool::sequence_t seq) noexcept
{
  if (d.constData()->read_only_) {
    return;
  }

  priv* data = d.data();
  data->is_valid_ = true;
  data->sequence_ = seq;
}

void Pool::set_previous_hash(PoolHash previous_hash) noexcept
{
  if (d.constData()->read_only_) {
    return;
  }

  priv* data = d.data();
  data->is_valid_ = true;
  data->previous_hash_ = previous_hash;
}

void Pool::set_storage(Storage storage) noexcept
{
  // We can set up storage even if Pool is read-only
  priv* data = d.data();
  data->is_valid_ = true;
  data->storage_ = storage.weak_ptr();
}

bool Pool::add_user_field(user_field_id_t id, UserField field) noexcept
{
  if (d.constData()->read_only_ || (!field.is_valid())) {
    return false;
  }

  priv* data = d.data();
  data->is_valid_ = true;
  data->user_fields_[id] = field;

  return true;
}

UserField Pool::user_field(user_field_id_t id) const noexcept
{
  const priv* data = d.constData();
  auto it = data->user_fields_.find(id);
  return (data->user_fields_.end() == it) ? UserField{} : it->second;
}

::std::set<user_field_id_t> Pool::user_field_ids() const noexcept
{
  ::std::set<user_field_id_t> res;
  const priv* data = d.constData();
  for (const auto& it : data->user_fields_) {
    res.insert(it.first);
  }
  return res;
}

bool Pool::compose(sign_fn_t sign_fn)
{
  if (d.constData()->read_only_) {
    return true;
  }

  if (!d.constData()->is_valid_) {
    return false;
  }

  d->compose(sign_fn);
  return true;
}

::csdb::internal::byte_array Pool::to_binary() const noexcept
{
  return d->binary_representation_;
}

Pool Pool::from_binary(const ::csdb::internal::byte_array& data, verify_fn_t verify_fn)
{
  ::std::unique_ptr<priv> p(new priv());
  ::csdb::priv::ibstream is(data.data(), data.size());
  if (!p->get(is)) {
    return Pool();
  }
  p->binary_representation_ = data;
  if ((nullptr != verify_fn) && (!p->verify_sign(verify_fn))) {
    return Pool();
  }
  p->update_transactions();
  return Pool(p.release());
}

bool Pool::save(Storage storage)
{
  if ((!d.constData()->is_valid_) || ((!d.constData()->read_only_))) {
    return false;
  }

  Storage s = d->get_storage(storage);
  if (!s.isOpen()) {
    return false;
  }

  if (s.pool_save(*this)) {
    d->storage_ = s.weak_ptr();
    return true;
  }

  return false;
}

Pool Pool::load(PoolHash hash, verify_fn_t verify_fn, Storage storage)
{
  if (!storage.isOpen()) {
    storage = ::csdb::defaultStorage();
  }

  Pool res = storage.pool_load(hash);
  if (res.is_valid()) {
    res.set_storage(storage);
  }
  return res;
}

} // namespace csdb
