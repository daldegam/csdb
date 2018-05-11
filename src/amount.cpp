#include "csdb/amount.h"
#include "binary_streams.h"

namespace csdb {
Amount::Amount(double value)
{
  if ((value < static_cast<double>(std::numeric_limits<int32_t>::min()))
      || (value > static_cast<double>(std::numeric_limits<int32_t>::max()))) {
      throw std::overflow_error("Amount::Amount(double) overflow)");
  }

  integral_ = static_cast<int32_t>(value);
  if (value < 0.0) {
    --integral_;
  }

  double frac = value - static_cast<double>(integral_);
  uint64_t multiplier = AMOUNT_MAX_FRACTION;
  for (int i = 0; i < std::numeric_limits<double>::digits10; ++i) {
    frac *= 10;
    multiplier /= 10;
  }

  fraction_ = static_cast<uint64_t>(frac + 0.5) * multiplier;
  if (fraction_ >= AMOUNT_MAX_FRACTION) {
    fraction_ -= AMOUNT_MAX_FRACTION;
    ++integral_;
  }
}

void Amount::put(priv::obstream& os) const
{
  os.put(integral_);
  os.put(fraction_);
}

bool Amount::get(priv::ibstream& is)
{
  return is.get(integral_) && is.get(fraction_);
}

} // namespace csdb
