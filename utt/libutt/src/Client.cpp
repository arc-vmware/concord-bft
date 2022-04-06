
#include <utt/Client.h>

namespace libutt::Client {

//////////////////////////////////////////////////////////////////////////////////////////////
Tx createTx_1t1(const Wallet& w, size_t coinIdx, const std::string& pid) {
  std::vector<Coin> inputCoins = std::vector<Coin>{w.coins.at(coinIdx)};
  auto budgetCoin = *w.budgetCoin;

  std::vector<std::tuple<std::string, Fr>> recip;
  recip.emplace_back(pid, inputCoins[0].getValue());

  return Tx(w.p, w.ask, inputCoins, budgetCoin, recip, w.bpk, w.rpk);
}

//////////////////////////////////////////////////////////////////////////////////////////////
Tx createTx_1t2(const Wallet& w, size_t coinIdx, size_t payment, const std::string& pid) {
  std::vector<Coin> inputCoins = std::vector<Coin>{w.coins.at(coinIdx)};
  auto budgetCoin = *w.budgetCoin;

  std::vector<std::tuple<std::string, Fr>> recip;
  recip.emplace_back(pid, payment);
  recip.emplace_back(w.ask.getPid(), inputCoins[0].getValue() - payment);

  return Tx(w.p, w.ask, inputCoins, budgetCoin, recip, w.bpk, w.rpk);
}

//////////////////////////////////////////////////////////////////////////////////////////////
Tx createTx_2t1(const Wallet& w, size_t coinIdx1, size_t coinIdx2, const std::string& pid) {
  std::vector<Coin> inputCoins = std::vector<Coin>{w.coins.at(coinIdx1), w.coins.at(coinIdx2)};
  auto budgetCoin = *w.budgetCoin;

  std::vector<std::tuple<std::string, Fr>> recip;
  recip.emplace_back(pid, inputCoins[0].getValue() + inputCoins[1].getValue());

  return Tx(w.p, w.ask, inputCoins, budgetCoin, recip, w.bpk, w.rpk);
}

//////////////////////////////////////////////////////////////////////////////////////////////
Tx createTx_2t2(const Wallet& w, size_t coinIdx1, size_t coinIdx2, size_t payment, const std::string& pid) {
  std::vector<Coin> inputCoins = std::vector<Coin>{w.coins.at(coinIdx1), w.coins.at(coinIdx2)};
  auto budgetCoin = *w.budgetCoin;

  std::vector<std::tuple<std::string, Fr>> recip;
  recip.emplace_back(pid, payment);
  recip.emplace_back(w.ask.getPid(), (inputCoins[0].getValue() + inputCoins[1].getValue()) - payment);

  return Tx(w.p, w.ask, inputCoins, budgetCoin, recip, w.bpk, w.rpk);
}

//////////////////////////////////////////////////////////////////////////////////////////////
Tx createTx_Self2t1(const Wallet& w, size_t coinIdx1, size_t coinIdx2) {
  std::vector<Coin> inputCoins = std::vector<Coin>{w.coins.at(coinIdx1), w.coins.at(coinIdx2)};

  std::vector<std::tuple<std::string, Fr>> recip;
  recip.emplace_back(w.ask.getPid(), inputCoins[0].getValue() + inputCoins[1].getValue());

  return Tx(w.p, w.ask, inputCoins, std::nullopt, recip, w.bpk, w.rpk);
}

//////////////////////////////////////////////////////////////////////////////////////////////
size_t calcBalance(const Wallet& w) {
  size_t balance = 0;
  for (const auto& c : w.coins) balance += c.getValue();
  return balance;
}

//////////////////////////////////////////////////////////////////////////////////////////////
size_t calcBudget(const Wallet& w) { return w.budgetCoin ? w.budgetCoin->getValue() : 0; }

//////////////////////////////////////////////////////////////////////////////////////////////
CoinStrategy k_CoinStrategyPreferExactChange = [](const Wallet& w, const std::string& pid, size_t payment) -> Tx {
  // Precondition: 0 < payment <= budget <= balance

  // Variant 1: Prefer exact payments (using sorted coins)
  //
  // (1) look for a single coin where value >= k, an exact coin will be prefered
  // (2) look for two coins with total value >= k, an exact sum will be prefered
  // (3) no two coins sum up to k, do a merge on the largest two coins

  // Example 1 (1 coin match):
  // Target Payment: 5
  // Wallet: [2, 3, 4, 4, 7, 8]
  //
  // (1) find lower bound (LB) of 5: [2, 3, 4, 4, 7, 8] --> found a coin >= 5
  //                                              ^
  // (2) Make a one coin payment with 7
  // Note: If we prefer to pay with two exact coins (if possible) we can go to example 2
  // by considering the subrange [2, 3, 4, 4] and skip step (1) of example 2.

  // Example 2 (2 coin matches):
  // Target Payment: 5
  // Wallet: [2, 3, 4, 4]
  //
  // (1) find lower bound (LB) of 5: [2, 3, 4, 4, end] -- we don't have a single coin candidate
  //                                               ^
  // (2) search for pairs >= 5
  // [2, 3, 4, 4]
  //  l        h      l+h = 6 found a match -- save and continue iterating
  //  l     h         l+h = 6 found a match -- ignore, already has a match
  //  l  h            l+h = 5 found exact match -- save and break (we prefer the exact match)
  //  Termination: l == h
  //
  // (3) Use exact match
  // Note: We use exact match over an inexact match and if neither exist we merge the
  // top two coins and try again.

  using CoinRef = std::pair<size_t, size_t>;  // [coinValue, coinIdx]

  std::vector<CoinRef> aux;

  for (size_t i = 0; i < w.coins.size(); ++i) {
    aux.emplace_back(w.coins[i].getValue(), i);
  }

  auto cmpCoinValue = [](const CoinRef& lhs, const CoinRef& rhs) { return lhs.first < rhs.first; };
  std::sort(aux.begin(), aux.end(), cmpCoinValue);

  auto lb = std::lower_bound(aux.begin(), aux.end(), CoinRef{payment, -1}, cmpCoinValue);
  if (lb != aux.end()) {
    // We can pay with one coin
    if (lb->first > payment) {
      return createTx_1t2(w, lb->second, payment, pid);
    } else {
      return createTx_1t1(w, lb->second, pid);
    }
  } else {  // Try to pay with two coins
    // We know that our balance is enough and no coin is >= payment (because lower_bound == end)
    // Then we may have two coins that satisfy the payment
    // If we don't have two coins we must merge
    size_t low = 0;
    size_t high = aux.size() - 1;
    std::optional<std::pair<size_t, size_t>> match;
    std::optional<std::pair<size_t, size_t>> exactMatch;

    while (low < high) {
      const auto sum = aux[low].first + aux[high].first;
      if (sum == payment) {
        exactMatch = std::make_pair(aux[low].second, aux[high].second);
        break;  // exact found
      } else if (sum > payment) {
        // found a pair (but we want to look for an exact match)
        if (!match) match = std::make_pair(aux[low].second, aux[high].second);
        --high;
      } else {
        ++low;
      }
    }

    if (exactMatch) {
      return createTx_2t1(w, exactMatch->first, exactMatch->second, pid);
    } else if (match) {
      return createTx_2t2(w, match->first, match->second, payment, pid);
    }
  }

  // At this point no one or two coins are sufficient to do the payment
  // We merge the top two coins
  const auto lastIdx = aux.size() - 1;
  return createTx_Self2t1(w, aux[lastIdx - 1].second, aux[lastIdx].second);
};

//////////////////////////////////////////////////////////////////////////////////////////////
Tx createTxForPayment(const Wallet& w, const std::string& pid, size_t payment, const CoinStrategy& strategy) {
  if (!strategy) throw std::runtime_error("Coin strategy not provided!");
  if (w.coins.empty()) throw std::runtime_error("Wallet has no coins!");
  if (pid.empty()) throw std::runtime_error("Empty pid!");
  if (payment == 0) throw std::runtime_error("Payment must be positive!");

  const size_t balance = calcBalance(w);
  if (balance < payment) throw std::runtime_error("Wallet has insufficient balance!");
  const size_t budget = calcBudget(w);
  if (budget < payment) throw std::runtime_error("Wallet has insufficient anonymous budget!");

  return strategy(w, pid, payment);
}

}  // namespace libutt::Client