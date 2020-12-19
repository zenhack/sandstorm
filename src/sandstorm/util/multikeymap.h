#pragma once

#include <stdint.h>
#include <kj/map.h>
#include <sandstorm/util.h>

namespace sandstorm {

template<typename LeftKey, typename RightKey, typename Value>
class MultiKeyMap {
  // A poor-man's multimap; this is a map that lets you look up
  // a value by two alternate keys.
  //
  // It would be nice to have a more complete & polished version of this in kj.
  public:
    void insert(LeftKey lk, RightKey rk, Value v);
    kj::Maybe<Value&> findLeft(LeftKey&& key);
    kj::Maybe<Value&> findRight(RightKey&& key);
    bool eraseLeft(LeftKey&& key);
    bool eraseRight(RightKey&& key);

  template <
    typename Predicate,
    typename = decltype(
      kj::instance<Predicate>()(
        kj::instance<LeftKey&>(),
        kj::instance<RightKey&>,
        kj::instance<Value&>()))>
  size_t eraseAll(Predicate&& predicate) {
    return directMap.eraseAll([KJ_MVCAP(predicate)](uint64_t& directKey, Entry& entry) {
      return predicate(entry.leftEntry.key, entry.rightEntry.key, entry.value);
    });
  }

  private:
    struct Entry {
      Entry(Entry&&) = default;
      typename kj::HashMap<LeftKey, uint64_t>::Entry& leftEntry;
      typename kj::HashMap<RightKey, uint64_t>::Entry& rightEntry;
      Value value;
    };

    kj::HashMap<LeftKey, uint64_t> leftMap;
    kj::HashMap<RightKey, uint64_t> rightMap;
    kj::HashMap<uint64_t, Entry> directMap;
    uint64_t nextKey;

    bool eraseDirect(uint64_t key);
};
};
