#include "multikeymap.h"

namespace sandstorm {

template<typename LeftKey, typename RightKey, typename Value>
void MultiKeyMap<LeftKey, RightKey, Value>::insert(LeftKey lk, RightKey rk, Value v) {
  uint64_t directKey = nextKey++;
  auto leftEntry = leftMap.insert(lk, directKey);
  auto rightEntry = rightMap.insert(rk, directKey);
  directMap.insert(directKey, Entry{leftEntry, rightEntry, v});
}

template<typename LeftKey, typename RightKey, typename Value>
kj::Maybe<Value&> MultiKeyMap<LeftKey, RightKey, Value>::findLeft(LeftKey&& key) {
  KJ_IF_MAYBE(directIndex, leftMap.find(key)) {
    return directMap.find(*directIndex);
  } else {
    return nullptr;
  }
}

template<typename LeftKey, typename RightKey, typename Value>
kj::Maybe<Value&> MultiKeyMap<LeftKey, RightKey, Value>::findRight(RightKey&& key) {
  KJ_IF_MAYBE(directIndex, rightMap.find(key)) {
    return directMap.find(*directIndex);
  } else {
    return nullptr;
  }
}

template<typename LeftKey, typename RightKey, typename Value>
bool MultiKeyMap<LeftKey, RightKey, Value>::eraseLeft(LeftKey&& key) {
  KJ_IF_MAYBE(directIndex, leftMap.find(key)) {
    return eraseDirect(*directIndex);
  } else {
    return false;
  }
}

template<typename LeftKey, typename RightKey, typename Value>
bool MultiKeyMap<LeftKey, RightKey, Value>::eraseRight(RightKey&& key) {
  KJ_IF_MAYBE(directIndex, rightMap.find(key)) {
    return eraseDirect(*directIndex);
  } else {
    return false;
  }
}

template<typename LeftKey, typename RightKey, typename Value>
bool MultiKeyMap<LeftKey, RightKey, Value>::eraseDirect(uint64_t key) {
  KJ_IF_MAYBE(entry, directMap.find(key)) {
    leftMap.erase(entry->leftEntry);
    rightMap.erase(entry->rightEntry);
    directMap.erase(*entry);
    return true;
  } else {
    return false;
  }
}

};
