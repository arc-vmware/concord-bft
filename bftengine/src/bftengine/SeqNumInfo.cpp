// Concord
//
// Copyright (c) 2018-2020 VMware, Inc. All Rights Reserved.
//
// This product is licensed to you under the Apache 2.0 license (the "License").  You may not use this product except in
// compliance with the Apache 2.0 License.
//
// This product may include a number of subcomponents with separate copyright notices and license terms. Your use of
// these subcomponents is subject to the terms and conditions of the subcomponent's license, as noted in the LICENSE
// file.

#include "SeqNumInfo.hpp"
#include "InternalReplicaApi.hpp"
#include "OpenTracing.hpp"
#include "messages/SignatureInternalMsgs.hpp"
#include "CryptoManager.hpp"

namespace bftEngine {
namespace impl {

SeqNumInfo::SeqNumInfo()
    : replica(nullptr),
      prePrepareMsg(nullptr),
      prepareSigCollector(nullptr),
      commitMsgsCollector(nullptr),
      fastPathOptimisticCollector(nullptr),
      fastPathThresholdCollector(nullptr),
      fastPathTimeOfSelfPartialProof(MinTime),
      // partialProofsSet(nullptr),
      primary(false),
      forcedCompleted(false),
      slowPathHasStarted(false),
      firstSeenFromPrimary(MinTime),
      timeOfLastInfoRequest(MinTime),
      commitUpdateTime(MinTime) {}

SeqNumInfo::~SeqNumInfo() {
  resetAndFree();

  delete prepareSigCollector;
  delete commitMsgsCollector;
  // delete partialProofsSet;
  delete fastPathOptimisticCollector;
  delete fastPathThresholdCollector;
}

void SeqNumInfo::resetCommitSignatures() { commitMsgsCollector->resetAndFree(); }

void SeqNumInfo::resetPrepareSignatures() { prepareSigCollector->resetAndFree(); }

void SeqNumInfo::resetAndFree() {
  delete prePrepareMsg;
  prePrepareMsg = nullptr;

  prepareSigCollector->resetAndFree();
  commitMsgsCollector->resetAndFree();
  // partialProofsSet->resetAndFree();
  fastPathOptimisticCollector->resetAndFree();
  fastPathThresholdCollector->resetAndFree();

  primary = false;

  forcedCompleted = false;

  slowPathHasStarted = false;

  firstSeenFromPrimary = MinTime;
  timeOfLastInfoRequest = MinTime;
  commitUpdateTime = getMonotonicTime();  // TODO(GG): TBD
}

void SeqNumInfo::getAndReset(PrePrepareMsg*& outPrePrepare, PrepareFullMsg*& outCombinedValidSignatureMsg) {
  outPrePrepare = prePrepareMsg;
  prePrepareMsg = nullptr;

  prepareSigCollector->getAndReset(outCombinedValidSignatureMsg);

  resetAndFree();
}

bool SeqNumInfo::addMsg(PrePrepareMsg* m, bool directAdd, bool isTimeCorrect) {
  if (prePrepareMsg != nullptr) return false;

  ConcordAssert(primary == false);
  ConcordAssert(!forcedCompleted);
  ConcordAssert(!prepareSigCollector->hasPartialMsgFromReplica(replica->getReplicasInfo().myId()));

  prePrepareMsg = m;
  isTimeCorrect_ = isTimeCorrect;

  // set expected
  Digest tmpDigest;
  Digest::calcCombination(m->digestOfRequests(), m->viewNumber(), m->seqNumber(), tmpDigest);
  if (!directAdd)
    prepareSigCollector->setExpected(m->seqNumber(), m->viewNumber(), tmpDigest);
  else
    prepareSigCollector->initExpected(m->seqNumber(), m->viewNumber(), tmpDigest);

  if (firstSeenFromPrimary == MinTime)  // TODO(GG): remove condition - TBD
    firstSeenFromPrimary = getMonotonicTime();

  return true;
}

bool SeqNumInfo::addSelfMsg(PrePrepareMsg* m, bool directAdd) {
  ConcordAssert(primary == false);
  ConcordAssert(replica->getReplicasInfo().myId() == replica->getReplicasInfo().primaryOfView(m->viewNumber()));
  ConcordAssert(!forcedCompleted);
  ConcordAssert(prePrepareMsg == nullptr);

  // ConcordAssert(me->id() == m->senderId()); // GG: incorrect assert - because after a view change it may has been
  // sent by another replica

  prePrepareMsg = m;
  primary = true;

  // set expected
  Digest tmpDigest;
  Digest::calcCombination(m->digestOfRequests(), m->viewNumber(), m->seqNumber(), tmpDigest);
  if (!directAdd)
    prepareSigCollector->setExpected(m->seqNumber(), m->viewNumber(), tmpDigest);
  else
    prepareSigCollector->initExpected(m->seqNumber(), m->viewNumber(), tmpDigest);

  if (firstSeenFromPrimary == MinTime)  // TODO(GG): remove condition - TBD
    firstSeenFromPrimary = getMonotonicTime();

  return true;
}

bool SeqNumInfo::addMsg(PreparePartialMsg* m) {
  ConcordAssert(replica->getReplicasInfo().myId() != m->senderId());
  ConcordAssert(!forcedCompleted);

  bool retVal = prepareSigCollector->addMsgWithPartialSignature(m, m->senderId());

  return retVal;
}

bool SeqNumInfo::addSelfMsg(PreparePartialMsg* m, bool directAdd) {
  ConcordAssert(replica->getReplicasInfo().myId() == m->senderId());
  ConcordAssert(!forcedCompleted);

  bool r;

  if (!directAdd)
    r = prepareSigCollector->addMsgWithPartialSignature(m, m->senderId());
  else
    r = prepareSigCollector->initMsgWithPartialSignature(m, m->senderId());

  ConcordAssert(r);

  return true;
}

bool SeqNumInfo::addMsg(PrepareFullMsg* m, bool directAdd) {
  ConcordAssert(directAdd || replica->getReplicasInfo().myId() != m->senderId());  // TODO(GG): TBD
  ConcordAssert(!forcedCompleted);

  bool retVal;
  if (!directAdd)
    retVal = prepareSigCollector->addMsgWithCombinedSignature(m);
  else
    retVal = prepareSigCollector->initMsgWithCombinedSignature(m);

  return retVal;
}

bool SeqNumInfo::addMsg(CommitPartialMsg* m) {
  ConcordAssert(replica->getReplicasInfo().myId() != m->senderId());  // TODO(GG): TBD
  ConcordAssert(!forcedCompleted);

  bool r = commitMsgsCollector->addMsgWithPartialSignature(m, m->senderId());

  if (r) commitUpdateTime = getMonotonicTime();

  return r;
}

bool SeqNumInfo::addSelfCommitPartialMsgAndDigest(CommitPartialMsg* m, Digest& commitDigest, bool directAdd) {
  ConcordAssert(replica->getReplicasInfo().myId() == m->senderId());
  ConcordAssert(!forcedCompleted);

  Digest tmpDigest;
  Digest::calcCombination(commitDigest, m->viewNumber(), m->seqNumber(), tmpDigest);
  bool r;
  if (!directAdd) {
    commitMsgsCollector->setExpected(m->seqNumber(), m->viewNumber(), tmpDigest);
    r = commitMsgsCollector->addMsgWithPartialSignature(m, m->senderId());
  } else {
    commitMsgsCollector->initExpected(m->seqNumber(), m->viewNumber(), tmpDigest);
    r = commitMsgsCollector->initMsgWithPartialSignature(m, m->senderId());
  }
  ConcordAssert(r);
  commitUpdateTime = getMonotonicTime();

  return true;
}

bool SeqNumInfo::addMsg(CommitFullMsg* m, bool directAdd) {
  ConcordAssert(directAdd || replica->getReplicasInfo().myId() != m->senderId());  // TODO(GG): TBD
  ConcordAssert(!forcedCompleted);

  bool r;
  if (!directAdd)
    r = commitMsgsCollector->addMsgWithCombinedSignature(m);
  else
    r = commitMsgsCollector->initMsgWithCombinedSignature(m);

  if (r) commitUpdateTime = getMonotonicTime();

  return r;
}

void SeqNumInfo::forceComplete() {
  ConcordAssert(!forcedCompleted);
  ConcordAssert(hasPrePrepareMsg());
  // ConcordAssert(this->partialProofsSet->hasFullProof());
  ConcordAssert(hasFastPathFullCommitProof());

  forcedCompleted = true;
  commitUpdateTime = getMonotonicTime();
}

PrePrepareMsg* SeqNumInfo::getPrePrepareMsg() const { return prePrepareMsg; }

PrePrepareMsg* SeqNumInfo::getSelfPrePrepareMsg() const {
  if (primary) {
    return prePrepareMsg;
  }
  return nullptr;
}

PreparePartialMsg* SeqNumInfo::getSelfPreparePartialMsg() const {
  PreparePartialMsg* p = prepareSigCollector->getPartialMsgFromReplica(replica->getReplicasInfo().myId());
  return p;
}

PrepareFullMsg* SeqNumInfo::getValidPrepareFullMsg() const {
  return prepareSigCollector->getMsgWithValidCombinedSignature();
}

CommitPartialMsg* SeqNumInfo::getSelfCommitPartialMsg() const {
  CommitPartialMsg* p = commitMsgsCollector->getPartialMsgFromReplica(replica->getReplicasInfo().myId());
  return p;
}

CommitFullMsg* SeqNumInfo::getValidCommitFullMsg() const {
  return commitMsgsCollector->getMsgWithValidCombinedSignature();
}

bool SeqNumInfo::hasPrePrepareMsg() const { return (prePrepareMsg != nullptr); }

bool SeqNumInfo::isPrepared() const {
  return forcedCompleted || ((prePrepareMsg != nullptr) && prepareSigCollector->isComplete());
}

bool SeqNumInfo::isCommitted__gg() const {
  // TODO(GG): TBD - asserts on 'prepared'

  bool retVal = forcedCompleted || commitMsgsCollector->isComplete();
  return retVal;
}

bool SeqNumInfo::preparedOrHasPreparePartialFromReplica(ReplicaId repId) const {
  return isPrepared() || prepareSigCollector->hasPartialMsgFromReplica(repId);
}

bool SeqNumInfo::committedOrHasCommitPartialFromReplica(ReplicaId repId) const {
  return isCommitted__gg() || commitMsgsCollector->hasPartialMsgFromReplica(repId);
}

Time SeqNumInfo::getTimeOfFirstRelevantInfoFromPrimary() const { return firstSeenFromPrimary; }

Time SeqNumInfo::getTimeOfLastInfoRequest() const { return timeOfLastInfoRequest; }

// PartialProofsSet& SeqNumInfo::partialProofs() { return *partialProofsSet; }

bool SeqNumInfo::hasFastPathFullCommitProof() const {
  auto optimistic = fastPathOptimisticCollector->getMsgWithValidCombinedSignature();
  auto threshold = fastPathThresholdCollector->getMsgWithValidCombinedSignature();
  return optimistic || threshold;
}

bool SeqNumInfo::hasFastPathPartialCommitProofFromReplica(ReplicaId repId) const {
  auto optimistic = fastPathOptimisticCollector->getPartialMsgFromReplica(repId);
  auto threshold = fastPathThresholdCollector->getPartialMsgFromReplica(repId);
  return optimistic || threshold;
}

PartialCommitProofMsg* SeqNumInfo::getFastPathSelfPartialCommitProofMsg() const {
  const auto myReplicaId = replica->getReplicasInfo().myId();
  auto optimistic = fastPathOptimisticCollector->getPartialMsgFromReplica(myReplicaId);
  auto threshold = fastPathThresholdCollector->getPartialMsgFromReplica(myReplicaId);
  ConcordAssert(!(optimistic && threshold));
  return optimistic ? optimistic : threshold;
}

FullCommitProofMsg* SeqNumInfo::getFastPathFullCommitProofMsg() const {
  auto optimistic = fastPathOptimisticCollector->getMsgWithValidCombinedSignature();
  auto threshold = fastPathThresholdCollector->getMsgWithValidCombinedSignature();
  ConcordAssert(!(optimistic && threshold));
  return optimistic ? optimistic : threshold;
}

void SeqNumInfo::setFastPathTimeOfSelfPartialProof(const Time& t) { fastPathTimeOfSelfPartialProof = t; }

Time SeqNumInfo::getFastPathTimeOfSelfPartialProof() { return fastPathTimeOfSelfPartialProof; }

bool SeqNumInfo::addFastPathSelfPartialCommitMsgAndDigest(PartialCommitProofMsg* m, Digest& commitDigest) {
  ConcordAssert(m != nullptr);
  const ReplicaId myId = m->senderId();
  ConcordAssert(myId == replica->getReplicasInfo().myId());

  // ToDo--EDJ: Check if these invariants hold
  // ConcordAssert(seqNumber == 0);
  // ConcordAssert(expectedDigest.isZero());
  // ConcordAssert(selfPartialCommitProof == nullptr);
  // ConcordAssert(fullCommitProof == nullptr);

  bool result = false;
  switch (m->commitPath()) {
    case CommitPath::OPTIMISTIC_FAST:
      fastPathOptimisticCollector->setExpected(m->seqNumber(), m->viewNumber(), commitDigest);
      result = fastPathOptimisticCollector->addMsgWithPartialSignature(m, myId);
      break;
    case CommitPath::FAST_WITH_THRESHOLD:
      fastPathOptimisticCollector->setExpected(m->seqNumber(), m->viewNumber(), commitDigest);
      result = fastPathThresholdCollector->addMsgWithPartialSignature(m, myId);
      break;
    default:
      ConcordAssert(false && "addFastPathSelfPartialCommitMsgAndDigest - wrong CommitPath!");
  }

  return result;
}

bool SeqNumInfo::addFastPathPartialCommitMsg(PartialCommitProofMsg* m) {
  ConcordAssert(m != nullptr);

  const ReplicaId repId = m->senderId();
  ConcordAssert(repId != replica->getReplicasInfo().myId());
  // ToDo--EDJ: Check invariants
  // ConcordAssert((seqNumber == 0) || (seqNumber == m->seqNumber()));
  ConcordAssert(replica->getReplicasInfo().isIdOfReplica(repId));

  if (hasFastPathFullCommitProof()) return false;
  // if (fullCommitProof != nullptr) return false;

  auto selfPartialCommitProof = getFastPathSelfPartialCommitProofMsg();
  CommitPath cPath = m->commitPath();

  // Check different fast commit path
  if (selfPartialCommitProof && selfPartialCommitProof->commitPath() != cPath) {
    LOG_WARN(CNSUS,
             "Ignoring PartialCommitProofMsg (" << CommitPathToStr(cPath) << "). Current path is "
                                                << CommitPathToStr(selfPartialCommitProof->commitPath()));
    return false;
  }

  auto result = false;
  switch (cPath) {
    case CommitPath::OPTIMISTIC_FAST:
      result = fastPathOptimisticCollector->addMsgWithPartialSignature(m, repId);
      break;
    case CommitPath::FAST_WITH_THRESHOLD:
      result = fastPathThresholdCollector->addMsgWithPartialSignature(m, repId);
      break;
    default:
      ConcordAssert(false && "addFastPathPartialCommitMsg - wrong CommitPath!");
  }

  return result;
}

bool SeqNumInfo::addFastPathFullCommitMsg(FullCommitProofMsg* m) {
  ConcordAssert(m != nullptr);

  if (hasFastPathFullCommitProof()) return false;

  PartialCommitProofMsg* myPCP = getFastPathSelfPartialCommitProofMsg();

  if (myPCP == nullptr) {
    // TODO(GG): can be improved (we can keep the FullCommitProof  message until myPCP!=nullptr
    LOG_WARN(CNSUS, "FullCommitProofMsg arrived before PrePrepare. TODO(GG): should be handled to avoid delays. ");
    return false;
  }

  if (m->seqNumber() != myPCP->seqNumber() || m->viewNumber() != myPCP->viewNumber()) {
    LOG_WARN(CNSUS, "Received unexpected FullCommitProofMsg");
    return false;
  }

  // ToDo--EDJ: FullCommitProofMsg doesn't say to which fast path it belongs
  const auto cPath = myPCP->commitPath();
  bool result = false;
  switch (cPath) {
    case CommitPath::OPTIMISTIC_FAST:
      result = fastPathOptimisticCollector->addMsgWithCombinedSignature(m);
      break;
    case CommitPath::FAST_WITH_THRESHOLD:
      result = fastPathThresholdCollector->addMsgWithCombinedSignature(m);
      break;
    default:
      ConcordAssert(false && "addFastPathFullCommitMsg - wrong CommitPath!");
  }

  return result;
}

void SeqNumInfo::startSlowPath() { slowPathHasStarted = true; }

bool SeqNumInfo::slowPathStarted() { return slowPathHasStarted; }

void SeqNumInfo::setTimeOfLastInfoRequest(Time t) { timeOfLastInfoRequest = t; }

void SeqNumInfo::onCompletionOfPrepareSignaturesProcessing(SeqNum seqNumber,
                                                           ViewNum viewNumber,
                                                           const std::set<ReplicaId>& replicasWithBadSigs) {
  prepareSigCollector->onCompletionOfSignaturesProcessing(seqNumber, viewNumber, replicasWithBadSigs);
}

void SeqNumInfo::onCompletionOfPrepareSignaturesProcessing(SeqNum seqNumber,
                                                           ViewNum viewNumber,
                                                           const char* combinedSig,
                                                           uint16_t combinedSigLen,
                                                           const concordUtils::SpanContext& span_context) {
  prepareSigCollector->onCompletionOfSignaturesProcessing(
      seqNumber, viewNumber, combinedSig, combinedSigLen, span_context);
}

void SeqNumInfo::onCompletionOfCombinedPrepareSigVerification(SeqNum seqNumber, ViewNum viewNumber, bool isValid) {
  prepareSigCollector->onCompletionOfCombinedSigVerification(seqNumber, viewNumber, isValid);
}

///////////////////////////////////////////////////////////////////////////////
// class SeqNumInfo::ExFuncForPrepareCollector
///////////////////////////////////////////////////////////////////////////////

PrepareFullMsg* SeqNumInfo::ExFuncForPrepareCollector::createCombinedSignatureMsg(
    void* context,
    SeqNum seqNumber,
    ViewNum viewNumber,
    const char* const combinedSig,
    uint16_t combinedSigLen,
    const concordUtils::SpanContext& span_context) {
  InternalReplicaApi* r = (InternalReplicaApi*)context;
  return PrepareFullMsg::create(
      viewNumber, seqNumber, r->getReplicasInfo().myId(), combinedSig, combinedSigLen, span_context);
}

InternalMessage SeqNumInfo::ExFuncForPrepareCollector::createInterCombinedSigFailed(
    SeqNum seqNumber, ViewNum viewNumber, const std::set<uint16_t>& replicasWithBadSigs) {
  return CombinedSigFailedInternalMsg(seqNumber, viewNumber, replicasWithBadSigs);
}

InternalMessage SeqNumInfo::ExFuncForPrepareCollector::createInterCombinedSigSucceeded(
    SeqNum seqNumber,
    ViewNum viewNumber,
    const char* combinedSig,
    uint16_t combinedSigLen,
    const concordUtils::SpanContext& span_context) {
  return CombinedSigSucceededInternalMsg(seqNumber, viewNumber, combinedSig, combinedSigLen, span_context);
}

InternalMessage SeqNumInfo::ExFuncForPrepareCollector::createInterVerifyCombinedSigResult(SeqNum seqNumber,
                                                                                          ViewNum viewNumber,
                                                                                          bool isValid) {
  return VerifyCombinedSigResultInternalMsg(seqNumber, viewNumber, isValid);
}

uint16_t SeqNumInfo::ExFuncForPrepareCollector::numberOfRequiredSignatures(void* context) {
  InternalReplicaApi* r = (InternalReplicaApi*)context;
  const ReplicasInfo& info = r->getReplicasInfo();
  return (uint16_t)((info.fVal() * 2) + info.cVal() + 1);
}

std::shared_ptr<IThresholdVerifier> SeqNumInfo::ExFuncForPrepareCollector::thresholdVerifier(SeqNum seqNumber) {
  return CryptoManager::instance().thresholdVerifierForSlowPathCommit(seqNumber);
}

concord::util::SimpleThreadPool& SeqNumInfo::ExFuncForPrepareCollector::threadPool(void* context) {
  InternalReplicaApi* r = (InternalReplicaApi*)context;
  return r->getInternalThreadPool();
}

IncomingMsgsStorage& SeqNumInfo::ExFuncForPrepareCollector::incomingMsgsStorage(void* context) {
  InternalReplicaApi* r = (InternalReplicaApi*)context;
  return r->getIncomingMsgsStorage();
}

///////////////////////////////////////////////////////////////////////////////
// class SeqNumInfo::ExFuncForCommitCollector
///////////////////////////////////////////////////////////////////////////////

CommitFullMsg* SeqNumInfo::ExFuncForCommitCollector::createCombinedSignatureMsg(
    void* context,
    SeqNum seqNumber,
    ViewNum viewNumber,
    const char* const combinedSig,
    uint16_t combinedSigLen,
    const concordUtils::SpanContext& span_context) {
  InternalReplicaApi* r = (InternalReplicaApi*)context;
  return CommitFullMsg::create(
      viewNumber, seqNumber, r->getReplicasInfo().myId(), combinedSig, combinedSigLen, span_context);
}

InternalMessage SeqNumInfo::ExFuncForCommitCollector::createInterCombinedSigFailed(
    SeqNum seqNumber, ViewNum viewNumber, const std::set<uint16_t>& replicasWithBadSigs) {
  return CombinedCommitSigFailedInternalMsg(seqNumber, viewNumber, replicasWithBadSigs);
}

InternalMessage SeqNumInfo::ExFuncForCommitCollector::createInterCombinedSigSucceeded(
    SeqNum seqNumber,
    ViewNum viewNumber,
    const char* combinedSig,
    uint16_t combinedSigLen,
    const concordUtils::SpanContext& span_context) {
  return CombinedCommitSigSucceededInternalMsg(seqNumber, viewNumber, combinedSig, combinedSigLen, span_context);
}

InternalMessage SeqNumInfo::ExFuncForCommitCollector::createInterVerifyCombinedSigResult(SeqNum seqNumber,
                                                                                         ViewNum viewNumber,
                                                                                         bool isValid) {
  return VerifyCombinedCommitSigResultInternalMsg(seqNumber, viewNumber, isValid);
}

uint16_t SeqNumInfo::ExFuncForCommitCollector::numberOfRequiredSignatures(void* context) {
  InternalReplicaApi* r = (InternalReplicaApi*)context;
  const ReplicasInfo& info = r->getReplicasInfo();
  return (uint16_t)((info.fVal() * 2) + info.cVal() + 1);
}

std::shared_ptr<IThresholdVerifier> SeqNumInfo::ExFuncForCommitCollector::thresholdVerifier(SeqNum seqNumber) {
  return CryptoManager::instance().thresholdVerifierForSlowPathCommit(seqNumber);
}

concord::util::SimpleThreadPool& SeqNumInfo::ExFuncForCommitCollector::threadPool(void* context) {
  InternalReplicaApi* r = (InternalReplicaApi*)context;
  return r->getInternalThreadPool();
}

IncomingMsgsStorage& SeqNumInfo::ExFuncForCommitCollector::incomingMsgsStorage(void* context) {
  InternalReplicaApi* r = (InternalReplicaApi*)context;
  return r->getIncomingMsgsStorage();
}

///////////////////////////////////////////////////////////////////////////////
// class SeqNumInfo::ExFuncForFastPathOptimisticCollector
///////////////////////////////////////////////////////////////////////////////

FullCommitProofMsg* SeqNumInfo::ExFuncForFastPathOptimisticCollector::createCombinedSignatureMsg(
    void* context,
    SeqNum seqNumber,
    ViewNum viewNumber,
    const char* const combinedSig,
    uint16_t combinedSigLen,
    const concordUtils::SpanContext& span_context) {
  InternalReplicaApi* r = (InternalReplicaApi*)context;

  return new FullCommitProofMsg(
      r->getReplicasInfo().myId(), viewNumber, seqNumber, combinedSig, combinedSigLen, span_context);
}

InternalMessage SeqNumInfo::ExFuncForFastPathOptimisticCollector::createInterCombinedSigFailed(
    SeqNum seqNumber, ViewNum viewNumber, const std::set<uint16_t>& replicasWithBadSigs) {
  return CombinedCommitSigFailedInternalMsg(seqNumber, viewNumber, replicasWithBadSigs);
}

InternalMessage SeqNumInfo::ExFuncForFastPathOptimisticCollector::createInterCombinedSigSucceeded(
    SeqNum seqNumber,
    ViewNum viewNumber,
    const char* combinedSig,
    uint16_t combinedSigLen,
    const concordUtils::SpanContext& span_context) {
  return CombinedCommitSigSucceededInternalMsg(seqNumber, viewNumber, combinedSig, combinedSigLen, span_context);
}

InternalMessage SeqNumInfo::ExFuncForFastPathOptimisticCollector::createInterVerifyCombinedSigResult(SeqNum seqNumber,
                                                                                                     ViewNum viewNumber,
                                                                                                     bool isValid) {
  return VerifyCombinedCommitSigResultInternalMsg(seqNumber, viewNumber, isValid);
}

uint16_t SeqNumInfo::ExFuncForFastPathOptimisticCollector::numberOfRequiredSignatures(void* context) {
  InternalReplicaApi* r = (InternalReplicaApi*)context;
  const ReplicasInfo& info = r->getReplicasInfo();
  return 3 * info.fVal() + 2 * info.cVal() + 1;
}

std::shared_ptr<IThresholdVerifier> SeqNumInfo::ExFuncForFastPathOptimisticCollector::thresholdVerifier(
    SeqNum seqNumber) {
  return CryptoManager::instance().thresholdVerifierForOptimisticCommit(seqNumber);
}

concord::util::SimpleThreadPool& SeqNumInfo::ExFuncForFastPathOptimisticCollector::threadPool(void* context) {
  InternalReplicaApi* r = (InternalReplicaApi*)context;
  return r->getInternalThreadPool();
}

IncomingMsgsStorage& SeqNumInfo::ExFuncForFastPathOptimisticCollector::incomingMsgsStorage(void* context) {
  InternalReplicaApi* r = (InternalReplicaApi*)context;
  return r->getIncomingMsgsStorage();
}

///////////////////////////////////////////////////////////////////////////////
// class SeqNumInfo::ExFuncForFastPathThresholdCollector
///////////////////////////////////////////////////////////////////////////////

FullCommitProofMsg* SeqNumInfo::ExFuncForFastPathThresholdCollector::createCombinedSignatureMsg(
    void* context,
    SeqNum seqNumber,
    ViewNum viewNumber,
    const char* const combinedSig,
    uint16_t combinedSigLen,
    const concordUtils::SpanContext& span_context) {
  InternalReplicaApi* r = (InternalReplicaApi*)context;

  return new FullCommitProofMsg(
      r->getReplicasInfo().myId(), viewNumber, seqNumber, combinedSig, combinedSigLen, span_context);
}

InternalMessage SeqNumInfo::ExFuncForFastPathThresholdCollector::createInterCombinedSigFailed(
    SeqNum seqNumber, ViewNum viewNumber, const std::set<uint16_t>& replicasWithBadSigs) {
  return CombinedCommitSigFailedInternalMsg(seqNumber, viewNumber, replicasWithBadSigs);
}

InternalMessage SeqNumInfo::ExFuncForFastPathThresholdCollector::createInterCombinedSigSucceeded(
    SeqNum seqNumber,
    ViewNum viewNumber,
    const char* combinedSig,
    uint16_t combinedSigLen,
    const concordUtils::SpanContext& span_context) {
  return CombinedCommitSigSucceededInternalMsg(seqNumber, viewNumber, combinedSig, combinedSigLen, span_context);
}

InternalMessage SeqNumInfo::ExFuncForFastPathThresholdCollector::createInterVerifyCombinedSigResult(SeqNum seqNumber,
                                                                                                    ViewNum viewNumber,
                                                                                                    bool isValid) {
  return VerifyCombinedCommitSigResultInternalMsg(seqNumber, viewNumber, isValid);
}

uint16_t SeqNumInfo::ExFuncForFastPathThresholdCollector::numberOfRequiredSignatures(void* context) {
  InternalReplicaApi* r = (InternalReplicaApi*)context;
  const ReplicasInfo& info = r->getReplicasInfo();
  return 3 * info.fVal() + info.cVal() + 1;
}

std::shared_ptr<IThresholdVerifier> SeqNumInfo::ExFuncForFastPathThresholdCollector::thresholdVerifier(
    SeqNum seqNumber) {
  return CryptoManager::instance().thresholdVerifierForCommit(seqNumber);
}

concord::util::SimpleThreadPool& SeqNumInfo::ExFuncForFastPathThresholdCollector::threadPool(void* context) {
  InternalReplicaApi* r = (InternalReplicaApi*)context;
  return r->getInternalThreadPool();
}

IncomingMsgsStorage& SeqNumInfo::ExFuncForFastPathThresholdCollector::incomingMsgsStorage(void* context) {
  InternalReplicaApi* r = (InternalReplicaApi*)context;
  return r->getIncomingMsgsStorage();
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

void SeqNumInfo::init(SeqNumInfo& i, void* d) {
  void* context = d;
  InternalReplicaApi* r = (InternalReplicaApi*)context;

  i.replica = r;

  i.prepareSigCollector =
      new CollectorOfThresholdSignatures<PreparePartialMsg, PrepareFullMsg, ExFuncForPrepareCollector>(context);
  i.commitMsgsCollector =
      new CollectorOfThresholdSignatures<CommitPartialMsg, CommitFullMsg, ExFuncForCommitCollector>(context);
  // i.partialProofsSet = new PartialProofsSet((InternalReplicaApi*)r);
  i.fastPathOptimisticCollector = new CollectorOfThresholdSignatures<PartialCommitProofMsg,
                                                                     FullCommitProofMsg,
                                                                     ExFuncForFastPathOptimisticCollector>(context);
  i.fastPathThresholdCollector = new CollectorOfThresholdSignatures<PartialCommitProofMsg,
                                                                    FullCommitProofMsg,
                                                                    ExFuncForFastPathThresholdCollector>(context);
}

}  // namespace impl
}  // namespace bftEngine
