---------------------------- MODULE Recovery ----------------------------
EXTENDS Integers, FiniteSets

\* Bounded target-protocol model. Cryptographic checks are assumed predicates;
\* this model neither implements proofs nor establishes quantum soundness.
CONSTANTS CandidateHeightGate, CheckSpent, AtomicStorage,
          CheckEffectBinding, ScopeReplayByEffects
VARIABLES live, disk
vars == <<live, disk>>
Slots == 0..4
Kinds == {"legacy", "legacy-fee", "prepare", "migrate", "spend", "rotate"}
Claims == {"valid", "bad-owner", "bad-member", "bad-binding", "bad-value",
           "bad-program", "bad-possession"}
First == 2
Second == 4
Last == 4
Legacy(k) == k \in {"legacy", "legacy-fee"}

Base == [height |-> 0, known |-> {0,1}, spent |-> {},
         version |-> [r \in Slots |-> IF r=1 THEN 1 ELSE 0],
         value |-> [r \in Slots |-> IF r \in {0,1} THEN 3 ELSE 0],
         key |-> [r \in Slots |-> 0], count |-> [r \in Slots |-> 0],
         fees |-> 0, seen |-> {}, badProof |-> FALSE, retiredLegacy |-> FALSE]
Init == /\ live = Base /\ disk = Base

GateHeight(s) == IF CandidateHeightGate THEN s.height+1 ELSE s.height
Phase(h) == IF h >= Second THEN 2 ELSE IF h >= First THEN 1 ELSE 0

Allowed(s,t) ==
 LET v == s.version[t.input]
     p == Phase(GateHeight(s))
 IN CASE Legacy(t.kind) -> p<2 /\ v \in {0,1,2}
      [] t.kind="prepare" -> p=1 /\ v \in {0,1}
      [] t.kind="migrate" -> p=2 /\ v=2
      [] t.kind="spend" -> p=2 /\ v=3
      [] t.kind="rotate" -> (p=1 /\ v=2) \/ (p=2 /\ v=3)

TargetVersion(s,t) ==
 IF Legacy(t.kind) THEN IF Phase(GateHeight(s))=0 THEN 1 ELSE 2
 ELSE IF t.kind="prepare" THEN 2
 ELSE IF t.kind="rotate" THEN s.version[t.input] ELSE 3

Txs(s) == {[input |-> r, output |-> o, kind |-> k, key |-> key,
            nonce |-> 0, claim |-> claim] :
            r \in s.known, o \in Slots \ s.known, k \in Kinds,
            key \in 0..2, claim \in Claims}
EffectsId(t) == <<t.input,t.output,t.kind,t.key,t.nonce>>
ReplayKey(t) == IF ScopeReplayByEffects THEN EffectsId(t) ELSE t.nonce
ProofOK(t) == t.claim="valid" \/ (~CheckEffectBinding /\ t.claim="bad-binding")

Shape(s,t) ==
 /\ t.output > t.input
 /\ s.height < Last
 /\ s.value[t.input] >= 1
 /\ Allowed(s,t)
 /\ IF TargetVersion(s,t)>=2 THEN t.key \in {1,2} ELSE t.key=0
 /\ t.key >= s.key[t.input]
 /\ t.kind="migrate" => t.key=s.key[t.input]

Eligible(s,t) ==
 /\ Shape(s,t)
 /\ ProofOK(t)
 /\ IF CheckSpent THEN t.input \notin s.spent ELSE TRUE
 /\ ReplayKey(t) \notin s.seen

Applied(s,t) == [s EXCEPT
 !.known = @ \cup {t.output},
 !.spent = @ \cup {t.input},
 !.version[t.output] = TargetVersion(s,t),
 !.value[t.output] = s.value[t.input]-1,
 !.key[t.output] = t.key,
 !.count[t.input] = @+1,
 !.fees = @+1,
 !.seen = @ \cup {ReplayKey(t)},
 !.badProof = @ \/ t.claim#"valid",
 !.retiredLegacy = @ \/ (Legacy(t.kind) /\ s.height+1>=Second)]

Spend == \E t \in Txs(live):
 /\ Eligible(live,t)
 /\ live' = Applied(live,t)
 /\ UNCHANGED disk

Advance == /\ live.height < Last
           /\ live' = [live EXCEPT !.height = @+1]
           /\ UNCHANGED disk

Persist == /\ disk' = IF AtomicStorage THEN live
                       ELSE [live EXCEPT !.spent=disk.spent, !.count=disk.count]
           /\ UNCHANGED live

Crash == /\ live' = disk /\ UNCHANGED disk
Next == Spend \/ Advance \/ Persist \/ Crash

RECURSIVE CreditSum(_, _)
CreditSum(s,n) == IF n<0 THEN 0 ELSE
 (IF n \in s.known \ s.spent THEN s.value[n] ELSE 0) + CreditSum(s,n-1)
Supply(s) == CreditSum(s,4)+s.fees

TypeOK == \A s \in {live,disk}:
 /\ s.height \in 0..Last
 /\ s.known \subseteq Slots
 /\ s.spent \subseteq s.known
 /\ s.version \in [Slots -> 0..3]
 /\ s.key \in [Slots -> 0..2]
 /\ s.value \in [Slots -> 0..3]
Conservation == Supply(live)=6 /\ Supply(disk)=6
NoDoubleSpend == \A s \in {live,disk}: \A r \in Slots: s.count[r]<=1
NoRetiredLegacy == ~live.retiredLegacy /\ ~disk.retiredLegacy
ProofContract == ~live.badProof /\ ~disk.badProof
ReplayIsolation == \A s \in {live,disk}: \A t \in Txs(s):
 (Shape(s,t) /\ t.claim="valid" /\ t.input \notin s.spent)
 => ReplayKey(t) \notin s.seen

\* These deliberately false invariants produce witnesses of reachable progress.
NoV2Created == \A r \in live.known: live.version[r]#2
NoV3Created == \A r \in live.known: live.version[r]#3
NoV3Consumed == \A r \in live.known: live.version[r]#3 \/ live.count[r]=0
=============================================================================
