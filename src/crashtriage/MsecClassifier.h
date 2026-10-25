#pragma once

// MSEC !exploitable-style classifier over a CrashArtifact's evidence list.
//
// The classifier is deliberately deterministic and inspectable: rules
// look at (exception_code, fault_address kind, mitigation flags, evidence
// slugs) and pick a bucket. Confidence starts at 0.5 and moves up per
// supporting evidence slug (bounded to 1.0). The rationale is a one-line
// summary; evidence_slugs enumerates which Evidence entries fed the call.

#include "crashtriage/CrashArtifact.h"

namespace angelia::crashtriage {

// Runs the classifier over `a`. Requires that `a.analysis` has been
// populated (otherwise verdict.bucket == NotClassified with a message).
// Returns the verdict directly and, as a side effect, stores it on `a`.
MsecVerdict classify(CrashArtifact& a);

}  // namespace angelia::crashtriage
