# Dependency baseline domain

`eligibility` and `compare` accept explicit capture coverage from a dedicated
complete query. A visual graph alone cannot establish this contract. The host
must validate source and current user entitlement independently; the model
does not authenticate claims supplied by a browser. Signatures use stable
logical IDs supplied by a qualified adapter and never derive identity from pod
addresses or display names. Missing observations remain “not observed”.

`BaselineReview` presents supplied version records, eligibility and passive
watch definitions. No persistence, authorization, complete source adapter,
schedule, notification, or deployment qualification is supplied here.
`watchStatus` deduplicates identical signature/window observations; its
cooldown is measured from the latest recorded observation and does not assert
that a notification was sent.
