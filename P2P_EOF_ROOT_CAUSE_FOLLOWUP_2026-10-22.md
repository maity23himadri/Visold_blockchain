# Visold P2P TCP EOF root-cause follow-up — 2026-10-22

## সারসংক্ষেপ

**Active TCP session interruption-এর মূল initiating cause এখনও প্রমাণিত হয়নি।** তাই ওই অজানা কারণের জন্য কোনো networking-behavior fix যোগ করা হয়নি, এবং EOF কমেছে বা root cause ঠিক হয়েছে—এমন দাবি করা হচ্ছে না।

একই ৭→৮ node sequence-এ ৩০০ সেকেন্ডের forensic run থেকে অধিকাংশ failure-এ application-layer sequence সংকুচিত করা গেছে: এক endpoint-এ `SSLEOFError`/loop exit, তারপর disconnect cleanup, তারপর TCP FIN/RST এবং বিপরীত endpoint-এ EOF। তবে সব stream-এ ordering এক নয়। ১৫টি correlated TCP stream-এর মধ্যে ১২টিতে একই endpoint-এর FIN/RST exit log-এর পরে; ২টিতে একই পাশের FIN log-এর মাত্র প্রায় ০.৩ ms আগে; ১টিতে opposite-side FIN প্রথম exit-এর সামান্য আগে। ফলে এই evidence **বেশিরভাগ ক্ষেত্রেই cleanup downstream**, কিন্তু universal causality প্রমাণ করে না।

একই ডিভাইসে আটটি node চালানোর resource-stress অনুমানটি **বর্তমান মাপা data দ্বারা সমর্থিত নয়**, যদিও sampling প্রথম প্রায় ১০৭ সেকেন্ডে শুরু হয়নি বলে অতি স্বল্পমেয়াদি আগের spike সম্পূর্ণভাবে বাদ দেওয়া যাচ্ছে না।

## পরীক্ষার পদ্ধতি ও ফল

`tools/run_tcp_eof_7to8_repro.py` দিয়ে সাতটি node একসঙ্গে চালিয়ে প্রতিটি ছয় peer-সহ স্থিতিশীল হওয়ার পর node 8 চালানো হয়। আটটি node সাত peer-সহ ১০ সেকেন্ড স্থিতিশীল হওয়ার পর ৩০০ সেকেন্ড মাপা হয়। Test window: **2026-10-22 07:19:36.746468–07:24:36.746468 UTC**; run সম্পন্ন হয়।

P2P policy values আট node-এ consistent ছিল: `max_peers=30`, `min_peers=25`, `peer_decay_secs=3600`, per-IP connection limit `12/60s`, `PEX_INTERVAL=60s`, `RECONNECT_INTERVAL=60s`। কোনো peer/subnet limit, retry interval বা PEX policy override করা হয়নি। শুধু localhost topology-তে পরীক্ষাটি সীমাবদ্ধ রাখতে DNS seed bootstrap বন্ধ ছিল এবং প্রত্যেক node-কে পরীক্ষার নির্দিষ্ট localhost endpoint দেওয়া হয়েছিল।

Mesh **পরীক্ষার পুরো সময় স্থিতিশীল ছিল না**: `criteria_passed=false`, peer-count-এর সর্বনিম্ন ৫, connected link সর্বোচ্চ ২৮-এর মধ্যে সর্বনিম্ন ২৪, এবং ৩০০টি এক-সেকেন্ড sample-এর মধ্যে ৪৯টিতে সব node-এ সাত peer ছিল। Session churn record ছিল ২৯। অতএব এটি স্থিতিশীলতা-পাস নয়; বরং ব্যর্থতা পুনরুৎপাদনকারী পর্যবেক্ষণ।

Measurement window-তে ৩০টি `PeerLoopExit` event ছিল: ২৯টি `unexpected_exception:SSLEOFError` এবং ১টি `ping_send_failed_after_socket_timeout`। এগুলোকে ৩০টি স্বাধীন TCP failure বলা যাবে না। Packet capture-এ ১৫টি TCP stream incarnation-এর সঙ্গে endpoint logs correlate হয়েছে; এক link-এর দুই endpoint-এর log একই stream-এর duplicate observation। Exception-time TCP state snapshots: `ESTABLISHED=13`, `CLOSED=13`, `unavailable_OSError=3`, `not_sampled=1`।

১৫টি stream-এর first terminal packet classification: ৪টি FIN ও ১০টি RST প্রথম-exit log করা একই endpoint থেকে; ১টি FIN বিপরীত endpoint থেকে। Timing-এ ১২টি same-side FIN/RST application exit log-এর পরে, ২টি same-side FIN log-এর প্রায় ০.২৭–০.৩২ ms আগে, এবং ওই একটি opposite-side FIN-ও প্রথম exit-এর অল্প আগে। প্রথম exit-এর কাছাকাছি close records-এ caller ছিল `_on_peer_disconnect`। অতএব ১২টি link-এ cleanup-পরবর্তী packet order স্পষ্ট; ৩টি near-simultaneous/pre-existing terminal event-এর initiating path আলাদা প্রমাণ ছাড়া নির্ধারিত নয়।

### নির্দিষ্ট session-এর event order

TCP stream 40, endpoint pair `127.0.0.1:30960`↔`127.0.0.1:38076`, shared session ID `99dc2ca704bf02cdc440`:

1. Node 7-এর inbound-side loop-এ `07:19:37.810932 UTC`-তে `SSLEOFError` হয়। শেষ successfully received message ছিল `RECEIPT_RESPONSE` (প্রায় ०.९६ ms আগে)। Exception-time snapshot: `tcp_state=ESTABLISHED`, `socket_fd=24`, `socket_closed=false`।
2. Node 7-এর socket-close record `07:19:37.812229 UTC`-তে `_on_peer_disconnect` caller দেখায়।
3. Packet capture-এ ওই endpoint থেকে FIN `07:19:37.812506 UTC`-তে—প্রথম EOF log-এর প্রায় ১.৫৭ ms পরে—বের হয়।
4. Node 4-এর বিপরীত endpoint-এর `SSLEOFError` `07:19:37.817881 UTC`-তে দেখা যায়; তার snapshot-এ TCP state ইতিমধ্যে `CLOSED`। তার send failures ও close event সেই পরবর্তী teardown-এর অংশ।

এই link-এ প্রথম EOF-এর আগে remote FIN/RST বা TLS alert দেখা যায়নি; প্রথম terminal packet ছিল EOF-পরবর্তী local FIN। সম্পূর্ণ capture-এ kernel packet-drop count ছিল ০। Decrypt করা capture-এ এই run-এর কোনো TLS alert record পাওয়া যায়নি। এই evidence এই প্রতিনিধিত্বমূলক link-এ local TLS/read error → local cleanup → opposite-side error sequence দেখায়; **কেন open, `ESTABLISHED` socket থেকে OpenSSL `SSLEOFError` ফেরায় তা এখনও ব্যাখ্যা করে না**।

অন্য stream-গুলোর ordering এক নয়। বিশেষ করে দুই same-side FIN এবং এক opposite-side FIN application exit log-এর অল্প আগে দেখা গেছে; তাদের জন্য timestamp-নিকটতা একাই কারণ বা caller প্রমাণ করে না। কিছু exception-time socket snapshots `unavailable_OSError` ছিল। Event window-এ ৪টি `_register_peer` close record ছিল, কিন্তু ১৫টি EOF-matched stream-এর কাছের close caller `_on_peer_disconnect`; duplicate arbitration-কে এই stream-গুলোর সাধারণ কারণ হিসেবে প্রমাণ করার মতো same-stream `_register_peer` record মেলেনি। Orderly node shutdown measurement window-এর পরে হয়েছে, সেটি বাদ।

## একই ডিভাইসে resource-stress অনুমান

Device-এ ৬টি CPU core ছিল। Read-only sampler ২-সেকেন্ড interval-এ মাপা ৩০০-সেকেন্ড window-এর ৯৫টি sample সংগ্রহ করেছে (প্রায় শেষ ১৯০ সেকেন্ড; sampling শুরু হয় test start-এর প্রায় ১০৬.৮ সেকেন্ড পরে):

- load average 1-minute range **0.52–1.29** (mean 0.895), 95th percentile 1.26;
- available memory **19,577–19,665 MiB**; memory PSI `some.avg10` সর্বত্র 0.00%;
- CPU PSI `some.avg10` range **0.72–4.66%**;
- per-node process CPU peak **90.31%** (এক core-এর), আট node-এর aggregate peak **144.01%** (প্রায় 1.44 core);
- প্রতি node RSS peak **69.1 MiB**, FD count **18–22**; inherited nofile limit **65,535**।

Sampler শুরু হওয়ার আগের একটি spot sample-এও ৬ core-এ load `0.89 / 1.37 / 1.57`, available RAM প্রায় ১৯ GiB, memory PSI শূন্য ছিল। ফলে মাপা অংশে CPU saturation, memory pressure বা FD exhaustion-এর লক্ষণ নেই। Capture, TLS key logging এবং strict EOF diagnostics-সহ এই forensic run-এ কিছু অতিরিক্ত overhead ছিল। তবুও device stress এই run-এর মূল কারণ—এমন প্রমাণ নেই। প্রথম প্রায় ১০৭ সেকেন্ডের sampling gap ও transient pressure-এর সম্ভাবনার কারণে একে সম্পূর্ণ অসম্ভবও বলা হচ্ছে না।

## পূর্বের confirmed fixes ও regression protection

বর্তমান source-এ আগের তদন্তে deterministic regression দিয়ে ধরা দুটি adjacent issue সংরক্ষিত আছে: (1) stale TCP decay snapshot যেন একই peer-এর replacement session-কে evict না করে—শুধু নির্বাচিত exact session object remove/close করা; (2) সফলভাবে decode হওয়া inbound TCP message-এ `last_seen` refresh করা। এগুলোর race/activity regressions পাস করেছে। কিন্তু ৩,৬০০-সেকেন্ড decay threshold এবং পাঁচ মিনিটের run-এর timing এই দুই issue-কে বর্তমান `ESTABLISHED`-state `SSLEOFError`-এর প্রমাণিত কারণ বানায় না।

PEX dial-budget accounting ও PING/PONG behavior অপরিবর্তিত এবং তাদের regressions পাস করেছে। নিষিদ্ধ peer/subnet/interval/per-IP policy বদলানো হয়নি; `visold/kernel/config.py` uploaded baseline-এর সঙ্গে byte-for-byte একই।

## Source-এ পরিবর্তন ও আচরণগত সীমা

- Session/endpoint/timestamp/last-inbound-message correlation, writer exception visibility, close/unwrap/shutdown caller audit এবং EOF/exception মুহূর্তে passive TCP/TLS state snapshot যোগ করা হয়েছে।
- TLS key-log (`VISOLD_TLS_KEYLOG_FILE`) ও strict ragged-EOF (`VISOLD_TLS_STRICT_EOF_DIAGNOSTIC`) opt-in diagnostics; default production run-এ এগুলো বন্ধ। Test harness-এ full-packet capture/keylog switches explicit opt-in.
- **Unexplained active EOF-এর সংশ্লিষ্ট networking logic পরিবর্তন করা হয়নি**; speculative timeout, peer policy, retry বা PEX changes নেই।
- Package build identity manifest বর্তমান package source-এর সঙ্গে মেলে।

## যাচাই ও অনিশ্চয়তা

Updated source-এর ১৩টি focused regression module-এ **৯৯টি test pass**; compile, architecture checker ও source-identity verification pass। ১২০-সেকেন্ডের আলাদা loopback TLS full-duplex stress control-এ spontaneous EOF হয়নি, কিন্তু সেটি প্রকৃত Visold message workload/ownership path-কে সম্পূর্ণ reproduce করে না। Full project suite চালানো হয়নি।

**Root-cause status: unresolved.** Evidence দেখায় অনেক stream-এ local SSL/read error-এর পরে cleanup FIN/RST আসে; কিন্তু open TCP socket-এ TLS EOF-এর initiating cause, এবং তিনটি near-simultaneous/pre-existing terminal event-এর কারণ, প্রমাণিত নয়। Resource exhaustion-ও current measurements-এ দেখা যায়নি। পরের প্রমাণ-সংগ্রহে একই socket/thread-এর `recv*` syscall return, live descriptor identity, `shutdown/close` syscall, এবং SSL shutdown/error state একসঙ্গে capture করা দরকার—বিশেষ করে `ESTABLISHED` snapshot-এর আগে/পরে। এই run-এ application-level close hook কোনো raw close/unwrap/shutdown action log করেনি, কিন্তু সেটি syscall-level tracing-এর বিকল্প নয়। এই আলাদা সংকেত না পাওয়া পর্যন্ত কোনো core behavior fix অনুমোদিত/যাচাইকৃত বলা যাবে না।

Exact test commands ও ফলাফল [`P2P_EOF_TEST_RESULTS_2026-10-22.md`](P2P_EOF_TEST_RESULTS_2026-10-22.md)-এ আছে। TLS traffic secrets ও raw capture deliverable ZIP-এ অন্তর্ভুক্ত করা হয়নি।
